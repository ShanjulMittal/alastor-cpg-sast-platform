"""
Singleton Neo4j Bolt driver and database initialization procedures.
"""
import os
import re
import logging
from typing import Optional, Tuple
from neo4j import GraphDatabase, Driver

logger = logging.getLogger("cpg-sast.neo4j")


def resolve_neo4j_runtime_auth() -> Optional[Tuple[str, str]]:
    """
    Resolves Neo4j Bolt credentials strictly from environment variables (NEO4J_AUTH / NEO4J_PASSWORD),
    falling back only to local docker-compose.yml substitution defaults for developer workstations.
    No credentials are hardcoded in Python source code.
    """
    raw_auth = os.environ.get("NEO4J_AUTH", "").strip()
    if "/" in raw_auth and raw_auth.lower() != "none":
        usr, pwd = raw_auth.split("/", 1)
        return (usr, pwd)

    env_user = os.environ.get("NEO4J_USER", "").strip()
    env_cred = os.environ.get("NEO4J_PASSWORD", "").strip()
    if env_cred:
        return (env_user or "neo4j", env_cred)

    compose_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "docker-compose.yml")
    )
    if os.path.isfile(compose_path):
        try:
            with open(compose_path, "r", encoding="utf-8") as fh:
                content = fh.read()
            m = re.search(
                r"NEO4J_AUTH:\s*\"?\$\{NEO4J_USER:-([^}]+)\}/\$\{NEO4J_PASSWORD:-([^}]+)\}\"?",
                content,
            )
            if m:
                return (env_user or m.group(1), m.group(2))
        except OSError:
            pass
    return None


class Neo4jClient:
    _instance: Optional["Neo4jClient"] = None

    def __init__(self):
        self.uri = os.environ.get("NEO4J_URI") or "bolt://localhost:7687"
        runtime_auth = resolve_neo4j_runtime_auth()
        self.user = runtime_auth[0] if runtime_auth else ""
        self.driver: Driver = GraphDatabase.driver(
            self.uri,
            auth=runtime_auth,
            max_connection_lifetime=3600,
            max_connection_pool_size=50
        )

    @classmethod
    def get_instance(cls) -> "Neo4jClient":
        if cls._instance is None:
            cls._instance = Neo4jClient()
        return cls._instance

    def verify_connectivity_and_apoc(self) -> bool:
        """Verifies Neo4j connection and confirms APOC library is operational."""
        self.driver.verify_connectivity()
        with self.driver.session() as session:
            result = session.run("CALL apoc.help('iterate') YIELD name RETURN count(name) AS c")
            record = result.single()
            if not record or record["c"] < 1:
                raise RuntimeError("Neo4j APOC library is not available.")
        logger.info("Connected to Neo4j successfully. APOC verified.")
        return True

    def init_schema(self) -> None:
        """Creates unique constraints and high-throughput indexes."""
        # Cleanup any legacy constraint conflicts if they exist
        drop_queries = [
            "DROP CONSTRAINT app_file_path IF EXISTS",
            "DROP CONSTRAINT app_dir_path IF EXISTS"
        ]
        with self.driver.session() as session:
            for dq in drop_queries:
                try:
                    session.run(dq)
                except Exception:
                    pass

        queries = [
            "CREATE CONSTRAINT cpg_node_id IF NOT EXISTS FOR (n:CPGNode) REQUIRE n.id IS UNIQUE",
            "CREATE INDEX cpg_node_label IF NOT EXISTS FOR (n:CPGNode) ON (n.label)",
            "CREATE INDEX cpg_node_name IF NOT EXISTS FOR (n:CPGNode) ON (n.name)",
            "CREATE INDEX cpg_node_filepath IF NOT EXISTS FOR (n:CPGNode) ON (n.filepath)",
            "CREATE INDEX idx_cpg_source IF NOT EXISTS FOR (n:CPGNode) ON (n.is_source)",
            "CREATE INDEX idx_cpg_sink IF NOT EXISTS FOR (n:CPGNode) ON (n.is_sink)",
            "CREATE INDEX idx_var_fp_name IF NOT EXISTS FOR (v:Variable) ON (v.filepath, v.name)",
            "CREATE CONSTRAINT app_file_id IF NOT EXISTS FOR (f:AppFile) REQUIRE f.id IS UNIQUE",
            "CREATE CONSTRAINT app_dir_id IF NOT EXISTS FOR (d:AppDirectory) REQUIRE d.id IS UNIQUE",
            "CREATE INDEX app_file_category IF NOT EXISTS FOR (f:AppFile) ON (f.category)",
            "CREATE INDEX app_file_filepath IF NOT EXISTS FOR (f:AppFile) ON (f.filepath)"
        ]
        with self.driver.session() as session:
            for q in queries:
                session.run(q)
        logger.info("Neo4j CPG and Application Tree schema constraints and indexes initialized.")

    def clear_database(self) -> None:
        """Clears all CPG, File, Directory, and AppElement nodes and relationships safely in batches."""
        with self.driver.session() as session:
            try:
                session.run(
                    "CALL apoc.periodic.iterate("
                    "'MATCH (n) RETURN n', "
                    "'DETACH DELETE n', "
                    "{batchSize: 10000, parallel: false})"
                )
            except Exception as apoc_err:
                logger.warning("APOC periodic iterate failed (%s), falling back to chunked Cypher delete.", apoc_err)
                while True:
                    res = session.run("MATCH (n) WITH n LIMIT 10000 DETACH DELETE n RETURN count(n) AS deleted")
                    rec = res.single()
                    if not rec or rec["deleted"] == 0:
                        break
        logger.info("Cleared existing graph database.")

    def close(self) -> None:
        if self.driver:
            self.driver.close()
            Neo4jClient._instance = None
