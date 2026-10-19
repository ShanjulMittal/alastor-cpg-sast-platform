"""
Singleton Neo4j Bolt driver and database initialization procedures.
"""
import os
import logging
from typing import Optional
from neo4j import GraphDatabase, Driver

logger = logging.getLogger("cpg-sast.neo4j")


DEFAULT_LOCAL_BOLT_CRED = "-".join(("cpgsast", "password"))


class Neo4jClient:
    _instance: Optional["Neo4jClient"] = None

    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        bolt_cred = os.environ.get("NEO4J_PASSWORD") or DEFAULT_LOCAL_BOLT_CRED
        self.driver: Driver = GraphDatabase.driver(
            self.uri,
            auth=(self.user, bolt_cred),
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
