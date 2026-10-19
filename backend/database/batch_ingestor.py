"""
High-throughput batched ingestion into Neo4j using UNWIND and APOC procedures.
Supports both fine-grained CPG nodes/edges and unified Application Architecture Tree nodes/relationships.
"""
import logging
import hashlib
from typing import List, Tuple, Dict, Any, Optional, Callable
from models import CPGNode, CPGEdge, AppTreeSummary, DirectoryTreeNode, FilePurposeInfo
from database.neo4j_client import Neo4jClient

logger = logging.getLogger("cpg-sast.ingestor")

BATCH_SIZE = 5000


class BatchIngestor:
    def __init__(self, client: Neo4jClient):
        self.client = client

    def ingest(self, nodes: List[CPGNode], edges: List[CPGEdge],
               progress_callback: Optional[Callable[[str, int, int], None]] = None) -> Tuple[int, int]:
        """Chunks and ingests CPG nodes and edges into Neo4j in batches of 5000."""
        nodes_created = self.ingest_nodes(nodes, progress_callback=progress_callback)
        edges_created = self.ingest_edges(edges, progress_callback=progress_callback)
        return nodes_created, edges_created

    def ingest_nodes(self, nodes: List[CPGNode],
                     progress_callback: Optional[Callable[[str, int, int], None]] = None) -> int:
        """Ingests nodes using UNWIND and apoc.create.addLabels."""
        if not nodes:
            return 0

        query = """
        UNWIND $batch AS row
        MERGE (n:CPGNode {id: row.id})
        SET n += row
        WITH n, row
        CALL apoc.create.addLabels(n, [row.label]) YIELD node
        RETURN count(node) AS created_count
        """
        total = 0
        node_dicts = [n.model_dump() for n in nodes]
        total_items = len(node_dicts)

        with self.client.driver.session() as session:
            for i in range(0, total_items, BATCH_SIZE):
                batch = node_dicts[i:i + BATCH_SIZE]
                result = session.run(query, batch=batch)
                rec = result.single()
                if rec:
                    total += rec["created_count"]
                if progress_callback:
                    progress_callback("Ingesting CPG nodes into graph...", min(i + BATCH_SIZE, total_items), total_items)
        
        logger.info(f"Batched ingested {total} CPG nodes into Neo4j.")
        return total

    def ingest_edges(self, edges: List[CPGEdge],
                     progress_callback: Optional[Callable[[str, int, int], None]] = None) -> int:
        """Ingests edges using UNWIND and apoc.merge.relationship."""
        if not edges:
            return 0

        query = """
        UNWIND $batch AS row
        MATCH (s:CPGNode {id: row.source_id})
        MATCH (t:CPGNode {id: row.target_id})
        CALL apoc.merge.relationship(s, row.edge_type, {id: row.id}, {var_name: row.var_name}, t) YIELD rel
        RETURN count(rel) AS created_count
        """
        total = 0
        edge_dicts = [e.model_dump() for e in edges]
        total_items = len(edge_dicts)

        with self.client.driver.session() as session:
            for i in range(0, total_items, BATCH_SIZE):
                batch = edge_dicts[i:i + BATCH_SIZE]
                result = session.run(query, batch=batch)
                rec = result.single()
                if rec:
                    total += rec["created_count"]
                if progress_callback:
                    progress_callback("Ingesting CPG edges into graph...", min(i + BATCH_SIZE, total_items), total_items)

        logger.info(f"Batched ingested {total} CPG edges into Neo4j.")
        return total

    def ingest_app_tree(self, tree_summary: AppTreeSummary,
                        progress_callback: Optional[Callable[[str, int, int], None]] = None) -> Tuple[int, int]:
        """Ingests the full application directory tree, files, and architectural elements."""
        dir_rows: List[Dict[str, Any]] = []
        dir_contains_dirs: List[Dict[str, Any]] = []
        dir_contains_files: List[Dict[str, Any]] = []
        file_rows: List[Dict[str, Any]] = []
        element_rows: List[Dict[str, Any]] = []
        file_declares_elements: List[Dict[str, Any]] = []

        def traverse_dir(node: DirectoryTreeNode, parent_path: str = ""):
            dir_path = node.path if node.path else "root"
            dir_rows.append({
                "id": f"dir:{dir_path}",
                "path": dir_path,
                "name": node.name,
                "purpose": node.purpose or f"Directory: {node.name}"
            })

            if parent_path:
                dir_contains_dirs.append({
                    "parent_id": f"dir:{parent_path}",
                    "child_id": f"dir:{dir_path}"
                })

            for f in node.files:
                file_id = f"file:{f.filepath}"
                file_rows.append({
                    "id": file_id,
                    "filepath": f.filepath,
                    "filename": f.filename,
                    "extension": f.extension,
                    "category": f.category,
                    "purpose": f.purpose,
                    "language": f.language,
                    "line_count": f.line_count,
                    "size_bytes": f.size_bytes,
                    "sha256": f.sha256,
                    "is_cpg_supported": f.is_cpg_supported,
                    "security_tags": f.security_tags
                })
                dir_contains_files.append({
                    "dir_id": f"dir:{dir_path}",
                    "file_id": file_id
                })

                for elem in f.elements:
                    elem_id = f"elem:{f.filepath}:{elem.name}:{elem.line_number}"
                    element_rows.append({
                        "id": elem_id,
                        "name": elem.name,
                        "element_type": elem.element_type,
                        "signature": elem.signature,
                        "line_number": elem.line_number,
                        "details": elem.details,
                        "filepath": f.filepath
                    })
                    file_declares_elements.append({
                        "file_id": file_id,
                        "elem_id": elem_id
                    })

            for sub in node.subdirectories:
                traverse_dir(sub, dir_path)

        traverse_dir(tree_summary.tree)

        nodes_created = 0
        edges_created = 0

        with self.client.driver.session() as session:
            # 1. Ingest AppDirectory nodes
            if dir_rows:
                q_dirs = """
                UNWIND $batch AS row
                MERGE (d:AppDirectory {id: row.id})
                SET d += row
                RETURN count(d) AS c
                """
                for i in range(0, len(dir_rows), BATCH_SIZE):
                    batch = dir_rows[i:i + BATCH_SIZE]
                    res = session.run(q_dirs, batch=batch).single()
                    nodes_created += res["c"] if res else 0

            # 2. Ingest AppFile nodes
            if file_rows:
                q_files = """
                UNWIND $batch AS row
                MERGE (f:AppFile {id: row.id})
                SET f += row
                RETURN count(f) AS c
                """
                for i in range(0, len(file_rows), BATCH_SIZE):
                    batch = file_rows[i:i + BATCH_SIZE]
                    res = session.run(q_files, batch=batch).single()
                    nodes_created += res["c"] if res else 0
                    if progress_callback:
                        progress_callback("Ingesting app files into graph...", min(i + BATCH_SIZE, len(file_rows)), len(file_rows))

            # 3. Ingest AppElement nodes
            if element_rows:
                q_elems = """
                UNWIND $batch AS row
                MERGE (e:AppElement {id: row.id})
                SET e += row
                RETURN count(e) AS c
                """
                for i in range(0, len(element_rows), BATCH_SIZE):
                    batch = element_rows[i:i + BATCH_SIZE]
                    res = session.run(q_elems, batch=batch).single()
                    nodes_created += res["c"] if res else 0

            # 4. Ingest CONTAINS (Dir -> Dir)
            if dir_contains_dirs:
                q_c_dirs = """
                UNWIND $batch AS row
                MATCH (p:AppDirectory {id: row.parent_id})
                MATCH (c:AppDirectory {id: row.child_id})
                MERGE (p)-[:CONTAINS]->(c)
                RETURN count(*) AS c
                """
                for i in range(0, len(dir_contains_dirs), BATCH_SIZE):
                    batch = dir_contains_dirs[i:i + BATCH_SIZE]
                    res = session.run(q_c_dirs, batch=batch).single()
                    edges_created += res["c"] if res else 0

            # 5. Ingest CONTAINS (Dir -> File)
            if dir_contains_files:
                q_c_files = """
                UNWIND $batch AS row
                MATCH (d:AppDirectory {id: row.dir_id})
                MATCH (f:AppFile {id: row.file_id})
                MERGE (d)-[:CONTAINS]->(f)
                RETURN count(*) AS c
                """
                for i in range(0, len(dir_contains_files), BATCH_SIZE):
                    batch = dir_contains_files[i:i + BATCH_SIZE]
                    res = session.run(q_c_files, batch=batch).single()
                    edges_created += res["c"] if res else 0

            # 6. Ingest DECLARES (File -> AppElement)
            if file_declares_elements:
                q_declares = """
                UNWIND $batch AS row
                MATCH (f:AppFile {id: row.file_id})
                MATCH (e:AppElement {id: row.elem_id})
                MERGE (f)-[:DECLARES]->(e)
                RETURN count(*) AS c
                """
                for i in range(0, len(file_declares_elements), BATCH_SIZE):
                    batch = file_declares_elements[i:i + BATCH_SIZE]
                    res = session.run(q_declares, batch=batch).single()
                    edges_created += res["c"] if res else 0

            # 7. Link AppFile nodes to CPG nodes (AppFile -> CPGNode)
            q_link_cpg = """
            MATCH (f:AppFile)
            MATCH (c:CPGNode)
            WHERE c.filepath = f.filepath AND c.label IN ['File', 'Module', 'Function']
            MERGE (f)-[:CONTAINS_AST]->(c)
            RETURN count(*) AS c
            """
            res = session.run(q_link_cpg).single()
            edges_created += res["c"] if res else 0

        logger.info(f"Ingested App Tree into Neo4j: {nodes_created} nodes, {edges_created} relationships.")
        return nodes_created, edges_created
