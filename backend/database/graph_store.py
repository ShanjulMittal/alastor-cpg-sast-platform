"""
Dual-Engine GraphStore for ALASTOR v5.0 Pillar 1:
- Primary Engine: `Neo4jGraphStore` (Neo4j 5 + APOC via Bolt)
- Zero-Docker Fallback: `EmbeddedGraphStore` (Pure-Python SQLite WAL in `.alastor_vault/cpg_embedded.db`)
- Facade: `GraphStoreManager` honoring `ALASTOR_GRAPH_ENGINE=auto|neo4j|embedded`

Security & Reliability Invariants:
- Strictly parameterized `?` SQLite queries ONLY (zero SQL string interpolation).
- `.alastor_vault` directory 0o700 / `cpg_embedded.db` file 0o600 (best-effort on Windows).
- `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`
- Thread-safe via `threading.RLock()`.
- Zero JVM dependencies.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from collections import defaultdict, deque
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from compiler.scanner import ScannedFile
from database.batch_ingestor import BatchIngestor
from database.neo4j_client import Neo4jClient
from engine.community_detector import build_community_graph_view
from engine.polyglot_rules import run_polyglot_rules
from engine.rule_executor import (
    RULES,
    RuleExecutor,
    build_cpg_finding_from_rule,
    is_sanitizer_compatible_for_sink,
    merge_findings_deduplicated,
)
from models import (
    AppTreeSummary,
    CPGEdge,
    CPGNode,
    CommunityMapResponse,
    DirectoryTreeNode,
    Finding,
    GraphEngineMode,
)

logger = logging.getLogger("cpg-sast.graph-store")

_RULES_BY_ID: Dict[str, Dict[str, Any]] = {r["id"]: r for r in RULES}
_CFG_EDGE_TYPES: Set[str] = {"CFG_NEXT", "CFG_TRUE", "CFG_FALSE", "CFG_LOOP_BACK", "CFG_BREAK"}
_SQLITE_BATCH_SIZE = 5000
_MAX_VIEW_NODES = 300
_MAX_VIEW_EDGES = 600

_ROUTE_HINTS: Tuple[str, ...] = (
    "@app.",
    "@router.",
    "@GetMapping",
    "@PostMapping",
    "@PutMapping",
    "@DeleteMapping",
    "@RequestMapping",
    "app.get(",
    "app.post(",
    "router.get(",
    "router.post(",
    "http.HandleFunc",
)

_PATH_TRAVERSAL_SINKS: Set[str] = {
    "open",
    "shutil.rmtree",
    "shutil.copy",
    "shutil.move",
    "os.remove",
    "os.unlink",
    "send_file",
    "FileResponse",
    "fs.readFile",
    "fs.readFileSync",
    "fs.writeFile",
    "fs.writeFileSync",
    "fs.unlink",
    "fs.rmSync",
}

_SSRF_HTTP_SINKS: Set[str] = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.request",
    "http_requests.get",
    "http_requests.post",
    "http_requests.request",
    "httpx.get",
    "httpx.post",
    "axios.get",
    "axios.post",
}

_LOG_INJECTION_SINKS: Set[str] = {
    "logger.info",
    "logger.warning",
    "logger.error",
    "logger.critical",
    "logging.info",
    "logging.warning",
    "logging.error",
}

_REDIRECT_SINKS: Set[str] = {
    "RedirectResponse",
    "redirect",
    "flask.redirect",
    "res.redirect",
    "NextResponse.redirect",
}


def _sanitize_log_text(value: Any) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").replace("\x00", "").strip()[:300]


def _norm_filepath(filepath: Optional[str]) -> str:
    return (filepath or "").replace("\\", "/").lstrip("/").strip()


def _filepath_matches(node_fp: str, query_fp: str) -> bool:
    n_fp = _norm_filepath(node_fp)
    q_fp = _norm_filepath(query_fp)
    if not q_fp:
        return True
    if not n_fp:
        return False
    return n_fp == q_fp or n_fp.endswith("/" + q_fp) or q_fp.endswith("/" + n_fp) or n_fp.endswith(q_fp)


def _node_to_reactflow_dict(node: CPGNode) -> Dict[str, Any]:
    return {
        "id": node.id,
        "label": node.label,
        "name": node.name,
        "filepath": node.filepath,
        "start_line": node.start_line,
        "end_line": node.end_line,
        "start_col": node.start_col,
        "end_col": node.end_col,
        "scope_id": node.scope_id,
        "ast_type": node.ast_type,
        "code": node.code,
        "is_source": node.is_source,
        "is_sink": node.is_sink,
        "is_sanitizer": node.is_sanitizer,
        "sanitizer_domains": list(node.sanitizer_domains),
        "sink_domain": node.sink_domain,
        "language": node.language,
    }


def _normalize_raw_node_dict(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(raw.get("id") or ""),
        "label": str(raw.get("label") or "Call"),
        "name": str(raw.get("name") or raw.get("ast_type") or "node"),
        "filepath": str(raw.get("filepath") or ""),
        "start_line": int(raw.get("start_line") or 1),
        "end_line": int(raw.get("end_line") or raw.get("start_line") or 1),
        "start_col": int(raw.get("start_col") or 0),
        "end_col": int(raw.get("end_col") or 0),
        "scope_id": str(raw.get("scope_id") or "global"),
        "ast_type": str(raw.get("ast_type") or "statement"),
        "code": str(raw.get("code") or raw.get("name") or ""),
        "is_source": bool(raw.get("is_source", False)),
        "is_sink": bool(raw.get("is_sink", False)),
        "is_sanitizer": bool(raw.get("is_sanitizer", False)),
        "language": str(raw.get("language") or "python"),
    }


def _edge_to_reactflow_dict(edge: CPGEdge) -> Dict[str, Any]:
    return {
        "id": edge.id,
        "source": edge.source_id,
        "target": edge.target_id,
        "type": edge.edge_type,
        "var_name": edge.var_name,
    }


def _best_effort_chmod(path: str, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _build_app_tree_spider(app_tree: AppTreeSummary) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}

    def _walk(dir_node: DirectoryTreeNode, parent_dir_id: Optional[str]) -> None:
        if len(nodes) >= _MAX_VIEW_NODES:
            return
        d_path = dir_node.path or "root"
        dir_id = f"dir:{d_path}"
        nodes[dir_id] = {
            "id": dir_id,
            "label": "Directory",
            "name": dir_node.name or "root",
            "filepath": d_path,
            "start_line": 1,
            "end_line": 1,
            "ast_type": "app_directory",
            "code": dir_node.purpose or f"Directory: {dir_node.name}",
            "is_source": False,
            "is_sink": False,
            "is_sanitizer": False,
        }
        if parent_dir_id and len(edges) < _MAX_VIEW_EDGES:
            eid = f"contains:{parent_dir_id}->{dir_id}"
            edges[eid] = {"id": eid, "source": parent_dir_id, "target": dir_id, "type": "CONTAINS", "var_name": None}

        for f in dir_node.files:
            if len(nodes) >= _MAX_VIEW_NODES:
                break
            fid = f"file:{f.filepath}"
            nodes[fid] = {
                "id": fid,
                "label": "File",
                "name": f.filename,
                "filepath": f.filepath,
                "start_line": 1,
                "end_line": max(1, f.line_count),
                "ast_type": "app_file",
                "code": f.purpose or f.filepath,
                "language": f.language,
                "is_source": False,
                "is_sink": False,
                "is_sanitizer": False,
            }
            if len(edges) < _MAX_VIEW_EDGES:
                eid = f"contains:{dir_id}->{fid}"
                edges[eid] = {"id": eid, "source": dir_id, "target": fid, "type": "CONTAINS", "var_name": None}

        for sub in dir_node.subdirectories:
            _walk(sub, dir_id)

    _walk(app_tree.tree, None)

    for ce in app_tree.cross_file_edges or []:
        if len(edges) >= _MAX_VIEW_EDGES:
            break
        src_id = f"file:{ce.source_filepath}"
        tgt_id = f"file:{ce.target_filepath}"
        if src_id in nodes and tgt_id in nodes:
            eid = f"xfile:{ce.source_filepath}->{ce.target_filepath}"
            edges[eid] = {
                "id": eid,
                "source": src_id,
                "target": tgt_id,
                "type": ce.edge_type or "IMPORTS",
                "var_name": ", ".join(ce.symbols[:3]) if ce.symbols else None,
            }

    return {"view_mode": "SPIDER", "nodes": list(nodes.values()), "edges": list(edges.values())}


# ---------------------------------------------------------------------------
# EmbeddedGraphStore — Pure-Python SQLite WAL CPG Engine
# ---------------------------------------------------------------------------


class EmbeddedGraphStore:
    """
    Pure-Python SQLite WAL-backed Code Property Graph store with lazy in-memory adjacency
    hydration and 100%-parity native Python rule evaluation across RULE-1..RULE-16 + Polyglot RULE-22..RULE-33.
    """

    mode: GraphEngineMode = "EMBEDDED_SQLITE"

    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._loaded: bool = False

        self._nodes: Dict[str, CPGNode] = {}
        self._edges: Dict[str, CPGEdge] = {}
        self._out_edges: Dict[str, List[CPGEdge]] = defaultdict(list)
        self._in_edges: Dict[str, List[CPGEdge]] = defaultdict(list)
        self._nodes_by_file: Dict[str, List[CPGNode]] = defaultdict(list)
        self._nodes_by_label: Dict[str, List[CPGNode]] = defaultdict(list)
        self._app_tree: Optional[AppTreeSummary] = None

        self._open_connection()
        self.init_schema()

    def _open_connection(self) -> None:
        with self._lock:
            parent_dir = os.path.dirname(self.db_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
                _best_effort_chmod(parent_dir, 0o700)
            if self._conn is None:
                self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._conn.execute("PRAGMA journal_mode=WAL;")
                self._conn.execute("PRAGMA synchronous=NORMAL;")
                self._conn.execute("PRAGMA foreign_keys=OFF;")
                _best_effort_chmod(self.db_path, 0o600)

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._open_connection()
        assert self._conn is not None
        return self._conn

    def is_ready(self) -> bool:
        with self._lock:
            try:
                conn = self._get_conn()
                conn.execute("SELECT 1").fetchone()
                return True
            except sqlite3.Error:
                return False

    def init_schema(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cpg_nodes (
                    id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    ast_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    code TEXT NOT NULL,
                    filepath TEXT NOT NULL,
                    start_line INTEGER NOT NULL,
                    end_line INTEGER NOT NULL,
                    start_col INTEGER NOT NULL,
                    end_col INTEGER NOT NULL,
                    scope_id TEXT NOT NULL,
                    is_source INTEGER NOT NULL DEFAULT 0,
                    is_sink INTEGER NOT NULL DEFAULT 0,
                    is_sanitizer INTEGER NOT NULL DEFAULT 0,
                    sanitizer_domains_json TEXT NOT NULL DEFAULT '[]',
                    sink_domain TEXT,
                    language TEXT NOT NULL DEFAULT 'python'
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_nodes_filepath ON cpg_nodes (filepath)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_nodes_label ON cpg_nodes (label)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_nodes_source ON cpg_nodes (is_source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_nodes_sink ON cpg_nodes (is_sink)")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cpg_edges (
                    id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    edge_type TEXT NOT NULL,
                    var_name TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_edges_source ON cpg_edges (source_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_edges_target ON cpg_edges (target_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_edges_type ON cpg_edges (edge_type)")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS app_tree_json (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS communities_json (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS meta_kv (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL
                )
                """
            )
            conn.commit()
            _best_effort_chmod(self.db_path, 0o600)

    def _reset_memory_indices(self) -> None:
        self._nodes.clear()
        self._edges.clear()
        self._out_edges.clear()
        self._in_edges.clear()
        self._nodes_by_file.clear()
        self._nodes_by_label.clear()

    def _rebuild_memory_indices(self) -> None:
        self._out_edges.clear()
        self._in_edges.clear()
        self._nodes_by_file.clear()
        self._nodes_by_label.clear()
        for node in self._nodes.values():
            self._nodes_by_file[node.filepath].append(node)
            self._nodes_by_label[node.label].append(node)
        for edge in self._edges.values():
            self._out_edges[edge.source_id].append(edge)
            self._in_edges[edge.target_id].append(edge)

    def _ensure_loaded(self) -> None:
        with self._lock:
            if self._loaded:
                return
            conn = self._get_conn()
            self._reset_memory_indices()

            node_rows = conn.execute(
                """
                SELECT id, label, ast_type, name, code, filepath,
                       start_line, end_line, start_col, end_col, scope_id,
                       is_source, is_sink, is_sanitizer,
                       sanitizer_domains_json, sink_domain, language
                FROM cpg_nodes
                """
            ).fetchall()
            for r in node_rows:
                try:
                    san_domains = json.loads(r["sanitizer_domains_json"] or "[]")
                    if not isinstance(san_domains, list):
                        san_domains = []
                except (ValueError, TypeError):
                    san_domains = []
                node = CPGNode(
                    id=r["id"],
                    label=r["label"],
                    ast_type=r["ast_type"],
                    name=r["name"],
                    code=r["code"],
                    filepath=r["filepath"],
                    start_line=int(r["start_line"]),
                    end_line=int(r["end_line"]),
                    start_col=int(r["start_col"]),
                    end_col=int(r["end_col"]),
                    scope_id=r["scope_id"],
                    is_source=bool(r["is_source"]),
                    is_sink=bool(r["is_sink"]),
                    is_sanitizer=bool(r["is_sanitizer"]),
                    sanitizer_domains=[str(d) for d in san_domains],
                    sink_domain=r["sink_domain"],
                    language=r["language"] or "python",
                )
                self._nodes[node.id] = node

            edge_rows = conn.execute(
                "SELECT id, source_id, target_id, edge_type, var_name FROM cpg_edges"
            ).fetchall()
            for r in edge_rows:
                edge = CPGEdge(
                    id=r["id"],
                    source_id=r["source_id"],
                    target_id=r["target_id"],
                    edge_type=r["edge_type"],
                    var_name=r["var_name"],
                )
                self._edges[edge.id] = edge

            self._rebuild_memory_indices()
            self._loaded = True

    def clear_database(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute("DELETE FROM cpg_edges")
            conn.execute("DELETE FROM cpg_nodes")
            conn.execute("DELETE FROM app_tree_json")
            conn.execute("DELETE FROM communities_json")
            conn.execute("DELETE FROM meta_kv")
            conn.commit()
            self._reset_memory_indices()
            self._app_tree = None
            self._loaded = True

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None

    def ingest_cpg(
        self,
        nodes: List[CPGNode],
        edges: List[CPGEdge],
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Tuple[int, int]:
        with self._lock:
            self._ensure_loaded()
            conn = self._get_conn()

            unique_nodes = list({n.id: n for n in nodes}.values())
            total_nodes = len(unique_nodes)
            node_tuples = [
                (
                    n.id,
                    n.label,
                    n.ast_type,
                    n.name,
                    n.code,
                    n.filepath,
                    int(n.start_line),
                    int(n.end_line),
                    int(n.start_col),
                    int(n.end_col),
                    n.scope_id,
                    1 if n.is_source else 0,
                    1 if n.is_sink else 0,
                    1 if n.is_sanitizer else 0,
                    json.dumps(list(n.sanitizer_domains)),
                    n.sink_domain,
                    n.language or "python",
                )
                for n in unique_nodes
            ]

            for i in range(0, total_nodes, _SQLITE_BATCH_SIZE):
                batch = node_tuples[i:i + _SQLITE_BATCH_SIZE]
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO cpg_nodes (
                        id, label, ast_type, name, code, filepath,
                        start_line, end_line, start_col, end_col, scope_id,
                        is_source, is_sink, is_sanitizer,
                        sanitizer_domains_json, sink_domain, language
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    batch,
                )
                if progress_callback:
                    progress_callback(
                        "Ingesting CPG nodes into embedded SQLite...",
                        min(i + _SQLITE_BATCH_SIZE, total_nodes),
                        total_nodes,
                    )

            for n in unique_nodes:
                self._nodes[n.id] = n

            unique_edges = [
                e for e in {e.id: e for e in edges}.values()
                if e.source_id in self._nodes and e.target_id in self._nodes
            ]
            total_edges = len(unique_edges)
            edge_tuples = [
                (e.id, e.source_id, e.target_id, e.edge_type, e.var_name)
                for e in unique_edges
            ]

            for i in range(0, total_edges, _SQLITE_BATCH_SIZE):
                batch = edge_tuples[i:i + _SQLITE_BATCH_SIZE]
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO cpg_edges (
                        id, source_id, target_id, edge_type, var_name
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    batch,
                )
                if progress_callback:
                    progress_callback(
                        "Ingesting CPG edges into embedded SQLite...",
                        min(i + _SQLITE_BATCH_SIZE, total_edges),
                        total_edges,
                    )

            conn.commit()
            for e in unique_edges:
                self._edges[e.id] = e
            self._rebuild_memory_indices()
            self._loaded = True
            return total_nodes, total_edges

    def ingest_app_tree(self, summary: AppTreeSummary) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT OR REPLACE INTO app_tree_json (id, payload) VALUES (1, ?)",
                (summary.model_dump_json(),),
            )
            conn.commit()
            self._app_tree = summary

    def get_app_tree(self) -> Optional[AppTreeSummary]:
        with self._lock:
            if self._app_tree is not None:
                return self._app_tree
            conn = self._get_conn()
            row = conn.execute("SELECT payload FROM app_tree_json WHERE id = 1").fetchone()
            if row and row["payload"]:
                try:
                    self._app_tree = AppTreeSummary.model_validate_json(row["payload"])
                    return self._app_tree
                except Exception as exc:
                    logger.warning("Failed to deserialize persisted app_tree: %s", _sanitize_log_text(exc))
            return None

    def get_counts(self) -> Dict[str, int]:
        with self._lock:
            conn = self._get_conn()
            n_row = conn.execute("SELECT COUNT(*) AS c FROM cpg_nodes").fetchone()
            e_row = conn.execute("SELECT COUNT(*) AS c FROM cpg_edges").fetchone()
            return {
                "nodes": int(n_row["c"]) if n_row else 0,
                "edges": int(e_row["c"]) if e_row else 0,
            }

    def save_communities(self, community_map: CommunityMapResponse) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT OR REPLACE INTO communities_json (id, payload) VALUES (1, ?)",
                (community_map.model_dump_json(),),
            )
            conn.commit()

    def get_communities(self) -> CommunityMapResponse:
        with self._lock:
            conn = self._get_conn()
            row = conn.execute("SELECT payload FROM communities_json WHERE id = 1").fetchone()
            if row and row["payload"]:
                try:
                    return CommunityMapResponse.model_validate_json(row["payload"])
                except Exception as exc:
                    logger.warning("Failed to deserialize persisted communities: %s", _sanitize_log_text(exc))
            return CommunityMapResponse(graph_engine_mode=self.mode)

    def save_meta(self, key: str, value: Any) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT OR REPLACE INTO meta_kv (key, value_json) VALUES (?, ?)",
                (str(key), json.dumps(value)),
            )
            conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        with self._lock:
            conn = self._get_conn()
            row = conn.execute("SELECT value_json FROM meta_kv WHERE key = ?", (str(key),)).fetchone()
            if row is None:
                return default
            try:
                return json.loads(row["value_json"])
            except (ValueError, TypeError):
                return default

    # -----------------------------------------------------------------------
    # Graph Traversal Helpers for Native Python Rule Parity
    # -----------------------------------------------------------------------

    def _has_upstream_dfg_sanitizer(self, target_id: str, max_hops: int, sink_domain: Optional[str] = None) -> bool:
        visited: Set[str] = {target_id}
        queue: deque[Tuple[str, int]] = deque([(target_id, 0)])
        while queue:
            curr_id, depth = queue.popleft()
            if depth >= max_hops:
                continue
            for edge in self._in_edges.get(curr_id, ()):
                if edge.edge_type != "DFG_FLOWS_TO":
                    continue
                src = self._nodes.get(edge.source_id)
                if src is None or src.id in visited:
                    continue
                if src.is_sanitizer and is_sanitizer_compatible_for_sink(src.sanitizer_domains, sink_domain):
                    return True
                visited.add(src.id)
                queue.append((src.id, depth + 1))
        return False

    def _ast_descendants(self, start_id: str, max_depth: int) -> List[CPGNode]:
        found: List[CPGNode] = []
        visited: Set[str] = {start_id}
        queue: deque[Tuple[str, int]] = deque([(start_id, 0)])
        while queue:
            curr_id, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self._out_edges.get(curr_id, ()):
                if edge.edge_type != "AST_CHILD":
                    continue
                nxt = self._nodes.get(edge.target_id)
                if nxt is None or nxt.id in visited:
                    continue
                visited.add(nxt.id)
                found.append(nxt)
                queue.append((nxt.id, depth + 1))
        return found

    def _shortest_dfg_paths_for_domain(
        self,
        sources: Sequence[CPGNode],
        target_ids: Set[str],
        sink_domain: Optional[str],
        max_depth: int,
    ) -> List[Tuple[List[CPGNode], List[CPGEdge]]]:
        """
        Finds the shortest unsanitized `DFG_FLOWS_TO` path (1..max_depth) from each source to each
        reachable target in `target_ids` under domain-aware sanitizer filtering for `sink_domain`.
        """
        if not sources or not target_ids:
            return []

        results: List[Tuple[List[CPGNode], List[CPGEdge]]] = []
        for src in sources:
            if src.is_sanitizer and is_sanitizer_compatible_for_sink(src.sanitizer_domains, sink_domain):
                continue
            parent: Dict[str, Tuple[str, CPGEdge]] = {}
            visited: Set[str] = {src.id}
            queue: deque[Tuple[str, int]] = deque([(src.id, 0)])

            while queue:
                curr_id, depth = queue.popleft()
                if depth >= max_depth:
                    continue
                for edge in self._out_edges.get(curr_id, ()):
                    if edge.edge_type != "DFG_FLOWS_TO":
                        continue
                    nxt = self._nodes.get(edge.target_id)
                    if nxt is None or nxt.id in visited:
                        continue
                    if nxt.is_sanitizer and is_sanitizer_compatible_for_sink(nxt.sanitizer_domains, sink_domain):
                        continue
                    visited.add(nxt.id)
                    parent[nxt.id] = (curr_id, edge)
                    if nxt.id in target_ids:
                        p_nodes: List[CPGNode] = [nxt]
                        p_edges: List[CPGEdge] = []
                        walk_id = nxt.id
                        while walk_id != src.id:
                            prev_id, p_edge = parent[walk_id]
                            p_edges.append(p_edge)
                            p_nodes.append(self._nodes[prev_id])
                            walk_id = prev_id
                        p_nodes.reverse()
                        p_edges.reverse()
                        results.append((p_nodes, p_edges))
                    queue.append((nxt.id, depth + 1))
        return results

    def _emit_finding(
        self,
        rule_id: str,
        severity: str,
        title: str,
        path_nodes: Sequence[CPGNode],
        path_edges: Sequence[CPGEdge],
        seen_keys: Set[Tuple[str, str]],
        out_findings: List[Finding],
    ) -> None:
        rule = _RULES_BY_ID[rule_id]
        built = build_cpg_finding_from_rule(
            rule=rule,
            severity=severity,
            title=title,
            raw_nodes=[n.model_dump() for n in path_nodes],
            raw_edges=[_edge_to_reactflow_dict(e) for e in path_edges],
        )
        if built is None:
            return
        finding, dedup_key = built
        if dedup_key in seen_keys:
            return
        seen_keys.add(dedup_key)
        out_findings.append(finding)

    # -----------------------------------------------------------------------
    # Native Python Parity Evaluators for RULE-1 .. RULE-16
    # -----------------------------------------------------------------------

    def _eval_rule_1_taint(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        sources = [n for n in self._nodes.values() if n.is_source]
        sinks_by_domain: Dict[Optional[str], Set[str]] = defaultdict(set)
        for n in self._nodes.values():
            if n.is_sink:
                sinks_by_domain[n.sink_domain].add(n.id)

        all_paths: List[Tuple[List[CPGNode], List[CPGEdge]]] = []
        for domain, sink_ids in sinks_by_domain.items():
            all_paths.extend(
                self._shortest_dfg_paths_for_domain(sources, sink_ids, domain, max_depth=15)
            )
        all_paths.sort(key=lambda pair: (len(pair[0]), pair[0][0].id, pair[0][-1].id))
        for p_nodes, p_edges in all_paths[:100]:
            self._emit_finding(
                "RULE-1-TAINT",
                "CRITICAL",
                "Taint Vulnerability: Untrusted Input Flows to Sensitive Sink",
                p_nodes,
                p_edges,
                seen,
                out,
            )

    def _eval_rule_2_orphan(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        auth_guards = {"getSession", "sendCode", "verifySession", "verifyToken", "authenticate"}
        skip_names = {"main", "__init__", "__call__", "anonymous_func"}
        count = 0
        for f in self._nodes_by_label.get("Function", ()):
            if count >= 150:
                break
            if any(e.edge_type == "CALLS" for e in self._in_edges.get(f.id, ())):
                continue
            if f.name in skip_names or f.name.startswith("test_") or f.name.startswith("_decommissioned_"):
                continue
            if f.filepath.startswith("scratch/") or f.filepath.endswith(".tsx"):
                continue
            if f.code.startswith("export ") or "@app." in f.code or "@router." in f.code:
                continue

            low_name = f.name.lower()
            flagged = (
                f.name in auth_guards
                or any(k in low_name for k in ("debug", "shell", "gadget", "backdoor"))
                or any(k in f.code for k in ("subprocess", "os.system", "shell=True"))
                or any(desc.is_sink for desc in self._ast_descendants(f.id, 8))
            )
            if not flagged:
                continue
            if f.name in auth_guards:
                title = f"Bypassed / Orphaned Security Control (Uncalled Auth Guard): {f.name}()"
            else:
                title = f"Dormant Zero-Day Gadget / Uncalled Open Function: {f.name}"
            self._emit_finding("RULE-2-ORPHAN", "HIGH", title, [f], [], seen, out)
            count += 1

    def _eval_rule_3_deadstore(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        vars_by_file_name: Dict[Tuple[str, str], List[CPGNode]] = defaultdict(list)
        for v in self._nodes_by_label.get("Variable", ()):
            vars_by_file_name[(v.filepath, v.name)].append(v)

        skip_ast_types = {"pattern_list", "tuple_pattern", "object_pattern", "array_pattern"}
        count = 0
        for edge in self._edges.values():
            if count >= 150:
                break
            if edge.edge_type != "DFG_FLOWS_TO":
                continue
            src = self._nodes.get(edge.source_id)
            tgt = self._nodes.get(edge.target_id)
            if src is None or tgt is None or src.label != "Call" or tgt.label != "Variable":
                continue
            if any(e.edge_type == "DFG_FLOWS_TO" for e in self._out_edges.get(tgt.id, ())):
                continue
            if tgt.name.startswith("_") or len(tgt.name) <= 2:
                continue
            if any(ch in tgt.name for ch in (".", "[", ",", "{")):
                continue
            if tgt.ast_type in skip_ast_types or src.name in ("Field", "create"):
                continue

            has_other_ref = False
            for other in vars_by_file_name.get((tgt.filepath, tgt.name), ()):
                if other.id == tgt.id:
                    continue
                if other.start_line >= tgt.start_line:
                    has_other_ref = True
                    break
                if other.scope_id == tgt.scope_id:
                    fed_by_call = any(
                        e.edge_type == "DFG_FLOWS_TO"
                        and (self._nodes.get(e.source_id) is not None and self._nodes[e.source_id].label == "Call")
                        for e in self._in_edges.get(other.id, ())
                    )
                    if not fed_by_call:
                        has_other_ref = True
                        break
            if has_other_ref:
                continue

            self._emit_finding(
                "RULE-3-DEADSTORE",
                "MEDIUM",
                f"Dead Store / Unused Data Element: {tgt.name}",
                [src, tgt],
                [edge],
                seen,
                out,
            )
            count += 1

    def _eval_rule_4_infinite_loop(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        count = 0
        for loop in self._nodes_by_label.get("LoopBlock", ()):
            if count >= 150:
                break
            code = loop.code or ""
            is_unbounded = (
                code.startswith("while True")
                or code.startswith("while(true)")
                or code.startswith("while (true)")
                or code.startswith("while 1")
                or "for(;;)" in code
                or "for (;;)" in code
            )
            if not is_unbounded:
                continue
            if any(e.edge_type == "CFG_FALSE" for e in self._out_edges.get(loop.id, ())):
                continue

            parent: Dict[str, Tuple[str, CPGEdge]] = {}
            visited: Set[str] = {loop.id}
            queue: deque[Tuple[str, int]] = deque([(loop.id, 0)])
            has_escape = False
            back_tail: Optional[Tuple[CPGNode, CPGEdge]] = None

            while queue:
                curr_id, depth = queue.popleft()
                if depth > 0:
                    curr_node = self._nodes[curr_id]
                    if curr_node.label == "Return":
                        has_escape = True
                        break
                    for oe in self._out_edges.get(curr_id, ()):
                        if oe.edge_type == "CFG_BREAK":
                            has_escape = True
                            break
                        if oe.edge_type == "CFG_LOOP_BACK" and oe.target_id == loop.id and back_tail is None:
                            back_tail = (curr_node, oe)
                    if has_escape:
                        break
                if depth >= 15:
                    continue
                for oe in self._out_edges.get(curr_id, ()):
                    if oe.edge_type not in ("CFG_TRUE", "CFG_NEXT"):
                        continue
                    if oe.target_id not in self._nodes or oe.target_id in visited:
                        continue
                    visited.add(oe.target_id)
                    parent[oe.target_id] = (curr_id, oe)
                    queue.append((oe.target_id, depth + 1))

            if has_escape or back_tail is None:
                continue

            tail_node, back_edge = back_tail
            cycle_nodes: List[CPGNode] = [tail_node]
            cycle_edges: List[CPGEdge] = []
            walk_id = tail_node.id
            while walk_id != loop.id:
                prev_id, p_edge = parent[walk_id]
                cycle_edges.append(p_edge)
                cycle_nodes.append(self._nodes[prev_id])
                walk_id = prev_id
            cycle_nodes.reverse()
            cycle_edges.reverse()
            cycle_edges.append(back_edge)

            self._emit_finding(
                "RULE-4-INFINITE-LOOP",
                "HIGH",
                "Logical Flaw: Non-Terminating Infinite Loop",
                cycle_nodes,
                cycle_edges,
                seen,
                out,
            )
            count += 1

    def _eval_rule_5_unreachable(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        stmt_labels = {"Assignment", "Call", "ControlBlock", "LoopBlock", "Return"}
        count = 0
        for fn in self._nodes_by_label.get("Function", ()):
            if count >= 150:
                break
            blocks = [
                n for n in self._ast_descendants(fn.id, 3)
                if n.ast_type in ("block", "statement_block")
            ]
            for blk in blocks:
                returns = [
                    self._nodes[e.target_id]
                    for e in self._out_edges.get(blk.id, ())
                    if e.edge_type == "AST_CHILD"
                    and e.target_id in self._nodes
                    and self._nodes[e.target_id].label == "Return"
                    and self._nodes[e.target_id].scope_id == fn.id
                ]
                if not returns:
                    continue
                stmts = [
                    s for s in self._ast_descendants(blk.id, 2)
                    if s.scope_id == fn.id and s.label in stmt_labels
                ]
                for ret in returns:
                    ret_desc_ids = {d.id for d in self._ast_descendants(ret.id, 5)}
                    for stmt in stmts:
                        if count >= 150:
                            break
                        if stmt.id == ret.id or stmt.id in ret_desc_ids:
                            continue
                        if not (
                            stmt.start_line > ret.end_line
                            or (stmt.start_line == ret.end_line and stmt.start_col > ret.end_col)
                        ):
                            continue
                        if any(e.edge_type in _CFG_EDGE_TYPES for e in self._in_edges.get(stmt.id, ())):
                            continue
                        self._emit_finding(
                            "RULE-5-UNREACHABLE",
                            "MEDIUM",
                            "Logical Flaw: Unreachable Dead Code Block",
                            [stmt, fn],
                            [],
                            seen,
                            out,
                        )
                        count += 1

    def _eval_rule_6_proc_exec(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        subproc_names = {"Popen", "run", "call", "check_output"}
        for c in self._nodes_by_label.get("Call", ()):
            is_py_shell = "shell=True" in c.code and ("subprocess" in c.name or c.name in subproc_names)
            is_node_exec = c.name in ("cp.exec", "child_process.exec")
            if is_py_shell or is_node_exec:
                sev = "MEDIUM" if is_node_exec else "CRITICAL"
                self._emit_finding("RULE-6-SHELL-INJECTION", sev, f"Unsafe Shell Execution: {c.name}", [c], [], seen, out)

    def _eval_rule_7_sqli_format(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        for c in self._nodes_by_label.get("Call", ()):
            if not (c.name.endswith(".execute") or "cursor.execute" in c.code):
                continue
            code = c.code
            is_interp = (
                'f"SELECT' in code
                or "f'SELECT" in code
                or 'f"INSERT' in code
                or 'f"UPDATE' in code
                or 'f"DELETE' in code
                or ("SELECT " in code and (".format(" in code or " + " in code or " % " in code))
            )
            if not is_interp:
                continue
            if self._has_upstream_dfg_sanitizer(c.id, 5, sink_domain="SQL"):
                continue
            self._emit_finding(
                "RULE-7-SQLI-FORMAT",
                "HIGH",
                f"Unparameterized SQL String Interpolation in {c.name}",
                [c],
                [],
                seen,
                out,
            )

    def _eval_rule_8_hardcoded_secret(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        for a in self._nodes_by_label.get("Assignment", ()):
            low_name = a.name.lower()
            if not any(tok in low_name for tok in ("password", "secret", "api_key")):
                continue
            code = a.code
            if '"' not in code and "'" not in code:
                continue
            if any(ex in code for ex in ("===", "!==", "==", "os.getenv(", "os.environ.get(", "process.env.")):
                continue
            if code.endswith('""') or code.endswith("''"):
                continue
            self._emit_finding(
                "RULE-8-HARDCODED-SECRET",
                "HIGH",
                f"Hardcoded Secret / Fallback Credential in {a.name}",
                [a],
                [],
                seen,
                out,
            )

        for c in self._nodes_by_label.get("Call", ()):
            code = c.code
            is_driver = (
                (c.name.endswith("GraphDatabase.driver") and "auth=(" in code and ('"' in code or "'" in code))
                or (c.name in ("psycopg2.connect", "mysql.connector.connect") and ('password="' in code or "password='" in code))
                or (c.name in ("jwt.encode", "jose.jwt.encode") and (', "' in code or ", '" in code))
            )
            if is_driver:
                self._emit_finding(
                    "RULE-8-HARDCODED-SECRET",
                    "MEDIUM",
                    f"Hardcoded SDK / Database Driver Credential in {c.name}",
                    [c],
                    [],
                    seen,
                    out,
                )

    def _eval_rule_9_dom_xss(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        for sink in self._nodes.values():
            is_doc_write = sink.label == "Call" and sink.name in ("document.write", "document.writeln")
            is_inner_html = (
                sink.label == "Assignment"
                and sink.is_sink
                and (
                    sink.name.endswith(".innerHTML")
                    or sink.name.endswith(".outerHTML")
                    or sink.name == "dangerouslySetInnerHTML"
                )
            )
            is_set_src = (
                sink.label == "Call"
                and sink.name.endswith(".setAttribute")
                and ('("src",' in sink.code or "('src'," in sink.code)
                and '("src","' not in sink.code
                and "('src','" not in sink.code
            )
            if not (is_doc_write or is_inner_html or is_set_src):
                continue

            if is_doc_write:
                title = f"DOM-Based XSS / Dynamic Script Sink: {sink.name}()"
            elif is_set_src:
                title = f'Dynamic Script Source Injection via {sink.name}("src", ...)'
            elif 'href="${esc(' in sink.code:
                title = f"DOM XSS via Unvalidated URL Scheme in <a href> (esc() Bypass): {sink.name}"
            else:
                title = f"Unsanitized DOM HTML Sink: {sink.name}"

            use_node: Optional[CPGNode] = None
            r2: Optional[CPGEdge] = None
            for e in self._in_edges.get(sink.id, ()):
                if e.edge_type == "DFG_FLOWS_TO" and e.source_id in self._nodes:
                    use_node = self._nodes[e.source_id]
                    r2 = e
                    break

            def_node: Optional[CPGNode] = None
            r1: Optional[CPGEdge] = None
            if use_node is not None:
                for e in self._in_edges.get(use_node.id, ()):
                    if e.edge_type == "DFG_FLOWS_TO" and e.source_id in self._nodes:
                        cand = self._nodes[e.source_id]
                        if cand.id != use_node.id and cand.id != sink.id:
                            def_node = cand
                            r1 = e
                            break

            if def_node is not None and use_node is not None and r1 is not None and r2 is not None:
                p_nodes, p_edges = [def_node, use_node, sink], [r1, r2]
            elif use_node is not None and r2 is not None:
                p_nodes, p_edges = [use_node, sink], [r2]
            else:
                p_nodes, p_edges = [sink], []

            self._emit_finding("RULE-9-DOM-XSS", "HIGH", title, p_nodes, p_edges, seen, out)

    def _eval_rule_10_path_traversal(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        sources = [n for n in self._nodes.values() if n.is_source]
        sinks = {
            c.id
            for c in self._nodes_by_label.get("Call", ())
            if c.name in _PATH_TRAVERSAL_SINKS
            or c.name.endswith(".readFile")
            or c.name.endswith(".readFileSync")
            or c.name.endswith(".writeFile")
            or c.name.endswith(".writeFileSync")
        }
        paths = self._shortest_dfg_paths_for_domain(sources, sinks, "PATH", max_depth=12)
        paths.sort(key=lambda pair: (len(pair[0]), pair[0][0].id, pair[0][-1].id))
        for p_nodes, p_edges in paths[:100]:
            sink = p_nodes[-1]
            self._emit_finding(
                "RULE-10-PATH-TRAVERSAL",
                "HIGH",
                f"Path Traversal: Untrusted Input Flows to Filesystem Sink {sink.name}()",
                p_nodes,
                p_edges,
                seen,
                out,
            )

    def _eval_rule_11_ssrf_urlopen(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        for u in self._nodes_by_label.get("Call", ()):
            is_urllib = (
                u.name in ("urlopen", "urlretrieve")
                or u.name.endswith(".urlopen")
                or u.name.endswith(".urlretrieve")
            )
            if not is_urllib or u.is_sanitizer:
                continue
            if '("https://' in u.code or "('https://" in u.code:
                continue
            if self._has_upstream_dfg_sanitizer(u.id, 6, sink_domain="URL"):
                continue
            self._emit_finding(
                "RULE-11-SSRF-URLOPEN",
                "MEDIUM",
                f"Dynamic urllib Request (SSRF / file:// Local File Read Risk): {u.name}()",
                [u],
                [],
                seen,
                out,
            )

        sources = [n for n in self._nodes.values() if n.is_source and "sys.argv" not in n.code]
        sinks = {c.id for c in self._nodes_by_label.get("Call", ()) if c.name in _SSRF_HTTP_SINKS}
        paths = self._shortest_dfg_paths_for_domain(sources, sinks, "URL", max_depth=12)
        paths.sort(key=lambda pair: (len(pair[0]), pair[0][0].id, pair[0][-1].id))
        for p_nodes, p_edges in paths:
            sink = p_nodes[-1]
            self._emit_finding(
                "RULE-11-SSRF-URLOPEN",
                "HIGH",
                f"Server-Side Request Forgery (SSRF): Untrusted URL Flows to {sink.name}()",
                p_nodes,
                p_edges,
                seen,
                out,
            )

    def _eval_rule_12_log_injection(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        sources = [n for n in self._nodes.values() if n.is_source and "sys.argv" not in n.code]
        sinks = {
            c.id
            for c in self._nodes_by_label.get("Call", ())
            if c.name in _LOG_INJECTION_SINKS
            and ('f"' in c.code or "f'" in c.code or " + " in c.code)
        }
        paths = self._shortest_dfg_paths_for_domain(sources, sinks, None, max_depth=10)
        paths.sort(key=lambda pair: (len(pair[0]), pair[0][0].id, pair[0][-1].id))
        for p_nodes, p_edges in paths[:100]:
            sink = p_nodes[-1]
            self._emit_finding(
                "RULE-12-LOG-INJECTION",
                "LOW",
                f"Tainted Log Injection (Unsanitized CR/LF Input): {sink.name}()",
                p_nodes,
                p_edges,
                seen,
                out,
            )

    def _eval_rule_13_deser_crypto(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        deser_calls = {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "jsonpickle.decode", "shelve.open"}
        weak_hashes = {"hashlib.md5", "hashlib.sha1", "CryptoJS.MD5", "CryptoJS.SHA1"}
        count = 0
        for c in self._nodes_by_label.get("Call", ()):
            if count >= 100:
                break
            is_deser = c.name in deser_calls or (
                c.name == "yaml.load" and "SafeLoader" not in c.code and "CSafeLoader" not in c.code
            )
            is_weak_hash = c.name in weak_hashes and "usedforsecurity=False" not in c.code
            is_jwt = c.name in ("jwt.decode", "jose.jwt.decode") and "verify_signature" in c.code and "False" in c.code
            if not (is_deser or is_weak_hash or is_jwt):
                continue
            if is_weak_hash:
                sev = "MEDIUM"
                title = f"Weak Cryptographic Digest Without Security Exemption: {c.name}()"
            elif is_jwt:
                sev = "HIGH"
                title = f"Unverified JWT Signature Verification Bypass: {c.name}()"
            else:
                sev = "HIGH"
                title = f"Insecure Deserialization of Untrusted Object Stream: {c.name}()"
            self._emit_finding("RULE-13-UNSAFE-DESERIALIZATION-CRYPTO", sev, title, [c], [], seen, out)
            count += 1

    def _eval_rule_14_code_injection(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        eval_calls = {"eval", "exec", "render_template_string", "vm.runInNewContext", "vm.runInThisContext"}
        count = 0
        for c in self._nodes_by_label.get("Call", ()):
            if count >= 100:
                break
            if not (c.name in eval_calls or c.code.startswith("new Function(")):
                continue
            if c.code.startswith(('eval("', "eval('", 'exec("', "exec('")):
                continue
            if self._has_upstream_dfg_sanitizer(c.id, 5, sink_domain="CODE"):
                continue
            self._emit_finding(
                "RULE-14-CODE-INJECTION",
                "CRITICAL",
                f"Dynamic Code / Template Execution Sink (CWE-94): {c.name}()",
                [c],
                [],
                seen,
                out,
            )
            count += 1

    def _eval_rule_15_xxe_tls(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        count = 0
        for c in self._nodes_by_label.get("Call", ()):
            if count >= 100:
                break
            is_xxe = ("XMLParser" in c.name and "resolve_entities=True" in c.code) or c.name in (
                "xml.dom.minidom.parseString",
                "minidom.parseString",
                "xml.sax.make_parser",
            )
            is_tls = (
                "verify=False" in c.code
                and (
                    c.name.startswith(("requests.", "http_requests.", "httpx."))
                    or c.name.endswith((".get", ".post", ".request"))
                )
            ) or c.name in ("ssl._create_unverified_context", "_create_unverified_context")
            if not (is_xxe or is_tls):
                continue
            if is_tls:
                title = f"Improper TLS Certificate Validation Bypass (CWE-295): {c.name}()"
            else:
                title = f"XML External Entity (XXE) Unsafe Parser Configuration (CWE-611): {c.name}()"
            self._emit_finding("RULE-15-XXE-TLS-BYPASS", "HIGH", title, [c], [], seen, out)
            count += 1

    def _eval_rule_16_prng_redirect(self, seen: Set[Tuple[str, str]], out: List[Finding]) -> None:
        sec_tokens = ("token", "secret", "otp", "nonce", "csrf", "reset_code", "session_key")
        weak_rng = ("random.randint(", "random.choice(", "random.choices(", "random.random(", "Math.random()")
        for a in self._nodes_by_label.get("Assignment", ()):
            low = a.name.lower()
            if not any(tok in low for tok in sec_tokens):
                continue
            if not any(rng in a.code for rng in weak_rng):
                continue
            if "secrets." in a.code or "SystemRandom" in a.code:
                continue
            self._emit_finding(
                "RULE-16-INSECURE-RANDOM-OPEN-REDIRECT",
                "MEDIUM",
                f"Cryptographically Weak PRNG in Security Token Assignment (CWE-330): {a.name}",
                [a],
                [],
                seen,
                out,
            )

        sources = [n for n in self._nodes.values() if n.is_source and "sys.argv" not in n.code]
        sinks = {c.id for c in self._nodes_by_label.get("Call", ()) if c.name in _REDIRECT_SINKS}
        paths = self._shortest_dfg_paths_for_domain(sources, sinks, "URL", max_depth=10)
        paths.sort(key=lambda pair: (len(pair[0]), pair[0][0].id, pair[0][-1].id))
        for p_nodes, p_edges in paths:
            sink = p_nodes[-1]
            self._emit_finding(
                "RULE-16-INSECURE-RANDOM-OPEN-REDIRECT",
                "MEDIUM",
                f"Unvalidated Open Redirect from Untrusted Input (CWE-601): {sink.name}()",
                p_nodes,
                p_edges,
                seen,
                out,
            )

    def run_cpg_rules(
        self,
        scanned_files: Optional[List[ScannedFile]] = None,
        enabled_rule_ids: Optional[Set[str]] = None,
    ) -> List[Finding]:
        """Executes all enabled native Python CPG parity rules (RULE-1..16) plus Polyglot rules (RULE-22..33)."""
        with self._lock:
            self._ensure_loaded()
            seen_keys: Set[Tuple[str, str]] = set()
            findings: List[Finding] = []

            def _is_enabled(rid: str) -> bool:
                return enabled_rule_ids is None or rid in enabled_rule_ids

            if _is_enabled("RULE-1-TAINT"):
                self._eval_rule_1_taint(seen_keys, findings)
            if _is_enabled("RULE-2-ORPHAN"):
                self._eval_rule_2_orphan(seen_keys, findings)
            if _is_enabled("RULE-3-DEADSTORE"):
                self._eval_rule_3_deadstore(seen_keys, findings)
            if _is_enabled("RULE-4-INFINITE-LOOP"):
                self._eval_rule_4_infinite_loop(seen_keys, findings)
            if _is_enabled("RULE-5-UNREACHABLE"):
                self._eval_rule_5_unreachable(seen_keys, findings)
            if _is_enabled("RULE-6-SHELL-INJECTION"):
                self._eval_rule_6_proc_exec(seen_keys, findings)
            if _is_enabled("RULE-7-SQLI-FORMAT"):
                self._eval_rule_7_sqli_format(seen_keys, findings)
            if _is_enabled("RULE-8-HARDCODED-SECRET"):
                self._eval_rule_8_hardcoded_secret(seen_keys, findings)
            if _is_enabled("RULE-9-DOM-XSS"):
                self._eval_rule_9_dom_xss(seen_keys, findings)
            if _is_enabled("RULE-10-PATH-TRAVERSAL"):
                self._eval_rule_10_path_traversal(seen_keys, findings)
            if _is_enabled("RULE-11-SSRF-URLOPEN"):
                self._eval_rule_11_ssrf_urlopen(seen_keys, findings)
            if _is_enabled("RULE-12-LOG-INJECTION"):
                self._eval_rule_12_log_injection(seen_keys, findings)
            if _is_enabled("RULE-13-UNSAFE-DESERIALIZATION-CRYPTO"):
                self._eval_rule_13_deser_crypto(seen_keys, findings)
            if _is_enabled("RULE-14-CODE-INJECTION"):
                self._eval_rule_14_code_injection(seen_keys, findings)
            if _is_enabled("RULE-15-XXE-TLS-BYPASS"):
                self._eval_rule_15_xxe_tls(seen_keys, findings)
            if _is_enabled("RULE-16-INSECURE-RANDOM-OPEN-REDIRECT"):
                self._eval_rule_16_prng_redirect(seen_keys, findings)

            if scanned_files:
                polyglot_hits = run_polyglot_rules(
                    scanned_files=scanned_files,
                    all_nodes=list(self._nodes.values()),
                    all_edges=list(self._edges.values()),
                    enabled_rule_ids=enabled_rule_ids,
                )
                return merge_findings_deduplicated(findings, polyglot_hits)
            return findings

    # -----------------------------------------------------------------------
    # Native ReactFlow Graph View Queries (All 8 Modes)
    # -----------------------------------------------------------------------

    def _collect_subgraph_from_edges(
        self,
        candidate_edges: Iterable[CPGEdge],
        view_mode: str,
        filepath: Optional[str] = None,
        extra_nodes: Optional[Sequence[CPGNode]] = None,
    ) -> Dict[str, Any]:
        all_candidates = list(candidate_edges)
        if filepath:
            scoped = [
                e for e in all_candidates
                if (e.source_id in self._nodes and _filepath_matches(self._nodes[e.source_id].filepath, filepath))
                or (e.target_id in self._nodes and _filepath_matches(self._nodes[e.target_id].filepath, filepath))
            ]
            selected_edges = scoped if scoped else all_candidates
        else:
            selected_edges = all_candidates

        nodes_out: Dict[str, Dict[str, Any]] = {}
        edges_out: List[Dict[str, Any]] = []

        for e in selected_edges:
            if len(edges_out) >= _MAX_VIEW_EDGES:
                break
            s_node = self._nodes.get(e.source_id)
            t_node = self._nodes.get(e.target_id)
            if s_node is None or t_node is None:
                continue
            new_nodes_needed = (0 if s_node.id in nodes_out else 1) + (0 if t_node.id in nodes_out else 1)
            if len(nodes_out) + new_nodes_needed > _MAX_VIEW_NODES:
                continue
            nodes_out[s_node.id] = _node_to_reactflow_dict(s_node)
            nodes_out[t_node.id] = _node_to_reactflow_dict(t_node)
            edges_out.append(_edge_to_reactflow_dict(e))

        if extra_nodes:
            for n in extra_nodes:
                if len(nodes_out) >= _MAX_VIEW_NODES:
                    break
                if n.id not in nodes_out:
                    nodes_out[n.id] = _node_to_reactflow_dict(n)

        return {
            "view_mode": view_mode,
            "nodes": list(nodes_out.values()),
            "edges": edges_out,
        }

    def query_graph_view(
        self,
        view_mode: str,
        finding_id: Optional[str] = None,
        filepath: Optional[str] = None,
        findings: Optional[List[Finding]] = None,
        app_tree: Optional[AppTreeSummary] = None,
    ) -> Dict[str, Any]:
        mode_upper = (view_mode or "FULL_CPG").strip().upper()
        with self._lock:
            self._ensure_loaded()

            if mode_upper == "COMMUNITY_MAP":
                return build_community_graph_view(self.get_communities())

            if mode_upper == "FINDING_PATH":
                target_finding: Optional[Finding] = None
                if findings:
                    if finding_id:
                        target_finding = next((f for f in findings if f.id == finding_id), None)
                    else:
                        target_finding = findings[0]
                if target_finding is None:
                    return {"view_mode": "FINDING_PATH", "nodes": [], "edges": []}

                nodes_out = [_normalize_raw_node_dict(n) for n in (target_finding.path_nodes or [])]
                edges_out = [dict(e) for e in (target_finding.path_edges or [])]
                return {"view_mode": "FINDING_PATH", "nodes": nodes_out, "edges": edges_out}

            if mode_upper in ("ENTRYPOINTS", "ENTRYPOINT_GRAPH"):
                ep_seeds = [
                    n for n in self._nodes.values()
                    if n.is_source
                    or (n.label == "Function" and any(h in (n.code or "") for h in _ROUTE_HINTS))
                ]
                if not ep_seeds:
                    ep_seeds = list(self._nodes_by_label.get("Function", ()))[:25] or list(self._nodes.values())[:25]

                nodes_out: Dict[str, Dict[str, Any]] = {}
                edges_out: Dict[str, Dict[str, Any]] = {}
                queue: deque[Tuple[str, int]] = deque()
                for seed in ep_seeds[:60]:
                    nodes_out[seed.id] = _node_to_reactflow_dict(seed)
                    queue.append((seed.id, 0))

                while queue and len(nodes_out) < _MAX_VIEW_NODES and len(edges_out) < _MAX_VIEW_EDGES:
                    curr_id, depth = queue.popleft()
                    if depth >= 3:
                        continue
                    for oe in self._out_edges.get(curr_id, ()):
                        if oe.edge_type not in ("DFG_FLOWS_TO", "CALLS", "CFG_NEXT"):
                            continue
                        tgt = self._nodes.get(oe.target_id)
                        if tgt is None:
                            continue
                        if tgt.id not in nodes_out and len(nodes_out) < _MAX_VIEW_NODES:
                            nodes_out[tgt.id] = _node_to_reactflow_dict(tgt)
                            queue.append((tgt.id, depth + 1))
                        if tgt.id in nodes_out and oe.id not in edges_out and len(edges_out) < _MAX_VIEW_EDGES:
                            edges_out[oe.id] = _edge_to_reactflow_dict(oe)

                return {"view_mode": mode_upper, "nodes": list(nodes_out.values()), "edges": list(edges_out.values())}

            if mode_upper == "CALL_GRAPH":
                call_edges = [e for e in self._edges.values() if e.edge_type == "CALLS"]
                base = self._collect_subgraph_from_edges(call_edges, "CALL_GRAPH", filepath=filepath)
                nodes_by_id = {n["id"]: n for n in base["nodes"]}
                edges_list = list(base["edges"])
                seen_eids = {e["id"] for e in edges_list}

                # Enrich with enclosing Function nodes for each call site
                for edge_d in list(edges_list):
                    src_id = edge_d["source"]
                    cur = src_id
                    for _ in range(4):
                        parent_ast = next(
                            (ie for ie in self._in_edges.get(cur, ()) if ie.edge_type == "AST_CHILD"),
                            None,
                        )
                        if parent_ast is None:
                            break
                        p_node = self._nodes.get(parent_ast.source_id)
                        if p_node is None:
                            break
                        if p_node.label == "Function":
                            if p_node.id not in nodes_by_id and len(nodes_by_id) < _MAX_VIEW_NODES:
                                nodes_by_id[p_node.id] = _node_to_reactflow_dict(p_node)
                            def_eid = f"def-{p_node.id}-{src_id}"
                            if p_node.id in nodes_by_id and def_eid not in seen_eids and len(edges_list) < _MAX_VIEW_EDGES:
                                seen_eids.add(def_eid)
                                edges_list.append(
                                    {"id": def_eid, "source": p_node.id, "target": src_id, "type": "DEFINES", "var_name": "calls"}
                                )
                            break
                        cur = p_node.id

                return {"view_mode": "CALL_GRAPH", "nodes": list(nodes_by_id.values()), "edges": edges_list}

            if mode_upper in ("DFG", "DFG_ONLY"):
                dfg_edges = [e for e in self._edges.values() if e.edge_type == "DFG_FLOWS_TO"]
                return self._collect_subgraph_from_edges(dfg_edges, mode_upper, filepath=filepath)

            if mode_upper in ("CFG", "CFG_ONLY"):
                cfg_edges = [e for e in self._edges.values() if e.edge_type in _CFG_EDGE_TYPES]
                return self._collect_subgraph_from_edges(cfg_edges, mode_upper, filepath=filepath)

            if mode_upper in ("SPIDER", "APP_TREE"):
                effective_tree = app_tree or self.get_app_tree()
                if effective_tree is not None:
                    return _build_app_tree_spider(effective_tree)
                # Fallback bounded spider over CPG graph
                return self._collect_subgraph_from_edges(
                    self._edges.values(),
                    mode_upper,
                    filepath=filepath,
                    extra_nodes=list(self._nodes.values())[:50],
                )

            # Default: FULL_CPG
            return self._collect_subgraph_from_edges(
                self._edges.values(),
                "FULL_CPG",
                filepath=filepath,
                extra_nodes=list(self._nodes.values())[:50],
            )


# ---------------------------------------------------------------------------
# Neo4jGraphStore — Primary Bolt + APOC Engine Wrapper
# ---------------------------------------------------------------------------


class Neo4jGraphStore:
    """
    Wraps Neo4jClient + BatchIngestor + RuleExecutor as the primary GraphStore engine,
    persisting communities and auxiliary metadata cleanly in the companion `EmbeddedGraphStore`.
    """

    mode: GraphEngineMode = "NEO4J_APOC"

    def __init__(self, neo4j_client: Neo4jClient, embedded_cache: EmbeddedGraphStore):
        self.neo4j_client = neo4j_client
        self.embedded_cache = embedded_cache
        self._last_nodes: List[CPGNode] = []
        self._last_edges: List[CPGEdge] = []

    def is_ready(self) -> bool:
        try:
            return bool(self.neo4j_client.verify_connectivity_and_apoc())
        except Exception:
            return False

    def init_schema(self) -> None:
        self.neo4j_client.init_schema()
        self.embedded_cache.init_schema()

    def clear_database(self) -> None:
        self.neo4j_client.clear_database()
        self.embedded_cache.clear_database()
        self._last_nodes = []
        self._last_edges = []

    def ingest_cpg(
        self,
        nodes: List[CPGNode],
        edges: List[CPGEdge],
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Tuple[int, int]:
        ingestor = BatchIngestor(self.neo4j_client)
        nc, ec = ingestor.ingest(nodes, edges, progress_callback=progress_callback)
        self._last_nodes = list(nodes)
        self._last_edges = list(edges)
        return nc, ec

    def ingest_app_tree(
        self,
        summary: AppTreeSummary,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> None:
        ingestor = BatchIngestor(self.neo4j_client)
        ingestor.ingest_app_tree(summary, progress_callback=progress_callback)
        self.embedded_cache.ingest_app_tree(summary)

    def get_counts(self) -> Dict[str, int]:
        with self.neo4j_client.driver.session() as session:
            n_rec = session.run("MATCH (n:CPGNode) RETURN count(n) AS c").single()
            e_rec = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()
            return {
                "nodes": int(n_rec["c"]) if n_rec else 0,
                "edges": int(e_rec["c"]) if e_rec else 0,
            }

    def save_communities(self, community_map: CommunityMapResponse) -> None:
        self.embedded_cache.save_communities(community_map)

    def get_communities(self) -> CommunityMapResponse:
        cm = self.embedded_cache.get_communities()
        cm.graph_engine_mode = self.mode
        return cm

    def save_meta(self, key: str, value: Any) -> None:
        self.embedded_cache.save_meta(key, value)

    def get_meta(self, key: str, default: Any = None) -> Any:
        return self.embedded_cache.get_meta(key, default)

    def run_cpg_rules(
        self,
        scanned_files: Optional[List[ScannedFile]] = None,
        enabled_rule_ids: Optional[Set[str]] = None,
    ) -> List[Finding]:
        executor = RuleExecutor(self.neo4j_client)
        return executor.execute_all_rules_with_polyglot(
            scanned_files=scanned_files,
            all_nodes=self._last_nodes,
            all_edges=self._last_edges,
            enabled_rule_ids=enabled_rule_ids,
        )

    def query_graph_view(
        self,
        view_mode: str,
        finding_id: Optional[str] = None,
        filepath: Optional[str] = None,
        findings: Optional[List[Finding]] = None,
        app_tree: Optional[AppTreeSummary] = None,
    ) -> Dict[str, Any]:
        mode_upper = (view_mode or "FULL_CPG").strip().upper()
        if mode_upper == "COMMUNITY_MAP":
            return build_community_graph_view(self.get_communities())
        if mode_upper == "FINDING_PATH":
            return self.embedded_cache.query_graph_view(
                view_mode="FINDING_PATH",
                finding_id=finding_id,
                filepath=filepath,
                findings=findings,
                app_tree=app_tree,
            )

        rel_map = {
            "DFG": ":DFG_FLOWS_TO",
            "DFG_ONLY": ":DFG_FLOWS_TO",
            "CFG": ":CFG_NEXT|CFG_TRUE|CFG_FALSE|CFG_LOOP_BACK|CFG_BREAK",
            "CFG_ONLY": ":CFG_NEXT|CFG_TRUE|CFG_FALSE|CFG_LOOP_BACK|CFG_BREAK",
            "CALL_GRAPH": ":CALLS",
        }
        rel_filter = rel_map.get(mode_upper, "")
        params: Dict[str, Any] = {}
        where_stmt = ""
        if filepath:
            params["filepath"] = _norm_filepath(filepath)
            where_stmt = "WHERE (s.filepath ENDS WITH $filepath OR $filepath ENDS WITH s.filepath OR t.filepath ENDS WITH $filepath)"

        cypher = (
            f"MATCH (s:CPGNode)-[r{rel_filter}]->(t:CPGNode) {where_stmt} "
            "WITH s, r, t LIMIT 240 "
            "RETURN collect(DISTINCT properties(s)) + collect(DISTINCT properties(t)) AS all_nodes, "
            "collect(DISTINCT {id: toString(coalesce(r.id, elementId(r))), source: s.id, target: t.id, type: type(r), var_name: r.var_name}) AS all_edges"
        )
        with self.neo4j_client.driver.session() as session:
            rec = session.run(cypher, **params).single()
            raw_nodes = rec["all_nodes"] if rec else []
            raw_edges = rec["all_edges"] if rec else []

        uniq_nodes: Dict[str, Dict[str, Any]] = {}
        for n in raw_nodes or []:
            if isinstance(n, dict) and n.get("id"):
                uniq_nodes[str(n["id"])] = _normalize_raw_node_dict(n)
        uniq_edges: Dict[str, Dict[str, Any]] = {}
        for e in raw_edges or []:
            if isinstance(e, dict) and e.get("id"):
                uniq_edges[str(e["id"])] = dict(e)
        return {"view_mode": mode_upper, "nodes": list(uniq_nodes.values()), "edges": list(uniq_edges.values())}

    def close(self) -> None:
        self.embedded_cache.close()


# ---------------------------------------------------------------------------
# GraphStoreManager — Automatic Dual-Engine Facade
# ---------------------------------------------------------------------------


class GraphStoreManager:
    """
    Singleton-capable facade managing transparent Neo4j -> Embedded SQLite WAL failover.
    Honors `ALASTOR_GRAPH_ENGINE=auto|neo4j|embedded` (defaults to `auto`).
    """

    _instance: Optional["GraphStoreManager"] = None
    _instance_lock = threading.RLock()

    def __init__(self, neo4j_client: Any, vault_dir: str):
        self.neo4j_client = neo4j_client
        self.vault_dir = os.path.abspath(vault_dir)
        os.makedirs(self.vault_dir, exist_ok=True)
        _best_effort_chmod(self.vault_dir, 0o700)

        self._lock = threading.RLock()
        self._db_path = os.path.join(self.vault_dir, "cpg_embedded.db")
        self._embedded_store = EmbeddedGraphStore(self._db_path)
        self._neo4j_store: Optional[Neo4jGraphStore] = None
        self._active_store: Optional[Any] = None

    @classmethod
    def get_instance(
        cls,
        neo4j_client: Any = None,
        vault_dir: Optional[str] = None,
    ) -> "GraphStoreManager":
        with cls._instance_lock:
            if cls._instance is None:
                client = neo4j_client if neo4j_client is not None else Neo4jClient.get_instance()
                if vault_dir is None:
                    platform_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
                    vault_dir = os.path.join(platform_root, ".alastor_vault")
                cls._instance = cls(neo4j_client=client, vault_dir=vault_dir)
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._instance_lock:
            if cls._instance is not None:
                cls._instance.close()
                cls._instance = None

    @property
    def mode(self) -> GraphEngineMode:
        with self._lock:
            if self._active_store is None:
                return self.ensure_backend(force_probe=False)
            return self._active_store.mode

    def ensure_backend(self, force_probe: bool = False) -> GraphEngineMode:
        """
        Selects and activates the appropriate GraphStore backend based on `ALASTOR_GRAPH_ENGINE`:
        - `embedded`: always uses `EmbeddedGraphStore` without probing Neo4j.
        - `neo4j`: requires healthy Neo4j + APOC (raises if unavailable).
        - `auto` (default): probes Neo4j + APOC and seamlessly falls back to `EmbeddedGraphStore` if offline.
        """
        with self._lock:
            pref = os.environ.get("ALASTOR_GRAPH_ENGINE", "auto").strip().lower()

            if pref == "embedded":
                self._active_store = self._embedded_store
                return self._embedded_store.mode

            if pref == "neo4j":
                if self.neo4j_client is None:
                    raise RuntimeError("ALASTOR_GRAPH_ENGINE=neo4j requires a configured Neo4jClient.")
                self.neo4j_client.verify_connectivity_and_apoc()
                if self._neo4j_store is None:
                    self._neo4j_store = Neo4jGraphStore(self.neo4j_client, self._embedded_store)
                self._active_store = self._neo4j_store
                return self._neo4j_store.mode

            # Default: auto
            if self._active_store is not None and not force_probe:
                return self._active_store.mode

            if self.neo4j_client is not None:
                try:
                    if self.neo4j_client.verify_connectivity_and_apoc():
                        if self._neo4j_store is None:
                            self._neo4j_store = Neo4jGraphStore(self.neo4j_client, self._embedded_store)
                        self._active_store = self._neo4j_store
                        logger.info("GraphStoreManager active engine: NEO4J_APOC")
                        return self._neo4j_store.mode
                except Exception as exc:
                    logger.warning(
                        "Neo4j/APOC unavailable (%s); activating Zero-Docker Embedded SQLite CPG fallback.",
                        _sanitize_log_text(exc),
                    )

            self._active_store = self._embedded_store
            logger.info("GraphStoreManager active engine: EMBEDDED_SQLITE (%s)", self._db_path)
            return self._embedded_store.mode

    def _backend(self) -> Any:
        with self._lock:
            if self._active_store is None:
                self.ensure_backend(force_probe=False)
            return self._active_store

    def init_schema(self) -> None:
        self._backend().init_schema()

    def clear_database(self) -> None:
        self._backend().clear_database()

    def ingest_cpg(
        self,
        nodes: List[CPGNode],
        edges: List[CPGEdge],
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Tuple[int, int]:
        return self._backend().ingest_cpg(nodes, edges, progress_callback=progress_callback)

    def ingest_app_tree(self, summary: AppTreeSummary) -> None:
        self._backend().ingest_app_tree(summary)

    def get_counts(self) -> Dict[str, int]:
        return self._backend().get_counts()

    def save_communities(self, community_map: CommunityMapResponse) -> None:
        self._backend().save_communities(community_map)

    def get_communities(self) -> CommunityMapResponse:
        return self._backend().get_communities()

    def save_meta(self, key: str, value: Any) -> None:
        self._backend().save_meta(key, value)

    def get_meta(self, key: str, default: Any = None) -> Any:
        return self._backend().get_meta(key, default)

    def run_cpg_rules(
        self,
        scanned_files: Optional[List[ScannedFile]] = None,
        enabled_rule_ids: Optional[Set[str]] = None,
    ) -> List[Finding]:
        return self._backend().run_cpg_rules(scanned_files=scanned_files, enabled_rule_ids=enabled_rule_ids)

    def query_graph_view(
        self,
        view_mode: str,
        finding_id: Optional[str] = None,
        filepath: Optional[str] = None,
        findings: Optional[List[Finding]] = None,
        app_tree: Optional[AppTreeSummary] = None,
    ) -> Dict[str, Any]:
        return self._backend().query_graph_view(
            view_mode=view_mode,
            finding_id=finding_id,
            filepath=filepath,
            findings=findings,
            app_tree=app_tree,
        )

    def close(self) -> None:
        with self._lock:
            self._embedded_store.close()
            self._active_store = None
            self._neo4j_store = None
