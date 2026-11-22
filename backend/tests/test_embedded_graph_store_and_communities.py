"""
TDD Suite for ALASTOR v5.0 Pillar 1 Task 3:
- Dual-Engine GraphStore (Neo4jGraphStore + EmbeddedGraphStore SQLite WAL + GraphStoreManager failover)
- Domain-Aware Sanitizer RULE-1-TAINT & Full Native Python Rule Parity (RULE-1..RULE-16 + Polyglot RULE-22..RULE-33)
- Deterministic Leiden/Modularity Community Detector & ReactFlow COMMUNITY_MAP View
"""
from __future__ import annotations

import hashlib
import os
import random
import sqlite3
import sys
import threading
from pathlib import Path
from typing import List
from unittest import mock

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from compiler.ast_parser import ASTNormalizer
from compiler.call_graph_builder import CallGraphBuilder
from compiler.cfg_builder import CFGBuilder
from compiler.dfg_builder import DFGBuilder
from compiler.scanner import ScannedFile
from database.graph_store import EmbeddedGraphStore, GraphStoreManager, Neo4jGraphStore
from engine.community_detector import build_community_graph_view, detect_code_communities
from engine.rule_executor import (
    RULES,
    RuleExecutor,
    is_sanitizer_compatible_for_sink,
    merge_findings_deduplicated,
)
from models import (
    AppTreeSummary,
    CPGEdge,
    CPGNode,
    CrossFileEdge,
    DirectoryTreeNode,
    FilePurposeInfo,
    Finding,
)


def _mk_node(
    nid: str,
    label: str = "Call",
    ast_type: str = "call",
    name: str = "fn",
    code: str = "fn()",
    filepath: str = "app/main.py",
    start_line: int = 10,
    end_line: int = 10,
    scope_id: str = "fn_main",
    is_source: bool = False,
    is_sink: bool = False,
    is_sanitizer: bool = False,
    sanitizer_domains: List[str] | None = None,
    sink_domain: str | None = None,
    language: str = "python",
) -> CPGNode:
    return CPGNode(
        id=nid,
        label=label,  # type: ignore[arg-type]
        ast_type=ast_type,
        name=name,
        code=code,
        filepath=filepath,
        start_line=start_line,
        end_line=end_line,
        start_col=0,
        end_col=len(code),
        scope_id=scope_id,
        is_source=is_source,
        is_sink=is_sink,
        is_sanitizer=is_sanitizer,
        sanitizer_domains=sanitizer_domains or [],
        sink_domain=sink_domain,
        language=language,
    )


def _mk_edge(src: str, tgt: str, etype: str = "DFG_FLOWS_TO", var_name: str | None = None) -> CPGEdge:
    eid = hashlib.sha256(f"{src}:{tgt}:{etype}:{var_name or ''}".encode()).hexdigest()[:24]
    return CPGEdge(id=eid, source_id=src, target_id=tgt, edge_type=etype, var_name=var_name)  # type: ignore[arg-type]


def _mk_scanned_file(filepath: str, language: str, code: str) -> ScannedFile:
    raw = code.encode("utf-8")
    return ScannedFile(
        filepath=filepath,
        full_path=f"/virtual/{filepath}",
        sha256=hashlib.sha256(raw).hexdigest(),
        language=language,
        content_bytes=raw,
    )


def _compile_files_in_memory(files: List[ScannedFile]):
    all_nodes: List[CPGNode] = []
    all_edges: List[CPGEdge] = []
    node_map = {}
    file_nodes = {}

    for sf in files:
        norm = ASTNormalizer(sf)
        nodes, ast_edges = norm.parse()
        all_nodes.extend(nodes)
        all_edges.extend(ast_edges)
        node_map.update(norm.node_map)
        file_nodes[sf.filepath] = nodes

    fn_params = {}
    fn_returns = {}
    func_by_id = {n.id: n for n in all_nodes if n.label == "Function"}
    for n in all_nodes:
        if n.label == "Parameter" and n.scope_id in func_by_id:
            fn_params.setdefault(func_by_id[n.scope_id].name, []).append(n)
        elif n.label == "Return" and n.scope_id in func_by_id:
            fn_returns.setdefault(func_by_id[n.scope_id].name, []).append(n)

    for sf in files:
        f_nodes = file_nodes[sf.filepath]
        all_edges.extend(CFGBuilder(sf.filepath, sf.content_bytes, sf.language, f_nodes, node_map).build())
        all_edges.extend(
            DFGBuilder(sf.filepath, sf.content_bytes, sf.language, f_nodes, node_map, fn_params, fn_returns).build()
        )

    all_edges.extend(CallGraphBuilder(all_nodes).resolve_calls())
    return all_nodes, all_edges


# ---------------------------------------------------------------------------
# 1. Domain-Aware Sanitizer Helper & RuleExecutor Cypher + Polyglot Merge
# ---------------------------------------------------------------------------


class TestDomainAwareRuleExecutor:
    def test_is_sanitizer_compatible_for_sink_matrix(self):
        # Cross-domain sanitization must NEVER clear incompatible sinks
        assert is_sanitizer_compatible_for_sink(["HTML"], "SHELL") is False
        assert is_sanitizer_compatible_for_sink(["HTML"], "SQL") is False
        assert is_sanitizer_compatible_for_sink(["HTML"], "URL") is False
        assert is_sanitizer_compatible_for_sink(["SQL"], "SHELL") is False

        # Same-domain sanitization clears matching sink
        assert is_sanitizer_compatible_for_sink(["HTML"], "HTML") is True
        assert is_sanitizer_compatible_for_sink(["SHELL"], "SHELL") is True
        assert is_sanitizer_compatible_for_sink(["SQL", "PATH"], "PATH") is True

        # UNIVERSAL clears every sink domain
        assert is_sanitizer_compatible_for_sink(["UNIVERSAL"], "SHELL") is True
        assert is_sanitizer_compatible_for_sink(["UNIVERSAL"], "SQL") is True
        assert is_sanitizer_compatible_for_sink(["UNIVERSAL"], "URL") is True

        # Backward compatibility: legacy sanitizer nodes without domains or sinks without sink_domain
        assert is_sanitizer_compatible_for_sink([], "SHELL") is True
        assert is_sanitizer_compatible_for_sink(["HTML"], None) is True

    def test_rule1_cypher_contains_domain_aware_sanitizer_guard(self):
        rule1 = next(r for r in RULES if r["id"] == "RULE-1-TAINT")
        cypher = rule1["cypher"]
        assert "sanitizer_domains" in cypher
        assert "UNIVERSAL" in cypher
        assert "sink.sink_domain" in cypher

    def test_execute_all_rules_with_polyglot_merges_without_duplicates(self):
        mock_client = mock.MagicMock()
        executor = RuleExecutor(mock_client)

        go_sf = _mk_scanned_file(
            "cmd/runner.go",
            "go",
            'package main\nimport "os/exec"\nfunc run(userCmd string) { exec.Command("sh", "-c", userCmd) }\n',
        )
        fake_cypher_finding = Finding(
            id="cypher-f-1",
            rule_id="RULE-1-TAINT",
            severity="CRITICAL",
            title="Taint Vulnerability: Untrusted Input Flows to Sensitive Sink",
            path_nodes=[{"id": "n1", "filepath": "app.py", "start_line": 5}],
            path_edges=[],
        )

        with mock.patch.object(executor, "run_all_rules", return_value=[fake_cypher_finding]):
            merged = executor.execute_all_rules_with_polyglot(
                scanned_files=[go_sf],
                all_nodes=[],
                all_edges=[],
            )
            rule_ids = {f.rule_id for f in merged}
            assert "RULE-1-TAINT" in rule_ids
            assert "RULE-27-POLYGLOT-CMDI" in rule_ids

            # Calling again with a duplicate polyglot finding returned by Cypher should deduplicate
            poly_finding = next(f for f in merged if f.rule_id == "RULE-27-POLYGLOT-CMDI")
            with mock.patch.object(executor, "run_all_rules", return_value=[fake_cypher_finding, poly_finding]):
                deduped = executor.execute_all_rules_with_polyglot(
                    scanned_files=[go_sf],
                    all_nodes=[],
                    all_edges=[],
                )
                assert sum(1 for f in deduped if f.rule_id == "RULE-27-POLYGLOT-CMDI") == 1

    def test_merge_findings_deduplicated_preserves_multi_source_shared_sink_paths(self):
        # Two distinct entrypoints flowing into the EXACT same sink line must BOTH be preserved!
        f_path_a = Finding(
            id="taint-path-a",
            rule_id="RULE-1-TAINT",
            severity="CRITICAL",
            title="Taint Vulnerability: Untrusted Input Flows to Sensitive Sink",
            path_nodes=[
                {"id": "src_a", "filepath": "api/route_a.py", "start_line": 10},
                {"id": "sink_shared", "filepath": "core/runner.py", "start_line": 42},
            ],
            path_edges=[{"id": "e1", "source": "src_a", "target": "sink_shared", "type": "DFG_FLOWS_TO"}],
        )
        f_path_b = Finding(
            id="taint-path-b",
            rule_id="RULE-1-TAINT",
            severity="CRITICAL",
            title="Taint Vulnerability: Untrusted Input Flows to Sensitive Sink",
            path_nodes=[
                {"id": "src_b", "filepath": "api/route_b.py", "start_line": 22},
                {"id": "sink_shared", "filepath": "core/runner.py", "start_line": 42},
            ],
            path_edges=[{"id": "e2", "source": "src_b", "target": "sink_shared", "type": "DFG_FLOWS_TO"}],
        )
        # Duplicate of f_path_a with different id but identical node IDs must be dropped
        f_path_a_dup = Finding(
            id="taint-path-a-dup",
            rule_id="RULE-1-TAINT",
            severity="CRITICAL",
            title="Taint Vulnerability: Untrusted Input Flows to Sensitive Sink",
            path_nodes=[
                {"id": "src_a", "filepath": "api/route_a.py", "start_line": 10},
                {"id": "sink_shared", "filepath": "core/runner.py", "start_line": 42},
            ],
            path_edges=[],
        )
        # Single-node findings on the same (rule_id, filepath, start_line) MUST still deduplicate
        f_single_1 = Finding(
            id="single-1",
            rule_id="RULE-6-SHELL-INJECTION",
            severity="CRITICAL",
            title="Unsafe Shell Execution",
            path_nodes=[{"id": "c1", "filepath": "core/runner.py", "start_line": 42}],
            path_edges=[],
        )
        f_single_2 = Finding(
            id="single-2",
            rule_id="RULE-6-SHELL-INJECTION",
            severity="CRITICAL",
            title="Unsafe Shell Execution",
            path_nodes=[{"id": "c2", "filepath": "core/runner.py", "start_line": 42}],
            path_edges=[],
        )

        merged = merge_findings_deduplicated([f_path_a, f_single_1], [f_path_b, f_path_a_dup, f_single_2])
        taint_ids = [f.id for f in merged if f.rule_id == "RULE-1-TAINT"]
        assert taint_ids == ["taint-path-a", "taint-path-b"]
        single_ids = [f.id for f in merged if f.rule_id == "RULE-6-SHELL-INJECTION"]
        assert single_ids == ["single-1"]


# ---------------------------------------------------------------------------
# 2. EmbeddedGraphStore SQLite WAL Persistence & Reload
# ---------------------------------------------------------------------------


class TestEmbeddedGraphStorePersistence:
    def test_sqlite_wal_mode_and_persistence_across_reload(self, tmp_path):
        db_path = str(tmp_path / ".alastor_vault" / "cpg_embedded.db")
        store = EmbeddedGraphStore(db_path)
        store.init_schema()

        # Verify WAL mode active on SQLite file
        conn = sqlite3.connect(db_path)
        try:
            journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            assert str(journal_mode).lower() == "wal"
        finally:
            conn.close()

        n1 = _mk_node("n1", label="Parameter", ast_type="identifier", name="cmd", code="cmd", filepath="api/run.py", start_line=4, is_source=True)
        n2 = _mk_node("n2", label="Call", ast_type="call", name="os.system", code="os.system(cmd)", filepath="api/run.py", start_line=6, is_sink=True, sink_domain="SHELL")
        e1 = _mk_edge("n1", "n2", "DFG_FLOWS_TO", var_name="cmd")

        nc, ec = store.ingest_cpg([n1, n2], [e1])
        assert nc == 2
        assert ec == 1
        assert store.get_counts() == {"nodes": 2, "edges": 1}

        comm_map = detect_code_communities([n1, n2], [e1], graph_engine_mode="EMBEDDED_SQLITE")
        store.save_communities(comm_map)
        store.save_meta("last_scan_root", "/tmp/project")
        store.save_meta("languages_detected", {"python": 1})
        store.close()

        # Instantiate a brand new EmbeddedGraphStore pointing at the same SQLite DB
        reloaded = EmbeddedGraphStore(db_path)
        try:
            assert reloaded.mode == "EMBEDDED_SQLITE"
            assert reloaded.get_counts() == {"nodes": 2, "edges": 1}
            assert reloaded.get_meta("last_scan_root") == "/tmp/project"
            assert reloaded.get_meta("languages_detected") == {"python": 1}
            assert reloaded.get_meta("missing_key", "fallback") == "fallback"

            loaded_comm = reloaded.get_communities()
            assert loaded_comm.total_communities == comm_map.total_communities
            assert loaded_comm.communities[0].id == comm_map.communities[0].id

            # Rule evaluation must work seamlessly on reloaded in-memory graph indices
            findings = reloaded.run_cpg_rules()
            assert any(f.rule_id == "RULE-1-TAINT" for f in findings)

            reloaded.clear_database()
            assert reloaded.get_counts() == {"nodes": 0, "edges": 0}
        finally:
            reloaded.close()

    def test_thread_safety_under_concurrent_access(self, tmp_path):
        db_path = str(tmp_path / "vault" / "cpg_embedded.db")
        store = EmbeddedGraphStore(db_path)
        store.init_schema()
        errors: List[Exception] = []

        def worker(idx: int):
            try:
                node = _mk_node(f"t-{idx}", name=f"fn_{idx}", filepath=f"mod_{idx}.py", start_line=idx + 1)
                store.ingest_cpg([node], [])
                store.save_meta(f"k-{idx}", idx)
                _ = store.get_counts()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        try:
            assert not errors
            assert store.get_counts()["nodes"] == 8
        finally:
            store.close()

    def test_ingest_cpg_atomic_on_commit_error_and_close_resets_loaded_flag(self, tmp_path):
        db_path = str(tmp_path / "vault" / "atomic.db")
        store = EmbeddedGraphStore(db_path)
        n1 = _mk_node("n_ok", filepath="ok.py", start_line=1)
        store.ingest_cpg([n1], [])
        assert store.get_counts() == {"nodes": 1, "edges": 0}

        # Simulate SQLite commit failure: in-memory _nodes/_edges must NOT be mutated
        n2 = _mk_node("n_fail", filepath="fail.py", start_line=2)
        e_fail = _mk_edge("n_ok", "n_fail", "DFG_FLOWS_TO", "x")
        real_conn = store._get_conn()

        class _FailingCommitConn:
            def __getattr__(self, item):
                return getattr(real_conn, item)

            def commit(self):
                real_conn.rollback()
                raise sqlite3.OperationalError("simulated disk full")

        with mock.patch.object(store, "_get_conn", return_value=_FailingCommitConn()):
            with pytest.raises(sqlite3.OperationalError, match="simulated disk full"):
                store.ingest_cpg([n2], [e_fail])

        assert "n_fail" not in store._nodes
        assert e_fail.id not in store._edges
        assert store.get_counts() == {"nodes": 1, "edges": 0}

        # Closing must reset _loaded so subsequent re-open reloads cleanly from disk
        store.close()
        assert store._loaded is False
        assert store.get_counts() == {"nodes": 1, "edges": 0}
        store.close()


# ---------------------------------------------------------------------------
# 3. EmbeddedGraphStore Native Python Rule Parity (RULE-1..16 + Polyglot)
# ---------------------------------------------------------------------------


class TestEmbeddedGraphStoreRuleParity:
    def test_rule1_domain_aware_sanitizer_html_does_not_clear_shell_while_shlex_does(self, tmp_path):
        store = EmbeddedGraphStore(str(tmp_path / "cpg.db"))
        try:
            # Case A: source -> html.escape (HTML) -> os.system (SHELL) => MUST FLAG!
            src_a = _mk_node("src_a", label="Parameter", name="user_in", code="user_in", filepath="a.py", start_line=2, is_source=True)
            san_html = _mk_node(
                "san_html",
                label="Call",
                name="html.escape",
                code="html.escape(user_in)",
                filepath="a.py",
                start_line=3,
                is_sanitizer=True,
                sanitizer_domains=["HTML"],
            )
            sink_shell_a = _mk_node(
                "sink_a",
                label="Call",
                name="os.system",
                code="os.system(safe_html)",
                filepath="a.py",
                start_line=4,
                is_sink=True,
                sink_domain="SHELL",
            )

            # Case B: source -> shlex.quote (SHELL) -> os.system (SHELL) => MUST BE NEUTRALIZED!
            src_b = _mk_node("src_b", label="Parameter", name="arg", code="arg", filepath="b.py", start_line=2, is_source=True)
            san_shell = _mk_node(
                "san_shell",
                label="Call",
                name="shlex.quote",
                code="shlex.quote(arg)",
                filepath="b.py",
                start_line=3,
                is_sanitizer=True,
                sanitizer_domains=["SHELL"],
            )
            sink_shell_b = _mk_node(
                "sink_b",
                label="Call",
                name="os.system",
                code="os.system(quoted)",
                filepath="b.py",
                start_line=4,
                is_sink=True,
                sink_domain="SHELL",
            )

            # Case C: source -> int (UNIVERSAL) -> os.system (SHELL) => MUST BE NEUTRALIZED!
            src_c = _mk_node("src_c", label="Parameter", name="num", code="num", filepath="c.py", start_line=2, is_source=True)
            san_univ = _mk_node(
                "san_univ",
                label="Call",
                name="int",
                code="int(num)",
                filepath="c.py",
                start_line=3,
                is_sanitizer=True,
                sanitizer_domains=["UNIVERSAL"],
            )
            sink_shell_c = _mk_node(
                "sink_c",
                label="Call",
                name="os.system",
                code="os.system(str(n))",
                filepath="c.py",
                start_line=4,
                is_sink=True,
                sink_domain="SHELL",
            )

            nodes = [src_a, san_html, sink_shell_a, src_b, san_shell, sink_shell_b, src_c, san_univ, sink_shell_c]
            edges = [
                _mk_edge("src_a", "san_html", "DFG_FLOWS_TO", "user_in"),
                _mk_edge("san_html", "sink_a", "DFG_FLOWS_TO", "safe_html"),
                _mk_edge("src_b", "san_shell", "DFG_FLOWS_TO", "arg"),
                _mk_edge("san_shell", "sink_b", "DFG_FLOWS_TO", "quoted"),
                _mk_edge("src_c", "san_univ", "DFG_FLOWS_TO", "num"),
                _mk_edge("san_univ", "sink_c", "DFG_FLOWS_TO", "n"),
            ]
            store.ingest_cpg(nodes, edges)

            findings = store.run_cpg_rules(enabled_rule_ids={"RULE-1-TAINT"})
            assert len(findings) == 1
            assert findings[0].rule_id == "RULE-1-TAINT"
            assert findings[0].path_nodes[-1]["id"] == "sink_a"
        finally:
            store.close()

    def test_rules_2_3_4_5_structural_logic_flaws(self, tmp_path):
        store = EmbeddedGraphStore(str(tmp_path / "cpg_struct.db"))
        try:
            # RULE-2-ORPHAN: uncalled auth guard `getSession` + uncalled debug gadget
            fn_auth = _mk_node("fn_auth", label="Function", ast_type="function_definition", name="getSession", code="def getSession(req): return None", filepath="auth.py", start_line=1, end_line=5)
            fn_called = _mk_node("fn_called", label="Function", ast_type="function_definition", name="debug_helper", code="def debug_helper(): pass", filepath="auth.py", start_line=10, end_line=12)
            caller = _mk_node("caller_c", label="Call", name="debug_helper", code="debug_helper()", filepath="auth.py", start_line=15)

            # RULE-3-DEADSTORE: Call -> Variable with no outgoing DFG and no other reference
            ds_call = _mk_node("ds_call", label="Call", name="compute_hash", code="compute_hash(x)", filepath="dead.py", start_line=3, scope_id="fn_dead")
            ds_var = _mk_node("ds_var", label="Variable", ast_type="identifier", name="unused_digest", code="unused_digest", filepath="dead.py", start_line=3, scope_id="fn_dead")

            # RULE-4-INFINITE-LOOP: while True with CFG_LOOP_BACK and no CFG_FALSE / CFG_BREAK / Return
            loop_hdr = _mk_node("loop_hdr", label="LoopBlock", ast_type="while_statement", name="while", code="while True:\n    work()", filepath="loop.py", start_line=2, end_line=4, scope_id="fn_loop")
            loop_body = _mk_node("loop_body", label="Call", name="work", code="work()", filepath="loop.py", start_line=3, scope_id="fn_loop")

            # RULE-5-UNREACHABLE: Function -> block -> Return, followed by Call with no incoming CFG
            fn_unr = _mk_node("fn_unr", label="Function", ast_type="function_definition", name="do_work", code="def do_work():\n    return 1\n    cleanup()", filepath="unr.py", start_line=1, end_line=4, scope_id="mod")
            blk_unr = _mk_node("blk_unr", label="ControlBlock", ast_type="block", name="block", code="return 1\ncleanup()", filepath="unr.py", start_line=2, end_line=4, scope_id="fn_unr")
            ret_unr = _mk_node("ret_unr", label="Return", ast_type="return_statement", name="return", code="return 1", filepath="unr.py", start_line=2, end_line=2, scope_id="fn_unr")
            dead_stmt = _mk_node("dead_stmt", label="Call", ast_type="call", name="cleanup", code="cleanup()", filepath="unr.py", start_line=3, end_line=3, scope_id="fn_unr")

            nodes = [fn_auth, fn_called, caller, ds_call, ds_var, loop_hdr, loop_body, fn_unr, blk_unr, ret_unr, dead_stmt]
            edges = [
                _mk_edge("caller_c", "fn_called", "CALLS"),
                _mk_edge("ds_call", "ds_var", "DFG_FLOWS_TO", "unused_digest"),
                _mk_edge("loop_hdr", "loop_body", "CFG_TRUE"),
                _mk_edge("loop_body", "loop_hdr", "CFG_LOOP_BACK"),
                _mk_edge("fn_unr", "blk_unr", "AST_CHILD"),
                _mk_edge("blk_unr", "ret_unr", "AST_CHILD"),
                _mk_edge("blk_unr", "dead_stmt", "AST_CHILD"),
            ]
            store.ingest_cpg(nodes, edges)

            findings = store.run_cpg_rules()
            found_rules = {f.rule_id for f in findings}
            assert "RULE-2-ORPHAN" in found_rules
            assert "RULE-3-DEADSTORE" in found_rules
            assert "RULE-4-INFINITE-LOOP" in found_rules
            assert "RULE-5-UNREACHABLE" in found_rules

            # Ensure called function was NOT flagged as orphan
            orphan_titles = [f.title for f in findings if f.rule_id == "RULE-2-ORPHAN"]
            assert any("getSession" in t for t in orphan_titles)
            assert not any("debug_helper" in t for t in orphan_titles)
        finally:
            store.close()

    def test_rules_6_through_16_and_polyglot_rules_27_30(self, tmp_path):
        store = EmbeddedGraphStore(str(tmp_path / "cpg_sinks.db"))
        try:
            src_http = _mk_node("src_http", label="Parameter", name="user_url", code="request.args.get('url')", filepath="web.py", start_line=2, is_source=True)
            c_shell = _mk_node("c_shell", label="Call", name="subprocess.run", code="subprocess.run(cmd, shell=True)", filepath="web.py", start_line=5)
            c_sqli = _mk_node("c_sqli", label="Call", name="cursor.execute", code='cursor.execute(f"SELECT * FROM users WHERE name={u}")', filepath="web.py", start_line=6)
            a_secret = _mk_node("a_secret", label="Assignment", name="db_password", code='db_password = "hardcoded_sample_val"', filepath="web.py", start_line=7)
            c_xss = _mk_node("c_xss", label="Call", name="document.write", code="document.write(payload)", filepath="ui.js", start_line=8, language="javascript")
            c_path = _mk_node("c_path", label="Call", name="open", code="open(user_url)", filepath="web.py", start_line=9, is_sink=True, sink_domain="PATH")
            c_ssrf = _mk_node("c_ssrf", label="Call", name="requests.get", code="requests.get(user_url)", filepath="web.py", start_line=10)
            c_log = _mk_node("c_log", label="Call", name="logger.info", code='logger.info(f"Visiting {user_url}")', filepath="web.py", start_line=11)
            c_deser = _mk_node("c_deser", label="Call", name="pickle.loads", code="pickle.loads(raw)", filepath="web.py", start_line=12)
            c_eval = _mk_node("c_eval", label="Call", name="eval", code="eval(expr)", filepath="web.py", start_line=13)
            c_tls = _mk_node("c_tls", label="Call", name="requests.get", code="requests.get(endpoint, verify=False)", filepath="web.py", start_line=14)
            a_prng = _mk_node("a_prng", label="Assignment", name="reset_token", code="reset_token = str(random.randint(1000, 9999))", filepath="web.py", start_line=15)
            c_redir = _mk_node("c_redir", label="Call", name="RedirectResponse", code="RedirectResponse(user_url)", filepath="web.py", start_line=16)

            nodes = [src_http, c_shell, c_sqli, a_secret, c_xss, c_path, c_ssrf, c_log, c_deser, c_eval, c_tls, a_prng, c_redir]
            edges = [
                _mk_edge("src_http", "c_path", "DFG_FLOWS_TO", "user_url"),
                _mk_edge("src_http", "c_ssrf", "DFG_FLOWS_TO", "user_url"),
                _mk_edge("src_http", "c_log", "DFG_FLOWS_TO", "user_url"),
                _mk_edge("src_http", "c_redir", "DFG_FLOWS_TO", "user_url"),
            ]
            store.ingest_cpg(nodes, edges)

            go_sf = _mk_scanned_file(
                "services/exec.go",
                "go",
                'package services\nimport "os/exec"\nfunc Run(arg string) { exec.Command("sh", "-c", arg) }\n',
            )
            sol_sf = _mk_scanned_file(
                "contracts/Vault.sol",
                "solidity",
                (
                    "pragma solidity ^0.8.20;\n"
                    "contract Vault {\n"
                    "    mapping(address => uint256) public balances;\n"
                    "    function withdraw() external {\n"
                    "        uint256 amt = balances[msg.sender];\n"
                    '        (bool ok, ) = msg.sender.call{value: amt}("");\n'
                    "        require(ok);\n"
                    "        balances[msg.sender] = 0;\n"
                    "    }\n"
                    "}\n"
                ),
            )

            findings = store.run_cpg_rules(scanned_files=[go_sf, sol_sf])
            rule_ids = {f.rule_id for f in findings}
            for expected_rule in [
                "RULE-6-SHELL-INJECTION",
                "RULE-7-SQLI-FORMAT",
                "RULE-8-HARDCODED-SECRET",
                "RULE-9-DOM-XSS",
                "RULE-10-PATH-TRAVERSAL",
                "RULE-11-SSRF-URLOPEN",
                "RULE-12-LOG-INJECTION",
                "RULE-13-UNSAFE-DESERIALIZATION-CRYPTO",
                "RULE-14-CODE-INJECTION",
                "RULE-15-XXE-TLS-BYPASS",
                "RULE-16-INSECURE-RANDOM-OPEN-REDIRECT",
                "RULE-27-POLYGLOT-CMDI",
                "RULE-30-SOLIDITY-REENTRANCY",
            ]:
                assert expected_rule in rule_ids, f"Missing expected rule: {expected_rule}"
        finally:
            store.close()

    def test_end_to_end_compiled_python_taint_in_embedded_store(self, tmp_path):
        vuln_sf = _mk_scanned_file(
            "api/vuln_handler.py",
            "python",
            (
                "import os\n"
                "import html\n"
                "def vuln_route(request):\n"
                "    user_cmd = request.args.get('cmd')\n"
                "    escaped = html.escape(user_cmd)\n"
                "    os.system(escaped)\n"
            ),
        )
        safe_sf = _mk_scanned_file(
            "api/safe_handler.py",
            "python",
            (
                "import os\n"
                "import shlex\n"
                "def safe_route(request):\n"
                "    user_cmd = request.args.get('cmd')\n"
                "    quoted = shlex.quote(user_cmd)\n"
                "    os.system(quoted)\n"
            ),
        )
        nodes, edges = _compile_files_in_memory([vuln_sf, safe_sf])
        store = EmbeddedGraphStore(str(tmp_path / "compiled.db"))
        try:
            store.ingest_cpg(nodes, edges)
            findings = store.run_cpg_rules(scanned_files=[vuln_sf, safe_sf], enabled_rule_ids={"RULE-1-TAINT"})
            flagged_files = {f.path_nodes[-1]["filepath"] for f in findings}
            assert "api/vuln_handler.py" in flagged_files
            assert "api/safe_handler.py" not in flagged_files
        finally:
            store.close()


# ---------------------------------------------------------------------------
# 4. All 8 Graph View Modes in EmbeddedGraphStore
# ---------------------------------------------------------------------------


class TestEmbeddedGraphStoreViews:
    def test_all_eight_graph_view_modes(self, tmp_path):
        store = EmbeddedGraphStore(str(tmp_path / "views.db"))
        try:
            fn_a = _mk_node("fn_a", label="Function", ast_type="function_definition", name="handle_req", code="def handle_req(q): return helper(q)", filepath="api/routes.py", start_line=1, end_line=5)
            p_q = _mk_node("p_q", label="Parameter", ast_type="identifier", name="q", code="q", filepath="api/routes.py", start_line=1, scope_id="fn_a", is_source=True)
            c_help = _mk_node("c_help", label="Call", ast_type="call", name="helper", code="helper(q)", filepath="api/routes.py", start_line=2, scope_id="fn_a")
            fn_b = _mk_node("fn_b", label="Function", ast_type="function_definition", name="helper", code="def helper(x): os.system(x)", filepath="core/exec.py", start_line=1, end_line=4)
            c_sink = _mk_node("c_sink", label="Call", ast_type="call", name="os.system", code="os.system(x)", filepath="core/exec.py", start_line=2, scope_id="fn_b", is_sink=True, sink_domain="SHELL")

            nodes = [fn_a, p_q, c_help, fn_b, c_sink]
            edges = [
                _mk_edge("fn_a", "c_help", "AST_CHILD"),
                _mk_edge("p_q", "c_help", "DFG_FLOWS_TO", "q"),
                _mk_edge("c_help", "fn_b", "CALLS"),
                _mk_edge("c_help", "c_sink", "DFG_FLOWS_TO", "x"),
                _mk_edge("fn_a", "c_help", "CFG_NEXT"),
                _mk_edge("c_help", "c_sink", "CFG_NEXT"),
            ]
            store.ingest_cpg(nodes, edges)

            comm_map = detect_code_communities(nodes, edges, graph_engine_mode="EMBEDDED_SQLITE")
            store.save_communities(comm_map)
            findings = store.run_cpg_rules(enabled_rule_ids={"RULE-1-TAINT"})
            assert findings

            required_node_keys = {
                "id", "label", "name", "filepath", "start_line", "end_line",
                "ast_type", "code", "is_source", "is_sink", "is_sanitizer",
            }

            for mode in [
                "FINDING_PATH",
                "CALL_GRAPH",
                "ENTRYPOINTS",
                "DFG",
                "CFG",
                "SPIDER",
                "FULL_CPG",
                "COMMUNITY_MAP",
            ]:
                view = store.query_graph_view(
                    view_mode=mode,
                    finding_id=findings[0].id if mode == "FINDING_PATH" else None,
                    filepath="api/routes.py" if mode in ("DFG", "CFG", "CALL_GRAPH") else None,
                    findings=findings,
                )
                assert isinstance(view, dict), f"View {mode} must return dict"
                assert len(view["nodes"]) >= 1, f"View {mode} returned empty nodes"
                for nd in view["nodes"]:
                    assert required_node_keys.issubset(nd.keys()), f"View {mode} missing keys in {nd}"
                if mode == "COMMUNITY_MAP":
                    assert view["view_mode"] == "COMMUNITY_MAP"
                    assert "summary" in view
                else:
                    assert isinstance(view["edges"], list)
                    assert len(view["edges"]) >= 1, f"View {mode} returned empty edges"
        finally:
            store.close()

    def test_app_tree_spider_and_app_tree_view_modes_preserve_label_and_persist(self, tmp_path):
        app_tree = AppTreeSummary(
            root_path="/repo",
            total_files=2,
            total_directories=2,
            total_lines=40,
            category_counts={"API": 1, "Core": 1},
            detected_tech_stack=["Python"],
            tree=DirectoryTreeNode(
                name="repo",
                path="repo",
                purpose="Root",
                subdirectories=[
                    DirectoryTreeNode(
                        name="api",
                        path="api",
                        purpose="Routes",
                        files=[
                            FilePurposeInfo(
                                filepath="api/routes.py",
                                filename="routes.py",
                                extension=".py",
                                category="API",
                                purpose="HTTP routes",
                                language="python",
                                line_count=20,
                                size_bytes=200,
                                sha256="aaa",
                                is_cpg_supported=True,
                            ),
                            FilePurposeInfo(
                                filepath="api/service.py",
                                filename="service.py",
                                extension=".py",
                                category="Core",
                                purpose="Business logic",
                                language="python",
                                line_count=20,
                                size_bytes=220,
                                sha256="bbb",
                                is_cpg_supported=True,
                            ),
                        ],
                    )
                ],
            ),
            flat_files=[],
            cross_file_edges=[
                CrossFileEdge(
                    source_filepath="api/routes.py",
                    target_filepath="api/service.py",
                    edge_type="IMPORTS",
                    symbols=["run_job"],
                    flow_label="IMPORTS",
                )
            ],
        )

        db_path = str(tmp_path / "spider.db")
        store = EmbeddedGraphStore(db_path)
        try:
            store.ingest_app_tree(app_tree)
            spider_view = store.query_graph_view("SPIDER")
            assert spider_view["view_mode"] == "SPIDER"
            assert any(e["type"] == "IMPORTS" for e in spider_view["edges"])
            assert any(e["type"] == "CONTAINS" for e in spider_view["edges"])

            tree_view = store.query_graph_view("APP_TREE")
            assert tree_view["view_mode"] == "APP_TREE"
            assert len(tree_view["nodes"]) == len(spider_view["nodes"])
        finally:
            store.close()

        # Verify Neo4jGraphStore supports SPIDER/APP_TREE & ENTRYPOINTS with project-wide fallback
        neo_mock = mock.MagicMock()
        mock_session = mock.MagicMock()
        neo_mock.driver.session.return_value.__enter__.return_value = mock_session

        ep_rec = {
            "all_nodes": [
                {
                    "id": "ep1",
                    "label": "Function",
                    "name": "route_login",
                    "filepath": "api/routes.py",
                    "start_line": 3,
                    "end_line": 8,
                    "ast_type": "function_definition",
                    "code": "@app.post('/login')\ndef route_login(): pass",
                    "is_source": True,
                    "is_sink": False,
                    "is_sanitizer": False,
                },
                {
                    "id": "sink1",
                    "label": "Call",
                    "name": "os.system",
                    "filepath": "api/service.py",
                    "start_line": 12,
                    "end_line": 12,
                    "ast_type": "call",
                    "code": "os.system(cmd)",
                    "is_source": False,
                    "is_sink": True,
                    "is_sanitizer": False,
                },
            ],
            "all_edges": [
                {"id": "e_ep", "source": "ep1", "target": "sink1", "type": "DFG_FLOWS_TO", "var_name": "cmd"}
            ],
        }
        # First call (scoped to missing filepath) returns empty; second call (project-wide fallback) returns ep_rec
        empty_res = mock.MagicMock()
        empty_res.single.return_value = {"all_nodes": [], "all_edges": []}
        populated_res = mock.MagicMock()
        populated_res.single.return_value = ep_rec
        mock_session.run.side_effect = [empty_res, populated_res]

        reloaded_cache = EmbeddedGraphStore(db_path)
        neo_store = Neo4jGraphStore(neo_mock, reloaded_cache)
        try:
            neo_spider = neo_store.query_graph_view("SPIDER")
            assert neo_spider["view_mode"] == "SPIDER"
            assert any(e["type"] == "IMPORTS" for e in neo_spider["edges"])

            neo_app_tree = neo_store.query_graph_view("APP_TREE")
            assert neo_app_tree["view_mode"] == "APP_TREE"

            neo_ep = neo_store.query_graph_view("ENTRYPOINTS", filepath="unmatched/file.py")
            assert neo_ep["view_mode"] == "ENTRYPOINTS"
            assert len(neo_ep["nodes"]) == 2
            assert len(neo_ep["edges"]) == 1
            assert mock_session.run.call_count == 2
            first_query = mock_session.run.call_args_list[0][0][0]
            assert "is_source" in first_query
            assert "DFG_FLOWS_TO" in first_query
        finally:
            neo_store.close()


# ---------------------------------------------------------------------------
# 5. GraphStoreManager Automatic Failover & Engine Selection
# ---------------------------------------------------------------------------


class TestGraphStoreManagerFailover:
    def test_auto_mode_falls_back_to_embedded_when_neo4j_offline(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "auto")
        offline_neo4j = mock.MagicMock()
        offline_neo4j.verify_connectivity_and_apoc.side_effect = ConnectionRefusedError("Bolt offline")

        mgr = GraphStoreManager(neo4j_client=offline_neo4j, vault_dir=str(tmp_path / ".alastor_vault"))
        try:
            active_mode = mgr.ensure_backend(force_probe=True)
            assert active_mode == "EMBEDDED_SQLITE"
            assert mgr.mode == "EMBEDDED_SQLITE"
            offline_neo4j.verify_connectivity_and_apoc.assert_called_once()

            # Facade operations must work cleanly on the embedded fallback
            mgr.init_schema()
            n1 = _mk_node("m1", filepath="svc.py", is_source=True)
            n2 = _mk_node("m2", filepath="svc.py", is_sink=True, sink_domain="SHELL")
            e1 = _mk_edge("m1", "m2", "DFG_FLOWS_TO", "x")
            assert mgr.ingest_cpg([n1, n2], [e1]) == (2, 1)
            assert mgr.get_counts() == {"nodes": 2, "edges": 1}
            assert any(f.rule_id == "RULE-1-TAINT" for f in mgr.run_cpg_rules())
        finally:
            mgr.close()

    def test_embedded_mode_never_probes_neo4j(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "embedded")
        neo4j_mock = mock.MagicMock()

        mgr = GraphStoreManager(neo4j_client=neo4j_mock, vault_dir=str(tmp_path / ".alastor_vault"))
        try:
            assert mgr.ensure_backend(force_probe=True) == "EMBEDDED_SQLITE"
            assert mgr.mode == "EMBEDDED_SQLITE"
            neo4j_mock.verify_connectivity_and_apoc.assert_not_called()
        finally:
            mgr.close()

    def test_auto_mode_uses_neo4j_when_healthy(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "auto")
        healthy_neo4j = mock.MagicMock()
        healthy_neo4j.verify_connectivity_and_apoc.return_value = True

        mgr = GraphStoreManager(neo4j_client=healthy_neo4j, vault_dir=str(tmp_path / ".alastor_vault"))
        try:
            assert mgr.ensure_backend(force_probe=True) == "NEO4J_APOC"
            assert mgr.mode == "NEO4J_APOC"
            assert isinstance(mgr._active_store, Neo4jGraphStore)

            # Communities persist via embedded_cache even in Neo4j mode
            cm = detect_code_communities([_mk_node("x1", filepath="a.py")], [], graph_engine_mode="NEO4J_APOC")
            mgr.save_communities(cm)
            loaded = mgr.get_communities()
            assert loaded.total_communities == 1
        finally:
            mgr.close()

    def test_forced_neo4j_mode_raises_when_offline(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "neo4j")
        offline_neo4j = mock.MagicMock()
        offline_neo4j.verify_connectivity_and_apoc.side_effect = RuntimeError("Neo4j unreachable")

        mgr = GraphStoreManager(neo4j_client=offline_neo4j, vault_dir=str(tmp_path / ".alastor_vault"))
        try:
            with pytest.raises(RuntimeError, match="Neo4j unreachable"):
                mgr.ensure_backend(force_probe=True)
        finally:
            mgr.close()

    def test_forced_neo4j_mode_raises_when_probe_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "neo4j")
        false_neo4j = mock.MagicMock()
        false_neo4j.verify_connectivity_and_apoc.return_value = False

        mgr = GraphStoreManager(neo4j_client=false_neo4j, vault_dir=str(tmp_path / ".alastor_vault"))
        try:
            with pytest.raises(RuntimeError, match="verify|False|Neo4j"):
                mgr.ensure_backend(force_probe=True)
        finally:
            mgr.close()


# ---------------------------------------------------------------------------
# 6. Deterministic Leiden Community Detector & Polyglot Bridge Detection
# ---------------------------------------------------------------------------


class TestDeterministicCommunityDetector:
    def _build_polyglot_fixture(self):
        # Cluster 1: Python API routes + service (strongly coupled)
        py_r = _mk_node("py_r", label="Function", name="post_transfer", code="@app.post('/transfer')\ndef post_transfer(): pass", filepath="api_routes/transfer.py", start_line=1, is_source=True, language="python")
        py_s = _mk_node("py_s", label="Function", name="validate_transfer", code="def validate_transfer(): pass", filepath="api_routes/validator.py", start_line=1, language="python")
        py_m = _mk_node("py_m", label="Call", name="os.system", code="os.system(cmd)", filepath="api_routes/bridge.py", start_line=5, is_sink=True, sink_domain="SHELL", language="python")

        # Cluster 2: Solidity smart contracts (strongly coupled)
        sol_v = _mk_node("sol_v", label="Function", name="withdraw", code="function withdraw() external {}", filepath="smart_contracts/Vault.sol", start_line=10, is_sink=True, sink_domain="REENTRANCY", language="solidity")
        sol_t = _mk_node("sol_t", label="Function", name="transfer", code="function transfer() external {}", filepath="smart_contracts/Token.sol", start_line=10, language="solidity")
        sol_g = _mk_node("sol_g", label="Function", name="checkOwner", code="function checkOwner() internal {}", filepath="smart_contracts/Guard.sol", start_line=5, language="solidity")

        # Cluster 3: Disconnected Go utility module (no edges to Python or Solidity)
        go_u = _mk_node("go_u", label="Function", name="FormatLog", code="func FormatLog() {}", filepath="go_workers/logger.go", start_line=3, language="go")

        nodes = [py_r, py_s, py_m, sol_v, sol_t, sol_g, go_u]
        edges = [
            # Strong intra-Python cluster edges
            _mk_edge("py_r", "py_s", "CALLS"),
            _mk_edge("py_s", "py_m", "CALLS"),
            _mk_edge("py_r", "py_m", "DFG_FLOWS_TO", "payload"),
            # Strong intra-Solidity cluster edges
            _mk_edge("sol_v", "sol_t", "CALLS"),
            _mk_edge("sol_t", "sol_g", "CALLS"),
            _mk_edge("sol_v", "sol_g", "DFG_FLOWS_TO", "sender"),
            # Cross-language polyglot bridge (Python -> Solidity)
            _mk_edge("py_m", "sol_v", "CALLS"),
        ]
        findings = [
            Finding(
                id="f-crit-sol",
                rule_id="RULE-30-SOLIDITY-REENTRANCY",
                severity="CRITICAL",
                title="Solidity Reentrancy",
                path_nodes=[{"id": "sol_v", "filepath": "smart_contracts/Vault.sol", "start_line": 10}],
                path_edges=[],
            )
        ]
        return nodes, edges, findings

    def test_determinism_across_shuffled_runs_and_polyglot_bridges(self):
        nodes, edges, findings = self._build_polyglot_fixture()

        res1 = detect_code_communities(nodes, edges, findings=findings, graph_engine_mode="EMBEDDED_SQLITE")

        # Shuffle input lists to guarantee order-independent determinism
        rng = random.Random(42)
        shuffled_nodes = list(nodes)
        shuffled_edges = list(edges)
        rng.shuffle(shuffled_nodes)
        rng.shuffle(shuffled_edges)

        res2 = detect_code_communities(shuffled_nodes, shuffled_edges, findings=findings, graph_engine_mode="EMBEDDED_SQLITE")

        assert res1.model_dump() == res2.model_dump()
        assert res1.total_communities == 3
        assert res1.polyglot_bridges_count >= 1
        assert any(e.is_polyglot_bridge for e in res1.cross_community_edges)

        # Verify disconnected Go worker is in its own isolated community
        go_comm = next(c for c in res1.communities if "go_workers/logger.go" in c.filepaths)
        assert go_comm.filepaths == ["go_workers/logger.go"]
        assert go_comm.primary_language == "go"
        assert go_comm.risk_tier == "LOW"

        # Verify Solidity community has CRITICAL risk tier due to CRITICAL finding
        sol_comm = next(c for c in res1.communities if "smart_contracts/Vault.sol" in c.filepaths)
        assert sol_comm.primary_language == "solidity"
        assert sol_comm.finding_count == 1
        assert sol_comm.risk_tier == "CRITICAL"

        # Verify Python community has entrypoint + sink -> HIGH risk tier
        py_comm = next(c for c in res1.communities if "api_routes/transfer.py" in c.filepaths)
        assert py_comm.primary_language == "python"
        assert py_comm.entrypoint_count >= 1
        assert py_comm.sink_count >= 1
        assert py_comm.risk_tier == "HIGH"

    def test_build_community_graph_view_reactflow_contract(self):
        nodes, edges, findings = self._build_polyglot_fixture()
        comm_map = detect_code_communities(nodes, edges, findings=findings, graph_engine_mode="EMBEDDED_SQLITE")
        view = build_community_graph_view(comm_map)

        assert view["view_mode"] == "COMMUNITY_MAP"
        assert len(view["nodes"]) == comm_map.total_communities
        assert len(view["edges"]) == len(comm_map.cross_community_edges)
        assert view["summary"]["total_communities"] == comm_map.total_communities
        assert view["summary"]["polyglot_bridges_count"] == comm_map.polyglot_bridges_count
        assert view["summary"]["graph_engine_mode"] == "EMBEDDED_SQLITE"

        first_node = view["nodes"][0]
        assert first_node["label"] == "CommunityCluster"
        assert first_node["ast_type"] == "community_cluster"
        assert "risk_tier" in first_node
        assert "filepaths" in first_node
        assert "languages" in first_node

        bridge_edges = [e for e in view["edges"] if e["is_polyglot_bridge"]]
        assert len(bridge_edges) >= 1
        assert bridge_edges[0]["type"] == "POLYGLOT_BRIDGE"
        assert "(Polyglot)" in bridge_edges[0]["label"]


# ---------------------------------------------------------------------------
# 7. FastAPI Route Wiring, Offline Zero-Docker Failover & Enterprise Rules
# ---------------------------------------------------------------------------


class TestFastApiDualEngineAndEnterpriseRules:
    def test_fastapi_languages_capabilities_and_health_engine_mode(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient
        import main as main_mod

        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "embedded")
        isolated_mgr = GraphStoreManager(
            neo4j_client=main_mod.neo4j_client,
            vault_dir=str(tmp_path / ".alastor_vault"),
        )
        isolated_mgr.ensure_backend(force_probe=True)
        monkeypatch.setattr(main_mod, "graph_store_mgr", isolated_mgr)

        try:
            client = TestClient(main_mod.app)

            cap_resp = client.get("/api/languages/capabilities")
            assert cap_resp.status_code == 200
            cap_data = cap_resp.json()
            assert cap_data["total_languages"] >= 18
            assert cap_data["ready_parsers"] >= 18
            lang_keys = {item["language"] for item in cap_data["languages"]}
            for expected in ("python", "javascript", "typescript", "go", "java", "rust", "cpp", "solidity", "web_template"):
                assert expected in lang_keys

            health_resp = client.get("/api/health")
            assert health_resp.status_code == 200
            health_data = health_resp.json()
            assert health_data["status"] == "HEALTHY"
            assert health_data["graph_engine_mode"] == "EMBEDDED_SQLITE"
            assert health_data["neo4j"] == "OFFLINE_EMBEDDED_FALLBACK"
        finally:
            isolated_mgr.close()

    def test_fastapi_offline_embedded_scan_communities_metrics_and_graph_views(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient
        import main as main_mod
        from engine.enterprise_manager import EnterpriseManager

        # Build a realistic 4-language polyglot workspace (.py, .go, .sol, .jinja2)
        workspace = tmp_path / "polyglot_repo"
        (workspace / "api").mkdir(parents=True)
        (workspace / "services").mkdir(parents=True)
        (workspace / "contracts").mkdir(parents=True)
        (workspace / "templates").mkdir(parents=True)

        (workspace / "api" / "runner.py").write_text(
            "import os\n"
            "def execute_shell(cmd):\n"
            "    if cmd:\n"
            "        os.system(cmd)\n"
            "    return True\n\n"
            "def handle_request(request):\n"
            "    user_cmd = request.args.get('cmd')\n"
            "    return execute_shell(user_cmd)\n",
            encoding="utf-8",
        )
        (workspace / "services" / "worker.go").write_text(
            'package services\n'
            'import "os/exec"\n'
            'func RunJob(userCmd string) error {\n'
            '    cmd := exec.Command("sh", "-c", userCmd)\n'
            '    return cmd.Run()\n'
            '}\n',
            encoding="utf-8",
        )
        (workspace / "contracts" / "TreasuryVault.sol").write_text(
            "pragma solidity ^0.8.20;\n"
            "contract TreasuryVault {\n"
            "    mapping(address => uint256) public balances;\n"
            "    function withdraw() external {\n"
            "        uint256 amount = balances[msg.sender];\n"
            '        (bool ok, ) = msg.sender.call{value: amount}("");\n'
            "        require(ok);\n"
            "        balances[msg.sender] = 0;\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        (workspace / "templates" / "profile.jinja2").write_text(
            "<html>\n"
            "<body>\n"
            "  <div class='bio'>{{ user_bio | safe }}</div>\n"
            "  <form method='post' action='/profile/update'>\n"
            "    <input type='text' name='bio' />\n"
            "    <button type='submit'>Save</button>\n"
            "  </form>\n"
            "</body>\n"
            "</html>\n",
            encoding="utf-8",
        )

        # Force Zero-Docker Embedded mode + simulate offline Neo4j
        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "embedded")
        monkeypatch.setattr(
            main_mod.neo4j_client,
            "verify_connectivity_and_apoc",
            mock.MagicMock(side_effect=ConnectionRefusedError("Neo4j Docker stopped")),
        )

        # Isolate all mutable globals + EnterpriseManager so test never pollutes disk or other tests
        isolated_mgr = GraphStoreManager(
            neo4j_client=main_mod.neo4j_client,
            vault_dir=str(tmp_path / ".alastor_vault"),
        )
        isolated_em = EnterpriseManager()
        monkeypatch.setattr(isolated_em, "_save_persisted_state", lambda: None)
        monkeypatch.setattr(isolated_em, "_save_scan_cache", lambda: None)
        monkeypatch.setattr(main_mod, "enterprise_mgr", isolated_em)
        monkeypatch.setattr(main_mod, "graph_store_mgr", isolated_mgr)
        monkeypatch.setattr(main_mod, "current_scan_dir", str(workspace))
        monkeypatch.setattr(main_mod, "current_app_tree", None)
        monkeypatch.setattr(main_mod, "current_community_map", None)
        monkeypatch.setattr(main_mod, "_cached_findings", None)
        monkeypatch.setattr(main_mod, "_cached_external_findings", [])
        monkeypatch.setattr(main_mod, "_cached_advisories", [])
        monkeypatch.setattr(main_mod, "_last_neo4j_ingested_dir", None)
        monkeypatch.setattr(main_mod, "_last_scope_telemetry", None)
        monkeypatch.setattr(main_mod, "_last_languages_detected", {})
        monkeypatch.setattr(main_mod, "_last_scanned_files", [])
        monkeypatch.setattr(main_mod, "_last_cpg_nodes", [])
        monkeypatch.setattr(main_mod, "_last_cpg_edges", [])

        try:
            client = TestClient(main_mod.app)

            # 1. POST /api/scan in Offline Embedded SQLite mode
            scan_resp = client.post("/api/scan", json={"target_path": str(workspace)})
            assert scan_resp.status_code == 200, scan_resp.text
            scan_body = scan_resp.json()
            assert scan_body["status"] == "SUCCESS"
            assert scan_body["graph_engine_mode"] == "EMBEDDED_SQLITE"
            assert scan_body["nodes_created"] > 0
            assert scan_body["edges_created"] > 0
            assert scan_body["communities_count"] >= 1
            for lang_k in ("python", "go", "solidity", "web_template"):
                assert scan_body["languages_detected"].get(lang_k, 0) >= 1
            assert scan_body["scope_telemetry"] is not None
            assert scan_body["scope_telemetry"]["total_discovered"] >= 4

            # 2. GET /api/findings returns enriched polyglot findings
            findings_resp = client.get("/api/findings")
            assert findings_resp.status_code == 200
            findings_body = findings_resp.json()
            found_rule_ids = {f["rule_id"] for f in findings_body}
            for req_rule in (
                "RULE-1-TAINT",
                "RULE-27-POLYGLOT-CMDI",
                "RULE-30-SOLIDITY-REENTRANCY",
                "RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI",
                "RULE-33-TEMPLATE-MISSING-CSRF",
            ):
                assert req_rule in found_rule_ids, f"Missing {req_rule}; got {sorted(found_rule_ids)}"
            for f_item in findings_body:
                assert f_item.get("plain_english_summary"), f"Missing plain_english_summary on {f_item['rule_id']}"
                assert f_item.get("raci_responsible"), f"Missing raci_responsible on {f_item['rule_id']}"

            # 3. GET /api/metrics returns HTTP 200 with EMBEDDED_SQLITE + polyglot telemetry
            metrics_resp = client.get("/api/metrics")
            assert metrics_resp.status_code == 200
            metrics_body = metrics_resp.json()
            assert metrics_body["graph_engine_mode"] == "EMBEDDED_SQLITE"
            assert metrics_body["total_nodes"] > 0
            assert metrics_body["total_edges"] > 0
            assert metrics_body["communities_count"] >= 1
            assert metrics_body["scope_telemetry"] is not None
            assert metrics_body["languages_detected"].get("solidity", 0) >= 1

            # 4. GET /api/graph/communities returns Leiden community & bridge map
            comm_resp = client.get("/api/graph/communities")
            assert comm_resp.status_code == 200
            comm_body = comm_resp.json()
            assert comm_body["graph_engine_mode"] == "EMBEDDED_SQLITE"
            assert comm_body["total_communities"] >= 1
            assert len(comm_body["communities"]) == comm_body["total_communities"]

            # 5. GET /api/graph across COMMUNITY_MAP, ENTRYPOINT_GRAPH, DFG_ONLY, CFG_ONLY, CALL_GRAPH, SPIDER, APP_TREE, FULL_CPG, FINDING_PATH
            for vm in ("COMMUNITY_MAP", "ENTRYPOINT_GRAPH", "DFG_ONLY", "CFG_ONLY", "CALL_GRAPH", "APP_TREE", "SPIDER", "FULL_CPG"):
                g_resp = client.get("/api/graph", params={"view_mode": vm})
                assert g_resp.status_code == 200, f"view_mode={vm} failed: {g_resp.text}"
                g_body = g_resp.json()
                assert len(g_body["nodes"]) >= 1, f"view_mode={vm} returned 0 nodes"

            fp_resp = client.get("/api/graph", params={"view_mode": "FINDING_PATH", "finding_id": findings_body[0]["id"]})
            assert fp_resp.status_code == 200
            assert len(fp_resp.json()["nodes"]) >= 1

            loc_resp = client.get("/api/node-at-location", params={"filepath": "api/runner.py", "line": 4})
            assert loc_resp.status_code == 200
            assert loc_resp.json()["node"] is not None

            # Empty or slash-only filepath must return {"node": None} (never match every node via endswith(""))
            for empty_fp in ("", "/", "\\", "   "):
                empty_loc = client.get("/api/node-at-location", params={"filepath": empty_fp, "line": 1})
                assert empty_loc.status_code == 200
                assert empty_loc.json() == {"node": None}, f"Expected None for filepath={empty_fp!r}"
        finally:
            isolated_mgr.close()

    def test_fastapi_startup_auto_failover_when_neo4j_offline(self, tmp_path, monkeypatch):
        import main as main_mod

        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "auto")
        offline_neo4j = mock.MagicMock()
        offline_neo4j.verify_connectivity_and_apoc.side_effect = ConnectionRefusedError("Bolt port 7687 closed")

        isolated_mgr = GraphStoreManager(
            neo4j_client=offline_neo4j,
            vault_dir=str(tmp_path / ".alastor_vault"),
        )
        # Pre-seed a community map to confirm startup_event restores it
        seeded_cm = detect_code_communities([_mk_node("s1", filepath="svc/app.py")], [], graph_engine_mode="EMBEDDED_SQLITE")
        isolated_mgr.ensure_backend(force_probe=True)
        isolated_mgr.save_communities(seeded_cm)
        # Reset _active_store so startup_event triggers a fresh auto probe
        isolated_mgr._active_store = None

        monkeypatch.setattr(main_mod, "graph_store_mgr", isolated_mgr)
        monkeypatch.setattr(main_mod, "current_scan_dir", str(tmp_path))
        monkeypatch.setattr(main_mod, "current_community_map", None)

        try:
            main_mod.startup_event()
            assert isolated_mgr.mode == "EMBEDDED_SQLITE"
            assert main_mod.current_community_map is not None
            assert main_mod.current_community_map.total_communities == 1
        finally:
            isolated_mgr.close()

    def test_enterprise_rule_catalog_includes_all_12_polyglot_rules(self):
        from engine.enterprise_manager import EnterpriseManager
        from engine.polyglot_rules import POLYGLOT_RULE_CATALOG

        em = EnterpriseManager()
        query_ids = {q.id for q in em.queries}
        settings_q_ids = {q.id for q in em.get_settings_response().queries}

        sample_file_by_lang = {
            "c": "native/buffer.c",
            "cpp": "native/mem.cpp",
            "rust": "crates/ffi/src/lib.rs",
            "go": "services/query.go",
            "java": "src/main/java/App.java",
            "solidity": "contracts/Vault.sol",
            "web_template": "templates/index.jinja2",
        }

        raw_findings: List[Finding] = []
        for idx, spec in enumerate(POLYGLOT_RULE_CATALOG):
            rid = spec["id"]
            assert rid in query_ids, f"{rid} missing from EnterpriseManager.queries"
            assert rid in settings_q_ids, f"{rid} missing from get_settings().queries"
            first_lang = spec["languages"][0]
            fp = sample_file_by_lang.get(first_lang, "app/sample.py")
            raw_findings.append(
                Finding(
                    id=f"poly-test-{idx:02d}",
                    rule_id=rid,
                    severity=spec["severity"],
                    title=spec["name"],
                    description=spec["description"],
                    cwe_id=spec["cwe_id"],
                    owasp_category=spec["owasp_category"],
                    cvss_score=float(spec["cvss_score"]),
                    remediation=spec["remediation"],
                    path_nodes=[
                        {
                            "id": f"pn-{idx}",
                            "label": "Call",
                            "name": "sink_call",
                            "code": "vulnerable_sink(user_input)",
                            "filepath": fp,
                            "start_line": 12 + idx,
                            "end_line": 12 + idx,
                            "start_col": 4,
                            "end_col": 32,
                            "is_source": False,
                            "is_sink": True,
                            "is_sanitizer": False,
                        }
                    ],
                    path_edges=[],
                    scan_engine="SAST",
                )
            )

        enriched = em.enrich_findings(raw_findings)
        assert len(enriched) == len(POLYGLOT_RULE_CATALOG) == 12
        for ef in enriched:
            assert ef.plain_english_summary and len(ef.plain_english_summary) > 20
            assert ef.non_coder_analogy and len(ef.non_coder_analogy) > 15
            assert "electrical panel" not in ef.non_coder_analogy, f"{ef.rule_id} fell through to generic analogy"
            assert ef.business_impact and len(ef.business_impact) > 15
            assert ef.management_action_steps and len(ef.management_action_steps) >= 1
            assert ef.raci_responsible
            assert ef.raci_accountable
            assert ef.best_fix_location is not None
            # Verify no out-of-Literal mutations occurred during enrichment
            validated = Finding.model_validate(ef.model_dump())
            assert validated.rule_id == ef.rule_id

    def test_enrichment_regression_polyglot_deser_and_rule15_tls_bypass(self):
        from engine.enterprise_manager import EnterpriseManager

        em = EnterpriseManager()

        java_deser = Finding(
            id="reg-deser-java",
            rule_id="RULE-28-POLYGLOT-DESER",
            severity="CRITICAL",
            title="Polyglot Unsafe Native Object Deserialization",
            description="Java ObjectInputStream.readObject deserializes untrusted stream.",
            cwe_id="CWE-502",
            owasp_category="A08:2021 - Software and Data Integrity Failures",
            cvss_score=9.8,
            remediation="Use schema-validated JSON parsers or strict ObjectInputFilter allowlists instead of ObjectInputStream.readObject.",
            path_nodes=[
                {
                    "id": "java-deser-1",
                    "label": "Call",
                    "name": "ois.readObject",
                    "code": "Object obj = new ObjectInputStream(in).readObject();",
                    "filepath": "src/main/java/PayloadHandler.java",
                    "start_line": 24,
                    "end_line": 24,
                    "start_col": 8,
                    "end_col": 58,
                    "is_source": False,
                    "is_sink": True,
                    "is_sanitizer": False,
                }
            ],
            path_edges=[],
            scan_engine="SAST",
        )

        tls_bypass = Finding(
            id="reg-rule15-tls",
            rule_id="RULE-15-XXE-TLS-BYPASS",
            severity="HIGH",
            title="Disabled TLS Certificate Verification (verify=False)",
            description="HTTPS client disables TLS certificate verification via verify=False.",
            cwe_id="CWE-611",
            owasp_category="A05:2021 - Security Misconfiguration",
            cvss_score=7.5,
            remediation="Enable TLS certificate verification (verify=True) and use trusted CA bundles.",
            path_nodes=[
                {
                    "id": "py-tls-1",
                    "label": "Call",
                    "name": "requests.get",
                    "code": "resp = requests.get(endpoint, verify=False)",
                    "filepath": "api/client.py",
                    "start_line": 14,
                    "end_line": 14,
                    "start_col": 4,
                    "end_col": 47,
                    "is_source": False,
                    "is_sink": True,
                    "is_sanitizer": False,
                }
            ],
            path_edges=[],
            scan_engine="SAST",
        )

        weak_md5 = Finding(
            id="reg-rule13-md5",
            rule_id="RULE-13-UNSAFE-DESERIALIZATION-CRYPTO",
            severity="HIGH",
            title="Weak Cryptographic Digest (MD5)",
            description="Weak hash algorithm hashlib.md5 used for password/token digest.",
            cwe_id="CWE-502",
            owasp_category="A02:2021 - Cryptographic Failures",
            cvss_score=7.5,
            remediation="",
            path_nodes=[
                {
                    "id": "py-md5-1",
                    "label": "Call",
                    "name": "hashlib.md5",
                    "code": "h = hashlib.md5(user_secret.encode()).hexdigest()",
                    "filepath": "api/crypto.py",
                    "start_line": 9,
                    "end_line": 9,
                    "start_col": 4,
                    "end_col": 53,
                    "is_source": False,
                    "is_sink": True,
                    "is_sanitizer": False,
                }
            ],
            path_edges=[],
            scan_engine="SAST",
        )

        enriched = em.enrich_findings([java_deser, tls_bypass, weak_md5])
        by_id = {f.id: f for f in enriched}

        # 1. RULE-28-POLYGLOT-DESER (Java ObjectInputStream) must NEVER emit hashlib.sha256
        ef_deser = by_id["reg-deser-java"]
        assert ef_deser.best_fix_location is not None
        assert "hashlib.sha256" not in ef_deser.best_fix_location.recommended_fix
        assert "JSON" in ef_deser.best_fix_location.recommended_fix or "ObjectInputFilter" in ef_deser.best_fix_location.recommended_fix

        # 2. RULE-15-XXE-TLS-BYPASS with verify=False must NOT be mislabeled as XML XXE
        ef_tls = by_id["reg-rule15-tls"]
        assert ef_tls.best_fix_location is not None
        assert "factory.setFeature" not in ef_tls.best_fix_location.recommended_fix
        assert "XML parser" not in ef_tls.plain_english_summary
        assert "TLS" in ef_tls.plain_english_summary or "certificate" in ef_tls.plain_english_summary.lower()
        assert "verify=True" in ef_tls.best_fix_location.recommended_fix or "TLS" in ef_tls.best_fix_location.recommended_fix

        # 3. RULE-13-UNSAFE-DESERIALIZATION-CRYPTO with hashlib.md5 MUST still emit hashlib.sha256
        ef_md5 = by_id["reg-rule13-md5"]
        assert ef_md5.best_fix_location is not None
        assert "hashlib.sha256" in ef_md5.best_fix_location.recommended_fix

    def test_log_domain_sanitizer_clears_rule12_only_and_never_shell_path_url(self, tmp_path):
        store = EmbeddedGraphStore(str(tmp_path / "log_domain_parity.db"))
        try:
            # 1. source -> _sanitize_log(["LOG"]) -> os.system (SHELL) => MUST FLAG RULE-1!
            src_sh = _mk_node("src_sh", label="Parameter", name="cmd", code="cmd", filepath="sh.py", start_line=2, is_source=True)
            san_sh = _mk_node("san_sh", label="Call", name="_sanitize_log", code="_sanitize_log(cmd)", filepath="sh.py", start_line=3, is_sanitizer=True, sanitizer_domains=["LOG"])
            sink_sh = _mk_node("sink_sh", label="Call", name="os.system", code="os.system(clean_sh)", filepath="sh.py", start_line=4, is_sink=True, sink_domain="SHELL")

            # 2. source -> _sanitize_log(["LOG"]) -> open (PATH) => MUST FLAG RULE-10!
            src_pt = _mk_node("src_pt", label="Parameter", name="fname", code="fname", filepath="pt.py", start_line=2, is_source=True)
            san_pt = _mk_node("san_pt", label="Call", name="_sanitize_log", code="_sanitize_log(fname)", filepath="pt.py", start_line=3, is_sanitizer=True, sanitizer_domains=["LOG"])
            sink_pt = _mk_node("sink_pt", label="Call", name="open", code="open(clean_pt)", filepath="pt.py", start_line=4, is_sink=False, sink_domain="PATH")

            # 3. source -> _sanitize_log(["LOG"]) -> requests.get (URL) => MUST FLAG RULE-11!
            src_url = _mk_node("src_url", label="Parameter", name="target_url", code="target_url", filepath="url.py", start_line=2, is_source=True)
            san_url = _mk_node("san_url", label="Call", name="_sanitize_log", code="_sanitize_log(target_url)", filepath="url.py", start_line=3, is_sanitizer=True, sanitizer_domains=["LOG"])
            sink_url = _mk_node("sink_url", label="Call", name="requests.get", code="requests.get(clean_url)", filepath="url.py", start_line=4, is_sink=False, sink_domain="URL")

            # 4. source -> _sanitize_log(["LOG"]) -> logger.info (LOG) => MUST BE NEUTRALIZED (0 RULE-12)!
            src_log_safe = _mk_node("src_log_safe", label="Parameter", name="user_msg", code="user_msg", filepath="log_ok.py", start_line=2, is_source=True)
            san_log_safe = _mk_node("san_log_safe", label="Call", name="_sanitize_log", code="_sanitize_log(user_msg)", filepath="log_ok.py", start_line=3, is_sanitizer=True, sanitizer_domains=["LOG"])
            sink_log_safe = _mk_node("sink_log_safe", label="Call", name="logger.info", code='logger.info(f"msg={clean_msg}")', filepath="log_ok.py", start_line=4)

            # 5. source -> shlex.quote(["SHELL"]) -> logger.info (LOG) => MUST STILL FLAG RULE-12!
            src_log_bad = _mk_node("src_log_bad", label="Parameter", name="raw_msg", code="raw_msg", filepath="log_bad.py", start_line=2, is_source=True)
            san_log_wrong = _mk_node("san_log_wrong", label="Call", name="shlex.quote", code="shlex.quote(raw_msg)", filepath="log_bad.py", start_line=3, is_sanitizer=True, sanitizer_domains=["SHELL"])
            sink_log_bad = _mk_node("sink_log_bad", label="Call", name="logger.info", code='logger.info(f"msg={quoted_msg}")', filepath="log_bad.py", start_line=4)

            nodes = [
                src_sh, san_sh, sink_sh,
                src_pt, san_pt, sink_pt,
                src_url, san_url, sink_url,
                src_log_safe, san_log_safe, sink_log_safe,
                src_log_bad, san_log_wrong, sink_log_bad,
            ]
            edges = [
                _mk_edge("src_sh", "san_sh", "DFG_FLOWS_TO", "cmd"),
                _mk_edge("san_sh", "sink_sh", "DFG_FLOWS_TO", "clean_sh"),
                _mk_edge("src_pt", "san_pt", "DFG_FLOWS_TO", "fname"),
                _mk_edge("san_pt", "sink_pt", "DFG_FLOWS_TO", "clean_pt"),
                _mk_edge("src_url", "san_url", "DFG_FLOWS_TO", "target_url"),
                _mk_edge("san_url", "sink_url", "DFG_FLOWS_TO", "clean_url"),
                _mk_edge("src_log_safe", "san_log_safe", "DFG_FLOWS_TO", "user_msg"),
                _mk_edge("san_log_safe", "sink_log_safe", "DFG_FLOWS_TO", "clean_msg"),
                _mk_edge("src_log_bad", "san_log_wrong", "DFG_FLOWS_TO", "raw_msg"),
                _mk_edge("san_log_wrong", "sink_log_bad", "DFG_FLOWS_TO", "quoted_msg"),
            ]
            store.ingest_cpg(nodes, edges)

            findings = store.run_cpg_rules(
                enabled_rule_ids={
                    "RULE-1-TAINT",
                    "RULE-10-PATH-TRAVERSAL",
                    "RULE-11-SSRF-URLOPEN",
                    "RULE-12-LOG-INJECTION",
                }
            )
            from collections import defaultdict
            by_rule = defaultdict(list)
            for f in findings:
                by_rule[f.rule_id].append(f.path_nodes[-1]["id"])

            assert "sink_sh" in by_rule["RULE-1-TAINT"]
            assert "sink_pt" in by_rule["RULE-10-PATH-TRAVERSAL"]
            assert "sink_url" in by_rule["RULE-11-SSRF-URLOPEN"]
            assert "sink_log_safe" not in by_rule["RULE-12-LOG-INJECTION"]
            assert "sink_log_bad" in by_rule["RULE-12-LOG-INJECTION"]
        finally:
            store.close()

    def test_custom_sanitizer_endpoint_updates_embedded_sqlite_and_clears_finding_immediately(
        self, tmp_path, monkeypatch
    ):
        from fastapi.testclient import TestClient
        import main as main_mod
        from compiler.ast_parser import SANITIZER_PATTERNS
        from engine.enterprise_manager import EnterpriseManager

        workspace = tmp_path / "custom_san_app"
        workspace.mkdir()
        (workspace / "app.py").write_text(
            "import os\n"
            "def custom_guard(val):\n"
            "    return val\n"
            "def run_cmd(request):\n"
            "    raw = request.args.get('cmd')\n"
            "    checked = custom_guard(raw)\n"
            "    os.system(checked)\n",
            encoding="utf-8",
        )

        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "embedded")
        isolated_mgr = GraphStoreManager(
            neo4j_client=main_mod.neo4j_client,
            vault_dir=str(tmp_path / ".alastor_vault"),
        )
        isolated_em = EnterpriseManager()
        monkeypatch.setattr(isolated_em, "_save_persisted_state", lambda: None)
        monkeypatch.setattr(isolated_em, "_save_scan_cache", lambda: None)
        monkeypatch.setattr(main_mod, "enterprise_mgr", isolated_em)
        monkeypatch.setattr(main_mod, "graph_store_mgr", isolated_mgr)
        monkeypatch.setattr(main_mod, "current_scan_dir", str(workspace))
        monkeypatch.setattr(main_mod, "current_app_tree", None)
        monkeypatch.setattr(main_mod, "current_community_map", None)
        monkeypatch.setattr(main_mod, "_cached_findings", None)
        monkeypatch.setattr(main_mod, "_cached_external_findings", [])
        monkeypatch.setattr(main_mod, "_cached_advisories", [])
        monkeypatch.setattr(main_mod, "_last_neo4j_ingested_dir", None)
        monkeypatch.setattr(main_mod, "_last_scope_telemetry", None)
        monkeypatch.setattr(main_mod, "_last_languages_detected", {})
        monkeypatch.setattr(main_mod, "_last_scanned_files", [])
        monkeypatch.setattr(main_mod, "_last_cpg_nodes", [])
        monkeypatch.setattr(main_mod, "_last_cpg_edges", [])

        try:
            client = TestClient(main_mod.app)
            scan_resp = client.post("/api/scan", json={"target_path": str(workspace)})
            assert scan_resp.status_code == 200, scan_resp.text

            before_findings = client.get("/api/findings").json()
            assert any(f["rule_id"] == "RULE-1-TAINT" for f in before_findings)

            # Register custom_guard as a custom sanitizer -> must update SQLite + memory in-place
            san_resp = client.post(
                "/api/settings/sanitizers",
                json={
                    "function_name": "custom_guard",
                    "language": "python",
                    "target_cwe": "CWE-78",
                    "description": "Custom allowlist shell guard",
                },
            )
            assert san_resp.status_code == 200, san_resp.text
            san_id = san_resp.json()["id"]

            after_findings = client.get("/api/findings").json()
            assert not any(f["rule_id"] == "RULE-1-TAINT" for f in after_findings)

            # Verify SQLite persisted the sanitizer update across fresh reload
            reloaded = EmbeddedGraphStore(isolated_mgr._db_path)
            try:
                reloaded_rules = reloaded.run_cpg_rules(enabled_rule_ids={"RULE-1-TAINT"})
                assert reloaded_rules == []
            finally:
                reloaded.close()

            # Toggle custom sanitizer OFF -> finding must immediately re-appear
            toggle_resp = client.post(f"/api/settings/sanitizers/{san_id}/toggle")
            assert toggle_resp.status_code == 200
            assert toggle_resp.json()["active"] is False

            reopened_findings = client.get("/api/findings").json()
            assert any(f["rule_id"] == "RULE-1-TAINT" for f in reopened_findings)
        finally:
            SANITIZER_PATTERNS.discard("custom_guard")
            isolated_mgr.close()

    def test_project_activation_isolates_languages_scope_telemetry_and_communities(
        self, tmp_path, monkeypatch
    ):
        from fastapi.testclient import TestClient
        import main as main_mod
        from engine.enterprise_manager import EnterpriseManager

        proj_a_dir = tmp_path / "project_alpha"
        proj_b_dir = tmp_path / "project_beta"
        (proj_a_dir / "api").mkdir(parents=True)
        (proj_b_dir / "cmd").mkdir(parents=True)

        (proj_a_dir / "api" / "service.py").write_text(
            "import os\ndef handler(req):\n    os.system(req.args.get('x'))\n",
            encoding="utf-8",
        )
        (proj_a_dir / ".gitignore").write_text("ignored_secret.py\n", encoding="utf-8")
        (proj_a_dir / "ignored_secret.py").write_text("X = 1\n", encoding="utf-8")

        (proj_b_dir / "cmd" / "server.go").write_text(
            'package main\nfunc main() {}\n',
            encoding="utf-8",
        )

        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "embedded")
        isolated_mgr = GraphStoreManager(
            neo4j_client=main_mod.neo4j_client,
            vault_dir=str(tmp_path / ".alastor_vault"),
        )
        isolated_em = EnterpriseManager()
        monkeypatch.setattr(isolated_em, "_save_persisted_state", lambda: None)
        monkeypatch.setattr(isolated_em, "_save_scan_cache", lambda: None)
        monkeypatch.setattr(main_mod, "enterprise_mgr", isolated_em)
        monkeypatch.setattr(main_mod, "graph_store_mgr", isolated_mgr)
        monkeypatch.setattr(main_mod, "current_scan_dir", str(proj_a_dir))
        monkeypatch.setattr(main_mod, "current_app_tree", None)
        monkeypatch.setattr(main_mod, "current_community_map", None)
        monkeypatch.setattr(main_mod, "_cached_findings", None)
        monkeypatch.setattr(main_mod, "_cached_external_findings", [])
        monkeypatch.setattr(main_mod, "_cached_advisories", [])
        monkeypatch.setattr(main_mod, "_last_neo4j_ingested_dir", None)
        monkeypatch.setattr(main_mod, "_last_scope_telemetry", None)
        monkeypatch.setattr(main_mod, "_last_languages_detected", {})
        monkeypatch.setattr(main_mod, "_last_scanned_files", [])
        monkeypatch.setattr(main_mod, "_last_cpg_nodes", [])
        monkeypatch.setattr(main_mod, "_last_cpg_edges", [])

        try:
            client = TestClient(main_mod.app)
            proj_a_resp = client.post(
                "/api/projects",
                json={
                    "name": "Alpha Py",
                    "scm_provider": "LOCAL",
                    "target_path": str(proj_a_dir),
                    "run_scan_immediately": False,
                },
            )
            assert proj_a_resp.status_code == 200, proj_a_resp.text
            proj_a_id = proj_a_resp.json()["id"]

            proj_b_resp = client.post(
                "/api/projects",
                json={
                    "name": "Beta Go",
                    "scm_provider": "LOCAL",
                    "target_path": str(proj_b_dir),
                    "run_scan_immediately": False,
                },
            )
            assert proj_b_resp.status_code == 200, proj_b_resp.text
            proj_b_id = proj_b_resp.json()["id"]

            # Scan Project A -> populates python language, gitignore_excluded >= 1, communities >= 1
            scan_a = client.post("/api/scan", json={"target_path": str(proj_a_dir)})
            assert scan_a.status_code == 200, scan_a.text
            metrics_a = client.get("/api/metrics").json()
            assert metrics_a["languages_detected"].get("python", 0) >= 1
            assert metrics_a["scope_telemetry"] is not None
            assert metrics_a["scope_telemetry"]["gitignore_excluded"] >= 1
            assert metrics_a["communities_count"] >= 1
            assert client.get("/api/graph/communities").json()["total_communities"] >= 1

            # Activate Project B -> MUST NOT leak Project A's python language, gitignore telemetry, or communities!
            act_b = client.post(f"/api/projects/{proj_b_id}/activate")
            assert act_b.status_code == 200, act_b.text

            metrics_b = client.get("/api/metrics").json()
            assert "python" not in metrics_b["languages_detected"], (
                f"Project A python leaked into Project B metrics: {metrics_b['languages_detected']}"
            )
            assert metrics_b["languages_detected"].get("go", 0) == 1
            assert metrics_b["scope_telemetry"] is None
            assert metrics_b["communities_count"] == 0

            comm_b = client.get("/api/graph/communities").json()
            assert comm_b["total_communities"] == 0
            assert comm_b["communities"] == []

            # Re-activating Project A restores Project A's telemetry & communities cleanly
            act_a = client.post(f"/api/projects/{proj_a_id}/activate")
            assert act_a.status_code == 200, act_a.text
            metrics_a_again = client.get("/api/metrics").json()
            assert metrics_a_again["languages_detected"].get("python", 0) >= 1
            assert metrics_a_again["communities_count"] >= 1
        finally:
            isolated_mgr.close()

    def test_pass3_verified_log_helper_gets_log_domain_only_and_does_not_clear_shell(
        self, tmp_path, monkeypatch
    ):
        from fastapi.testclient import TestClient
        import main as main_mod
        from engine.enterprise_manager import EnterpriseManager

        workspace = tmp_path / "pass3_domain_app"
        workspace.mkdir()
        (workspace / "service.py").write_text(
            "import os\n"
            "import re\n"
            "import logging\n"
            "logger = logging.getLogger('svc')\n"
            "def _clean_log(val):\n"
            "    return re.sub(r'[\\r\\n]+', ' ', str(val))\n"
            "def endpoint(request):\n"
            "    raw = request.args.get('q')\n"
            "    cleaned = _clean_log(raw)\n"
            "    logger.info(f'user={cleaned}')\n"
            "    os.system(cleaned)\n",
            encoding="utf-8",
        )

        monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "embedded")
        isolated_mgr = GraphStoreManager(
            neo4j_client=main_mod.neo4j_client,
            vault_dir=str(tmp_path / ".alastor_vault"),
        )
        isolated_em = EnterpriseManager()
        monkeypatch.setattr(isolated_em, "_save_persisted_state", lambda: None)
        monkeypatch.setattr(isolated_em, "_save_scan_cache", lambda: None)
        monkeypatch.setattr(main_mod, "enterprise_mgr", isolated_em)
        monkeypatch.setattr(main_mod, "graph_store_mgr", isolated_mgr)
        monkeypatch.setattr(main_mod, "current_scan_dir", str(workspace))
        monkeypatch.setattr(main_mod, "current_app_tree", None)
        monkeypatch.setattr(main_mod, "current_community_map", None)
        monkeypatch.setattr(main_mod, "_cached_findings", None)
        monkeypatch.setattr(main_mod, "_cached_external_findings", [])
        monkeypatch.setattr(main_mod, "_cached_advisories", [])
        monkeypatch.setattr(main_mod, "_last_neo4j_ingested_dir", None)
        monkeypatch.setattr(main_mod, "_last_scope_telemetry", None)
        monkeypatch.setattr(main_mod, "_last_languages_detected", {})
        monkeypatch.setattr(main_mod, "_last_scanned_files", [])
        monkeypatch.setattr(main_mod, "_last_cpg_nodes", [])
        monkeypatch.setattr(main_mod, "_last_cpg_edges", [])

        try:
            client = TestClient(main_mod.app)
            scan_resp = client.post("/api/scan", json={"target_path": str(workspace)})
            assert scan_resp.status_code == 200, scan_resp.text

            clean_calls = [
                n for n in isolated_mgr._embedded_store._nodes.values()
                if n.label == "Call" and n.name == "_clean_log"
            ]
            assert len(clean_calls) >= 1
            assert all(n.is_sanitizer is True and n.sanitizer_domains == ["LOG"] for n in clean_calls)

            findings = client.get("/api/findings").json()
            rule_ids = {f["rule_id"] for f in findings}
            assert "RULE-1-TAINT" in rule_ids, "CRLF _clean_log() must NOT neutralize os.system() SHELL sink"
            assert "RULE-12-LOG-INJECTION" not in rule_ids, "CRLF _clean_log() MUST neutralize logger.info() LOG sink"
        finally:
            isolated_mgr.close()




