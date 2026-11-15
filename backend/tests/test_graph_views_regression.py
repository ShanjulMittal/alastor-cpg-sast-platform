from pathlib import Path
from typing import Any, Dict, List

from fastapi.testclient import TestClient


def test_api_operations_engine_caches_unchanged_workspace_and_invalidates_on_edit_or_triage(
    tmp_path: Path,
    monkeypatch,
):
    from engine.api_operations_engine import ApiOperationsEngine
    from models import BestFixLocation, Finding

    app_file = tmp_path / "service_api.py"
    app_file.write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        '@app.get("/orders/{order_id}")\n'
        "def read_order(order_id: str):\n"
        '    return {"order_id": order_id}\n',
        encoding="utf-8",
    )

    finding = Finding(
        id="FIND-ORDER-1",
        rule_id="RULE-7-SQLI",
        severity="HIGH",
        title="SQL sink in read_order",
        description="Test finding linked to service_api.py",
        cwe_id="CWE-89",
        triage_status="TO_VERIFY",
        path_nodes=[
            {
                "id": "n-1",
                "label": "Call",
                "name": "read_order",
                "code": "return {'order_id': order_id}",
                "filepath": "service_api.py",
                "start_line": 6,
                "end_line": 7,
            }
        ],
        path_edges=[],
        best_fix_location=BestFixLocation(
            node_id="n-1",
            filepath="service_api.py",
            line=6,
            column=4,
            code_snippet="read_order",
            explanation="Validate order_id",
            recommended_fix="int(order_id)",
        ),
    )

    engine = ApiOperationsEngine()
    parse_calls: List[str] = []
    real_index_py = engine._index_python_file

    def counting_index_py(rel_fp: str, src_text: str, graph: Any):
        parse_calls.append(rel_fp)
        return real_index_py(rel_fp, src_text, graph)

    monkeypatch.setattr(engine, "_index_python_file", counting_index_py)

    report_1 = engine.analyze_workspace_api_operations(str(tmp_path), findings=[finding])
    assert report_1.total_endpoints == 1
    assert report_1.vulnerable_endpoints_count == 1
    assert len(parse_calls) == 1

    # Unchanged files + unchanged findings -> must hit cache without re-parsing ASTs
    report_2 = engine.analyze_workspace_api_operations(str(tmp_path), findings=[finding])
    assert report_2.total_endpoints == 1
    assert report_2.vulnerable_endpoints_count == 1
    assert len(parse_calls) == 1

    # Triage status change to NOT_EXPLOITABLE -> must recompute vulnerability correlation
    finding.triage_status = "NOT_EXPLOITABLE"
    report_3 = engine.analyze_workspace_api_operations(str(tmp_path), findings=[finding])
    assert report_3.total_endpoints == 1
    assert report_3.vulnerable_endpoints_count == 0

    # File edit adding a second route -> must invalidate file-stat cache and parse updated source
    app_file.write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        '@app.get("/orders/{order_id}")\n'
        "def read_order(order_id: str):\n"
        '    return {"order_id": order_id}\n\n'
        '@app.post("/orders")\n'
        "def create_order():\n"
        '    return {"created": True}\n',
        encoding="utf-8",
    )
    report_4 = engine.analyze_workspace_api_operations(str(tmp_path), findings=[finding])
    assert report_4.total_endpoints == 2
    assert len(parse_calls) >= 2


def test_entrypoint_graph_synthesizes_callable_flows_when_project_has_zero_http_routes(
    tmp_path: Path,
    monkeypatch,
):
    import main as backend_main
    from compiler.app_tree import AppTreeAnalyzer

    (tmp_path / "worker.go").write_text(
        "package worker\n\n"
        "func ParseManifest(raw string) []string {\n"
        "    return []string{raw}\n"
        "}\n\n"
        "func RunBatchJob(raw string) int {\n"
        "    items := ParseManifest(raw)\n"
        "    return len(items)\n"
        "}\n",
        encoding="utf-8",
    )

    tree = AppTreeAnalyzer(str(tmp_path)).analyze()
    with TestClient(backend_main.app) as client:
        monkeypatch.setattr(backend_main, "current_scan_dir", str(tmp_path))
        monkeypatch.setattr(backend_main, "current_app_tree", tree)
        monkeypatch.setattr(backend_main, "get_or_compute_findings", lambda: [])

        resp = client.get("/api/graph?view_mode=ENTRYPOINT_GRAPH")
        assert resp.status_code == 200
        payload = resp.json()

        nodes = payload.get("nodes", [])
        edges = payload.get("edges", [])
        assert len(nodes) >= 3
        assert len(edges) >= 2
        node_names = " ".join(str(n.get("name", "")) for n in nodes)
        assert "ParseManifest" in node_names or "RunBatchJob" in node_names or "worker.go" in node_names


def test_dfg_only_and_cfg_only_fallback_emit_mode_accurate_edge_types(
    tmp_path: Path,
    monkeypatch,
):
    import main as backend_main
    from compiler.app_tree import AppTreeAnalyzer

    (tmp_path / "ledger_flow.py").write_text(
        "def normalize_amount(raw_val: str) -> float:\n"
        "    return round(float(raw_val.strip()), 2)\n\n"
        "def compute_fee(amount: float) -> float:\n"
        "    return round(amount * 0.02, 2)\n\n"
        "def settle_transfer(raw_val: str) -> dict:\n"
        "    amt = normalize_amount(raw_val)\n"
        "    fee = compute_fee(amt)\n"
        '    return {"amount": amt, "fee": fee}\n',
        encoding="utf-8",
    )

    tree = AppTreeAnalyzer(str(tmp_path)).analyze()
    monkeypatch.setattr(type(backend_main.neo4j_client), "driver", property(lambda _self: None))
    monkeypatch.setattr(backend_main, "current_scan_dir", str(tmp_path))
    monkeypatch.setattr(backend_main, "current_app_tree", tree)

    client = TestClient(backend_main.app)
    dfg_resp = client.get("/api/graph?view_mode=DFG_ONLY")
    assert dfg_resp.status_code == 200
    dfg_data = dfg_resp.json()
    assert len(dfg_data["nodes"]) >= 3
    assert len(dfg_data["edges"]) >= 2
    assert all(e.get("type") == "DFG_FLOWS_TO" for e in dfg_data["edges"])

    cfg_resp = client.get("/api/graph?view_mode=CFG_ONLY")
    assert cfg_resp.status_code == 200
    cfg_data = cfg_resp.json()
    assert len(cfg_data["nodes"]) >= 3
    assert len(cfg_data["edges"]) >= 2
    assert all(str(e.get("type", "")).startswith("CFG_") for e in cfg_data["edges"])


def test_dfg_and_cfg_dedup_preserves_edges_without_explicit_rel_id_and_bounds_node_explosion(
    monkeypatch,
):
    import main as backend_main

    # Simulate Neo4j returning edges whose `id` is None (e.g. relationships created without an `id` property)
    synthetic_nodes: List[Dict[str, Any]] = []
    synthetic_edges: List[Dict[str, Any]] = []
    for idx in range(90):
        src_id = f"cpg-src-{idx}"
        tgt_id = f"cpg-tgt-{idx}"
        synthetic_nodes.append(
            {
                "id": src_id,
                "label": "Identifier",
                "name": f"var_{idx}",
                "code": f"var_{idx} = input_{idx}",
                "filepath": f"mod_{idx % 6}.py",
                "start_line": idx + 1,
                "end_line": idx + 1,
                "scope_id": f"mod_{idx % 6}.py:fn_{idx % 6}",
            }
        )
        synthetic_nodes.append(
            {
                "id": tgt_id,
                "label": "Call",
                "name": f"sink_{idx}",
                "code": f"process(var_{idx})",
                "filepath": f"mod_{idx % 6}.py",
                "start_line": idx + 2,
                "end_line": idx + 2,
                "scope_id": f"mod_{idx % 6}.py:fn_{idx % 6}",
            }
        )
        synthetic_edges.append(
            {
                "id": None,
                "source": src_id,
                "target": tgt_id,
                "type": "DFG_FLOWS_TO",
                "var_name": f"var_{idx}",
            }
        )

    class _FakeRecord(dict):
        pass

    class _FakeResult:
        def single(self):
            return _FakeRecord(all_nodes=synthetic_nodes, all_edges=synthetic_edges)

    class _FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def run(self, *_args, **_kwargs):
            return _FakeResult()

    class _FakeDriver:
        def session(self):
            return _FakeSession()

    monkeypatch.setattr(backend_main.neo4j_client, "driver", _FakeDriver())
    monkeypatch.setattr(backend_main, "current_app_tree", None)

    client = TestClient(backend_main.app)
    resp = client.get("/api/graph?view_mode=DFG_ONLY")
    assert resp.status_code == 200
    payload = resp.json()

    # Must not collapse all `id=None` edges into a single `None` key AND must bound node explosion <= 72 nodes!
    assert len(payload["edges"]) >= 12
    assert all(bool(e.get("id")) for e in payload["edges"])
    assert len(payload["nodes"]) <= 72


def test_entrypoint_graph_with_http_routes_and_operations_renders_downstream_nodes(
    tmp_path: Path,
    monkeypatch,
):
    import main as backend_main
    from models import BestFixLocation, Finding

    (tmp_path / "orders_api.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        '@app.post("/orders/{order_id}/settle")\n'
        "def settle_order(order_id: str, cursor=None):\n"
        '    cursor.execute("INSERT INTO orders (id) VALUES (?)", (order_id,))\n'
        '    return {"settled": order_id}\n',
        encoding="utf-8",
    )

    finding = Finding(
        id="FIND-SETTLE-1",
        rule_id="RULE-7-SQLI",
        severity="HIGH",
        title="SQL operation in settle_order",
        description="Test linked finding",
        cwe_id="CWE-89",
        triage_status="TO_VERIFY",
        path_nodes=[
            {
                "id": "n-sql",
                "label": "Call",
                "name": "cursor.execute",
                "code": "cursor.execute(...)",
                "filepath": "orders_api.py",
                "start_line": 7,
                "end_line": 7,
            }
        ],
        path_edges=[],
        best_fix_location=BestFixLocation(
            node_id="n-sql",
            filepath="orders_api.py",
            line=7,
            column=4,
            code_snippet="cursor.execute(...)",
            explanation="Parameterize query",
            recommended_fix="cursor.execute('...', (order_id,))",
        ),
    )

    monkeypatch.setattr(backend_main, "current_scan_dir", str(tmp_path))
    monkeypatch.setattr(backend_main, "get_or_compute_findings", lambda: [finding])

    client = TestClient(backend_main.app)
    resp = client.get("/api/graph?view_mode=ENTRYPOINT_GRAPH")
    assert resp.status_code == 200
    payload = resp.json()

    assert len(payload["nodes"]) >= 4
    assert len(payload["edges"]) >= 3
    names = " ".join(str(n.get("name", "")) for n in payload["nodes"])
    assert "/orders/{order_id}/settle" in names
    assert "settle_order()" in names
