from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from compiler.app_tree import AppTreeAnalyzer, CrossFileEdge
from engine.remediation_patcher import (
    batch_apply_workspace_patches,
    preview_finding_remediation,
    synthesize_single_node_context_graph,
    undo_workspace_patch,
)
from models import (
    BatchRemediateRequest,
    BatchRemediateResponse,
    BestFixLocation,
    CPGNode,
    Finding,
)


def test_app_tree_extracts_cross_file_imports(tmp_path: Path):
    (tmp_path / "utils").mkdir()
    (tmp_path / "utils" / "Sanitizer.ts").write_text(
        "export function cleanInput(v: string) { return v.trim(); }\n", encoding="utf-8"
    )
    (tmp_path / "api.ts").write_text(
        "import { cleanInput } from './utils/Sanitizer';\nexport function handle(x: string) { return cleanInput(x); }\n",
        encoding="utf-8",
    )
    summary = AppTreeAnalyzer(str(tmp_path)).analyze()
    assert len(summary.cross_file_edges) >= 1
    edge = summary.cross_file_edges[0]
    assert isinstance(edge, CrossFileEdge)
    assert edge.source_filepath == "api.ts"
    assert edge.target_filepath == "utils/Sanitizer.ts"
    assert edge.edge_type == "IMPORTS"
    assert "cleanInput" in edge.symbols

    api_info = next(f for f in summary.flat_files if f.filepath == "api.ts")
    assert "utils/Sanitizer.ts" in api_info.imports_files


def test_app_tree_extracts_python_and_ts_alias_cross_file_imports(tmp_path: Path):
    # Python package with absolute, from-import, and relative imports
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "helpers.py").write_text(
        "def sanitize_sql(q: str) -> str:\n    return q.strip()\n",
        encoding="utf-8",
    )
    (pkg / "db.py").write_text(
        "def query(sql: str):\n    return sql\n",
        encoding="utf-8",
    )
    (pkg / "service.py").write_text(
        "from .helpers import sanitize_sql\nimport pkg.db\n\ndef run(q: str):\n    return pkg.db.query(sanitize_sql(q))\n",
        encoding="utf-8",
    )

    # Frontend TS with @/ alias and /index.tsx resolution + require()
    comp_dir = tmp_path / "frontend" / "src" / "components" / "Badge"
    comp_dir.mkdir(parents=True)
    (comp_dir / "index.tsx").write_text(
        "export const Badge = () => null;\n",
        encoding="utf-8",
    )
    lib_dir = tmp_path / "frontend" / "src" / "lib"
    lib_dir.mkdir(parents=True)
    (lib_dir / "format.js").write_text(
        "module.exports = { fmt: (x) => String(x) };\n",
        encoding="utf-8",
    )
    page_dir = tmp_path / "frontend" / "src" / "app"
    page_dir.mkdir(parents=True)
    (page_dir / "page.tsx").write_text(
        "import { Badge } from '@/components/Badge';\n"
        "const { fmt } = require('../lib/format');\n"
        "export default function Page() { return fmt(Badge); }\n",
        encoding="utf-8",
    )

    summary = AppTreeAnalyzer(str(tmp_path)).analyze()
    pairs = {(e.source_filepath, e.target_filepath): e for e in summary.cross_file_edges}

    assert ("pkg/service.py", "pkg/helpers.py") in pairs
    assert "sanitize_sql" in pairs[("pkg/service.py", "pkg/helpers.py")].symbols
    assert ("pkg/service.py", "pkg/db.py") in pairs
    assert ("frontend/src/app/page.tsx", "frontend/src/components/Badge/index.tsx") in pairs
    assert ("frontend/src/app/page.tsx", "frontend/src/lib/format.js") in pairs

    # Ensure edges are deduplicated
    assert len(pairs) == len(summary.cross_file_edges)


def test_single_node_finding_synthesizes_3_step_directional_chain():
    lone_node = CPGNode(
        id="iac-1", label="Call", ast_type="config", name="Dockerfile:USER root",
        code="USER root", filepath="Dockerfile",
        start_line=8, end_line=8, start_col=0, end_col=9, scope_id="Dockerfile",
        is_source=False, is_sink=True, is_sanitizer=False,
    )
    finding = Finding(
        id="FIND-IAC-1", rule_id="IAC-1", severity="HIGH",
        title="Container Runs as Root", description="Container lacks non-root user.",
        cwe_id="CWE-250", path_nodes=[lone_node], path_edges=[], scan_engine="IaC",
    )
    graph = synthesize_single_node_context_graph(finding)
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2
    assert graph["nodes"][0]["is_source"] is True
    assert graph["nodes"][0]["is_synthesized_context"] is True
    assert graph["nodes"][1]["is_bfl"] is True
    assert graph["nodes"][2]["is_sink"] is True
    assert graph["nodes"][2]["is_synthesized_context"] is True
    assert graph["edges"][0]["step_index"] == 1
    assert graph["edges"][1]["step_index"] == 2
    assert graph["edges"][0]["flow_label"]
    assert graph["edges"][1]["flow_label"]
    assert graph["edges"][0]["type"] == "DFG_FLOWS_TO"
    assert graph["edges"][1]["type"] == "DFG_FLOWS_TO"


def test_single_node_variants_and_multi_node_enrichment():
    # SCA empty path_nodes falling back to best_fix_location
    sca_finding = Finding(
        id="FIND-SCA-1",
        rule_id="SCA-2-LIVE-CVE-LOCKFILE",
        severity="CRITICAL",
        title="Vulnerable requests version",
        cwe_id="CWE-1395",
        scan_engine="SCA",
        path_nodes=[],
        path_edges=[],
        best_fix_location=BestFixLocation(
            filepath="requirements.txt",
            line=3,
            code_snippet="requests==2.25.0",
            recommended_fix="Upgrade requests to >= 2.32.4",
        ),
    )
    sca_graph = synthesize_single_node_context_graph(sca_finding)
    assert len(sca_graph["nodes"]) == 3
    assert sca_graph["nodes"][1]["filepath"] == "requirements.txt"
    assert sca_graph["nodes"][1]["is_bfl"] is True
    assert "CWE-1395" in sca_graph["nodes"][2]["code"]

    # Multi-node finding preserves existing chain and adds step_index + flow_label + is_bfl
    n1 = CPGNode(
        id="src-1", label="Parameter", ast_type="identifier", name="cmd",
        code="cmd: str", filepath="app.py", start_line=4, end_line=4,
        start_col=0, end_col=8, scope_id="run", is_source=True, is_sink=False,
    )
    n2 = CPGNode(
        id="sink-1", label="Call", ast_type="call", name="os.system",
        code="os.system(cmd)", filepath="app.py", start_line=6, end_line=6,
        start_col=4, end_col=18, scope_id="run", is_source=False, is_sink=True,
    )
    multi_finding = Finding(
        id="FIND-TAINT-1",
        rule_id="RULE-1-TAINT",
        severity="CRITICAL",
        title="OS Command Injection",
        cwe_id="CWE-78",
        path_nodes=[n1, n2],
        path_edges=[{"id": "e1", "source": "src-1", "target": "sink-1", "type": "DFG_FLOWS_TO", "var_name": "cmd"}],
        best_fix_location=BestFixLocation(node_id="sink-1", filepath="app.py", line=6),
    )
    m_graph = synthesize_single_node_context_graph(multi_finding)
    assert len(m_graph["nodes"]) == 2
    assert len(m_graph["edges"]) == 1
    assert m_graph["nodes"][1]["is_bfl"] is True
    assert m_graph["edges"][0]["step_index"] == 1
    assert "cmd" in m_graph["edges"][0]["flow_label"]


def test_batch_apply_fixes_multiple_findings_atomically(tmp_path: Path):
    f_py = tmp_path / "service.py"
    f_py.write_text(
        "import hashlib\nimport yaml\n\ndef h(b):\n    return hashlib.md5(b).hexdigest()\n\ndef y(s):\n    return yaml.load(s)\n",
        encoding="utf-8",
    )
    findings = [
        Finding(
            id="F-CRYPTO", rule_id="RULE-3", severity="MEDIUM", title="Weak Hash",
            description="MD5 used", cwe_id="CWE-328",
            path_nodes=[CPGNode(
                id="n-md5", label="Call", ast_type="call", name="hashlib.md5",
                code="return hashlib.md5(b).hexdigest()", filepath="service.py",
                start_line=5, end_line=5, start_col=11, end_col=36, scope_id="h",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
        Finding(
            id="F-YAML", rule_id="RULE-10", severity="HIGH", title="Unsafe YAML",
            description="yaml.load used", cwe_id="CWE-502",
            path_nodes=[CPGNode(
                id="n-yaml", label="Call", ast_type="call", name="yaml.load",
                code="return yaml.load(s)", filepath="service.py",
                start_line=8, end_line=8, start_col=11, end_col=23, scope_id="y",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
    ]
    vault = tmp_path / ".alastor_patches"
    result = batch_apply_workspace_patches(findings, [str(tmp_path)], str(vault))
    assert result["status"] == "BATCH_APPLIED"
    assert result["applied_count"] == 2
    assert result["skipped_count"] == 0
    assert len(result["applied_patch_ids"]) == 2
    assert "service.py" in result["patched_files"]
    assert set(result["applied_finding_ids"]) == {"F-CRYPTO", "F-YAML"}
    assert "--- a/service.py" in result["unified_diff"]
    updated_text = f_py.read_text(encoding="utf-8")
    assert "sha256" in updated_text
    assert "safe_load" in updated_text


def test_batch_apply_handles_import_line_shifts_skips_manual_and_supports_undo(tmp_path: Path):
    f_py = tmp_path / "worker.py"
    original_src = (
        "import os\n"
        "import random\n\n"
        "def run_cmd(cmd):\n"
        "    return os.system(cmd)\n\n"
        "def gen_otp():\n"
        "    tok = random.randint(1000, 9999)\n"
        "    return tok\n"
    )
    f_py.write_text(original_src, encoding="utf-8")

    findings = [
        Finding(
            id="F-CMD",
            rule_id="RULE-1-TAINT",
            severity="CRITICAL",
            title="OS Command Injection",
            cwe_id="CWE-78",
            path_nodes=[CPGNode(
                id="n-cmd", label="Call", ast_type="call", name="os.system",
                code="return os.system(cmd)", filepath="worker.py",
                start_line=5, end_line=5, start_col=4, end_col=25, scope_id="run_cmd",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
        Finding(
            id="F-RNG",
            rule_id="RULE-16-INSECURE-RANDOM-OPEN-REDIRECT",
            severity="MEDIUM",
            title="Predictable PRNG",
            cwe_id="CWE-330",
            path_nodes=[CPGNode(
                id="n-rng", label="Assignment", ast_type="assign", name="tok",
                code="tok = random.randint(1000, 9999)", filepath="worker.py",
                start_line=8, end_line=8, start_col=4, end_col=36, scope_id="gen_otp",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
        Finding(
            id="F-MANUAL",
            rule_id="CUSTOM-MANUAL-ONLY",
            severity="LOW",
            title="Custom Advisory",
            cwe_id="CWE-200",
            path_nodes=[CPGNode(
                id="n-man", label="Return", ast_type="return", name="return",
                code="return tok", filepath="worker.py",
                start_line=9, end_line=9, start_col=4, end_col=14, scope_id="gen_otp",
                is_source=False, is_sink=False, is_sanitizer=False,
            )],
            path_edges=[],
        ),
    ]

    assert preview_finding_remediation(findings[2], [str(tmp_path)])["can_auto_patch"] is False

    vault = tmp_path / ".alastor_patches"
    res = batch_apply_workspace_patches(findings, [str(tmp_path)], str(vault))
    assert res["applied_count"] == 2
    assert res["skipped_count"] == 1
    assert set(res["applied_finding_ids"]) == {"F-CMD", "F-RNG"}

    patched_src = f_py.read_text(encoding="utf-8")
    assert "subprocess.run(" in patched_src
    assert "secrets.token_urlsafe(32)" in patched_src
    assert "import secrets" in patched_src
    assert "import shlex" in patched_src
    assert "ALASTOR BFL Fix Guidance" not in patched_src

    # Undo in reverse order restores exact original file
    for pid in reversed(res["applied_patch_ids"]):
        undo_workspace_patch(pid, [str(tmp_path)], str(vault))
    assert f_py.read_text(encoding="utf-8") == original_src


def test_api_graph_enrichment_and_batch_remediate_endpoint(tmp_path: Path):
    import main

    (tmp_path / "utils").mkdir()
    (tmp_path / "utils" / "Sanitizer.ts").write_text(
        "export function cleanInput(v: string) { return v.trim(); }\n",
        encoding="utf-8",
    )
    (tmp_path / "api.ts").write_text(
        "import { cleanInput } from './utils/Sanitizer';\nexport function handle(x: string) { return cleanInput(x); }\n",
        encoding="utf-8",
    )
    svc_py = tmp_path / "service.py"
    svc_py.write_text(
        "import hashlib\nimport yaml\n\ndef h(b):\n    return hashlib.md5(b).hexdigest()\n\ndef y(s):\n    return yaml.load(s)\n",
        encoding="utf-8",
    )

    lone_finding = Finding(
        id="F-CRYPTO-API",
        rule_id="RULE-3",
        severity="MEDIUM",
        title="Weak MD5 Digest",
        description="MD5 used",
        cwe_id="CWE-328",
        path_nodes=[CPGNode(
            id="n-md5", label="Call", ast_type="call", name="hashlib.md5",
            code="return hashlib.md5(b).hexdigest()", filepath="service.py",
            start_line=5, end_line=5, start_col=11, end_col=36, scope_id="h",
            is_source=False, is_sink=True, is_sanitizer=False,
        )],
        path_edges=[],
    )
    yaml_finding = Finding(
        id="F-YAML-API",
        rule_id="RULE-10",
        severity="HIGH",
        title="Unsafe YAML Load",
        description="yaml.load used",
        cwe_id="CWE-502",
        path_nodes=[CPGNode(
            id="n-yaml", label="Call", ast_type="call", name="yaml.load",
            code="return yaml.load(s)", filepath="service.py",
            start_line=8, end_line=8, start_col=11, end_col=23, scope_id="y",
            is_source=False, is_sink=True, is_sanitizer=False,
        )],
        path_edges=[],
    )

    prev_scan_dir = main.current_scan_dir
    prev_app_tree = main.current_app_tree
    vault_dir = str(tmp_path / ".alastor_patches")

    try:
        main.current_scan_dir = str(tmp_path)
        main.current_app_tree = AppTreeAnalyzer(str(tmp_path)).analyze()
        client = TestClient(main.app)

        # 1. GET /api/graph?view_mode=FINDING_PATH synthesizes 3-node chain
        with patch.object(main, "get_or_compute_findings", return_value=[lone_finding, yaml_finding]):
            fp_resp = client.get("/api/graph", params={"view_mode": "FINDING_PATH", "finding_id": "F-CRYPTO-API"})
            assert fp_resp.status_code == 200
            fp_data = fp_resp.json()
            assert len(fp_data["nodes"]) == 3
            assert len(fp_data["edges"]) == 2
            assert fp_data["edges"][0]["step_index"] == 1
            assert fp_data["edges"][0]["flow_label"]

        # 2. GET /api/graph?view_mode=APP_TREE falls back to current_app_tree when Neo4j has 0 AppFile nodes & includes IMPORTS edge
        mock_session_cm = MagicMock()
        mock_session = MagicMock()
        mock_session.run.return_value.single.return_value = {"all_nodes": [], "all_edges": []}
        mock_session_cm.__enter__.return_value = mock_session
        with patch.object(main.neo4j_client, "driver") as mock_driver:
            mock_driver.session.return_value = mock_session_cm
            tree_resp = client.get("/api/graph", params={"view_mode": "APP_TREE"})
            assert tree_resp.status_code == 200
            tree_data = tree_resp.json()
            node_ids = {n["id"] for n in tree_data["nodes"]}
            assert "file:api.ts" in node_ids
            assert "file:utils/Sanitizer.ts" in node_ids
            import_edges = [e for e in tree_data["edges"] if e["type"] == "IMPORTS"]
            assert any(
                e["id"] == "xfile:api.ts->utils/Sanitizer.ts"
                and e["source"] == "file:api.ts"
                and e["target"] == "file:utils/Sanitizer.ts"
                and e.get("flow_label")
                and isinstance(e.get("step_index"), int)
                and e["step_index"] >= 1
                for e in import_edges
            )
            assert [e["step_index"] for e in tree_data["edges"]] == list(
                range(1, len(tree_data["edges"]) + 1)
            )

        # 2b. GET /api/graph?view_mode=APP_TREE with Neo4j AppFile nodes and current_app_tree=None still appends IMPORTS edges,
        #     and GET /api/app-tree preserves cross_file_edges + imports_files in serialized response.
        main.current_app_tree = None
        mock_session.run.return_value.single.return_value = {
            "all_nodes": [
                {"props": {"id": "file:api.ts", "filepath": "api.ts"}, "label": "AppFile"},
                {"props": {"id": "file:utils/Sanitizer.ts", "filepath": "utils/Sanitizer.ts"}, "label": "AppFile"},
            ],
            "all_edges": [
                {"id": "contains:root->api", "source": "dir:root", "target": "file:api.ts", "type": "CONTAINS", "var_name": None},
            ],
        }
        with patch.object(main.neo4j_client, "driver") as mock_driver:
            mock_driver.session.return_value = mock_session_cm
            neo_tree_resp = client.get("/api/graph", params={"view_mode": "APP_TREE"})
            assert neo_tree_resp.status_code == 200
            neo_edges = neo_tree_resp.json()["edges"]
            assert any(e["type"] == "IMPORTS" and "cleanInput" in (e.get("flow_label") or "") for e in neo_edges)
            assert any(e["type"] == "CONTAINS" and e.get("flow_label") == "CONTAINS ▶" for e in neo_edges)
            assert [e["step_index"] for e in neo_edges] == list(range(1, len(neo_edges) + 1))

            # DFG_ONLY edge humanization + step_index check
            mock_session.run.return_value.single.return_value = {
                "all_nodes": [
                    {"id": "n1", "label": "Parameter", "filepath": "api.ts", "start_line": 1, "end_line": 1},
                    {"id": "n2", "label": "Call", "filepath": "api.ts", "start_line": 2, "end_line": 2},
                ],
                "all_edges": [
                    {"id": "dfg-1", "source": "n1", "target": "n2", "type": "DFG_FLOWS_TO", "var_name": "x"},
                ],
            }
            dfg_resp = client.get("/api/graph", params={"view_mode": "DFG_ONLY"})
            assert dfg_resp.status_code == 200
            dfg_edges = dfg_resp.json()["edges"]
            assert len(dfg_edges) == 1
            assert dfg_edges[0]["flow_label"] == "TAINT (x) ▶"
            assert dfg_edges[0]["step_index"] == 1

        app_tree_resp = client.get("/api/app-tree")
        assert app_tree_resp.status_code == 200
        app_tree_json = app_tree_resp.json()
        assert any(
            ce["source_filepath"] == "api.ts" and ce["target_filepath"] == "utils/Sanitizer.ts"
            for ce in app_tree_json["cross_file_edges"]
        )

        # 3. POST /api/remediate/batch-apply fixes both findings & runs single CPG re-scan
        with (
            patch.object(main, "_get_authorized_remediation_roots", return_value=[str(tmp_path)]),
            patch.object(main, "_get_remediation_vault_root", return_value=vault_dir),
            patch.object(main, "scan_project", return_value=None) as mock_scan,
            patch.object(
                main,
                "get_or_compute_findings",
                side_effect=[[lone_finding, yaml_finding], []],
            ),
        ):
            req_payload = BatchRemediateRequest(finding_ids=["F-CRYPTO-API", "F-YAML-API"]).model_dump()
            batch_resp = client.post("/api/remediate/batch-apply", json=req_payload)
            assert batch_resp.status_code == 200
            parsed = BatchRemediateResponse(**batch_resp.json())
            assert parsed.status == "BATCH_APPLIED"
            assert parsed.applied_count == 2
            assert parsed.verified_severed_count == 2
            assert parsed.remaining_findings_count == 0
            assert "service.py" in parsed.patched_files
            assert "sha256" in parsed.unified_diff
            assert "safe_load" in parsed.unified_diff
            assert mock_scan.call_count == 1

        # 4. POST /api/remediate/batch-apply maps FileNotFoundError -> 404 and ValueError -> 409
        with (
            patch.object(main, "get_or_compute_findings", return_value=[lone_finding]),
            patch.object(main, "batch_apply_workspace_patches", side_effect=ValueError("SHA256 mismatch")),
        ):
            conflict_resp = client.post(
                "/api/remediate/batch-apply",
                json=BatchRemediateRequest(finding_ids=["F-CRYPTO-API"]).model_dump(),
            )
            assert conflict_resp.status_code == 409

        with (
            patch.object(main, "get_or_compute_findings", return_value=[lone_finding]),
            patch.object(main, "batch_apply_workspace_patches", side_effect=FileNotFoundError("Missing file")),
        ):
            missing_resp = client.post(
                "/api/remediate/batch-apply",
                json=BatchRemediateRequest(finding_ids=["F-CRYPTO-API"]).model_dump(),
            )
            assert missing_resp.status_code == 404
    finally:
        main.current_scan_dir = prev_scan_dir
        main.current_app_tree = prev_app_tree


def test_batch_apply_skips_duplicate_same_line_and_handles_large_line_shifts(tmp_path: Path):
    import engine.remediation_patcher as rp

    # File has TWO identical statements on lines 4 and 5; TWO findings both target line 5!
    # The duplicate finding on line 5 must be skipped (NOT jump to line 4 via offset probing).
    dup_py = tmp_path / "dup_service.py"
    dup_py.write_text(
        "import hashlib\n\ndef pair(a, b):\n    x = hashlib.md5(a).hexdigest()\n    x = hashlib.md5(a).hexdigest()\n    return x\n",
        encoding="utf-8",
    )
    dup_findings = [
        Finding(
            id="F-DUP-1",
            rule_id="RULE-3",
            severity="MEDIUM",
            title="Weak Hash #1",
            description="MD5 at line 5",
            cwe_id="CWE-328",
            path_nodes=[CPGNode(
                id="n-dup-1", label="Call", ast_type="call", name="hashlib.md5",
                code="x = hashlib.md5(a).hexdigest()", filepath="dup_service.py",
                start_line=5, end_line=5, start_col=4, end_col=34, scope_id="pair",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
        Finding(
            id="F-DUP-2",
            rule_id="RULE-13-UNSAFE-DESERIALIZATION-CRYPTO",
            severity="MEDIUM",
            title="Weak Hash #2 (same line)",
            description="Duplicate finding on line 5",
            cwe_id="CWE-328",
            path_nodes=[CPGNode(
                id="n-dup-2", label="Call", ast_type="call", name="hashlib.md5",
                code="x = hashlib.md5(a).hexdigest()", filepath="dup_service.py",
                start_line=5, end_line=5, start_col=4, end_col=34, scope_id="pair",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
    ]
    vault = tmp_path / ".alastor_patches"
    dup_res = batch_apply_workspace_patches(dup_findings, [str(tmp_path)], str(vault))
    assert dup_res["applied_count"] == 1
    assert dup_res["skipped_count"] == 1
    dup_lines = dup_py.read_text(encoding="utf-8").splitlines()
    # Line 4 untouched, line 5 patched once
    assert "hashlib.md5(a)" in dup_lines[3]
    assert "sha256" in dup_lines[4]

    # Also verify >10 line shift handling via expected_shift = len(cur_lines) - len(initial_lines)
    shift_py = tmp_path / "shift_service.py"
    shift_py.write_text(
        "import hashlib\nimport yaml\n\ndef top_fn(b):\n    return hashlib.md5(b).hexdigest()\n\ndef bottom_fn(s):\n    return yaml.load(s)\n",
        encoding="utf-8",
    )
    shift_findings = [
        Finding(
            id="F-TOP",
            rule_id="RULE-3",
            severity="MEDIUM",
            title="Top MD5",
            cwe_id="CWE-328",
            path_nodes=[CPGNode(
                id="n-top", label="Call", ast_type="call", name="hashlib.md5",
                code="return hashlib.md5(b).hexdigest()", filepath="shift_service.py",
                start_line=5, end_line=5, start_col=4, end_col=37, scope_id="top_fn",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
        Finding(
            id="F-BOTTOM",
            rule_id="RULE-10",
            severity="HIGH",
            title="Bottom YAML",
            cwe_id="CWE-502",
            path_nodes=[CPGNode(
                id="n-bot", label="Call", ast_type="call", name="yaml.load",
                code="return yaml.load(s)", filepath="shift_service.py",
                start_line=8, end_line=8, start_col=4, end_col=23, scope_id="bottom_fn",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
    ]
    real_preview = rp.preview_finding_remediation

    def _preview_with_15_header_lines(finding_obj, roots, target_line_override=None):
        prev = real_preview(finding_obj, roots, target_line_override=target_line_override)
        if prev and getattr(finding_obj, "id", "") == "F-BOTTOM" and target_line_override is not None:
            banner = "".join(f"# helper header line {i}\n" for i in range(15))
            prev = dict(prev)
            prev["patched_content"] = banner + str(prev["patched_content"])
        return prev

    with patch.object(rp, "preview_finding_remediation", side_effect=_preview_with_15_header_lines):
        shift_res = batch_apply_workspace_patches(shift_findings, [str(tmp_path)], str(vault))
    assert shift_res["applied_count"] == 2
    shifted_text = shift_py.read_text(encoding="utf-8")
    assert "sha256" in shifted_text
    assert "safe_load" in shifted_text


def test_batch_apply_rolls_back_atomically_on_mid_batch_failure(tmp_path: Path):
    import engine.remediation_patcher as rp

    f_one = tmp_path / "first.py"
    f_two = tmp_path / "second.py"
    orig_one = "import hashlib\n\ndef h1(b):\n    return hashlib.md5(b).hexdigest()\n"
    orig_two = "import yaml\n\ndef y2(s):\n    return yaml.load(s)\n"
    f_one.write_text(orig_one, encoding="utf-8")
    f_two.write_text(orig_two, encoding="utf-8")

    findings = [
        Finding(
            id="F-RB-1",
            rule_id="RULE-3",
            severity="MEDIUM",
            title="Hash in first.py",
            cwe_id="CWE-328",
            path_nodes=[CPGNode(
                id="n-rb-1", label="Call", ast_type="call", name="hashlib.md5",
                code="return hashlib.md5(b).hexdigest()", filepath="first.py",
                start_line=4, end_line=4, start_col=4, end_col=37, scope_id="h1",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
        Finding(
            id="F-RB-2",
            rule_id="RULE-10",
            severity="HIGH",
            title="YAML in second.py",
            cwe_id="CWE-502",
            path_nodes=[CPGNode(
                id="n-rb-2", label="Call", ast_type="call", name="yaml.load",
                code="return yaml.load(s)", filepath="second.py",
                start_line=4, end_line=4, start_col=4, end_col=23, scope_id="y2",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
    ]

    vault = tmp_path / ".alastor_patches"
    real_apply = rp.apply_workspace_patch
    call_counter = {"n": 0}

    def _fail_on_second_apply(**kwargs):
        call_counter["n"] += 1
        if call_counter["n"] == 2:
            raise ValueError("Simulated SHA256 optimistic concurrency conflict on second file")
        return real_apply(**kwargs)

    with patch.object(rp, "apply_workspace_patch", side_effect=_fail_on_second_apply):
        with pytest.raises(ValueError, match="Simulated SHA256"):
            batch_apply_workspace_patches(findings, [str(tmp_path)], str(vault))

    # First file MUST be rolled back to exact original bytes, and second file untouched!
    assert f_one.read_text(encoding="utf-8") == orig_one
    assert f_two.read_text(encoding="utf-8") == orig_two
    assert not vault.exists() or list(vault.glob("*.json")) == []
