"""
Strict TDD Suite for ALASTOR v5.0 Pillar 5 Task 3:
- Typed SDK additions (`alastor_sdk.py`): `pr_gate`, `generate_security_test`,
  `evaluate_compliance`, `stitch_microservices`
- Hardened CLI `alastor pr-gate` (`alastor_cli.py`) — offline & `--server` modes
- 9 Workspace-Confined FastAPI `/api/nextgen/*` Routes (`main.py`)
"""
from __future__ import annotations

import ast
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

from click.testing import CliRunner
from fastapi.testclient import TestClient
import httpx
import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

RAW_SECRET_GH = "ghp_" + "1234567890abcdef" * 2 + "1234"
RAW_SECRET_CUSTOM = "SuperSecretNextGenCanary_XYZ987654"
BYOK_CANARY = "sk-ant-api03-" + "TESTHOSTBYOKNEXTGEN1234567890"


def _git(repo_dir: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def _init_git_repo(repo_dir: Path) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", str(repo_dir)], check=True, capture_output=True, text=True)
    _git(repo_dir, "config", "user.name", "Alastor Test")
    _git(repo_dir, "config", "user.email", "alastor-test@example.com")


def _commit_all(repo_dir: Path, message: str) -> str:
    _git(repo_dir, "add", "-A")
    _git(repo_dir, "commit", "-m", message)
    return _git(repo_dir, "rev-parse", "HEAD")


def _create_dir_link(link_path: Path, target_dir: Path) -> None:
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link_path), str(target_dir)],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        os.symlink(str(target_dir), str(link_path), target_is_directory=True)


def _remove_dir_link(link_path: Path) -> None:
    if os.name == "nt":
        os.rmdir(link_path)
    else:
        os.unlink(link_path)


def _create_pr_multi_commit_repo(repo: Path) -> None:
    """Creates a multi-commit repo: commit1=base, commit2=vulnerable PR, commit3=clean PR."""
    _init_git_repo(repo)
    (repo / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
    (repo / "base_service.py").write_text(
        "def add_items(a: int, b: int) -> int:\n"
        "    return a + b\n",
        encoding="utf-8",
    )
    # Hostile target .env that MUST NEVER be auto-loaded
    (repo / ".env").write_text(
        f"ALASTOR_HOSTILE_PR_CANARY=MUST_NOT_LOAD\nOPENAI_API_KEY={BYOK_CANARY}\n",
        encoding="utf-8",
    )
    _commit_all(repo, "commit 1: clean base")

    (repo / "pr_feature.py").write_text(
        "import subprocess\n"
        "def deploy_service(user_target: str) -> bytes:\n"
        "    return subprocess.check_output('echo ' + user_target, shell=True)\n",
        encoding="utf-8",
    )
    _commit_all(repo, "commit 2: introduce shell injection")


def _create_two_microservices(root: Path) -> tuple[Path, Path]:
    gw = root / "api-gateway"
    gw.mkdir(parents=True, exist_ok=True)
    (gw / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
    (gw / "gateway.py").write_text(
        "import requests\n"
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        'BILLING_BASE = "http://billing-service:8080"\n\n'
        '@app.post("/checkout/{order_id}")\n'
        "def checkout(order_id: str):\n"
        '    return requests.post(f"{BILLING_BASE}/api/billing/{order_id}", timeout=5)\n',
        encoding="utf-8",
    )

    billing = root / "billing-service"
    billing.mkdir(parents=True, exist_ok=True)
    (billing / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
    (billing / "app.py").write_text(
        "import sqlite3\n"
        "import subprocess\n"
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        '@app.post("/api/billing/{invoice_id}")\n'
        "def charge_invoice(invoice_id: str):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        '    conn.execute(f"SELECT * FROM invoices WHERE id = \'{invoice_id}\'")\n'
        "    return subprocess.check_output('echo ' + invoice_id, shell=True)\n",
        encoding="utf-8",
    )
    return gw, billing


# ---------------------------------------------------------------------------
# 1. SDK Tests
# ---------------------------------------------------------------------------
class TestNextgenSdk:
    def test_sdk_pr_gate_generate_test_compliance_and_stitch_microservices(self, tmp_path: Path):
        import alastor_sdk
        from models import (
            BestFixLocation,
            ComplianceEvaluateResponse,
            Finding,
            MicroserviceGraphResponse,
            MicroserviceRepoInput,
            PrDeltaGateResponse,
            SecurityTestGenerateResponse,
        )

        repo = tmp_path / "sdk_pr_repo"
        _create_pr_multi_commit_repo(repo)
        vault = tmp_path / "vault"

        # 1a. alastor_sdk.pr_gate -> BLOCK_MERGE on new shell injection
        gate_block = alastor_sdk.pr_gate(
            repo_path=str(repo),
            base_ref="HEAD~1",
            head_ref="HEAD",
            fail_on_new_severity="HIGH",
            vault_dir=str(vault),
        )
        assert isinstance(gate_block, PrDeltaGateResponse)
        assert gate_block.gate_decision == "BLOCK_MERGE"
        assert gate_block.blocking_count >= 1
        assert gate_block.newly_introduced_count >= 1
        assert "pr_feature.py" in gate_block.changed_files
        assert "ALASTOR_HOSTILE_PR_CANARY" not in os.environ

        # Clean commit -> PASS
        (repo / "docs_note.py").write_text(
            "def format_note(text: str) -> str:\n"
            "    return text.strip()\n",
            encoding="utf-8",
        )
        _commit_all(repo, "commit 3: clean helper")
        gate_pass = alastor_sdk.pr_gate(
            repo_path=str(repo),
            base_ref="HEAD~1",
            head_ref="HEAD",
            vault_dir=str(vault),
        )
        assert gate_pass.gate_decision == "PASS"
        assert gate_pass.blocking_count == 0

        # 1b. alastor_sdk.generate_security_test -> preview + write + overwrite FileExistsError
        finding = Finding(
            id="SDK-FIND-SQLI-1",
            rule_id="RULE-7-SQLI-FORMAT",
            severity="HIGH",
            cwe_id="CWE-89",
            title=f"SQL Injection near {RAW_SECRET_GH}",
            description=f"Unsafe SQL interpolation {RAW_SECRET_CUSTOM}",
            secret_value_raw=RAW_SECRET_CUSTOM,
            best_fix_location=BestFixLocation(
                node_id="n1",
                filepath="app.py",
                line=12,
                code_snippet=f"SELECT * FROM users WHERE key='{RAW_SECRET_GH}'",
            ),
        )
        preview = alastor_sdk.generate_security_test(
            repo_path=str(repo),
            finding=finding,
            framework="auto",
            write_to_workspace=False,
        )
        assert isinstance(preview, SecurityTestGenerateResponse)
        assert preview.framework == "pytest"
        assert preview.syntax_valid is True
        assert preview.written_to_disk is False
        ast.parse(preview.test_code)
        assert RAW_SECRET_GH not in preview.model_dump_json()
        assert RAW_SECRET_CUSTOM not in preview.model_dump_json()

        written = alastor_sdk.generate_security_test(
            repo_path=str(repo),
            finding=finding,
            framework="pytest",
            write_to_workspace=True,
            overwrite=False,
        )
        assert written.written_to_disk is True
        assert written.written_path is not None and Path(written.written_path).is_file()
        with pytest.raises(FileExistsError):
            alastor_sdk.generate_security_test(
                repo_path=str(repo),
                finding=finding,
                framework="pytest",
                write_to_workspace=True,
                overwrite=False,
            )

        # 1c. alastor_sdk.evaluate_compliance -> all 5 frameworks + zero raw secret leakage
        comp = alastor_sdk.evaluate_compliance(
            repo_path=str(repo),
            findings=[finding],
        )
        assert isinstance(comp, ComplianceEvaluateResponse)
        assert len(comp.frameworks) == 5
        assert comp.overall_score_percent < 100.0
        comp_json = comp.model_dump_json()
        assert RAW_SECRET_GH not in comp_json
        assert RAW_SECRET_CUSTOM not in comp_json

        # 1d. alastor_sdk.stitch_microservices -> stitches api-gateway -> billing-service
        gw, billing = _create_two_microservices(tmp_path / "ms_sdk")
        graph = alastor_sdk.stitch_microservices(
            services=[
                MicroserviceRepoInput(service_name="api-gateway", repo_path=str(gw)),
                MicroserviceRepoInput(service_name="billing-service", repo_path=str(billing)),
            ],
            scan_findings=True,
        )
        assert isinstance(graph, MicroserviceGraphResponse)
        assert graph.services_analyzed == 2
        assert graph.stitched_edges_count >= 1
        assert graph.cross_service_attack_paths_count >= 1
        assert len(graph.reactflow_nodes) == 2
        assert len(graph.reactflow_edges) >= 1


# ---------------------------------------------------------------------------
# 2. CLI `alastor pr-gate` Tests
# ---------------------------------------------------------------------------
class TestAlastorPrGateCli:
    def test_cli_help_includes_pr_gate(self):
        from alastor_cli import cli

        runner = CliRunner()
        res = runner.invoke(cli, ["--help"])
        assert res.exit_code == 0, res.output
        assert "pr-gate" in res.output

    def test_cli_pr_gate_block_pass_bad_ref_and_out_md(self, tmp_path: Path):
        from alastor_cli import cli

        repo = tmp_path / "cli_pr_repo"
        _create_pr_multi_commit_repo(repo)
        vault = tmp_path / "vault"
        out_md = tmp_path / "reports" / "pr_summary.md"

        runner = CliRunner()

        # 1. Commit 2 introduced shell injection -> exit 1, BLOCK_MERGE, writes Markdown
        r_block = runner.invoke(
            cli,
            [
                "pr-gate",
                "--repo",
                str(repo),
                "--base",
                "HEAD~1",
                "--head",
                "HEAD",
                "--fail-on",
                "HIGH",
                "--out-md",
                str(out_md),
                "--vault-dir",
                str(vault),
                "--json",
            ],
        )
        assert r_block.exit_code == 1, r_block.output
        block_data = json.loads(r_block.output)
        assert block_data["gate_decision"] == "BLOCK_MERGE"
        assert block_data["blocking_count"] >= 1
        assert out_md.is_file()
        md_text = out_md.read_text(encoding="utf-8")
        assert "BLOCK_MERGE" in md_text
        assert "pr_feature.py" in md_text
        assert BYOK_CANARY not in md_text
        assert "ALASTOR_HOSTILE_PR_CANARY" not in os.environ

        # 2. Commit 3 clean helper -> exit 0, PASS
        (repo / "clean_util.py").write_text(
            "def safe_len(val: str) -> int:\n"
            "    return len(val)\n",
            encoding="utf-8",
        )
        _commit_all(repo, "commit 3: clean helper")

        r_pass = runner.invoke(
            cli,
            [
                "pr-gate",
                "--repo",
                str(repo),
                "--base",
                "HEAD~1",
                "--head",
                "HEAD",
                "--vault-dir",
                str(vault),
                "--json",
            ],
        )
        assert r_pass.exit_code == 0, r_pass.output
        pass_data = json.loads(r_pass.output)
        assert pass_data["gate_decision"] == "PASS"
        assert pass_data["blocking_count"] == 0

        # 3. Bad git ref -> exit 2
        r_bad_ref = runner.invoke(
            cli,
            [
                "pr-gate",
                "--repo",
                str(repo),
                "--base",
                "--exec=evil",
                "--head",
                "HEAD",
                "--vault-dir",
                str(vault),
            ],
        )
        assert r_bad_ref.exit_code == 2

        # 4. Missing repo -> exit 2
        r_missing = runner.invoke(
            cli,
            ["pr-gate", "--repo", str(tmp_path / "does_not_exist"), "--vault-dir", str(vault)],
        )
        assert r_missing.exit_code == 2

        # 5. Symlink/junction leaf on --out-md -> exit 2
        outside_md = tmp_path / "outside_secret.txt"
        outside_md.write_text("KEEP_ME", encoding="utf-8")
        link_parent = tmp_path / "link_parent"
        outside_dir = tmp_path / "outside_dir"
        outside_dir.mkdir()
        _create_dir_link(link_parent, outside_dir)
        try:
            r_link = runner.invoke(
                cli,
                [
                    "pr-gate",
                    "--repo",
                    str(repo),
                    "--out-md",
                    str(link_parent / "evil.md"),
                    "--vault-dir",
                    str(vault),
                ],
            )
            assert r_link.exit_code == 2
            assert list(outside_dir.iterdir()) == []
        finally:
            _remove_dir_link(link_parent)

    def test_cli_pr_gate_remote_server_mode(self, tmp_path: Path):
        from alastor_cli import cli

        repo = tmp_path / "remote_repo"
        repo.mkdir()
        out_md = tmp_path / "remote_pr.md"
        runner = CliRunner()

        def _make_mock_client(status_code: int, payload: Dict[str, Any] | None = None, is_redirect: bool = False):
            mock_resp = mock.MagicMock()
            mock_resp.status_code = status_code
            mock_resp.is_redirect = is_redirect
            if status_code >= 400:
                req = httpx.Request("POST", "http://127.0.0.1:8000/api/nextgen/pr-gate")
                resp_obj = httpx.Response(status_code, request=req)
                mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
                    f"HTTP {status_code}", request=req, response=resp_obj
                )
            else:
                mock_resp.raise_for_status.return_value = None
            if payload is not None:
                mock_resp.json.return_value = payload

            mock_client = mock.MagicMock()
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            mock_client.post.return_value = mock_resp
            return mock_client

        pass_payload = {
            "project_path": str(repo),
            "base_ref": "HEAD~1",
            "head_ref": "HEAD",
            "gate_decision": "PASS",
            "gate_reason": "0 blocking findings",
            "changed_files": ["clean.py"],
            "impacted_neighbor_files": [],
            "newly_introduced_count": 0,
            "modified_context_count": 0,
            "pre_existing_count": 0,
            "blocking_count": 0,
            "annotations": [],
            "newly_introduced_findings": [],
            "pr_markdown_summary": "## ALASTOR PR Delta Security Gate: `PASS`\n",
        }
        client_pass = _make_mock_client(200, pass_payload)
        with mock.patch("alastor_cli.httpx.Client", return_value=client_pass) as mock_cls:
            r_pass = runner.invoke(
                cli,
                [
                    "pr-gate",
                    "--repo",
                    str(repo),
                    "--server",
                    "http://127.0.0.1:8000",
                    "--out-md",
                    str(out_md),
                    "--json",
                ],
            )
        assert r_pass.exit_code == 0, r_pass.output
        assert mock_cls.call_args.kwargs.get("follow_redirects") is False
        assert client_pass.post.call_args.args[0] == "/api/nextgen/pr-gate"
        assert "PASS" in out_md.read_text(encoding="utf-8")

        block_payload = dict(pass_payload)
        block_payload["gate_decision"] = "BLOCK_MERGE"
        block_payload["blocking_count"] = 1
        block_payload["newly_introduced_count"] = 1
        block_payload["pr_markdown_summary"] = "## ALASTOR PR Delta Security Gate: `BLOCK_MERGE`\n"
        client_block = _make_mock_client(200, block_payload)
        with mock.patch("alastor_cli.httpx.Client", return_value=client_block):
            r_block = runner.invoke(
                cli,
                [
                    "pr-gate",
                    "--repo",
                    str(repo),
                    "--server",
                    "http://127.0.0.1:8000",
                    "--no-block-secrets",
                    "--no-block-ev",
                    "--no-cpg-neighbors",
                    "--json",
                ],
            )
        assert r_block.exit_code == 1, r_block.output
        sent_body = client_block.post.call_args.kwargs["json"]
        assert sent_body["block_on_new_secrets"] is False
        assert sent_body["block_on_new_ev_confirmed"] is False
        assert sent_body["include_cpg_neighbors"] is False

        # 302 redirect MUST exit 2
        client_redir = _make_mock_client(302, is_redirect=True)
        with mock.patch("alastor_cli.httpx.Client", return_value=client_redir):
            r_redir = runner.invoke(
                cli,
                ["pr-gate", "--repo", str(repo), "--server", "http://127.0.0.1:8000"],
            )
        assert r_redir.exit_code == 2

        # 400 HTTP error MUST exit 2
        client_400 = _make_mock_client(400)
        with mock.patch("alastor_cli.httpx.Client", return_value=client_400):
            r_400 = runner.invoke(
                cli,
                ["pr-gate", "--repo", str(repo), "--server", "http://127.0.0.1:8000"],
            )
        assert r_400.exit_code == 2

        # Unsafe --server URL scheme MUST exit 2
        assert (
            runner.invoke(
                cli,
                ["pr-gate", "--repo", str(repo), "--server", "file:///etc/passwd"],
            ).exit_code
            == 2
        )


# ---------------------------------------------------------------------------
# 3. FastAPI 9 Confined `/api/nextgen/*` Route Tests
# ---------------------------------------------------------------------------
class TestNextgenFastApiRoutes:
    def test_all_nine_nextgen_routes_are_sync_handlers(self):
        import main as main_mod

        nextgen_routes = [
            r for r in main_mod.app.routes if getattr(r, "path", "").startswith("/api/nextgen/")
        ]
        assert len(nextgen_routes) == 9
        for route in nextgen_routes:
            endpoint = getattr(route, "endpoint", None)
            assert endpoint is not None
            assert not inspect.iscoroutinefunction(endpoint), (
                f"Route {route.path} must be a sync `def` handler so blocking work stays in FastAPI threadpool"
            )

    def test_all_nine_nextgen_routes_confinement_lifecycle_and_security(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        import main as main_mod
        from database.checkpoint_store import CheckpointStore
        from engine.compliance_and_rules_engine import CustomRuleEngine
        from engine.exploit_verification_engine import ExploitVerificationEngine
        from models import BestFixLocation, Finding

        ws = tmp_path / "confined_ws"
        _create_pr_multi_commit_repo(ws)

        outside = tmp_path / "outside_ws"
        _create_pr_multi_commit_repo(outside)

        ms_root = tmp_path / "ms_ws"
        gw, billing = _create_two_microservices(ms_root)

        vault = tmp_path / "vault"
        iso_store = CheckpointStore(str(vault))
        iso_ev = ExploitVerificationEngine(vault_dir=str(vault))
        iso_rules = CustomRuleEngine(vault_dir=str(vault))

        sqli_finding = Finding(
            id="NEXTGEN-FIND-SQLI-1",
            rule_id="RULE-7-SQLI-FORMAT",
            severity="HIGH",
            cwe_id="CWE-89",
            title=f"SQL Injection in {RAW_SECRET_GH}",
            description=f"SQLi near {RAW_SECRET_CUSTOM}",
            secret_value_raw=RAW_SECRET_CUSTOM,
            best_fix_location=BestFixLocation(
                node_id="n-ng-1",
                filepath="base_service.py",
                line=1,
                code_snippet=f"cursor.execute(f'SELECT {RAW_SECRET_GH}')",
            ),
        )

        # Monkeypatch confinement cleanly to tmp_path workspaces & isolate vault/caches,
        # restoring everything via monkeypatch + explicit try/finally.
        orig_allowed_fn = main_mod._get_ai_allowed_roots
        monkeypatch.setattr(main_mod, "startup_event", lambda: None)
        monkeypatch.setattr(main_mod, "shutdown_event", lambda: None)
        monkeypatch.setattr(main_mod, "checkpoint_store", iso_store)
        monkeypatch.setattr(main_mod, "ev_engine", iso_ev)
        monkeypatch.setattr(main_mod, "custom_rule_engine", iso_rules)
        monkeypatch.setattr(main_mod, "_get_ai_allowed_roots", lambda: [str(ws), str(ms_root)])
        monkeypatch.setattr(main_mod, "current_scan_dir", str(ws))
        monkeypatch.setattr(main_mod, "_cached_findings", [])
        monkeypatch.setattr(main_mod, "_cached_external_findings", [])
        monkeypatch.setattr(main_mod, "_cached_cognitive_findings", [])
        monkeypatch.setattr(main_mod, "_cached_cognitive_dir", "")

        try:
            with TestClient(main_mod.app) as client:
                # 1. Path traversal (`../../etc`) & outside-root -> HTTP 400 across ALL 5 path-accepting routes!
                for bad_path in ("../../etc", str(outside), ""):
                    assert (
                        client.post(
                            "/api/nextgen/pr-gate",
                            json={"project_path": bad_path},
                        ).status_code
                        == 400
                    )
                    assert (
                        client.post(
                            "/api/nextgen/generate-test",
                            json={
                                "project_path": bad_path,
                                "finding": sqli_finding.model_dump(),
                            },
                        ).status_code
                        == 400
                    )
                    assert (
                        client.post(
                            "/api/nextgen/compliance/evaluate",
                            json={"project_path": bad_path},
                        ).status_code
                        == 400
                    )
                    assert (
                        client.post(
                            "/api/nextgen/custom-rules/test",
                            json={
                                "rule": {
                                    "rule_id": "TMP-RULE-1",
                                    "name": "Eval check",
                                    "pattern": r"\beval\s*\(",
                                },
                                "project_path": bad_path,
                            },
                        ).status_code
                        == 400
                    )
                    assert (
                        client.post(
                            "/api/nextgen/microservice-graph",
                            json={
                                "services": [
                                    {"service_name": "svc", "repo_path": bad_path}
                                ],
                                "scan_findings": False,
                            },
                        ).status_code
                        == 400
                    )

                # 2. POST /api/nextgen/pr-gate: 400 on `--exec=evil`, 200 on real confined git repo
                r_bad_ref = client.post(
                    "/api/nextgen/pr-gate",
                    json={"project_path": str(ws), "base_ref": "--exec=evil", "head_ref": "HEAD"},
                )
                assert r_bad_ref.status_code == 400

                r_gate = client.post(
                    "/api/nextgen/pr-gate",
                    json={"project_path": str(ws), "base_ref": "HEAD~1", "head_ref": "HEAD"},
                )
                assert r_gate.status_code == 200, r_gate.text
                gate_body = r_gate.json()
                assert gate_body["gate_decision"] == "BLOCK_MERGE"
                assert gate_body["blocking_count"] >= 1
                assert "pr_feature.py" in gate_body["changed_files"]

                # 3. POST /api/nextgen/generate-test:
                # 400 when neither finding nor finding_id provided
                assert (
                    client.post(
                        "/api/nextgen/generate-test",
                        json={"project_path": str(ws)},
                    ).status_code
                    == 400
                )
                # 404 on unknown finding_id
                assert (
                    client.post(
                        "/api/nextgen/generate-test",
                        json={"project_path": str(ws), "finding_id": "MISSING-FINDING-999"},
                    ).status_code
                    == 404
                )
                # 200 preview with inline finding (syntax_valid=True, zero raw secret leak)
                r_tg_prev = client.post(
                    "/api/nextgen/generate-test",
                    json={
                        "project_path": str(ws),
                        "finding": sqli_finding.model_dump(),
                        "framework": "auto",
                        "write_to_workspace": False,
                    },
                )
                assert r_tg_prev.status_code == 200, r_tg_prev.text
                tg_prev_body = r_tg_prev.json()
                assert tg_prev_body["syntax_valid"] is True
                assert tg_prev_body["framework"] == "pytest"
                assert tg_prev_body["written_to_disk"] is False
                assert RAW_SECRET_GH not in r_tg_prev.text
                assert RAW_SECRET_CUSTOM not in r_tg_prev.text

                # 200 write -> 409 on overwrite=False
                r_tg_write = client.post(
                    "/api/nextgen/generate-test",
                    json={
                        "project_path": str(ws),
                        "finding": sqli_finding.model_dump(),
                        "framework": "pytest",
                        "write_to_workspace": True,
                        "overwrite": False,
                    },
                )
                assert r_tg_write.status_code == 200, r_tg_write.text
                assert r_tg_write.json()["written_to_disk"] is True

                r_tg_conflict = client.post(
                    "/api/nextgen/generate-test",
                    json={
                        "project_path": str(ws),
                        "finding": sqli_finding.model_dump(),
                        "framework": "pytest",
                        "write_to_workspace": True,
                        "overwrite": False,
                    },
                )
                assert r_tg_conflict.status_code == 409

                # Lookup finding_id from active workspace _cached_findings
                monkeypatch.setattr(main_mod, "_cached_findings", [sqli_finding])
                r_tg_by_id = client.post(
                    "/api/nextgen/generate-test",
                    json={
                        "project_path": str(ws),
                        "finding_id": sqli_finding.id,
                        "write_to_workspace": False,
                    },
                )
                assert r_tg_by_id.status_code == 200, r_tg_by_id.text
                assert r_tg_by_id.json()["finding_id"] == sqli_finding.id

                # 4. Custom Rules CRUD lifecycle + 400 on ReDoS `(a+)+`
                monkeypatch.setattr(main_mod, "_cached_findings", [])
                bad_redos_rule = {
                    "rule_id": "CUSTOM-REDOS-1",
                    "name": "Evil ReDoS",
                    "pattern": "(a+)+",
                }
                assert client.post("/api/nextgen/custom-rules", json=bad_redos_rule).status_code == 400
                assert (
                    client.post(
                        "/api/nextgen/custom-rules/test",
                        json={"rule": bad_redos_rule, "sample_code": "aaaa!"},
                    ).status_code
                    == 400
                )

                good_rule = {
                    "rule_id": "CUSTOM-SUBPROCESS-SHELL",
                    "name": "Detect subprocess shell=True",
                    "severity": "CRITICAL",
                    "cwe_id": "CWE-78",
                    "languages": ["python"],
                    "pattern": r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True",
                    "anti_pattern": r"#\s*alastor-ignore",
                    "description": "Blocks shell=True subprocess invocations.",
                    "remediation": "Pass list argv with shell=False.",
                    "enabled": True,
                }
                r_cr_create = client.post("/api/nextgen/custom-rules", json=good_rule)
                assert r_cr_create.status_code in (200, 201), r_cr_create.text
                assert r_cr_create.json()["rule_id"] == "CUSTOM-SUBPROCESS-SHELL"

                # Duplicate rule_id -> 409
                assert client.post("/api/nextgen/custom-rules", json=good_rule).status_code == 409

                # GET list
                r_cr_list = client.get("/api/nextgen/custom-rules")
                assert r_cr_list.status_code == 200
                assert any(r["rule_id"] == "CUSTOM-SUBPROCESS-SHELL" for r in r_cr_list.json())

                # PUT update (and 404 missing, 400 ReDoS)
                assert (
                    client.put("/api/nextgen/custom-rules/MISSING-999", json=good_rule).status_code
                    == 404
                )
                assert (
                    client.put(
                        "/api/nextgen/custom-rules/CUSTOM-SUBPROCESS-SHELL",
                        json={**good_rule, "pattern": "(a+)+"},
                    ).status_code
                    == 400
                )
                r_cr_put = client.put(
                    "/api/nextgen/custom-rules/CUSTOM-SUBPROCESS-SHELL",
                    json={**good_rule, "severity": "HIGH", "description": "Updated rule description"},
                )
                assert r_cr_put.status_code == 200, r_cr_put.text
                assert r_cr_put.json()["severity"] == "HIGH"

                # POST /api/nextgen/custom-rules/test (inline sample with secret scrubbing + workspace)
                r_cr_test_inline = client.post(
                    "/api/nextgen/custom-rules/test",
                    json={
                        "rule": good_rule,
                        "sample_code": f"subprocess.run(cmd, shell=True)  # {RAW_SECRET_GH}\n",
                        "sample_language": "python",
                    },
                )
                assert r_cr_test_inline.status_code == 200, r_cr_test_inline.text
                test_inline_body = r_cr_test_inline.json()
                assert test_inline_body["regex_safe"] is True
                assert test_inline_body["matches_count"] == 1
                assert RAW_SECRET_GH not in r_cr_test_inline.text

                r_cr_test_ws = client.post(
                    "/api/nextgen/custom-rules/test",
                    json={"rule": good_rule, "project_path": str(ws)},
                )
                assert r_cr_test_ws.status_code == 200, r_cr_test_ws.text
                assert r_cr_test_ws.json()["matches_count"] >= 1

                # 5. POST /api/nextgen/compliance/evaluate -> 200 all 5 frameworks + evaluates enabled custom rules without mutating _cached_findings!
                assert main_mod._cached_findings == []
                r_comp = client.post(
                    "/api/nextgen/compliance/evaluate",
                    json={"project_path": str(ws)},
                )
                assert r_comp.status_code == 200, r_comp.text
                comp_body = r_comp.json()
                assert len(comp_body["frameworks"]) == 5
                assert {fw["framework_id"] for fw in comp_body["frameworks"]} == {
                    "PCI_DSS_4_0",
                    "SOC2",
                    "ISO_27001",
                    "HIPAA",
                    "OWASP_ASVS_5_0",
                }
                assert comp_body["total_findings_evaluated"] >= 1
                assert comp_body["overall_score_percent"] < 100.0
                # Custom rule evaluation MUST NOT mutate _cached_findings
                assert main_mod._cached_findings == []

                # DELETE custom rule -> 200, repeat -> 404
                r_cr_del = client.delete("/api/nextgen/custom-rules/CUSTOM-SUBPROCESS-SHELL")
                assert r_cr_del.status_code == 200
                assert r_cr_del.json() == {"deleted": True, "rule_id": "CUSTOM-SUBPROCESS-SHELL"}
                assert client.delete("/api/nextgen/custom-rules/CUSTOM-SUBPROCESS-SHELL").status_code == 404

                # 6. POST /api/nextgen/microservice-graph -> 200 stitching 2 temp services
                r_ms = client.post(
                    "/api/nextgen/microservice-graph",
                    json={
                        "services": [
                            {"service_name": "api-gateway", "repo_path": str(gw)},
                            {"service_name": "billing-service", "repo_path": str(billing)},
                        ],
                        "scan_findings": True,
                    },
                )
                assert r_ms.status_code == 200, r_ms.text
                ms_body = r_ms.json()
                assert ms_body["services_analyzed"] == 2
                assert ms_body["stitched_edges_count"] >= 1
                assert ms_body["cross_service_attack_paths_count"] >= 1
                assert len(ms_body["reactflow_nodes"]) == 2
                assert len(ms_body["reactflow_edges"]) >= 1
                assert len(ms_body["attack_paths"]) >= 1

                # 7. Active workspace EV-confirmed finding flows through POST /api/nextgen/pr-gate
                ev_low = Finding(
                    id="EV-LOW-PR-1",
                    rule_id="RULE-EV-IDOR",
                    severity="LOW",
                    cwe_id="CWE-639",
                    title="Confirmed EV IDOR in pr_feature",
                    ev_status="RUNTIME_EXPLOIT_CONFIRMED",
                    best_fix_location=BestFixLocation(filepath="pr_feature.py", line=2),
                )
                monkeypatch.setattr(main_mod, "_cached_findings", [ev_low])
                r_ev_gate = client.post(
                    "/api/nextgen/pr-gate",
                    json={
                        "project_path": str(ws),
                        "base_ref": "HEAD~1",
                        "head_ref": "HEAD",
                        "fail_on_new_severity": "CRITICAL",
                        "block_on_new_ev_confirmed": True,
                    },
                )
                assert r_ev_gate.status_code == 200, r_ev_gate.text
                assert r_ev_gate.json()["gate_decision"] == "BLOCK_MERGE"
                assert r_ev_gate.json()["blocking_count"] == 1
                monkeypatch.setattr(main_mod, "_cached_findings", [])

                # 8. Symlink/junction project_path rejected with HTTP 400 on all 5 path routes
                ws_link = tmp_path / "ws_link"
                _create_dir_link(ws_link, ws)
                try:
                    monkeypatch.setattr(main_mod, "_get_ai_allowed_roots", lambda: [str(tmp_path)])
                    assert (
                        client.post(
                            "/api/nextgen/pr-gate",
                            json={"project_path": str(ws_link)},
                        ).status_code
                        == 400
                    )
                    assert (
                        client.post(
                            "/api/nextgen/generate-test",
                            json={
                                "project_path": str(ws_link),
                                "finding": sqli_finding.model_dump(),
                            },
                        ).status_code
                        == 400
                    )
                    assert (
                        client.post(
                            "/api/nextgen/compliance/evaluate",
                            json={"project_path": str(ws_link)},
                        ).status_code
                        == 400
                    )
                    assert (
                        client.post(
                            "/api/nextgen/custom-rules/test",
                            json={"rule": good_rule, "project_path": str(ws_link)},
                        ).status_code
                        == 400
                    )
                    assert (
                        client.post(
                            "/api/nextgen/microservice-graph",
                            json={
                                "services": [{"service_name": "gw", "repo_path": str(ws_link)}],
                                "scan_findings": False,
                            },
                        ).status_code
                        == 400
                    )
                finally:
                    _remove_dir_link(ws_link)
        finally:
            monkeypatch.setattr(main_mod, "_get_ai_allowed_roots", orig_allowed_fn)
            if iso_store._conn is not None:
                iso_store.close()
