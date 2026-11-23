"""
Strict TDD Suite for ALASTOR v5.0 Pillar 4 Task 3:
- Typed Python SDK (`alastor_sdk.py`)
- Embedded-First Hardened CLI (`alastor_cli.py`) & `pyproject.toml`
- 8 Confined FastAPI `/api/fleet/*` & `/api/fusion/*` Endpoints (`main.py`)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

from click.testing import CliRunner
from fastapi.testclient import TestClient
import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

RAW_SECRET_CANARY = "ghp_1234567890abcdef1234567890abcdef9988"
BYOK_CANARY = "sk-ant-api03-TESTHOSTBYOKKEYCANARY1234567890"


def _init_git_repo(repo_dir: Path) -> str:
    subprocess.run(["git", "init", str(repo_dir)], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.name", "Alastor Test"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.email", "test@alastor.local"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-m", "initial"],
        check=True,
        capture_output=True,
        text=True,
    )
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def _create_clean_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
    (repo_dir / "app.py").write_text(
        "def add_numbers(a: int, b: int) -> int:\n"
        "    return a + b\n",
        encoding="utf-8",
    )
    return _init_git_repo(repo_dir)


def _create_vuln_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
    (repo_dir / "app.py").write_text(
        "import subprocess\n"
        "def run_cmd(user_arg: str) -> bytes:\n"
        "    return subprocess.check_output('ls ' + user_arg, shell=True)\n",
        encoding="utf-8",
    )
    # Hostile target .env that MUST NEVER be auto-loaded by ALASTOR
    (repo_dir / ".env").write_text(
        f"ALASTOR_HOSTILE_CANARY=MUST_NOT_LOAD\nOPENAI_API_KEY={BYOK_CANARY}\n",
        encoding="utf-8",
    )
    return _init_git_repo(repo_dir)


def _create_medium_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
    (repo_dir / "helper.py").write_text(
        "def greet(name: str) -> str:\n"
        "    return f'hello {name}'\n",
        encoding="utf-8",
    )
    return _init_git_repo(repo_dir)


class TestPackagingAndEntryPoint:
    def test_pyproject_toml_and_module_cli_help(self):
        pyproject_path = BACKEND_DIR / "pyproject.toml"
        assert pyproject_path.is_file()
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        assert data["project"]["name"] == "alastor-sast"
        assert data["project"]["version"] == "5.0.0"
        assert data["project"]["scripts"]["alastor"] == "alastor_cli:main"
        assert set(["alastor_cli", "alastor_sdk", "models", "main"]).issubset(
            set(data["tool"]["setuptools"]["py-modules"])
        )

        proc = subprocess.run(
            [sys.executable, "-m", "alastor_cli", "--help"],
            cwd=str(BACKEND_DIR),
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert proc.returncode == 0, proc.stderr
        for subcmd in ("setup", "doctor", "estimate", "scan", "remediate", "validate", "ev-replay", "gc"):
            assert subcmd in proc.stdout


class TestAlastorSdk:
    def test_doctor_and_estimate_never_leak_secrets_or_load_target_env(self, tmp_path: Path):
        import alastor_sdk
        from engine.frontier_ai_engine import FrontierAiEngine
        from models import AiConfigUpdateRequest, DoctorReport, EstimateReport

        vault = tmp_path / "vault"
        ai_eng = FrontierAiEngine(vault_dir=str(vault))
        ai_eng.update_config(
            AiConfigUpdateRequest(
                provider="anthropic",
                model="claude-3-5-sonnet",
                base_url="https://api.anthropic.com",
                api_key=BYOK_CANARY,
                persist_key=True,
            )
        )

        doc = alastor_sdk.doctor(vault_dir=str(vault), check_neo4j=False)
        assert isinstance(doc, DoctorReport)
        assert doc.overall_status in ("READY", "DEGRADED")
        assert doc.parsers_ready >= 18
        assert doc.parsers_total >= 18
        assert doc.vault_writable is True
        assert BYOK_CANARY not in doc.model_dump_json()

        repo = tmp_path / "repo"
        _create_vuln_repo(repo)
        est = alastor_sdk.estimate(str(repo), vault_dir=str(vault))
        assert isinstance(est, EstimateReport)
        assert est.total_files >= 1
        assert est.total_loc >= 3
        assert "python" in est.languages
        assert "ALASTOR_HOSTILE_CANARY" not in os.environ

    def test_sdk_inject_findings_and_fuse_scanner_report(self, tmp_path: Path):
        import alastor_sdk
        from models import BestFixLocation, Finding, ScannerFusionResponse

        repo = tmp_path / "repo"
        _create_clean_repo(repo)

        ext_finding = Finding(
            id="EXT-INJECT-1",
            rule_id="SEMGREP-SQLI-1",
            severity="HIGH",
            title="Potential SQL Injection",
            description=f"SQL query built dynamically near token {RAW_SECRET_CANARY}",
            cwe_id="CWE-89",
            source_engine="SEMGREP",
            secret_value_raw=RAW_SECRET_CANARY,
            best_fix_location=BestFixLocation(
                node_id="n1",
                filepath="app.py",
                line=2,
                code_snippet="return a + b",
            ),
        )
        res_inj = alastor_sdk.inject_findings(str(repo), [ext_finding], run_s6_verify=True)
        assert isinstance(res_inj, ScannerFusionResponse)
        assert res_inj.new_unique_count == 1
        assert res_inj.s6_verified_count >= 1
        assert RAW_SECRET_CANARY not in res_inj.model_dump_json()

        semgrep_report = json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.sqli",
                        "path": "app.py",
                        "start": {"line": 2, "col": 5},
                        "end": {"line": 2, "col": 17},
                        "extra": {
                            "message": f"SQLi near {RAW_SECRET_CANARY}",
                            "severity": "ERROR",
                            "metadata": {"cwe": ["CWE-89"]},
                        },
                    }
                ],
                "errors": [],
            }
        )
        res_fuse = alastor_sdk.fuse_scanner_report(str(repo), semgrep_report, run_s6_verify=False)
        assert res_fuse.detected_format == "SEMGREP_JSON"
        assert res_fuse.new_unique_count == 1
        assert RAW_SECRET_CANARY not in res_fuse.model_dump_json()

    def test_sdk_scan_refuses_hostile_config_and_supports_artifacts_and_fleet(self, tmp_path: Path):
        import alastor_sdk
        from alastor_sdk import FleetOptions, ScanOptions
        from engine.hostile_repo_guard import HostileRepoError

        repo = tmp_path / "vuln_repo"
        _create_vuln_repo(repo)
        vault = tmp_path / "vault"

        # Hostile config inside target repo MUST be rejected
        with pytest.raises(HostileRepoError):
            alastor_sdk.scan(
                ScanOptions(
                    repo=str(repo),
                    config_file=str(repo / ".env"),
                    vault_dir=str(vault),
                )
            )
        assert "ALASTOR_HOSTILE_CANARY" not in os.environ

        # Scan with SARIF / DOCX / PDF artifacts
        out_sarif = tmp_path / "out_sarif"
        res_sarif = alastor_sdk.scan(
            ScanOptions(
                repo=str(repo),
                out_dir=str(out_sarif),
                output_format="sarif",
                vault_dir=str(vault),
                resume=False,
            )
        )
        assert res_sarif.exit_code == 1  # CRITICAL/HIGH -> NO_GO_HOLD_RELEASE
        assert len(res_sarif.output_files) == 1
        sarif_doc = json.loads(Path(res_sarif.output_files[0]).read_text(encoding="utf-8"))
        assert sarif_doc["version"] == "2.1.0"
        assert "runs" in sarif_doc

        out_docx = tmp_path / "out_docx"
        res_docx = alastor_sdk.scan(
            ScanOptions(
                repo=str(repo),
                out_dir=str(out_docx),
                output_format="docx",
                vault_dir=str(vault),
                resume=True,
            )
        )
        assert len(res_docx.output_files) == 1
        assert Path(res_docx.output_files[0]).suffix == ".docx"
        assert Path(res_docx.output_files[0]).stat().st_size > 1000
        assert res_docx.run_id == res_sarif.run_id
        assert len(res_docx.resumed_stages) >= 1

        # Clean repo fleet scan via FleetOptions
        clean_a = tmp_path / "clean_a"
        clean_b = tmp_path / "clean_b"
        _create_clean_repo(clean_a)
        _create_clean_repo(clean_b)
        csv_file = tmp_path / "fleet.csv"
        csv_file.write_text(
            "repo,app_group,profile\n"
            f"{clean_a},core-api,deterministic\n"
            f"{clean_b},billing-api,deterministic\n",
            encoding="utf-8",
        )
        fleet_resp = alastor_sdk.run_fleet(
            FleetOptions(csv_path=str(csv_file), group_by_app=True, vault_dir=str(vault))
        )
        assert fleet_resp.status == "COMPLETED"
        assert fleet_resp.completed_repos == 2
        assert len(fleet_resp.app_rollups) == 2


class TestAlastorCliSubcommands:
    def test_setup_install_agents_and_guardrails(self, tmp_path: Path):
        from alastor_cli import cli

        runner = CliRunner()
        target = tmp_path / "project"
        target.mkdir()
        vault = tmp_path / "vault"

        res = runner.invoke(
            cli,
            ["setup", "--install-agents", "--target-dir", str(target), "--vault-dir", str(vault), "--json"],
        )
        assert res.exit_code == 0, res.output
        payload = json.loads(res.output)
        assert payload["agents_installed"] is True
        agents_md = target / "AGENTS.md"
        assert agents_md.is_file()
        content1 = agents_md.read_text(encoding="utf-8")
        assert "ALASTOR:BEGIN" in content1
        assert "alastor scan" in content1

        # Re-running updates managed block cleanly
        res2 = runner.invoke(
            cli,
            ["setup", "--install-agents", "--target-dir", str(target), "--vault-dir", str(vault)],
        )
        assert res2.exit_code == 0

        # Non-ALASTOR AGENTS.md refuses silent overwrite unless --force
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        (custom_dir / "AGENTS.md").write_text("# My Custom Agent Instructions\n", encoding="utf-8")
        res_refuse = runner.invoke(
            cli,
            ["setup", "--install-agents", "--target-dir", str(custom_dir), "--vault-dir", str(vault)],
        )
        assert res_refuse.exit_code == 2
        assert (custom_dir / "AGENTS.md").read_text(encoding="utf-8") == "# My Custom Agent Instructions\n"

        res_force = runner.invoke(
            cli,
            ["setup", "--install-agents", "--target-dir", str(custom_dir), "--force", "--vault-dir", str(vault)],
        )
        assert res_force.exit_code == 0
        updated_custom = (custom_dir / "AGENTS.md").read_text(encoding="utf-8")
        assert "# My Custom Agent Instructions" in updated_custom
        assert "ALASTOR:BEGIN" in updated_custom

    def test_doctor_and_estimate_cli(self, tmp_path: Path):
        from alastor_cli import cli
        from engine.frontier_ai_engine import FrontierAiEngine
        from models import AiConfigUpdateRequest

        vault = tmp_path / "vault"
        FrontierAiEngine(vault_dir=str(vault)).update_config(
            AiConfigUpdateRequest(
                provider="openai",
                model="gpt-4o",
                base_url="https://api.openai.com/v1",
                api_key=BYOK_CANARY,
                persist_key=True,
            )
        )
        runner = CliRunner()
        r_doc = runner.invoke(cli, ["doctor", "--vault-dir", str(vault), "--json"])
        assert r_doc.exit_code == 0, r_doc.output
        assert BYOK_CANARY not in r_doc.output
        doc_json = json.loads(r_doc.output)
        assert doc_json["parsers_ready"] >= 18

        repo = tmp_path / "repo"
        _create_clean_repo(repo)
        r_est = runner.invoke(cli, ["estimate", "--repo", str(repo), "--vault-dir", str(vault), "--json"])
        assert r_est.exit_code == 0, r_est.output
        est_json = json.loads(r_est.output)
        assert est_json["total_files"] >= 1
        assert est_json["total_loc"] >= 2
        assert "python" in est_json["languages"]

    def test_scan_fusion_resume_hostile_config_sandbox_and_fleet_cli(self, tmp_path: Path):
        from alastor_cli import cli

        repo = tmp_path / "svc_clean"
        _create_medium_repo(repo)
        vault = tmp_path / "vault"
        out_dir = tmp_path / "out"

        semgrep_file = tmp_path / "semgrep.json"
        semgrep_file.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "python.lang.security.audit.medium-check",
                            "path": "helper.py",
                            "start": {"line": 2, "col": 5},
                            "end": {"line": 2, "col": 20},
                            "extra": {
                                "message": f"Sample issue with leaked {RAW_SECRET_CANARY}",
                                "severity": "WARNING",
                                "metadata": {"cwe": ["CWE-601"]},
                            },
                        }
                    ],
                    "errors": [],
                }
            ),
            encoding="utf-8",
        )

        runner = CliRunner()
        # 1. Scan with fusion report & JSON artifact
        r1 = runner.invoke(
            cli,
            [
                "scan",
                "--repo",
                str(repo),
                "--fusion-report",
                str(semgrep_file),
                "--out",
                str(out_dir),
                "--format",
                "json",
                "--vault-dir",
                str(vault),
                "--json",
            ],
        )
        assert r1.exit_code == 0, r1.output
        assert RAW_SECRET_CANARY not in r1.output
        d1 = json.loads(r1.output)
        assert d1["total_findings"] >= 1
        assert (out_dir / "findings.json").is_file()

        # 2. Second run with --resume reuses checkpoints
        r2 = runner.invoke(
            cli,
            [
                "scan",
                "--repo",
                str(repo),
                "--resume",
                "--vault-dir",
                str(vault),
                "--json",
            ],
        )
        assert r2.exit_code == 0, r2.output
        d2 = json.loads(r2.output)
        assert d2["run_id"] == d1["run_id"]
        assert len(d2["resumed_stages"]) >= 3

        # 3. Threshold failure with --fail-on MEDIUM -> exit 1
        r_fail = runner.invoke(
            cli,
            [
                "scan",
                "--repo",
                str(repo),
                "--fusion-report",
                str(semgrep_file),
                "--fail-on",
                "MEDIUM",
                "--vault-dir",
                str(vault),
                "--json",
            ],
        )
        assert r_fail.exit_code == 1

        # 4. Hostile target .env config -> exit 2
        (repo / ".env").write_text("EVIL=1\n", encoding="utf-8")
        r_hostile = runner.invoke(
            cli,
            [
                "scan",
                "--repo",
                str(repo),
                "--config",
                str(repo / ".env"),
                "--vault-dir",
                str(vault),
            ],
        )
        assert r_hostile.exit_code == 2

        # 5. --sandbox dry-run prints hardened Docker argv
        r_sbx = runner.invoke(
            cli,
            ["scan", "--repo", str(repo), "--sandbox", "--out", str(out_dir), "--json"],
        )
        assert r_sbx.exit_code == 0, r_sbx.output
        sbx_data = json.loads(r_sbx.output)
        argv = sbx_data["docker_argv"]
        assert "--network=none" in argv
        assert "--read-only" in argv
        assert "--cap-drop=ALL" in argv

        # 6. Multi-repo CSV manifest with --group-by-app
        repo_b = tmp_path / "svc_b"
        _create_clean_repo(repo_b)
        fleet_csv = tmp_path / "fleet.csv"
        fleet_csv.write_text(
            "repo,app_group\n"
            f"{repo},alpha-app\n"
            f"{repo_b},beta-app\n",
            encoding="utf-8",
        )
        r_fleet = runner.invoke(
            cli,
            [
                "scan",
                "--repo-file",
                str(fleet_csv),
                "--group-by-app",
                "--vault-dir",
                str(vault),
                "--json",
            ],
        )
        assert r_fleet.exit_code == 0, r_fleet.output
        fleet_data = json.loads(r_fleet.output)
        assert len(fleet_data["app_rollups"]) == 2

    def test_remediate_provenance_validate_ev_replay_and_gc_cli(self, tmp_path: Path):
        from alastor_cli import cli

        repo = tmp_path / "vuln_repo"
        _create_vuln_repo(repo)
        vault = tmp_path / "vault"
        runner = CliRunner()
        original_code = (repo / "app.py").read_text(encoding="utf-8")

        # 1. Forged run-id with --mode fix -> exit 2, file untouched!
        r_forged = runner.invoke(
            cli,
            [
                "remediate",
                "--repo",
                str(repo),
                "--mode",
                "fix",
                "--run-id",
                "forged-id",
                "--vault-dir",
                str(vault),
                "--json",
            ],
        )
        assert r_forged.exit_code == 2
        assert (repo / "app.py").read_text(encoding="utf-8") == original_code

        # 2. --mode report-only succeeds without modifying target file
        r_report_only = runner.invoke(
            cli,
            [
                "remediate",
                "--repo",
                str(repo),
                "--mode",
                "report-only",
                "--vault-dir",
                str(vault),
                "--json",
            ],
        )
        assert r_report_only.exit_code == 0, r_report_only.output
        rep_data = json.loads(r_report_only.output)
        assert rep_data["mode"] == "report-only"
        assert rep_data["applied_count"] == 0
        assert (repo / "app.py").read_text(encoding="utf-8") == original_code

        # 3. Real host scan creates valid checkpoint -> validate & remediate --mode fix succeed
        r_scan = runner.invoke(
            cli,
            ["scan", "--repo", str(repo), "--vault-dir", str(vault), "--json"],
        )
        assert r_scan.exit_code == 1  # CRITICAL/HIGH finding
        run_id = json.loads(r_scan.output)["run_id"]

        r_val = runner.invoke(
            cli,
            ["validate", "--repo", str(repo), "--run-id", run_id, "--vault-dir", str(vault), "--json"],
        )
        assert r_val.exit_code == 0, r_val.output
        val_data = json.loads(r_val.output)
        assert val_data["validated_count"] >= 1

        r_fix = runner.invoke(
            cli,
            ["remediate", "--repo", str(repo), "--mode", "fix", "--run-id", run_id, "--vault-dir", str(vault), "--json"],
        )
        assert r_fix.exit_code == 0, r_fix.output
        fix_data = json.loads(r_fix.output)
        assert fix_data["provenance_verified"] is True
        assert fix_data["applied_count"] >= 1
        assert "shell=True" not in (repo / "app.py").read_text(encoding="utf-8")

        # 4. ev-replay (0 replays -> exit 0)
        r_ev = runner.invoke(
            cli,
            ["ev-replay", "--repo", str(repo), "--vault-dir", str(vault), "--json"],
        )
        assert r_ev.exit_code == 0, r_ev.output
        ev_data = json.loads(r_ev.output)
        assert ev_data["replayed_count"] == 0

        # 5. gc dry-run
        # Create a second run so keep-last 1 can report pruning 1 run
        _create_clean_repo(tmp_path / "repo2")
        runner.invoke(cli, ["scan", "--repo", str(tmp_path / "repo2"), "--vault-dir", str(vault), "--json"])

        r_gc = runner.invoke(
            cli,
            ["gc", "--older-than-days", "0", "--keep-last", "1", "--dry-run", "--vault-dir", str(vault), "--json"],
        )
        assert r_gc.exit_code == 0, r_gc.output
        gc_data = json.loads(r_gc.output)
        assert gc_data["dry_run"] is True
        assert gc_data["pruned_runs"] == 1
        assert gc_data["kept_runs"] == 1

    def test_remote_server_mode_validates_url_and_dispatches_safely(self, tmp_path: Path):
        from alastor_cli import cli

        runner = CliRunner()
        # Reject unsafe --server scheme / control chars
        r_bad = runner.invoke(cli, ["doctor", "--server", "file:///etc/passwd"])
        assert r_bad.exit_code == 2

        r_ctrl = runner.invoke(cli, ["doctor", "--server", "http://127.0.0.1:8000\r\nEvil: 1"])
        assert r_ctrl.exit_code == 2

        fake_doc = {
            "overall_status": "READY",
            "python_version": "3.12.10",
            "parsers_ready": 18,
            "parsers_total": 18,
            "graph_backend": "EMBEDDED_SQLITE_WAL",
            "git_available": True,
            "docker_available": False,
            "vault_path": str(tmp_path),
            "vault_writable": True,
            "checks": [],
        }
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = fake_doc
        mock_resp.raise_for_status.return_value = None

        mock_client = mock.MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = None
        mock_client.get.return_value = mock_resp

        with mock.patch("alastor_cli.httpx.Client", return_value=mock_client) as mock_cls:
            r_ok = runner.invoke(cli, ["doctor", "--server", "http://127.0.0.1:8000", "--json"])
        assert r_ok.exit_code == 0, r_ok.output
        mock_cls.assert_called_once()
        assert mock_cls.call_args.kwargs.get("follow_redirects") is False
        assert json.loads(r_ok.output)["parsers_ready"] == 18


class TestFastApiFleetAndFusionRoutes:
    def test_all_eight_fleet_and_fusion_routes_with_confinement(self, tmp_path: Path, monkeypatch):
        import main as main_mod
        from database.checkpoint_store import CheckpointStore

        ws = tmp_path / "confined_ws"
        _create_medium_repo(ws)
        outside = tmp_path / "outside_ws"
        _create_clean_repo(outside)

        vault = tmp_path / "vault"
        iso_store = CheckpointStore(str(vault))

        monkeypatch.setattr(main_mod, "startup_event", lambda: None)
        monkeypatch.setattr(main_mod, "shutdown_event", lambda: None)
        monkeypatch.setattr(main_mod, "checkpoint_store", iso_store)
        monkeypatch.setattr(main_mod, "_get_ai_allowed_roots", lambda: [str(ws)])
        monkeypatch.setattr(main_mod, "current_scan_dir", str(ws))
        monkeypatch.setattr(main_mod, "_cached_findings", [])
        monkeypatch.setattr(main_mod, "_cached_external_findings", [])
        monkeypatch.setattr(main_mod, "_cached_cognitive_findings", [])
        monkeypatch.setattr(main_mod, "_cached_cognitive_dir", "")

        try:
            with TestClient(main_mod.app) as client:
                # 1. GET /api/fleet/doctor -> 200
                r_doc = client.get("/api/fleet/doctor")
                assert r_doc.status_code == 200, r_doc.text
                assert r_doc.json()["parsers_ready"] >= 18

                # 2. POST /api/fleet/estimate -> 200 confined, 400 traversal/outside
                r_est = client.post("/api/fleet/estimate", json={"project_path": str(ws)})
                assert r_est.status_code == 200, r_est.text
                assert r_est.json()["total_files"] >= 1

                assert client.post("/api/fleet/estimate", json={"project_path": "../../etc"}).status_code == 400
                assert client.post("/api/fleet/estimate", json={"project_path": str(outside)}).status_code == 400

                # 3. POST /api/fusion/import -> 200 (scrubbed secrets & merged into workspace), 400 on bad inputs
                gitleaks_payload = json.dumps(
                    [
                        {
                            "RuleID": "github-pat",
                            "Description": "GitHub Personal Access Token",
                            "File": "helper.py",
                            "StartLine": 2,
                            "EndLine": 2,
                            "Match": f"TOKEN='{RAW_SECRET_CANARY}'",
                            "Secret": RAW_SECRET_CANARY,
                        }
                    ]
                )
                r_fuse = client.post(
                    "/api/fusion/import",
                    json={"project_path": str(ws), "report_json": gitleaks_payload},
                )
                assert r_fuse.status_code == 200, r_fuse.text
                assert RAW_SECRET_CANARY not in r_fuse.text
                fuse_body = r_fuse.json()
                assert fuse_body["detected_format"] == "GITLEAKS_JSON"
                assert fuse_body["new_unique_count"] == 1
                assert len(main_mod._cached_findings or []) >= 1

                assert (
                    client.post(
                        "/api/fusion/import",
                        json={"project_path": "../../etc", "report_json": gitleaks_payload},
                    ).status_code
                    == 400
                )
                assert (
                    client.post(
                        "/api/fusion/import",
                        json={"project_path": str(ws), "report_json": "{not valid json"},
                    ).status_code
                    == 400
                )

                # 4. POST /api/fleet/run -> 200 confined CSV, 400 unsafe file:// URL, then GET /api/fleet/runs
                r_bad_fleet = client.post(
                    "/api/fleet/run",
                    json={"csv_content": "repo,app_group\nfile:///etc/passwd,evil\n"},
                )
                assert r_bad_fleet.status_code == 400

                r_bad_outside = client.post(
                    "/api/fleet/run",
                    json={"csv_content": f"repo,app_group\n{outside},escape\n"},
                )
                assert r_bad_outside.status_code == 400

                r_fleet = client.post(
                    "/api/fleet/run",
                    json={
                        "manifest_name": "api-test-fleet",
                        "csv_content": f"repo,app_group\n{ws},payments\n",
                        "group_by_app": True,
                        "resume": False,
                        "stop_after": "s2",
                    },
                )
                assert r_fleet.status_code == 200, r_fleet.text
                fleet_body = r_fleet.json()
                assert fleet_body["completed_repos"] == 1
                run_id = fleet_body["repo_results"][0]["run_id"]

                # 5. GET /api/fleet/runs
                r_runs = client.get("/api/fleet/runs")
                assert r_runs.status_code == 200
                assert any(r["fleet_run_id"] == fleet_body["fleet_run_id"] for r in r_runs.json()["runs"])

                # 6. GET /api/fleet/checkpoints -> 200, 400 traversal
                r_ck = client.get("/api/fleet/checkpoints", params={"project_path": str(ws)})
                assert r_ck.status_code == 200
                assert any(c["run_id"] == run_id for c in r_ck.json())
                assert client.get("/api/fleet/checkpoints", params={"project_path": "../../etc"}).status_code == 400

                # 7. POST /api/fleet/checkpoints/{run_id}/resume -> 200 existing, 404 unknown
                r_res = client.post(f"/api/fleet/checkpoints/{run_id}/resume", json={})
                assert r_res.status_code == 200, r_res.text
                res_body = r_res.json()
                assert res_body["run_id"] == run_id
                assert res_body["status"] == "RESUMED_COMPLETED"
                assert "S0_CPG" in res_body["resumed_stages"]

                assert client.post("/api/fleet/checkpoints/run-does-not-exist/resume").status_code == 404

                # 8. POST /api/fleet/gc -> 200 dry-run
                r_gc = client.post(
                    "/api/fleet/gc",
                    json={"older_than_days": 0, "keep_last": 0, "dry_run": True},
                )
                assert r_gc.status_code == 200, r_gc.text
                gc_body = r_gc.json()
                assert gc_body["dry_run"] is True
                assert gc_body["pruned_runs"] >= 1

                # 9. Outside-workspace checkpoint resume MUST return HTTP 400
                out_run = iso_store.create_or_get_run(str(outside), commit_sha="deadbeef")
                assert (
                    client.post(f"/api/fleet/checkpoints/{out_run.run_id}/resume", json={}).status_code
                    == 400
                )

                # 10. Fusion corroboration flows immediately into /api/findings & /api/aspm/pasta
                native_sqli = main_mod.Finding(
                    id="NAT-SQLI-1",
                    rule_id="RULE-26-POLYGLOT-SQLI",
                    severity="HIGH",
                    title="SQL Injection in helper",
                    cwe_id="CWE-89",
                    path_nodes=[
                        {
                            "id": "nat-1",
                            "label": "Call",
                            "ast_type": "call",
                            "name": "execute",
                            "code": "cur.execute(sql)",
                            "filepath": "helper.py",
                            "start_line": 2,
                            "end_line": 2,
                            "is_sink": True,
                        }
                    ],
                )
                monkeypatch.setattr(main_mod, "_cached_findings", [native_sqli])
                semgrep_corr = json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "python.sqli",
                                "path": "helper.py",
                                "start": {"line": 2, "col": 5},
                                "end": {"line": 2, "col": 15},
                                "extra": {
                                    "message": "SQL injection",
                                    "severity": "ERROR",
                                    "metadata": {"cwe": ["CWE-89"]},
                                },
                            }
                        ],
                        "errors": [],
                    }
                )
                r_corr = client.post(
                    "/api/fusion/import",
                    json={"project_path": str(ws), "report_json": semgrep_corr},
                )
                assert r_corr.status_code == 200, r_corr.text
                assert r_corr.json()["corroborated_count"] == 1
                r_findings = client.get("/api/findings")
                assert r_findings.status_code == 200
                matched = next(f for f in r_findings.json() if f["id"] == "NAT-SQLI-1")
                assert "SEMGREP" in matched["corroborated_by"]
        finally:
            iso_store.close()

    def test_pdf_export_commit_sha_provenance_mismatch_and_ev_replay_exit1(self, tmp_path: Path):
        import alastor_sdk
        from alastor_cli import cli
        from alastor_sdk import ScanOptions
        from models import EvReplayResponse, EvReplayResultItem

        repo = tmp_path / "repo_pdf"
        _create_vuln_repo(repo)
        vault = tmp_path / "vault"
        out_pdf = tmp_path / "out_pdf"

        res_pdf = alastor_sdk.scan(
            ScanOptions(
                repo=str(repo),
                out_dir=str(out_pdf),
                output_format="pdf",
                vault_dir=str(vault),
                resume=False,
            )
        )
        assert len(res_pdf.output_files) == 1
        pdf_path = Path(res_pdf.output_files[0])
        assert pdf_path.suffix == ".pdf"
        assert pdf_path.read_bytes().startswith(b"%PDF-")

        runner = CliRunner()
        # Missing --run-id in --mode fix -> exit 2
        r_no_run = runner.invoke(
            cli,
            ["remediate", "--repo", str(repo), "--mode", "fix", "--vault-dir", str(vault)],
        )
        assert r_no_run.exit_code == 2

        # Advance git HEAD -> stale run_id provenance mismatch -> exit 2
        (repo / "extra.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "extra.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-m", "advance head"], check=True, capture_output=True)

        r_stale_sha = runner.invoke(
            cli,
            [
                "remediate",
                "--repo",
                str(repo),
                "--mode",
                "fix",
                "--run-id",
                res_pdf.run_id,
                "--vault-dir",
                str(vault),
            ],
        )
        assert r_stale_sha.exit_code == 2

        # EV replay with still_vulnerable_count > 0 -> exit 1
        vuln_replay = EvReplayResponse(
            project_path=str(repo),
            replayed_count=1,
            fixed_verified_count=0,
            still_vulnerable_count=1,
            error_count=0,
            results=[
                EvReplayResultItem(
                    replay_id="EVR-1",
                    probe_family="EV-SQLI-ERROR-DIFF",
                    finding_id="F-1",
                    previous_status="RUNTIME_EXPLOIT_CONFIRMED",
                    new_status="STILL_VULNERABLE",
                    http_status=500,
                    evidence_summary="Still vulnerable",
                )
            ],
        )
        with mock.patch("alastor_cli.alastor_sdk.ev_replay", return_value=vuln_replay):
            r_ev_fail = runner.invoke(cli, ["ev-replay", "--repo", str(repo), "--json"])
        assert r_ev_fail.exit_code == 1
