"""
Strict TDD Suite for ALASTOR v5.1 Task 2:
- Hardened Dual Docker Egress-Proxy Sandbox Images (`docker/sandbox/Dockerfile`,
  `docker/sandbox/egress.Dockerfile`, `docker/sandbox/ca/.gitkeep`)
- Mediated-Egress Sandbox Orchestrator (`backend/engine/sandbox_orchestrator.py`):
  `validate_mediated_llm_host`, `generate_squid_egress_config`,
  `build_mediated_sandbox_plan`, `inspect_sandbox_images`
- SDK & CLI Wiring (`backend/alastor_sdk.py`, `backend/alastor_cli.py`):
  `doctor` sandbox_images drift check, `agentic_hunt`, `agentic_patch`,
  `build_sandbox_plan`, and `alastor scan --sandbox --egress ... --allow-llm-host ...`
- 3 Confined Sync FastAPI Routes (`backend/main.py`):
  `POST /api/cognitive/agentic-hunt`, `POST /api/cognitive/agentic-patch`,
  `POST /api/fleet/sandbox-plan`
"""
from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest import mock

from click.testing import CliRunner
from fastapi.testclient import TestClient
import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

RAW_SECRET_CANARY = "ghp_" + "1234567890abcdef" * 2 + "5678"
BYOK_CANARY = "sk-ant-api03-" + "TESTV51TASK2CANARY1234567890"


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


def _create_sample_vuln_repo(repo_dir: Path) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
    (repo_dir / "app.py").write_text(
        "import sqlite3\n"
        "import subprocess\n\n"
        "def find_user(username: str):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    return conn.execute(f\"SELECT * FROM users WHERE name = '{username}'\")\n\n"
        "def run_diag(arg: str):\n"
        "    return subprocess.check_output('echo ' + arg, shell=True)\n",
        encoding="utf-8",
    )
    (repo_dir / ".env").write_text(
        f"ALASTOR_HOSTILE_V51_CANARY=MUST_NOT_LOAD\nOPENAI_API_KEY={BYOK_CANARY}\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# 1. Dockerfile Static Security Verification
# ---------------------------------------------------------------------------
class TestDockerSandboxFiles:
    def test_dockerfiles_and_ca_gitkeep_security_hardening(self):
        sandbox_dir = REPO_ROOT / "docker" / "sandbox"
        gitkeep = sandbox_dir / "ca" / ".gitkeep"
        scanner_df = sandbox_dir / "Dockerfile"
        egress_df = sandbox_dir / "egress.Dockerfile"

        assert gitkeep.is_file(), "docker/sandbox/ca/.gitkeep must exist"
        assert scanner_df.is_file(), "docker/sandbox/Dockerfile must exist"
        assert egress_df.is_file(), "docker/sandbox/egress.Dockerfile must exist"

        scanner_text = scanner_df.read_text(encoding="utf-8")
        assert "ARG BASE_IMAGE=python:3.12-slim" in scanner_text
        assert "AS ca" in scanner_text
        assert "docker/sandbox/ca/" in scanner_text
        assert "BEGIN CERTIFICATE" in scanner_text
        assert "PRIVATE KEY" in scanner_text
        assert "git" in scanner_text
        assert "ca-certificates" in scanner_text
        assert "socat" in scanner_text
        assert "safe.directory /workspace" in scanner_text
        assert "GIT_CONFIG_COUNT=4" in scanner_text
        assert "core.fsmonitor" in scanner_text
        assert "core.hooksPath" in scanner_text
        assert "core.sshCommand" in scanner_text
        assert "credential.helper" in scanner_text
        assert "backend/requirements.txt" in scanner_text
        assert "--no-cache-dir" in scanner_text
        assert "find / -xdev -perm /6000 -type f -exec chmod ug-s {} +" in scanner_text
        assert "ARG ALASTOR_IMAGE_VERSION=5.1.0" in scanner_text
        assert "ARG ALASTOR_IMAGE_GIT_SHA=unknown" in scanner_text
        assert "org.alastor.version" in scanner_text
        assert "org.alastor.git_sha" in scanner_text
        assert 'org.alastor.role="scanner"' in scanner_text
        assert "USER 65534:65534" in scanner_text
        assert 'ENTRYPOINT ["python", "-m", "alastor_cli"]' in scanner_text

        egress_text = egress_df.read_text(encoding="utf-8")
        assert "ARG BASE_IMAGE=ubuntu:24.04" in egress_text
        assert "squid" in egress_text
        assert "socat" in egress_text
        assert "--no-install-recommends" in egress_text
        assert "/var/lib/apt/lists/*" in egress_text
        assert "find / -xdev -perm /6000 -type f -exec chmod ug-s {} +" in egress_text
        assert "ARG ALASTOR_IMAGE_VERSION=5.1.0" in egress_text
        assert "org.alastor.version" in egress_text
        assert 'org.alastor.role="egress-proxy"' in egress_text
        assert "USER 65534:65534" in egress_text


# ---------------------------------------------------------------------------
# 2. Squid Egress Config, Host Validation, Mediated Plan & Image Inspection
# ---------------------------------------------------------------------------
class TestSandboxOrchestrator:
    def test_validate_mediated_llm_host_and_squid_egress_config(self):
        from engine.hostile_repo_guard import HostileRepoError
        from engine.sandbox_orchestrator import (
            generate_squid_egress_config,
            validate_mediated_llm_host,
        )

        assert validate_mediated_llm_host(" API.OpenAI.COM ") == "api.openai.com"
        assert validate_mediated_llm_host("api.anthropic.com") == "api.anthropic.com"
        assert (
            validate_mediated_llm_host("generativelanguage.googleapis.com")
            == "generativelanguage.googleapis.com"
        )

        cfg = generate_squid_egress_config(
            ["API.OpenAI.COM", "api.anthropic.com", "api.openai.com"],
            port=3128,
        )
        lines = [ln.strip() for ln in cfg.splitlines() if ln.strip()]
        assert "http_port 127.0.0.1:3128" in lines
        assert "acl SSL_ports port 443" in lines
        assert "acl CONNECT method CONNECT" in lines
        assert "acl allowed_llm dstdomain api.openai.com api.anthropic.com" in lines
        assert "http_access deny !CONNECT" in lines
        assert "http_access deny !SSL_ports" in lines
        assert "http_access allow CONNECT SSL_ports allowed_llm" in lines
        assert "http_access deny all" in lines
        assert "cache deny all" in lines
        assert "access_log none" in lines
        assert "cache_log /dev/null" in lines
        assert "pid_filename /tmp/squid.pid" in lines
        assert lines.index("http_access allow CONNECT SSL_ports allowed_llm") < lines.index(
            "http_access deny all"
        )

        # Empty allowlist and bad ports rejected
        with pytest.raises(HostileRepoError):
            generate_squid_egress_config([])
        for bad_port in (80, 443, 1023, 65536, True):
            with pytest.raises(HostileRepoError):
                generate_squid_egress_config(["api.openai.com"], port=bad_port)  # type: ignore[arg-type]

        # Metadata IPs, private/loopback/link-local IPs, wildcards, CRLF/Squid injection rejected
        bad_hosts = [
            "",
            "   ",
            "-evil.com",
            ".openai.com",
            "*.openai.com",
            "169.254.169.254",
            "100.100.100.200",
            "fd00:ec2::254",
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "::1",
            "metadata.google.internal",
            "localhost",
            "sub.localhost",
            "printer.local",
            "db.internal",
            "api.openai.com\nhttp_access allow all",
            "api.openai.com\r\nevil",
            "api.openai.com\x00",
            "api.openai.com\x7f",
            "api.openai.com;evil",
            "api.openai.com#comment",
            "https://api.openai.com",
            "api.openai.com:443",
            "user@api.openai.com",
            "api.openai.com/v1",
            "127.1",
        ]
        for bh in bad_hosts:
            with pytest.raises(HostileRepoError, match="."):
                validate_mediated_llm_host(bh)
            with pytest.raises(HostileRepoError):
                generate_squid_egress_config([bh])

    def test_build_mediated_sandbox_plan_none_and_mediated(self, tmp_path: Path):
        from engine.hostile_repo_guard import HostileRepoError
        from engine.sandbox_orchestrator import (
            ALASTOR_SANDBOX_VERSION,
            EGRESS_IMAGE_NAME,
            SANDBOX_IMAGE_NAME,
            build_mediated_sandbox_plan,
        )
        from models import SandboxExecutionPlan, SandboxPlanRequest

        repo = tmp_path / "repo"
        out_dir = tmp_path / "out"
        _create_sample_vuln_repo(repo)
        out_dir.mkdir()

        # 1. None mode
        plan_none = build_mediated_sandbox_plan(
            SandboxPlanRequest(
                project_path=str(repo),
                output_dir=str(out_dir),
                egress_mode="none",
            )
        )
        assert isinstance(plan_none, SandboxExecutionPlan)
        assert plan_none.egress_mode == "none"
        assert plan_none.squid_config is None
        assert plan_none.egress_docker_cmd is None
        assert len(plan_none.build_commands) == 2
        assert any(
            SANDBOX_IMAGE_NAME in bc and f"ALASTOR_IMAGE_VERSION={ALASTOR_SANDBOX_VERSION}" in bc
            for bc in plan_none.build_commands
        )
        assert any(
            EGRESS_IMAGE_NAME in bc and f"ALASTOR_IMAGE_VERSION={ALASTOR_SANDBOX_VERSION}" in bc
            for bc in plan_none.build_commands
        )
        sc = plan_none.scanner_docker_cmd
        assert "--network=none" in sc
        assert "--read-only" in sc
        assert "--cap-drop=ALL" in sc
        assert "--security-opt=no-new-privileges:true" in sc
        assert "--pids-limit=256" in sc
        assert "--memory=2g" in sc
        assert "--user" in sc and "65534:65534" in sc
        assert any(arg.endswith(":/workspace:ro") for arg in sc)
        assert any(arg.endswith(":/out:rw") for arg in sc)
        assert SANDBOX_IMAGE_NAME in sc
        assert len(plan_none.security_invariants) >= 4

        # 2. Mediated mode: scanner STILL keeps --network=none + Unix socket bridge!
        plan_med = build_mediated_sandbox_plan(
            SandboxPlanRequest(
                project_path=str(repo),
                egress_mode="mediated",
                allowed_llm_hosts=["api.openai.com", "api.anthropic.com"],
            )
        )
        assert plan_med.egress_mode == "mediated"
        assert plan_med.allowed_llm_hosts == ["api.openai.com", "api.anthropic.com"]
        assert plan_med.squid_config is not None
        assert "acl allowed_llm dstdomain api.openai.com api.anthropic.com" in plan_med.squid_config
        assert "http_access deny all" in plan_med.squid_config

        ec = plan_med.egress_docker_cmd
        assert ec is not None
        assert ec[0:3] == ["docker", "run", "--rm"]
        assert "--read-only" in ec
        assert "--cap-drop=ALL" in ec
        assert "--security-opt=no-new-privileges:true" in ec
        assert "--user" in ec and "65534:65534" in ec
        assert "/tmp:rw,noexec,nosuid,size=64m" in ec
        assert any(arg.endswith(":/etc/squid/squid.conf:ro") for arg in ec)
        assert any(arg.endswith(":/run/alastor-egress:rw") for arg in ec)
        assert EGRESS_IMAGE_NAME in ec
        ec_joined = " ".join(ec)
        assert "squid" in ec_joined and "socat" in ec_joined
        assert "/run/alastor-egress/proxy.sock" in ec_joined

        sc_med = plan_med.scanner_docker_cmd
        assert "--network=none" in sc_med
        assert "--read-only" in sc_med
        assert "--cap-drop=ALL" in sc_med
        assert "--security-opt=no-new-privileges:true" in sc_med
        assert "--user" in sc_med and "65534:65534" in sc_med
        assert any(arg.endswith(":/run/alastor-egress:rw") for arg in sc_med)
        assert "ALASTOR_EGRESS_SOCKET=/run/alastor-egress/proxy.sock" in sc_med
        assert "HTTP_PROXY=http://127.0.0.1:3128" in sc_med
        assert "HTTPS_PROXY=http://127.0.0.1:3128" in sc_med
        assert any(arg.endswith(":/workspace:ro") for arg in sc_med)
        assert any(arg.endswith(":/out:rw") for arg in sc_med)

        # 3. Mediated mode with empty allowlist, bad host, traversal, symlink, or colon injection fails closed
        with pytest.raises(HostileRepoError):
            build_mediated_sandbox_plan(
                SandboxPlanRequest(
                    project_path=str(repo),
                    egress_mode="mediated",
                    allowed_llm_hosts=[],
                )
            )
        with pytest.raises(HostileRepoError):
            build_mediated_sandbox_plan(
                SandboxPlanRequest(
                    project_path=str(repo),
                    egress_mode="mediated",
                    allowed_llm_hosts=["169.254.169.254"],
                )
            )
        with pytest.raises(HostileRepoError):
            build_mediated_sandbox_plan(
                SandboxPlanRequest(
                    project_path=str(repo),
                    output_dir=str(out_dir / "bad:rw"),
                    egress_mode="none",
                )
            )
        with pytest.raises(HostileRepoError):
            build_mediated_sandbox_plan(
                SandboxPlanRequest(
                    project_path=str(repo / ".." / "repo"),
                    egress_mode="none",
                )
            )
        repo_link = tmp_path / "repo_link"
        _create_dir_link(repo_link, repo)
        try:
            with pytest.raises(HostileRepoError):
                build_mediated_sandbox_plan(
                    SandboxPlanRequest(
                        project_path=str(repo_link),
                        egress_mode="none",
                    )
                )
        finally:
            _remove_dir_link(repo_link)

    def test_inspect_sandbox_images_ready_drifted_missing_and_no_docker(self):
        from engine.sandbox_orchestrator import (
            ALASTOR_SANDBOX_VERSION,
            EGRESS_IMAGE_NAME,
            SANDBOX_IMAGE_NAME,
            inspect_sandbox_images,
        )

        # 1. Both matching 5.1.0
        def _runner_both_ok(cmd: List[str], **_kw: Any) -> SimpleNamespace:
            return SimpleNamespace(returncode=0, stdout="5.1.0\n", stderr="")

        st_ok = inspect_sandbox_images(subprocess_runner=_runner_both_ok)
        assert st_ok.docker_available is True
        assert st_ok.expected_version == ALASTOR_SANDBOX_VERSION
        assert st_ok.sandbox_image.present is True
        assert st_ok.sandbox_image.label_version == "5.1.0"
        assert st_ok.sandbox_image.version_matches is True
        assert st_ok.egress_image.present is True
        assert st_ok.egress_image.label_version == "5.1.0"
        assert st_ok.egress_image.version_matches is True
        assert st_ok.ready_for_none_mode is True
        assert st_ok.ready_for_mediated_mode is True

        # 2. Drifted 5.0.0 on egress image
        def _runner_drifted(cmd: List[str], **_kw: Any) -> SimpleNamespace:
            img = cmd[-1]
            if img == SANDBOX_IMAGE_NAME:
                return SimpleNamespace(returncode=0, stdout="5.1.0\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="5.0.0\n", stderr="")

        st_drift = inspect_sandbox_images(subprocess_runner=_runner_drifted)
        assert st_drift.docker_available is True
        assert st_drift.sandbox_image.version_matches is True
        assert st_drift.egress_image.present is True
        assert st_drift.egress_image.label_version == "5.0.0"
        assert st_drift.egress_image.version_matches is False
        assert st_drift.ready_for_none_mode is True
        assert st_drift.ready_for_mediated_mode is False

        # 3. Missing egress image
        def _runner_missing_egress(cmd: List[str], **_kw: Any) -> SimpleNamespace:
            if cmd[-1] == SANDBOX_IMAGE_NAME:
                return SimpleNamespace(returncode=0, stdout="5.1.0\n", stderr="")
            return SimpleNamespace(
                returncode=1,
                stdout="",
                stderr=f"Error: No such object: {EGRESS_IMAGE_NAME}",
            )

        st_miss = inspect_sandbox_images(subprocess_runner=_runner_missing_egress)
        assert st_miss.docker_available is True
        assert st_miss.sandbox_image.present is True
        assert st_miss.egress_image.present is False
        assert st_miss.ready_for_none_mode is True
        assert st_miss.ready_for_mediated_mode is False

        # 4. Docker daemon down / missing degrades gracefully (never raises)
        def _runner_daemon_down(cmd: List[str], **_kw: Any) -> SimpleNamespace:
            return SimpleNamespace(
                returncode=1,
                stdout="",
                stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
            )

        st_down = inspect_sandbox_images(subprocess_runner=_runner_daemon_down)
        assert st_down.docker_available is False
        assert st_down.ready_for_none_mode is False
        assert st_down.ready_for_mediated_mode is False

        with mock.patch("engine.sandbox_orchestrator.shutil.which", return_value=None):
            st_no_bin = inspect_sandbox_images()
        assert st_no_bin.docker_available is False
        assert st_no_bin.sandbox_image.present is False
        assert st_no_bin.egress_image.present is False
        assert st_no_bin.ready_for_none_mode is False
        assert st_no_bin.ready_for_mediated_mode is False


# ---------------------------------------------------------------------------
# 3. SDK & CLI Wiring Tests
# ---------------------------------------------------------------------------
class TestV51SdkAndCliWiring:
    def test_sdk_doctor_sandbox_images_and_agentic_functions(self, tmp_path: Path):
        import alastor_sdk
        from models import (
            AgenticHuntResponse,
            AgenticPatchResponse,
            BestFixLocation,
            Finding,
            SandboxExecutionPlan,
            SandboxImageInfo,
            SandboxImageStatus,
        )

        vault = tmp_path / "vault"
        repo = tmp_path / "repo"
        _create_sample_vuln_repo(repo)

        # 1. doctor() sandbox_images OK when both match 5.1.0
        ready_status = SandboxImageStatus(
            docker_available=True,
            expected_version="5.1.0",
            sandbox_image=SandboxImageInfo(
                image_name="alastor-sandbox:local",
                present=True,
                label_version="5.1.0",
                expected_version="5.1.0",
                version_matches=True,
                detail="ok",
            ),
            egress_image=SandboxImageInfo(
                image_name="alastor-egress:local",
                present=True,
                label_version="5.1.0",
                expected_version="5.1.0",
                version_matches=True,
                detail="ok",
            ),
            ready_for_none_mode=True,
            ready_for_mediated_mode=True,
        )
        with mock.patch("alastor_sdk.inspect_sandbox_images", return_value=ready_status):
            doc_ok = alastor_sdk.doctor(vault_dir=str(vault))
        chk_ok = next((c for c in doc_ok.checks if c.name == "sandbox_images"), None)
        assert chk_ok is not None
        assert chk_ok.status == "OK"

        # 2. doctor() sandbox_images WARN when drifted/missing
        drift_status = SandboxImageStatus(
            docker_available=True,
            expected_version="5.1.0",
            sandbox_image=SandboxImageInfo(
                image_name="alastor-sandbox:local",
                present=True,
                label_version="5.0.0",
                expected_version="5.1.0",
                version_matches=False,
                detail="Version 5.0.0 drifted from 5.1.0",
            ),
            egress_image=SandboxImageInfo(
                image_name="alastor-egress:local",
                present=False,
                label_version=None,
                expected_version="5.1.0",
                version_matches=False,
                detail="Missing",
            ),
            ready_for_none_mode=False,
            ready_for_mediated_mode=False,
        )
        with mock.patch("alastor_sdk.inspect_sandbox_images", return_value=drift_status):
            doc_warn = alastor_sdk.doctor(vault_dir=str(vault))
        chk_warn = next((c for c in doc_warn.checks if c.name == "sandbox_images"), None)
        assert chk_warn is not None
        assert chk_warn.status == "WARN"
        assert "5.1.0" in chk_warn.detail

        # 3. agentic_hunt (deterministic fallback, zero secret leakage)
        hunt_res = alastor_sdk.agentic_hunt(
            str(repo),
            use_byok_llm=False,
            run_s6_verify=True,
            vault_dir=str(vault),
        )
        assert isinstance(hunt_res, AgenticHuntResponse)
        assert hunt_res.execution_mode == "DETERMINISTIC_FALLBACK"
        assert len(hunt_res.trace) >= 2
        assert BYOK_CANARY not in hunt_res.model_dump_json()

        # 4. agentic_patch (deterministic fallback with inline finding)
        finding = Finding(
            id="SDK-V51-PATCH-1",
            rule_id="RULE-7-SQLI-FORMAT",
            severity="HIGH",
            title=f"SQLi {RAW_SECRET_CANARY}",
            description=f"Unsafe SQL interpolation {RAW_SECRET_CANARY}",
            cwe_id="CWE-89",
            secret_value_raw=RAW_SECRET_CANARY,
            best_fix_location=BestFixLocation(
                node_id="n1",
                filepath="app.py",
                line=6,
                code_snippet="return conn.execute(f\"SELECT * FROM users WHERE name = '{username}'\")",
            ),
        )
        patch_res = alastor_sdk.agentic_patch(
            str(repo),
            finding=finding,
            use_byok_llm=False,
            vault_dir=str(vault),
        )
        assert isinstance(patch_res, AgenticPatchResponse)
        assert patch_res.execution_mode == "DETERMINISTIC_FALLBACK"
        assert patch_res.s11_panel is not None
        assert len(patch_res.trace) >= 2
        assert RAW_SECRET_CANARY not in patch_res.model_dump_json()

        # 5. build_sandbox_plan
        plan = alastor_sdk.build_sandbox_plan(
            str(repo),
            egress_mode="mediated",
            allowed_llm_hosts=["api.openai.com"],
        )
        assert isinstance(plan, SandboxExecutionPlan)
        assert plan.egress_mode == "mediated"
        assert "--network=none" in plan.scanner_docker_cmd
        assert plan.squid_config is not None and "api.openai.com" in plan.squid_config

    def test_cli_doctor_and_sandbox_mediated_egress(self, tmp_path: Path):
        from alastor_cli import cli

        repo = tmp_path / "cli_repo"
        out_dir = tmp_path / "cli_out"
        _create_sample_vuln_repo(repo)
        out_dir.mkdir()
        vault = tmp_path / "vault"

        runner = CliRunner()

        r_doc = runner.invoke(cli, ["doctor", "--vault-dir", str(vault), "--json"])
        assert r_doc.exit_code == 0, r_doc.output
        doc_data = json.loads(r_doc.output)
        assert any(c["name"] == "sandbox_images" for c in doc_data["checks"])

        r_med = runner.invoke(
            cli,
            [
                "scan",
                "--repo",
                str(repo),
                "--out",
                str(out_dir),
                "--sandbox",
                "--egress",
                "mediated",
                "--allow-llm-host",
                "api.openai.com",
                "--json",
            ],
        )
        assert r_med.exit_code == 0, r_med.output
        med_data = json.loads(r_med.output)
        assert med_data["egress_mode"] == "mediated"
        assert med_data["allowed_llm_hosts"] == ["api.openai.com"]
        assert "acl allowed_llm dstdomain api.openai.com" in med_data["squid_config"]
        assert "--network=none" in med_data["scanner_docker_cmd"]
        assert "--network=none" in med_data["docker_argv"]
        assert med_data["egress_docker_cmd"] is not None
        assert "alastor-egress:local" in med_data["egress_docker_cmd"]

        # Cloud metadata IP rejected cleanly with exit 2
        r_bad = runner.invoke(
            cli,
            [
                "scan",
                "--repo",
                str(repo),
                "--sandbox",
                "--egress",
                "mediated",
                "--allow-llm-host",
                "169.254.169.254",
                "--json",
            ],
        )
        assert r_bad.exit_code == 2

        # Mediated egress without any allowed host fails with exit 2
        r_empty = runner.invoke(
            cli,
            [
                "scan",
                "--repo",
                str(repo),
                "--sandbox",
                "--egress",
                "mediated",
                "--json",
            ],
        )
        assert r_empty.exit_code == 2


# ---------------------------------------------------------------------------
# 4. Confined Sync FastAPI Routes (/api/cognitive/agentic-*, /api/fleet/sandbox-plan)
# ---------------------------------------------------------------------------
class TestV51FastApiRoutes:
    def test_v51_routes_are_sync_handlers(self):
        import main as main_mod

        expected = {
            "/api/cognitive/agentic-hunt",
            "/api/cognitive/agentic-patch",
            "/api/fleet/sandbox-plan",
        }
        found = {}
        for route in main_mod.app.routes:
            path = getattr(route, "path", "")
            if path in expected:
                found[path] = getattr(route, "endpoint", None)

        assert set(found.keys()) == expected
        for path, endpoint in found.items():
            assert endpoint is not None
            assert not inspect.iscoroutinefunction(endpoint), (
                f"Route {path} MUST be a sync def handler"
            )

    def test_v51_routes_confinement_and_functional_lifecycle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        import main as main_mod
        from database.checkpoint_store import CheckpointStore
        from engine.compliance_and_rules_engine import CustomRuleEngine
        from engine.exploit_verification_engine import ExploitVerificationEngine
        from models import BestFixLocation, Finding

        ws = tmp_path / "confined_ws"
        _create_sample_vuln_repo(ws)
        outside = tmp_path / "outside_ws"
        _create_sample_vuln_repo(outside)

        vault = tmp_path / "vault"
        iso_store = CheckpointStore(str(vault))
        iso_ev = ExploitVerificationEngine(vault_dir=str(vault))
        iso_rules = CustomRuleEngine(vault_dir=str(vault))

        inline_finding = Finding(
            id="API-V51-PATCH-1",
            rule_id="RULE-7-SQLI-FORMAT",
            severity="HIGH",
            cwe_id="CWE-89",
            title=f"SQL Injection near {RAW_SECRET_CANARY}",
            description="Dynamic SQL f-string",
            secret_value_raw=RAW_SECRET_CANARY,
            best_fix_location=BestFixLocation(
                node_id="n-v51-1",
                filepath="app.py",
                line=6,
                code_snippet="return conn.execute(f\"SELECT * FROM users WHERE name = '{username}'\")",
            ),
        )

        monkeypatch.setattr(main_mod, "startup_event", lambda: None)
        monkeypatch.setattr(main_mod, "shutdown_event", lambda: None)
        monkeypatch.setattr(main_mod, "checkpoint_store", iso_store)
        monkeypatch.setattr(main_mod, "ev_engine", iso_ev)
        monkeypatch.setattr(main_mod, "custom_rule_engine", iso_rules)
        monkeypatch.setattr(main_mod, "_get_ai_allowed_roots", lambda: [str(ws)])
        monkeypatch.setattr(main_mod, "current_scan_dir", str(ws))
        monkeypatch.setattr(main_mod, "_cached_findings", [])
        monkeypatch.setattr(main_mod, "_cached_external_findings", [])
        monkeypatch.setattr(main_mod, "_cached_cognitive_findings", [])
        monkeypatch.setattr(main_mod, "_cached_cognitive_dir", "")

        try:
            with TestClient(main_mod.app, raise_server_exceptions=False) as client:
                # 1. Traversal / outside-root / empty / regular-file / symlink -> HTTP 400 on ALL 3 routes
                reg_file = ws / "app.py"
                for bad_path in ("../../etc", str(outside), "", str(reg_file)):
                    assert (
                        client.post(
                            "/api/cognitive/agentic-hunt",
                            json={"project_path": bad_path, "use_byok_llm": False},
                        ).status_code
                        == 400
                    )
                    assert (
                        client.post(
                            "/api/cognitive/agentic-patch",
                            json={
                                "project_path": bad_path,
                                "finding": inline_finding.model_dump(),
                                "use_byok_llm": False,
                            },
                        ).status_code
                        == 400
                    )
                    assert (
                        client.post(
                            "/api/fleet/sandbox-plan",
                            json={"project_path": bad_path, "egress_mode": "none"},
                        ).status_code
                        == 400
                    )

                # Confined symlink / junction project_path -> HTTP 400
                ws_link = tmp_path / "ws_link"
                _create_dir_link(ws_link, ws)
                try:
                    with monkeypatch.context() as mp:
                        mp.setattr(main_mod, "_get_ai_allowed_roots", lambda: [str(tmp_path)])
                        for ep, payload in (
                            ("/api/cognitive/agentic-hunt", {"project_path": str(ws_link), "use_byok_llm": False}),
                            (
                                "/api/cognitive/agentic-patch",
                                {
                                    "project_path": str(ws_link),
                                    "finding": inline_finding.model_dump(),
                                    "use_byok_llm": False,
                                },
                            ),
                            ("/api/fleet/sandbox-plan", {"project_path": str(ws_link), "egress_mode": "none"}),
                        ):
                            assert client.post(ep, json=payload).status_code == 400
                finally:
                    _remove_dir_link(ws_link)

                # output_dir traversal / outside-root / colon injection / symlink on /api/fleet/sandbox-plan -> HTTP 400
                for bad_out in ("../../etc", str(outside), str(ws / "bad:rw"), str(reg_file)):
                    r_bad_out = client.post(
                        "/api/fleet/sandbox-plan",
                        json={
                            "project_path": str(ws),
                            "output_dir": bad_out,
                            "egress_mode": "none",
                        },
                    )
                    assert r_bad_out.status_code == 400

                out_link = ws / "out_link"
                _create_dir_link(out_link, outside)
                try:
                    assert (
                        client.post(
                            "/api/fleet/sandbox-plan",
                            json={
                                "project_path": str(ws),
                                "output_dir": str(out_link),
                                "egress_mode": "none",
                            },
                        ).status_code
                        == 400
                    )
                finally:
                    _remove_dir_link(out_link)

                # 2. POST /api/cognitive/agentic-hunt (use_byok_llm=False) -> 200 DETERMINISTIC_FALLBACK
                r_hunt = client.post(
                    "/api/cognitive/agentic-hunt",
                    json={"project_path": str(ws), "use_byok_llm": False, "run_s6_verify": True},
                )
                assert r_hunt.status_code == 200, r_hunt.text
                hunt_body = r_hunt.json()
                assert hunt_body["execution_mode"] == "DETERMINISTIC_FALLBACK"
                assert hunt_body["stop_reason"] == "FALLBACK_COMPLETE"
                assert len(hunt_body["trace"]) >= 2
                assert len(hunt_body["findings"]) >= 1
                assert BYOK_CANARY not in r_hunt.text

                # Discovered cognitive finding ID can be patched directly via /api/cognitive/agentic-patch
                discovered_fid = hunt_body["findings"][0]["id"]
                r_patch_cog = client.post(
                    "/api/cognitive/agentic-patch",
                    json={
                        "project_path": str(ws),
                        "finding_id": discovered_fid,
                        "use_byok_llm": False,
                    },
                )
                assert r_patch_cog.status_code == 200, r_patch_cog.text
                assert r_patch_cog.json()["finding_id"] == discovered_fid

                # 3. POST /api/cognitive/agentic-patch
                # Neither finding nor finding_id -> 400
                assert (
                    client.post(
                        "/api/cognitive/agentic-patch",
                        json={"project_path": str(ws), "use_byok_llm": False},
                    ).status_code
                    == 400
                )
                # Unknown finding_id -> 404
                assert (
                    client.post(
                        "/api/cognitive/agentic-patch",
                        json={
                            "project_path": str(ws),
                            "finding_id": "DOES-NOT-EXIST-999",
                            "use_byok_llm": False,
                        },
                    ).status_code
                    == 404
                )
                # Valid inline finding -> 200 with s11_panel and trace
                r_patch = client.post(
                    "/api/cognitive/agentic-patch",
                    json={
                        "project_path": str(ws),
                        "finding": inline_finding.model_dump(),
                        "use_byok_llm": False,
                    },
                )
                assert r_patch.status_code == 200, r_patch.text
                patch_body = r_patch.json()
                assert patch_body["execution_mode"] == "DETERMINISTIC_FALLBACK"
                assert patch_body["s11_panel"] is not None
                assert len(patch_body["trace"]) >= 2
                assert RAW_SECRET_CANARY not in r_patch.text

                # Lookup finding_id from _cached_findings -> 200
                monkeypatch.setattr(main_mod, "_cached_findings", [inline_finding])
                r_patch_by_id = client.post(
                    "/api/cognitive/agentic-patch",
                    json={
                        "project_path": str(ws),
                        "finding_id": inline_finding.id,
                        "use_byok_llm": False,
                    },
                )
                assert r_patch_by_id.status_code == 200, r_patch_by_id.text
                assert r_patch_by_id.json()["finding_id"] == inline_finding.id

                # 4. POST /api/fleet/sandbox-plan
                r_plan = client.post(
                    "/api/fleet/sandbox-plan",
                    json={
                        "project_path": str(ws),
                        "egress_mode": "mediated",
                        "allowed_llm_hosts": ["api.anthropic.com"],
                    },
                )
                assert r_plan.status_code == 200, r_plan.text
                plan_body = r_plan.json()
                assert plan_body["egress_mode"] == "mediated"
                assert "acl allowed_llm dstdomain api.anthropic.com" in plan_body["squid_config"]
                assert "http_access deny all" in plan_body["squid_config"]
                assert "--network=none" in plan_body["scanner_docker_cmd"]
                assert plan_body["egress_docker_cmd"] is not None

                # Bad hosts & invalid mode -> 400 (or 422 on schema enum, never 500)
                for bad_host in ("169.254.169.254", "metadata.google.internal", "*.anthropic.com"):
                    r_bad_host = client.post(
                        "/api/fleet/sandbox-plan",
                        json={
                            "project_path": str(ws),
                            "egress_mode": "mediated",
                            "allowed_llm_hosts": [bad_host],
                        },
                    )
                    assert r_bad_host.status_code == 400

                assert (
                    client.post(
                        "/api/fleet/sandbox-plan",
                        json={
                            "project_path": str(ws),
                            "egress_mode": "mediated",
                            "allowed_llm_hosts": [],
                        },
                    ).status_code
                    == 400
                )
                r_bad_mode = client.post(
                    "/api/fleet/sandbox-plan",
                    json={"project_path": str(ws), "egress_mode": "open"},
                )
                assert r_bad_mode.status_code in (400, 422)

                # 5. GET /api/fleet/doctor includes sandbox_images check
                r_doc = client.get("/api/fleet/doctor")
                assert r_doc.status_code == 200, r_doc.text
                assert any(c["name"] == "sandbox_images" for c in r_doc.json()["checks"])

                # 6. Verify graph_store_mgr is forwarded ONLY when workspace matches active scan root
                ws2 = tmp_path / "confined_ws_2"
                _create_sample_vuln_repo(ws2)
                captured_stores: List[Any] = []

                def _spy_hunt(req_obj, ai_engine=None, graph_store=None):
                    captured_stores.append((req_obj.project_path, ai_engine, graph_store))
                    from models import AgenticHuntResponse
                    return AgenticHuntResponse(
                        project_path=req_obj.project_path,
                        execution_mode="DETERMINISTIC_FALLBACK",
                        turns_used=1,
                        tool_calls_used=1,
                        stop_reason="FALLBACK_COMPLETE",
                    )

                fake_store = mock.MagicMock()
                with monkeypatch.context() as mp:
                    mp.setattr(main_mod, "_get_ai_allowed_roots", lambda: [str(ws), str(ws2)])
                    mp.setattr(main_mod, "graph_store_mgr", fake_store)
                    mp.setattr(main_mod, "run_agentic_react_hunt", _spy_hunt)
                    assert (
                        client.post(
                            "/api/cognitive/agentic-hunt",
                            json={"project_path": str(ws), "use_byok_llm": True},
                        ).status_code
                        == 200
                    )
                    assert (
                        client.post(
                            "/api/cognitive/agentic-hunt",
                            json={"project_path": str(ws2), "use_byok_llm": False},
                        ).status_code
                        == 200
                    )
                assert len(captured_stores) == 2
                assert captured_stores[0][1] is main_mod.frontier_ai_engine
                assert captured_stores[0][2] is fake_store
                assert captured_stores[1][1] is None
                assert captured_stores[1][2] is None
        finally:
            if iso_store._conn is not None:
                iso_store.close()
