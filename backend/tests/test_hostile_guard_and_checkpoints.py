"""
TDD Suite for ALASTOR v5.0 Pillar 4 Task 1:
- Pillar 4 Data Contracts (`models.py`: Finding fusion fields + Section 17 models)
- Hostile-Repo Isolation (`engine/hostile_repo_guard.py`)
- SQLite WAL Stage Checkpoints, Host Provenance & GC (`database/checkpoint_store.py`)
"""
from __future__ import annotations

import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from database.checkpoint_store import CheckpointStore
from engine.hostile_repo_guard import (
    HardenedGitCommand,
    HostileRepoError,
    assert_safe_config_source,
    build_hardened_git_env_and_argv,
    build_sandbox_docker_command,
    find_hostile_target_configs,
    get_repo_commit_sha,
    run_hardened_git,
    safe_cleanup_workspace,
    validate_clone_url,
)
from models import (
    DoctorCheckItem,
    DoctorReport,
    EstimateReport,
    Finding,
    FleetAppGroupRollup,
    FleetRepoResult,
    FleetRepoSpec,
    FleetRunListResponse,
    FleetRunRequest,
    FleetRunResponse,
    GcReport,
    GcRequest,
    ScanRunCheckpointSummary,
    ScannerFusionRequest,
    ScannerFusionResponse,
    StageCheckpointItem,
)


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


def _init_git_repo_with_commit(repo_dir: Path) -> str:
    subprocess.run(["git", "init", str(repo_dir)], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.name", "Alastor Test"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.email", "alastor-test@example.com"],
        check=True,
        capture_output=True,
        text=True,
    )
    (repo_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (repo_dir / ".gitattributes").write_text("*.py filter=evil diff=evil\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-m", "initial"],
        check=True,
        capture_output=True,
        text=True,
    )
    res = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout.strip()


class TestPillar4Models:
    def test_finding_fusion_fields_backward_compatible(self):
        legacy = Finding(
            id="f-1",
            rule_id="RULE-1",
            severity="HIGH",
            title="SQL Injection",
        )
        assert legacy.source_engine is None
        assert legacy.corroborated_by == []

        fused = Finding(
            id="f-2",
            rule_id="SEMGREP-SQLI",
            severity="CRITICAL",
            title="SQLi from Semgrep",
            source_engine="SEMGREP",
            corroborated_by=["ALASTOR_CPG", "CODEQL"],
        )
        assert fused.source_engine == "SEMGREP"
        assert fused.corroborated_by == ["ALASTOR_CPG", "CODEQL"]

    def test_section17_models_construct_with_expected_defaults(self):
        doc = DoctorReport(
            overall_status="READY",
            python_version="3.12.10",
            parsers_ready=8,
            parsers_total=8,
            graph_backend="EMBEDDED_SQLITE",
            git_available=True,
            docker_available=False,
            vault_path="/tmp/vault",
            vault_writable=True,
            checks=[DoctorCheckItem(name="git", status="OK", detail="git available")],
        )
        assert doc.overall_status == "READY"
        assert len(doc.checks) == 1

        est = EstimateReport(project_path="/repo", total_files=10, total_loc=500)
        assert est.recommended_profile == "deterministic"

        fusion_req = ScannerFusionRequest(project_path="/repo", report_json="{}")
        assert fusion_req.correlate_cpg is True
        fusion_res = ScannerFusionResponse(
            project_path="/repo",
            detected_format="SARIF_2_1",
            imported_raw_count=3,
            normalized_count=3,
            corroborated_count=1,
            new_unique_count=2,
            cpg_enriched_count=2,
        )
        assert fusion_res.s6_verified_count == 0

        fleet_req = FleetRunRequest(repos=[FleetRepoSpec(repo="/repo", app_group="core")])
        assert fleet_req.max_workers == 2
        assert fleet_req.resume is True

        gc_req = GcRequest()
        assert gc_req.older_than_days == 30
        assert gc_req.keep_last == 20


class TestHostileRepoGuard:
    def test_hardened_git_neutralizes_malicious_config_drivers(self, tmp_path: Path):
        repo_dir = tmp_path / "hostile_repo"
        repo_dir.mkdir()
        expected_sha = _init_git_repo_with_commit(repo_dir)

        marker = tmp_path / "PWNED_MARKER.txt"
        evil_script = tmp_path / "evil_trigger.py"
        evil_script.write_text(
            f"import pathlib\npathlib.Path(r'{marker}').write_text('pwned')\n",
            encoding="utf-8",
        )
        py_exe = sys.executable.replace("\\", "/")
        evil_cmd = f"{py_exe} {evil_script.as_posix()}"

        hooks_dir = repo_dir / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        (hooks_dir / "post-checkout").write_text(f"#!/bin/sh\n{evil_cmd}\n", encoding="utf-8")

        git_config = repo_dir / ".git" / "config"
        with git_config.open("a", encoding="utf-8") as fh:
            fh.write(
                f"\n[core]\n"
                f"\tfsmonitor = {evil_cmd}\n"
                f"\thooksPath = .git/hooks\n"
                f"\tsshCommand = {evil_cmd}\n"
                f"\tpager = {evil_cmd}\n"
                f"\teditor = {evil_cmd}\n"
                f"\tgitProxy = {evil_cmd}\n"
                f"\taskPass = {evil_cmd}\n"
                f"\talternateRefsCommand = {evil_cmd}\n"
                f"[sequence]\n"
                f"\teditor = {evil_cmd}\n"
                f"[uploadpack]\n"
                f"\tpackObjectsHook = {evil_cmd}\n"
                f"[gpg]\n"
                f"\tprogram = {evil_cmd}\n"
                f'[gpg "ssh"]\n'
                f"\tprogram = {evil_cmd}\n"
                f'[filter "evil"]\n'
                f"\tsmudge = {evil_cmd}\n"
                f"\tclean = {evil_cmd}\n"
                f"\tprocess = {evil_cmd}\n"
                f"\trequired = true\n"
                f'[filter "Evil"]\n'
                f"\tsmudge = {evil_cmd}\n"
                f"\tclean = {evil_cmd}\n"
                f"\tprocess = {evil_cmd}\n"
                f"\trequired = true\n"
                f"[diff]\n"
                f"\texternal = {evil_cmd}\n"
                f'[diff "evil"]\n'
                f"\ttextconv = {evil_cmd}\n"
                f"\tcommand = {evil_cmd}\n"
                f'[diff "Evil"]\n'
                f"\ttextconv = {evil_cmd}\n"
                f"\tcommand = {evil_cmd}\n"
                f"[pager]\n"
                f"\tdiff = {evil_cmd}\n"
                f'[remote "origin"]\n'
                f"\tuploadpack = {evil_cmd}\n"
                f"\treceivepack = {evil_cmd}\n"
                f"\tvcs = {evil_cmd}\n"
                f"\tproxy = {evil_cmd}\n"
                f'[credential "https://evil.example"]\n'
                f"\thelper = {evil_cmd}\n"
                f'[merge "evil"]\n'
                f"\tdriver = {evil_cmd}\n"
                f'[protocol "ext"]\n'
                f"\tallow = always\n"
                f'[protocol "https"]\n'
                f"\tallow = always\n"
                f'[url "ext::sh -c evil"]\n'
                f"\tinsteadOf = https://github.com/\n"
                f"\tpushInsteadOf = https://github.com/\n"
            )

        custom_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "HOME": os.environ.get("HOME", str(tmp_path)),
            "USERPROFILE": os.environ.get("USERPROFILE", str(tmp_path)),
            "GIT_EXTERNAL_DIFF": evil_cmd,
            "GIT_SSH_COMMAND": evil_cmd,
            "GIT_DIR": str(tmp_path / "hijack_git_dir"),
            "GIT_CONFIG_PARAMETERS": "'core.fsmonitor=evil'",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "user.name",
            "GIT_CONFIG_VALUE_0": "PreservedPin",
        }
        hardened = build_hardened_git_env_and_argv(str(repo_dir), environ=custom_env)
        assert isinstance(hardened, HardenedGitCommand)
        assert "GIT_EXTERNAL_DIFF" not in hardened.env
        assert "GIT_SSH_COMMAND" not in hardened.env
        assert "GIT_DIR" not in hardened.env
        assert "GIT_CONFIG_PARAMETERS" not in hardened.env

        # Preserved pre-existing GIT_CONFIG_COUNT pin + forced security overrides (case-sensitive subsections)
        pin_count = int(hardened.env["GIT_CONFIG_COUNT"])
        exact_pins = {
            hardened.env[f"GIT_CONFIG_KEY_{i}"]: hardened.env[f"GIT_CONFIG_VALUE_{i}"]
            for i in range(pin_count)
        }
        lower_pins = {k.lower(): v for k, v in exact_pins.items()}
        assert lower_pins.get("user.name") == "PreservedPin"
        assert lower_pins.get("core.fsmonitor") == ""
        assert lower_pins.get("core.hookspath") == "/dev/null"
        assert lower_pins.get("core.sshcommand") == "false"
        assert lower_pins.get("core.pager") == ""
        assert lower_pins.get("core.editor") == "false"
        assert lower_pins.get("sequence.editor") == "false"
        assert lower_pins.get("core.gitproxy") == ""
        assert lower_pins.get("core.askpass") == ""
        assert lower_pins.get("core.alternaterefscommand") == ""
        assert lower_pins.get("uploadpack.packobjectshook") == ""
        assert lower_pins.get("gpg.program") == "false"
        assert lower_pins.get("gpg.ssh.program") == "false"
        assert lower_pins.get("protocol.allow") == "user"
        assert lower_pins.get("protocol.file.allow") == "never"
        assert lower_pins.get("protocol.ext.allow") == "never"
        assert lower_pins.get("protocol.https.allow") == "user"
        assert lower_pins.get("diff.external") == ""
        assert lower_pins.get("credential.helper") == ""
        assert lower_pins.get("credential.https://evil.example.helper") == ""
        assert lower_pins.get("pager.diff") == "false"
        assert lower_pins.get("remote.origin.uploadpack") == ""
        assert lower_pins.get("remote.origin.receivepack") == ""
        assert lower_pins.get("remote.origin.vcs") == ""
        assert lower_pins.get("remote.origin.proxy") == ""
        assert lower_pins.get("merge.evil.driver") == "false"
        assert lower_pins.get("url.ext::sh -c evil.insteadof") == ""
        assert lower_pins.get("url.ext::sh -c evil.pushinsteadof") == ""

        # Both case-variant subsections MUST be neutralized independently!
        for variant in ("evil", "Evil"):
            assert exact_pins.get(f"filter.{variant}.smudge") == ""
            assert exact_pins.get(f"filter.{variant}.clean") == ""
            assert exact_pins.get(f"filter.{variant}.process") == ""
            assert exact_pins.get(f"filter.{variant}.required") == "false"
            assert exact_pins.get(f"diff.{variant}.textconv") == ""
            assert exact_pins.get(f"diff.{variant}.command") == ""

        (repo_dir / "app.py").write_text("print('modified')\n", encoding="utf-8")
        status_res = run_hardened_git(str(repo_dir), ["status"], environ=custom_env)
        assert status_res.returncode == 0
        diff_res = run_hardened_git(str(repo_dir), ["diff"], environ=custom_env)
        assert diff_res.returncode == 0
        assert "modified" in diff_res.stdout
        log_res = run_hardened_git(str(repo_dir), ["log", "-p", "-n", "1"], environ=custom_env)
        assert log_res.returncode == 0
        sha = get_repo_commit_sha(str(repo_dir))
        assert sha == expected_sha
        assert not marker.exists(), "Malicious git config driver executed!"

    def test_benign_repo_diff_works_cleanly(self, tmp_path: Path):
        repo_dir = tmp_path / "benign_repo"
        repo_dir.mkdir()
        _init_git_repo_with_commit(repo_dir)
        (repo_dir / "app.py").write_text("print('updated')\n", encoding="utf-8")

        hardened = build_hardened_git_env_and_argv(str(repo_dir))
        pin_keys = {
            hardened.env[f"GIT_CONFIG_KEY_{i}"].lower()
            for i in range(int(hardened.env["GIT_CONFIG_COUNT"]))
        }
        assert "diff.external" not in pin_keys

        diff_res = run_hardened_git(str(repo_dir), ["diff"])
        assert diff_res.returncode == 0
        assert "+print('updated')" in diff_res.stdout

    def test_get_repo_commit_sha_non_git_returns_empty_and_missing_raises(self, tmp_path: Path):
        non_git = tmp_path / "plain_dir"
        non_git.mkdir()
        assert get_repo_commit_sha(str(non_git)) == ""

        with pytest.raises(HostileRepoError):
            build_hardened_git_env_and_argv(str(tmp_path / "does_not_exist"))

    def test_assert_safe_config_source_refuses_target_configs(self, tmp_path: Path):
        repo_dir = tmp_path / "target_repo"
        repo_dir.mkdir()
        (repo_dir / ".env").write_text("OPENAI_API_KEY=sk-evil\n", encoding="utf-8")
        (repo_dir / "config.yaml").write_text("ai:\n  provider: evil\n", encoding="utf-8")
        (repo_dir / ".alastor.yaml").write_text("unsafe: true\n", encoding="utf-8")

        hooks = repo_dir / ".git" / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "pre-commit.sample").write_text("# sample", encoding="utf-8")
        (hooks / "post-checkout").write_text("#!/bin/sh\nid\n", encoding="utf-8")

        with pytest.raises(HostileRepoError):
            assert_safe_config_source(str(repo_dir / ".env"), str(repo_dir))
        with pytest.raises(HostileRepoError):
            assert_safe_config_source(str(repo_dir / "config.yaml"), str(repo_dir))
        with pytest.raises(HostileRepoError):
            assert_safe_config_source(str(repo_dir / ".alastor.yaml"), str(repo_dir))

        external_cfg = tmp_path / "alastor-user-config.yaml"
        external_cfg.write_text("profile: deterministic\n", encoding="utf-8")
        resolved = assert_safe_config_source(str(external_cfg), str(repo_dir))
        assert os.path.realpath(str(external_cfg)) == resolved

        found = find_hostile_target_configs(str(repo_dir))
        assert ".env" in found
        assert "config.yaml" in found
        assert ".alastor.yaml" in found
        assert ".git/hooks/post-checkout" in found
        assert ".git/hooks/pre-commit.sample" not in found

        # Nested junction/symlink inside repo pointing outside MUST still be refused!
        outside_cfg_dir = tmp_path / "outside_cfg_dir"
        (outside_cfg_dir / "sub").mkdir(parents=True)
        outside_cfg = outside_cfg_dir / "sub" / "config.yaml"
        outside_cfg.write_text("safe: true\n", encoding="utf-8")
        assert assert_safe_config_source(str(outside_cfg), str(repo_dir)) == os.path.realpath(str(outside_cfg))

        repo_junc = repo_dir / "nested_junc"
        _create_dir_link(repo_junc, outside_cfg_dir)
        try:
            with pytest.raises(HostileRepoError):
                assert_safe_config_source(str(repo_junc / "sub" / "config.yaml"), str(repo_dir))
            with pytest.raises(HostileRepoError):
                assert_safe_config_source(str(repo_junc / ".." / "alastor-user-config.yaml"), str(repo_dir))
        finally:
            _remove_dir_link(repo_junc)

        # Symlinked/junction `.git` directory must NOT be traversed by find_hostile_target_configs
        symlinked_git_repo = tmp_path / "symlink_git_repo"
        symlinked_git_repo.mkdir()
        outside_git = tmp_path / "outside_git"
        (outside_git / "hooks").mkdir(parents=True)
        (outside_git / "hooks" / "pre-commit").write_text("#!/bin/sh\necho evil\n", encoding="utf-8")
        _create_dir_link(symlinked_git_repo / ".git", outside_git)
        try:
            assert find_hostile_target_configs(str(symlinked_git_repo)) == []
        finally:
            _remove_dir_link(symlinked_git_repo / ".git")

    @pytest.mark.parametrize(
        "valid_url",
        [
            "https://github.com/org/repo.git",
            "  https://github.com/org/repo.git  ",
            "http://localhost:8080/org/repo.git",
            "ssh://git@github.com/org/repo.git",
            "git@github.com:org/repo.git",
            "git@gitlab.internal.corp:team/sub/service",
        ],
    )
    def test_validate_clone_url_accepts_safe_urls(self, valid_url: str):
        cleaned = validate_clone_url(valid_url)
        assert cleaned == valid_url.strip()

    @pytest.mark.parametrize(
        "unsafe_url",
        [
            "",
            "   ",
            "file:///etc/passwd",
            "FILE:///C:/Windows/System32",
            "ext::sh -c id",
            "fd::17/repo",
            "git::https://github.com/org/repo.git",
            "ftp://example.com/repo.git",
            "--upload-pack=evil",
            "-oProxyCommand=evil",
            "https://user:pass@host/repo",
            "https://token@github.com/org/repo.git",
            "ssh://user:secret@github.com/org/repo.git",
            "https://evil.com/a\nb",
            "https://evil.com/a\rb",
            "https://evil.com/a\n",
            "https://evil.com/a\x00b",
            "https://evil.com/a b",
            "https://github.com/org/../evil",
            "git@github.com:../evil/repo",
            "git@-github.com:org/repo",
            "/local/path/repo",
            "C:\\local\\repo",
        ],
    )
    def test_validate_clone_url_rejects_unsafe_urls(self, unsafe_url: str):
        with pytest.raises(HostileRepoError):
            validate_clone_url(unsafe_url)

    def test_safe_cleanup_workspace_blocks_symlink_and_junction_escapes(self, tmp_path: Path):
        allowed_parent = tmp_path / "workspaces"
        allowed_parent.mkdir()
        outside = tmp_path / "outside_sensitive"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("DO_NOT_DELETE", encoding="utf-8")

        ws = allowed_parent / "repo_ws_1"
        ws.mkdir()
        (ws / "source.py").write_text("x = 123\n", encoding="utf-8")

        # Simulate Windows read-only .git pack file
        pack_dir = ws / ".git" / "objects" / "pack"
        pack_dir.mkdir(parents=True)
        pack_file = pack_dir / "pack-test.idx"
        pack_file.write_bytes(b"PACKDATA" * 8)
        os.chmod(pack_file, stat.S_IREAD)

        # Create escape link inside workspace pointing to outside dir
        if os.name == "nt":
            junction_path = ws / "escape_junction"
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction_path), str(outside)],
                check=True,
                capture_output=True,
                text=True,
            )
            assert os.path.isjunction(junction_path)
            try:
                os.symlink(str(outside), str(ws / "escape_symlink"), target_is_directory=True)
            except OSError:
                pass
        else:
            os.symlink(str(outside), str(ws / "escape_symlink"), target_is_directory=True)

        reclaimed = safe_cleanup_workspace(str(ws), str(allowed_parent))
        assert reclaimed >= len(b"PACKDATA" * 8)
        assert not ws.exists()
        assert sentinel.exists()
        assert sentinel.read_text(encoding="utf-8") == "DO_NOT_DELETE"

        # Cleanup handles read-only real subdirectories and NEVER calls os.chmod on links/junctions
        ws_ro = allowed_parent / "repo_ws_ro"
        ro_subdir = ws_ro / "locked_dir"
        ro_subdir.mkdir(parents=True)
        ro_inner_file = ro_subdir / "inner.bin"
        ro_inner_file.write_bytes(b"Z" * 16)
        escape_link = ws_ro / "link_out"
        _create_dir_link(escape_link, outside)
        os.chmod(ro_subdir, stat.S_IREAD | stat.S_IEXEC if os.name != "nt" else stat.S_IREAD)
        chmod_paths: list[str] = []
        real_chmod = os.chmod

        def _spy_chmod(p, mode, *args, **kwargs):
            chmod_paths.append(os.path.normcase(os.path.abspath(str(p))))
            return real_chmod(p, mode, *args, **kwargs)

        with mock.patch("engine.hostile_repo_guard.os.chmod", side_effect=_spy_chmod):
            reclaimed_ro = safe_cleanup_workspace(str(ws_ro), str(allowed_parent))
        assert reclaimed_ro >= 16
        assert not ws_ro.exists()
        assert sentinel.exists()
        assert os.path.normcase(os.path.abspath(str(escape_link))) not in chmod_paths

        # Refuses cleaning allowed_parent itself or outside paths
        with pytest.raises(HostileRepoError):
            safe_cleanup_workspace(str(allowed_parent), str(allowed_parent))
        with pytest.raises(HostileRepoError):
            safe_cleanup_workspace(str(allowed_parent / ".." / "outside_sensitive"), str(allowed_parent))
        with pytest.raises(HostileRepoError):
            safe_cleanup_workspace(str(outside), str(allowed_parent))

        # Refuses intermediate AND top-level junction/symlink pointing outside allowed_parent
        (outside / "nested_target").mkdir(exist_ok=True)
        nested_sentinel = outside / "nested_target" / "keep.txt"
        nested_sentinel.write_text("KEEP", encoding="utf-8")
        top_junc = allowed_parent / "top_escape_junc"
        _create_dir_link(top_junc, outside)
        try:
            with pytest.raises(HostileRepoError):
                safe_cleanup_workspace(str(top_junc), str(allowed_parent))
            with pytest.raises(HostileRepoError):
                safe_cleanup_workspace(str(top_junc / "nested_target"), str(allowed_parent))
            assert sentinel.exists()
            assert nested_sentinel.exists()
        finally:
            _remove_dir_link(top_junc)

    def test_build_sandbox_docker_command(self, tmp_path: Path):
        repo_dir = tmp_path / "repo"
        out_dir = tmp_path / "out"
        repo_dir.mkdir()
        out_dir.mkdir()

        argv = build_sandbox_docker_command(str(repo_dir), str(out_dir))
        assert argv[0:3] == ["docker", "run", "--rm"]
        assert "--read-only" in argv
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges:true" in argv
        assert "--pids-limit=256" in argv
        assert "--memory=2g" in argv
        assert "--network=none" in argv
        assert any(a.endswith(":/workspace:ro") for a in argv)
        assert any(a.endswith(":/out:rw") for a in argv)
        assert "alastor-scanner:v5" in argv

        argv_egress = build_sandbox_docker_command(
            str(repo_dir),
            str(out_dir),
            allow_egress_hosts=["api.github.com", "generativelanguage.googleapis.com"],
            cli_args=["scan", "--repo", "/workspace"],
        )
        assert "--network=none" not in argv_egress
        assert "ALASTOR_ALLOWED_EGRESS=api.github.com,generativelanguage.googleapis.com" in argv_egress

        with pytest.raises(HostileRepoError):
            build_sandbox_docker_command(str(repo_dir) + "\nevil", str(out_dir))

        # Colon injection in Docker -v paths (outside Windows drive letter prefix)
        with pytest.raises(HostileRepoError):
            build_sandbox_docker_command(str(repo_dir / "bad:ro"), str(out_dir))
        with pytest.raises(HostileRepoError):
            build_sandbox_docker_command(str(repo_dir), str(out_dir / "bad:rw"))

        # Image validation
        for bad_img in ("", "-evil", "bad image", "alastor;id"):
            with pytest.raises(HostileRepoError):
                build_sandbox_docker_command(str(repo_dir), str(out_dir), image=bad_img)

        # Egress host & cloud metadata validation
        for bad_host in ("", "-evil", "api.github.com;id", "bad host", "169.254.169.254", "100.100.100.200", "metadata.google.internal", None):
            with pytest.raises(HostileRepoError):
                build_sandbox_docker_command(
                    str(repo_dir),
                    str(out_dir),
                    allow_egress_hosts=[bad_host],  # type: ignore[list-item]
                )

        # Non-str cli_args rejected
        with pytest.raises(HostileRepoError):
            build_sandbox_docker_command(
                str(repo_dir),
                str(out_dir),
                cli_args=["scan", None],  # type: ignore[list-item]
            )


class TestCheckpointStore:
    def test_sqlite_wal_lifecycle_tamper_rejection_resume_and_provenance(self, tmp_path: Path):
        vault_dir = tmp_path / ".alastor_vault"
        repo_dir = tmp_path / "project_alpha"
        repo_dir.mkdir()

        store = CheckpointStore(str(vault_dir))
        try:
            assert (vault_dir / "checkpoints.db").exists()
            # Verify WAL + foreign_keys pragmas
            mode = store._conn.execute("PRAGMA journal_mode;").fetchone()[0]
            fk = store._conn.execute("PRAGMA foreign_keys;").fetchone()[0]
            assert str(mode).lower() == "wal"
            assert fk == 1

            run = store.create_or_get_run(
                repo_path=str(repo_dir),
                commit_sha="deadbeef1234",
                app_group="payments",
                options={"profile": "deterministic"},
            )
            assert run.status == "RUNNING"
            assert run.app_group == "payments"
            assert run.host_provenance_valid is True

            s0 = store.save_stage(
                run.run_id,
                "S0_CPG",
                "COMPLETED",
                payload={"nodes": 42, "edges": 88},
                duration_ms=12.5,
                metadata={"engine": "EMBEDDED_SQLITE"},
            )
            assert isinstance(s0, StageCheckpointItem)
            assert len(s0.payload_sha256) == 64

            s1 = store.save_stage(
                run.run_id,
                "S1_RULES",
                "COMPLETED",
                payload={"findings": [{"id": "f-1", "severity": "HIGH"}]},
                duration_ms=8.1,
            )
            assert s1.status == "COMPLETED"

            got_s0 = store.get_stage(run.run_id, "S0_CPG")
            assert got_s0 is not None
            item_s0, payload_s0 = got_s0
            assert item_s0.metadata == {"engine": "EMBEDDED_SQLITE"}
            assert payload_s0 == {"nodes": 42, "edges": 88}

            # Tamper directly with S1_RULES payload_json in SQLite -> must reject!
            with sqlite3.connect(str(vault_dir / "checkpoints.db")) as raw_conn:
                raw_conn.execute(
                    "UPDATE stage_checkpoints SET payload_json = ? WHERE run_id = ? AND stage_name = ?",
                    ('{"findings": []}', run.run_id, "S1_RULES"),
                )
                raw_conn.commit()
            assert store.get_stage(run.run_id, "S1_RULES") is None

            # Resume finds prior run + untampered S0_CPG
            resumed = store.create_or_get_run(
                repo_path=str(repo_dir),
                commit_sha="deadbeef1234",
                resume=True,
            )
            assert resumed.run_id == run.run_id
            stage_names = [s.stage_name for s in resumed.stages]
            assert "S0_CPG" in stage_names
            assert "S1_RULES" not in stage_names

            # Provenance fails while status is RUNNING
            ok, reason = store.verify_host_provenance(run.run_id, str(repo_dir), "deadbeef1234")
            assert ok is False
            assert "RUNNING" in reason

            store.mark_run_status(run.run_id, "COMPLETED", summary={"total_findings": 1})
            ok, reason = store.verify_host_provenance(run.run_id, str(repo_dir), "deadbeef1234")
            assert ok is True, reason

            # Wrong commit SHA fails
            ok_sha, _ = store.verify_host_provenance(run.run_id, str(repo_dir), "cafebabe9999")
            assert ok_sha is False

            # Wrong repo fails
            other_repo = tmp_path / "other_repo"
            other_repo.mkdir()
            ok_repo, _ = store.verify_host_provenance(run.run_id, str(other_repo), "deadbeef1234")
            assert ok_repo is False

            # Unknown run fails
            ok_missing, _ = store.verify_host_provenance("run-missing", str(repo_dir), "deadbeef1234")
            assert ok_missing is False

            # Foreign host_fingerprint fails
            with sqlite3.connect(str(vault_dir / "checkpoints.db")) as raw_conn:
                raw_conn.execute(
                    "UPDATE scan_runs SET host_fingerprint = ? WHERE run_id = ?",
                    ("foreign-host-fp-0000", run.run_id),
                )
                raw_conn.commit()
            ok_foreign, _ = store.verify_host_provenance(run.run_id, str(repo_dir), "deadbeef1234")
            assert ok_foreign is False
            fetched = store.get_run(run.run_id)
            assert fetched is not None
            assert fetched.host_provenance_valid is False
        finally:
            store.close()

    def test_fleet_runs_persistence_and_gc_pruning(self, tmp_path: Path):
        vault_dir = tmp_path / ".alastor_vault"
        temp_parent = tmp_path / "fleet_tmp"
        temp_parent.mkdir()
        outside = tmp_path / "outside_keep"
        outside.mkdir()
        keep_file = outside / "important.txt"
        keep_file.write_text("KEEP", encoding="utf-8")

        store = CheckpointStore(str(vault_dir))
        try:
            fleet = FleetRunResponse(
                fleet_run_id="fleet-001",
                manifest_name="nightly-fleet",
                status="COMPLETED",
                total_repos=2,
                completed_repos=2,
                failed_repos=0,
                created_at="2026-11-23T00:00:00+00:00",
                repo_results=[
                    FleetRepoResult(
                        repo="/repos/a",
                        app_group="core",
                        run_id="run-a",
                        status="COMPLETED",
                        total_findings=3,
                        high_count=1,
                    )
                ],
                app_rollups=[
                    FleetAppGroupRollup(
                        app_group="core",
                        repo_count=1,
                        completed_repos=1,
                        failed_repos=0,
                        total_findings=3,
                        critical_count=0,
                        high_count=1,
                        corroborated_count=0,
                        ev_confirmed_count=0,
                        go_live_decision="CONDITIONAL_GO_LIVE",
                    )
                ],
            )
            store.save_fleet_run(fleet)
            listed = store.list_fleet_runs(limit=10)
            assert isinstance(listed, FleetRunListResponse)
            assert listed.total == 1
            assert listed.runs[0].fleet_run_id == "fleet-001"
            assert listed.runs[0].app_rollups[0].app_group == "core"

            repo_a = tmp_path / "repo_a"
            repo_b = tmp_path / "repo_b"
            repo_c = tmp_path / "repo_c"
            for r in (repo_a, repo_b, repo_c):
                r.mkdir()

            r1 = store.create_or_get_run(str(repo_a), "sha1")
            store.save_stage(r1.run_id, "S0_CPG", "COMPLETED", {"n": 1})
            r2 = store.create_or_get_run(str(repo_b), "sha2")
            store.save_stage(r2.run_id, "S0_CPG", "COMPLETED", {"n": 2})
            r3 = store.create_or_get_run(str(repo_c), "sha3")
            store.save_stage(r3.run_id, "S0_CPG", "COMPLETED", {"n": 3})

            # Create two orphaned temp workspace dirs + one junction to outside
            old_ws = temp_parent / "orphan_ws_1"
            old_ws.mkdir()
            (old_ws / "data.bin").write_bytes(b"A" * 256)
            if os.name == "nt":
                subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(temp_parent / "skip_junc"), str(outside)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            else:
                os.symlink(str(outside), str(temp_parent / "skip_sym"))

            dry = store.gc(
                older_than_days=0,
                keep_last=1,
                dry_run=True,
                temp_workspaces_parent=str(temp_parent),
            )
            assert isinstance(dry, GcReport)
            assert dry.dry_run is True
            assert dry.pruned_runs == 2
            assert dry.pruned_checkpoints == 2
            assert dry.pruned_temp_dirs == 1
            assert dry.reclaimed_bytes >= 256
            assert dry.kept_runs == 1
            assert len(store.list_runs()) == 3
            assert old_ws.exists()

            real = store.gc(
                older_than_days=0,
                keep_last=1,
                dry_run=False,
                temp_workspaces_parent=str(temp_parent),
            )
            assert real.dry_run is False
            assert real.pruned_runs == 2
            assert real.pruned_checkpoints == 2
            assert real.pruned_temp_dirs == 1
            assert real.kept_runs == 1
            remaining = store.list_runs()
            assert len(remaining) == 1
            assert remaining[0].run_id == r3.run_id
            assert not old_ws.exists()
            assert keep_file.exists()

            if os.name == "nt":
                os.rmdir(temp_parent / "skip_junc")
        finally:
            store.close()
