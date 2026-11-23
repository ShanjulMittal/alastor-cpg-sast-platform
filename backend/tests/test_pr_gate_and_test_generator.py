"""
Strict TDD Suite for ALASTOR v5.0 Pillar 5 Task 1:
- Section 18 Pillar 5 Pydantic Data Contracts (`models.py`)
- PR / Git-Diff Incremental Security Gate (`engine/pr_delta_gate.py`)
- Automated Security Regression Unit-Test Generator (`engine/security_test_generator.py`)
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from engine.hostile_repo_guard import HostileRepoError
from engine.pr_delta_gate import (
    evaluate_pr_delta_gate,
    parse_unified_diff_added_lines,
    validate_git_ref,
)
from engine.security_test_generator import (
    detect_test_framework,
    generate_security_regression_test,
)
from models import (
    BestFixLocation,
    ComplianceControlResult,
    ComplianceEvaluateRequest,
    ComplianceEvaluateResponse,
    ComplianceFrameworkReport,
    CrossServiceAttackPath,
    CustomRuleMatchItem,
    CustomRuleTestRequest,
    CustomRuleTestResponse,
    CustomSecurityRule,
    Finding,
    MicroserviceCallEdge,
    MicroserviceEndpointItem,
    MicroserviceGraphRequest,
    MicroserviceGraphResponse,
    MicroserviceRepoInput,
    PrDeltaAnnotation,
    PrDeltaGateRequest,
    PrDeltaGateResponse,
    SecurityTestGenerateRequest,
    SecurityTestGenerateResponse,
)

RAW_SECRET_GITHUB = "ghp_1234567890abcdef1234567890abcdef1234"
RAW_SECRET_CUSTOM = "SuperSecretLiteralToken_XYZ987654"


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


class TestPillar5Section18Models:
    def test_pr_delta_and_testgen_models_defaults(self):
        pr_req = PrDeltaGateRequest(project_path="/repo")
        assert pr_req.base_ref == "HEAD~1"
        assert pr_req.head_ref == "HEAD"
        assert pr_req.fail_on_new_severity == "HIGH"
        assert pr_req.block_on_new_secrets is True
        assert pr_req.block_on_new_ev_confirmed is True
        assert pr_req.include_cpg_neighbors is True

        ann = PrDeltaAnnotation(
            finding_id="f-1",
            classification="NEWLY_INTRODUCED",
            severity="CRITICAL",
            rule_id="RULE-6-SHELL-INJECTION",
            filepath="pr_feature.py",
            line=10,
            title="Unsafe Shell Execution",
            message="Added in PR",
        )
        assert ann.cwe_id == ""

        pr_resp = PrDeltaGateResponse(
            project_path="/repo",
            base_ref="HEAD~1",
            head_ref="HEAD",
            gate_decision="BLOCK_MERGE",
            gate_reason="New critical finding",
            annotations=[ann],
        )
        assert pr_resp.blocking_count == 0
        assert pr_resp.changed_files == []

        tg_req = SecurityTestGenerateRequest(project_path="/repo", finding_id="f-1")
        assert tg_req.framework == "auto"
        assert tg_req.write_to_workspace is False
        assert tg_req.overwrite is False

        tg_resp = SecurityTestGenerateResponse(
            project_path="/repo",
            finding_id="f-1",
            cwe_id="CWE-89",
            framework="pytest",
            suggested_relative_path="tests/security/test_alastor_cwe_89.py",
            test_name="test_security_regression_cwe_89",
            test_code="def test_security_regression_cwe_89(): assert True\n",
            syntax_valid=True,
            run_command_hint="pytest tests/security/test_alastor_cwe_89.py",
        )
        assert tg_resp.written_to_disk is False
        assert tg_resp.written_path is None

    def test_compliance_custom_rules_and_microservice_models(self):
        ctrl = ComplianceControlResult(
            control_id="PCI-6.2.4",
            title="Prevent Injection",
            description="Prevent SQL/Command injection",
            status="FAIL",
            matched_finding_ids=["f-1"],
            matched_cwes=["CWE-89"],
            evidence_summary="1 SQLi finding",
        )
        rep = ComplianceFrameworkReport(
            framework_id="PCI_DSS_4_0",
            framework_name="PCI DSS",
            version="4.0",
            score_percent=80.0,
            status="NON_COMPLIANT",
            passed_controls=4,
            warning_controls=0,
            failed_controls=1,
            total_controls=5,
            controls=[ctrl],
        )
        c_req = ComplianceEvaluateRequest(project_path="/repo")
        assert c_req.frameworks is None
        c_resp = ComplianceEvaluateResponse(
            project_path="/repo",
            evaluated_at="2026-11-23T00:00:00Z",
            total_findings_evaluated=1,
            overall_score_percent=80.0,
            frameworks=[rep],
        )
        assert len(c_resp.frameworks) == 1

        rule = CustomSecurityRule(
            rule_id="CUSTOM-001",
            name="Disallow eval",
            pattern=r"\beval\s*\(",
        )
        assert rule.cwe_id == "CWE-20"
        assert "python" in rule.languages

        t_req = CustomRuleTestRequest(rule=rule, sample_code="eval(x)")
        m_item = CustomRuleMatchItem(filepath="app.py", line=1, matched_excerpt="eval(x)")
        t_resp = CustomRuleTestResponse(
            rule_id=t_req.rule.rule_id,
            regex_safe=True,
            matches_count=1,
            matches=[m_item],
        )
        assert t_resp.suppressed_count == 0

        ms_in = MicroserviceRepoInput(service_name="api-gateway", repo_path="/repos/gw")
        ms_ep = MicroserviceEndpointItem(
            service_name="billing",
            protocol="HTTP",
            method="POST",
            normalized_path="/api/pay/:param",
            raw_path="/api/pay/{id}",
            filepath="routes.py",
            line=12,
        )
        ms_edge = MicroserviceCallEdge(
            edge_id="e-1",
            source_service="api-gateway",
            target_service="billing",
            protocol="HTTP",
            method="POST",
            normalized_path="/api/pay/:param",
            caller_filepath="client.py",
            caller_line=20,
            callee_filepath="routes.py",
            callee_line=12,
        )
        ms_path = CrossServiceAttackPath(
            path_id="p-1",
            title="Gateway to Billing SQLi",
            composite_severity="CRITICAL",
            hop_count=2,
            services=["api-gateway", "billing"],
            finding_ids=["f-1"],
            narrative="Untrusted input crosses services",
        )
        g_req = MicroserviceGraphRequest(services=[ms_in])
        assert g_req.scan_findings is True
        g_resp = MicroserviceGraphResponse(
            services_analyzed=2,
            total_inbound_endpoints=1,
            total_outbound_calls=1,
            stitched_edges_count=1,
            cross_service_attack_paths_count=1,
            endpoints=[ms_ep],
            edges=[ms_edge],
            attack_paths=[ms_path],
        )
        assert g_resp.warnings == []


class TestValidateGitRefAndDiffParser:
    @pytest.mark.parametrize(
        "bad_ref",
        [
            "",
            "   ",
            "--exec=evil",
            "-n",
            "--upload-pack=touch /tmp/pwn",
            "a..b",
            "main...feature",
            "HEAD@{0}",
            "main@{yesterday}",
            "main\n--help",
            "main\revil",
            "main\x00evil",
            "main\x7f",
            "main branch",
            "origin\tmain",
            ".hidden",
            "a//b",
            "refs/heads/main.lock",
            "refs/heads/",
            "refs\\heads\\main",
            "~/secret",
            "^HEAD",
        ],
    )
    def test_validate_git_ref_rejects_malicious_or_invalid_refs(self, bad_ref: str):
        with pytest.raises((HostileRepoError, ValueError)):
            validate_git_ref(bad_ref)

    @pytest.mark.parametrize(
        "good_ref",
        [
            "HEAD",
            "HEAD~1",
            "HEAD~12",
            "HEAD^",
            "main",
            "origin/main",
            "release/v5.0.1",
            "feature_branch-2026",
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "WORKTREE",
        ],
    )
    def test_validate_git_ref_allows_legitimate_refs(self, good_ref: str):
        assert validate_git_ref(good_ref) == good_ref

    def test_parse_unified_diff_added_lines_edge_cases(self):
        diff_text = "\n".join(
            [
                "diff --git a/pr_feature.py b/pr_feature.py",
                "new file mode 100644",
                "index 0000000..1111111",
                "--- /dev/null",
                "+++ b/pr_feature.py",
                "@@ -0,0 +1,3 @@",
                "+import subprocess",
                "+def run(x):",
                "+    return subprocess.run(x, shell=True)",
                "diff --git a/single_line.py b/single_line.py",
                "index 2222222..3333333 100644",
                "--- a/single_line.py",
                "+++ b/single_line.py",
                "@@ -5 +5 @@",
                "-old = 1",
                "+new = 2",
                "@@ -20,2 +20,0 @@",
                "-deleted_a = 1",
                "-deleted_b = 2",
                'diff --git "a/dir space/my \\"file\\".py" "b/dir space/my \\"file\\".py"',
                '--- "a/dir space/my \\"file\\".py"',
                '+++ "b/dir space/my \\"file\\".py"',
                "@@ -1 +1,2 @@",
                "-x = 1",
                "+--- not a header",
                "++++ also not a header",
                "diff --git a/removed.py b/removed.py",
                "deleted file mode 100644",
                "--- a/removed.py",
                "+++ /dev/null",
                "@@ -1,2 +0,0 @@",
                "-a = 1",
                "-b = 2",
            ]
        )
        changed, added_by_file, newly_added = parse_unified_diff_added_lines(diff_text)
        assert "pr_feature.py" in changed
        assert "single_line.py" in changed
        assert 'dir space/my "file".py' in changed
        assert "/dev/null" not in changed
        assert "removed.py" not in changed

        assert "pr_feature.py" in newly_added
        assert "single_line.py" not in newly_added
        assert added_by_file["pr_feature.py"] == {1, 2, 3}
        assert added_by_file["single_line.py"] == {5}
        assert added_by_file['dir space/my "file".py'] == {1, 2}


class TestPrDeltaGate:
    def test_multi_commit_repo_separates_newly_introduced_from_pre_existing(self, tmp_path: Path):
        repo = tmp_path / "app_repo"
        _init_git_repo(repo)

        # Commit 1 (base): pre-existing vulnerable legacy.py + safe service.py + pinned manifest
        (repo / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
        (repo / "legacy.py").write_text(
            "def run_legacy(user_input: str):\n"
            "    return eval(user_input)\n",
            encoding="utf-8",
        )
        (repo / "service.py").write_text(
            "def safe_add(a: int, b: int) -> int:\n"
            "    return a + b\n",
            encoding="utf-8",
        )
        _commit_all(repo, "commit 1: base with legacy vuln")

        # Commit 2 (head): introduces a brand-new shell injection in pr_feature.py
        (repo / "pr_feature.py").write_text(
            "import subprocess\n"
            "def deploy(target: str) -> bytes:\n"
            "    return subprocess.check_output('echo ' + target, shell=True)\n",
            encoding="utf-8",
        )
        _commit_all(repo, "commit 2: add pr_feature with shell=True")

        res_block = evaluate_pr_delta_gate(
            PrDeltaGateRequest(
                project_path=str(repo),
                base_ref="HEAD~1",
                head_ref="HEAD",
            )
        )
        assert res_block.gate_decision == "BLOCK_MERGE"
        assert res_block.blocking_count >= 1
        assert res_block.newly_introduced_count >= 1
        assert res_block.pre_existing_count >= 1
        assert "pr_feature.py" in res_block.changed_files

        pr_anns = [a for a in res_block.annotations if a.filepath == "pr_feature.py"]
        legacy_anns = [a for a in res_block.annotations if a.filepath == "legacy.py"]
        assert pr_anns and all(a.classification == "NEWLY_INTRODUCED" for a in pr_anns)
        assert legacy_anns and all(a.classification == "PRE_EXISTING" for a in legacy_anns)
        assert any(
            (f.best_fix_location and f.best_fix_location.filepath == "pr_feature.py")
            or any(n.get("filepath") == "pr_feature.py" for n in f.path_nodes)
            for f in res_block.newly_introduced_findings
        )
        assert "BLOCK_MERGE" in res_block.pr_markdown_summary
        assert "pr_feature.py" in res_block.pr_markdown_summary

        # Commit 3 (clean PR): adds clean benign helper docs_helper.py
        (repo / "docs_helper.py").write_text(
            "def format_doc_title(raw: str) -> str:\n"
            "    return raw.strip().title()\n",
            encoding="utf-8",
        )
        _commit_all(repo, "commit 3: add clean docs_helper")

        res_pass = evaluate_pr_delta_gate(
            PrDeltaGateRequest(
                project_path=str(repo),
                base_ref="HEAD~1",
                head_ref="HEAD",
            )
        )
        assert res_pass.newly_introduced_count == 0
        assert res_pass.blocking_count == 0
        assert res_pass.gate_decision == "PASS"
        assert res_pass.pre_existing_count >= 2
        assert "PASS" in res_pass.pr_markdown_summary

    def test_worktree_diff_detects_uncommitted_vulnerability(self, tmp_path: Path):
        repo = tmp_path / "worktree_repo"
        _init_git_repo(repo)
        (repo / "app.py").write_text(
            "def greet(name: str) -> str:\n"
            "    return f'hi {name}'\n",
            encoding="utf-8",
        )
        _commit_all(repo, "initial clean commit")

        # Uncommitted working tree change introducing SQLi / shell=True
        (repo / "app.py").write_text(
            "import subprocess\n"
            "def greet(name: str) -> bytes:\n"
            "    return subprocess.check_output('echo ' + name, shell=True)\n",
            encoding="utf-8",
        )
        res = evaluate_pr_delta_gate(
            PrDeltaGateRequest(
                project_path=str(repo),
                base_ref="HEAD",
                head_ref="WORKTREE",
            )
        )
        assert res.gate_decision == "BLOCK_MERGE"
        assert res.newly_introduced_count >= 1
        assert "app.py" in res.changed_files

    def test_cpg_1hop_neighbors_and_modified_context_classification(self, tmp_path: Path):
        repo = tmp_path / "cpg_neighbor_repo"
        _init_git_repo(repo)
        (repo / "sanitizer_util.py").write_text(
            "def normalize_tag(val: str) -> str:\n"
            "    return val.strip()\n",
            encoding="utf-8",
        )
        (repo / "consumer.py").write_text(
            "from sanitizer_util import normalize_tag\n"
            "\n"
            "def handle_request(raw: str):\n"
            "    tag = normalize_tag(raw)\n"
            "    return eval(tag)\n",
            encoding="utf-8",
        )
        _commit_all(repo, "base with cross-file call")

        # Modify only sanitizer_util.py cleanly; consumer.py is a 1-hop CPG caller
        (repo / "sanitizer_util.py").write_text(
            "def normalize_tag(val: str) -> str:\n"
            "    return val.strip().lower()\n",
            encoding="utf-8",
        )
        _commit_all(repo, "update normalize_tag")

        res_with_neighbors = evaluate_pr_delta_gate(
            PrDeltaGateRequest(
                project_path=str(repo),
                base_ref="HEAD~1",
                head_ref="HEAD",
                include_cpg_neighbors=True,
            )
        )
        assert "consumer.py" in res_with_neighbors.impacted_neighbor_files
        assert res_with_neighbors.modified_context_count >= 1
        assert res_with_neighbors.newly_introduced_count == 0
        assert res_with_neighbors.gate_decision == "PASS"
        consumer_anns = [a for a in res_with_neighbors.annotations if a.filepath == "consumer.py"]
        assert consumer_anns and all(a.classification == "MODIFIED_CONTEXT" for a in consumer_anns)

        res_no_neighbors = evaluate_pr_delta_gate(
            PrDeltaGateRequest(
                project_path=str(repo),
                base_ref="HEAD~1",
                head_ref="HEAD",
                include_cpg_neighbors=False,
            )
        )
        assert res_no_neighbors.impacted_neighbor_files == []
        consumer_anns_off = [a for a in res_no_neighbors.annotations if a.filepath == "consumer.py"]
        assert consumer_anns_off and all(a.classification == "PRE_EXISTING" for a in consumer_anns_off)

    def test_policy_flags_and_secret_scrubbing_and_hostile_git_guard(self, tmp_path: Path):
        repo = tmp_path / "policy_repo"
        _init_git_repo(repo)
        (repo / "base.py").write_text("x = 1\n", encoding="utf-8")
        _commit_all(repo, "base")

        (repo / "auth.py").write_text(
            "def check():\n"
            "    return True\n",
            encoding="utf-8",
        )
        _commit_all(repo, "add auth.py")

        # Low-severity secret finding + Low-severity EV-confirmed finding + Medium finding
        injected = [
            Finding(
                id="f-sec-low",
                rule_id="SECRET-GITHUB-PAT",
                severity="LOW",
                cwe_id="CWE-798",
                title=f"Exposed token {RAW_SECRET_GITHUB}",
                description=f"Hardcoded secret {RAW_SECRET_GITHUB}",
                is_secret_finding=True,
                secret_value_raw=RAW_SECRET_GITHUB,
                best_fix_location=BestFixLocation(
                    filepath="auth.py",
                    line=1,
                    code_snippet=f"TOKEN = '{RAW_SECRET_GITHUB}'",
                ),
            ),
            Finding(
                id="f-ev-low",
                rule_id="RULE-EV-CUSTOM",
                severity="LOW",
                cwe_id="CWE-639",
                title="Confirmed IDOR",
                ev_status="RUNTIME_EXPLOIT_CONFIRMED",
                best_fix_location=BestFixLocation(filepath="auth.py", line=2),
            ),
        ]

        # Both enabled -> BLOCK_MERGE with 2 blocking
        res_strict = evaluate_pr_delta_gate(
            PrDeltaGateRequest(
                project_path=str(repo),
                base_ref="HEAD~1",
                head_ref="HEAD",
                fail_on_new_severity="CRITICAL",
                block_on_new_secrets=True,
                block_on_new_ev_confirmed=True,
            ),
            findings=injected,
        )
        assert res_strict.gate_decision == "BLOCK_MERGE"
        assert res_strict.blocking_count == 2
        # Zero raw secret leakage across entire response
        serialized = res_strict.model_dump_json()
        assert RAW_SECRET_GITHUB not in serialized
        assert RAW_SECRET_GITHUB not in res_strict.pr_markdown_summary

        # Disable both flags while threshold is CRITICAL -> PASS
        res_relaxed = evaluate_pr_delta_gate(
            PrDeltaGateRequest(
                project_path=str(repo),
                base_ref="HEAD~1",
                head_ref="HEAD",
                fail_on_new_severity="CRITICAL",
                block_on_new_secrets=False,
                block_on_new_ev_confirmed=False,
            ),
            findings=injected,
        )
        assert res_relaxed.gate_decision == "PASS"
        assert res_relaxed.blocking_count == 0

        # Hostile .git/config url.insteadOf must fail closed via run_hardened_git
        _git(repo, "config", "--local", "url.https://evil.example/.insteadOf", "https://github.com/")
        with pytest.raises((HostileRepoError, ValueError)):
            evaluate_pr_delta_gate(
                PrDeltaGateRequest(
                    project_path=str(repo),
                    base_ref="HEAD~1",
                    head_ref="HEAD",
                ),
                findings=injected,
            )


class TestSecurityTestGenerator:
    def test_detect_test_framework_across_languages(self, tmp_path: Path):
        py_finding = Finding(
            id="f-py",
            rule_id="RULE-7-SQLI-FORMAT",
            severity="HIGH",
            cwe_id="CWE-89",
            title="SQLi",
            best_fix_location=BestFixLocation(filepath="app/db.py", line=12),
        )
        assert detect_test_framework(py_finding, str(tmp_path)) == "pytest"

        go_finding = Finding(
            id="f-go",
            rule_id="POLY-GO-CMDI",
            severity="HIGH",
            cwe_id="CWE-78",
            title="Go Command Injection",
            best_fix_location=BestFixLocation(filepath="pkg/exec.go", line=22),
        )
        assert detect_test_framework(go_finding, str(tmp_path)) == "go_test"

        ts_finding = Finding(
            id="f-ts",
            rule_id="RULE-9-DOM-XSS",
            severity="HIGH",
            cwe_id="CWE-79",
            title="DOM XSS",
            best_fix_location=BestFixLocation(filepath="src/view.ts", line=5),
        )
        assert detect_test_framework(ts_finding, str(tmp_path)) == "jest"

        vitest_repo = tmp_path / "vitest_app"
        vitest_repo.mkdir()
        (vitest_repo / "package.json").write_text(
            json.dumps({"name": "web", "devDependencies": {"vitest": "^2.0.0"}}),
            encoding="utf-8",
        )
        assert detect_test_framework(ts_finding, str(vitest_repo)) == "vitest"

    @pytest.mark.parametrize(
        "cwe_id,rule_id,title",
        [
            ("CWE-89", "RULE-7-SQLI-FORMAT", "Unparameterized SQL String Interpolation"),
            ("CWE-78", "RULE-6-SHELL-INJECTION", "Unsafe Shell Execution"),
            ("CWE-79", "RULE-9-DOM-XSS", "Unsanitized DOM HTML Sink"),
            ("CWE-22", "RULE-10-PATH-TRAVERSAL", "Path Traversal in File Read"),
            ("CWE-918", "RULE-11-SSRF-URLOPEN", "SSRF to Internal Metadata"),
            ("CWE-639", "IDOR-BOLA-CHECK", "Missing Object Ownership Check (IDOR)"),
            ("CWE-502", "RULE-13-DESER", "Insecure Pickle Deserialization"),
            ("CWE-798", "SECRET-HARDCODED", "Hardcoded Credential in Source"),
            ("CWE-942", "CORS-WILDCARD", "Permissive CORS Reflection"),
            ("CWE-400", "GENERIC-SEC", "Generic Validation Gap"),
        ],
    )
    def test_pytest_generation_parses_with_ast_and_runs_under_pytest(
        self,
        tmp_path: Path,
        cwe_id: str,
        rule_id: str,
        title: str,
    ):
        repo = tmp_path / f"repo_{cwe_id.lower()}"
        repo.mkdir()
        finding = Finding(
            id=f"find-{cwe_id.lower()}",
            rule_id=rule_id,
            severity="HIGH",
            cwe_id=cwe_id,
            title=title,
            description=f"Sample finding for {cwe_id}",
            best_fix_location=BestFixLocation(
                filepath="app/handler.py",
                line=18,
                code_snippet="dangerous_call(user_input)",
            ),
        )
        resp = generate_security_regression_test(
            SecurityTestGenerateRequest(
                project_path=str(repo),
                finding_id=finding.id,
                framework="auto",
                write_to_workspace=True,
            ),
            finding,
        )
        assert resp.framework == "pytest"
        assert resp.cwe_id == cwe_id
        assert resp.syntax_valid is True
        ast.parse(resp.test_code)
        assert cwe_id in resp.test_code
        assert resp.written_to_disk is True
        assert resp.written_path is not None
        assert Path(resp.written_path).is_file()
        assert resp.suggested_relative_path.startswith("tests/security/test_alastor_")
        assert resp.suggested_relative_path.endswith(".py")

        # Execute representative generated pytest modules under real pytest
        if cwe_id in ("CWE-89", "CWE-78", "CWE-22", "CWE-798"):
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", resp.written_path],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert proc.returncode == 0, f"{cwe_id} generated test failed:\n{proc.stdout}\n{proc.stderr}"

    @pytest.mark.parametrize(
        "framework,filepath,cwe_id,expected_substr",
        [
            ("jest", "src/users.ts", "CWE-89", "describe("),
            ("jest", "src/exec.js", "CWE-78", "expect("),
            ("vitest", "src/dom.ts", "CWE-79", "from 'vitest'"),
            ("vitest", "src/files.ts", "CWE-22", "from 'vitest'"),
            ("go_test", "internal/auth.go", "CWE-798", "package security_test"),
            ("go_test", "internal/orders.go", "CWE-639", "func TestSecurityRegression"),
        ],
    )
    def test_jest_vitest_and_go_test_generation(
        self,
        tmp_path: Path,
        framework: str,
        filepath: str,
        cwe_id: str,
        expected_substr: str,
    ):
        repo = tmp_path / f"repo_{framework}_{cwe_id.lower()}"
        repo.mkdir()
        if framework == "vitest":
            (repo / "package.json").write_text(
                json.dumps({"devDependencies": {"vitest": "^2.0.0"}}),
                encoding="utf-8",
            )
        finding = Finding(
            id=f"f-{framework}-{cwe_id}",
            rule_id=f"RULE-{cwe_id}",
            severity="HIGH",
            cwe_id=cwe_id,
            title=f"Issue {cwe_id}",
            best_fix_location=BestFixLocation(filepath=filepath, line=14),
        )
        req_fw = "auto" if framework in ("jest", "vitest", "go_test") else framework
        resp = generate_security_regression_test(
            SecurityTestGenerateRequest(
                project_path=str(repo),
                finding_id=finding.id,
                framework=req_fw,  # type: ignore[arg-type]
                write_to_workspace=False,
            ),
            finding,
        )
        assert resp.framework == framework
        assert resp.syntax_valid is True
        assert expected_substr in resp.test_code
        assert cwe_id in resp.test_code
        assert resp.written_to_disk is False
        assert resp.written_path is None

    def test_zero_raw_secret_leakage_in_generated_tests(self, tmp_path: Path):
        repo = tmp_path / "secret_repo"
        repo.mkdir()
        finding = Finding(
            id="f-secret",
            rule_id="SECRET-GITHUB-PAT",
            severity="CRITICAL",
            cwe_id="CWE-798",
            title=f"Hardcoded GitHub PAT {RAW_SECRET_GITHUB}",
            description=f"Found {RAW_SECRET_GITHUB} and {RAW_SECRET_CUSTOM} in settings",
            remediation=f"Remove {RAW_SECRET_CUSTOM} immediately",
            is_secret_finding=True,
            secret_value_raw=RAW_SECRET_CUSTOM,
            best_fix_location=BestFixLocation(
                filepath="config.py",
                line=4,
                code_snippet=f"GH = '{RAW_SECRET_GITHUB}'; OTHER = '{RAW_SECRET_CUSTOM}'",
                recommended_fix="Use os.environ['GITHUB_TOKEN']",
            ),
        )
        for fw in ("pytest", "jest", "vitest", "go_test"):
            resp = generate_security_regression_test(
                SecurityTestGenerateRequest(
                    project_path=str(repo),
                    finding_id=finding.id,
                    framework=fw,  # type: ignore[arg-type]
                ),
                finding,
            )
            serialized = resp.model_dump_json()
            assert RAW_SECRET_GITHUB not in serialized
            assert RAW_SECRET_CUSTOM not in serialized
            assert RAW_SECRET_GITHUB not in resp.test_code
            assert RAW_SECRET_CUSTOM not in resp.test_code

    def test_confined_write_overwrite_guard_and_symlink_escape_rejection(self, tmp_path: Path):
        repo = tmp_path / "confined_repo"
        repo.mkdir()
        outside = tmp_path / "outside_target"
        outside.mkdir()

        finding = Finding(
            id="f-conf",
            rule_id="RULE-89",
            severity="HIGH",
            cwe_id="CWE-89",
            title="SQL Injection",
            best_fix_location=BestFixLocation(filepath="app.py", line=7),
        )

        # First write succeeds
        r1 = generate_security_regression_test(
            SecurityTestGenerateRequest(
                project_path=str(repo),
                finding_id=finding.id,
                write_to_workspace=True,
                overwrite=False,
            ),
            finding,
        )
        assert r1.written_to_disk is True
        target_file = Path(r1.written_path or "")
        assert target_file.is_file()
        assert os.path.commonpath([os.path.realpath(repo), os.path.realpath(target_file)]) == os.path.realpath(repo)

        # Second write with overwrite=False raises FileExistsError
        with pytest.raises(FileExistsError):
            generate_security_regression_test(
                SecurityTestGenerateRequest(
                    project_path=str(repo),
                    finding_id=finding.id,
                    write_to_workspace=True,
                    overwrite=False,
                ),
                finding,
            )

        # overwrite=True succeeds cleanly
        r2 = generate_security_regression_test(
            SecurityTestGenerateRequest(
                project_path=str(repo),
                finding_id=finding.id,
                write_to_workspace=True,
                overwrite=True,
            ),
            finding,
        )
        assert r2.written_to_disk is True

        # Symlink / NTFS junction on tests/security must fail closed
        link_repo = tmp_path / "link_escape_repo"
        (link_repo / "tests").mkdir(parents=True)
        sec_link = link_repo / "tests" / "security"
        _create_dir_link(sec_link, outside)
        try:
            with pytest.raises((HostileRepoError, ValueError)):
                generate_security_regression_test(
                    SecurityTestGenerateRequest(
                        project_path=str(link_repo),
                        finding_id=finding.id,
                        write_to_workspace=True,
                        overwrite=True,
                    ),
                    finding,
                )
            assert list(outside.iterdir()) == []
        finally:
            _remove_dir_link(sec_link)

        # Symlink / NTFS junction on parent `tests/` directory must also fail closed
        link_parent_repo = tmp_path / "link_parent_escape_repo"
        link_parent_repo.mkdir()
        tests_link = link_parent_repo / "tests"
        _create_dir_link(tests_link, outside)
        try:
            with pytest.raises((HostileRepoError, ValueError)):
                generate_security_regression_test(
                    SecurityTestGenerateRequest(
                        project_path=str(link_parent_repo),
                        finding_id=finding.id,
                        write_to_workspace=True,
                        overwrite=True,
                    ),
                    finding,
                )
            assert list(outside.iterdir()) == []
        finally:
            _remove_dir_link(tests_link)

    def test_all_generated_pytest_cwe_templates_execute_cleanly(self, tmp_path: Path):
        repo = tmp_path / "all_cwe_pytest_repo"
        repo.mkdir()
        cwes = (
            "CWE-89",
            "CWE-78",
            "CWE-79",
            "CWE-22",
            "CWE-918",
            "CWE-639",
            "CWE-502",
            "CWE-798",
            "CWE-942",
            "CWE-400",
        )
        for cwe in cwes:
            finding = Finding(
                id=f"all-{cwe.lower()}",
                rule_id=f"RULE-{cwe}",
                severity="HIGH",
                cwe_id=cwe,
                title=f"Regression {cwe}",
                best_fix_location=BestFixLocation(filepath="app.py", line=10),
            )
            resp = generate_security_regression_test(
                SecurityTestGenerateRequest(
                    project_path=str(repo),
                    finding_id=finding.id,
                    framework="pytest",
                    write_to_workspace=True,
                ),
                finding,
            )
            assert resp.syntax_valid is True
            assert resp.written_to_disk is True

        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "tests/security"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, f"Generated pytest suite failed:\n{proc.stdout}\n{proc.stderr}"
        assert "10 passed" in proc.stdout
