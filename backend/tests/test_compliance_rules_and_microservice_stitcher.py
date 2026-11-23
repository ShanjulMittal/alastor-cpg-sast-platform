"""
Strict TDD Suite for ALASTOR v5.0 Pillar 5 Task 2:
- Continuous Compliance Autopilot (`evaluate_compliance`)
- ReDoS-Safe Custom Rule Studio (`validate_custom_rule_regex`, `CustomRuleEngine`)
- Cross-Repo Microservice Attack-Graph Stitcher (`normalize_route_template`,
  `extract_service_surface`, `stitch_microservice_attack_graph`)
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from engine.compliance_and_rules_engine import (
    COMPLIANCE_FRAMEWORK_CATALOGS,
    CustomRuleEngine,
    evaluate_compliance,
    validate_custom_rule_regex,
)
from engine.hostile_repo_guard import HostileRepoError
from engine.microservice_stitcher import (
    _extract_host_hint_from_url,
    _normalize_queue_topic,
    _service_host_aliases,
    extract_service_surface,
    normalize_route_template,
    stitch_microservice_attack_graph,
)
from models import (
    BestFixLocation,
    ComplianceFrameworkId,
    CustomRuleTestRequest,
    CustomSecurityRule,
    Finding,
    MicroserviceGraphRequest,
    MicroserviceRepoInput,
)

RAW_SECRET_GH = "ghp_1234567890abcdef1234567890abcdef1234"
RAW_SECRET_STRIPE = "sk_live_" + "9876543210abcdef9876543210"
RAW_SECRET_DB = "postgres://admin:SuperSecretDbPass99@db.internal:5432/billing"
RAW_SECRET_CUSTOM = "LiteralSecretValue_XYZ_987654"


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


def _make_finding(
    fid: str,
    *,
    rule_id: str = "RULE-7-SQLI-FORMAT",
    severity: str = "HIGH",
    cwe_id: str | None = "CWE-89",
    title: str = "Security Finding",
    filepath: str = "app.py",
    line: int = 10,
    scan_engine: str = "SAST",
    ev_status: str | None = None,
    triage_status: str = "TO_VERIFY",
    secret_value_raw: str | None = None,
) -> Finding:
    return Finding(
        id=fid,
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        description=f"{title} in {filepath}:{line}",
        cwe_id=cwe_id,
        scan_engine=scan_engine,  # type: ignore[arg-type]
        ev_status=ev_status,  # type: ignore[arg-type]
        triage_status=triage_status,  # type: ignore[arg-type]
        secret_value_raw=secret_value_raw,
        best_fix_location=BestFixLocation(
            node_id=f"node-{fid}",
            filepath=filepath,
            line=line,
            code_snippet="# snippet",
        ),
        path_nodes=[{"filepath": filepath, "start_line": line, "code": title}],
    )


# ---------------------------------------------------------------------------
# 1. Continuous Compliance Autopilot
# ---------------------------------------------------------------------------
class TestComplianceAutopilot:
    def test_clean_workspace_all_five_frameworks_compliant_100_percent(self, tmp_path: Path):
        resp = evaluate_compliance(str(tmp_path), findings=[])

        assert resp.project_path == str(tmp_path)
        assert resp.total_findings_evaluated == 0
        assert resp.overall_score_percent == 100.0
        assert len(resp.frameworks) == 5

        expected_ids: set[ComplianceFrameworkId] = {
            "PCI_DSS_4_0",
            "SOC2",
            "ISO_27001",
            "HIPAA",
            "OWASP_ASVS_5_0",
        }
        assert {fw.framework_id for fw in resp.frameworks} == expected_ids

        for fw in resp.frameworks:
            assert 5 <= fw.total_controls <= 7
            assert fw.score_percent == 100.0
            assert fw.status == "COMPLIANT"
            assert fw.passed_controls == fw.total_controls
            assert fw.warning_controls == 0
            assert fw.failed_controls == 0
            assert all(ctrl.status == "PASS" for ctrl in fw.controls)
            assert all(ctrl.matched_finding_ids == [] for ctrl in fw.controls)

    def test_exact_cwe_matching_ev_confirmed_and_no_cwe79_on_cwe798_collision(self, tmp_path: Path):
        findings = [
            _make_finding(
                "f-sqli",
                rule_id="RULE-7-SQLI-FORMAT",
                severity="HIGH",
                cwe_id="CWE-89",
                title="SQL Injection in billing query",
            ),
            _make_finding(
                "f-secret",
                rule_id="RULE-8-HARDCODED-SECRET",
                severity="CRITICAL",
                cwe_id="CWE-798",
                title=f"Hardcoded GitHub PAT {RAW_SECRET_GH}",
                secret_value_raw=RAW_SECRET_CUSTOM,
            ),
            _make_finding(
                "f-ev",
                rule_id="COG-2-BUSINESS-LOGIC-TOCTOU",
                severity="MEDIUM",
                cwe_id="CWE-840",
                title=f"Confirmed race bypass with {RAW_SECRET_CUSTOM}",
                ev_status="RUNTIME_EXPLOIT_CONFIRMED",
                secret_value_raw=RAW_SECRET_CUSTOM,
            ),
        ]

        resp = evaluate_compliance(str(tmp_path), findings=findings)
        assert resp.total_findings_evaluated == 3
        assert resp.overall_score_percent < 100.0

        for fw in resp.frameworks:
            assert fw.status == "NON_COMPLIANT"
            assert fw.failed_controls >= 2
            # Verify math formula matches exactly
            expected_score = round(
                ((fw.passed_controls + 0.5 * fw.warning_controls) / fw.total_controls) * 100.0,
                1,
            )
            assert fw.score_percent == expected_score

            # No CWE-79 control may falsely trigger on CWE-798!
            for ctrl in fw.controls:
                assert "CWE-79" not in ctrl.matched_cwes
                assert RAW_SECRET_GH not in ctrl.evidence_summary
                assert RAW_SECRET_CUSTOM not in ctrl.evidence_summary

        # Check specific controls with CWE-79 stay PASS in all 5 catalogs
        by_fw = {fw.framework_id: fw for fw in resp.frameworks}
        for fw_id, fw_rep in by_fw.items():
            catalog = COMPLIANCE_FRAMEWORK_CATALOGS[fw_id]
            cwe79_control_ids = {
                c.control_id for c in catalog.controls if "CWE-79" in c.mapped_cwes
            }
            assert cwe79_control_ids, f"{fw_id} must define a CWE-79 control"
            for ctrl in fw_rep.controls:
                if ctrl.control_id in cwe79_control_ids:
                    assert ctrl.status == "PASS", (
                        f"{fw_id}:{ctrl.control_id} falsely triggered on CWE-798/unrelated findings"
                    )

        # EV-confirmed MEDIUM finding must cause at least one control requiring no EV-confirmed to FAIL
        ev_matched_controls = [
            ctrl
            for fw in resp.frameworks
            for ctrl in fw.controls
            if "f-ev" in ctrl.matched_finding_ids
        ]
        assert ev_matched_controls
        assert all(ctrl.status == "FAIL" for ctrl in ev_matched_controls)

    def test_medium_only_finding_produces_warning_and_at_risk_score_and_sca_matching(self, tmp_path: Path):
        medium_xss = _make_finding(
            "f-med-xss",
            rule_id="RULE-9-DOM-XSS",
            severity="MEDIUM",
            cwe_id="CWE-79",
            title="Reflected DOM XSS",
        )
        resolved_sqli = _make_finding(
            "f-resolved",
            rule_id="RULE-7-SQLI-FORMAT",
            severity="CRITICAL",
            cwe_id="CWE-89",
            triage_status="RESOLVED",
        )
        not_expl = _make_finding(
            "f-fp",
            rule_id="RULE-8-HARDCODED-SECRET",
            severity="CRITICAL",
            cwe_id="CWE-798",
            triage_status="NOT_EXPLOITABLE",
        )

        resp = evaluate_compliance(
            str(tmp_path),
            findings=[medium_xss, resolved_sqli, not_expl],
            frameworks=["OWASP_ASVS_5_0"],
        )
        assert len(resp.frameworks) == 1
        asvs = resp.frameworks[0]
        assert asvs.framework_id == "OWASP_ASVS_5_0"
        assert asvs.status == "AT_RISK"
        assert asvs.failed_controls == 0
        assert asvs.warning_controls == 1
        expected = round(((asvs.passed_controls + 0.5) / asvs.total_controls) * 100.0, 1)
        assert asvs.score_percent == expected
        assert resp.overall_score_percent == expected

        # SCA finding triggers clean-SCA control across frameworks
        sca_finding = _make_finding(
            "f-sca-1",
            rule_id="SCA-1-MANIFEST-AUDIT",
            severity="HIGH",
            cwe_id="CWE-1395",
            scan_engine="SCA",
            filepath="requirements.txt",
        )
        pci_resp = evaluate_compliance(str(tmp_path), findings=[sca_finding], frameworks=["PCI_DSS_4_0"])
        pci = pci_resp.frameworks[0]
        assert pci.status == "NON_COMPLIANT"
        assert any("f-sca-1" in c.matched_finding_ids and c.status == "FAIL" for c in pci.controls)

    def test_unknown_framework_raises_value_error(self, tmp_path: Path):
        with pytest.raises(ValueError):
            evaluate_compliance(str(tmp_path), findings=[], frameworks=["UNKNOWN_STD"])  # type: ignore[list-item]

    def test_cwe_canonicalization_leading_zeros_and_underscore_boundary(self, tmp_path: Path):
        findings = [
            _make_finding(
                "f-cwe079",
                rule_id="CUSTOM-XSS-ZERO",
                severity="HIGH",
                cwe_id="CWE-079",
                title="Leading zero XSS",
            ),
            _make_finding(
                "f-cwe79-under",
                rule_id="CUSTOM-XSS-UNDER",
                severity="MEDIUM",
                cwe_id="CWE-79_XSS",
                title="Underscore boundary XSS",
            ),
        ]
        resp = evaluate_compliance(str(tmp_path), findings=findings, frameworks=["OWASP_ASVS_5_0"])
        asvs = resp.frameworks[0]
        v52 = next(c for c in asvs.controls if c.control_id == "V5.2")
        assert v52.status == "FAIL"
        assert set(v52.matched_finding_ids) == {"f-cwe079", "f-cwe79-under"}
        assert v52.matched_cwes == ["CWE-79"]

        # Confirm CWE-798 alone does NOT trigger CWE-79
        resp_798 = evaluate_compliance(
            str(tmp_path),
            findings=[
                _make_finding(
                    "f-798",
                    rule_id="RULE-8-HARDCODED-SECRET",
                    severity="CRITICAL",
                    cwe_id="CWE-798",
                )
            ],
            frameworks=["OWASP_ASVS_5_0"],
        )
        v52_after = next(c for c in resp_798.frameworks[0].controls if c.control_id == "V5.2")
        assert v52_after.status == "PASS"
        assert v52_after.matched_finding_ids == []


# ---------------------------------------------------------------------------
# 2. Custom Rule Studio + ReDoS Validator + Atomic Vault
# ---------------------------------------------------------------------------
class TestCustomRuleStudio:
    @pytest.mark.parametrize(
        "bad_pattern",
        [
            "",
            "   ",
            "(a+)+",
            "(a*)*",
            "([a-z]+)*",
            "(?:a+)*",
            "(a|aa)+",
            "((a|aa))+",
            "(a|ab)*",
            "(.*a){5}",
            "(a+)(?#c)+x",
            "([a-z]+)(?#c)+x",
            "(?=a)(?#c)+",
            "(?i)(a|Aa)+x",
            "((?i:a)|A)+x",
            "(?:(?i:a)|A)+x",
            "((?i:ab)|A)+x",
            "(?i)((?-i:A)|a)+x",
            "(?x)(a | a)+x",
            r"(\x41|AA)+x",
            r"(\061|11)+x",
            r"(\u0041|AA)+x",
            r"(\N{LATIN SMALL LETTER A}|aa)+x",
            ".*.*.*.*x",
            "a*a*a*a*a*b",
            ".*(.*)",
            "(?:.*|x)(?:.*|y)(?:.*|z).*",
            "(?:a*|b)(?:a*|b)(?:a*|b)(?:a*|b)c",
            ".*(?:.*|x)y",
            "(?:(a*|x)|y)(?:(a*|z)|w)q",
            "(?:(?i:a*|x)|y)(?:(?i:a*|z)|w)q",
            "[a-z]+(?:a|0+)[a-z]+(?:a|0+)[a-z]+b",
            r"\w+(?:\w|\s+)\w+(?:\w|\s+)\w+!",
            r"\s*a?\s*a?\s*!",
            "a{0,50}" * 6 + "b",
            "a{0,50}b{0,50}a{0,50}",
            r"(foo)\1",
            r"(?P<id>a)(?P=id)",
            r"(?=.*secret)token",
            r"(?=a)+",
            "a" * 401,
            "foo\x01bar",
            "[unclosed",
        ],
    )
    def test_redos_validator_rejects_unsafe_and_malformed_patterns(self, bad_pattern: str):
        with pytest.raises(ValueError):
            validate_custom_rule_regex(bad_pattern)

    @pytest.mark.parametrize(
        "good_pattern",
        [
            r"pickle\.loads\s*\(",
            r"eval\s*\([^)]+\)",
            r"(?i)secret_key\s*=",
            r"\w+\s*\(\s*\w+\s*\)",
            r"requests\.(?:get|post)\s*\(\s*[^)]*\s*\)",
            r"(?:eval|exec)\s*\(",
            r"cursor\.execute\s*\(\s*f[\"']",
            r"yaml\.load\s*\([^)]*\)",
            r"SafeLoader",
        ],
    )
    def test_redos_validator_accepts_safe_patterns(self, good_pattern: str):
        compiled = validate_custom_rule_regex(good_pattern)
        assert compiled.pattern == good_pattern

    def test_crud_atomic_vault_persistence_and_permissions(self, tmp_path: Path):
        vault_dir = tmp_path / ".alastor_vault"
        engine = CustomRuleEngine(str(vault_dir))

        assert engine.list_rules() == []

        rule = CustomSecurityRule(
            rule_id="CUSTOM-PICKLE-01",
            name="Unsafe Pickle Deserialization",
            severity="CRITICAL",
            cwe_id="CWE-502",
            languages=["python"],
            pattern=r"pickle\.loads\s*\(",
            anti_pattern=r"hmac\.compare_digest",
            description="Detects untrusted pickle.loads",
            remediation="Use json.loads instead of pickle.loads.",
            compliance_controls=["PCI-2.2.1", "A.8.26"],
        )
        created = engine.create_rule(rule)
        assert created.rule_id == "CUSTOM-PICKLE-01"
        assert created.created_at is not None
        assert created.updated_at is not None

        vault_file = vault_dir / "custom_rules.json"
        assert vault_file.is_file()
        if os.name == "posix":
            assert stat.S_IMODE(os.stat(vault_file).st_mode) == 0o600
            assert stat.S_IMODE(os.stat(vault_dir).st_mode) == 0o700

        # Duplicate ID rejected
        with pytest.raises(ValueError):
            engine.create_rule(rule)

        # Invalid rule_id rejected
        with pytest.raises(ValueError):
            engine.create_rule(rule.model_copy(update={"rule_id": "../escape"}))

        # Re-read from fresh engine instance confirms persistence
        reloaded = CustomRuleEngine(str(vault_dir))
        listed = reloaded.list_rules()
        assert len(listed) == 1
        assert listed[0].rule_id == "CUSTOM-PICKLE-01"
        assert reloaded.get_rule("CUSTOM-PICKLE-01") is not None

        # Update preserves created_at and validates regex
        with pytest.raises(ValueError):
            reloaded.update_rule("CUSTOM-PICKLE-01", rule.model_copy(update={"pattern": "(a+)+"}))
        with pytest.raises(KeyError):
            reloaded.update_rule("MISSING-RULE", rule.model_copy(update={"rule_id": "MISSING-RULE"}))

        updated = reloaded.update_rule(
            "CUSTOM-PICKLE-01",
            rule.model_copy(update={"severity": "HIGH", "description": "Updated desc"}),
        )
        assert updated.created_at == created.created_at
        assert updated.severity == "HIGH"
        assert updated.description == "Updated desc"

        # Delete
        assert reloaded.delete_rule("CUSTOM-PICKLE-01") is True
        assert reloaded.delete_rule("CUSTOM-PICKLE-01") is False
        assert reloaded.list_rules() == []

    def test_atomic_vault_save_cleans_up_temp_file_on_replace_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        vault_dir = tmp_path / ".alastor_vault"
        engine = CustomRuleEngine(str(vault_dir))
        first = engine.create_rule(
            CustomSecurityRule(
                rule_id="CUSTOM-BASE-01",
                name="Base Rule",
                pattern=r"pickle\.loads\s*\(",
            )
        )
        assert first.rule_id == "CUSTOM-BASE-01"

        def _failing_replace(_src: str, _dst: str) -> None:
            raise OSError("Simulated disk replace failure")

        monkeypatch.setattr(os, "replace", _failing_replace)
        with pytest.raises(OSError):
            engine.create_rule(
                CustomSecurityRule(
                    rule_id="CUSTOM-FAIL-02",
                    name="Failing Rule",
                    pattern=r"yaml\.load\s*\(",
                )
            )

        leftover_tmps = [p.name for p in vault_dir.iterdir() if ".tmp." in p.name]
        assert leftover_tmps == []
        assert [r.rule_id for r in engine.list_rules()] == ["CUSTOM-BASE-01"]

    def test_sample_code_test_rule_anti_pattern_suppression_and_secret_scrubbing(self, tmp_path: Path):
        engine = CustomRuleEngine(str(tmp_path / ".alastor_vault"))
        rule = CustomSecurityRule(
            rule_id="CUSTOM-YAML-01",
            name="Unsafe yaml.load",
            severity="HIGH",
            cwe_id="CWE-502",
            languages=["python"],
            pattern=r"yaml\.load\s*\(",
            anti_pattern=r"SafeLoader",
        )
        sample = (
            f'token = "{RAW_SECRET_GH}"\n'
            f'data = yaml.load(payload)  # leak {RAW_SECRET_STRIPE}\n'
            "# unrelated comment line\n"
            "# another neutral spacer\n"
            "# SafeLoader verified on next line\n"
            "safe_data = yaml.load(cfg, Loader=SafeLoader)\n"
            f'db = "{RAW_SECRET_DB}"\n'
        )
        resp = engine.test_rule(
            CustomRuleTestRequest(rule=rule, sample_code=sample, sample_language="python")
        )
        assert resp.regex_safe is True
        assert resp.matches_count == 1
        assert resp.suppressed_count == 1
        assert len(resp.matches) == 2

        unsuppressed = [m for m in resp.matches if not m.suppressed_by_anti_pattern]
        suppressed = [m for m in resp.matches if m.suppressed_by_anti_pattern]
        assert len(unsuppressed) == 1
        assert unsuppressed[0].line == 2
        assert RAW_SECRET_STRIPE not in unsuppressed[0].matched_excerpt
        assert "[REDACTED_SECRET]" in unsuppressed[0].matched_excerpt
        assert len(suppressed) == 1
        assert suppressed[0].line == 6

        # +/- 1 line context anti-pattern suppression
        neighbor_sample = "# SafeLoader verified below\ndata = yaml.load(payload)\n"
        neighbor_resp = engine.test_rule(
            CustomRuleTestRequest(rule=rule, sample_code=neighbor_sample, sample_language="python")
        )
        assert neighbor_resp.matches_count == 0
        assert neighbor_resp.suppressed_count == 1

        # Match cap at 500 matches
        many_lines = "\n".join("yaml.load(x)" for _ in range(550))
        capped_resp = engine.test_rule(
            CustomRuleTestRequest(rule=rule, sample_code=many_lines, sample_language="python")
        )
        assert len(capped_resp.matches) == 500
        assert capped_resp.matches_count == 500
        assert any("500" in w for w in capped_resp.warnings)

        # Unsafe regex in test_rule raises ValueError
        with pytest.raises(ValueError):
            engine.test_rule(
                CustomRuleTestRequest(
                    rule=rule.model_copy(update={"pattern": "([a-z]+)*"}),
                    sample_code="abc",
                )
            )

    def test_workspace_test_rule_and_evaluate_enabled_rules_respects_gitignore_symlinks_and_confinement(
        self, tmp_path: Path
    ):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret_leak.py").write_text("pickle.loads(raw)\n", encoding="utf-8")

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".gitignore").write_text("ignored_dir/\n", encoding="utf-8")
        (repo / "ignored_dir").mkdir()
        (repo / "ignored_dir" / "skip.py").write_text("pickle.loads(ignored)\n", encoding="utf-8")
        (repo / "app.py").write_text(
            f'API_KEY = "{RAW_SECRET_GH}"\npickle.loads(user_blob)\n',
            encoding="utf-8",
        )
        (repo / "app.ts").write_text("pickle.loads(ts_blob)\n", encoding="utf-8")
        _create_dir_link(repo / "linked_outside", outside)

        try:
            vault = tmp_path / ".alastor_vault"
            engine = CustomRuleEngine(str(vault))
            py_rule = CustomSecurityRule(
                rule_id="CUSTOM-PICKLE-PY",
                name="Python Unsafe Pickle",
                severity="CRITICAL",
                cwe_id="CWE-502",
                languages=["python"],
                pattern=r"pickle\.loads\s*\(",
                description="Unsafe pickle deserialization",
                remediation="Use JSON.",
                enabled=True,
            )
            disabled_rule = CustomSecurityRule(
                rule_id="CUSTOM-DISABLED",
                name="Disabled Rule",
                severity="LOW",
                cwe_id="CWE-20",
                languages=["python"],
                pattern=r"API_KEY",
                enabled=False,
            )
            engine.create_rule(py_rule)
            engine.create_rule(disabled_rule)

            def _confine(path: str) -> str:
                real = os.path.realpath(path)
                root_real = os.path.realpath(str(repo))
                if os.path.commonpath([root_real, real]) != root_real:
                    raise HostileRepoError("Path outside confined workspace")
                return real

            # Outside path blocked by workspace_confinement_fn
            with pytest.raises(HostileRepoError):
                engine.test_rule(
                    CustomRuleTestRequest(rule=py_rule, project_path=str(outside)),
                    workspace_confinement_fn=_confine,
                )

            # Confined scan filters language (ignores app.ts), respects .gitignore, drops symlink escape
            ws_resp = engine.test_rule(
                CustomRuleTestRequest(rule=py_rule, project_path=str(repo)),
                workspace_confinement_fn=_confine,
            )
            assert ws_resp.matches_count == 1
            assert ws_resp.matches[0].filepath == "app.py"
            assert ws_resp.matches[0].line == 2

            # evaluate_enabled_rules_on_workspace returns valid Finding objects for enabled rules only
            findings = engine.evaluate_enabled_rules_on_workspace(str(repo))
            assert len(findings) == 1
            f = findings[0]
            assert f.source_engine == "ALASTOR_CUSTOM_RULE"
            assert f.rule_id == "CUSTOM-PICKLE-PY"
            assert f.cwe_id == "CWE-502"
            assert f.severity == "CRITICAL"
            assert f.best_fix_location is not None
            assert f.best_fix_location.filepath == "app.py"
            assert f.best_fix_location.line == 2
            assert RAW_SECRET_GH not in f.best_fix_location.code_snippet
        finally:
            if os.path.lexists(repo / "linked_outside"):
                _remove_dir_link(repo / "linked_outside")

    def test_rejects_dot_segment_rule_ids(self, tmp_path: Path):
        engine = CustomRuleEngine(str(tmp_path / ".alastor_vault"))
        for bad_id in (".", ".."):
            with pytest.raises(ValueError):
                engine._validate_rule_id(bad_id)
            with pytest.raises(ValueError):
                engine.get_rule(bad_id)
            with pytest.raises(ValueError):
                engine.create_rule(
                    CustomSecurityRule(
                        rule_id=bad_id,
                        name="Dot Segment Rule",
                        pattern=r"eval\(",
                    )
                )
            with pytest.raises(ValueError):
                engine.update_rule(
                    bad_id,
                    CustomSecurityRule(
                        rule_id=bad_id,
                        name="Dot Segment Rule",
                        pattern=r"eval\(",
                    ),
                )
            with pytest.raises(ValueError):
                engine.delete_rule(bad_id)


# ---------------------------------------------------------------------------
# 3. Cross-Repo Microservice Attack-Graph Stitcher
# ---------------------------------------------------------------------------
class TestMicroserviceAttackGraphStitcher:
    def test_normalize_route_template_variants(self):
        assert normalize_route_template("http://billing-service:8080/api/orders/123") == "/api/orders/:param"
        assert normalize_route_template("/api/orders/{order_id}") == "/api/orders/:param"
        assert normalize_route_template("/api/orders/${id}") == "/api/orders/:param"
        assert normalize_route_template("/api/orders/<int:order_id>") == "/api/orders/:param"
        assert normalize_route_template("/api/orders/:orderId") == "/api/orders/:param"
        assert normalize_route_template("/api/orders/42?expand=true#top") == "/api/orders/:param"
        assert normalize_route_template("https://svc.internal//api//v1//charges/%s") == "/api/v1/charges/:param"

    def test_two_repo_and_three_repo_stitching_reactflow_and_confinement(self, tmp_path: Path):
        gw = tmp_path / "api-gateway"
        gw.mkdir()
        (gw / "requirements.txt").write_text("fastapi==0.115.0\nrequests==2.32.3\n", encoding="utf-8")
        (gw / "routes.py").write_text(
            "import os\n"
            "import subprocess\n"
            "import requests\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n\n"
            "@app.post('/gateway/checkout/{order_id}')\n"
            "def checkout(order_id: str, cmd: str = ''):\n"
            f'    # token = "{RAW_SECRET_GH}"\n'
            "    subprocess.run(cmd, shell=True)\n"
            "    resp = requests.post(f'http://billing-service:8080/api/v1/charges/{order_id}')\n"
            "    producer.send('billing.events', {'order_id': order_id})\n"
            "    return resp.json()\n",
            encoding="utf-8",
        )

        billing = tmp_path / "billing-service"
        billing.mkdir()
        (billing / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
        (billing / "app.py").write_text(
            "import sqlite3\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n\n"
            "@app.post('/api/v1/charges/{charge_id}')\n"
            "def create_charge(charge_id: str):\n"
            "    conn = sqlite3.connect(':memory:')\n"
            "    cursor = conn.cursor()\n"
            '    cursor.execute(f"SELECT * FROM charges WHERE id = {charge_id}")\n'
            "    return {'status': 'ok'}\n\n"
            "@kafka_listener('billing.events')\n"
            "def on_billing_event(msg):\n"
            "    return msg\n",
            encoding="utf-8",
        )
        (billing / "billing.proto").write_text(
            "syntax = \"proto3\";\n"
            "service BillingGrpc {\n"
            "  rpc RefundCharge (RefundReq) returns (RefundResp);\n"
            "}\n",
            encoding="utf-8",
        )

        # Verify surface extraction independently including gRPC & Queue
        billing_eps, billing_calls, billing_findings = extract_service_surface(
            MicroserviceRepoInput(service_name="billing-service", repo_path=str(billing)),
            scan_findings=True,
        )
        assert any(e.protocol == "HTTP" and e.normalized_path == "/api/v1/charges/:param" for e in billing_eps)
        assert any(e.protocol == "QUEUE" and e.normalized_path == "billing.events" for e in billing_eps)
        assert any(e.protocol == "GRPC" and "RefundCharge" in e.raw_path for e in billing_eps)
        assert billing_findings

        # Full cross-repo stitch
        req = MicroserviceGraphRequest(
            services=[
                MicroserviceRepoInput(service_name="api-gateway", repo_path=str(gw)),
                MicroserviceRepoInput(service_name="billing-service", repo_path=str(billing)),
            ],
            scan_findings=True,
        )
        resp = stitch_microservice_attack_graph(req)

        assert resp.services_analyzed == 2
        assert resp.total_inbound_endpoints >= 3
        assert resp.total_outbound_calls >= 2
        assert resp.stitched_edges_count >= 2  # HTTP /api/v1/charges/:param + QUEUE billing.events
        assert any(
            e.source_service == "api-gateway"
            and e.target_service == "billing-service"
            and e.protocol == "HTTP"
            and e.normalized_path == "/api/v1/charges/:param"
            for e in resp.edges
        )
        assert any(
            e.source_service == "api-gateway"
            and e.target_service == "billing-service"
            and e.protocol == "QUEUE"
            and e.normalized_path == "billing.events"
            for e in resp.edges
        )
        assert resp.cross_service_attack_paths_count >= 1
        assert resp.attack_paths[0].composite_severity == "CRITICAL"
        assert "api-gateway" in resp.attack_paths[0].services
        assert "billing-service" in resp.attack_paths[0].services
        assert RAW_SECRET_GH not in resp.attack_paths[0].narrative

        # ReactFlow structure checks
        assert len(resp.reactflow_nodes) == 2
        for node in resp.reactflow_nodes:
            assert node["type"] == "serviceNode"
            assert "x" in node["position"] and "y" in node["position"]
            assert {"service_name", "endpoints_count", "findings_count", "highest_severity", "is_entry"} <= set(
                node["data"].keys()
            )
        assert len(resp.reactflow_edges) == resp.stitched_edges_count
        for rf_edge in resp.reactflow_edges:
            assert {"protocol", "method", "normalized_path", "is_attack_path"} <= set(rf_edge["data"].keys())
        assert any(rf_edge["animated"] is True and rf_edge["data"]["is_attack_path"] is True for rf_edge in resp.reactflow_edges)

        # Confinement check blocks outside repo path
        outside = tmp_path / "outside-svc"
        outside.mkdir()

        def _confine_gw_only(p: str) -> str:
            real = os.path.realpath(p)
            allowed = os.path.realpath(str(gw))
            if os.path.commonpath([allowed, real]) != allowed:
                raise HostileRepoError("Service path outside confined workspace")
            return real

        with pytest.raises(HostileRepoError):
            stitch_microservice_attack_graph(
                MicroserviceGraphRequest(
                    services=[
                        MicroserviceRepoInput(service_name="api-gateway", repo_path=str(gw)),
                        MicroserviceRepoInput(service_name="outside", repo_path=str(outside)),
                    ],
                    scan_findings=False,
                ),
                workspace_confinement_fn=_confine_gw_only,
            )

    def test_empty_services_raises_and_single_service_warns_gracefully(self, tmp_path: Path):
        with pytest.raises(ValueError):
            stitch_microservice_attack_graph(MicroserviceGraphRequest(services=[], scan_findings=False))

        solo = tmp_path / "solo-svc"
        solo.mkdir()
        (solo / "index.js").write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/api/ping', (req, res) => res.send('ok'));\n",
            encoding="utf-8",
        )
        resp = stitch_microservice_attack_graph(
            MicroserviceGraphRequest(
                services=[MicroserviceRepoInput(service_name="solo-svc", repo_path=str(solo))],
                scan_findings=False,
            )
        )
        assert resp.services_analyzed == 1
        assert resp.stitched_edges_count == 0
        assert resp.warnings
        assert len(resp.reactflow_nodes) == 1

    def test_three_hop_polyglot_chain_express_go_java_and_nextjs(self, tmp_path: Path):
        edge = tmp_path / "edge-proxy"
        (edge / "app" / "api" / "checkout").mkdir(parents=True)
        (edge / "app" / "api" / "checkout" / "route.ts").write_text(
            "export async function POST(req: Request) {\n"
            "  return fetch('http://auth-service:8080/internal/verify', { method: 'POST' });\n"
            "}\n",
            encoding="utf-8",
        )

        auth = tmp_path / "auth-service"
        auth.mkdir()
        (auth / "main.go").write_text(
            'package main\n'
            'import "net/http"\n'
            'func main() {\n'
            '  http.HandleFunc("/internal/verify", func(w http.ResponseWriter, r *http.Request) {\n'
            '    req, _ := http.NewRequest(http.MethodPost, "http://ledger-service:9000/api/ledger/entries/99", nil)\n'
            '    _ = req\n'
            '  })\n'
            '}\n',
            encoding="utf-8",
        )

        ledger = tmp_path / "ledger-service"
        ledger.mkdir()
        (ledger / "LedgerController.java").write_text(
            '@RequestMapping("/api/ledger")\n'
            'public class LedgerController {\n'
            '  @PostMapping("/entries/{entryId}")\n'
            '  public String postEntry() {\n'
            '    return "ok";\n'
            '  }\n'
            '}\n',
            encoding="utf-8",
        )
        (ledger / "danger.py").write_text(
            "import sqlite3\n"
            "def bad(eid):\n"
            "    cur = sqlite3.connect(':memory:').cursor()\n"
            '    cur.execute(f"SELECT * FROM entries WHERE id = {eid}")\n',
            encoding="utf-8",
        )

        resp = stitch_microservice_attack_graph(
            MicroserviceGraphRequest(
                services=[
                    MicroserviceRepoInput(service_name="edge-proxy", repo_path=str(edge)),
                    MicroserviceRepoInput(service_name="auth-service", repo_path=str(auth)),
                    MicroserviceRepoInput(service_name="ledger-service", repo_path=str(ledger)),
                ],
                scan_findings=True,
            )
        )
        assert resp.services_analyzed == 3
        assert resp.stitched_edges_count == 2
        assert any(
            e.source_service == "edge-proxy" and e.target_service == "auth-service"
            for e in resp.edges
        )
        assert any(
            e.source_service == "auth-service"
            and e.target_service == "ledger-service"
            and e.normalized_path == "/api/ledger/entries/:param"
            for e in resp.edges
        )
        assert any(
            p.hop_count == 2 and p.services == ["edge-proxy", "auth-service", "ledger-service"]
            for p in resp.attack_paths
        )
        pos_by_svc = {n["data"]["service_name"]: n["position"]["x"] for n in resp.reactflow_nodes}
        assert pos_by_svc["edge-proxy"] < pos_by_svc["auth-service"] < pos_by_svc["ledger-service"]

    def test_disconnected_cycle_discovery_and_host_affinity_and_placeholder_hosts(self, tmp_path: Path):
        # Component 1: gateway -> billing (with template host placeholder + external 1-char subdomain negative)
        gw = tmp_path / "gateway"
        gw.mkdir()
        (gw / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
        (gw / "gw.py").write_text(
            "import requests\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.post('/gw/run')\n"
            "def run_gw(bid: str):\n"
            "    requests.post(f'http://${BILLING_HOST}:8080/api/v1/charges/{bid}')\n"
            "    requests.get('https://a.example.com/status')\n",
            encoding="utf-8",
        )

        auth = tmp_path / "auth-service"
        auth.mkdir()
        (auth / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
        (auth / "auth.py").write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/status')\n"
            "def status():\n"
            "    return {'ok': True}\n",
            encoding="utf-8",
        )

        billing = tmp_path / "billing-service"
        billing.mkdir()
        (billing / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
        (billing / "bill.py").write_text(
            "import sqlite3\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.post('/api/v1/charges/{charge_id}')\n"
            "def charge(charge_id: str):\n"
            "    cur = sqlite3.connect(':memory:').cursor()\n"
            '    cur.execute(f"SELECT * FROM charges WHERE id = {charge_id}")\n'
            "    return {}\n",
            encoding="utf-8",
        )

        # Component 2: Disconnected mutual cycle svc-c <-> svc-d
        svc_c = tmp_path / "svc-c"
        svc_c.mkdir()
        (svc_c / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
        (svc_c / "c.py").write_text(
            "import requests\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/c/ping')\n"
            "def c_ping():\n"
            "    return requests.get('http://svc-d:8000/d/pong').json()\n",
            encoding="utf-8",
        )

        svc_d = tmp_path / "svc-d"
        svc_d.mkdir()
        (svc_d / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
        (svc_d / "d.py").write_text(
            "import sqlite3, requests\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/d/pong')\n"
            "def d_pong(uid: str):\n"
            "    cur = sqlite3.connect(':memory:').cursor()\n"
            '    cur.execute(f"SELECT * FROM t WHERE id = {uid}")\n'
            "    return requests.get('http://svc-c:8000/c/ping').json()\n",
            encoding="utf-8",
        )

        resp = stitch_microservice_attack_graph(
            MicroserviceGraphRequest(
                services=[
                    MicroserviceRepoInput(service_name="gateway", repo_path=str(gw)),
                    MicroserviceRepoInput(service_name="auth-service", repo_path=str(auth)),
                    MicroserviceRepoInput(service_name="billing-service", repo_path=str(billing)),
                    MicroserviceRepoInput(service_name="svc-c", repo_path=str(svc_c)),
                    MicroserviceRepoInput(service_name="svc-d", repo_path=str(svc_d)),
                ],
                scan_findings=True,
            )
        )

        # Template host placeholder matches path-only with 0.75 confidence
        gw_to_bill = [
            e for e in resp.edges
            if e.source_service == "gateway" and e.target_service == "billing-service"
        ]
        assert len(gw_to_bill) == 1
        assert gw_to_bill[0].confidence == 0.75

        # 1-char subdomain 'a.example.com' must NOT falsely match 'auth-service'
        assert not any(
            e.source_service == "gateway" and e.target_service == "auth-service"
            for e in resp.edges
        )

        # Both entry-rooted chain AND disconnected cycle component discovered
        assert any(p.services == ["gateway", "billing-service"] for p in resp.attack_paths)
        assert any(
            set(p.services) == {"svc-c", "svc-d"} for p in resp.attack_paths
        )

    def test_bracketed_host_placeholders_and_malformed_ipv6_urls_degrade_gracefully(self, tmp_path: Path):
        # Direct unit checks for ValueError-prone URLs (`urlsplit` & `.hostname`)
        assert normalize_route_template("http://[API_HOST]/orders/123") == "/orders/:param"
        assert normalize_route_template("http://[API_HOST]/orders") == "/orders"
        assert normalize_route_template("http://[::1/bad") == "/bad"
        assert normalize_route_template("http://[::1") == "/"

        assert _normalize_queue_topic("sqs://[QUEUE_HOST]/orders-topic") == "orders-topic"
        assert _normalize_queue_topic("http://[::1/bad") == "bad"
        assert _normalize_queue_topic("kafka://[::1") == "kafka://[::1"

        assert _extract_host_hint_from_url("http://[API_HOST]/orders") == ""
        assert _extract_host_hint_from_url("http://[::1/bad") == ""

        svc = MicroserviceRepoInput(
            service_name="orders-service",
            repo_path=str(tmp_path),
            base_url_hint="http://[API_HOST]/orders",
        )
        aliases = _service_host_aliases(svc)
        assert "orders-service" in aliases

        svc_bad_ipv6 = MicroserviceRepoInput(
            service_name="legacy-svc",
            repo_path=str(tmp_path),
            base_url_hint="http://[::1/bad",
        )
        assert "legacy-svc" in _service_host_aliases(svc_bad_ipv6)

        # End-to-end stitch does not crash when source code contains bracketed host URLs
        gw = tmp_path / "gw-bracket"
        gw.mkdir()
        (gw / "gw.py").write_text(
            "import requests\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/go')\n"
            "def go():\n"
            "    requests.post('http://[API_HOST]/orders')\n"
            "    requests.get('http://[::1/bad')\n"
            "    return {}\n",
            encoding="utf-8",
        )
        orders = tmp_path / "orders-bracket"
        orders.mkdir()
        (orders / "orders.py").write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.post('/orders')\n"
            "def create_order():\n"
            "    return {'ok': True}\n",
            encoding="utf-8",
        )
        resp = stitch_microservice_attack_graph(
            MicroserviceGraphRequest(
                services=[
                    MicroserviceRepoInput(
                        service_name="gw-bracket",
                        repo_path=str(gw),
                        base_url_hint="http://[::1/bad",
                    ),
                    MicroserviceRepoInput(
                        service_name="orders-bracket",
                        repo_path=str(orders),
                        base_url_hint="http://[API_HOST]",
                    ),
                ],
                scan_findings=False,
            )
        )
        assert resp.services_analyzed == 2
        assert any(
            e.source_service == "gw-bracket"
            and e.target_service == "orders-bracket"
            and e.normalized_path == "/orders"
            for e in resp.edges
        )

