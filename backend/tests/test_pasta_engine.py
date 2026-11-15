import json
import os
from pathlib import Path

from models import (
    BestFixLocation,
    Finding,
    PastaAssessmentResponse,
    PastaGateOverrideRequest,
    PastaProfileUpdateRequest,
    PipelineSecurityCheck,
    SastPlusSuiteResponse,
)
from engine.pasta_threat_engine import PastaThreatEngine


def _norm_vault_key(target_dir: str) -> str:
    return os.path.normcase(os.path.abspath(target_dir)).replace("\\", "/")


def test_sast_plus_suite_includes_optional_pasta_assessment():
    suite_default = SastPlusSuiteResponse(project_path="/tmp/demo")
    assert suite_default.pasta_assessment is None

    assessment = PastaAssessmentResponse(
        project_path="/tmp/demo",
        application_name="demo",
        generated_at="2026-11-15T15:00:00Z",
    )
    suite_with_pasta = SastPlusSuiteResponse(
        project_path="/tmp/demo",
        pasta_assessment=assessment,
    )
    assert suite_with_pasta.pasta_assessment is not None
    assert suite_with_pasta.pasta_assessment.application_name == "demo"


def test_fintech_auto_inference_seven_stages_attack_trees_and_redaction(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    repo_dir = tmp_path / "fintech_checkout_app"
    api_dir = repo_dir / "api"
    svc_dir = repo_dir / "services"
    api_dir.mkdir(parents=True)
    svc_dir.mkdir(parents=True)

    (repo_dir / "requirements.txt").write_text(
        "fastapi==0.115.0\nstripe==10.12.0\npydantic>=2.7.0\n",
        encoding="utf-8",
    )
    (svc_dir / "billing_ledger.py").write_text(
        "def record_invoice_entry(db_conn, invoice_id: str, amount_cents: int):\n"
        '    db_conn.execute("INSERT INTO ledger_entries (id, cents) VALUES (?, ?)", (invoice_id, amount_cents))\n'
        "    return True\n",
        encoding="utf-8",
    )
    (api_dir / "payments.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from services.billing_ledger import record_invoice_entry\n\n"
        'router = APIRouter(prefix="/api/v1/payments")\n\n'
        "def require_jwt_auth():\n"
        '    return {"sub": "merchant-1"}\n\n'
        '@router.post("/checkout")\n'
        "def create_checkout(invoice_id: str, amount_cents: int, user=Depends(require_jwt_auth)):\n"
        "    record_invoice_entry(None, invoice_id, amount_cents)\n"
        '    return {"ok": True}\n\n'
        '@router.post("/webhook-reconcile")\n'
        "def reconcile_unauthenticated(invoice_id: str):\n"
        "    record_invoice_entry(None, invoice_id, 0)\n"
        '    return {"reconciled": invoice_id}\n',
        encoding="utf-8",
    )

    sensitive_raw_marker = "sk_live_SUPER_SENSITIVE_RAW_VALUE_DO_NOT_LEAK_9999"

    sqli_finding = Finding(
        id="FIND-SQLI-FIN-01",
        rule_id="RULE-7-SQLI-FORMAT",
        severity="CRITICAL",
        title="SQL Injection in Ledger Query",
        description="Untrusted invoice filter concatenated into ledger query.",
        cwe_id="CWE-89",
        scan_engine="SAST",
        reachability_status="REACHABLE",
        path_nodes=[
            {
                "id": "n-entry-1",
                "label": "Parameter",
                "ast_type": "parameter",
                "name": "invoice_id",
                "code": "invoice_id: str",
                "filepath": "api/payments.py",
                "start_line": 10,
                "end_line": 10,
            },
            {
                "id": "n-prop-1",
                "label": "Call",
                "ast_type": "call",
                "name": "record_invoice_entry",
                "code": "record_invoice_entry(None, invoice_id, amount_cents)",
                "filepath": "api/payments.py",
                "start_line": 11,
                "end_line": 11,
            },
            {
                "id": "n-sink-1",
                "label": "Call",
                "ast_type": "call",
                "name": "db_conn.execute",
                "code": "db_conn.execute(raw_query)",
                "filepath": "services/billing_ledger.py",
                "start_line": 2,
                "end_line": 2,
            },
        ],
        best_fix_location=BestFixLocation(
            node_id="n-sink-1",
            filepath="services/billing_ledger.py",
            line=2,
            column=4,
            code_snippet="db_conn.execute(raw_query)",
            explanation="Use bound query parameters for ledger persistence.",
            recommended_fix="Use parameterized SQL placeholders (?, ?) with tuple bindings.",
        ),
    )

    active_cred_finding = Finding(
        id="FIND-CRED-STRIPE-01",
        rule_id="RULE-8-HARDCODED-SECRET",
        severity="HIGH",
        title="Live Stripe Credential in Checkout Config",
        description="Verified active Stripe token committed in source.",
        cwe_id="CWE-798",
        scan_engine="SAST",
        is_secret_finding=True,
        secret_key_name="STRIPE_KEY",
        secret_value_masked="sk_l••••••••9999",
        secret_value_raw=sensitive_raw_marker,
        secret_type="Stripe API Credential",
        secret_detector_id="stripe_key",
        secret_validation_status="VERIFIED_ACTIVE",
        secret_source="WORKING_TREE",
        best_fix_location=BestFixLocation(
            node_id="n-cred-1",
            filepath="api/payments.py",
            line=5,
            column=0,
            code_snippet='STRIPE_KEY = "sk_l..."',
            explanation="Load Stripe key from vault runtime environment.",
            recommended_fix='os.environ["STRIPE_KEY"]',
        ),
    )

    dormant_finding = Finding(
        id="FIND-ORPHAN-01",
        rule_id="RULE-2-ORPHAN",
        severity="HIGH",
        title="Dormant Maintenance Helper",
        description="Uncalled helper routine in billing_ledger.py.",
        cwe_id="CWE-561",
        scan_engine="SAST",
        reachability_status="UNREACHABLE_DORMANT",
        best_fix_location=BestFixLocation(
            node_id="n-orph-1",
            filepath="services/billing_ledger.py",
            line=3,
            column=0,
            code_snippet="def old_helper(): ...",
            explanation="Remove unused helper before release.",
            recommended_fix="Delete uncalled maintenance function.",
        ),
    )

    suppressed_finding = Finding(
        id="FIND-SUPPRESSED-01",
        rule_id="RULE-3-DEADSTORE",
        severity="MEDIUM",
        title="False Positive Dead Store",
        cwe_id="CWE-563",
        triage_status="NOT_EXPLOITABLE",
        best_fix_location=BestFixLocation(
            node_id="n-sup-1",
            filepath="api/payments.py",
            line=12,
            code_snippet="tmp = 1",
        ),
    )

    engine = PastaThreatEngine(vault_dir=str(vault_dir))
    resp = engine.evaluate_pasta(
        str(repo_dir),
        findings=[sqli_finding, active_cred_finding, dormant_finding, suppressed_finding],
    )

    assert resp.selected_business_preset == "AUTO_INFERRED"
    assert resp.effective_business_preset == "FINTECH_PAYMENTS"
    assert "PCI-DSS v4.0" in resp.compliance_frameworks
    assert "SOX" in resp.compliance_frameworks
    assert resp.inferred_business_reason

    cj_by_id = {cj.id: cj for cj in resp.crown_jewels}
    assert set(cj_by_id.keys()) == {
        "DATABASE_STORES",
        "SECRETS_AND_CREDENTIALS",
        "AI_AND_EXTERNAL_APIS",
        "HOST_RUNTIME_AND_OS",
        "AUTH_AND_SESSION_BOUNDARY",
    }
    assert cj_by_id["DATABASE_STORES"].weight_multiplier == 1.5
    assert cj_by_id["SECRETS_AND_CREDENTIALS"].weight_multiplier == 1.8
    assert cj_by_id["AI_AND_EXTERNAL_APIS"].weight_multiplier == 1.2
    assert cj_by_id["HOST_RUNTIME_AND_OS"].weight_multiplier == 1.7
    assert cj_by_id["AUTH_AND_SESSION_BOUNDARY"].weight_multiplier == 1.4

    assert len(resp.stages) == 7
    expected_stages = [
        (1, "PASTA-1", "I", "Define Objectives (DO)"),
        (2, "PASTA-2", "II", "Define Technical Scope (DTS)"),
        (3, "PASTA-3", "III", "Application Decomposition (AD)"),
        (4, "PASTA-4", "IV", "Threat Analysis (TA)"),
        (5, "PASTA-5", "V", "Weakness & Vulnerability Analysis (WVA)"),
        (6, "PASTA-6", "VI", "Attack Modeling & Simulation (AMS)"),
        (7, "PASTA-7", "VII", "Risk & Impact Analysis (RIA)"),
    ]
    for st, (exp_num, exp_code, exp_roman, exp_title) in zip(resp.stages, expected_stages):
        assert st.stage_number == exp_num
        assert st.stage_code == exp_code
        assert st.stage_roman == exp_roman
        assert st.title == exp_title
        assert len(st.evidence_items) >= 1

    stage4_capecs = " ".join(ev.cwe_or_capec for ev in resp.stages[3].evidence_items)
    assert "CAPEC-66 / T1190" in stage4_capecs
    assert "CAPEC-560 / T1552" in stage4_capecs

    # Suppressed NOT_EXPLOITABLE finding must not appear in golive_observations
    obs_linked_ids = {o.linked_finding_id for o in resp.golive_observations if o.linked_finding_id}
    assert "FIND-SUPPRESSED-01" not in obs_linked_ids
    assert "FIND-SQLI-FIN-01" in obs_linked_ids
    assert "FIND-CRED-STRIPE-01" in obs_linked_ids
    assert "FIND-ORPHAN-01" in obs_linked_ids

    # Attack trees check: exploitable + partially guarded scenarios, BFL shield edge
    assert 1 <= len(resp.attack_trees) <= 6
    sqli_tree = next(t for t in resp.attack_trees if t.linked_finding_id == "FIND-SQLI-FIN-01")
    assert sqli_tree.status == "EXPLOITABLE_PATH"
    roles = {n.node_role for n in sqli_tree.nodes}
    assert {"ENTRYPOINT", "CAPEC_VECTOR", "PROPAGATION", "VULN_SINK", "BFL_SHIELD", "CROWN_JEWEL", "GOAL"}.issubset(roles)
    bfl_edges = [e for e in sqli_tree.edges if e.label == "SEVERS AT BFL" and e.is_blocked is True]
    assert len(bfl_edges) == 1

    dormant_tree = next(t for t in resp.attack_trees if t.linked_finding_id == "FIND-ORPHAN-01")
    assert dormant_tree.status == "PARTIALLY_GUARDED"

    # Strict redaction: raw secret value must NEVER appear anywhere in serialized output
    dumped_json = resp.model_dump_json()
    assert sensitive_raw_marker not in dumped_json

    # Risk & Verdict invariants
    assert resp.golive_verdict == "NO_GO_HOLD_RELEASE"
    assert resp.golive_verdict_label == "NO-GO • HOLD RELEASE (MANDATORY BLOCKERS OPEN)"
    assert resp.mandatory_pre_golive_count >= 2
    assert resp.residual_risk_score >= 65
    assert resp.inherent_risk_score >= resp.residual_risk_score >= resp.projected_golive_risk_score


def test_clean_posture_baseline_severed_attack_tree_and_other_presets(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    engine = PastaThreatEngine(vault_dir=str(vault_dir))

    # 1. Healthcare preset auto-inference with 0 findings -> APPROVED_FOR_GO_LIVE + Severed tree
    hc_dir = tmp_path / "ehr_clinical_portal"
    hc_dir.mkdir()
    (hc_dir / "patient_fhir_service.py").write_text(
        "def get_patient_diagnosis_record(patient_id: int):\n"
        '    return {"patient_id": patient_id, "status": "ok"}\n',
        encoding="utf-8",
    )
    hc_resp = engine.evaluate_pasta(str(hc_dir), findings=[])
    assert hc_resp.effective_business_preset == "HEALTHCARE_PHI"
    assert "HIPAA Security Rule" in hc_resp.compliance_frameworks
    assert hc_resp.golive_verdict == "APPROVED_FOR_GO_LIVE"
    assert hc_resp.golive_verdict_label == "APPROVED FOR GO-LIVE (CLEAN POSTURE)"
    assert hc_resp.mandatory_pre_golive_count == 0
    assert hc_resp.post_golive_sla_count == 0
    assert hc_resp.waived_count == 0
    assert len(hc_resp.attack_trees) == 1
    clean_tree = hc_resp.attack_trees[0]
    assert clean_tree.title == "Baseline Defense-in-Depth Attack Simulation"
    assert clean_tree.status == "SEVERED_BY_CONTROLS"
    assert len(clean_tree.nodes) >= 4
    assert len(clean_tree.edges) >= 3
    assert any(n.is_severed for n in clean_tree.nodes)
    assert hc_resp.inherent_risk_score >= hc_resp.residual_risk_score >= hc_resp.projected_golive_risk_score

    # 2. AI SaaS Public preset auto-inference
    ai_dir = tmp_path / "genai_rag_service"
    ai_dir.mkdir()
    (ai_dir / "requirements.txt").write_text("openai==1.52.0\nlangchain==0.3.4\n", encoding="utf-8")
    (ai_dir / "prompt_router.py").write_text(
        "def build_vector_prompt(query: str) -> str:\n"
        "    return query.strip()[:200]\n",
        encoding="utf-8",
    )
    ai_resp = engine.evaluate_pasta(str(ai_dir), findings=[])
    assert ai_resp.effective_business_preset == "AI_SAAS_PUBLIC"
    assert "OWASP Top 10 for LLM" in ai_resp.compliance_frameworks


def test_golive_gate_default_classifications_all_tiers(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    repo_dir = tmp_path / "enterprise_ops_app"
    repo_dir.mkdir()

    subproc_mod = "sub" + "process"
    (repo_dir / "ops_api.py").write_text(
        f"import {subproc_mod}\n"
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        '@app.post("/ops/run-diag")\n'
        "def run_diag(host_arg: str):\n"
        f'    {subproc_mod}.run(["/usr/bin/ping", "-c", "1", host_arg], check=False)\n'
        '    return {"ran": host_arg}\n\n'
        '@app.post("/ops/update-note")\n'
        "def update_note(note_text: str):\n"
        '    return {"saved": note_text}\n',
        encoding="utf-8",
    )

    findings = [
        # 1. Reachable HIGH SAST -> MANDATORY_PRE_GO_LIVE (PRE_LAUNCH)
        Finding(
            id="F-HIGH-REACH",
            rule_id="RULE-10-PATH-TRAVERSAL",
            severity="HIGH",
            title="Reachable Path Traversal",
            cwe_id="CWE-22",
            reachability_status="REACHABLE",
            best_fix_location=BestFixLocation(filepath="file_svc.py", line=10),
        ),
        # 2. Working-tree HIGH structurally valid credential -> MANDATORY_PRE_GO_LIVE (PRE_LAUNCH)
        Finding(
            id="F-WT-CRED",
            rule_id="SECRET-WT",
            severity="HIGH",
            title="Working Tree JWT Signing Material",
            cwe_id="CWE-798",
            is_secret_finding=True,
            secret_source="WORKING_TREE",
            secret_validation_status="OFFLINE_STRUCTURALLY_VALID",
            best_fix_location=BestFixLocation(filepath="auth_cfg.py", line=4),
        ),
        # 3. Dormant HIGH -> POST_GO_LIVE_SLA (7_DAYS)
        Finding(
            id="F-HIGH-DORMANT",
            rule_id="RULE-4-INFINITE-LOOP",
            severity="HIGH",
            title="Dormant Loop in Legacy Worker",
            cwe_id="CWE-835",
            reachability_status="UNREACHABLE_DORMANT",
            best_fix_location=BestFixLocation(filepath="legacy_worker.py", line=22),
        ),
        # 4. GIT_HISTORY non-active credential -> POST_GO_LIVE_SLA (14_DAYS)
        Finding(
            id="F-GIT-HIST-CRED",
            rule_id="SECRET-GIT-HIST",
            severity="HIGH",
            title="Historical Commit Token",
            cwe_id="CWE-798",
            is_secret_finding=True,
            secret_source="GIT_HISTORY",
            secret_validation_status="OFFLINE_STRUCTURALLY_VALID",
            best_fix_location=BestFixLocation(filepath="old_deploy.py", line=8),
        ),
        # 5. MEDIUM finding -> POST_GO_LIVE_SLA (30_DAYS)
        Finding(
            id="F-MED-CRYPTO",
            rule_id="RULE-13-UNSAFE-DESERIALIZATION-CRYPTO",
            severity="MEDIUM",
            title="Weak Digest Checksum",
            cwe_id="CWE-327",
            reachability_status="REACHABLE",
            best_fix_location=BestFixLocation(filepath="checksum.py", line=14),
        ),
        # 6. TEST_OR_PLACEHOLDER credential -> POST_GO_LIVE_SLA (90_DAYS)
        Finding(
            id="F-TEST-CRED",
            rule_id="SECRET-TEST",
            severity="LOW",
            title="Sandbox Test Key Prefix",
            cwe_id="CWE-798",
            is_secret_finding=True,
            secret_source="WORKING_TREE",
            secret_validation_status="TEST_OR_PLACEHOLDER",
            best_fix_location=BestFixLocation(filepath="sandbox_cfg.py", line=2),
        ),
    ]

    pbom_checks = [
        PipelineSecurityCheck(
            id="pbom-ci-unpinned-actions",
            category="CI/CD Workflow Pinning",
            title="Unpinned GitHub Actions Tag in Release Pipeline",
            status="FAIL",
            primary_filepath=".github/workflows/release.yml",
            primary_line=18,
            details="Uses @main instead of immutable commit SHA.",
            remediation="Pin third-party GitHub Action to full 40-char commit SHA.",
        ),
        PipelineSecurityCheck(
            id="pbom-sbom-attestation",
            category="Supply-Chain Provenance",
            title="Missing SLSA Build Attestation Artifact",
            status="WARNING",
            primary_filepath="Dockerfile",
            primary_line=1,
            details="Container image build omits signed provenance attestation.",
            remediation="Add cosign / SLSA provenance generation step.",
        ),
    ]

    engine = PastaThreatEngine(vault_dir=str(vault_dir))
    resp = engine.evaluate_pasta(str(repo_dir), findings=findings, pipeline_checks=pbom_checks)

    by_linked = {o.linked_finding_id: o for o in resp.golive_observations if o.linked_finding_id}
    assert by_linked["F-HIGH-REACH"].gate_status == "MANDATORY_PRE_GO_LIVE"
    assert by_linked["F-HIGH-REACH"].sla_window == "PRE_LAUNCH"

    assert by_linked["F-WT-CRED"].gate_status == "MANDATORY_PRE_GO_LIVE"
    assert by_linked["F-WT-CRED"].sla_window == "PRE_LAUNCH"
    assert by_linked["F-WT-CRED"].source_type == "SECRET_VAULT"

    assert by_linked["F-HIGH-DORMANT"].gate_status == "POST_GO_LIVE_SLA"
    assert by_linked["F-HIGH-DORMANT"].sla_window == "7_DAYS"
    assert "7 days" in by_linked["F-HIGH-DORMANT"].compensating_control.lower()

    assert by_linked["F-GIT-HIST-CRED"].gate_status == "POST_GO_LIVE_SLA"
    assert by_linked["F-GIT-HIST-CRED"].sla_window == "14_DAYS"
    assert "git filter-repo" in by_linked["F-GIT-HIST-CRED"].compensating_control

    assert by_linked["F-MED-CRYPTO"].gate_status == "POST_GO_LIVE_SLA"
    assert by_linked["F-MED-CRYPTO"].sla_window == "30_DAYS"

    assert by_linked["F-TEST-CRED"].gate_status == "POST_GO_LIVE_SLA"
    assert by_linked["F-TEST-CRED"].sla_window == "90_DAYS"

    pbom_obs = [o for o in resp.golive_observations if o.source_type == "PBOM"]
    pbom_fail = next(o for o in pbom_obs if "unpinned-actions" in o.id)
    pbom_warn = next(o for o in pbom_obs if "sbom-attestation" in o.id)
    assert pbom_fail.gate_status == "MANDATORY_PRE_GO_LIVE"
    assert pbom_fail.sla_window == "PRE_LAUNCH"
    assert pbom_warn.gate_status == "POST_GO_LIVE_SLA"
    assert pbom_warn.sla_window == "90_DAYS"

    api_obs = [o for o in resp.golive_observations if o.source_type == "API_EXPOSURE"]
    exec_ep_obs = next(o for o in api_obs if "run-diag" in o.title.lower() or "run_diag" in o.title.lower())
    mut_ep_obs = next(o for o in api_obs if "update-note" in o.title.lower() or "update_note" in o.title.lower())
    assert exec_ep_obs.gate_status == "MANDATORY_PRE_GO_LIVE"
    assert exec_ep_obs.sla_window == "PRE_LAUNCH"
    assert mut_ep_obs.gate_status == "POST_GO_LIVE_SLA"
    assert mut_ep_obs.sla_window == "30_DAYS"


def test_profile_persistence_clamping_and_gate_override_verdict_transition(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    repo_dir = tmp_path / "stripe_gateway_service"
    repo_dir.mkdir()
    (repo_dir / "payment_handler.py").write_text(
        "def charge_card(card_token: str, cents: int):\n"
        '    return {"charged": cents}\n',
        encoding="utf-8",
    )

    crit_finding = Finding(
        id="FIND-CRIT-GATE-01",
        rule_id="RULE-1-TAINT",
        severity="CRITICAL",
        title="Command Execution in Payment Settlement",
        cwe_id="CWE-78",
        reachability_status="REACHABLE",
        best_fix_location=BestFixLocation(
            filepath="payment_handler.py",
            line=2,
            recommended_fix="Pass static argument list without command interpreter.",
        ),
    )
    med_finding = Finding(
        id="FIND-MED-GATE-02",
        rule_id="RULE-12-LOG-INJECTION",
        severity="MEDIUM",
        title="CRLF Log Entry Unsanitized",
        cwe_id="CWE-117",
        reachability_status="REACHABLE",
        best_fix_location=BestFixLocation(
            filepath="payment_handler.py",
            line=2,
            recommended_fix="Strip CR/LF characters before audit logging.",
        ),
    )

    engine = PastaThreatEngine(vault_dir=str(vault_dir))
    initial = engine.evaluate_pasta(str(repo_dir), findings=[crit_finding, med_finding])
    assert initial.effective_business_preset == "FINTECH_PAYMENTS"
    assert initial.golive_verdict == "NO_GO_HOLD_RELEASE"
    assert initial.mandatory_pre_golive_count == 1
    assert initial.post_golive_sla_count == 1

    crit_obs = next(o for o in initial.golive_observations if o.linked_finding_id == "FIND-CRIT-GATE-01")
    assert crit_obs.id.startswith("obs-")
    assert crit_obs.gate_status == "MANDATORY_PRE_GO_LIVE"
    assert crit_obs.is_overridden is False

    # 1. Override business profile & clamp Crown Jewel weights to [0.8, 2.0]
    engine.update_profile(
        str(repo_dir),
        PastaProfileUpdateRequest(
            business_preset="ENTERPRISE_INTERNAL",
            crown_jewel_weights={
                "DATABASE_STORES": 0.25,          # clamps to 0.8
                "HOST_RUNTIME_AND_OS": 3.4,       # clamps to 2.0
                "SECRETS_AND_CREDENTIALS": 1.95,  # preserved
            },
        ),
    )

    profiles_file = vault_dir / "pasta_profiles.json"
    assert profiles_file.is_file()
    persisted_map = json.loads(profiles_file.read_text(encoding="utf-8"))
    norm_key = _norm_vault_key(str(repo_dir))
    assert norm_key in persisted_map
    assert persisted_map[norm_key]["crown_jewel_weights"]["DATABASE_STORES"] == 0.8
    assert persisted_map[norm_key]["crown_jewel_weights"]["HOST_RUNTIME_AND_OS"] == 2.0
    assert persisted_map[norm_key]["crown_jewel_weights"]["SECRETS_AND_CREDENTIALS"] == 1.95

    # 2. Override mandatory blocker to POST_GO_LIVE_SLA -> transitions NO_GO_HOLD_RELEASE -> CONDITIONAL_GO_LIVE
    engine.update_gate_override(
        str(repo_dir),
        PastaGateOverrideRequest(
            observation_id=crit_obs.id,
            gate_status="POST_GO_LIVE_SLA",
            sla_window="7_DAYS",
            compensating_control_note="Emergency WAF virtual patch + internal subnet isolation active.",
        ),
    )

    # Re-instantiate engine from disk vault to verify full persistence across instances
    reloaded_engine = PastaThreatEngine(vault_dir=str(vault_dir))
    after_override = reloaded_engine.evaluate_pasta(str(repo_dir), findings=[crit_finding, med_finding])
    assert after_override.selected_business_preset == "ENTERPRISE_INTERNAL"
    assert after_override.effective_business_preset == "ENTERPRISE_INTERNAL"
    assert after_override.golive_verdict == "CONDITIONAL_GO_LIVE"
    assert after_override.golive_verdict_label == "CONDITIONAL GO-LIVE (APPROVED WITH SLA & COMPENSATING CONTROLS)"
    assert after_override.mandatory_pre_golive_count == 0
    assert after_override.post_golive_sla_count == 2
    assert after_override.inherent_risk_score >= after_override.residual_risk_score >= after_override.projected_golive_risk_score
    assert any("Phase A" in step for step in after_override.make_it_live_checklist)
    assert any("Phase B" in step for step in after_override.make_it_live_checklist)
    assert any("Final Verification Gate" in step for step in after_override.make_it_live_checklist)

    overridden_obs = next(o for o in after_override.golive_observations if o.id == crit_obs.id)
    assert overridden_obs.is_overridden is True
    assert overridden_obs.default_gate_status == "MANDATORY_PRE_GO_LIVE"
    assert overridden_obs.gate_status == "POST_GO_LIVE_SLA"
    assert overridden_obs.sla_window == "7_DAYS"
    assert "Emergency WAF virtual patch" in overridden_obs.compensating_control

    # 3. Reset profile defaults -> resets business_preset & weights while preserving gate_overrides
    reloaded_engine.update_profile(
        str(repo_dir),
        PastaProfileUpdateRequest(reset_defaults=True),
    )
    after_prof_reset = reloaded_engine.evaluate_pasta(str(repo_dir), findings=[crit_finding, med_finding])
    assert after_prof_reset.selected_business_preset == "AUTO_INFERRED"
    assert after_prof_reset.effective_business_preset == "FINTECH_PAYMENTS"
    assert after_prof_reset.golive_verdict == "CONDITIONAL_GO_LIVE"

    # 4. Waiver override with unspecified sla_window -> defaults to WAIVED
    reloaded_engine.update_gate_override(
        str(repo_dir),
        PastaGateOverrideRequest(
            observation_id=crit_obs.id,
            gate_status="RISK_ACCEPTED_WAIVER",
            compensating_control_note="CISO Exception #2026-88 signed for isolated air-gapped worker.",
        ),
    )
    after_waiver = reloaded_engine.evaluate_pasta(str(repo_dir), findings=[crit_finding, med_finding])
    waived_obs = next(o for o in after_waiver.golive_observations if o.id == crit_obs.id)
    assert waived_obs.gate_status == "RISK_ACCEPTED_WAIVER"
    assert waived_obs.sla_window == "WAIVED"
    assert after_waiver.waived_count == 1
    assert after_waiver.golive_verdict == "CONDITIONAL_GO_LIVE"

    # 5. Reset gate override -> restores NO_GO_HOLD_RELEASE
    reloaded_engine.update_gate_override(
        str(repo_dir),
        PastaGateOverrideRequest(observation_id=crit_obs.id, reset_override=True),
    )
    after_gate_reset = reloaded_engine.evaluate_pasta(str(repo_dir), findings=[crit_finding, med_finding])
    assert after_gate_reset.golive_verdict == "NO_GO_HOLD_RELEASE"
    assert after_gate_reset.mandatory_pre_golive_count == 1


def test_all_seven_capec_mappings_deduplication_and_npm_sbom(tmp_path: Path):
    default_eng = PastaThreatEngine()
    assert default_eng.vault_dir.endswith(".alastor_vault")

    vault_dir = tmp_path / "vault"
    repo_dir = tmp_path / "internal_portal"
    repo_dir.mkdir()
    (repo_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "internal-portal",
                "dependencies": {"react": "19.0.0", "lodash": "^4.17.21"},
            }
        ),
        encoding="utf-8",
    )

    seven_vector_findings = [
        Finding(id="F-78", rule_id="RULE-1-TAINT", severity="CRITICAL", title="OS Exec", cwe_id="CWE-78"),
        Finding(id="F-89", rule_id="RULE-7-SQLI-FORMAT", severity="HIGH", title="SQLi", cwe_id="CWE-89"),
        Finding(id="F-79", rule_id="RULE-9-DOM-XSS", severity="HIGH", title="DOM XSS", cwe_id="CWE-79"),
        Finding(id="F-22", rule_id="RULE-10-PATH-TRAVERSAL", severity="HIGH", title="Path Traversal", cwe_id="CWE-22"),
        Finding(id="F-918", rule_id="RULE-11-SSRF-URLOPEN", severity="HIGH", title="SSRF", cwe_id="CWE-918"),
        Finding(
            id="F-798",
            rule_id="RULE-8-HARDCODED-SECRET",
            severity="HIGH",
            title="Hardcoded Token",
            cwe_id="CWE-798",
            is_secret_finding=True,
        ),
        Finding(
            id="F-1395",
            rule_id="SCA-UNPINNED",
            severity="MEDIUM",
            title="Unpinned Package",
            cwe_id="CWE-1395",
            scan_engine="SCA",
        ),
    ]

    dup_pbom_checks = [
        PipelineSecurityCheck(id="pbom-1-pinning", category="Dependency Version Pinning", title="Pinning", status="WARNING"),
        PipelineSecurityCheck(id="pbom-3-secrets", category="Secret & Credential Leak Hygiene", title="Secrets", status="FAIL"),
    ]

    eng = PastaThreatEngine(vault_dir=str(vault_dir))
    resp = eng.evaluate_pasta(str(repo_dir), findings=seven_vector_findings, pipeline_checks=dup_pbom_checks)

    assert resp.effective_business_preset == "ENTERPRISE_INTERNAL"
    stage4_capecs = {ev.cwe_or_capec for ev in resp.stages[3].evidence_items}
    assert {
        "CAPEC-88 / T1190",
        "CAPEC-66 / T1190",
        "CAPEC-63 / T1189",
        "CAPEC-126 / T1083",
        "CAPEC-194 / T1567",
        "CAPEC-560 / T1552",
        "CAPEC-438 / T1195",
    }.issubset(stage4_capecs)

    # Top attack trees capped at 6
    assert len(resp.attack_trees) == 6
    # Duplicate pbom-1-pinning and pbom-3-secrets checks must not create duplicate PBOM observations
    assert [o for o in resp.golive_observations if o.source_type == "PBOM"] == []
    # Stage 2 reflects npm package.json pinned vs floating
    assert any("Floating SBOM" in ev.title for ev in resp.stages[1].evidence_items)

