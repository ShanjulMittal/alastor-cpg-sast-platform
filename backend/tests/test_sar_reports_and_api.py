import base64
from io import BytesIO
import json
import os
from pathlib import Path
import re
from unittest.mock import patch
import zlib

import docx
from fastapi.testclient import TestClient

from engine.enterprise_manager import EnterpriseManager
from engine.pasta_threat_engine import (
    PastaThreatEngine,
    _classify_threat_taxonomy,
    _redact_sensitive_text,
)
from engine.sar_report_generator import (
    SarReportBundle,
    build_sar_json_dict,
    generate_sar_docx_bytes,
    generate_sar_pdf_bytes,
    sanitize_bundle_for_export,
)
from models import (
    BestFixLocation,
    Finding,
    MetricsResponse,
    PastaGateOverrideRequest,
)


def _extract_all_docx_text(docx_bytes: bytes) -> str:
    document = docx.Document(BytesIO(docx_bytes))
    chunks = [p.text for p in document.paragraphs if p.text]
    for tbl in document.tables:
        for row in tbl.rows:
            for cell in row.cells:
                if cell.text:
                    chunks.append(cell.text)
    for section in document.sections:
        for hp in section.header.paragraphs:
            if hp.text:
                chunks.append(hp.text)
        for fp in section.footer.paragraphs:
            if fp.text:
                chunks.append(fp.text)
    return "\n".join(chunks)


def _extract_decompressed_pdf_streams(pdf_bytes: bytes) -> bytes:
    out_parts = [pdf_bytes]
    for match in re.finditer(rb"stream\r?\n(.*?)\s*endstream", pdf_bytes, re.DOTALL):
        raw_stream = match.group(1).strip()
        try:
            out_parts.append(zlib.decompress(raw_stream))
            continue
        except zlib.error:
            pass
        try:
            a85_payload = raw_stream[:-2] if raw_stream.endswith(b"~>") else raw_stream
            if a85_payload.startswith(b"<~"):
                a85_payload = a85_payload[2:]
            decoded = base64.a85decode(a85_payload, adobe=False)
            out_parts.append(zlib.decompress(decoded))
        except Exception:
            continue
    return b"\n".join(out_parts)


def _seed_sample_fintech_repo(repo_dir: Path) -> None:
    api_dir = repo_dir / "api"
    svc_dir = repo_dir / "services"
    api_dir.mkdir(parents=True, exist_ok=True)
    svc_dir.mkdir(parents=True, exist_ok=True)

    (repo_dir / "requirements.txt").write_text(
        "fastapi==0.115.0\nstripe==10.12.0\npydantic>=2.7.0\n",
        encoding="utf-8",
    )
    (svc_dir / "ledger.py").write_text(
        "def write_ledger_entry(conn, order_id: str, cents: int):\n"
        '    conn.execute("INSERT INTO settlements (id, cents) VALUES (?, ?)", (order_id, cents))\n'
        "    return True\n",
        encoding="utf-8",
    )
    (api_dir / "checkout.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from services.ledger import write_ledger_entry\n\n"
        'router = APIRouter(prefix="/api/v1/checkout")\n\n'
        "def verify_bearer_jwt():\n"
        '    return {"sub": "acct-1"}\n\n'
        '@router.post("/charge")\n'
        "def charge_card(order_id: str, cents: int, _u=Depends(verify_bearer_jwt)):\n"
        "    write_ledger_entry(None, order_id, cents)\n"
        '    return {"charged": True}\n\n'
        '@router.post("/reconcile-open")\n'
        "def reconcile_open(order_id: str):\n"
        "    write_ledger_entry(None, order_id, 0)\n"
        '    return {"reconciled": order_id}\n',
        encoding="utf-8",
    )


def _build_sample_findings(short_canary: str, long_canary: str) -> list[Finding]:
    xml_tricky_snippet = (
        f'raw_q = "<script>if (amt < 100 && bal > 0) {{ alert(\\"xss\\"); }}</script>" + "{long_canary}"'
    )
    sqli_blocker = Finding(
        id="FIND-SAR-SQLI-01",
        rule_id="RULE-7-SQLI-FORMAT",
        severity="CRITICAL",
        title='SQL Injection & XML Payload <script>&"test" in Settlement Ledger',
        description=(
            f"Untrusted filter interpolated into SQL query with payload {xml_tricky_snippet} "
            f"and fallback token {short_canary}."
        ),
        cwe_id="CWE-89",
        scan_engine="SAST",
        reachability_status="REACHABLE",
        path_nodes=[
            {
                "id": "n-sar-1",
                "label": "Parameter",
                "ast_type": "parameter",
                "name": "order_id",
                "code": "order_id: str",
                "filepath": "api/checkout.py",
                "start_line": 12,
                "end_line": 12,
            },
            {
                "id": "n-sar-2",
                "label": "Call",
                "ast_type": "call",
                "name": "conn.execute",
                "code": xml_tricky_snippet,
                "filepath": "services/ledger.py",
                "start_line": 2,
                "end_line": 2,
            },
        ],
        best_fix_location=BestFixLocation(
            node_id="n-sar-2",
            filepath="services/ledger.py",
            line=2,
            column=4,
            code_snippet=xml_tricky_snippet,
            explanation='Parameterize SQL statement & escape <script>&"test" literals.',
            recommended_fix='conn.execute("SELECT * FROM settlements WHERE id = ?", (safe_id,))',
        ),
    )

    cred_long = Finding(
        id="FIND-SAR-CRED-LONG",
        rule_id="RULE-8-HARDCODED-SECRET",
        severity="CRITICAL",
        title="Verified Active Payment Gateway Key in Checkout",
        description=f"Active credential {long_canary} found in checkout module.",
        cwe_id="CWE-798",
        scan_engine="SAST",
        is_secret_finding=True,
        secret_key_name="STRIPE_LIVE_TOKEN",
        secret_value_masked="sk_l••••••••9999",
        secret_value_raw=long_canary,
        secret_type="Stripe API Credential",
        secret_detector_id="stripe_key",
        secret_validation_status="VERIFIED_ACTIVE",
        secret_source="WORKING_TREE",
        best_fix_location=BestFixLocation(
            node_id="n-cred-long",
            filepath="api/checkout.py",
            line=5,
            column=0,
            code_snippet=f'TOKEN = "{long_canary}"',
            explanation="Move active gateway credential into secret vault.",
            recommended_fix='os.environ["STRIPE_LIVE_TOKEN"]',
        ),
    )

    cred_short = Finding(
        id="FIND-SAR-CRED-SHORT",
        rule_id="RULE-8-HARDCODED-SECRET",
        severity="MEDIUM",
        title="Revoked Legacy Token in Git History",
        description=f"Legacy credential {short_canary} found in historical commit.",
        cwe_id="CWE-798",
        scan_engine="SAST",
        is_secret_finding=True,
        secret_key_name="LEGACY_TOKEN",
        secret_value_masked="sk_l••••••••7788",
        secret_value_raw=short_canary,
        secret_type="Stripe API Credential",
        secret_detector_id="stripe_key",
        secret_validation_status="REVOKED_OR_INVALID",
        secret_source="GIT_HISTORY",
        best_fix_location=BestFixLocation(
            node_id="n-cred-short",
            filepath="api/checkout.py",
            line=6,
            column=0,
            code_snippet=f'OLD_TOKEN = "{short_canary}"',
            explanation="Purge historical token and verify rotation.",
            recommended_fix="git filter-repo & rotate key",
        ),
    )

    dormant_sla = Finding(
        id="FIND-SAR-DORMANT-01",
        rule_id="RULE-2-ORPHAN",
        severity="HIGH",
        title="Dormant Maintenance Reconciliation Helper",
        description='Uncalled helper with angle-brackets <T>&"check" in ledger.py.',
        cwe_id="CWE-561",
        scan_engine="SAST",
        reachability_status="UNREACHABLE_DORMANT",
        best_fix_location=BestFixLocation(
            node_id="n-dormant-1",
            filepath="services/ledger.py",
            line=3,
            column=0,
            code_snippet='def unused_helper(): return "<unused>&test"',
            explanation="Remove dead helper within post-launch sprint SLA.",
            recommended_fix="Delete unused helper function.",
        ),
    )

    waiver_cand = Finding(
        id="FIND-SAR-WAIVER-01",
        rule_id="RULE-3-DEADSTORE",
        severity="LOW",
        title="Minor Dead Store in Reconcile Counter",
        description="Unused diagnostic variable assignment.",
        cwe_id="CWE-563",
        scan_engine="SAST",
        reachability_status="CONDITIONALLY_REACHABLE",
        best_fix_location=BestFixLocation(
            node_id="n-waive-1",
            filepath="api/checkout.py",
            line=18,
            column=4,
            code_snippet="diag_count = 0",
            explanation="Remove unused diagnostic variable.",
            recommended_fix="Delete unused assignment.",
        ),
    )

    return [sqli_blocker, cred_long, cred_short, dormant_sla, waiver_cand]


def test_sar_bundle_redaction_docx_pdf_json_ten_sections_and_xml_safety(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    repo_dir = tmp_path / "fintech_sar_app"
    _seed_sample_fintech_repo(repo_dir)

    short_canary = "CANARY_RAW_CRED_BASE_7788"
    long_canary = "CANARY_RAW_CRED_BASE_7788_SUPERSTRING_9999"
    findings = _build_sample_findings(short_canary, long_canary)

    mgr = EnterpriseManager()
    mgr.pasta_engine = PastaThreatEngine(vault_dir=str(vault_dir))

    initial_pasta = mgr.pasta_engine.evaluate_pasta(str(repo_dir), findings=findings)
    waiver_obs = next(
        o for o in initial_pasta.golive_observations if o.linked_finding_id == "FIND-SAR-WAIVER-01"
    )
    mgr.pasta_engine.update_gate_override(
        str(repo_dir),
        PastaGateOverrideRequest(
            observation_id=waiver_obs.id,
            gate_status="RISK_ACCEPTED_WAIVER",
            sla_window="WAIVED",
            compensating_control_note='Accepted by CISO ARB with runtime telemetry <guard>&"alert".',
        ),
    )

    sast_plus = mgr.get_sast_plus_suite(str(repo_dir), findings)
    assert sast_plus.pasta_assessment is not None
    raci = mgr.get_raci_governance(findings)
    metrics = MetricsResponse(
        total_nodes=120,
        total_edges=240,
        total_findings=len(findings),
        critical_count=2,
        high_count=1,
        medium_count=1,
        low_count=1,
        total_app_files=3,
    )

    raw_bundle = SarReportBundle(
        application_name="fintech_sar_app",
        project_path=str(repo_dir),
        generated_at="2026-11-15T16:00:00Z",
        pasta=sast_plus.pasta_assessment,
        sast_plus=sast_plus,
        raci=raci,
        metrics=metrics,
        findings=findings,
    )

    sanitized = sanitize_bundle_for_export(raw_bundle)
    assert all(f.secret_value_raw is None for f in sanitized.findings)
    # Original findings list must not be mutated in place
    assert findings[1].secret_value_raw == long_canary
    assert findings[2].secret_value_raw == short_canary

    # 1. JSON SAR dict check + length-descending redaction check (no _SUPERSTRING_9999 leftover!)
    sar_json = build_sar_json_dict(raw_bundle)
    expected_json_keys = {
        "document_control",
        "executive_golive_scorecard",
        "pasta_assessment",
        "stride_threats",
        "mandatory_pre_golive_blockers",
        "post_golive_deferrable_observations",
        "waived_observations",
        "make_it_live_runbook",
        "architectural_strengths",
        "raci_and_signoff",
        "findings",
    }
    assert expected_json_keys.issubset(set(sar_json.keys()))
    dumped_sar_json = json.dumps(sar_json, ensure_ascii=False)
    assert short_canary not in dumped_sar_json
    assert long_canary not in dumped_sar_json
    assert "_SUPERSTRING_9999" not in dumped_sar_json
    assert "sk_l••••••••9999" in dumped_sar_json

    # 2. Word (.docx) binary generation & 10-section verification
    docx_bytes = generate_sar_docx_bytes(raw_bundle)
    assert docx_bytes.startswith(b"PK\x03\x04")
    assert short_canary.encode("utf-8") not in docx_bytes
    assert long_canary.encode("utf-8") not in docx_bytes
    assert b"_SUPERSTRING_9999" not in docx_bytes

    docx_text = _extract_all_docx_text(docx_bytes)
    assert short_canary not in docx_text
    assert long_canary not in docx_text
    assert "_SUPERSTRING_9999" not in docx_text

    docx_upper = docx_text.upper()
    for sec_num in range(1, 11):
        assert f"SECTION {sec_num}" in docx_upper
    for kw in (
        "PASTA",
        "STRIDE",
        "MANDATORY PRE-GO-LIVE",
        "POST-GO-LIVE",
        "MAKE IT LIVE",
        "RACI",
        "SIGN-OFF",
        "INHERENT RISK",
        "CURRENT RESIDUAL RISK",
        "FINAL PROJECTED GO-LIVE RISK LEVEL",
        "SECURITY ARCHITECT (ARB)",
        "ENGINEERING / TECH LEAD",
        "DEVOPS / SRE LEAD",
        "PRODUCT / BUSINESS RISK OWNER",
    ):
        assert kw in docx_upper

    # 3. PDF (.pdf) binary generation, XML escaping safety, size & redaction check
    pdf_bytes = generate_sar_pdf_bytes(raw_bundle)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2500
    assert short_canary.encode("utf-8") not in pdf_bytes
    assert long_canary.encode("utf-8") not in pdf_bytes
    assert b"_SUPERSTRING_9999" not in pdf_bytes

    decompressed_pdf = _extract_decompressed_pdf_streams(pdf_bytes)
    assert short_canary.encode("utf-8") not in decompressed_pdf
    assert long_canary.encode("utf-8") not in decompressed_pdf
    assert b"_SUPERSTRING_9999" not in decompressed_pdf
    for sec_num in range(1, 11):
        assert f"Section {sec_num}".encode("utf-8") in decompressed_pdf or f"SECTION {sec_num}".encode("utf-8") in decompressed_pdf


def test_sar_report_clean_zero_blockers_renders_attestation(tmp_path: Path):
    vault_dir = tmp_path / "vault_clean"
    repo_dir = tmp_path / "clean_internal_app"
    repo_dir.mkdir(parents=True)
    (repo_dir / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
    (repo_dir / "app.py").write_text(
        "def compute_sum(a: int, b: int) -> int:\n    return a + b\n",
        encoding="utf-8",
    )

    mgr = EnterpriseManager()
    mgr.pasta_engine = PastaThreatEngine(vault_dir=str(vault_dir))
    sast_plus = mgr.get_sast_plus_suite(str(repo_dir), [])
    assert sast_plus.pasta_assessment is not None
    assert sast_plus.pasta_assessment.mandatory_pre_golive_count == 0
    assert sast_plus.pasta_assessment.golive_verdict == "APPROVED_FOR_GO_LIVE"

    bundle = SarReportBundle(
        application_name="clean_internal_app",
        project_path=str(repo_dir),
        generated_at="2026-11-15T16:10:00Z",
        pasta=sast_plus.pasta_assessment,
        sast_plus=sast_plus,
        raci=mgr.get_raci_governance([]),
        metrics=MetricsResponse(
            total_nodes=10,
            total_edges=12,
            total_findings=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            total_app_files=2,
        ),
        findings=[],
    )

    docx_bytes = generate_sar_docx_bytes(bundle)
    docx_text = _extract_all_docx_text(docx_bytes)
    assert "0 Mandatory Pre-Go-Live Blockers Open" in docx_text

    pdf_bytes = generate_sar_pdf_bytes(bundle)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2500
    decompressed_pdf = _extract_decompressed_pdf_streams(pdf_bytes)
    assert b"0 Mandatory Pre-Go-Live Blockers Open" in decompressed_pdf


def test_pasta_api_endpoints_confinement_and_roundtrips(tmp_path: Path):
    import main

    vault_dir = tmp_path / "api_vault"
    repo_dir = tmp_path / "confined_fintech_ws"
    outside_dir = tmp_path / "unregistered_outside_ws"
    outside_dir.mkdir(parents=True)
    _seed_sample_fintech_repo(repo_dir)

    short_canary = "CANARY_API_CRED_SHORT_1111"
    long_canary = "CANARY_API_CRED_SHORT_1111_FULL_2222"
    sample_findings = _build_sample_findings(short_canary, long_canary)
    iso_pasta_engine = PastaThreatEngine(vault_dir=str(vault_dir))

    prev_scan_dir = main.current_scan_dir
    main.current_scan_dir = str(repo_dir)
    try:
        with (
            patch.object(main, "startup_event", return_value=None),
            patch.object(main, "shutdown_event", return_value=None),
            patch.object(main.enterprise_mgr, "pasta_engine", iso_pasta_engine),
            patch.object(main, "get_or_compute_findings", return_value=sample_findings),
            TestClient(main.app) as client,
        ):
            # 1. Path confinement checks (400 on C:\Windows\System32, outside_dir, and nonexistent path)
            sys32_path = r"C:\Windows\System32"
            for bad_path in (sys32_path, str(outside_dir), str(tmp_path / "missing_dir_xyz")):
                r_bad_get = client.get("/api/aspm/pasta", params={"project_path": bad_path})
                assert r_bad_get.status_code == 400

                r_bad_suite = client.get("/api/aspm/suite", params={"project_path": bad_path})
                assert r_bad_suite.status_code == 400

                r_bad_sar = client.get(
                    "/api/export/sar-report",
                    params={"format": "pdf", "project_path": bad_path},
                )
                assert r_bad_sar.status_code == 400

                r_bad_prof = client.post(
                    "/api/aspm/pasta/profile",
                    json={"project_path": bad_path, "business_preset": "FINTECH_PAYMENTS"},
                )
                assert r_bad_prof.status_code == 400

                r_bad_ov = client.post(
                    "/api/aspm/pasta/gate-override",
                    json={
                        "project_path": bad_path,
                        "observation_id": "obs-1",
                        "gate_status": "POST_GO_LIVE_SLA",
                    },
                )
                assert r_bad_ov.status_code == 400

            # Invalid format check -> 400
            r_bad_fmt = client.get("/api/export/sar-report", params={"format": "xml"})
            assert r_bad_fmt.status_code == 400

            # 2. Valid GET /api/aspm/pasta
            r_pasta = client.get("/api/aspm/pasta", params={"project_path": str(repo_dir)})
            assert r_pasta.status_code == 200
            pasta_body = r_pasta.json()
            assert len(pasta_body["stages"]) == 7
            assert len(pasta_body["attack_trees"]) >= 1
            assert pasta_body["golive_verdict"] == "NO_GO_HOLD_RELEASE"
            assert pasta_body["effective_business_preset"] == "FINTECH_PAYMENTS"
            assert long_canary not in json.dumps(pasta_body)

            # 3. GET /api/aspm/suite includes non-null pasta_assessment
            r_suite = client.get("/api/aspm/suite", params={"project_path": str(repo_dir)})
            assert r_suite.status_code == 200
            suite_body = r_suite.json()
            assert suite_body["pasta_assessment"] is not None
            assert len(suite_body["pasta_assessment"]["stages"]) == 7

            # 4. POST /api/aspm/pasta/profile update + reset roundtrip
            r_prof_set = client.post(
                "/api/aspm/pasta/profile",
                json={
                    "project_path": str(repo_dir),
                    "business_preset": "HEALTHCARE_PHI",
                    "crown_jewel_weights": {"DATABASE_STORES": 1.95},
                    "reset_defaults": False,
                },
            )
            assert r_prof_set.status_code == 200
            prof_set_body = r_prof_set.json()
            assert prof_set_body["selected_business_preset"] == "HEALTHCARE_PHI"
            assert prof_set_body["effective_business_preset"] == "HEALTHCARE_PHI"
            db_cj = next(c for c in prof_set_body["crown_jewels"] if c["id"] == "DATABASE_STORES")
            assert db_cj["weight_multiplier"] == 1.95

            r_prof_reset = client.post(
                "/api/aspm/pasta/profile",
                json={
                    "project_path": str(repo_dir),
                    "reset_defaults": True,
                },
            )
            assert r_prof_reset.status_code == 200
            prof_reset_body = r_prof_reset.json()
            assert prof_reset_body["selected_business_preset"] == "AUTO_INFERRED"
            assert prof_reset_body["effective_business_preset"] == "FINTECH_PAYMENTS"
            db_cj_reset = next(c for c in prof_reset_body["crown_jewels"] if c["id"] == "DATABASE_STORES")
            assert db_cj_reset["weight_multiplier"] == 1.5

            # 5. POST /api/aspm/pasta/gate-override update + reset roundtrip
            target_obs = next(
                o
                for o in prof_reset_body["golive_observations"]
                if o["gate_status"] == "MANDATORY_PRE_GO_LIVE"
            )
            obs_id = target_obs["id"]

            r_ov_set = client.post(
                "/api/aspm/pasta/gate-override",
                json={
                    "project_path": str(repo_dir),
                    "observation_id": obs_id,
                    "gate_status": "RISK_ACCEPTED_WAIVER",
                    "sla_window": "WAIVED",
                    "compensating_control_note": "WAF virtual patch + strict egress firewall enforced.",
                    "reset_override": False,
                },
            )
            assert r_ov_set.status_code == 200
            ov_set_body = r_ov_set.json()
            updated_obs = next(o for o in ov_set_body["golive_observations"] if o["id"] == obs_id)
            assert updated_obs["is_overridden"] is True
            assert updated_obs["gate_status"] == "RISK_ACCEPTED_WAIVER"
            assert ov_set_body["waived_count"] >= 1

            r_ov_reset = client.post(
                "/api/aspm/pasta/gate-override",
                json={
                    "project_path": str(repo_dir),
                    "observation_id": obs_id,
                    "reset_override": True,
                },
            )
            assert r_ov_reset.status_code == 200
            ov_reset_body = r_ov_reset.json()
            restored_obs = next(o for o in ov_reset_body["golive_observations"] if o["id"] == obs_id)
            assert restored_obs["is_overridden"] is False
            assert restored_obs["gate_status"] == "MANDATORY_PRE_GO_LIVE"
    finally:
        main.current_scan_dir = prev_scan_dir


def test_sar_export_endpoints_docx_pdf_json_and_legacy_report_enrichment(tmp_path: Path):
    import main

    vault_dir = tmp_path / "export_vault"
    repo_dir = tmp_path / "sar_export_target"
    _seed_sample_fintech_repo(repo_dir)

    short_canary = "CANARY_EXPORT_CRED_5555"
    long_canary = "CANARY_EXPORT_CRED_5555_EXTENDED_8888"
    sample_findings = _build_sample_findings(short_canary, long_canary)
    iso_pasta_engine = PastaThreatEngine(vault_dir=str(vault_dir))
    mock_metrics = MetricsResponse(
        total_nodes=88,
        total_edges=144,
        total_findings=len(sample_findings),
        critical_count=2,
        high_count=1,
        medium_count=1,
        low_count=1,
        total_app_files=3,
    )

    prev_scan_dir = main.current_scan_dir
    main.current_scan_dir = str(repo_dir)
    try:
        with (
            patch.object(main, "startup_event", return_value=None),
            patch.object(main, "shutdown_event", return_value=None),
            patch.object(main.enterprise_mgr, "pasta_engine", iso_pasta_engine),
            patch.object(main, "get_or_compute_findings", return_value=sample_findings),
            patch.object(main, "get_metrics", return_value=mock_metrics),
            TestClient(main.app) as client,
        ):
            # Confirm active RBAC operator CAN reveal secrets in UI, yet SAR exports MUST still redact!
            assert main.enterprise_mgr.active_user_can_reveal_secrets() is True

            # 1. Word (.docx) export
            r_docx = client.get(
                "/api/export/sar-report",
                params={"format": "docx", "project_path": str(repo_dir)},
            )
            assert r_docx.status_code == 200
            assert (
                r_docx.headers["content-type"]
                == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            )
            assert 'ALASTOR_SAR_GoLive_sar_export_target.docx"' in r_docx.headers["content-disposition"]
            assert r_docx.content.startswith(b"PK\x03\x04")
            assert short_canary.encode("utf-8") not in r_docx.content
            assert long_canary.encode("utf-8") not in r_docx.content

            docx_txt = _extract_all_docx_text(r_docx.content).upper()
            for kw in (
                "PASTA",
                "STRIDE",
                "MANDATORY PRE-GO-LIVE",
                "POST-GO-LIVE",
                "MAKE IT LIVE",
                "RACI",
                "SIGN-OFF",
            ):
                assert kw in docx_txt

            # 2. PDF (.pdf) export
            r_pdf = client.get(
                "/api/export/sar-report",
                params={"format": "pdf", "project_path": str(repo_dir)},
            )
            assert r_pdf.status_code == 200
            assert r_pdf.headers["content-type"].startswith("application/pdf")
            assert 'ALASTOR_SAR_GoLive_sar_export_target.pdf"' in r_pdf.headers["content-disposition"]
            assert r_pdf.content.startswith(b"%PDF-")
            assert len(r_pdf.content) > 2500
            decompressed_pdf = _extract_decompressed_pdf_streams(r_pdf.content)
            assert short_canary.encode("utf-8") not in decompressed_pdf
            assert long_canary.encode("utf-8") not in decompressed_pdf

            # 3. JSON SAR export
            r_json = client.get(
                "/api/export/sar-report",
                params={"format": "json", "project_path": str(repo_dir)},
            )
            assert r_json.status_code == 200
            assert short_canary not in r_json.text
            assert long_canary not in r_json.text
            sar_payload = r_json.json()
            assert sar_payload["executive_golive_scorecard"]["golive_verdict"] == "NO_GO_HOLD_RELEASE"
            assert len(sar_payload["pasta_assessment"]["stages"]) == 7

            # 4. Enriched GET /api/export/report (json + markdown)
            r_rep_json = client.get("/api/export/report", params={"format": "json"})
            assert r_rep_json.status_code == 200
            assert short_canary not in r_rep_json.text
            assert long_canary not in r_rep_json.text
            rep_json_body = r_rep_json.json()
            assert "pasta_golive_summary" in rep_json_body
            p_sum = rep_json_body["pasta_golive_summary"]
            for req_field in (
                "golive_verdict",
                "inherent_risk_score",
                "residual_risk_score",
                "projected_golive_risk_score",
                "mandatory_pre_golive_count",
                "post_golive_sla_count",
            ):
                assert req_field in p_sum

            r_rep_md = client.get("/api/export/report", params={"format": "markdown"})
            assert r_rep_md.status_code == 200
            assert "## PASTA 7-Stage Threat Simulation & Go-Live Readiness" in r_rep_md.text
            assert short_canary not in r_rep_md.text
            assert long_canary not in r_rep_md.text
    finally:
        main.current_scan_dir = prev_scan_dir


def test_sar_report_conditional_golive_verdict_banner(tmp_path: Path):
    vault_dir = tmp_path / "cond_vault"
    repo_dir = tmp_path / "conditional_saas_app"
    repo_dir.mkdir(parents=True)
    # Unpinned dependency triggers POST_GO_LIVE_SLA without any MANDATORY_PRE_GO_LIVE blocker
    (repo_dir / "requirements.txt").write_text("fastapi>=0.115.0\n", encoding="utf-8")
    (repo_dir / "app.py").write_text(
        "def healthy_ping() -> dict:\n    return {'ok': True}\n",
        encoding="utf-8",
    )

    dormant_only = Finding(
        id="FIND-COND-DORMANT-1",
        rule_id="RULE-2-ORPHAN",
        severity="MEDIUM",
        title="Dormant Helper Function",
        description="Uncalled helper eligible for post-launch SLA.",
        cwe_id="CWE-561",
        scan_engine="SAST",
        reachability_status="UNREACHABLE_DORMANT",
        best_fix_location=BestFixLocation(
            node_id="n-cond-1",
            filepath="app.py",
            line=1,
            column=0,
            code_snippet="def healthy_ping(): ...",
            explanation="Clean up in next sprint.",
            recommended_fix="Remove if unused.",
        ),
    )

    mgr = EnterpriseManager()
    mgr.pasta_engine = PastaThreatEngine(vault_dir=str(vault_dir))
    suite = mgr.get_sast_plus_suite(str(repo_dir), [dormant_only])
    assert suite.pasta_assessment is not None
    assert suite.pasta_assessment.golive_verdict == "CONDITIONAL_GO_LIVE"
    assert suite.pasta_assessment.mandatory_pre_golive_count == 0
    assert suite.pasta_assessment.post_golive_sla_count >= 1

    bundle = SarReportBundle(
        application_name="conditional_saas_app",
        project_path=str(repo_dir),
        generated_at="2026-11-15T16:30:00Z",
        pasta=suite.pasta_assessment,
        sast_plus=suite,
        raci=mgr.get_raci_governance([dormant_only]),
        metrics=MetricsResponse(
            total_nodes=14,
            total_edges=18,
            total_findings=1,
            critical_count=0,
            high_count=0,
            medium_count=1,
            low_count=0,
            total_app_files=2,
        ),
        findings=[dormant_only],
    )

    docx_txt = _extract_all_docx_text(generate_sar_docx_bytes(bundle))
    assert "CONDITIONAL GO-LIVE" in docx_txt
    assert "0 Mandatory Pre-Go-Live Blockers Open" in docx_txt

    pdf_bytes = generate_sar_pdf_bytes(bundle)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2500
    decompressed = _extract_decompressed_pdf_streams(pdf_bytes)
    assert b"CONDITIONAL GO-LIVE" in decompressed


def test_aspm_suite_scrubs_disk_backed_line_snippets_and_pasta(tmp_path: Path):
    import subprocess
    import main

    vault_dir = tmp_path / "disk_scrub_vault"
    repo_dir = tmp_path / "disk_scrub_workspace"
    repo_dir.mkdir(parents=True)

    raw_short_canary = "sk_live_" + "SUPER_SECRET_DISK"
    raw_disk_canary = raw_short_canary + "_LINE_9876543210"
    (repo_dir / "billing_keys.py").write_text(
        f'STRIPE_SECRET = "{raw_disk_canary}"\n'
        "def charge_customer(amount: int) -> bool:\n"
        "    return amount > 0\n",
        encoding="utf-8",
    )

    disk_cred_finding = Finding(
        id="FIND-DISK-SECRET-01",
        rule_id="RULE-8-HARDCODED-SECRET",
        severity="CRITICAL",
        title=f"Hardcoded Stripe Live Key in billing_keys.py ({raw_disk_canary})",
        description=f"Detected live Stripe key {raw_disk_canary} on disk.",
        cwe_id="CWE-798",
        scan_engine="SAST",
        is_secret_finding=True,
        secret_key_name="STRIPE_SECRET",
        secret_value_masked="sk_l••••••••3210",
        secret_value_raw=raw_disk_canary,
        secret_type="Stripe API Credential",
        secret_detector_id="stripe_key",
        secret_validation_status="VERIFIED_ACTIVE",
        secret_source="WORKING_TREE",
        best_fix_location=BestFixLocation(
            node_id="n-disk-sec-1",
            filepath="billing_keys.py",
            line=1,
            column=0,
            code_snippet="",
            explanation="Load Stripe key from secret manager vault.",
            recommended_fix='os.environ["STRIPE_SECRET"]',
        ),
    )
    short_prefix_finding = Finding(
        id="FIND-DISK-SECRET-PREFIX",
        rule_id="RULE-8-HARDCODED-SECRET",
        severity="HIGH",
        title="Legacy Stripe Prefix Key",
        description=f"Detected prefix token {raw_short_canary}.",
        cwe_id="CWE-798",
        scan_engine="SAST",
        is_secret_finding=True,
        secret_key_name="STRIPE_LEGACY_PREFIX",
        secret_value_masked="sk_l••••••••DISK",
        secret_value_raw=raw_short_canary,
        secret_type="Stripe API Credential",
        secret_detector_id="stripe_key",
        secret_validation_status="OFFLINE_STRUCTURALLY_VALID",
        secret_source="GIT_HISTORY",
        best_fix_location=BestFixLocation(
            node_id="n-disk-sec-2",
            filepath="billing_keys.py",
            line=1,
            column=0,
            code_snippet="",
            explanation="Purge historical key from git history.",
            recommended_fix="git filter-repo",
        ),
    )

    # Create a junction/symlink alias pointing to repo_dir to verify canonical realpath resolution
    alias_dir = tmp_path / "disk_scrub_junction_alias"
    alias_created = False
    try:
        os.symlink(str(repo_dir), str(alias_dir), target_is_directory=True)
        alias_created = True
    except OSError:
        if os.name == "nt":
            proc = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(alias_dir), str(repo_dir)],
                capture_output=True,
                text=True,
                check=False,
            )
            alias_created = proc.returncode == 0 and alias_dir.exists()

    iso_pasta_engine = PastaThreatEngine(vault_dir=str(vault_dir))

    prev_scan_dir = main.current_scan_dir
    main.current_scan_dir = str(repo_dir)
    try:
        with (
            patch.object(main, "startup_event", return_value=None),
            patch.object(main, "shutdown_event", return_value=None),
            patch.object(main.enterprise_mgr, "pasta_engine", iso_pasta_engine),
            patch.object(
                main,
                "get_or_compute_findings",
                return_value=[short_prefix_finding, disk_cred_finding],
            ),
            TestClient(main.app) as client,
        ):
            r_suite = client.get("/api/aspm/suite", params={"project_path": str(repo_dir)})
            assert r_suite.status_code == 200
            assert raw_disk_canary not in r_suite.text
            assert raw_short_canary not in r_suite.text
            assert "_LINE_9876543210" not in r_suite.text
            suite_json = r_suite.json()
            assert suite_json["pasta_assessment"]["mandatory_pre_golive_count"] >= 1

            r_pasta = client.get("/api/aspm/pasta", params={"project_path": str(repo_dir)})
            assert r_pasta.status_code == 200
            assert raw_disk_canary not in r_pasta.text
            assert raw_short_canary not in r_pasta.text
            assert "_LINE_9876543210" not in r_pasta.text
            assert r_pasta.json()["mandatory_pre_golive_count"] >= 1

            if alias_created:
                assert iso_pasta_engine._project_key(str(alias_dir)) == iso_pasta_engine._project_key(
                    str(repo_dir)
                )
                main.current_scan_dir = str(alias_dir)
                r_alias = client.get("/api/aspm/pasta", params={"project_path": str(repo_dir)})
                assert r_alias.status_code == 200
                assert r_alias.json()["mandatory_pre_golive_count"] >= 1
                assert raw_disk_canary not in r_alias.text
    finally:
        main.current_scan_dir = prev_scan_dir
        if alias_created and alias_dir.exists():
            if os.name == "nt" and not alias_dir.is_symlink():
                subprocess.run(["cmd", "/c", "rmdir", str(alias_dir)], check=False)
            else:
                alias_dir.unlink(missing_ok=True)


def test_redact_sensitive_text_sorts_overlapping_prefix_secrets():
    set_short_first: set[str] = set()
    set_short_first.add("TOK_ABC")
    set_short_first.add("TOK_ABC_SUPER_PROD_9999")

    set_long_first: set[str] = set()
    set_long_first.add("TOK_ABC_SUPER_PROD_9999")
    set_long_first.add("TOK_ABC")

    sample_text = "token=TOK_ABC_SUPER_PROD_9999 and short=TOK_ABC"
    for candidate_set in (
        {"TOK_ABC", "TOK_ABC_SUPER_PROD_9999"},
        {"TOK_ABC_SUPER_PROD_9999", "TOK_ABC"},
        set_short_first,
        set_long_first,
    ):
        redacted = _redact_sensitive_text(sample_text, candidate_set)
        assert "_SUPER_PROD_9999" not in redacted
        assert "TOK_ABC" not in redacted

    # Exercise multiple hash-bucket collisions so unsorted set order cannot pass by luck
    for idx in range(12):
        short_tok = f"TOK_ABC_{idx}"
        long_tok = f"{short_tok}_SUPER_PROD_9999"
        out = _redact_sensitive_text(
            f"primary={long_tok} fallback={short_tok}",
            {short_tok, long_tok},
        )
        assert "_SUPER_PROD_9999" not in out
        assert short_tok not in out

    # Verify explicit CWE precedence over generic "TAINT" / "INJECTION" rule_id substrings
    custom_sqli = Finding(
        id="F-CUST-SQLI",
        rule_id="CUSTOM-TAINT-INJECTION-QUERY",
        severity="HIGH",
        title="Custom SQL Taint Rule",
        description="Taint reaches SQL query sink.",
        cwe_id="CWE-89",
        scan_engine="SAST",
    )
    custom_xss = Finding(
        id="F-CUST-XSS",
        rule_id="CUSTOM-TAINT-DOM-RENDER",
        severity="HIGH",
        title="Custom XSS Taint Rule",
        description="Taint reaches innerHTML sink.",
        cwe_id="CWE-79",
        scan_engine="SAST",
    )
    assert _classify_threat_taxonomy(custom_sqli)[0] == "CAPEC-66 / T1190"
    assert _classify_threat_taxonomy(custom_xss)[0] == "CAPEC-63 / T1189"


