# 7-Stage PASTA Threat Modeling, Interactive Attack Trees & SAR Go-Live Word/PDF Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic 7-stage PASTA Threat Modeling & Interactive Attack Tree Workbench alongside STRIDE, plus a native Microsoft Word (`.docx`) and Adobe PDF (`.pdf`) Threat Modeling & Security Architecture Review (SAR) Go-Live Report generator with Mandatory Pre-Go-Live vs. Post-Go-Live SLA classification and live reviewer overrides.

**Architecture:** Isolate PASTA domain synthesis and per-project profile/gate-override persistence in `backend/engine/pasta_threat_engine.py`, isolate native 10-section `.docx` (`python-docx`) and `.pdf` (`reportlab`) generation in `backend/engine/sar_report_generator.py`, expose confined FastAPI routes in `backend/main.py`, and mount a self-contained Light-Only Daylight `PastaThreatWorkbench.tsx` (with ReactFlow Attack Tree canvas) inside `ThreatModelingView.tsx` plus flagship `.docx`/`.pdf` export cards in `frontend/src/app/page.tsx`.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, `python-docx`, `reportlab`, Next.js 15 / React 19, TypeScript, Zustand, `@xyflow/react` + `@dagrejs/dagre`, Tailwind CSS (Light-Only Daylight WCAG AA `>= 4.5:1`).

## Global Constraints

- **Work on `main` only** in `c:\Projects\Securecodereview\cpg-sast-platform` (per user instruction); keep Neo4j, FastAPI (`:8000`), and Next.js (`:3000`) live.
- **Light-Only Daylight UI (`>= 4.5:1` WCAG AA)**: Use `#f8fafc` / `#ffffff` surfaces, slate-900/800/700 typography, and high-contrast rose/amber/emerald/sky/indigo badges; zero dark-only backgrounds.
- **Zero Self-Audit Findings**: Never introduce raw dangerous sink strings, `shell=True`, unparameterized SQL, or unvalidated `open(user_path)` calls anywhere in `cpg-sast-platform` (ALASTOR self-scan must report `0` findings).
- **Strict Secret Redaction in Exports**: Raw credential values (`secret_value_raw`) must NEVER appear in `.docx`, `.pdf`, or `json` SAR reports regardless of RBAC role; always emit `secret_value_masked` only.
- **Workspace Path Confinement**: Every `project_path` query or body parameter must be confined against `_get_ai_allowed_roots()` via `os.path.realpath` + `os.path.commonpath` (`HTTP 400` on violation).

---

## File Map

- **Modify**: `backend/models.py` — Add Section 13 Pydantic models (`PastaCrownJewelItem`, `PastaEvidenceItem`, `PastaStageItem`, `PastaAttackTreeNode`, `PastaAttackTreeEdge`, `PastaAttackTreeScenario`, `GoLiveObservationItem`, `PastaProfileUpdateRequest`, `PastaGateOverrideRequest`, `PastaAssessmentResponse`) and `pasta_assessment: Optional[PastaAssessmentResponse] = None` on `SastPlusSuiteResponse`.
- **Create**: `backend/engine/pasta_threat_engine.py` — `PastaThreatEngine` implementing Stage I–VII deterministic synthesis, business profile auto-inference, `.alastor_vault/pasta_profiles.json` atomic persistence, Stage VI Attack Tree graph generation, Stage VII Inherent/Residual/Final Go-Live risk scoring, and Go-Live Gate classification + overrides.
- **Create**: `backend/tests/test_pasta_engine.py` — TDD unit tests for `PastaThreatEngine`.
- **Modify**: `backend/requirements.txt` — Add `python-docx==1.1.2` and `reportlab==4.2.5`.
- **Create**: `backend/engine/sar_report_generator.py` — `SarReportBundle`, `generate_sar_docx_bytes`, and `generate_sar_pdf_bytes` rendering all 10 ARB/CISO Go-Live sections with strict secret redaction.
- **Modify**: `backend/engine/enterprise_manager.py` — Attach `pasta_assessment` inside `get_sast_plus_suite`.
- **Modify**: `backend/main.py` — Add `GET /api/aspm/pasta`, `POST /api/aspm/pasta/profile`, `POST /api/aspm/pasta/gate-override`, `GET /api/export/sar-report`, and enrich `GET /api/export/report`.
- **Create**: `backend/tests/test_sar_reports_and_api.py` — TDD integration tests for FastAPI PASTA & `.docx`/`.pdf` SAR endpoints.
- **Modify**: `frontend/src/types/cpg.ts` — Add TypeScript definitions matching all backend PASTA & Go-Live schemas.
- **Modify**: `frontend/src/lib/api.ts` — Add typed PASTA & SAR binary download helpers.
- **Modify**: `frontend/src/store/useAuditStore.ts` — Add `pastaAssessment` state, single-flight fetch, profile/gate update actions, and `downloadSarGoLiveReport` binary `.docx`/`.pdf` download trigger.
- **Create**: `frontend/src/components/PastaThreatWorkbench.tsx` — Interactive 7-Stage PASTA & Go-Live Workbench with ReactFlow Attack Tree canvas, Business Profile & Crown Jewel overrides, Frontier AI Attack Tree explanation, and Go-Live Gate / SLA override matrix.
- **Modify**: `frontend/src/components/ThreatModelingView.tsx` — Mount `PASTA_WORKBENCH` tab and header `.docx`/`.pdf` SAR export buttons.
- **Modify**: `frontend/src/app/page.tsx` — Hydrate `fetchPastaState`, add flagship `.docx` and `.pdf` SAR Go-Live cards to Stage 4 Export Center, and enrich HTML Audit Dossier.

---

### Task 1: PASTA Data Models & Deterministic 7-Stage `PastaThreatEngine`

**Files:**
- Modify: `backend/models.py`
- Create: `backend/engine/pasta_threat_engine.py`
- Test: `backend/tests/test_pasta_engine.py`

**Interfaces:**
- Consumes: `Finding`, `BestFixLocation`, `SbomComponentItem`, `AttackSurfaceEndpoint`, `StrideThreatItem`, `PipelineSecurityCheck`, `SastPlusSuiteResponse`, `ApiOperationsReportResponse`, `AppTreeSummary` from `backend/models.py`; `ApiOperationsEngine.analyze_workspace_api_operations` from `backend/engine/api_operations_engine.py`; `AppTreeAnalyzer.analyze_directory` from `backend/compiler/app_tree.py`.
- Produces:
  - Pydantic models in `backend/models.py`: `PastaBusinessPreset`, `GoLiveGateStatus`, `GoLiveSlaWindow`, `GoLiveVerdict`, `PastaCrownJewelItem`, `PastaEvidenceItem`, `PastaStageItem`, `PastaAttackTreeNode`, `PastaAttackTreeEdge`, `PastaAttackTreeScenario`, `GoLiveObservationItem`, `PastaProfileUpdateRequest`, `PastaGateOverrideRequest`, `PastaAssessmentResponse`, plus `SastPlusSuiteResponse.pasta_assessment`.
  - `PastaThreatEngine` in `backend/engine/pasta_threat_engine.py` with methods:
    - `evaluate_pasta(target_dir: str, findings: List[Finding], app_tree: Optional[AppTreeSummary] = None, api_ops: Optional[ApiOperationsReportResponse] = None, sbom_components: Optional[List[SbomComponentItem]] = None, endpoints: Optional[List[AttackSurfaceEndpoint]] = None, stride_threats: Optional[List[StrideThreatItem]] = None, pipeline_checks: Optional[List[PipelineSecurityCheck]] = None) -> PastaAssessmentResponse`
    - `update_profile(target_dir: str, req: PastaProfileUpdateRequest) -> Dict[str, Any]`
    - `update_gate_override(target_dir: str, req: PastaGateOverrideRequest) -> Dict[str, Any]`

- [ ] **Step 1: Write the failing unit test suite (`backend/tests/test_pasta_engine.py`)**

Create `backend/tests/test_pasta_engine.py` testing:
1. Auto-inference of `FINTECH_PAYMENTS` when payment/stripe routes & packages exist, and `ENTERPRISE_INTERNAL` on neutral codebases.
2. Deterministic generation of all 7 stages (`PASTA-1` through `PASTA-7`) on both vulnerable and clean workspaces.
3. Stage VI Attack Tree synthesis: exploitable scenario with `EXPLOITABLE_PATH` + `BFL_SHIELD` node when a reachable `CRITICAL`/`HIGH` finding exists, AND non-empty `SEVERED_BY_CONTROLS` scenario when `0` findings exist.
4. Go-Live Gate classification: `CRITICAL` / `REACHABLE HIGH` / `VERIFIED_ACTIVE` secret -> `MANDATORY_PRE_GO_LIVE` (`NO_GO_HOLD_RELEASE`); dormant `HIGH` / `MEDIUM` / `LOW` -> `POST_GO_LIVE_SLA` with non-empty `compensating_control` and `sla_window`.
5. Live profile override (`update_profile`) & Gate override (`update_gate_override`) transitioning `NO_GO_HOLD_RELEASE` -> `CONDITIONAL_GO_LIVE` and recalculating `projected_golive_risk_score <= residual_risk_score <= inherent_risk_score`.

```python
import os
import tempfile
from models import (
    BestFixLocation,
    Finding,
    PastaGateOverrideRequest,
    PastaProfileUpdateRequest,
)
from engine.pasta_threat_engine import PastaThreatEngine


def _make_sample_workspace(root: str, fintech: bool = True) -> None:
    os.makedirs(os.path.join(root, "routes"), exist_ok=True)
    route_code = (
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/api/stripe/checkout')\n"
        "def create_payment(order_id: str):\n"
        "    return {'status': 'paid', 'order_id': order_id}\n"
        if fintech
        else "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/api/health')\n"
        "def health():\n"
        "    return {'ok': True}\n"
    )
    with open(os.path.join(root, "routes", "api.py"), "w", encoding="utf-8") as fh:
        fh.write(route_code)
    with open(os.path.join(root, "requirements.txt"), "w", encoding="utf-8") as fh:
        fh.write("fastapi==0.115.0\nstripe\n" if fintech else "fastapi==0.115.0\n")


def test_pasta_seven_stages_fintech_inference_and_golive_gates():
    with tempfile.TemporaryDirectory() as tmp:
        vault = os.path.join(tmp, ".vault")
        proj = os.path.join(tmp, "fintech_app")
        _make_sample_workspace(proj, fintech=True)

        crit_finding = Finding(
            id="f-crit-sqli-1",
            rule_id="RULE-2-SQLI",
            cwe_id="CWE-89",
            severity="CRITICAL",
            title="Reachable SQL Injection in Payment Ledger",
            description="Unsanitized order_id concatenated into SQL statement.",
            remediation="Use parameterized SQL placeholders.",
            scan_engine="SAST",
            reachability_status="REACHABLE",
            path_nodes=[
                {"id": "n1", "name": "order_id", "filepath": "routes/api.py", "start_line": 4},
                {"id": "n2", "name": "db_query", "filepath": "routes/api.py", "start_line": 5},
            ],
            best_fix_location=BestFixLocation(
                node_id="n2",
                filepath="routes/api.py",
                line=5,
                column=4,
                code_snippet="cursor_exec(order_id)",
                explanation="Parameterize order_id before query execution.",
                recommended_fix="cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))",
            ),
        )
        med_finding = Finding(
            id="f-med-dormant-2",
            rule_id="IAC-2-SECURITY-HEADERS",
            cwe_id="CWE-693",
            severity="MEDIUM",
            title="Missing Strict-Transport-Security Header",
            description="Response headers omit HSTS.",
            remediation="Add Strict-Transport-Security header.",
            scan_engine="IAC",
            reachability_status="DORMANT",
            path_nodes=[{"id": "n3", "name": "headers", "filepath": "routes/api.py", "start_line": 1}],
        )

        engine = PastaThreatEngine(vault_dir=vault)
        res = engine.evaluate_pasta(proj, [crit_finding, med_finding])

        assert res.effective_business_preset == "FINTECH_PAYMENTS"
        assert any("PCI-DSS" in fw for fw in res.compliance_frameworks)
        assert len(res.stages) == 7
        assert [s.stage_code for s in res.stages] == [f"PASTA-{i}" for i in range(1, 8)]
        assert res.golive_verdict == "NO_GO_HOLD_RELEASE"
        assert res.mandatory_pre_golive_count >= 1
        assert res.post_golive_sla_count >= 1
        assert res.inherent_risk_score >= res.residual_risk_score >= res.projected_golive_risk_score

        # Attack tree has exploitable scenario + BFL shield node
        assert len(res.attack_trees) >= 1
        exp_tree = next(t for t in res.attack_trees if t.status == "EXPLOITABLE_PATH")
        assert any(n.node_role == "BFL_SHIELD" for n in exp_tree.nodes)
        assert len(exp_tree.edges) >= 3

        # Override mandatory blocker to POST_GO_LIVE_SLA with compensating control -> CONDITIONAL_GO_LIVE
        blocker_obs = next(o for o in res.golive_observations if o.gate_status == "MANDATORY_PRE_GO_LIVE")
        engine.update_gate_override(
            proj,
            PastaGateOverrideRequest(
                project_path=proj,
                observation_id=blocker_obs.id,
                gate_status="POST_GO_LIVE_SLA",
                sla_window="7_DAYS",
                compensating_control_note="Cloudflare WAF SQLi virtual patch + internal VPC ACL active.",
            ),
        )
        res_after = engine.evaluate_pasta(proj, [crit_finding, med_finding])
        updated_obs = next(o for o in res_after.golive_observations if o.id == blocker_obs.id)
        assert updated_obs.is_overridden is True
        assert updated_obs.gate_status == "POST_GO_LIVE_SLA"
        assert updated_obs.sla_window == "7_DAYS"
        assert "Cloudflare WAF" in updated_obs.compensating_control
        if res_after.mandatory_pre_golive_count == 0:
            assert res_after.golive_verdict == "CONDITIONAL_GO_LIVE"


def test_pasta_clean_workspace_produces_severed_attack_tree_and_approved_or_conditional_verdict():
    with tempfile.TemporaryDirectory() as tmp:
        vault = os.path.join(tmp, ".vault")
        proj = os.path.join(tmp, "clean_app")
        _make_sample_workspace(proj, fintech=False)

        engine = PastaThreatEngine(vault_dir=vault)
        res = engine.evaluate_pasta(proj, [])
        assert len(res.stages) == 7
        assert res.mandatory_pre_golive_count == 0
        assert res.golive_verdict in ("APPROVED_FOR_GO_LIVE", "CONDITIONAL_GO_LIVE")
        assert len(res.attack_trees) >= 1
        assert len(res.attack_trees[0].nodes) >= 3

        # Profile override persists and adjusts compliance scope
        engine.update_profile(
            proj,
            PastaProfileUpdateRequest(
                project_path=proj,
                business_preset="HEALTHCARE_PHI",
                crown_jewel_weights={"DATABASE_STORES": 2.0},
            ),
        )
        res_hc = engine.evaluate_pasta(proj, [])
        assert res_hc.selected_business_preset == "HEALTHCARE_PHI"
        assert res_hc.effective_business_preset == "HEALTHCARE_PHI"
        assert any("HIPAA" in fw for fw in res_hc.compliance_frameworks)
```

- [ ] **Step 2: Run `pytest` to verify RED failure**

Run: `..\.venv\Scripts\python.exe -m pytest tests/test_pasta_engine.py -v` (inside `backend/`)
Expected: FAIL with `ImportError` / `ModuleNotFoundError: No module named 'engine.pasta_threat_engine'`.

- [ ] **Step 3: Add PASTA & Go-Live Pydantic models in `backend/models.py` and implement `backend/engine/pasta_threat_engine.py`**

1. In `backend/models.py`:
   - Add Section 13 (`# 13. 7-Stage PASTA Threat Modeling & SAR Go-Live Gate Models`) BEFORE `SastPlusSuiteResponse` (or use `Optional[PastaAssessmentResponse] = None` with `SastPlusSuiteResponse.model_rebuild()` at end of file) defining exact fields from Spec Section 4.1.
2. Create `backend/engine/pasta_threat_engine.py`:
   - Implement `PastaThreatEngine` with thread-safe `RLock`, `.alastor_vault/pasta_profiles.json` atomic persistence (`tempfile.NamedTemporaryFile` + `os.replace`), Stage I auto-inference (`FINTECH_PAYMENTS`, `HEALTHCARE_PHI`, `AI_SAAS_PUBLIC`, `ENTERPRISE_INTERNAL`), 5 Crown Jewel categories (`DATABASE_STORES`, `SECRETS_AND_CREDENTIALS`, `AI_AND_EXTERNAL_APIS`, `HOST_RUNTIME_AND_OS`, `AUTH_AND_SESSION_BOUNDARY`), Stage I–VII `PastaStageItem` synthesis, MITRE ATT&CK / CAPEC + STRIDE cross-reference table, Stage VI `PastaAttackTreeScenario` builder (both `EXPLOITABLE_PATH` for findings/exposed mutating routes and `SEVERED_BY_CONTROLS` baseline defense tree when clean), Stage VII Inherent / Residual / Final Projected Go-Live risk scoring, deterministic Go-Live Gate classification, reviewer override application, and `"Make It Live"` ordered checklist generation.

- [ ] **Step 4: Run `pytest` to verify GREEN pass**

Run: `..\.venv\Scripts\python.exe -m pytest tests/test_pasta_engine.py -v`
Expected: `2 passed`.

- [ ] **Step 5: Commit Task 1**

```powershell
git add backend/models.py backend/engine/pasta_threat_engine.py backend/tests/test_pasta_engine.py
git commit -m "feat(pasta): add 7-stage PASTA threat modeling engine, attack trees, and Go-Live gate policy"
```

---

### Task 2: Native Word (`.docx`) & PDF (`.pdf`) SAR Go-Live Report Engine + FastAPI Endpoints

**Files:**
- Modify: `backend/requirements.txt`
- Create: `backend/engine/sar_report_generator.py`
- Modify: `backend/engine/enterprise_manager.py`
- Modify: `backend/main.py`
- Test: `backend/tests/test_sar_reports_and_api.py`

**Interfaces:**
- Consumes: `PastaAssessmentResponse`, `PastaProfileUpdateRequest`, `PastaGateOverrideRequest`, `SastPlusSuiteResponse`, `RaciGovernanceResponse`, `MetricsResponse`, `Finding` from `backend/models.py`; `PastaThreatEngine` from `backend/engine/pasta_threat_engine.py`.
- Produces:
  - `SarReportBundle` + `generate_sar_docx_bytes(bundle: SarReportBundle) -> bytes` + `generate_sar_pdf_bytes(bundle: SarReportBundle) -> bytes` + `build_sar_json_dict(bundle: SarReportBundle) -> Dict[str, Any]` in `backend/engine/sar_report_generator.py`.
  - FastAPI endpoints in `backend/main.py`:
    - `GET /api/aspm/pasta?project_path=...` -> `PastaAssessmentResponse`
    - `POST /api/aspm/pasta/profile` -> `PastaAssessmentResponse`
    - `POST /api/aspm/pasta/gate-override` -> `PastaAssessmentResponse`
    - `GET /api/export/sar-report?format=docx|pdf|json&project_path=...` -> `Response` (`docx` / `pdf` binary attachment or `JSONResponse`)
    - Enriched `GET /api/aspm/suite` (`pasta_assessment` populated) and `GET /api/export/report` (PASTA & Go-Live summary in Markdown/JSON).

- [ ] **Step 1: Install `python-docx` and `reportlab` into `.venv` and update `backend/requirements.txt`**

Add `python-docx==1.1.2` and `reportlab==4.2.5` to `backend/requirements.txt` and install via `..\.venv\Scripts\python.exe -m pip install python-docx==1.1.2 reportlab==4.2.5`.

- [ ] **Step 2: Write the failing API & binary report tests (`backend/tests/test_sar_reports_and_api.py`)**

```python
import io
from docx import Document
from fastapi.testclient import TestClient
import main as backend_main
from models import Finding, BestFixLocation


def test_pasta_api_endpoints_and_path_confinement():
    client = TestClient(backend_main.app)

    # Path confinement blocks outside paths
    bad_res = client.get("/api/aspm/pasta", params={"project_path": "C:\\Windows\\System32"})
    assert bad_res.status_code == 400

    # Valid default workspace PASTA retrieval
    ok_res = client.get("/api/aspm/pasta")
    assert ok_res.status_code == 200
    body = ok_res.json()
    assert len(body["stages"]) == 7
    assert body["golive_verdict"] in (
        "APPROVED_FOR_GO_LIVE",
        "CONDITIONAL_GO_LIVE",
        "NO_GO_HOLD_RELEASE",
    )
    assert len(body["attack_trees"]) >= 1

    # Business profile update + reset roundtrip
    prof_res = client.post(
        "/api/aspm/pasta/profile",
        json={"business_preset": "FINTECH_PAYMENTS", "crown_jewel_weights": {"DATABASE_STORES": 1.8}},
    )
    assert prof_res.status_code == 200
    assert prof_res.json()["effective_business_preset"] == "FINTECH_PAYMENTS"

    rst_res = client.post("/api/aspm/pasta/profile", json={"reset_defaults": True})
    assert rst_res.status_code == 200
    assert rst_res.json()["selected_business_preset"] == "AUTO_INFERRED"


def test_sar_docx_and_pdf_report_generation_and_secret_redaction(monkeypatch):
    raw_canary_secret = "ghp_SUPERSECRETRAWVALUE9999999999999999"
    mock_secret_finding = Finding(
        id="sec-test-live-1",
        rule_id="RULE-8-HARDCODED-SECRET",
        cwe_id="CWE-798",
        severity="CRITICAL",
        title="Verified Active GitHub Token in Config",
        description="Hardcoded GitHub PAT detected in configuration.",
        remediation="Revoke token immediately and move to environment secret vault.",
        scan_engine="SAST",
        reachability_status="REACHABLE",
        is_secret_finding=True,
        secret_key_name="GITHUB_TOKEN",
        secret_value_raw=raw_canary_secret,
        secret_value_masked="ghp_SU****9999",
        secret_validation_status="VERIFIED_ACTIVE",
        secret_verified_identity="GitHub @corp-bot (repo)",
        path_nodes=[{"id": "s1", "name": "GITHUB_TOKEN", "filepath": "config.py", "start_line": 12}],
        best_fix_location=BestFixLocation(
            node_id="s1",
            filepath="config.py",
            line=12,
            column=1,
            code_snippet="GITHUB_TOKEN = 'ghp_SU****9999'",
            explanation="Move credential to runtime secret manager.",
            recommended_fix="GITHUB_TOKEN = os.environ['GITHUB_TOKEN']",
        ),
    )
    monkeypatch.setattr(backend_main, "get_or_compute_findings", lambda force_refresh=False: [mock_secret_finding])

    client = TestClient(backend_main.app)

    # 1. Word (.docx) binary verification
    docx_res = client.get("/api/export/sar-report", params={"format": "docx"})
    assert docx_res.status_code == 200
    assert "wordprocessingml.document" in docx_res.headers["content-type"]
    assert docx_res.content[:4] == b"PK\x03\x04"
    assert raw_canary_secret.encode("utf-8") not in docx_res.content

    doc = Document(io.BytesIO(docx_res.content))
    full_text = "\n".join(p.text for p in doc.paragraphs) + "\n" + "\n".join(
        cell.text for tbl in doc.tables for row in tbl.rows for cell in row.cells
    )
    assert raw_canary_secret not in full_text
    assert "PASTA" in full_text
    assert "STRIDE" in full_text
    assert "MANDATORY PRE-GO-LIVE" in full_text.upper()
    assert "POST-GO-LIVE" in full_text.upper()
    assert "MAKE IT LIVE" in full_text.upper() or "GO-LIVE RUNBOOK" in full_text.upper()

    # 2. PDF (.pdf) binary verification
    pdf_res = client.get("/api/export/sar-report", params={"format": "pdf"})
    assert pdf_res.status_code == 200
    assert "application/pdf" in pdf_res.headers["content-type"]
    assert pdf_res.content[:5] == b"%PDF-"
    assert len(pdf_res.content) > 2500
    assert raw_canary_secret.encode("utf-8") not in pdf_res.content

    # 3. JSON SAR verification
    json_res = client.get("/api/export/sar-report", params={"format": "json"})
    assert json_res.status_code == 200
    assert raw_canary_secret not in json_res.text
```

- [ ] **Step 3: Run `pytest` to verify RED failure**

Run: `..\.venv\Scripts\python.exe -m pytest tests/test_sar_reports_and_api.py -v`
Expected: FAIL (`404 Not Found` on `/api/aspm/pasta` & `/api/export/sar-report` / missing `sar_report_generator`).

- [ ] **Step 4: Implement `backend/engine/sar_report_generator.py`, wire `enterprise_manager.py`, and add FastAPI routes in `backend/main.py`**

1. Create `backend/engine/sar_report_generator.py`:
   - Sanitize/redact all findings (`secret_value_raw = None`, mask any residual raw token occurrences in snippets/descriptions) before building report sections.
   - Implement all 10 sections from Spec Section 3.2 in both `generate_sar_docx_bytes` (`python-docx` with styled cover callout, KPI scorecard table, executive decision narrative, PASTA I–III architecture decomposition, STRIDE 6-row matrix, PASTA 7-stage & Attack Tree tables, Section 6 Mandatory Pre-Go-Live Blockers table & BFL fix cards, Section 7 Post-Go-Live SLA & Compensating Controls table, Section 8 Step-by-Step "Make It Live" Runbook, Section 9 Passing Controls assurance register, Section 10 RACI, Waiver Log & ARB/CISO Sign-Off table) and `generate_sar_pdf_bytes` (`reportlab.platypus` A4 corporate stylesheet with `Paragraph`-wrapped cells so wide code/paths never overflow, repeating header rows, color-coded badges, and page numbering footer).
2. In `backend/engine/enterprise_manager.py`:
   - Instantiate `self.pasta_engine = PastaThreatEngine(vault_dir=...)` in `EnterpriseManager.__init__` and populate `pasta_assessment=...` inside `get_sast_plus_suite`.
3. In `backend/main.py`:
   - Add confined `_resolve_confined_project_dir(project_path)` helper reusing `_get_ai_allowed_roots()`.
   - Add `GET /api/aspm/pasta`, `POST /api/aspm/pasta/profile`, `POST /api/aspm/pasta/gate-override`, and `GET /api/export/sar-report`.
   - Enrich `GET /api/export/report` (`json` and `markdown`) with `pasta_summary` / `## PASTA 7-Stage & Go-Live Readiness Summary`.

- [ ] **Step 5: Run `pytest` to verify GREEN pass**

Run: `..\.venv\Scripts\python.exe -m pytest tests/test_pasta_engine.py tests/test_sar_reports_and_api.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit Task 2**

```powershell
git add backend/requirements.txt backend/engine/sar_report_generator.py backend/engine/enterprise_manager.py backend/main.py backend/tests/test_sar_reports_and_api.py
git commit -m "feat(sar-report): add Word (.docx) and PDF (.pdf) Go-Live architecture report generator and PASTA APIs"
```

---

### Task 3: Frontend PASTA & Go-Live Types, Store & Interactive `PastaThreatWorkbench.tsx`

**Files:**
- Modify: `frontend/src/types/cpg.ts`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/store/useAuditStore.ts`
- Create: `frontend/src/components/PastaThreatWorkbench.tsx`

**Interfaces:**
- Consumes: Backend `/api/aspm/pasta`, `/api/aspm/pasta/profile`, `/api/aspm/pasta/gate-override`, `/api/export/sar-report`, and existing `explainGraphAi`, `openCodeLocationInIde`, `projectPath` from `useAuditStore`.
- Produces:
  - TypeScript interfaces in `frontend/src/types/cpg.ts`: `PastaBusinessPreset`, `GoLiveGateStatus`, `GoLiveSlaWindow`, `GoLiveVerdict`, `PastaCrownJewelItem`, `PastaEvidenceItem`, `PastaStageItem`, `PastaAttackTreeNode`, `PastaAttackTreeEdge`, `PastaAttackTreeScenario`, `GoLiveObservationItem`, `PastaProfileUpdatePayload`, `PastaGateOverridePayload`, `PastaAssessmentResponse`, plus `SastPlusSuiteResponse.pasta_assessment?: PastaAssessmentResponse | null`.
  - API functions in `frontend/src/lib/api.ts`: `fetchPastaAssessment(projectPath?)`, `updatePastaProfile(payload)`, `overridePastaGate(payload)`, `downloadSarReportBlob(format: "docx" | "pdf", projectPath?)`.
  - Store fields & actions in `frontend/src/store/useAuditStore.ts`: `pastaAssessment`, `isLoadingPasta`, `isSavingPasta`, `exportingSarFormat`, `fetchPastaState`, `savePastaProfileState`, `savePastaGateOverride`, `downloadSarGoLiveReport`.
  - React component `<PastaThreatWorkbench />` in `frontend/src/components/PastaThreatWorkbench.tsx`.

- [ ] **Step 1: Add TypeScript types (`cpg.ts`), API helpers (`api.ts`), and Zustand actions (`useAuditStore.ts`)**

1. Mirror all Section 13 PASTA & Go-Live types in `frontend/src/types/cpg.ts`.
2. Add `fetchPastaAssessment`, `updatePastaProfile`, `overridePastaGate`, and `downloadSarReportBlob` (extracting sanitized filename from `Content-Disposition` or defaulting to `ALASTOR_SAR_GoLive_Report.${format}`) in `frontend/src/lib/api.ts`.
3. Add single-flight `fetchPastaState` (`_pastaInFlight`), `savePastaProfileState`, `savePastaGateOverride`, and `downloadSarGoLiveReport` in `frontend/src/store/useAuditStore.ts`, syncing `pastaAssessment` automatically when `fetchSastPlusSuite` returns `data.pasta_assessment` and refreshing after `triggerScan` / `activateProject`.

- [ ] **Step 2: Create `frontend/src/components/PastaThreatWorkbench.tsx` (Light-Only Daylight Theme)**

Implement `PastaThreatWorkbench.tsx` with:
1. **Executive Go-Live Verdict & 3-Stage Risk Header**:
   - Displays `APPROVED FOR GO-LIVE` (`bg-emerald-50 border-emerald-400 text-emerald-950`), `CONDITIONAL GO-LIVE` (`bg-amber-50 border-amber-400 text-amber-950`), or `NO-GO • HOLD RELEASE` (`bg-rose-50 border-rose-400 text-rose-950`) with executive plain-English rationale.
   - Displays 3 side-by-side scorecards: **1. Inherent Risk (`0–100`)**, **2. Current Residual Risk (`0–100`)**, and **3. Final Projected Go-Live Risk (`0–100`)**, plus Mandatory Pre-Go-Live vs Post-Go-Live SLA vs Waived counts.
   - Includes **Download SAR Word (`.docx`)** and **Download SAR PDF (`.pdf`)** buttons with loading spinners.
2. **PASTA Stage I Business Profile & Crown Jewel Weight Bar**:
   - Preset pills (`AUTO_INFERRED`, `FINTECH_PAYMENTS`, `HEALTHCARE_PHI`, `AI_SAAS_PUBLIC`, `ENTERPRISE_INTERNAL`), compliance framework badges (`PCI-DSS`, `HIPAA`, `SOC2`, `OWASP ASVS/LLM`), expandable Crown Jewel criticality sliders (`0.8x–2.0x` with `"Apply Weights"` + `"Reset Auto"`).
3. **Interactive 7-Stage PASTA Pipeline Stepper (`Stage I` -> `Stage VII`)**:
   - 7 responsive cards (`I. Objectives`, `II. Tech Scope`, `III. Decomposition`, `IV. Threat Analysis`, `V. Weaknesses`, `VI. Attack Trees`, `VII. Risk & Go-Live`) with `PASS / MONITORED / ACTION_REQUIRED` badges and `✔ OK / ✖ Gap` counters; selecting a stage highlights its dossier below.
4. **Stage VI Interactive ReactFlow Attack Tree Simulation Canvas**:
   - Wrapped in `<ReactFlowProvider>`, Dagre `LR` layout (`width: 268`, `height: 102`, `nodesep: 42`, `ranksep: 86`) with multi-stage `fitView`, custom Daylight card rendering by `node_role` (`GOAL`, `ENTRYPOINT`, `CAPEC_VECTOR`, `PROPAGATION`, `VULN_SINK`, `BFL_SHIELD`, `CROWN_JEWEL`), scenario selector pills, `"✨ AI Explain Attack Tree"` button (`explainGraphAi({ view_mode: "PASTA_ATTACK_TREE", nodes_digest, edges_digest })`), and `"Inspect in IDE"` click jump.
5. **Stage VII Go-Live Gate & Post-Go-Live Triage Matrix + "Make It Live" Runbook**:
   - Filter pills: `ALL`, `MANDATORY_PRE_GO_LIVE`, `POST_GO_LIVE_SLA`, `RISK_ACCEPTED_WAIVER`, and `MAKE_IT_LIVE_RUNBOOK`.
   - Inline reviewer controls per observation: Gate dropdown (`Mandatory Pre-Go-Live Blocker`, `Post-Go-Live Allowed (SLA)`, `Risk-Accepted Waiver`), SLA dropdown (`PRE_LAUNCH`, `7_DAYS`, `14_DAYS`, `30_DAYS`, `90_DAYS`, `WAIVED`), compensating-control / waiver note input + `Save Gate` / `Reset Default` buttons, and `Inspect Code` button.
6. **Selected PASTA Stage Evidence Dossier (`Stage I..VII`)**:
   - Shows `what_passed`, `what_failed`, STRIDE cross-walk badges (`STRIDE: S/T/R/I/D/E`), MITRE CAPEC tags, and evidence items with `Inspect in IDE` jump.

- [ ] **Step 3: Run TypeScript typecheck (`npx tsc --noEmit`)**

Run: `npx tsc --noEmit` (inside `frontend/`)
Expected: Exit code `0` (`0` TypeScript errors).

- [ ] **Step 4: Commit Task 3**

```powershell
git add frontend/src/types/cpg.ts frontend/src/lib/api.ts frontend/src/store/useAuditStore.ts frontend/src/components/PastaThreatWorkbench.tsx
git commit -m "feat(ui): add interactive 7-stage PASTA workbench, ReactFlow attack tree canvas, and Go-Live gate controls"
```

---

### Task 4: Wire `ThreatModelingView.tsx` & Stage 4 Export Center (`page.tsx`) + Full Verification

**Files:**
- Modify: `frontend/src/components/ThreatModelingView.tsx`
- Modify: `frontend/src/app/page.tsx`

**Interfaces:**
- Consumes: `<PastaThreatWorkbench />`, `useAuditStore` (`pastaAssessment`, `fetchPastaState`, `downloadSarGoLiveReport`, `exportingSarFormat`).
- Produces: Complete end-to-end UI integration in Stage 3 Threat Modeling and Stage 4 Enterprise Export Center, verified across backend `pytest`, frontend `tsc --noEmit`, ALASTOR self-audit (`0` findings), and live `:8000` + `:3000` servers.

- [ ] **Step 1: Integrate PASTA Workbench & `.docx`/`.pdf` SAR Export buttons into `ThreatModelingView.tsx` and `page.tsx`**

1. In `frontend/src/components/ThreatModelingView.tsx`:
   - Extend `activeSubTab` union with `"PASTA_WORKBENCH"`.
   - Add **`7-Stage PASTA & Go-Live`** tab button (`indigo-700` active styling) right beside `STRIDE_BOARD`, plus compact **`SAR Word (.docx)`** and **`SAR PDF (.pdf)`** download buttons on the right side of the Threat Modeling sub-navigation bar so operators can download the Go-Live report from any Threat Modeling tab.
   - Render `{activeSubTab === "PASTA_WORKBENCH" && <PastaThreatWorkbench />}`.
2. In `frontend/src/app/page.tsx`:
   - Call `void fetchPastaState()` in the mount `useEffect`.
   - Add two flagship cards at the top of `aspmSubSection === "EXPORTS"`:
     - **Threat Modeling & Go-Live SAR Report (`.docx` Word)** (`ARB & CISO • MICROSOFT WORD`)
     - **Threat Modeling & Go-Live SAR Report (`.pdf` PDF)** (`EXECUTIVE SIGN-OFF • ADOBE PDF`)
     explaining that they include STRIDE, 7-Stage PASTA, Attack Trees, Mandatory Pre-Go-Live Blockers, Post-Go-Live SLA & Compensating Controls, Final Go-Live Risk Level, and the "Make It Live" Runbook.
   - Include PASTA Go-Live Verdict & Final Risk Level in `handleDownloadHtmlDossier()` KPIs as well.

- [ ] **Step 2: Run full backend test suite, TypeScript typecheck, and ALASTOR self-audit**

1. Backend tests: `..\.venv\Scripts\python.exe -m pytest -v` (inside `backend/`) -> Expected: `100%` pass.
2. Frontend typecheck: `npx tsc --noEmit` (inside `frontend/`) -> Expected: `0` errors.
3. ALASTOR self-audit on `c:\Projects\Securecodereview\cpg-sast-platform`: verify `0` findings across SAST, SCA, IaC, and Secret Validator.

- [ ] **Step 3: Restart live FastAPI `:8000` daemon and smoke-test live endpoints (`:8000` & `:3000`)**

1. Restart the live uvicorn background daemon so the running app serves the new PASTA & `.docx`/`.pdf` SAR endpoints immediately.
2. Verify HTTP `200` on:
   - `GET http://127.0.0.1:8000/api/aspm/pasta` (`7` stages, `attack_trees`, `golive_verdict`)
   - `GET http://127.0.0.1:8000/api/export/sar-report?format=docx` (`PK\x03\x04` header)
   - `GET http://127.0.0.1:8000/api/export/sar-report?format=pdf` (`%PDF-` header)
   - `GET http://localhost:3000` (`200 OK`)

- [ ] **Step 4: Commit Task 4**

```powershell
git add frontend/src/components/ThreatModelingView.tsx frontend/src/app/page.tsx
git commit -m "feat(exports): wire PASTA workbench in Threat Modeling and SAR Word/PDF Go-Live reports in Export Center"
```
