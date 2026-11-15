# ALASTOR Design Specification — 7-Stage PASTA Threat Modeling, Interactive Attack Trees & Security Architecture Go-Live Report (Word `.docx` & PDF `.pdf`)

**Date:** 2026-11-15  
**Status:** Approved in Brainstorming — Ready for User Spec Review  
**Target Codebase:** `cpg-sast-platform` (`backend/` FastAPI + Neo4j CPG Engine, `frontend/` Next.js + ReactFlow + Monaco + Zustand)

---

## 1. Executive Summary & Goals

This upgrade extends ALASTOR's Threat Modeling and ASPM Export capabilities with two tightly unified capabilities while preserving **100% of existing v4.0 functionality**, enforcing the **Light-Only Daylight UI (`>= 4.5:1` WCAG AA contrast)**, and maintaining **zero self-audit findings** on `cpg-sast-platform`:

1. **7-Stage PASTA (Process for Attack Simulation and Threat Analysis) Workbench & Interactive Attack Tree Canvas (`backend/engine/pasta_threat_engine.py` + `frontend/src/components/PastaThreatWorkbench.tsx`)**:
   - Synthesizes deterministic, code-anchored evidence across all **7 PASTA Stages** (`Stage I: Define Objectives` through `Stage VII: Risk & Impact Analysis`) from ALASTOR's Application Tree, CycloneDX SBOM, PBOM checks, Multi-Framework API Operations Tracer, STRIDE findings, TruffleHog Secret Validator, and Neo4j CPG reachability paths.
   - Auto-infers **Business Criticality & Regulatory Scope** (`FINTECH_PAYMENTS`, `HEALTHCARE_PHI`, `AI_SAAS_PUBLIC`, `ENTERPRISE_INTERNAL`) and **Crown Jewel** weights from live codebase signals while supporting **live per-project profile and crown-jewel weight overrides** persisted in `.alastor_vault/pasta_profiles.json`.
   - Renders an interactive **Stage VI ReactFlow Attack Tree Simulation Canvas** (`Attacker Goal <- MITRE CAPEC Vector <- Exposed Entrypoint / Leaked Key -> Propagation Hop -> Vulnerable Sink -> Crown Jewel Impact`, plus green `BFL / Sanitizer Shield` chokepoint nodes), wired to **Frontier AI Explain** and 1-click **Inspect in IDE** navigation.
2. **Threat Modeling & Security Architecture Review (SAR) Go-Live Dossier Generator — Native Word (`.docx`) & PDF (`.pdf`) (`backend/engine/sar_report_generator.py`)**:
   - Classifies every observation across CPG SAST, SCA/SBOM, IaC/PBOM, TruffleHog Secret Vault, Unauthenticated API Operations, STRIDE, and PASTA into **Mandatory Pre-Go-Live Release Blockers (`MANDATORY_PRE_GO_LIVE`)**, **Post-Go-Live Deferrable Observations with Binding SLA & Temporary Compensating Controls (`POST_GO_LIVE_SLA`)**, or **Reviewer Risk-Accepted Waivers (`RISK_ACCEPTED_WAIVER`)**.
   - Allows security reviewers to **override any observation's Go-Live Gate**, adjust its post-launch SLA window (`PRE_LAUNCH`, `7_DAYS`, `14_DAYS`, `30_DAYS`, `90_DAYS`), and record a custom compensating-control or waiver justification persisted per project.
   - Computes three explicit risk scores (**Inherent Risk**, **Current Residual Risk**, and **Final Projected Go-Live Risk Level**) plus an executive **Go-Live Readiness Verdict (`APPROVED_FOR_GO_LIVE` | `CONDITIONAL_GO_LIVE` | `NO_GO_HOLD_RELEASE`)**.
   - Generates downloadable, publication-grade **Microsoft Word (`.docx`)** and **Adobe PDF (`.pdf`)** binary reports in pure Python (`python-docx` + `reportlab`, zero external OS binaries) covering all 10 enterprise Architecture Review Board (ARB) & CISO sign-off sections.

---

## 2. Pillar 1 — Deterministic 7-Stage PASTA Engine & Attack Tree Synthesis

### 2.1 Module Boundary & Persistence (`backend/engine/pasta_threat_engine.py`)

`PastaThreatEngine` is a standalone, thread-safe service that avoids bloating `enterprise_manager.py`. It accepts cached workspace inputs (`target_dir`, `findings`, `app_tree`, `api_ops_report`, `sast_plus_suite`) and reads/writes per-project overrides in `.alastor_vault/pasta_profiles.json` (`0o600` file permissions, atomic write via temp file + `os.replace`, protected by `threading.RLock()`).

#### Persisted Per-Project State Keyed by Normalized `project_path`

```json
{
  "c:/projects/target-app": {
    "business_preset": "AUTO_INFERRED",
    "crown_jewel_weights": {
      "DATABASE_STORES": 1.5,
      "SECRETS_AND_CREDENTIALS": 2.0,
      "AI_AND_EXTERNAL_APIS": 1.2,
      "HOST_RUNTIME_AND_OS": 1.8,
      "AUTH_AND_SESSION_BOUNDARY": 1.5
    },
    "gate_overrides": {
      "obs-rule-1-sqli-app.py-42": {
        "gate_status": "POST_GO_LIVE_SLA",
        "sla_window": "7_DAYS",
        "compensating_control_note": "Protected behind internal VPN ACL and Cloudflare WAF SQLi ruleet until Sprint 14 patch.",
        "updated_by": "Security Architect",
        "updated_at": "2026-11-15T15:20:00Z"
      }
    }
  }
}
```

### 2.2 Business Profile Auto-Inference & Presets (PASTA Stage I)

When `business_preset == "AUTO_INFERRED"`, `PastaThreatEngine` inspects route paths, model/file names, SBOM packages, and API operation categories:

| Preset ID | Auto-Detection Signals | Base Criticality Multiplier | Mapped Regulatory & Industry Frameworks |
|---|---|---|---|
| `FINTECH_PAYMENTS` | Routes/symbols/packages matching `stripe`, `payment`, `billing`, `invoice`, `ledger`, `wallet`, `checkout`, `bank`, `card` | `1.35x` | `PCI-DSS v4.0`, `SOX`, `SOC 2 Type II`, `OWASP ASVS L2` |
| `HEALTHCARE_PHI` | Signals matching `patient`, `fhir`, `hl7`, `hipaa`, `clinical`, `medical`, `diagnosis`, `prescription`, `ehr` | `1.35x` | `HIPAA Security Rule`, `HITECH`, `SOC 2 Type II`, `OWASP ASVS L2` |
| `AI_SAAS_PUBLIC` | `EXTERNAL_HTTP_OR_AI` operations, `openai`, `anthropic`, `gemini`, `langchain`, `llm`, `prompt`, `vector`, or `>= 1` public HTTP endpoints with AI SDKs | `1.20x` | `OWASP Top 10 for LLM`, `SOC 2 Type II`, `ISO/IEC 27001`, `OWASP API Top 10` |
| `ENTERPRISE_INTERNAL` | Default enterprise web/service baseline when none of the specialized domain signals dominate | `1.00x` | `SOC 2 Type II`, `ISO/IEC 27001`, `OWASP ASVS L1/L2` |

Operators can switch `business_preset` between `AUTO_INFERRED`, `FINTECH_PAYMENTS`, `HEALTHCARE_PHI`, `AI_SAAS_PUBLIC`, and `ENTERPRISE_INTERNAL`, or customize individual Crown Jewel weights (`0.8` to `2.0`). Resetting restores `AUTO_INFERRED` and default weights.

### 2.3 Evidence Synthesis Across All 7 PASTA Stages

Every stage produces a `PastaStageItem` containing:
- `stage_number` (`1..7`), `stage_code` (`PASTA-1..PASTA-7`), `stage_roman` (`I..VII`), `title`, `methodology_goal`
- `status`: `"PASS" | "MONITORED" | "ACTION_REQUIRED"`
- `ok_count`, `gap_count`, `summary`, `what_passed: List[str]`, `what_failed: List[str]`
- `evidence_items: List[PastaEvidenceItem]` (each with `id`, `verdict: "OK" | "GAP"`, `severity`, `title`, `detail`, `filepath`, `line`, `cwe_or_capec`, `stride_cross_ref`, `linked_finding_id`)

| Stage | PASTA Phase | Deterministic Evidence Synthesized in ALASTOR |
|---|---|---|
| **I** | **Define Objectives (`DO`)** | Effective Business Profile (auto-inferred reason or manual override), mapped regulatory obligations, SLA governance policy, and detected **Crown Jewels** (`DATABASE_STORES`, `SECRETS_AND_CREDENTIALS`, `AI_AND_EXTERNAL_APIS`, `HOST_RUNTIME_AND_OS`, `AUTH_AND_SESSION_BOUNDARY`) with asset counts and criticality multipliers. |
| **II** | **Define Technical Scope (`DTS`)** | Detected languages & frameworks (`AppTreeSummary.detected_tech_stack`), total scanned source/config files, CycloneDX SBOM dependency inventory (`pinned` vs `floating/unpinned`), and container/CI/CD `PBOM` boundary posture (`Dockerfile`, `docker-compose`, GitHub Actions/GitLab CI). |
| **III** | **Application Decomposition (`AD`)** | 4-Zone Trust Boundary breakdown, discovered HTTP/REST/CLI entrypoints (`PUBLIC / UNVERIFIED` vs `AUTH_GUARDED`), and inter-procedural CPG API operations (`DATABASE_READ`, `DATABASE_WRITE`, `EXTERNAL_HTTP_OR_AI`, `OS_COMMAND_EXEC`, `FILESYSTEM_IO`, `SECRET_OR_CRYPTO`). |
| **IV** | **Threat Analysis (`TA`)** | Active threat actor profiles (`External Opportunistic Attacker`, `Credential Harvester`, `Malicious Insider / Authenticated Abuser`, `Supply-Chain Adversary`), **MITRE ATT&CK & CAPEC** attack pattern correlation (`CAPEC-88 / T1190` OS Command Injection, `CAPEC-66 / T1190` SQL/Cypher Injection, `CAPEC-63 / T1189` XSS, `CAPEC-126 / T1083` Path Traversal, `CAPEC-194 / T1567` SSRF & AI Exfiltration, `CAPEC-560 / T1552` Unsecured Credentials, `CAPEC-438 / T1195` Supply Chain), and explicit **STRIDE (`S/T/R/I/D/E`)** cross-links. |
| **V** | **Weakness & Vulnerability Analysis (`WVA`)** | Full correlation of deterministic CPG SAST, SCA, IaC, and TruffleHog Secret Vault findings (`VERIFIED_ACTIVE`, `GIT_HISTORY`, `OFFLINE_STRUCTURALLY_VALID`), CWE mapping, Neo4j CPG reachability (`REACHABLE` from entrypoint vs `DORMANT`), EPSS exploit probability, and Best Fix Location (`BFL`) chokepoints. |
| **VI** | **Attack Modeling & Simulation (`AMS`)** | Synthesizes concrete multi-hop **Attack Trees** (`PastaAttackTreeScenario` + `nodes` + `edges`) connecting: `Ingress Entrypoint / Leaked Credential` -> `MITRE CAPEC Technique` -> `Handler / Propagation Hop` -> `CWE Vulnerable Sink` -> `Crown Jewel Breach Goal`, paired with `BFL / Sanitizer Shield` nodes showing exact code locations that sever the attack chain. When `0` active vulnerabilities exist, synthesizes **Hardened / Severed Attack Trees** from discovered entrypoints and verified sanitizers/auth guards so the simulation canvas always displays real architectural defense paths. |
| **VII** | **Risk & Impact Analysis (`RIA`)** | Computes **Inherent Risk (`0–100`)**, **Current Residual Risk (`0–100`)**, **Final Projected Go-Live Risk (`0–100`)**, Go-Live Readiness Verdict, Countermeasure Simulation rankings (`projected_risk_reduction` points per BFL fix), and the unified **Go-Live Gate Observation Register**. |

### 2.4 Quantitative Risk Formula & Go-Live Gate Classification (PASTA Stage VII)

1. **Inherent Risk Score (`0–100`)**:
   - Base exposure from attack surface (`min(28, public_endpoints * 2.5 + auth_endpoints * 1.0 + mutating_or_exec_ops * 1.8)`) + raw defect weight (`CRITICAL = 22`, `HIGH = 13`, `MEDIUM = 6`, `LOW = 2`, multiplied by `1.35x` when `REACHABLE` and `1.50x` when `secret_validation_status == "VERIFIED_ACTIVE"`), scaled by Stage I `business_preset` multiplier and normalized Crown Jewel factor, clamped to `[5, 100]`.
2. **Control Mitigation Credit (`0–40` pts deducted for Current Residual Risk)**:
   - Deductions awarded for verified architectural controls: ratio of `AUTH_GUARDED` endpoints (`up to 12 pts`), pinned CycloneDX SBOM dependencies (`up to 8 pts`), passing PBOM pipeline checks (`up to 8 pts`), and verified sanitizers / severed STRIDE domains (`up to 12 pts`), subject to a floor rule: **while `>= 1` unresolved `MANDATORY_PRE_GO_LIVE` blocker exists, `Current Residual Risk` cannot drop below `65` (`HIGH` / `CRITICAL`)**.
3. **Final Projected Go-Live Risk Score (`0–100`)**:
   - Recomputes Residual Risk after removing all `MANDATORY_PRE_GO_LIVE` observations (simulating completion of mandatory pre-launch fixes), retaining only `POST_GO_LIVE_SLA` (discounted by `45%` for active launch compensating controls) and `RISK_ACCEPTED_WAIVER` residual exposure.
   - Risk Level Bands:
     - `75–100`: `CRITICAL`
     - `50–74`: `HIGH`
     - `25–49`: `MODERATE`
     - `0–24`: `LOW`
4. **Deterministic Default Go-Live Gate Policy**:
   - **`MANDATORY_PRE_GO_LIVE` (`PRE_LAUNCH` — Release Blocker)**:
     - Any finding with `severity == "CRITICAL"`
     - Any secret finding with `secret_validation_status == "VERIFIED_ACTIVE"`
     - Any finding with `severity == "HIGH"` and `reachability_status == "REACHABLE"` (or `is_secret_finding == True` in working tree excluding `REVOKED_OR_INVALID` / `TEST_OR_PLACEHOLDER`)
     - Any `PUBLIC / UNVERIFIED` HTTP endpoint executing `OS_COMMAND_EXEC` or destructive `DATABASE_WRITE` with linked findings
     - Any `PBOM` check with `status == "FAIL"`
   - **`POST_GO_LIVE_SLA` (Deferrable Post-Launch with SLA & Compensating Control)**:
     - `HIGH` severity with `reachability_status != "REACHABLE"` (dormant/internal) -> Default SLA `7_DAYS`
     - `GIT_HISTORY` secrets that are `REVOKED_OR_INVALID` or `OFFLINE_STRUCTURALLY_VALID` -> Default SLA `14_DAYS` (git history scrub + rotation audit)
     - `MEDIUM` findings or unauthenticated high-exposure routes without active CPG sink exploit -> Default SLA `30_DAYS`
     - `LOW` / `INFO` findings, `TEST_OR_PLACEHOLDER` secrets, floating SBOM versions, and `PBOM` `WARNING` checks -> Default SLA `90_DAYS`
   - **`RISK_ACCEPTED_WAIVER`**:
     - Assigned only when explicitly overridden by an operator via `POST /api/aspm/pasta/gate-override` (or when `finding.triage_status == "NOT_EXPLOITABLE"`).
5. **Overall Go-Live Verdict**:
   - `NO_GO_HOLD_RELEASE`: `mandatory_pre_golive_count > 0`
   - `CONDITIONAL_GO_LIVE`: `mandatory_pre_golive_count == 0` and `(post_golive_sla_count > 0 or waived_count > 0)`
   - `APPROVED_FOR_GO_LIVE`: `mandatory_pre_golive_count == 0` and `post_golive_sla_count == 0` and `waived_count == 0`

---

## 3. Pillar 2 — Word (`.docx`) & PDF (`.pdf`) Security Architecture & Go-Live Report Engine

### 3.1 Module Boundary (`backend/engine/sar_report_generator.py`)

`SarReportGenerator` accepts the unified `SarReportBundle` (containing `PastaAssessmentResponse`, `SastPlusSuiteResponse`, `RaciGovernanceResponse`, `MetricsResponse`, RBAC-masked `Finding[]`, and `AppTreeSummary`) and renders:

1. **`generate_sar_docx_bytes(bundle) -> bytes`** (`python-docx`):
   - Styled Office OpenXML `.docx` document with custom Daylight corporate palette (navy `#0F172A` headings, slate `#F1F5F9` table headers, emerald `#047857` pass badges, amber `#B45309` conditional/post-go-live callouts, rose `#BE123C` blocker callouts), landscape/auto-fitted tables, repeating table header rows, monospace BFL code blocks, and page headers/footers.
2. **`generate_sar_pdf_bytes(bundle) -> bytes`** (`reportlab.platypus`):
   - Multi-page A4 corporate `.pdf` dossier using `SimpleDocTemplate`, `Paragraph`, `Table`, `KeepTogether`, and page-number canvas callbacks so long filepaths, CPG paths, and BFL code snippets wrap cleanly without horizontal clipping.

### 3.2 Mandatory 10-Section Report Structure (Both `.docx` and `.pdf`)

1. **Section 1 — Cover Banner, Document Control & Executive Go-Live Verdict**:
   - Application Name, Target Workspace Path, Assessment Timestamp, Active Business Profile & Regulatory Scope, Overall **Go-Live Verdict (`APPROVED FOR GO-LIVE` / `CONDITIONAL GO-LIVE` / `NO-GO — HOLD RELEASE`)**, and the **3-Stage Risk Scorecard** (`Inherent Risk` -> `Current Residual Risk` -> `Final Projected Go-Live Risk Level`).
2. **Section 2 — Management Executive Summary & Go-Live Decision Rationale**:
   - Plain-English synthesis explaining what issues were discovered, whether the application can go live today, what conditions apply, and what residual risk leadership is accepting at launch.
3. **Section 3 — Security Architecture & Technical Scope Review (PASTA Stages I–III)**:
   - Crown Jewels & Business Criticality table, Tech Stack & Application Tree module summary, 4-Zone Trust Boundary posture, Discovered API Entrypoints & Inter-Procedural Operations summary (`DB`, `OS`, `AI/HTTP`, `FS`, `Secrets`), CycloneDX SBOM pinning summary, and Container/CI PBOM status.
4. **Section 4 — STRIDE Threat Modeling Matrix (`S, T, R, I, D, E`)**:
   - Structured 6-row domain table showing Security Property, Status, `✔ Passed Checks`, `✖ Issues`, Key Architectural Observations, and Primary Mitigation Controls.
5. **Section 5 — 7-Stage PASTA Assessment & Simulated Attack Trees (PASTA Stages IV–VII)**:
   - 7-stage PASTA summary table (`Stage I` to `Stage VII` verdicts and pass/gap counts) + detailed **Simulated Attack Tree Scenarios** (`Entrypoint / Vector -> MITRE CAPEC -> Propagation -> CWE Sink -> Crown Jewel -> BFL Chokepoint Shield`).
6. **Section 6 — MANDATORY PRE-GO-LIVE BLOCKERS (`Gate 1: Must Fix Before Production Launch`)**:
   - Complete register of all `MANDATORY_PRE_GO_LIVE` items with Observation ID, Severity, Source Engine/Domain, CWE/CAPEC, Exact `filepath:line`, Why It Blocks Go-Live, Required Pre-Launch BFL Fix, RACI Responsible Owner, Effort Estimate, and Risk Reduction (`-N pts`). (Renders an explicit green attestation block when `0` blockers remain.)
7. **Section 7 — POST-GO-LIVE ALLOWED OBSERVATIONS (`Gate 2: Deferrable with Binding SLA & Compensating Controls`)**:
   - Complete register of all `POST_GO_LIVE_SLA` items detailing Severity, Location, **Why Safe to Defer Past Launch** (e.g., non-reachable CPG path, internal scope, defense-in-depth), **Mandatory Temporary Compensating Control at Launch**, **Binding Post-Go-Live SLA (`7 / 14 / 30 / 90 Days`)**, and Permanent Fix Action.
8. **Section 8 — Step-by-Step "What To Do To Make It Live" Runbook**:
   - **Phase A (Pre-Launch Mandatory Checklist)**: Ordered action steps (BFL code patches, active key revocations/rotations, auth middleware enforcement, container hardening, ALASTOR re-scan verification gate).
   - **Phase B (Post-Launch 7/14/30/90-Day Hardening Roadmap)**: Sprint-aligned follow-up schedule to retire temporary compensating controls.
9. **Section 9 — Verified Architectural Strengths & Passing Security Controls**:
   - Positive assurance inventory of passing STRIDE observations, auth-guarded entrypoints, verified sanitizers, clean/revoked secret checks, pinned SBOM packages, and passing PBOM checks.
10. **Section 10 — RACI Governance, Risk-Acceptance Waivers & Formal ARB / CISO Sign-Off**:
    - Waiver & Gate Override audit table (any `RISK_ACCEPTED_WAIVER` or manually overridden items with reviewer justification) + Formal Sign-Off Table (`Security Architect`, `Engineering / Tech Lead`, `DevOps / SRE Lead`, `Product / Business Risk Owner` with Verdict, Name/Role, Date, and Conditions).

### 3.3 Strict Export Security & RBAC Redaction Invariants

- Raw secret literals (`secret_value_raw`) are **never** included in `.docx`, `.pdf`, or `json` SAR exports regardless of active user role; only `secret_value_masked` (`ghp_****...`) and safe provider identity metadata (`secret_verified_identity`) are emitted so exported Word/PDF documents can be safely shared over email, Confluence, or audit portals without leaking credentials.
- Filename headers (`Content-Disposition: attachment; filename="ALASTOR_SAR_GoLive_<slug>.docx"`) sanitize `<slug>` strictly via `re.sub(r"[^A-Za-z0-9_-]+", "_", app_name)` to prevent HTTP header injection.

---

## 4. Backend Models & REST API Contracts

### 4.1 New Pydantic Models (`backend/models.py`) & TypeScript Interfaces (`frontend/src/types/cpg.ts`)

- `PastaBusinessPreset = Literal["AUTO_INFERRED", "FINTECH_PAYMENTS", "HEALTHCARE_PHI", "AI_SAAS_PUBLIC", "ENTERPRISE_INTERNAL"]`
- `GoLiveGateStatus = Literal["MANDATORY_PRE_GO_LIVE", "POST_GO_LIVE_SLA", "RISK_ACCEPTED_WAIVER"]`
- `GoLiveSlaWindow = Literal["PRE_LAUNCH", "7_DAYS", "14_DAYS", "30_DAYS", "90_DAYS", "WAIVED"]`
- `GoLiveVerdict = Literal["APPROVED_FOR_GO_LIVE", "CONDITIONAL_GO_LIVE", "NO_GO_HOLD_RELEASE"]`
- `PastaCrownJewelItem`: `id`, `name`, `category`, `asset_count`, `weight_multiplier` (`float`), `sensitivity_label`, `rationale`, `sample_locations: List[str]`
- `PastaEvidenceItem`: `id`, `stage_number`, `verdict` (`"OK" | "GAP"`), `severity`, `title`, `detail`, `filepath`, `line`, `cwe_or_capec`, `stride_cross_ref`, `linked_finding_id`
- `PastaStageItem`: `stage_number`, `stage_code`, `stage_roman`, `title`, `methodology_goal`, `status`, `ok_count`, `gap_count`, `summary`, `what_passed`, `what_failed`, `evidence_items`
- `PastaAttackTreeNode`: `id`, `node_role` (`"GOAL" | "CAPEC_VECTOR" | "ENTRYPOINT" | "PROPAGATION" | "VULN_SINK" | "BFL_SHIELD" | "CROWN_JEWEL"`), `title`, `subtitle`, `severity`, `filepath`, `line`, `cwe_or_capec`, `is_severed`, `linked_finding_id`
- `PastaAttackTreeEdge`: `id`, `source`, `target`, `label`, `is_blocked`
- `PastaAttackTreeScenario`: `id`, `title`, `attacker_persona`, `mitre_capec`, `stride_letter`, `target_crown_jewel`, `status` (`"EXPLOITABLE_PATH" | "PARTIALLY_GUARDED" | "SEVERED_BY_CONTROLS"`), `severity`, `narrative`, `bfl_remediation`, `projected_risk_reduction`, `linked_finding_id`, `primary_filepath`, `primary_line`, `nodes`, `edges`
- `GoLiveObservationItem`: `id`, `source_type` (`"SAST" | "SCA" | "IAC" | "SECRET_VAULT" | "API_EXPOSURE" | "PBOM" | "STRIDE_GAP"`), `title`, `severity`, `cwe_or_standard`, `pasta_stage` (`int`), `stride_letter`, `filepath`, `line`, `reachability_status`, `gate_status` (`GoLiveGateStatus`), `default_gate_status` (`GoLiveGateStatus`), `is_overridden` (`bool`), `sla_window` (`GoLiveSlaWindow`), `why_issue`, `why_gate_classification`, `mandatory_fix_action`, `compensating_control`, `effort_estimate`, `raci_owner`, `risk_reduction_points` (`int`), `linked_finding_id`
- `PastaProfileUpdateRequest`: `project_path: Optional[str] = None`, `business_preset: PastaBusinessPreset = "AUTO_INFERRED"`, `crown_jewel_weights: Dict[str, float] = {}`, `reset_defaults: bool = False`
- `PastaGateOverrideRequest`: `project_path: Optional[str] = None`, `observation_id: str`, `gate_status: GoLiveGateStatus`, `sla_window: Optional[GoLiveSlaWindow] = None`, `compensating_control_note: Optional[str] = None`, `reset_override: bool = False`
- `PastaAssessmentResponse`:
  - `project_path`, `application_name`, `generated_at`
  - `selected_business_preset`, `effective_business_preset`, `inferred_business_reason`, `compliance_frameworks: List[str]`
  - `crown_jewels: List[PastaCrownJewelItem]`
  - `inherent_risk_score: int`, `inherent_risk_level: str`
  - `residual_risk_score: int`, `residual_risk_level: str`
  - `projected_golive_risk_score: int`, `projected_golive_risk_level: str`
  - `golive_verdict: GoLiveVerdict`, `golive_verdict_label: str`, `golive_executive_summary: str`
  - `mandatory_pre_golive_count: int`, `post_golive_sla_count: int`, `waived_count: int`, `passing_controls_count: int`
  - `stages: List[PastaStageItem]` (always length `7`, `PASTA-1..PASTA-7`)
  - `attack_trees: List[PastaAttackTreeScenario]` (always `>= 1` scenario)
  - `golive_observations: List[GoLiveObservationItem]`
  - `make_it_live_checklist: List[str]`
- `SastPlusSuiteResponse` adds optional `pasta_assessment: Optional[PastaAssessmentResponse] = None` for backward-compatible single-roundtrip hydration.

### 4.2 FastAPI Endpoints (`backend/main.py`)

1. `GET /api/aspm/pasta?project_path=...` -> `PastaAssessmentResponse` (path-confined against `_get_ai_allowed_roots()`).
2. `POST /api/aspm/pasta/profile` -> updates Stage I preset / crown-jewel weights and returns recalculated `PastaAssessmentResponse`.
3. `POST /api/aspm/pasta/gate-override` -> updates or resets a single observation's Go-Live Gate / SLA / waiver note and returns recalculated `PastaAssessmentResponse`.
4. `GET /api/export/sar-report?format=docx|pdf|json&project_path=...` -> returns binary `.docx` (`application/vnd.openxmlformats-officedocument.wordprocessingml.document`), binary `.pdf` (`application/pdf`), or structured `json` bundle.
5. `GET /api/export/report` (`markdown` & `json`) -> enriched with a summary section for 7-Stage PASTA & Go-Live Readiness Verdict.

---

## 5. Frontend Light-Only Daylight UX Specification

### 5.1 `PastaThreatWorkbench.tsx` (Mounted in `ThreatModelingView.tsx`)

1. **Threat Modeling Sub-Tab Bar (`ThreatModelingView.tsx`)**:
   - Adds **`PASTA Simulation & Go-Live (7-Stage)`** (`PASTA_WORKBENCH`) alongside `4-Zone Trust Boundaries`, `STRIDE Threat Dossier`, `Secret Keys Vault`, and `Entrypoints & PBOM`, plus quick **Download SAR Word (`.docx`)** and **Download SAR PDF (`.pdf`)** action buttons in the Threat Modeling header bar so reviewers can export from any Threat Modeling sub-tab.
2. **Inside `PastaThreatWorkbench.tsx` (Strict Daylight Palette: `#f8fafc` / `#ffffff`, `>= 4.5:1` contrast)**:
   - **Go-Live Readiness & Risk Command Strip**:
     - Verdict Banner (`APPROVED FOR GO-LIVE` emerald, `CONDITIONAL GO-LIVE` amber, or `NO-GO • HOLD RELEASE` rose) + 3 Risk Scorecards (`Inherent Risk` -> `Current Residual Risk` -> `Final Projected Go-Live Risk`) + `Download Word (.docx)` & `Download PDF (.pdf)` primary buttons.
     - **Stage I Business Profile & Crown Jewel Bar**: Preset selector (`Auto-Inferred`, `FinTech / PCI-DSS`, `Healthcare / HIPAA`, `AI SaaS / OWASP-LLM`, `Enterprise / SOC2`), expandable Crown Jewel criticality weight sliders (`0.8x–2.0x`), and `Reset to Auto` button.
   - **Interactive 7-Stage PASTA Stepper (`I` -> `VII`)**:
     - 7 clickable stage cards showing Roman numeral, title, `PASS / MONITORED / ACTION_REQUIRED` pill, and `✔ OK` vs `✖ Gap` counts. Clicking a stage filters or scrolls to its detailed evidence panel.
   - **Stage VI Interactive ReactFlow Attack Tree Simulation Canvas**:
     - Scenario selector pills (`Exploitable Paths` vs `Hardened/Severed Paths`), Dagre LR layout with explicit node width/height hints and multi-stage `fitView`, custom Daylight node styling by `node_role` (`GOAL`, `ENTRYPOINT`, `CAPEC_VECTOR`, `PROPAGATION`, `VULN_SINK`, `BFL_SHIELD`, `CROWN_JEWEL`), `"✨ AI Explain Attack Tree"` button (invoking `explainGraphWithAi` with Attack Tree nodes/edges), and click-to-open `"Inspect in IDE"` jump.
   - **Stage VII Go-Live Gate & Post-Go-Live Triage Matrix**:
     - Filter tabs: `ALL OBSERVATIONS`, `MANDATORY PRE-GO-LIVE (${mandatoryCount})`, `POST-GO-LIVE DEFERRABLE (${postCount})`, `WAIVED (${waivedCount})`, plus `"Make It Live" Runbook` checklist view.
     - Each row/card displays Severity, Source Domain, PASTA Stage & STRIDE cross-ref, `filepath:line` IDE jump, **Gate Selector (`Mandatory Pre-Go-Live` | `Post-Go-Live SLA` | `Risk-Accepted Waiver`)**, **SLA Selector (`Pre-Launch` | `7d` | `14d` | `30d` | `90d`)**, editable **Compensating Control / Waiver Note** inline save, and projected risk-score reduction (`-N pts`).

### 5.2 Stage 4 Export Center (`frontend/src/app/page.tsx`) & Store (`useAuditStore.ts`)

- Adds two flagship export cards at the top of Stage 4 -> **Enterprise Audit & Compliance Export Center**:
  1. **Threat Modeling & Go-Live Architecture Report (`.docx` Word)** (`EXECUTIVE & ARB • WORD DOCX`)
  2. **Threat Modeling & Go-Live Architecture Report (`.pdf` PDF)** (`CISO SIGN-OFF • ADOBE PDF`)
- Adds Zustand state & actions in `useAuditStore.ts`: `pastaAssessment`, `isLoadingPasta`, `isExportingSarFormat`, `fetchPastaAssessment`, `updatePastaProfile`, `overridePastaGateStatus`, and `downloadSarGoLiveReport(format: "docx" | "pdf")`.

---

## 6. Error Handling, Performance & Testing Plan

1. **Error Handling & Confinement**:
   - All `project_path` query/body inputs are validated via `os.path.realpath` + `os.path.commonpath` against `_get_ai_allowed_roots()`; unauthorized paths return HTTP `400`.
   - Missing optional scan state degrades gracefully using `AppTreeAnalyzer` + `ApiOperationsEngine` + `enterprise_mgr.run_sca_and_iac_scanners` so `/api/aspm/pasta` and `/api/export/sar-report` succeed even on freshly registered projects.
2. **Automated Verification Suite**:
   - New TDD suite `backend/tests/test_pasta_and_sar_reports.py`:
     - Verifies all 7 PASTA stages (`PASTA-1..PASTA-7`) populate deterministically on both vulnerable and clean workspaces.
     - Verifies Stage I auto-inference (`FINTECH_PAYMENTS`, `AI_SAAS_PUBLIC`, etc.) and live preset/crown-jewel weight override persistence + risk score recalculation.
     - Verifies Stage VI Attack Tree synthesis produces connected ReactFlow nodes/edges for both exploitable taint paths and clean/severed workspaces.
     - Verifies Go-Live Gate classification (`MANDATORY_PRE_GO_LIVE` vs `POST_GO_LIVE_SLA` + compensating controls), manual gate override + reset, and `NO_GO_HOLD_RELEASE` -> `CONDITIONAL_GO_LIVE` transition when blockers are reclassified or resolved.
     - Verifies `GET /api/export/sar-report?format=docx` returns valid ZIP/OpenXML `.docx` bytes (`PK\x03\x04`, parseable by `docx.Document(BytesIO(...))` containing all 10 required sections and zero raw secret leaks).
     - Verifies `GET /api/export/sar-report?format=pdf` returns valid `%PDF-` bytes (`> 2,000` bytes) with zero raw secret leaks.
   - Full `pytest` regression pass, `npx tsc --noEmit` zero-error check, ALASTOR self-audit (`0` findings on `cpg-sast-platform`), and live `:8000` / `:3000` endpoint verification.
