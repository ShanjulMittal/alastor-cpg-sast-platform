# ALASTOR v5.0 Pillar 3 — Live Exploit Verification (`EV`), Post-Fix `ev-replay`, Multi-Role IDOR Matrix & PASTA/SAR Promotion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a hardened, `httpx`-backed Live Exploit Verification (`EV`) and Post-Fix `ev-replay` engine with Zero-Collection CPG Auto-Probing + OpenAPI/Postman import, Multi-Role IDOR/BOLA matrix probing, `curl`/`pytest` PoC generation, PASTA Stage VII Mandatory Pre-Go-Live Blocker auto-promotion, SAR `.docx`/`.pdf` runtime attestation, 5 confined `/api/ev/*` FastAPI routes, and a Light-Only Daylight Live EV & Replay Console.

**Architecture:** Isolate target egress validation, collection/CPG route discovery, 6 deterministic non-destructive probe families, atomic `.alastor_vault/ev_replays.json` storage, and `curl`/`pytest` PoC generation inside `backend/engine/exploit_verification_engine.py`. Wire `ev_status` promotion into `pasta_threat_engine.py`, `sar_report_generator.py`, and `main.py`, and mount `LiveExploitVerificationConsole.tsx` inside `ThreatModelingView.tsx`.

**Tech Stack:** Python 3.12, `httpx==0.27.2` (already pinned), FastAPI, Pydantic v2, `python-docx`, `reportlab`, Next.js 15 / React 19, TypeScript, Zustand, Tailwind CSS (Light-Only Daylight WCAG AA `>= 4.5:1`).

## Global Constraints

- **Work on `main` only** in `c:\Projects\Securecodereview\cpg-sast-platform`; preserve all 235 existing backend tests.
- **Strict Target Egress Safety:** Loopback-only default + explicit RFC1918 staging opt-in (`allow_private_staging_host=True` + `authorized_staging_hosts`); permanently block public internet, cloud metadata (`169.254.169.254`, `100.100.100.200`, link-local), embedded credentials, HTTP redirects (`follow_redirects=False`), and ALASTOR self-port (`:8000`).
- **Zero Raw Credential Leakage:** Mask `Authorization`/`Cookie`/`X-API-Key` headers to `<USER_A_TOKEN>` / `<REDACTED_HEADER>` before storing in `.alastor_vault/ev_replays.json` (`0o600`), returning via API, or generating `curl`/`pytest` PoCs; scrub response snippets via `scrub_raw_secrets_text`.
- **Light-Only Daylight UI (`>= 4.5:1` WCAG AA):** `#f8fafc` / `#ffffff`, zero `dark:` classes, zero DOM XSS sinks.
- **Zero Production Self-Audit Findings:** Do NOT touch or stage `.superpowers/` or `synthetic_test_target/.vvaharness/`.

---

### Task 1: Pillar 3 Models (`models.py`) & Hardened `exploit_verification_engine.py` + Core TDD Suite

**Files:**
- Modify: `backend/models.py`
- Create: `backend/engine/exploit_verification_engine.py`
- Create: `backend/tests/test_exploit_verification_and_replay.py`

**Interfaces:**
- Produces in `backend/models.py`:
  - `EvStatusType = Literal["RUNTIME_EXPLOIT_CONFIRMED", "FIXED_VERIFIED", "NOT_REPRODUCED", "DRY_RUN_PLANNED"]`
  - Optional `ev_status: Optional[EvStatusType] = None` and `ev_evidence_summary: Optional[str] = None` on `Finding`
  - Section 16 EV models: `EvTargetPolicy`, `EvPlannedProbe`, `EvRunRequest`, `EvPlanResponse`, `EvProbeResultItem`, `EvReplayBundleItem`, `EvRunResponse`, `EvReplayRequest`, `EvReplayResultItem`, `EvReplayResponse`, `EvReplayListResponse`.
- Produces in `backend/engine/exploit_verification_engine.py`:
  - `validate_ev_target_url(target_url: str, allow_private_staging_host: bool = False, authorized_staging_hosts: Optional[List[str]] = None, check_self_port: bool = True) -> str`
  - `parse_api_collection_routes(collection_json: str) -> List[Dict[str, Any]]` (OpenAPI 3.x / Swagger 2.0 + Postman v2.1)
  - `ExploitVerificationEngine(vault_dir: str)`:
    - `plan_probes(target_dir, req, findings, api_ops) -> EvPlanResponse` (zero network traffic!)
    - `run_verification(target_dir, req, findings, api_ops, http_client=None) -> EvRunResponse` (requires `req.armed == True`)
    - `replay_confirmed(target_dir, req, http_client=None) -> EvReplayResponse`
    - `list_replays(target_dir) -> EvReplayListResponse`
    - `delete_replay(target_dir, replay_id) -> bool`
    - `get_confirmed_status_map(target_dir) -> Dict[str, Tuple[EvStatusType, str]]`
    - `generate_curl_poc(bundle)` & `generate_pytest_poc(bundle)`

- [ ] **Step 1–5 (TDD):** Write failing tests covering target URL blocks (public IP, `169.254.169.254`, `:8000` self-port, embedded creds, staging opt-in allow/deny), OpenAPI + Postman + zero-collection CPG discovery, live probes against an in-process FastAPI vulnerable app (`httpx.ASGITransport` proving `RUNTIME_EXPLOIT_CONFIRMED` across IDOR, SQLi, Reflected XSS, Credentialed CORS, Open Redirect, and missing security headers -> flipping to `FIXED_VERIFIED` on `ev-replay` after patching!), vault persistence (`0o600`), and zero raw auth-token leakage in vault/responses/`curl`/`pytest` PoCs -> implement -> verify GREEN -> commit.

---

### Task 2: PASTA Stage VII Mandatory Blocker Promotion, SAR `.docx`/`.pdf` Runtime Attestation & 5 Confined `/api/ev/*` Endpoints

**Files:**
- Modify: `backend/engine/pasta_threat_engine.py`
- Modify: `backend/engine/sar_report_generator.py`
- Modify: `backend/main.py`
- Modify: `backend/tests/test_exploit_verification_and_replay.py`

**Interfaces:**
- `PastaThreatEngine._classify_default_finding_gate`: auto-promotes `ev_status == "RUNTIME_EXPLOIT_CONFIRMED"` to `MANDATORY_PRE_GO_LIVE` (`PRE_LAUNCH`) regardless of static severity.
- `SarReportBundle`: optional `ev_replays: List[EvReplayBundleItem] = Field(default_factory=list)` scrubbed inside `sanitize_bundle_for_export` and rendered in Section 6 of `.docx`, `.pdf`, and JSON SAR dossiers.
- `backend/main.py`: 5 confined `/api/ev/*` endpoints (`POST /api/ev/plan`, `POST /api/ev/run`, `POST /api/ev/replay`, `GET /api/ev/replays`, `DELETE /api/ev/replays/{replay_id}`), plus automatic correlation of confirmed `ev_status` onto active findings for PASTA & SAR exports.

- [ ] **Step 1–5 (TDD):** Add FastAPI + PASTA + SAR `.docx`/`.pdf` tests (including confirming a `MEDIUM` finding with `ev_status="RUNTIME_EXPLOIT_CONFIRMED"` becomes a `MANDATORY_PRE_GO_LIVE` blocker causing `NO_GO_HOLD_RELEASE`, rendering in `.docx` & `.pdf` with zero raw token leakage, and HTTP `400` on traversal or blocked target URLs) -> implement -> verify GREEN -> commit.

---

### Task 3: Light-Only Daylight `LiveExploitVerificationConsole.tsx`, `ThreatModelingView.tsx` Tab & Store/API Wiring

**Files:**
- Modify: `frontend/src/types/cpg.ts`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/store/useAuditStore.ts`
- Create: `frontend/src/components/LiveExploitVerificationConsole.tsx`
- Modify: `frontend/src/components/ThreatModelingView.tsx`

- [ ] **Step 1–4:** Add 1-to-1 TypeScript interfaces, 5 API helpers (`normalizeLocalProjectPath`), Zustand slices (`evPlan`, `evRunResult`, `evReplays`, `evReplayResult`, loading/error states, project-switch epoch & reset guards), build Light-Only Daylight `LiveExploitVerificationConsole.tsx` (Arming switch, Safe Mode switch, Staging Opt-In, Multi-Role IDOR inputs, OpenAPI/Postman JSON box, live results table, 1-click `ev-replay`, Copy `curl` / Copy `pytest` PoC buttons), mount as 4th sub-tab in `ThreatModelingView.tsx`, verify `npx tsc --noEmit` (`0` errors) + `pytest -q` (`100%` pass) + `0` `dark:` / DOM-XSS findings, and commit.
