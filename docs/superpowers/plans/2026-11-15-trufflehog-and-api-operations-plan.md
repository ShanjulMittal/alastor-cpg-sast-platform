# Native TruffleHog-Grade Secret Validation & API Operations Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a native TruffleHog-grade secret scanner, `.git` commit-history hunter, and live provider key validator alongside a multi-framework API endpoint & inter-procedural CPG operations tracer and interactive ReactFlow explorer inside ALASTOR.

**Architecture:** Two focused, zero-external-binary Python engines (`backend/engine/secret_validator_engine.py` and `backend/engine/api_operations_engine.py`) integrate into ALASTOR's scan/findings pipeline and expose dedicated FastAPI endpoints (`/api/secrets/*` and `/api/endpoints/operations`). On the Next.js frontend, typed API helpers (`frontend/src/lib/api.ts`) and Zustand slices (`frontend/src/store/useAuditStore.ts`) power live secret verification controls in Stage 2 (`FlawExplorerSidebar.tsx`, `MonacoCodePane.tsx`) and Stage 3 (`ThreatModelingView.tsx`), plus a new interactive `ApiOperationsExplorerView.tsx` surfaced in Stage 3 (`MAP_360_THREATS` -> `API_OPERATIONS`) and Stage 4 (`SastPlusSuiteView.tsx` Pillar 3).

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, Tree-Sitter AST / ALASTOR CPG, stdlib `urllib.request` / `hmac` / `hashlib` / `subprocess`, Next.js 15 (React 19, TypeScript), `@xyflow/react` (`CustomGraphNode` + `DirectionalFlowEdge`), Zustand, Tailwind CSS (WCAG AA Light-Only Daylight theme), `pytest`.

## Global Constraints

- Zero external CLI binaries (`trufflehog` binary or Docker containers must NOT be required; all detection, `.git` history parsing, and live key verification run natively in Python stdlib).
- Auto-Verify Live by Default (`live_verification_enabled = True`), with a persistent `"Offline Mode"` toggle (`live_verification_enabled = False`) stored at `0o600` in `.alastor_vault/secret_scanner_config.json`.
- Outbound live key verification probes must ONLY contact hardcoded `https://` official provider hosts (`api.github.com`, `gitlab.com`, `sts.amazonaws.com`, `api.openai.com`, `generativelanguage.googleapis.com`, `api.anthropic.com`, `api.stripe.com`, `slack.com`, `api.sendgrid.com`, `huggingface.co`), block all `30x` HTTP redirects, enforce `timeout <= 4.0s`, never put raw secrets in URL query parameters or logs, and cache verdicts by `sha256(detector_id + ":" + raw_secret)`.
- Never write literal live-shaped fake secrets in production source or docs that would trigger ALASTOR's own self-audit (`0` findings required when scanning `cpg-sast-platform`; build synthetic test tokens dynamically in `tests/` via string concatenation such as `"ghp_" + "A" * 36`).
- Mandatory Light-Only High-Contrast Daylight Theme (`>= 4.5:1` WCAG AA contrast ratio on all text/badges; zero `vs-dark` or dark `bg-zinc-950` regressions).
- Do NOT run `npm run build` while `next dev` is actively serving port `3000` without restarting or checking dev server health; verify TypeScript via `npx tsc --noEmit` during tasks and verify live HTTP endpoints when running final checks.

---

### Task 1: Native TruffleHog-Grade Secret Scanner, Git-History Hunter & Live Key Validator (`backend`)

**Files:**
- Create: `c:\Projects\Securecodereview\cpg-sast-platform\backend\engine\secret_validator_engine.py`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\backend\models.py`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\backend\engine\enterprise_manager.py`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\backend\main.py`
- Test: `c:\Projects\Securecodereview\cpg-sast-platform\backend\tests\test_secret_validator_engine.py`

**Interfaces:**
- Consumes: `Finding`, `BestFixLocation` from `backend/models.py`; `_compute_shannon_entropy`, `_mask_secret_value` patterns from `backend/engine/enterprise_manager.py`.
- Produces:
  - Pydantic models in `backend/models.py`:
    - `SecretValidationStatus = Literal["VERIFIED_ACTIVE", "REVOKED_OR_INVALID", "OFFLINE_STRUCTURALLY_VALID", "TEST_OR_PLACEHOLDER", "VERIFICATION_ERROR"]`
    - Extended `Finding` fields:
      - `secret_validation_status: Optional[SecretValidationStatus] = None`
      - `secret_detector_id: Optional[str] = None`
      - `secret_verified_identity: Optional[str] = None`
      - `secret_validation_message: Optional[str] = None`
      - `secret_verified_at: Optional[str] = None`
      - `secret_source: Optional[Literal["WORKING_TREE", "GIT_HISTORY"]] = "WORKING_TREE"`
      - `secret_commit_sha: Optional[str] = None`
      - `secret_commit_author: Optional[str] = None`
    - `SecretScannerConfig(BaseModel)`: `live_verification_enabled: bool = True`, `scan_git_history: bool = True`, `max_git_commits: int = 50`, `supported_detectors_count: int = 14`
    - `SecretScannerConfigUpdate(BaseModel)`: `live_verification_enabled: Optional[bool] = None`, `scan_git_history: Optional[bool] = None`, `max_git_commits: Optional[int] = None`
    - `SecretVerifyRequest(BaseModel)`: `finding_ids: List[str] = Field(default_factory=list)`, `force_refresh: bool = False`, `allow_live_network: Optional[bool] = None`
    - `SecretInventoryResponse(BaseModel)`: `config: SecretScannerConfig`, `total_secrets: int`, `verified_active_count: int`, `revoked_count: int`, `structurally_valid_count: int`, `test_placeholder_count: int`, `git_history_count: int`, `secrets: List[Finding]`
  - Engine class `SecretValidatorEngine` in `backend/engine/secret_validator_engine.py` with singleton `get_secret_validator_engine(platform_root: Optional[str] = None) -> SecretValidatorEngine` and methods:
    - `get_config() -> SecretScannerConfig`
    - `update_config(payload: SecretScannerConfigUpdate) -> SecretScannerConfig`
    - `validate_secret_value(raw_secret: str, key_name: str = "", context_text: str = "", allow_live: Optional[bool] = None, force_refresh: bool = False) -> Dict[str, Any]`
    - `scan_and_validate_workspace(target_dir: str, existing_findings: List[Finding], allow_live: Optional[bool] = None, force_refresh: bool = False) -> List[Finding]`
    - `build_inventory_response(findings: List[Finding]) -> SecretInventoryResponse`
  - FastAPI routes in `backend/main.py`:
    - `GET /api/secrets/config` -> `SecretScannerConfig`
    - `POST /api/secrets/config` -> `SecretScannerConfig`
    - `GET /api/secrets/inventory` -> `SecretInventoryResponse`
    - `POST /api/secrets/verify` -> `SecretInventoryResponse`

- [ ] **Step 1: Write the failing unit & integration test suite (`backend/tests/test_secret_validator_engine.py`)**

Create `c:\Projects\Securecodereview\cpg-sast-platform\backend\tests\test_secret_validator_engine.py` constructing all test tokens dynamically via concatenation (so static scanners never flag the test file itself) and testing:
1. Live `200` verification on GitHub token (`"ghp_" + "a1B2" * 9`) via monkeypatched HTTP opener -> `VERIFIED_ACTIVE`, `secret_verified_identity` contains `@secops-bot`, and finding severity promoted to `"CRITICAL"`.
2. Live `401` verification on OpenAI token (`"sk-proj-" + "x9Y8" * 10`) -> `REVOKED_OR_INVALID`.
3. Test/Placeholder detection (`"sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"` and `"AKIA" + "IOSFODNN7EXAMPLE"`) -> `TEST_OR_PLACEHOLDER` with zero network calls.
4. Offline deterministic JWT (`eyJ...` unexpired vs expired `exp`), PEM private key, and Postgres URI (`postgres://admin:S3cureP@ssw0rd99!@db.internal:5432/prod`) -> `OFFLINE_STRUCTURALLY_VALID` with zero network calls.
5. `Offline Mode` config (`live_verification_enabled=False`) -> GitHub/Gemini tokens return `OFFLINE_STRUCTURALLY_VALID` and HTTP opener call count is `0`; SHA-256 cache ensures second call in live mode makes `0` duplicate HTTP calls unless `force_refresh=True`; `302` redirect response is blocked and returns `VERIFICATION_ERROR`.
6. Temporary `.git` repository test (`git init`, commit `config.py` with `"glpat-" + "Zz99Xx88Yy77Ww66Vv55"`, second commit deleting that line, `scan_and_validate_workspace`) -> emits `Finding` with `rule_id == "SECRET-GIT-HISTORY-LEAK"`, `secret_source == "GIT_HISTORY"`, non-empty `secret_commit_sha`, and masked value.
7. FastAPI `TestClient` routes `GET/POST /api/secrets/config`, `GET /api/secrets/inventory`, and `POST /api/secrets/verify`.

- [ ] **Step 2: Run pytest on `test_secret_validator_engine.py` to verify it fails**

Run in `c:\Projects\Securecodereview\cpg-sast-platform\backend`:
`..\.venv\Scripts\python.exe -m pytest tests/test_secret_validator_engine.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'engine.secret_validator_engine'` or missing models).

- [ ] **Step 3: Implement models (`backend/models.py`), `SecretValidatorEngine` (`backend/engine/secret_validator_engine.py`), enrichment preservation (`backend/engine/enterprise_manager.py`), and FastAPI routes (`backend/main.py`)**

Implementation specifics:
- In `backend/models.py`: add the 8 optional secret validation fields on `Finding` (`secret_validation_status`, `secret_detector_id`, `secret_verified_identity`, `secret_validation_message`, `secret_verified_at`, `secret_source`, `secret_commit_sha`, `secret_commit_author`) and add `SecretScannerConfig`, `SecretScannerConfigUpdate`, `SecretVerifyRequest`, and `SecretInventoryResponse`.
- In `backend/engine/secret_validator_engine.py`:
  - Define immutable `ALLOWED_VERIFY_HOSTS = frozenset({"api.github.com", "gitlab.com", "sts.amazonaws.com", "api.openai.com", "generativelanguage.googleapis.com", "api.anthropic.com", "api.stripe.com", "slack.com", "api.sendgrid.com", "huggingface.co"})`.
  - Implement `_NoRedirectHandler(urllib.request.HTTPRedirectHandler)` raising `urllib.error.HTTPError(..., 302, "Redirects blocked", hdrs, fp)` on any `30x` redirect.
  - Implement `_http_probe(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None, timeout: float = 4.0) -> Tuple[int, str, Dict[str, str]]` verifying `urlparse(url).scheme == "https"` and `hostname in ALLOWED_VERIFY_HOSTS` before opening.
  - Implement AWS SigV4 signed `POST https://sts.amazonaws.com/` (`Action=GetCallerIdentity&Version=2011-06-15`) using stdlib `hmac` + `hashlib.sha256` when both an `AKIA`/`ASIA` Access Key ID and a 40-char AWS Secret Access Key appear in the same file/context!
  - Implement working-tree + `.git` commit-history scanning (`subprocess.run(["git", "-C", target_dir, "log", "-p", "-n", str(max_commits), "--no-color", "--unified=0"], capture_output=True, text=True, timeout=12, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})`), skipping `docs/`, `tests/`, `*.md`, `*.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `.next/`, `node_modules/`, `.venv/`, `.alastor_patches/`, and `.alastor_vault/` so documentation and test suites never generate false positives.
  - Promote `finding.severity = "CRITICAL"` automatically whenever `secret_validation_status == "VERIFIED_ACTIVE"`.
- In `backend/engine/enterprise_manager.py`: ensure `_populate_secret_key_metadata` preserves pre-populated `secret_validation_status`, `secret_detector_id`, `secret_verified_identity`, `secret_validation_message`, `secret_source`, `secret_commit_sha`, and `secret_commit_author` without overwriting them, and include `secret_validation_status` note in `ThreatModelingView` secret vault records if serialized separately.
- In `backend/main.py`:
  - Hook `secret_validator_engine.scan_and_validate_workspace(target_dir, combined_before_enrich)` inside `get_or_compute_findings` when computing findings (skipping live network probes automatically if `target_dir` is `enterprise_mgr.platform_root` only if `0` secrets exist — note `platform_root` has `0` secrets anyway so it's instant!).
  - Register `GET /api/secrets/config`, `POST /api/secrets/config`, `GET /api/secrets/inventory`, and `POST /api/secrets/verify` (updating `_cached_findings` in place when `/api/secrets/verify` runs!).

- [ ] **Step 4: Run pytest to verify all Task 1 tests and existing suite pass**

Run in `c:\Projects\Securecodereview\cpg-sast-platform\backend`:
`..\.venv\Scripts\python.exe -m pytest tests/ -v`
Expected: All existing 31 tests + new `test_secret_validator_engine.py` tests PASS with `0` warnings.

- [ ] **Step 5: Commit Task 1**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add backend/models.py backend/engine/secret_validator_engine.py backend/engine/enterprise_manager.py backend/main.py backend/tests/test_secret_validator_engine.py
git commit -m "feat(secrets): add native TruffleHog-grade secret scanner, git-history hunter & live key validator"
```

---

### Task 2: Multi-Framework API Endpoints & Inter-Procedural CPG Operations Tracer (`backend`)

**Files:**
- Create: `c:\Projects\Securecodereview\cpg-sast-platform\backend\engine\api_operations_engine.py`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\backend\models.py`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\backend\engine\enterprise_manager.py`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\backend\main.py`
- Test: `c:\Projects\Securecodereview\cpg-sast-platform\backend\tests\test_api_operations_engine.py`

**Interfaces:**
- Consumes: `Finding`, `AttackSurfaceEndpoint` from `backend/models.py`.
- Produces:
  - Pydantic models in `backend/models.py`:
    - `ApiOperationCategory = Literal["AUTH_GUARD", "INPUT_VALIDATION", "DATABASE_READ", "DATABASE_WRITE", "EXTERNAL_HTTP_OR_AI", "FILESYSTEM_IO", "OS_COMMAND_EXEC", "SECRET_OR_CRYPTO"]`
    - `ApiOperationItem(BaseModel)`:
      - `id: str`
      - `step_index: int`
      - `category: ApiOperationCategory`
      - `operation_verb: str`
      - `target_resource: str`
      - `function_name: str`
      - `call_chain: List[str] = Field(default_factory=list)`
      - `filepath: str`
      - `line_number: int`
      - `code_snippet: str`
      - `is_mutating: bool = False`
      - `risk_note: Optional[str] = None`
    - `ApiEndpointOperationDossier(BaseModel)`:
      - `id: str`
      - `method: str`
      - `route_path: str`
      - `framework: str`
      - `handler_name: str`
      - `filepath: str`
      - `start_line: int`
      - `end_line: int`
      - `auth_status: Literal["AUTHENTICATED", "UNAUTHENTICATED", "PARTIAL_OR_CUSTOM"] = "UNAUTHENTICATED"`
      - `auth_mechanisms: List[str] = Field(default_factory=list)`
      - `request_params: List[str] = Field(default_factory=list)`
      - `response_type: Optional[str] = None`
      - `operations: List[ApiOperationItem] = Field(default_factory=list)`
      - `operation_categories: List[ApiOperationCategory] = Field(default_factory=list)`
      - `calls_functions: List[str] = Field(default_factory=list)`
      - `is_mutating: bool = False`
      - `risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"] = "SAFE"`
      - `linked_finding_ids: List[str] = Field(default_factory=list)`
      - `linked_findings_count: int = 0`
      - `plain_english_story: str = ""`
      - `flow_nodes: List[Dict[str, Any]] = Field(default_factory=list)`
      - `flow_edges: List[Dict[str, Any]] = Field(default_factory=list)`
    - `ApiOperationsReportResponse(BaseModel)`:
      - `project_path: str`
      - `total_endpoints: int`
      - `authenticated_count: int`
      - `unauthenticated_count: int`
      - `mutating_endpoints_count: int`
      - `db_endpoints_count: int`
      - `external_http_endpoints_count: int`
      - `exec_or_fs_endpoints_count: int`
      - `vulnerable_endpoints_count: int`
      - `frameworks_detected: List[str] = Field(default_factory=list)`
      - `endpoints: List[ApiEndpointOperationDossier] = Field(default_factory=list)`
  - Engine `ApiOperationsEngine` in `backend/engine/api_operations_engine.py` with `analyze_workspace_api_operations(target_dir: str, findings: Optional[List[Finding]] = None) -> ApiOperationsReportResponse`.
  - FastAPI endpoint `GET /api/endpoints/operations` in `backend/main.py` (accepting optional `project_path: Optional[str] = Query(None)`).

- [ ] **Step 1: Write the failing unit & integration test suite (`backend/tests/test_api_operations_engine.py`)**

Create `c:\Projects\Securecodereview\cpg-sast-platform\backend\tests\test_api_operations_engine.py` testing:
1. Multi-file FastAPI application (`api/orders.py` importing `services/order_service.py` and `services/payment_client.py`):
   - `@router.post("/orders/{order_id}/settle", response_model=ReceiptModel)` with `Depends(require_jwt_user)` calling `persist_order()` (`INSERT INTO settlements ...`) and `charge_gateway()` (`requests.post("https://api.stripe.com/v1/charges")`) -> discovers `POST /api/v1/orders/{order_id}/settle` (with `APIRouter(prefix="/api/v1")` resolved!), `auth_status == "AUTHENTICATED"`, inter-procedural operations include `AUTH_GUARD`, `DATABASE_WRITE` (`INSERT` on `settlements`), and `EXTERNAL_HTTP_OR_AI` (`requests.post`), `is_mutating == True`, `calls_functions` contains `persist_order` and `charge_gateway`, and `flow_nodes` / `flow_edges` have sequential `step_index` (`1..N`).
   - `@router.delete("/orders/{order_id}/purge")` with NO auth guard calling `os.remove(...)` and `subprocess.run(...)` -> `auth_status == "UNAUTHENTICATED"`, `FILESYSTEM_IO` + `OS_COMMAND_EXEC`, `is_mutating == True`, `risk_level` in `("CRITICAL", "HIGH")`.
2. Next.js App Router (`src/app/api/users/[id]/route.ts` exporting `export async function GET(req: Request)` and `export async function DELETE(req: Request)`) -> discovers `GET /api/users/{id}` and `DELETE /api/users/{id}` (`framework == "Next.js App Router"`).
3. Express router (`routes/webhooks.js` with `router.post("/webhook/github", verifySignature, async (req, res) => { ... })`) -> discovers `POST /webhook/github` (`framework == "Express.js"`), middleware `verifySignature` captured, and operations extracted.
4. Finding correlation: passing a `Finding` located inside `services/order_service.py` links `linked_findings_count == 1` and `linked_finding_ids` to the upstream `POST /api/v1/orders/{order_id}/settle` endpoint!
5. FastAPI `TestClient` route `GET /api/endpoints/operations` on `cpg-sast-platform` discovers ALASTOR's own `35+` FastAPI routes (`/api/scan`, `/api/findings`, `/api/graph`, `/api/secrets/verify`, etc.) with concrete Cypher/Filesystem/HTTP operations!

- [ ] **Step 2: Run pytest on `test_api_operations_engine.py` to verify it fails**

Run in `c:\Projects\Securecodereview\cpg-sast-platform\backend`:
`..\.venv\Scripts\python.exe -m pytest tests/test_api_operations_engine.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'engine.api_operations_engine'`).

- [ ] **Step 3: Implement models (`backend/models.py`), `ApiOperationsEngine` (`backend/engine/api_operations_engine.py`), `enterprise_manager.py` summary enrichment, and `GET /api/endpoints/operations` (`backend/main.py`)**

Implementation specifics:
- In `backend/engine/api_operations_engine.py`:
  - Walk workspace source files (`.py`, `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.go`, `.java`), excluding `node_modules`, `.venv`, `.next`, `dist`, `build`, `__pycache__`, `tests`, `.git`.
  - Build a multi-file function index mapping `(rel_filepath, fn_name)` and imported symbol aliases (`from services.order_service import persist_order`, `import { x } from "./y"`) so inter-procedural calls resolve cleanly across files up to `max_depth = 4` with a `visited` set preventing recursion loops.
  - Detect route definitions across FastAPI/Starlette (`APIRouter(prefix=...)` + multi-line `@app.<method>` / `@router.<method>`), Flask (`@app.route` / `@bp.route`), Django (`path(...)` + `@api_view`), Next.js App Router (`app/**/route.{ts,tsx,js,jsx}` converting `[param]` -> `{param}` and `[...slug]` -> `{slug*}`), Next.js Pages API (`pages/api/**`), Express/Fastify/Koa (`(app|router).(get|post|put|delete|patch)`), NestJS (`@Controller` + `@Get/@Post/...`), Go (`HandleFunc` / `.GET` / `.POST`), and Spring (`@GetMapping` / `@PostMapping` / `@RequestMapping`).
  - Extract ordered `ApiOperationItem` records across all 8 categories, build human-readable `plain_english_story`, correlate `Finding`s whose `best_fix_location` or `path_nodes` fall within `(filepath, start_line..end_line)` of the route handler or any called helper function, and synthesize `flow_nodes` + `flow_edges` compatible with ALASTOR's `CustomGraphNode` (`type="cpgNode"`) and `DirectionalFlowEdge` (`step_index` `1..N`, `flow_label`).
- In `backend/engine/enterprise_manager.py`: enrich `AttackSurfaceEndpoint` `plain_english_purpose` inside `get_sast_plus_suite` using `analyze_workspace_api_operations` so existing SAST+ consumers also get operation-rich descriptions.
- In `backend/main.py`: register `@app.get("/api/endpoints/operations", response_model=ApiOperationsReportResponse)`.

- [ ] **Step 4: Run pytest across all backend tests to verify everything passes**

Run in `c:\Projects\Securecodereview\cpg-sast-platform\backend`:
`..\.venv\Scripts\python.exe -m pytest tests/ -v`
Expected: 100% PASS, `0` warnings.

- [ ] **Step 5: Commit Task 2**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add backend/models.py backend/engine/api_operations_engine.py backend/engine/enterprise_manager.py backend/main.py backend/tests/test_api_operations_engine.py
git commit -m "feat(api-ops): add multi-framework API endpoint & inter-procedural CPG operations tracer"
```

---

### Task 3: Frontend Contracts, Store Slices & Live Secret Validation UX (`Stage 2` & `Stage 3`)

**Files:**
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\frontend\src\types\cpg.ts`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\frontend\src\lib\api.ts`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\frontend\src\store\useAuditStore.ts`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\frontend\src\components\FlawExplorerSidebar.tsx`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\frontend\src\components\MonacoCodePane.tsx`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\frontend\src\components\ThreatModelingView.tsx`

**Interfaces:**
- Consumes: Task 1 & Task 2 backend JSON contracts (`/api/secrets/config`, `/api/secrets/inventory`, `/api/secrets/verify`, `/api/endpoints/operations`).
- Produces:
  - TypeScript interfaces in `frontend/src/types/cpg.ts`:
    - `SecretValidationStatus`, extended `Finding` fields (`secret_validation_status`, `secret_detector_id`, `secret_verified_identity`, `secret_validation_message`, `secret_verified_at`, `secret_source`, `secret_commit_sha`, `secret_commit_author`), `SecretScannerConfig`, `SecretScannerConfigUpdate`, `SecretInventoryResponse`.
    - `MapSubTab = "SPIDER_360" | "THREAT_BOUNDARIES" | "API_OPERATIONS"`
    - `ApiOperationCategory`, `ApiOperationItem`, `ApiEndpointOperationDossier`, `ApiOperationsReportResponse`.
  - API helpers in `frontend/src/lib/api.ts`:
    - `fetchSecretScannerConfig()`, `updateSecretScannerConfig(payload)`, `fetchSecretInventory()`, `verifySecrets(payload)`, `fetchApiOperationsReport(projectPath?)`.
  - Store state & actions in `frontend/src/store/useAuditStore.ts`:
    - `secretScannerConfig: SecretScannerConfig | null`
    - `secretInventory: SecretInventoryResponse | null`
    - `isVerifyingSecrets: boolean`
    - `apiOperationsReport: ApiOperationsReportResponse | null`
    - `isLoadingApiOperations: boolean`
    - `fetchSecretConfigState()`, `saveSecretConfigState(payload)`, `fetchSecretInventoryState()`, `verifySecretsLive(findingIds?, forceRefresh?)`, `fetchApiOperationsState()`.

- [ ] **Step 1: Add TypeScript types (`frontend/src/types/cpg.ts`), API client functions (`frontend/src/lib/api.ts`), and Zustand store actions (`frontend/src/store/useAuditStore.ts`)**

Ensure `triggerScan`, `activateProject`, and initial workspace hydration also refresh `secretInventory` and `apiOperationsReport` cleanly, and `verifySecretsLive` updates both `secretInventory` and matching `Finding` items inside `state.findings` + `state.selectedFinding` immediately!

- [ ] **Step 2: Upgrade Secret Cards & Dossier in Stage 2 (`FlawExplorerSidebar.tsx` & `MonacoCodePane.tsx`)**

In `FlawExplorerSidebar.tsx` and `MonacoCodePane.tsx` (strict WCAG AA Light-Mode contrast `>= 4.5:1`):
- Render the TruffleHog-style validation badge on every secret card:
  - `VERIFIED_ACTIVE`: `bg-rose-100 text-rose-900 border-rose-400` (`● LIVE ACTIVE KEY`)
  - `REVOKED_OR_INVALID`: `bg-emerald-50 text-emerald-900 border-emerald-300` (`✓ REVOKED / INACTIVE`)
  - `OFFLINE_STRUCTURALLY_VALID`: `bg-amber-100 text-amber-950 border-amber-400` (`◆ STRUCTURALLY VALID`)
  - `TEST_OR_PLACEHOLDER`: `bg-slate-100 text-slate-800 border-slate-300` (`○ TEST / MOCK KEY`)
  - `VERIFICATION_ERROR`: `bg-orange-50 text-orange-900 border-orange-300` (`! VERIFY TIMEOUT`)
- Render `GIT COMMIT <sha[:7]>` badge (`bg-purple-50 text-purple-900 border-purple-300`) when `f.secret_source === "GIT_HISTORY"`.
- Show `f.secret_verified_identity || f.secret_validation_message` below the masked value box and add a 1-click **`Verify Key`** button (`onClick={(e) => { e.stopPropagation(); void verifySecretsLive([f.id], true); }}`) right alongside `Reveal Key`.

- [ ] **Step 3: Upgrade Stage 3 `Secret Keys & Credentials Vault` (`ThreatModelingView.tsx`)**

In `ThreatModelingView.tsx` (`Secret Keys & Credentials Vault` sub-tab):
- Add a crisp Daylight Vault Command Bar with:
  - 5 KPI summary pills: `Total Keys`, `Live Active`, `Revoked / Inactive`, `Structurally Valid`, `Git History Leaks`.
  - **`Live Verification: AUTO (ONLINE)` / `OFFLINE MODE`** toggle button wired to `saveSecretConfigState({ live_verification_enabled: !live })`.
  - **`Scan .git History: ON / OFF`** toggle button wired to `saveSecretConfigState({ scan_git_history: !gitHist })`.
  - **`Verify All Keys Live`** primary action button wired to `verifySecretsLive([], true)`.
  - Filter pills (`ALL`, `VERIFIED_ACTIVE`, `GIT_HISTORY`, `STRUCTURALLY_VALID`, `REVOKED_OR_TEST`).
- Enrich each Vault credential card with its detector badge (`secret_detector_id`), validation verdict pill, verified identity/message banner, git commit provenance (`commit SHA + author` if `GIT_HISTORY`), and per-card `Re-Verify Key` button.

- [ ] **Step 4: Run `npx tsc --noEmit` to verify zero TypeScript errors**

Run in `c:\Projects\Securecodereview\cpg-sast-platform\frontend`:
`npx tsc --noEmit`
Expected: Exit code `0` with zero errors.

- [ ] **Step 5: Commit Task 3**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add frontend/src/types/cpg.ts frontend/src/lib/api.ts frontend/src/store/useAuditStore.ts frontend/src/components/FlawExplorerSidebar.tsx frontend/src/components/MonacoCodePane.tsx frontend/src/components/ThreatModelingView.tsx
git commit -m "feat(ui-secrets): add live key validation badges, vault controls & git-history provenance"
```

---

### Task 4: Interactive `API Endpoints & Operations Explorer`, Stage 3/4 Integration & Full-Stack Verification

**Files:**
- Create: `c:\Projects\Securecodereview\cpg-sast-platform\frontend\src\components\ApiOperationsExplorerView.tsx`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\frontend\src\app\page.tsx`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\frontend\src\components\SastPlusSuiteView.tsx`
- Modify: `c:\Projects\Securecodereview\cpg-sast-platform\frontend\src\components\QuickCommandModal.tsx`

**Interfaces:**
- Consumes: `ApiOperationsReportResponse`, `ApiEndpointOperationDossier`, `ApiOperationItem` from `frontend/src/types/cpg.ts`; `useAuditStore` (`apiOperationsReport`, `fetchApiOperationsState`, `openCodeLocationInIde`, `explainCurrentGraphAi`, `setAiDrawerOpen`); `CustomGraphNode` (`frontend/src/components/CustomGraphNode.tsx`) and `DirectionalFlowEdge` (`frontend/src/components/DirectionalFlowEdge.tsx`).
- Produces: `ApiOperationsExplorerView` React component rendered in Stage 3 (`mapSubTab === "API_OPERATIONS"`) and Stage 4 (`SastPlusSuiteView.tsx` `effectiveTab === "ATTACK_SURFACE"`).

- [ ] **Step 1: Build `ApiOperationsExplorerView.tsx` (`frontend/src/components/ApiOperationsExplorerView.tsx`)**

Build `ApiOperationsExplorerView.tsx` in strict WCAG AA High-Contrast Daylight styling (`>= 4.5:1` contrast):
- **Top KPI & Export Strip**:
  - Cards for `Total API Endpoints`, `DB Read / Write Routes`, `Outbound HTTP / AI Routes`, `File I/O & OS Exec Routes`, `Unauthenticated Mutating`, and `Endpoints with Active Flaws`.
  - `Refresh Trace`, `Export JSON`, and `Export CSV` buttons.
- **Split Master-Detail Explorer**:
  - **Left Master Inventory**:
    - Search input (filters by `route_path`, `handler_name`, `filepath`, `framework`, or any `operation.target_resource` / `operation_verb`).
    - Method filter pills (`ALL`, `GET`, `POST`, `PUT`, `DELETE`, `PATCH`) + Category filter pills (`ALL`, `DATABASE_WRITE`, `DATABASE_READ`, `EXTERNAL_HTTP_OR_AI`, `FILESYSTEM_IO`, `OS_COMMAND_EXEC`, `SECRET_OR_CRYPTO`, `UNAUTHENTICATED`, `VULNERABLE`).
    - Endpoint cards showing color-coded HTTP method badge (`GET` sky, `POST` emerald, `PUT`/`PATCH` amber, `DELETE` rose), route path, framework badge, `filepath:L<start_line>`, auth status badge (`AUTHENTICATED` emerald vs `UNAUTHENTICATED` amber/rose), operation category micro-chips, and linked flaw count.
  - **Right Selected Endpoint Inspector**:
    - **Endpoint Header & Plain-English Operation Story**: Method + Route + Handler signature, `Open Handler in IDE` button (`openCodeLocationInIde(ep.filepath, ep.start_line, ep.linked_finding_ids[0])`), and `Explain Endpoint Flow with AI` button (`setAiDrawerOpen(true, "GRAPH")` + `explainCurrentGraphAi("API_ENDPOINT_FLOW", nodesDigest, edgesDigest)`).
    - **Unauthenticated Mutating Warning Banner** when `ep.is_mutating && ep.auth_status === "UNAUTHENTICATED"`.
    - **Interactive Directional ReactFlow Canvas (`height: 300px`)**: Renders `ep.flow_nodes` and `ep.flow_edges` in `LR` layout using `nodeTypes={{ cpgNode: CustomGraphNode }}` and `edgeTypes={{ directionalFlow: DirectionalFlowEdge }}`, `sourceHandle="right-src"` -> `targetHandle="left-tgt"`, `18x18` outer-border arrowheads, numbered step badges `①..Ⓝ`, `Fit Flow` button, and click-node-to-open-in-IDE handler!
    - **Ordered Operations Performed Table / Timeline**: Lists every `ApiOperationItem` (`①`, Category badge, `operation_verb`, `target_resource`, inter-procedural `call_chain` `fnA() -> fnB()`, `filepath:L<line>`, `code_snippet`, and `Inspect` button jumping to exact file & line in Stage 2).
    - **Inputs, Auth Guards & Linked CPG Findings Grid**: Displays `request_params`, `auth_mechanisms`, `calls_functions`, and clickable linked vulnerability cards.

- [ ] **Step 2: Wire `ApiOperationsExplorerView` into Stage 3 (`page.tsx`), Stage 4 (`SastPlusSuiteView.tsx`), and `Ctrl+K` (`QuickCommandModal.tsx`)**

- In `frontend/src/app/page.tsx` (Stage 3 `MAP_360_THREATS` sub-bar):
  - Add the 3rd sub-pill **`API Endpoints & Operations`** (`mapSubTab === "API_OPERATIONS"`, showing `apiOperationsReport?.total_endpoints` count badge) right beside `360° Architecture & Call Flows` and `Trust Boundaries, STRIDE & PBOM`, and render `<ApiOperationsExplorerView />` when `mapSubTab === "API_OPERATIONS"`.
- In `frontend/src/components/SastPlusSuiteView.tsx`:
  - Replace Pillar 3 (`effectiveTab === "ATTACK_SURFACE"`) with `<ApiOperationsExplorerView embedded />` AND convert any remaining legacy dark `bg-zinc-950` / `bg-zinc-900` / `text-zinc-200` / `text-white` card backgrounds in `SastPlusSuiteView.tsx` to crisp WCAG AA Daylight classes (`bg-white`, `bg-slate-50`, `text-slate-900`, `text-slate-700`, `border-slate-200`)!
- In `frontend/src/components/QuickCommandModal.tsx`:
  - Add fuzzy-searchable commands for **"Open API Endpoints & Operations Explorer"** (`Stage 3 -> API_OPERATIONS`) and **"Open Secret Keys & Live TruffleHog Validator Vault"** (`Stage 3 -> THREAT_BOUNDARIES`).

- [ ] **Step 3: Verify Frontend TypeScript & Live Full-Stack Endpoints**

1. Run TypeScript check in `c:\Projects\Securecodereview\cpg-sast-platform\frontend`:
   `npx tsc --noEmit` -> `0` errors.
2. Run full backend test suite in `c:\Projects\Securecodereview\cpg-sast-platform\backend`:
   `..\.venv\Scripts\python.exe -m pytest tests/ -v` -> `100%` pass, `0` warnings.
3. Run E2E verification harness in `c:\Projects\Securecodereview\cpg-sast-platform`:
   `.\.venv\Scripts\python.exe verify_harness.py` -> `20/20` assertions passing.
4. Verify live endpoints on `http://127.0.0.1:8000` (`GET /api/secrets/config`, `GET /api/secrets/inventory`, `GET /api/endpoints/operations`) and run a full ALASTOR self-scan (`POST /api/scan` on `c:\Projects\Securecodereview\cpg-sast-platform`) confirming:
   - `0` active vulnerability/secret findings on `cpg-sast-platform`!
   - `GET /api/endpoints/operations` discovers ALASTOR's `35+` live FastAPI endpoints and their exact operations!

- [ ] **Step 4: Commit Task 4**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add frontend/src/components/ApiOperationsExplorerView.tsx frontend/src/app/page.tsx frontend/src/components/SastPlusSuiteView.tsx frontend/src/components/QuickCommandModal.tsx
git commit -m "feat(ui-api-ops): add interactive API Endpoints & Operations Explorer across Stages 3 & 4"
```
