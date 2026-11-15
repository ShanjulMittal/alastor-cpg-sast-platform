# ALASTOR Design Specification — Native TruffleHog-Grade Secret Key Validation & Deep API Endpoints Operations Intelligence

**Date:** 2026-11-15  
**Status:** Approved in Brainstorming — Ready for User Spec Review  
**Target Codebase:** `cpg-sast-platform` (`backend/` FastAPI + Neo4j CPG Engine, `frontend/` Next.js + ReactFlow + Monaco + Zustand)

---

## 1. Executive Summary & Goals

This upgrade appends two tightly integrated security intelligence subsystems directly inside ALASTOR while preserving **100% of existing v4.0 capabilities**, maintaining the **Guided 4-Stage High-Contrast Daylight UI (`>= 4.5:1` WCAG AA)**, and guaranteeing **zero self-audit findings** on `cpg-sast-platform`:

1. **Native TruffleHog-Grade Secret Scanner, Git-History Hunter & Live Key Validator (`backend/engine/secret_validator_engine.py`)**:
   - Built natively inside ALASTOR in pure Python with zero external binary or Docker dependencies.
   - Scans both the **active working tree** and **`.git` commit history** (`git log -p -n 50`) to uncover secrets committed and later deleted.
   - **Auto-Verify Live by Default** (`live_verification_enabled = True`): Automatically validates discovered credentials against safe, read-only official provider identity endpoints (`GitHub`, `GitLab`, `AWS STS GetCallerIdentity`, `OpenAI`, `Google Gemini`, `Anthropic`, `Stripe`, `Slack`, `SendGrid`, `HuggingFace`, and webhook/JWT/checksum verifiers), paired with a persistent **"Offline Mode" toggle** to disable outbound network probes when auditing air-gapped or canary-sensitive repositories.
2. **Multi-Framework API Endpoints & Inter-Procedural CPG Operations Tracer (`backend/engine/api_operations_engine.py` + `frontend/src/components/ApiOperationsExplorerView.tsx`)**:
   - Discovers API routes across **FastAPI, Flask, Django, Next.js App Router (`app/api/**/route.ts|js`) & Pages API (`pages/api/**`), Express/Fastify/Koa, NestJS/Spring decorators, and Go HTTP routers**.
   - Walks each endpoint's AST, inter-procedural Call Graph (up to depth `4` across imported project modules), and Data-Flow Graph (DFG) to inventory **every concrete operation performed inside that endpoint**: authentication/RBAC guards, request/response schemas, SQL/ORM/Cypher database reads & writes, outbound HTTP/AI API calls, filesystem I/O, OS command execution, and secret/crypto operations.
   - Surfaces an interactive **API Endpoints & Operations Explorer** (in Stage 3 `3. 360° Map & Threats` and Stage 4 `SAST+ Attack Surface`) featuring a filterable inventory, an interactive directional **`Endpoint -> Helper Functions -> Concrete Operations` ReactFlow graph** (with `18x18` outer-border arrowheads and numbered steps `① -> ② -> ③`), a code-anchored Operation Timeline, and 1-click navigation into the Stage 2 Monaco IDE.

---

## 2. Pillar 1 — Native TruffleHog-Grade Secret Scanner & Live Key Validation Engine

### 2.1 Architecture & Module Boundary (`backend/engine/secret_validator_engine.py`)

`SecretValidatorEngine` is a self-contained backend service invoked automatically during `/api/scan` (enriching existing CPG `RULE-8-HARDCODED-SECRET` / `IAC-1-COMPOSE-SECRET` findings and emitting additional `SECRET-TRUFFLE-GIT-HISTORY` / `SECRET-TRUFFLE-DETECTOR` findings for secrets missed by AST-only passes) and callable on demand via REST endpoints.

#### Supported Detector Families & Verification Modes

| Detector ID | Provider / Credential Class | Structural Detection Pattern | Live Read-Only Verification Probe (When `live_verification_enabled=True`) | Offline / Structural Validation |
|---|---|---|---|---|
| `github_pat` | GitHub Personal / Fine-Grained / OAuth Token | `ghp_`, `github_pat_`, `gho_`, `ghs_` | `GET https://api.github.com/user` (`Authorization: Bearer <token>`) -> extracts `login` & `X-OAuth-Scopes` | Prefix + token length + base62 charset + Shannon entropy |
| `gitlab_pat` | GitLab Personal Access Token | `glpat-` token prefix | `GET https://gitlab.com/api/v4/personal_access_tokens/self` (`PRIVATE-TOKEN`) -> extracts token name/scopes | Prefix + length + charset check |
| `aws_iam` | AWS Access Key ID (+ paired Secret Access Key in nearby context) | `AKIA` / `ASIA` 20-char key ID + 40-char secret in same file/commit | Signed SigV4 `POST https://sts.amazonaws.com/` (`Action=GetCallerIdentity&Version=2011-06-15`) -> extracts Account ID & ARN; if no paired secret is present, marks `OFFLINE_STRUCTURALLY_VALID` | AWS key ID charset + known canary exclusion (`EXAMPLE`) |
| `openai_key` | OpenAI Project / User API Key | `sk-proj-`, `sk-svcacct-`, legacy `sk-` | `GET https://api.openai.com/v1/models` (`Authorization: Bearer <token>`) | Prefix + length + entropy check |
| `gemini_key` | Google Gemini / Cloud API Key | `AIza` 39-char key | `GET https://generativelanguage.googleapis.com/v1beta/models` (`x-goog-api-key: <token>`) | `AIza` prefix + exact 39-char base64url check |
| `anthropic_key` | Anthropic Claude API Key | `sk-ant-api03-` prefix | `GET https://api.anthropic.com/v1/models` (`x-api-key: <token>`, `anthropic-version: 2023-06-01`) | Prefix + length + entropy check |
| `stripe_key` | Stripe Live / Restricted / Test Secret Key | `sk_live_`, `rk_live_`, `sk_test_`, `rk_test_` | `sk_test_` / `rk_test_` classified immediately as `TEST_OR_PLACEHOLDER` unless probed; `sk_live_` / `rk_live_` probed via `GET https://api.stripe.com/v1/account` (`Authorization: Bearer <token>`) | Live vs. Test prefix + charset check |
| `slack_token` | Slack Bot / User Token & Incoming Webhook | `xoxb-`, `xoxp-`, `https://hooks.slack.com/services/...` | Bot/User token: `POST https://slack.com/api/auth.test` (`Authorization: Bearer <token>`) -> extracts workspace `team` & `user` | Segment structure + numeric team/app IDs |
| `sendgrid_key` | SendGrid API Key | `SG.` 2-dot-separated base64url segments | `GET https://api.sendgrid.com/v3/scopes` (`Authorization: Bearer <token>`) | 3-part `SG.<id>.<secret>` base64url check |
| `huggingface_token` | HuggingFace Hub Access Token | `hf_` 37-char token | `GET https://huggingface.co/api/whoami-v2` (`Authorization: Bearer <token>`) -> extracts username/type | Prefix + length + alpha charset check |
| `jwt_bearer` | Hardcoded Signed JWT | 3-part base64url `eyJ...` | Offline deterministic inspection (no arbitrary third-party host ping) | Base64url header/payload decode -> extracts `alg`, `iss`, `sub`, `exp` (flags unexpired vs. expired JWT) |
| `private_key_pem` | RSA / EC / OpenSSH / PKCS8 Private Key | `-----BEGIN .* PRIVATE KEY-----` | Offline deterministic inspection | Validates PEM header/footer balance & base64 body decode |
| `database_uri` | PostgreSQL / MySQL / MongoDB / Redis URI with embedded password | `(postgres|mysql|mongodb(\+srv)?|redis)://user:pass@host` | Offline deterministic inspection (never connects to user DBs) | Parses scheme, username, host, and non-placeholder password entropy |
| `generic_high_entropy` | Generic Assignment Credential (`RULE-8` / `IAC-1`) | AST/YAML secret assignment | Offline structural + placeholder/entropy check | Distinguishes real high-entropy secrets (`>= 3.5` bits/char) from placeholders (`changeme`, `example`, `xxx`, `todo`, `<...>`, env interpolations) |

### 2.2 Git Commit History Scanning (`.git` Hunter)

1. When scanning a target directory containing a `.git` folder and `scan_git_history = True` (default `True`), `SecretValidatorEngine.scan_git_history(target_dir, max_commits=50)` runs:
   - `git -C <resolved_target_dir> log -p -n 50 --no-color --unified=0` via `subprocess.run(..., shell=False, timeout=12)` with `GIT_TERMINAL_PROMPT=0`.
2. Only added lines (`+...`, excluding `+++ b/...`) across code/config files (excluding `docs/`, `*.md`, `*.png`, `*.lock`, `package-lock.json`, `.alastor_patches/`, and test fixture mocks) are inspected against the high-confidence detector table.
3. Deduplication:
   - If a secret literal is **already present in the current working tree**, the working-tree finding is annotated with `git_commit_sha` (when introduced in recent history) without creating a duplicate card.
   - If a secret literal was **deleted from the working tree** but still exists in `.git` commit history, ALASTOR emits a dedicated `Finding` (`rule_id="SECRET-GIT-HISTORY-LEAK"`, `scan_engine="SAST"`, `is_secret_finding=True`, `secret_source="GIT_HISTORY"`) with exact commit SHA, author, commit date, historical filepath, and remediation instructions (`git filter-repo` + immediate credential rotation).

### 2.3 Validation Verdicts, Caching, Security & Offline Mode

1. **Five Canonical Validation Statuses (`SecretValidationStatus`)**:
   - `VERIFIED_ACTIVE`: Live provider endpoint returned HTTP `200` confirming an active credential. Automatically upgrades finding severity to `CRITICAL` and populates `secret_verified_identity` (e.g., `"GitHub user @octocat (scopes: repo, workflow)"` or `"AWS Account 123456789012 (arn:aws:iam::...:user/deploy)"`).
   - `REVOKED_OR_INVALID`: Live provider endpoint explicitly returned HTTP `401` (or provider-specific invalid-auth payload such as Slack `{"ok": false, "error": "invalid_auth"}`), proving the leaked credential is currently inactive/revoked.
   - `OFFLINE_STRUCTURALLY_VALID`: Credential passes strict prefix, length, checksum/base64, entropy, or unexpired JWT structure checks, while outbound probing was either disabled (`Offline Mode`) or not applicable (`PEM`, `DB URI`, `JWT`, unpaired AWS key ID).
   - `TEST_OR_PLACEHOLDER`: Matches known documentation/test prefixes or canary strings (`sk_test_`, `rk_test_`, `EXAMPLE`, `changeme`, `dummy`, `placeholder`, `your_api_key`, `localhost` dummy DB password). Downgrades noise clearly for triagers.
   - `VERIFICATION_ERROR`: Outbound provider check timed out or hit HTTP `429` / `5xx` network error; structural validity is preserved alongside the error reason.
2. **Strict Outbound Probe Safety Invariants**:
   - Outbound HTTP probes use Python stdlib `urllib.request` with a custom no-redirect handler (`HTTPRedirectHandler` blocking all `30x` redirects), `timeout=4.0` seconds, and **strictly hardcoded `https://` official provider URLs** from an immutable allowlist (`api.github.com`, `gitlab.com`, `sts.amazonaws.com`, `api.openai.com`, `generativelanguage.googleapis.com`, `api.anthropic.com`, `api.stripe.com`, `slack.com`, `api.sendgrid.com`, `huggingface.co`). User-supplied hostnames are **never** contacted.
   - Verification results are cached in memory keyed by `sha256(detector_id + ":" + raw_secret)` (TTL `30` minutes) and executed via `ThreadPoolExecutor(max_workers=6)` so scanning 20 secrets adds `< 1.5s` wall-clock latency.
   - Raw secret values are **never** logged, **never** sent in query strings (even Gemini uses the `x-goog-api-key` HTTP header rather than `?key=`), and remain masked (`secret_value_masked`) unless RBAC `can_reveal_secrets` is authorized.
   - Config state (`live_verification_enabled: bool = True`, `scan_git_history: bool = True`, `max_git_commits: int = 50`) persists locally in `.alastor_vault/secret_scanner_config.json` (`0o600` permissions).

### 2.4 Backend Data Models & REST Endpoints (Pillar 1)

- **Extended `Finding` fields (`backend/models.py` & `frontend/src/types/cpg.ts`)**:
  - `secret_validation_status: Optional[Literal["VERIFIED_ACTIVE", "REVOKED_OR_INVALID", "OFFLINE_STRUCTURALLY_VALID", "TEST_OR_PLACEHOLDER", "VERIFICATION_ERROR"]] = None`
  - `secret_detector_id: Optional[str] = None`
  - `secret_verified_identity: Optional[str] = None`
  - `secret_validation_message: Optional[str] = None`
  - `secret_verified_at: Optional[str] = None`
  - `secret_source: Optional[Literal["WORKING_TREE", "GIT_HISTORY"]] = "WORKING_TREE"`
  - `secret_commit_sha: Optional[str] = None`
  - `secret_commit_author: Optional[str] = None`
- **REST Endpoints in `backend/main.py`**:
  - `GET /api/secrets/config` -> `SecretScannerConfigResponse` (`live_verification_enabled`, `scan_git_history`, `max_git_commits`, `supported_detectors_count`)
  - `POST /api/secrets/config` -> updates `.alastor_vault/secret_scanner_config.json` and returns `SecretScannerConfigResponse`
  - `GET /api/secrets/inventory` -> `SecretInventoryResponse` (all active + git-history secret findings with validation breakdowns: `verified_active_count`, `revoked_count`, `structurally_valid_count`, `test_placeholder_count`, `git_history_count`)
  - `POST /api/secrets/verify` -> accepts `{ finding_ids?: List[str], force_refresh?: bool, allow_live_network?: bool }`, runs live/structural verification across requested (or all) secret findings, updates cached findings in place, and returns updated `SecretInventoryResponse`.

---

## 3. Pillar 2 — Multi-Framework API Endpoints & CPG Operations Tracer

### 3.1 Architecture & Module Boundary (`backend/engine/api_operations_engine.py`)

`ApiOperationsEngine` analyzes all scanned workspace files + CPG AST/Call-Graph/DFG artifacts to produce a rich `ApiOperationsReport` (`GET /api/endpoints/operations` and embedded summary in `SastPlusSuiteResponse`).

### 3.2 Multi-Framework Endpoint Discovery

`ApiOperationsEngine.discover_endpoints(target_dir, discovered_files)` extracts every API endpoint with exact `filepath`, `start_line`, `end_line`, `http_method`, `route_path`, `framework`, `handler_name`, `request_params`, and `response_model`:

1. **Python — FastAPI / Starlette / APIRouter**:
   - Matches `@app.<method>("...")`, `@router.<method>("...")`, `@api_router.<method>("...")` (including multi-line decorators, `prefix=` on `APIRouter(prefix="/api/v1")`, `response_model=...`, `dependencies=[Depends(...)]`), plus the bound `def` / `async def` signature, typed query/path parameters, `Depends(...)` guards, and Pydantic `BaseModel` body arguments.
2. **Python — Flask / Blueprint & Django**:
   - Flask `@app.route("/path", methods=[...])`, `@bp.route(...)`, `@bp.get/post(...)`; Django `path("route/", views.fn)` / `re_path(...)` resolved to view functions in the workspace + `@api_view([...])` DRF decorators.
3. **TypeScript / JavaScript — Next.js App Router & Pages Router**:
   - `**/app/**/route.{ts,tsx,js,jsx}`: maps filesystem path segments (converting `[id]` -> `{id}`) and exported `export async function GET|POST|PUT|DELETE|PATCH|OPTIONS(req: NextRequest)` handlers.
   - `**/pages/api/**/*.{ts,tsx,js,jsx}`: maps `export default function handler(req, res)` with internal `req.method === "POST"` branching.
4. **TypeScript / JavaScript — Express / Fastify / Koa / NestJS**:
   - `app.get|post|put|delete|patch("/path", ...middlewares, handler)` and `router.<method>("/path", ...)` (extracting middleware chain names as `AUTH_GUARD` / `INPUT_VALIDATION` steps!).
   - NestJS `@Controller("prefix")` + `@Get("sub")` / `@Post("sub")` method decorators.
5. **Go / Java Spring Boot (Static AST/Pattern Support)**:
   - Go `http.HandleFunc("/path", fn)`, Gin/Echo `r.GET("/path", fn)`, Chi `r.Get("/path", fn)`; Java Spring `@RestController` / `@RequestMapping` + `@GetMapping` / `@PostMapping` / `@PutMapping` / `@DeleteMapping`.

### 3.3 Inter-Procedural CPG Operation Tracing (Depth <= 4)

For each discovered endpoint handler `(filepath, handler_name, start_line, end_line)`:

1. **Function Body & Call-Graph Index**:
   - Builds a workspace function symbol index `(filepath, func_name) -> {start_line, end_line, params, body_lines, called_symbols, imported_symbol_origins}` using Tree-Sitter AST nodes (from `ASTParser`) + `AppTreeAnalyzer` cross-file import resolution.
2. **BFS / DFS Call-Chain Traversal (`max_depth = 4`, cycle-safe visited set)**:
   - Walks statements inside the route handler in source-line order; whenever the handler invokes an intra-project helper function `helper_fn(...)` (same file or imported module), traverses into `helper_fn` (`hop_depth + 1`) attributing discovered operations with their full call chain (e.g., `dispatch_settlement() -> lookup_transaction() -> cursor.execute()`).
3. **8 Concrete Operation Categories (`ApiOperationCategory`: `"AUTH_GUARD" | "INPUT_VALIDATION" | "DATABASE_READ" | "DATABASE_WRITE" | "EXTERNAL_HTTP_OR_AI" | "FILESYSTEM_IO" | "OS_COMMAND_EXEC" | "SECRET_OR_CRYPTO"`)**:
   - `AUTH_GUARD`: `Depends(get_current_user)`, `Security(...)`, `jwt.decode`, `verify_token`, `check_rbac`, Express auth middlewares (`requireAuth`, `authenticate`, `verifyJwt`), NextAuth `getServerSession` / `auth()`, Django `@login_required` / `IsAuthenticated`.
   - `INPUT_VALIDATION`: Route/query/body parameter extraction (`req.json()`, `request.args`, `req.body`, `req.query`, Pydantic model validation, `zod.parse` / `safeParse`, `shlex.quote`, `int()`, `commonpath` confinement).
   - `DATABASE_READ` & `DATABASE_WRITE`:
     - Distinguishes **Read** (`SELECT`, `.find(`, `.findOne(`, `.objects.filter(`, `.objects.get(`, `session.query(`, Cypher `MATCH ... RETURN` without `CREATE`/`MERGE`/`DELETE`/`SET`) vs. **Write/Mutate** (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `.save()`, `.create()`, `.updateOne()`, `.deleteOne()`, `session.add()`, `session.commit()`, Cypher `CREATE` / `MERGE` / `SET` / `DETACH DELETE`).
     - Extracts target table / collection / node label when statically visible in the query string or ORM model name.
   - `EXTERNAL_HTTP_OR_AI`: Outbound HTTP calls (`requests.get/post`, `httpx.*`, `urllib.request.urlopen`, `fetch(`, `axios.*`) and AI SDK/API calls (`openai`, `genai`, `anthropic`, `FrontierAiEngine`) with target URL/host expression.
   - `FILESYSTEM_IO`: File reads (`open(..., "r")`, `Path.read_text`, `fs.readFile*`, `os.walk`), file writes/deletes (`open(..., "w"|"a"|"wb")`, `Path.write_text`, `fs.writeFile*`, `shutil.rmtree`, `os.remove`), and multipart file uploads (`UploadFile`).
   - `OS_COMMAND_EXEC`: `os.system`, `subprocess.run`, `subprocess.Popen`, `child_process.exec`, `child_process.spawn`.
   - `SECRET_OR_CRYPTO`: `os.getenv` / `os.environ` / `process.env` secret reads, `.alastor_vault` access, `hashlib.*`, `hmac.*`, `bcrypt`, `jwt.encode`, `secrets.token_*`.
4. **Endpoint Graph Synthesis (`flow_nodes` & `flow_edges`)**:
   - Every `ApiEndpointOperationDossier` pre-computes a clean directional flow graph (`Caller -> Route Entrypoint -> Auth/Validation Guards -> Helper Functions -> Concrete DB/FS/HTTP/OS Operations`), numbered `①`, `②`, `③`... so the frontend renders it instantaneously with `CustomGraphNode` and `DirectionalFlowEdge`.
5. **Security Posture & Finding Correlation**:
   - Links every active `Finding` whose `path_nodes` or `best_fix_location` overlaps the endpoint handler or any helper function in its transitive call chain!
   - Flags high-signal API risks automatically in the dossier summary (e.g., **Unauthenticated Mutating Endpoint** when `http_method in ("POST", "PUT", "DELETE", "PATCH")`, performs `DATABASE_WRITE` / `FILESYSTEM_IO` / `OS_COMMAND_EXEC`, and has `0` `AUTH_GUARD` operations).

### 3.4 Backend Data Models & REST Endpoints (Pillar 2)

- **Models (`backend/models.py` & `frontend/src/types/cpg.ts`)**:
  - `ApiOperationItem`: `id`, `step_index`, `category`, `operation_verb` (e.g., `"SQL SELECT"`, `"Cypher MERGE"`, `"HTTP POST"`, `"File Write"`, `"Subprocess Run"`), `target_resource`, `function_name`, `call_chain: List[str]`, `filepath`, `line_number`, `code_snippet`, `is_mutating: bool`, `risk_note: Optional[str]`.
  - `ApiEndpointOperationDossier`: `id`, `method`, `route_path`, `framework`, `handler_name`, `filepath`, `start_line`, `end_line`, `auth_status: Literal["AUTHENTICATED", "UNAUTHENTICATED", "PARTIAL_OR_CUSTOM"]`, `auth_mechanisms: List[str]`, `request_params: List[str]`, `response_type: Optional[str]`, `operations: List[ApiOperationItem]`, `operation_categories: List[str]`, `calls_functions: List[str]`, `is_mutating: bool`, `risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]`, `linked_finding_ids: List[str]`, `linked_findings_count: int`, `plain_english_story: str`, `flow_nodes: List[Dict[str, Any]]`, `flow_edges: List[Dict[str, Any]]`.
  - `ApiOperationsReportResponse`: `project_path`, `total_endpoints`, `authenticated_count`, `unauthenticated_count`, `mutating_endpoints_count`, `db_endpoints_count`, `external_http_endpoints_count`, `exec_or_fs_endpoints_count`, `vulnerable_endpoints_count`, `frameworks_detected: List[str]`, `endpoints: List[ApiEndpointOperationDossier]`.
- **REST Endpoint in `backend/main.py`**:
  - `GET /api/endpoints/operations` -> returns `ApiOperationsReportResponse` for the currently active workspace.

---

## 4. Frontend UX & Daylight Theme Integration

### 4.1 Secret Validation Controls & Badges
1. **Stage 2 (`FlawExplorerSidebar.tsx` & `MonacoCodePane.tsx`)**:
   - Secret cards in `FlawExplorerSidebar.tsx` display:
     - Validation badge: `VERIFIED ACTIVE` (high-contrast crimson `bg-rose-100 text-rose-900 border-rose-400`), `REVOKED / INACTIVE` (`bg-emerald-50 text-emerald-900 border-emerald-300`), `STRUCTURALLY VALID` (`bg-amber-50 text-amber-900 border-amber-300`), or `TEST / MOCK` (`bg-slate-100 text-slate-800 border-slate-300`).
     - Source badge when from git history: `GIT COMMIT <short_sha>` (`bg-purple-50 text-purple-900 border-purple-300`).
     - `Verify Key` button right beside `Reveal Key` so operators can trigger or refresh live validation on a single secret in 1 click, displaying `secret_verified_identity` / `secret_validation_message` inline.
2. **Stage 3 (`ThreatModelingView.tsx` -> `Secret Keys & Credentials Vault` Tab)**:
   - Top Vault Control Bar with:
     - **KPI Counters**: `Total Secrets` · `🔴 Verified Active (Live)` · `🟢 Revoked / Inactive` · `🟡 Structurally Valid` · `🕒 Git Commit History`.
     - **`Auto-Verify Live Keys` Switch** (`LIVE PROBES ON` vs. `OFFLINE MODE` persisted via `POST /api/secrets/config`) + **`Scan .git History`** toggle + **`Verify All Keys Now`** button.
     - Quick Filter Pills (`All` · `Verified Active` · `Git History` · `Structurally Valid` · `Revoked / Test`).
   - Each Vault Credential Card displays detector type, Shannon entropy, validation badge, verified identity/message, git commit metadata (if historical), RBAC-gated reveal/copy, single-key `Re-Verify`, and `Locate Key in Code`.

### 4.2 Interactive `API Endpoints & Operations Explorer` (`frontend/src/components/ApiOperationsExplorerView.tsx`)
1. **Navigation Placement (Zero Clutter, 4-Stage Architecture Preserved)**:
   - **Stage 3 (`3. 360° Map & Threats` in `page.tsx` & `MapSubTab` in `cpg.ts`)**: Adds a 3rd top pill **`API Endpoints & Operations ({count})`** (`mapSubTab === "API_OPERATIONS"`) right beside `360° Architecture & Call Flows` and `Trust Boundaries, STRIDE & PBOM`, plus a shortcut entry in `Ctrl+K` (`QuickCommandModal.tsx`).
   - **Stage 4 (`SastPlusSuiteView.tsx` Pillar 3 `ATTACK_SURFACE`)**: Embeds `ApiOperationsExplorerView` directly inside Pillar 3 (replacing the basic 6-column dark static table) AND upgrades remaining dark `bg-zinc-950`/`text-zinc-200` classes in `SastPlusSuiteView.tsx` to crisp WCAG AA Daylight tokens (`bg-white`, `bg-slate-50`, `text-slate-900`, `border-slate-200`).
2. **Explorer Layout & Capabilities**:
   - **Top Executive Summary Strip**: KPI cards (`Total API Endpoints`, `Database Read/Write Routes`, `External HTTP / AI Routes`, `File / OS Command Routes`, `Unauthenticated Mutating Routes`, `Routes with Active Flaws`) + `Export API Inventory (.json / .csv)`.
   - **Left Master List (Searchable & Filterable)**:
     - Search by route path, handler name, file, or resource (`users`, `SELECT`, `stripe`, etc.).
     - Filter pills by HTTP Method (`ALL`, `GET`, `POST`, `PUT`, `DELETE`, `PATCH`), Operation Category (`DB_WRITE`, `DB_READ`, `EXTERNAL_HTTP`, `FILE_IO`, `OS_EXEC`, `SECRET_CRYPTO`), and Auth/Risk (`Unauthenticated`, `With Flaws`).
     - Each endpoint card shows color-coded HTTP method badge, route path, framework chip, `filepath:line`, auth badge, and compact operation count pills.
   - **Right Detail Inspector (Selected Endpoint)**:
     - **Header & Plain-English Story Banner**: Explains end-to-end what the endpoint accepts, how it authenticates, what internal helpers it calls, and what operations/side-effects it performs, with **`Open Handler in IDE`** and **`Explain Endpoint with Frontier AI`** buttons.
     - **Interactive Directional `Endpoint -> Helpers -> Operations` ReactFlow Canvas**: Renders `flow_nodes` and `flow_edges` using `CustomGraphNode` + `DirectionalFlowEdge` (`LR` Left-to-Right layout, `18x18` outer-border arrowheads, numbered badges `① -> ② -> ③`, clickable nodes jumping straight to `filepath:line` in Stage 2).
     - **Step-by-Step Operations Timeline Table**: Ordered list of every operation (`Step #`, `Category Badge`, `Operation Verb & Resource`, `Call Chain`, `File:Line`, `Code Snippet`, `Inspect in IDE`).
     - **Parameters, Auth Guards & Linked Vulnerabilities Strip**: Shows extracted route/body parameters, detected auth guards (or warning banner if mutating + unauthenticated), and clickable cards for any linked CPG vulnerabilities.

---

## 5. Error Handling, Edge Cases & Verification Plan

1. **Graceful Degradation**:
   - Repositories without `.git` (uploaded zip/snippets) skip `scan_git_history` cleanly without warnings.
   - Codebases with zero HTTP routes (e.g., pure CLI libraries) return `total_endpoints: 0` cleanly and offer callable module entrypoints context without UI errors.
   - Provider rate-limits or offline networks during live key verification catch `URLError`/`HTTPError`/`TimeoutError` per-key within `4.0s` and fall back to structural metadata without failing `/api/scan`.
2. **Automated Verification Suite**:
   - **`backend/tests/test_secret_validator_engine.py`**:
     - Tests detector extraction across GitHub, AWS (paired + unpaired), OpenAI, Gemini, Anthropic, Stripe (`sk_live_` vs `sk_test_`), Slack, JWT (expired vs unexpired), PEM, and DB URIs.
     - Tests mocked HTTP `200` (`VERIFIED_ACTIVE` + severity upgrade to `CRITICAL`), HTTP `401` (`REVOKED_OR_INVALID`), `Offline Mode` (`live_verification_enabled=False` -> zero network calls, `OFFLINE_STRUCTURALLY_VALID`), SHA-256 verification caching, redirect blocking (`302` rejected), and real temporary `.git` repository commit-then-delete history detection (`SECRET-GIT-HISTORY-LEAK`).
   - **`backend/tests/test_api_operations_engine.py`**:
     - Tests multi-framework route extraction across FastAPI (`@app.get`/`@router.post` + `Depends`), Next.js App Router (`app/api/orders/[id]/route.ts`), and Express (`router.delete`).
     - Tests inter-procedural operation tracing (`route -> service_helper -> SQL INSERT + external requests.post + open(..., "w") + subprocess.run`), `AUTHENTICATED` vs `UNAUTHENTICATED` mutating detection, directional `flow_nodes`/`flow_edges` step numbering, and `/api/endpoints/operations` REST response.
   - **Frontend & Full-Stack Gates**:
     - `npx tsc --noEmit` and `npm run build` (`0` errors).
     - WCAG AA Light-Mode contrast check across `ApiOperationsExplorerView.tsx`, `ThreatModelingView.tsx`, `FlawExplorerSidebar.tsx`, and `SastPlusSuiteView.tsx`.
     - `verify_harness.py` (`20/20` passing) + ALASTOR self-audit on `cpg-sast-platform` (`0` active findings — verifying ALASTOR discovers its own `40+` FastAPI endpoints & operations accurately while reporting `0` secret leaks or vulnerabilities!).
