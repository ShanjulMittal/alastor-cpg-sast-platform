# ALASTOR v5.0 Pillar 2 Design Specification — 17-Lens Cognitive Semantic Hunter, Repo-Kind Baselines, S6 Adversarial Verifier, S8 Multi-Hop Exploit Chains & S11 Dual-Verified 3-Persona Patch Panel

**Date:** 2026-11-22  
**Status:** Approved in Brainstorming — Ready for Spec Review  
**Roadmap Context:** Pillar 2 of 5 in the ALASTOR v5.0 ("100% VVAH Parity + 300% Beyond") architecture evolution  
**Target Codebase:** `cpg-sast-platform` (`backend/` FastAPI + Dual Neo4j/SQLite CPG Engine, `frontend/` Next.js + ReactFlow + Monaco + Zustand)

---

## 1. Executive Summary & Goals

Pillar 2 brings **100% of VVAH's semantic cognitive discovery, adversarial verification, exploit chaining, and 3-persona patch validation** into ALASTOR—and extends **300% beyond VVAH** by executing a **Hybrid Deterministic-First (\$0 Offline) + CPG-Micro-Sliced BYOK Agentic Deep-Dive** architecture that works cleanly without any API key, slashes LLM token consumption by ~85% when BYOK AI (`Gemini`, `OpenAI`, `Anthropic`, `Ollama`) is configured, runs automatic **CPG Sibling Sweeps**, auto-injects confirmed **S8 Multi-Hop Exploit Chains** into **PASTA Stage VI Attack Trees & `.docx`/`.pdf` SAR Go-Live Dossiers**, and dual-verifies **S11 patches** with both the 3-persona review panel AND deterministic AST syntax + hostile-patch + CPG taint-severance gates.

All existing ALASTOR v4.0 + Pillar 1 capabilities (`18` Tree-sitter languages, dual `Neo4j` / `Embedded SQLite`, `33` deterministic rules, SCA/SBOM, Git-history Secret Validator, PASTA/STRIDE, `.docx`/`.pdf` SAR exports, Light-Only Daylight WCAG AA UI, and `0` production self-audit findings) remain **100% preserved**.

---

## 2. Backend Architecture & Module Boundaries

### 2.1 Shared BYOK Structured Dispatch (`backend/engine/frontier_ai_engine.py` — thin extension)
- Expose one reusable, thread-safe helper on `FrontierAiEngine`:
  - `has_usable_credentials() -> bool` (public accessor around `_has_usable_credentials()`)
  - `dispatch_structured_json(workflow: str, system_prompt: str, user_prompt: str, cache_material: str, max_output_tokens: int = 1800) -> Tuple[Optional[Dict[str, Any]], bool, Optional[str]]` returning `(parsed_json_or_none, cache_hit, error_message_or_none)`.
- Enforces all existing security invariants: SSRF-hardened provider URL allowlist + `_NoRedirectHandler`, zero raw credential leakage, SHA-256 verdict caching in `.alastor_vault/ai_verdict_cache.json`, and **strict hostile prompt-injection stripping** (`strip_hostile_target_instructions(text)` — strips/refuses target `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `copilot-instructions.md` files and sanitizes embedded instruction-override blocks before any model dispatch).

### 2.2 17-Lens Security Playbooks, Repo-Kind Auto-Baselines & CPG Sibling Sweeps (`backend/engine/security_playbooks.py` — new)

1. **17 Specialist Playbooks (`PLAYBOOK_CATALOG`)**:
   - **15 Lenses (`kind="LENS"`):** `access-control` (IDOR/BOLA/multi-tenant), `logic-bug` (money/quantity/race/TOCTOU/workflow skip), `csrf` (state-changing routes, unsafe `SameSite`, credentialed reflected/wildcard CORS), `ssrf` (outbound URL/webhook/proxy fetches), `templates` (server-rendered XSS/SSTI/form CSRF), `sensitive-data` (PII/tokens/password hashes/tracebacks in responses/logs), `missing-controls` (missing auth/rate-limit/cookie flags/debug enabled), `batch-etl` (bulk ingestion/generated SQL/trusted upstream jobs), `client-side` (DOM XSS, `localStorage` tokens, `postMessage` no origin check, prototype pollution), `crypto` (weak hashes/ciphers, predictable RNG, bad IV/TLS), `deserialization` (`pickle`, `yaml.load`, native object streams), `iac` (privileged containers, over-permissive IAM, unpinned CI), `injection` (SQL/NoSQL/OS/LDAP/XXE/CRLF/path traversal/ReDoS), `log-injection` (forged logs/CRLF/sensitive log leaks), `hardcoded-creds` (keys/secrets in source/config/manifests).
   - **2 Methods (`kind="METHOD"`):** `code-exploration` (directory-grouped architecture & surface inventory with coverage gap reporting) and `sibling-instances` (post-confirmation repository-wide pattern & CPG sibling sweep).
   - Each playbook defines `id`, `name`, `kind`, `description`, `cwe_ids`, `trigger_signals`, `hard_gate_criteria`, `false_positive_traps`, `real_mitigations`, and `supports_deterministic_probe`.

2. **Repo-Kind Auto-Baseline Engine (`classify_repo_kinds_and_baselines`)**:
   - Deterministically classifies the workspace into one or more kinds from `ScannedFile`, `AppTreeSummary`, manifests, and `ApiOperationsReportResponse`:
     - `web-api` (10 mandatory baseline items: OWASP `A01`, `A02`, `A03`, `A04`, `A05`, `A07`, `A08`, `A10`, `XSS`, `CSRF`)
     - `web-template` (4 items: unescaped output XSS, SSTI, missing form CSRF, secrets in markup)
     - `mobile` (5 items: OWASP Mobile `M1`, `M3`, `M5`, `M8`, `M9`)
     - `iac` (5 items: IAM/RBAC, network exposure, secrets in manifests, privileged containers, TLS/storage encryption)
     - `native` (6 items: `CWE-119/787`, `CWE-416`, `CWE-190`, `CWE-134`, `CWE-362`, `CWE-78`)
     - `library` (4 items: injection, unsafe deserialization, path traversal, ReDoS)
   - Evaluates each baseline item against active findings + executed playbook probes into explicit `status: Literal["COVERED_CLEAN", "FINDING_DETECTED", "UNDISPOSED_GAP"]` with linked finding IDs and evidence rationale so gaps never masquerade as clean coverage!

3. **Hybrid Semantic Hunter (`run_cognitive_hunt`)**:
   - **Stage A — \$0 Deterministic Semantic Probes (always runs, zero network/tokens):**
     - `COG-1-IDOR-BOLA` (`access-control`, `CWE-639`): Flags API routes accepting object identifiers (`/{id}`, `/{user_id}`, `/{order_id}`, `req.params.id`, `request.args['id']`) that perform DB/storage reads, updates, or deletes without an authorization/ownership check (`owner_id`, `user_id ==`, `tenant_id`, `current_user`, `Depends(`, `@login_required`, `@Authorize`, `authorize`, `check_permission`).
     - `COG-2-BUSINESS-LOGIC-TOCTOU` (`logic-bug`, `CWE-840` / `CWE-362`): Flags payment/transfer/balance/quantity/coupon handlers updating amounts without non-negative validation (`<= 0`, `> 0`, `abs(`, `Decimal`) or atomic lock/transaction guards (`SELECT ... FOR UPDATE`, `with transaction`, `Lock`, `atomic`).
     - `COG-3-CORS-CSRF-CONTROLS` (`csrf` / `missing-controls`, `CWE-942` / `CWE-352` / `CWE-614`): Flags credentialed wildcard/reflected CORS (`allow_origins=["*"]` + `allow_credentials=True` or `Access-Control-Allow-Origin: req.headers.origin` + credentials), cookies set with `httponly=False` or `secure=False`, or `DEBUG = True` in production web settings.
     - `COG-4-SENSITIVE-DATA-EXPOSURE` (`sensitive-data`, `CWE-200` / `CWE-532`): Flags HTTP responses/logs directly serializing `password_hash`, `secret_key`, `jwt_secret`, `credit_card`, `ssn`, or raw `traceback.format_exc()` to external callers.
     - `COG-5-CLIENT-POSTMESSAGE-STORAGE` (`client-side`, `CWE-345` / `CWE-922`): Flags `window.addEventListener("message", ...)` handlers missing `.origin` validation and JWT/auth tokens persisted directly in `localStorage.setItem(...)`.
   - **Stage B — Optional CPG-Micro-Sliced BYOK Agentic Deep-Dive (`mode="HYBRID_AI"` when credentials are configured):**
     - Selects highest-risk Leiden communities and unguarded API endpoints, packs `<=40`-line CPG micro-slices + matching lens playbook (strictly excluding `CLAUDE.md`/`AGENTS.md`/`.cursorrules`), parses typed JSON findings, and deterministically validates every `(filepath, line)` against real files inside the confined workspace root (dropping hallucinated coordinates!).
   - **Stage C — Automatic CPG Sibling Sweep (`sibling-instances`):**
     - For every confirmed semantic or high-severity finding, deterministically scans the workspace for sibling call/route/handler patterns sharing the same missing control or dangerous sink signature, emitting deduplicated `SIBLING_SWEEP` observations linked to the parent finding!

### 2.3 S6 Adversarial Verifier & S11 Dual-Verified 3-Persona Patch Panel (`backend/engine/adversarial_verifier.py` — new)

1. **S6 Adversarial Verifier (`verify_findings_adversarially`)**:
   - Evaluates each candidate finding against **Out-of-Scope Exclusion Rules A–F**:
     - `RULE_A_NO_REAL_ATTACKER` (unreachable dead/orphan non-entrypoint with no attacker input)
     - `RULE_B_NO_SECURITY_IMPACT` (informational/style-only with zero CIA impact)
     - `RULE_C_WRONG_LAYER` (defense enforced at verified boundary/middleware)
     - `RULE_D_HANDLED_ELSEWHERE` (domain-compatible sanitizer proven on CPG path)
     - `RULE_E_TEST_OR_FIXTURE_ONLY` (test/mock/example file outside production runtime)
     - `RULE_F_NOISE_FLOOR` (missing/invalid file coordinate on disk)
   - **Deterministic Mode (\$0 offline):** Validates file/line existence on disk, reachability status, domain-compatible sanitizer coverage, secret validation status (`VERIFIED_ACTIVE` vs `TEST_OR_PLACEHOLDER`), and computes deterministic CVSS 3.1 vector (`CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...`) and score.
   - **Hybrid BYOK Mode:** Sends a compressed CPG micro-slice + finding evidence + Exclusion Rules A–F through a devil's-advocate adversarial prompt to `FrontierAiEngine.dispatch_structured_json(...)` (SHA-256 cached), returning `verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"]`, `confidence` (`0–100`), `cvss_vector`, `cvss_score`, `exclusion_rule`, `adversarial_rationale`, and `verification_mode: Literal["DETERMINISTIC", "HYBRID_AI"]`.

2. **S11 Dual-Verified 3-Persona Patch Panel (`validate_patch_with_panel`)**:
   - Accepts `{ finding_id, filepath, original_code, proposed_code, use_ai }` (confined to workspace root via `_safe_resolve_under`).
   - **Gate 1 — Deterministic Safety & Hostile-Patch Post-Gate (\$0, ALWAYS runs — FAIL-CLOSED):**
     - **AST / Syntax Check:** `ast.parse` for Python; balanced delimiter/syntax check for JS/TS/Go/Java/etc.
     - **Hostile-Patch Post-Gate (VVAH S10/S11 parity+):** Blocks prompt-injected patches that newly introduce dangerous constructs not present in `original_code`: aliased or raw `subprocess`/`os.system`/`os.exec*`/`os.spawn*`/`asyncio.create_subprocess*`, `ctypes`, `eval`/`exec`, `curl`/`wget` exfiltration, or home-dir/host secret paths (`~/.ssh`, `/etc/passwd`, `.env`, `id_rsa`) — permitting `subprocess.run([...], shell=False)` ONLY as a narrow CWE-78 list-argv fix!
     - **CPG Taint-Severance Check:** Re-parses the patched file slice through `ASTNormalizer` + `DFGBuilder` to confirm whether the target vulnerable sink is neutralized!
   - **Gate 2 — 3-Persona Review Panel (`Security Architect`, `Penetration Tester`, `Cross-Repo Analyzer`):**
     - Produces 3 structured persona scorecards (`persona_id`, `persona_label`, `verdict: "APPROVE" | "CONCERN" | "REJECT"`, `score: 0..100`, `findings: List[str]`, `summary: str`).
     - Runs deterministic structural heuristics offline (\$0) and upgrades to BYOK 3-persona adversarial prompts when `use_ai=True` and credentials exist.
     - **Overall Verdict Rule:** Any deterministic gate failure (`syntax_ok == False` or `hostile_patch_blocked == True`) forces `overall_verdict = "REJECTED"` regardless of AI persona votes! Otherwise combines persona verdicts + CPG severance into `APPROVED | REVISIONS_REQUIRED | REJECTED`.

### 2.4 S8 Multi-Hop Exploit Chain Synthesizer (`backend/engine/exploit_chain_engine.py` — new) + PASTA/SAR Sync
- **Deterministic Multi-Hop Chain Stitching (`synthesize_exploit_chains`)**:
  - Builds an exploitability graph connecting:
    1. Exposed / unauthenticated API entrypoints (`ApiOperationsReportResponse`)
    2. Leaked credentials (`VERIFIED_ACTIVE` / `GIT_HISTORY` secret findings)
    3. CPG + Semantic findings (`RULE-1..33`, `COG-1..5`)
    4. Pillar 1 **Leiden Cross-Community & Polyglot Bridges** (`CommunityMapResponse`)
    5. Business Crown Jewels (`PastaAssessmentResponse`)
  - Discovers and ranks multi-step attack chains (up to top 10 highest-impact chains), computing:
    - `id`, `title`, `severity`, `chain_cvss` (amplified composite CVSS capped at `10.0`), `blast_radius_communities`, `hops: List[ExploitChainHop]`, `linked_finding_ids`, `break_the_chain_fix` (single highest-leverage BFL that severs the chain), `narrative`, and ReactFlow-ready `nodes` + `edges`.
  - Optionally enriches narratives via `FrontierAiEngine.dispatch_structured_json(...)` when `use_ai=True` and credentials exist.
- **PASTA Stage VI & SAR `.docx`/`.pdf` Auto-Injection:**
  - `PastaThreatEngine.evaluate_pasta(...)` accepts optional `exploit_chains: Optional[List[ExploitChainItem]] = None` and converts top confirmed S8 chains into `PastaAttackTreeScenario` entries (tagged `S8_EXPLOIT_CHAIN`) in Stage VI alongside CPG taint attack trees!
  - `sar_report_generator.py` renders confirmed S8 Multi-Hop Exploit Chains in **Section 5 (7-Stage PASTA & Attack Trees)** of both `.docx` Word and `.pdf` Adobe SAR Go-Live Dossiers (strictly scrubbed through `sanitize_bundle_for_export` with zero raw secret leakage!).

---

## 3. Data Models, API Routes & Daylight Frontend UI

### 3.1 New Pydantic Models (`backend/models.py` — Section 15)
- `PlaybookDefinitionItem`, `RepoBaselineItem`, `CognitivePlaybooksResponse`
- `CognitiveHuntRequest`, `CognitiveHuntResponse`
- `AdversarialVerifyRequest`, `AdversarialFindingVerdict`, `AdversarialVerifyResponse`
- `ExploitChainHop`, `ExploitChainItem`, `ExploitChainRequest`, `ExploitChainResponse`
- `PersonaReviewItem`, `PatchPanelValidateRequest`, `PatchPanelValidateResponse`

### 3.2 New FastAPI Endpoints (`backend/main.py`)
- `GET /api/cognitive/playbooks?project_path=...` -> `CognitivePlaybooksResponse`
- `POST /api/cognitive/hunt` -> `CognitiveHuntResponse`
- `POST /api/cognitive/adversarial-verify` -> `AdversarialVerifyResponse`
- `GET /api/cognitive/exploit-chains?project_path=...` & `POST /api/cognitive/exploit-chains` -> `ExploitChainResponse`
- `POST /api/cognitive/validate-patch` -> `PatchPanelValidateResponse`

### 3.3 Light-Only Daylight Frontend UI (`frontend/src/`)
- **`frontend/src/types/cpg.ts`, `frontend/src/lib/api.ts`, `frontend/src/store/useAuditStore.ts`**: Full 1-to-1 TypeScript interfaces, API clients, and Zustand slices (`cognitivePlaybooks`, `cognitiveHuntResult`, `adversarialVerdicts`, `exploitChains`, `patchPanelResult`, plus loading flags and actions).
- **`frontend/src/components/CognitiveSecurityWorkbench.tsx` (new)** mounted inside **`ThreatModelingView.tsx`** as a 3rd sub-tab (`Cognitive Hunt & Chains` alongside `STRIDE` and `PASTA 7-Stage & Attack Trees`):
  - **17-Lens Playbook & Repo-Kind Baseline Panel:** Shows detected repo kinds, mandatory baseline disposition pills (`COVERED_CLEAN`, `FINDING_DETECTED`, `UNDISPOSED_GAP`), lens toggles, and 1-click **"Run Semantic Hunt (\$0 / Hybrid BYOK)"**.
  - **S6 Adversarial Verifier Table:** Batch-verify active findings with Exclusion Rule A–F pills, CVSS 3.1 scorecards, `TRUE_POSITIVE`/`FALSE_POSITIVE` verdicts, and 1-click apply-to-triage.
  - **S8 Multi-Hop Exploit Chain ReactFlow Canvas (`reactflow` `11.11.4` + `@dagrejs/dagre`):** Interactive horizontal multi-hop chain diagram with click-to-jump into Monaco and live PASTA/SAR sync indicator.
- **`frontend/src/components/FrontierAiCopilotDrawer.tsx`**: Add **"Run S11 3-Persona + AST/CPG Validation"** inside the `PATCH` tab, displaying the 3 deterministic safety gates (`AST Syntax`, `Hostile-Patch Post-Gate`, `CPG Severance`) and the 3 persona scorecards (`Security Architect`, `Penetration Tester`, `Cross-Repo Analyzer`).

---

## 4. Security Invariants & Verification Plan

1. **Security Invariants:**
   - All `project_path` / `filepath` inputs validated via `os.path.realpath` + `os.path.commonpath` against `_get_ai_allowed_roots()` (HTTP `400` on traversal).
   - Target `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, and `.github/copilot-instructions.md` are **never** included in AI prompts (`strip_hostile_target_instructions`).
   - Hostile-patch post-gate fails closed (`REJECTED`) on injected `subprocess`/`os.exec*`/`ctypes`/secret-path code.
   - Zero raw secret leakage across all `/api/cognitive/*`, PASTA, and `.docx`/`.pdf` SAR outputs.
   - 100% Light-Only Daylight WCAG AA (`>= 4.5:1`) UI; zero DOM XSS sinks; zero production self-audit findings.
2. **TDD Suites:**
   - `backend/tests/test_cognitive_playbooks_and_verifier.py`: Tests all 17 playbooks, Repo-Kind classification & gap tracking, deterministic `COG-1..5` probes (IDOR/BOLA, Business Logic/TOCTOU, CORS/CSRF, Sensitive Data, Client `postMessage`/`localStorage`), automatic Sibling Sweep, prompt-injection stripping, S6 Exclusion Rules A–F + CVSS 3.1 (offline & mocked BYOK), and S11 Dual-Verified 3-Persona Panel (including hostile-patch rejection).
   - `backend/tests/test_exploit_chains_and_cognitive_api.py`: Tests S8 Multi-Hop Exploit Chain stitching across findings + secrets + Leiden communities, PASTA Stage VI & `.docx`/`.pdf` SAR auto-injection, all 5 `/api/cognitive/*` routes, confinement HTTP `400`, and zero secret leakage.
   - Full regression: `pytest -v` (`100%` pass), `npx tsc --noEmit` (`0` errors), ALASTOR self-audit (`0` production findings), and live `:8000`/`:3000` smoke verification.
