# ALASTOR v5.0 Pillar 2 — 17-Lens Cognitive Semantic Hunter, S6 Adversarial Verifier, S8 Multi-Hop Exploit Chains & S11 Dual-Verified 3-Persona Patch Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver 100% of VVAH's cognitive security discovery, adversarial verification, multi-hop exploit chaining, and 3-persona patch validation—upgraded with a Hybrid Deterministic-First (\$0 Offline) + CPG-Micro-Sliced BYOK architecture, automatic CPG Sibling Sweeps, hostile prompt-injection stripping, PASTA Stage VI & `.docx`/`.pdf` SAR auto-injection, and a Light-Only Daylight UI workbench.

**Architecture:** Expose a thin `dispatch_structured_json(...)` + `strip_hostile_target_instructions(...)` seam on `FrontierAiEngine`, then isolate Pillar 2 into three focused specialist engines (`security_playbooks.py`, `adversarial_verifier.py`, `exploit_chain_engine.py`), wire S8 chains directly into `pasta_threat_engine.py` and `sar_report_generator.py`, expose 5 confined `/api/cognitive/*` endpoints in `main.py`, and render the interactive Light-Only Daylight `CognitiveSecurityWorkbench.tsx` (in `ThreatModelingView.tsx`) plus the S11 3-Persona Patch Panel (in `FrontierAiCopilotDrawer.tsx`).

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, existing `FrontierAiEngine` BYOK providers (`Gemini`, `OpenAI`, `Anthropic`, `Ollama`), Dual Neo4j/SQLite `GraphStore`, `python-docx`, `reportlab`, Next.js 15 / React 19, TypeScript, Zustand, `reactflow` (`11.11.4`) + `@dagrejs/dagre`, Tailwind CSS (Light-Only Daylight WCAG AA `>= 4.5:1`).

## Global Constraints

- **Work on `main` only** in `c:\Projects\Securecodereview\cpg-sast-platform`; preserve 100% of existing ALASTOR v4.0 + Pillar 1 capabilities (all 194 existing backend tests must remain passing).
- **Hybrid \$0 Offline + BYOK AI:** Every Pillar 2 capability MUST work deterministically at \$0 when no LLM API key is configured, and seamlessly upgrade to CPG-micro-sliced BYOK reasoning when credentials exist.
- **Security Invariants:**
  - Workspace path confinement (`os.path.realpath` + `os.path.commonpath` against `_get_ai_allowed_roots()`; HTTP `400` on traversal).
  - Never read or forward target `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, or `.github/copilot-instructions.md` into LLM prompts (`strip_hostile_target_instructions`).
  - Hostile-patch post-gate in S11 fails closed (`REJECTED`) on prompt-injected `subprocess`/`os.exec*`/`os.spawn*`/`asyncio.create_subprocess*`/`ctypes`/`eval`/`exec`/home-dir secret reads (`~/.ssh`, `/etc/passwd`, `id_rsa`, `.env`).
  - Zero raw secret leakage across `/api/cognitive/*`, PASTA, and `.docx`/`.pdf` SAR exports; sanitized logs via `_sanitize_log`.
- **Light-Only Daylight UI (`>= 4.5:1` WCAG AA):** `#f8fafc` / `#ffffff` surfaces, `slate-900`/`800`/`700` text, high-contrast semantic pills; zero dark-only backgrounds; `reactflow` `11.11.4` with module-scoped `nodeTypes`/`edgeTypes`.
- **Zero Production Self-Audit Findings:** Maintain `0` findings across production files; do NOT touch or stage `.superpowers/` or `synthetic_test_target/.vvaharness/`.

---

## File Map

| File | Action | Responsibility |
| :--- | :--- | :--- |
| `backend/models.py` | Modify | Section 15 Pydantic models (`PlaybookDefinitionItem`, `RepoBaselineItem`, `CognitivePlaybooksResponse`, `CognitiveHuntRequest/Response`, `AdversarialVerifyRequest/Response`, `AdversarialFindingVerdict`, `ExploitChainHop/Item/Request/Response`, `PersonaReviewItem`, `PatchPanelValidateRequest/Response`) |
| `backend/engine/frontier_ai_engine.py` | Modify | Add `has_usable_credentials()`, `strip_hostile_target_instructions()`, `is_hostile_instruction_file()`, and `dispatch_structured_json(...)` reusing SSRF-hardened BYOK dispatch & SHA-256 caching |
| `backend/engine/security_playbooks.py` | Create | All 17 VVAH specialist playbooks, Repo-Kind Auto-Baseline engine (`web-api`, `web-template`, `mobile`, `iac`, `native`, `library`), deterministic `COG-1..COG-5` semantic probes, BYOK micro-sliced deep hunt, and automatic CPG Sibling Sweeps |
| `backend/engine/adversarial_verifier.py` | Create | S6 Adversarial Verifier (Exclusion Rules A–F, CVSS 3.1 vector/score, offline + BYOK) and S11 Dual-Verified 3-Persona Patch Review Panel (AST syntax + hostile-patch post-gate + CPG severance + `Security Architect` / `Penetration Tester` / `Cross-Repo Analyzer`) |
| `backend/engine/exploit_chain_engine.py` | Create | S8 Multi-Hop Exploit Chain Synthesizer across entrypoints, secrets, findings, Leiden communities, and Crown Jewels + ReactFlow graph builder |
| `backend/engine/pasta_threat_engine.py` | Modify | Accept optional `exploit_chains` into Stage VI Attack Trees (`S8_EXPLOIT_CHAIN` scenarios) |
| `backend/engine/sar_report_generator.py` | Modify | Render confirmed S8 Multi-Hop Exploit Chains in Section 5 of `.docx` and `.pdf` SAR Go-Live Dossiers (strictly scrubbed) |
| `backend/engine/enterprise_manager.py` | Modify | Register `COG-1..COG-5` rules in default catalog and add plain-English / RACI / STRIDE / PASTA enrichment |
| `backend/main.py` | Modify | Expose 5 confined `/api/cognitive/*` routes (`playbooks`, `hunt`, `adversarial-verify`, `exploit-chains`, `validate-patch`) and wire S8 chains into PASTA & SAR exports |
| `backend/tests/test_cognitive_playbooks_and_verifier.py` | Create | TDD suite for 17 playbooks, Repo-Kind baselines, `COG-1..5` probes, Sibling Sweeps, prompt-injection stripping, S6 verifier, and S11 3-persona hostile-patch rejection |
| `backend/tests/test_exploit_chains_and_cognitive_api.py` | Create | TDD suite for S8 chains, PASTA/SAR `.docx`/`.pdf` injection, all 5 `/api/cognitive/*` routes, confinement HTTP `400`, and zero secret leaks |
| `frontend/src/types/cpg.ts` | Modify | Add 1-to-1 TypeScript interfaces for Pillar 2 cognitive models |
| `frontend/src/lib/api.ts` | Modify | Add 5 API client functions for `/api/cognitive/*` |
| `frontend/src/store/useAuditStore.ts` | Modify | Add Pillar 2 cognitive state slices & actions (`fetchCognitivePlaybooks`, `runCognitiveSemanticHunt`, `runAdversarialVerification`, `fetchExploitChains`, `runPatchPanelValidation`) |
| `frontend/src/components/CognitiveSecurityWorkbench.tsx` | Create | Light-Only Daylight workbench: 17-Lens Playbooks & Repo-Kind Baseline matrix, S6 Adversarial Verifier table, and S8 Multi-Hop Exploit Chain ReactFlow canvas |
| `frontend/src/components/ThreatModelingView.tsx` | Modify | Mount `COGNITIVE_HUNTER` (`Cognitive Hunt & Chains`) 3rd sub-tab alongside `STRIDE` and `PASTA_WORKBENCH` |
| `frontend/src/components/FrontierAiCopilotDrawer.tsx` | Modify | Wire S11 Dual-Verified 3-Persona Patch Panel inside the `PATCH` tab |

---

### Task 1: Pillar 2 Models, Shared BYOK Structured Dispatch + Prompt-Injection Stripper, and 17-Lens `security_playbooks.py`

**Files:**
- Modify: `backend/models.py`
- Modify: `backend/engine/frontier_ai_engine.py`
- Create: `backend/engine/security_playbooks.py`
- Create: `backend/tests/test_cognitive_playbooks_and_verifier.py`

**Interfaces:**
- Consumes: `compiler.scanner.scan_directory_with_telemetry`, `engine.api_operations_engine.ApiOperationsEngine`, `engine.frontier_ai_engine.FrontierAiEngine`, `models.*`.
- Produces:
  - `backend/models.py`: Section 15 Cognitive Pydantic models (exact types listed in File Map).
  - `backend/engine/frontier_ai_engine.py`: `is_hostile_instruction_file(filepath: str) -> bool`, `strip_hostile_target_instructions(text: str) -> str`, `FrontierAiEngine.has_usable_credentials() -> bool`, `FrontierAiEngine.dispatch_structured_json(workflow: str, system_prompt: str, user_prompt: str, cache_material: str, max_output_tokens: int = 1800) -> Tuple[Optional[Dict[str, Any]], bool, Optional[str]]`.
  - `backend/engine/security_playbooks.py`:
    - `PLAYBOOK_CATALOG: List[PlaybookDefinitionItem]` (all 17 VVAH playbooks: 15 lenses + 2 methods)
    - `COGNITIVE_RULE_CATALOG: List[Dict[str, Any]]` (`COG-1-IDOR-BOLA` through `COG-5-CLIENT-POSTMESSAGE-STORAGE`)
    - `classify_repo_kinds_and_baselines(target_dir: str, scanned_files: List[ScannedFile], active_findings: List[Finding], api_ops: Optional[ApiOperationsReportResponse] = None, executed_playbooks: Optional[Set[str]] = None) -> CognitivePlaybooksResponse`
    - `run_cognitive_hunt(target_dir: str, active_findings: List[Finding], ai_engine: Optional[FrontierAiEngine] = None, playbook_ids: Optional[List[str]] = None, use_ai: bool = False, community_map: Optional[CommunityMapResponse] = None, api_ops: Optional[ApiOperationsReportResponse] = None) -> CognitiveHuntResponse`
    - `run_cpg_sibling_sweep(target_dir: str, seed_findings: List[Finding], scanned_files: List[ScannedFile]) -> List[Finding]`

- [ ] **Step 1: Write failing TDD tests in `backend/tests/test_cognitive_playbooks_and_verifier.py`**
  - Verify all 17 VVAH playbooks exist (`15` lenses + `2` methods: `code-exploration`, `sibling-instances`).
  - Verify `is_hostile_instruction_file` flags `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md` and `strip_hostile_target_instructions` neutralizes prompt-injection overrides.
  - Verify `classify_repo_kinds_and_baselines` detects `web-api` (10 baseline items), `native` (6 items), `iac` (5 items), `web-template` (4 items), `mobile` (5 items), and `library` (4 items), marking uncovered categories `UNDISPOSED_GAP` and matched findings `FINDING_DETECTED`.
  - Verify deterministic `$0` `run_cognitive_hunt(..., use_ai=False)` detects:
    - `COG-1-IDOR-BOLA` on unguarded `/orders/{order_id}` DB mutation (and does NOT flag when `owner_id == current_user.id` check exists!)
    - `COG-2-BUSINESS-LOGIC-TOCTOU` on balance transfer lacking non-negative check / transaction lock
    - `COG-3-CORS-CSRF-CONTROLS` on wildcard CORS + `allow_credentials=True` and `httponly=False` cookie
    - `COG-4-SENSITIVE-DATA-EXPOSURE` on returning `password_hash` / `traceback.format_exc()`
    - `COG-5-CLIENT-POSTMESSAGE-STORAGE` on `addEventListener("message", ...)` missing `.origin` check and `localStorage.setItem("access_token", ...)`
  - Verify automatic **CPG Sibling Sweep** finds a sibling unguarded route in another file when seeded with a confirmed IDOR route.
  - Verify `use_ai=True` with mocked `dispatch_structured_json` strips `CLAUDE.md`, validates real `file:line` coordinates on disk, and drops hallucinated non-existent file paths!

- [ ] **Step 2: Run test to verify RED**
  `..\.venv\Scripts\python.exe -m pytest tests/test_cognitive_playbooks_and_verifier.py -v` -> FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `backend/models.py` Section 15, `backend/engine/frontier_ai_engine.py` helpers, and `backend/engine/security_playbooks.py`**

- [ ] **Step 4: Run tests and full pytest suite to verify GREEN**
  `..\.venv\Scripts\python.exe -m pytest tests/test_cognitive_playbooks_and_verifier.py -v` and `..\.venv\Scripts\python.exe -m pytest -q`.

- [ ] **Step 5: Commit Task 1**
  ```powershell
  git add backend/models.py backend/engine/frontier_ai_engine.py backend/engine/security_playbooks.py backend/tests/test_cognitive_playbooks_and_verifier.py
  git commit -m "feat(cognitive): add Pillar 2 models, prompt-injection stripping, 17-lens playbooks, and deterministic semantic hunter"
  ```

---

### Task 2: S6 Adversarial Verifier & S11 Dual-Verified 3-Persona Patch Review Panel (`backend/engine/adversarial_verifier.py`)

**Files:**
- Create: `backend/engine/adversarial_verifier.py`
- Modify: `backend/tests/test_cognitive_playbooks_and_verifier.py`

**Interfaces:**
- Consumes: `models.*` (Section 15), `engine.frontier_ai_engine.FrontierAiEngine`, `compiler.ast_parser.ASTNormalizer`, `compiler.dfg_builder.DFGBuilder`, `compiler.language_registry.resolve_language_for_filename`.
- Produces:
  - `backend/engine/adversarial_verifier.py`:
    - `EXCLUSION_RULES: Dict[str, str]` (Rules A–F)
    - `verify_findings_adversarially(target_dir: str, findings: List[Finding], ai_engine: Optional[FrontierAiEngine] = None, finding_ids: Optional[List[str]] = None, use_ai: bool = False) -> AdversarialVerifyResponse`
    - `check_hostile_patch_post_gate(original_code: str, proposed_code: str, cwe_id: Optional[str] = None) -> Tuple[bool, List[str]]` (returns `(is_safe, blocked_reasons)`)
    - `validate_patch_with_panel(target_dir: str, req: PatchPanelValidateRequest, finding: Optional[Finding] = None, ai_engine: Optional[FrontierAiEngine] = None) -> PatchPanelValidateResponse`

- [ ] **Step 1: Add failing TDD tests to `backend/tests/test_cognitive_playbooks_and_verifier.py`**
  - Verify S6 deterministic verification:
    - Reachable real finding on disk -> `TRUE_POSITIVE` with valid `CVSS:3.1/...` vector and score.
    - Finding in `tests/test_demo.py` -> `FALSE_POSITIVE` with `exclusion_rule == "RULE_E_TEST_OR_FIXTURE_ONLY"`.
    - Finding pointing to non-existent file on disk -> `FALSE_POSITIVE` with `exclusion_rule == "RULE_F_NOISE_FLOOR"`.
    - Secret finding with `secret_validation_status == "TEST_OR_PLACEHOLDER"` -> `FALSE_POSITIVE`.
    - Hybrid BYOK S6 mode (mocked `dispatch_structured_json`) honors structured AI verdict & CVSS 3.1 vector while still scrubbing raw secrets!
  - Verify S11 Dual-Verified 3-Persona Panel:
    - Clean parameterized SQL / `shlex.quote` patch -> `syntax_ok=True`, `hostile_patch_blocked=False`, `cpg_sink_severed=True`, 3 distinct personas (`Security Architect`, `Penetration Tester`, `Cross-Repo Analyzer`), `overall_verdict == "APPROVED"`.
    - Broken Python syntax patch -> `syntax_ok=False`, `overall_verdict == "REJECTED"`.
    - Prompt-injected hostile patch introducing `import subprocess as sp; sp.Popen(...)`, `ctypes`, `os.execv`, or reading `~/.ssh/id_rsa` -> `hostile_patch_blocked=True`, `overall_verdict == "REJECTED"` **even if mocked AI personas vote `APPROVE`**!
    - Narrow CWE-78 list-argv fix (`subprocess.run(["ls", target], shell=False)`) -> permitted by hostile-patch post-gate (`hostile_patch_blocked=False`).

- [ ] **Step 2: Run tests to verify RED**
  `..\.venv\Scripts\python.exe -m pytest tests/test_cognitive_playbooks_and_verifier.py -v` -> FAIL.

- [ ] **Step 3: Implement `backend/engine/adversarial_verifier.py`**

- [ ] **Step 4: Run tests and full pytest suite to verify GREEN**

- [ ] **Step 5: Commit Task 2**
  ```powershell
  git add backend/engine/adversarial_verifier.py backend/tests/test_cognitive_playbooks_and_verifier.py
  git commit -m "feat(cognitive): add S6 adversarial verifier with CVSS 3.1 and S11 dual-verified 3-persona patch panel"
  ```

---

### Task 3: S8 Multi-Hop Exploit Chain Synthesizer, PASTA Stage VI & SAR `.docx`/`.pdf` Integration, and Confined `/api/cognitive/*` Endpoints

**Files:**
- Create: `backend/engine/exploit_chain_engine.py`
- Modify: `backend/engine/pasta_threat_engine.py`
- Modify: `backend/engine/sar_report_generator.py`
- Modify: `backend/engine/enterprise_manager.py`
- Modify: `backend/main.py`
- Create: `backend/tests/test_exploit_chains_and_cognitive_api.py`

**Interfaces:**
- Consumes: `engine.security_playbooks`, `engine.adversarial_verifier`, `engine.community_detector`, `engine.pasta_threat_engine`, `engine.sar_report_generator`, `engine.frontier_ai_engine`, `models.*`.
- Produces:
  - `backend/engine/exploit_chain_engine.py`: `synthesize_exploit_chains(target_dir: str, findings: List[Finding], api_ops: Optional[ApiOperationsReportResponse] = None, community_map: Optional[CommunityMapResponse] = None, ai_engine: Optional[FrontierAiEngine] = None, use_ai: bool = False) -> ExploitChainResponse`
  - `backend/engine/pasta_threat_engine.py`: `evaluate_pasta(..., exploit_chains: Optional[List[ExploitChainItem]] = None)` injects top confirmed S8 chains as `PastaAttackTreeScenario` entries in Stage VI!
  - `backend/engine/sar_report_generator.py`: Section 5 renders S8 Multi-Hop Exploit Chains table & narratives in both `.docx` and `.pdf` (redacted through `sanitize_bundle_for_export`).
  - `backend/engine/enterprise_manager.py`: Registers `COG-1..COG-5` in default query rules and plain-English/RACI/STRIDE/PASTA enrichment.
  - `backend/main.py`: 5 confined endpoints:
    - `GET /api/cognitive/playbooks`
    - `POST /api/cognitive/hunt`
    - `POST /api/cognitive/adversarial-verify`
    - `GET /api/cognitive/exploit-chains` & `POST /api/cognitive/exploit-chains`
    - `POST /api/cognitive/validate-patch`

- [ ] **Step 1: Write failing TDD tests in `backend/tests/test_exploit_chains_and_cognitive_api.py`**
  - Verify `synthesize_exploit_chains` stitches an exposed unauthenticated route + leaked active secret + IDOR/SQLi finding across Leiden communities into a multi-hop chain (`len(chain.hops) >= 3`, `chain.chain_cvss >= 8.0`, non-empty `nodes` + `edges`, `break_the_chain_fix` populated, zero raw secret leakage!).
  - Verify PASTA Stage VI includes S8 chains and `GET /api/export/sar-report?format=docx` + `format=pdf` render the S8 Exploit Chain title cleanly with zero raw secret leakage.
  - Verify all 5 `/api/cognitive/*` FastAPI endpoints return HTTP `200` on valid confined workspace, HTTP `400` on path traversal outside `_get_ai_allowed_roots()`, and persist/merge semantic findings cleanly!

- [ ] **Step 2: Run test to verify RED**
  `..\.venv\Scripts\python.exe -m pytest tests/test_exploit_chains_and_cognitive_api.py -v` -> FAIL.

- [ ] **Step 3: Implement `exploit_chain_engine.py`, wire `pasta_threat_engine.py`, `sar_report_generator.py`, `enterprise_manager.py`, and `main.py`**

- [ ] **Step 4: Run full pytest suite & ALASTOR self-audit to verify GREEN**

- [ ] **Step 5: Commit Task 3**
  ```powershell
  git add backend/engine/exploit_chain_engine.py backend/engine/pasta_threat_engine.py backend/engine/sar_report_generator.py backend/engine/enterprise_manager.py backend/main.py backend/tests/test_exploit_chains_and_cognitive_api.py
  git commit -m "feat(cognitive): add S8 multi-hop exploit chains, PASTA/SAR sync, and confined /api/cognitive endpoints"
  ```

---

### Task 4: Light-Only Daylight Frontend UI (`CognitiveSecurityWorkbench.tsx`, `ThreatModelingView.tsx`, `FrontierAiCopilotDrawer.tsx`) & Full-Stack Verification

**Files:**
- Modify: `frontend/src/types/cpg.ts`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/store/useAuditStore.ts`
- Create: `frontend/src/components/CognitiveSecurityWorkbench.tsx`
- Modify: `frontend/src/components/ThreatModelingView.tsx`
- Modify: `frontend/src/components/FrontierAiCopilotDrawer.tsx`

**Interfaces:**
- Consumes: All 5 `/api/cognitive/*` FastAPI endpoints from Task 3.
- Produces:
  - TypeScript types & API helpers for all Pillar 2 cognitive responses.
  - Zustand store slices (`cognitivePlaybooks`, `cognitiveHuntResult`, `adversarialVerdicts`, `exploitChains`, `patchPanelResult`, loading flags, and actions).
  - `CognitiveSecurityWorkbench.tsx`: Light-Only Daylight 3-panel workbench (17-Lens Playbooks & Repo-Kind Baseline Matrix, S6 Adversarial Verifier Table with 1-click apply-to-triage, and S8 Multi-Hop Exploit Chain ReactFlow `11.11.4` + `@dagrejs/dagre` canvas with click-to-jump into Monaco).
  - `ThreatModelingView.tsx`: Mounts `COGNITIVE_HUNTER` (`Cognitive Hunt & Chains`) sub-tab alongside `STRIDE` and `PASTA_WORKBENCH`.
  - `FrontierAiCopilotDrawer.tsx`: Adds **"Run S11 3-Persona + AST/CPG Validation"** inside the `PATCH` tab showing the 3 deterministic gates (`AST Syntax`, `Hostile-Patch Post-Gate`, `CPG Severance`) and 3 persona scorecards (`Security Architect`, `Penetration Tester`, `Cross-Repo Analyzer`).

- [ ] **Step 1: Add TypeScript types in `cpg.ts`, API clients in `api.ts`, and Zustand actions in `useAuditStore.ts`**
- [ ] **Step 2: Create `CognitiveSecurityWorkbench.tsx` and wire into `ThreatModelingView.tsx` and `FrontierAiCopilotDrawer.tsx`**
- [ ] **Step 3: Run `npx tsc --noEmit` (`0` errors), full `pytest -q` (`100%` pass), and ALASTOR self-audit (`0` production findings)**
- [ ] **Step 4: Commit Task 4**
  ```powershell
  git add frontend/src/types/cpg.ts frontend/src/lib/api.ts frontend/src/store/useAuditStore.ts frontend/src/components/CognitiveSecurityWorkbench.tsx frontend/src/components/ThreatModelingView.tsx frontend/src/components/FrontierAiCopilotDrawer.tsx
  git commit -m "feat(ui): add Cognitive Security Workbench (17-lens hunter, S6 verifier, S8 chains) and S11 3-persona patch panel"
  ```
