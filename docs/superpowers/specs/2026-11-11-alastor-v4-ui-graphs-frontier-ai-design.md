# ALASTOR v4.0 Design Specification — Directional Graphs & 360° Flow, Simplified Workflow UI, and Token-Efficient BYOK Frontier AI

**Date:** 2026-11-11  
**Status:** Approved in Brainstorming — Ready for User Spec Review  
**Target Codebase:** `cpg-sast-platform` (`backend/` FastAPI + Neo4j CPG Engine, `frontend/` Next.js + ReactFlow + Monaco + Zustand)

---

## 1. Executive Summary & Goals

ALASTOR v4.0 upgrades the platform across three tightly integrated pillars while strictly enforcing **zero feature reduction (reorganization + net-new additions only)** and **zero self-audit SAST findings**:

1. **Directional Graphs & 360° Flow Comprehension:** Make flow direction unmistakable across **every** graph and 360° view (Attack Path, Full CPG, DFG, CFG, Call Graph, Entrypoints, 360° Spider/Mind-Map Architecture Tree, Single-Node SCA/IaC Findings, and Trust Boundary Map) with 100% visible perimeter-docked arrowheads, animated directional edge chevrons + semantic labels, cross-file `IMPORTS`/`CALLS` dependency edges, hover/click upstream-downstream blast-radius highlighting, and a plain-English **Flow Story & Step Inspector**.
2. **Simplified 4-Stage Workflow UI (Option A):** Replace the current 5 overlapping navigation surfaces (blocking startup `AlastorPortalGate`, nested 7-category `Menu ▾`, 10-icon `LeftFunctionBar`, 3 stacked graph toolbars, and scattered sub-tabs) with a clean **Guided 4-Stage Workflow Bar** (*1. Scan & Repos · 2. Triage & Fix · 3. 360° Map & Threats · 4. ASPM, Rules & Reports*), progressive disclosure for advanced graph controls, centralized frontend API client (`frontend/src/lib/api.ts`), and net-new **One-Click Batch Auto-Fix ("Fix All Safe Issues")**.
3. **Token-Efficient Multi-Provider BYOK Frontier AI:** Allow operators to connect **Google Gemini**, **OpenAI**, **Anthropic Claude**, or **OpenAI-Compatible endpoints** (OpenRouter, Ollama, vLLM) via a local `0o600` key vault. Instead of sending whole source files to LLMs, ALASTOR extracts deterministic **CPG Micro-Slices** (90–95% prompt token reduction), deduplicates requests with a **SHA-256 Slice Verdict Cache**, supports **Batch Digest Validation** (up to 10 findings per API call), and exposes live **Token Savings Telemetry** across 4 security workflows.

---

## 2. Pillar 1 — Directional Graphs & 360° Flow Engine

### 2.1 Root Causes Addressed
1. **Buried 360° Arrowheads:** `CustomGraphNode.tsx` previously anchored `AppTree` handles at `top: "50%", left: "50%"` behind opaque `w-52`/`w-56` cards, hiding 100% of ReactFlow `markerEnd` arrowheads.
2. **Hardcoded Top/Bottom CPG Handles:** `CustomGraphNode.tsx` hardcoded `Position.Top` / `Position.Bottom` even when layout direction was `LR` (`Left → Right`) or `MIND_MAP`, creating tangled S-curves.
3. **Unlabeled Edges & Missing Cross-File Flows:** Structural/control edges lacked human-readable flow semantics; `APP_TREE` lacked cross-file `IMPORTS`/`CALLS` edges; single-node findings (`SCA-*`, `IAC-*`, `RULE-3`, `RULE-8`) rendered as lone floating cards without flow context; `ThreatModelingView.tsx` rendered Trust Boundaries as static CSS boxes without directional edges.

### 2.2 Technical Design
1. **Dynamic Perimeter Handle Docking (`frontend/src/components/CustomGraphNode.tsx`):**
   - Expose 4 perimeter target/source handle pairs (`top`, `right`, `bottom`, `left`) on every node card (`CPGNode` and `AppTree` cards), styled cleanly on the outer border.
   - In `TB` (Top-to-Bottom) layouts: route edges `sourceHandle="bottom-src"` → `targetHandle="top-tgt"`.
   - In `LR` (Left-to-Right) and `MIND_MAP` layouts: route edges `sourceHandle="right-src"` → `targetHandle="left-tgt"`.
   - In `SPIDER_360` radial layouts: compute the angle `atan2(dy, dx)` between source `(x1, y1)` and target `(x2, y2)` node centers and select the facing perimeter handle pair (`right-src → left-tgt`, `left-src → right-tgt`, `bottom-src → top-tgt`, or `top-src → bottom-tgt`) so **100% of arrowheads dock visibly outside the target card border**.
2. **Custom Directional Edge Renderer (`frontend/src/components/DirectionalFlowEdge.tsx`):**
   - Custom ReactFlow SVG edge component rendering:
     - High-contrast `markerEnd` directional arrowhead (`orient="auto"`).
     - Mid-edge directional badge pill showing step sequence + human-readable verb + directional chevron (e.g., `① TAINT ▶`, `② CALLS ▶`, `IMPORTS ▶`, `TRUE ▶`, `FALSE ▶`, `LOOP ↺`, `CONTAINS ▶`, `SANITY CHECK ▶`).
     - Subtle animated SVG flow dash/particle moving strictly from `source → target` on active taint paths, cross-file calls, and hovered blast-radius chains.
3. **Backend Graph & 360° Dependency Enrichment (`backend/compiler/app_tree.py`, `backend/main.py`):**
   - Extend `AppTreeAnalyzer` in `backend/compiler/app_tree.py` to parse Python (`import ...`, `from ... import ...`) and JS/TS (`import ... from "..."`, `export ... from "..."`, `require("...")`) statements and resolve intra-repo relative/module paths into `FilePurposeInfo.imports_files: List[str]` and `AppTreeSummary.cross_file_edges: List[CrossFileEdge]` (`{source_filepath, target_filepath, edge_type: "IMPORTS" | "CALLS", symbols: List[str]}`).
   - In `/api/graph` (`backend/main.py`) and client-side finding graph hydration (`ReactFlowGraphPane.tsx`):
     - Attach human-readable `flow_label`, `step_index`, and `flow_explanation` metadata to edges.
     - **Single-Node Finding Context Synthesis:** Whenever a finding has `len(path_nodes) == 1` and `len(path_edges) == 0` (e.g., `SCA-*`, `IAC-*`, `RULE-3`, `RULE-8`), synthesize a 3-node directional context chain (`[1] Origin / Entrypoint / Manifest ──CONFIGURES / EXPOSES──▶ [2] Vulnerable Chokepoint (BFL) ──IMPACT──▶ [3] Runtime Exploit / Blast Radius`) marked `is_synthesized_context: true` so every finding displays a clear directional attack story.
     - Add a toggle in 360° view (`Show Cross-File Imports & Calls`) enabled by default to overlay purple/cyan directional `IMPORTS ▶` / `CALLS ▶` arcs across repository files.
4. **Plain-English Flow Story Bar, Legend & Blast-Radius Highlighting (`ReactFlowGraphPane.tsx`):**
   - **Flow Story Bar:** Compact banner docked at the top of the graph canvas summarizing the currently displayed graph in plain English (e.g., *"Attack Path (3 steps): Untrusted input at `routes.py:18` flows through BFL chokepoint `runner.py:42` into OS command sink `runner.py:45`."* or *"360° Architecture: 24 files across 5 directories with 19 cross-file import/call flows."*), plus clickable step chips (`① → ② → ③`) that pan/zoom and sync Monaco.
   - **Blast-Radius Highlighting:** Clicking or hovering a node highlights all transitive upstream predecessors (cyan) and downstream reachable targets (rose/amber) while dimming unrelated nodes/edges to `25%` opacity (`Esc` or canvas click clears).
   - **Collapsible Legend & Layer Drawer:** Compact pill showing color/arrow semantics (`Source → BFL Chokepoint → Sink`, `Containment`, `Cross-File Import/Call`, `True/False Branch`) while tucking granular AST/CFG/DFG edge-type checkboxes into a clean `Layers & Layout ▾` popover.
5. **Interactive Directional Trust Boundary Flow Graph (`ThreatModelingView.tsx`):**
   - Upgrade the `BOUNDARIES` tab in `ThreatModelingView.tsx` from 4 static CSS cards to an interactive **4-Zone Directional Trust Boundary Graph** (using ReactFlow + `DirectionalFlowEdge` + zone swimlanes):
     - `Zone 1: Untrusted External Ingress` ──`HTTP / CLI / Webhook ▶`──▶ `Zone 2: Application Entrypoints` ──`Taint / Call Flow ▶`──▶ `Zone 3: Validation & BFL Sanitizers` ──`Guarded vs Unsanitized ▶`──▶ `Zone 4: Critical Sinks, DB & Secrets`.
     - Clicking any node or crossing edge opens its exact file/line in the Triage & Fix editor.

---

## 3. Pillar 2 — Complete Frontend UX Rework (Zero Feature Loss + Additions)

### 3.1 Navigation & Workspace Architecture (Option A)
1. **Non-Blocking Startup:** `showPortalGate` defaults to `false` so operators land directly in the productive workspace (`AlastorPortalGate` remains accessible via clicking the brand crest / operator badge if desired).
2. **Unified Top Workflow Header (`StudioCommandHeader.tsx`):**
   - Left: ALASTOR brand crest + active target repository pill (with instant click to switch/rescan target).
   - Center: **4 Primary Workflow Stage Pills** (replaces `LeftFunctionBar` 10-icon micro-rail and nested 7-category `Menu ▾`):
     1. **`1. Scan & Repos`** — Unified Target Launcher (Local Folder/File, GitHub/GitLab Public & Private Clone, ZIP Upload) + `ProjectsHubView` (saved repos, webhooks, automation, history, track-changes diff).
     2. **`2. Triage & Fix`** — Clean 3-pane workspace:
        - Left: `FlawExplorerSidebar` with search, severity/engine/secret filters, **One-Click "Fix All Safe Issues" Batch Auto-Fix button**, and **Batch AI Validate** button.
        - Center: `MonacoCodePane` (source + inline BFL diff editor + **"Audit Selection with Frontier AI"** action on highlighted lines).
        - Right: `ReactFlowGraphPane` (Directional Attack Path / CPG / File Slice + Flow Story Bar).
        - Layout quick-switch (`Split` · `Code Focus` · `Graph Focus`).
     3. **`3. 360° Map & Threats`** — Segmented full-canvas view switching cleanly between:
        - `360° Architecture Spider & Mind-Map` (full-viewport `ReactFlowGraphPane` in `APP_TREE` / `CALL_GRAPH` / `ENTRYPOINTS` mode with cross-file directional edges & file inspector)
        - `Trust Boundary Flow & STRIDE Threat Model` (`ThreatModelingView` with the new interactive 4-Zone Directional Trust Boundary Graph, STRIDE Matrix, Secrets Vault, Entrypoints, and CI/CD PBOM).
     4. **`4. ASPM, Rules & Reports`** — Clean horizontal sub-navigation preserving **100% of enterprise capabilities**:
        - `Executive Posture & Deep-Dive Analytics` (`ExecutiveAspmWorkspace` + `DeepDiveDashboard`)
        - `SAST+ Plain-English Translator, Live SBOM & Academy` (`SastPlusSuiteView`)
        - `Rule Engine, Cypher & Sanitizer Studio` (`RuleEngineProfilesView` + `EngineAccessWorkspace` + Live Web CVE Intel)
        - `RACI Governance, RBAC & Integrations` (`RaciGovernanceView` + `UserAccountProfileView` + `IntegrationHubModal` Jira/GitHub connectors)
        - `Export Center` (One-click SARIF, HTML Executive Dossier, Markdown, CSV, CycloneDX SBOM, Unified `.patch` bundle).
   - Right: `⌘K / Ctrl+K` Quick Command button, Theme/Appearance toggle (preserving all 6 themes), and **`✨ Frontier AI` Copilot Drawer Toggle** (with live `% Tokens Saved` badge).

### 3.2 Net-New Workflow Additions
1. **Centralized API Client (`frontend/src/lib/api.ts`):** Single typed API client wrapping `BACKEND_URL`, structured error parsing, and timeout handling; removes hardcoded `http://localhost:8000` strings from `ReactFlowGraphPane.tsx` and sibling views.
2. **One-Click Batch Auto-Fix (`POST /api/remediate/batch-apply`):**
   - Backend endpoint iterating over deterministic `can_auto_patch` findings (either specified `finding_ids` or all open auto-patchable findings in the active project), applying non-overlapping BFL patches safely bottom-up per file with backup snapshots in `.alastor_patches/`, running a single CPG verification re-scan at the end, and returning `{applied_count, skipped_count, verified_severed_ids, unified_diff, remaining_findings}` + undo support.

---

## 4. Pillar 3 — Token-Efficient Multi-Provider BYOK Frontier AI

### 4.1 Supported Providers & Local Vault Security
- **Module:** `backend/engine/frontier_ai_engine.py`
- **Supported Providers:**
  1. `gemini` — Google Gemini REST API (`https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`, default model `gemini-2.5-flash`)
  2. `openai` — OpenAI Chat Completions (`https://api.openai.com/v1/chat/completions`, default model `gpt-4o-mini`)
  3. `anthropic` — Anthropic Messages API (`https://api.anthropic.com/v1/messages`, default model `claude-3-5-haiku-latest`)
  4. `openai_compatible` — Custom base URL for OpenRouter, Ollama (`http://localhost:11434/v1`), or vLLM, validated strictly to allow only `https://` hosts or explicit loopback (`localhost` / `127.0.0.1`) to prevent SSRF against cloud metadata IPs (`169.254.169.254`).
- **Zero-Leak Storage:**
  - Stored locally in `.alastor_vault/ai_config.json` (already excluded by `.gitignore`) with `os.chmod(..., 0o600)` and `realpath` + `commonpath` confinement inside `.alastor_vault/`.
  - `GET /api/ai/config` **never** returns raw API keys—only `has_api_key: true` and a masked preview (`••••••••abcd`), plus cumulative token-savings telemetry. Keys can also be supplied per-session in memory (`persist_key: false`).

### 4.2 Token-Compression Engine (90–95% Savings)
1. **Deterministic CPG Micro-Slicer (`build_cpg_micro_slice`):**
   - Given a `Finding`, extracts *only*:
     - Enclosing function/class header line (1–2 lines)
     - Deduplicated line windows around each `path_node` and `best_fix_location` (`±3` lines of context, capped at 40 lines total)
     - Compact taint edge chain (`line 18 --[req.args]--> line 42`) + `rule_id` / `cwe_id`
   - Computes `full_file_tokens_est = max(1, file_char_len // 4)` vs `slice_prompt_tokens` so exact token compression (`tokens_saved`, `savings_pct`) is measured on every call.
2. **SHA-256 Slice Verdict Cache:**
   - Cache key: `SHA-256(provider + model + workflow + normalized_micro_slice + rule_id)`.
   - Stored in `.alastor_vault/ai_verdict_cache.json` (bounded LRU of 500 entries). Repeat validations after rescanning unchanged slices cost **0 API tokens** (`cache_hit: true`).
3. **Multi-Finding Batch Digest Prompting:**
   - `POST /api/ai/validate-findings` groups up to 10 findings' micro-slices into a **single** compact JSON-mode prompt, amortizing system-prompt overhead ~10x.

### 4.3 Four AI Security Workflows & REST Endpoints
1. `GET /api/ai/config` & `POST /api/ai/config` & `POST /api/ai/test-connection` — Configure provider, model, optional custom endpoint, key persistence, and verify connectivity with a minimal 10-token ping.
2. `POST /api/ai/validate-findings` — Single or Batch Digest TP/FP validation (`finding_ids: List[str]`). Returns structured verdicts per finding: `verdict` (`TRUE_POSITIVE` | `FALSE_POSITIVE` | `NEEDS_REVIEW`), `confidence` (`0.0–1.0`), `exploitability_summary`, `recommended_action`, `suggested_triage_status` (one-click apply to finding triage state), and `token_telemetry`.
3. `POST /api/ai/audit-code-selection` — Deep security & business-logic audit on user-selected lines in `MonacoCodePane` (`filepath`, `start_line`, `end_line`, optional `focus_question`). Sends *only* the selected lines + enclosing signature (`realpath`-confined to active scanned project root) and returns structured logic/authz/crypto observations + secure replacement snippet.
4. `POST /api/ai/synthesize-patch` — Synthesizes or reviews a context-aware remediation patch for complex/non-template findings using the micro-slice, ready to preview/apply in `MonacoCodePane` DiffEditor.
5. `POST /api/ai/explain-graph` — Generates a crisp plain-English architectural & attack-flow walkthrough from a compact node/edge digest of the active CPG / 360° / Trust Boundary graph.

### 4.4 Frontend Frontier AI Copilot (`frontend/src/components/FrontierAiCopilotDrawer.tsx`)
- Slide-out right drawer + inline triggers in `FlawExplorerSidebar` (*"✨ AI Validate"* / *"✨ Batch Validate Top 10"*), `MonacoCodePane` (*"✨ AI Audit Selection"* & *"✨ AI Synthesize Patch"*), and `ReactFlowGraphPane` (*"✨ AI Explain Flow"*).
- Displays a live **Token Efficiency Meter** (`Prompt Tokens Used` · `Full-File Equivalent` · `% Tokens Saved` · `Cache Hits`) and provider setup form with masked BYOK input.

---

## 5. Error Handling, Fallbacks & Self-Audit Guarantees

- **No AI Key Configured:** App remains 100% functional offline/deterministically; clicking any AI button opens the Copilot Drawer's quick BYOK setup card with clear instructions.
- **Provider Errors (401 Invalid Key, 429 Quota/Rate Limit, Timeout, Malformed JSON):** Caught cleanly in `frontier_ai_engine.py`, returning structured HTTP 200 `{ok: false, error_code, user_message}` responses rendered as actionable inline alerts (never crashing the UI or leaking headers/keys).
- **Path & SSRF Hardening (0 Self-Audit Findings):**
  - All file reads in `frontier_ai_engine.py` and `batch-apply` enforce `os.path.realpath` + `os.path.commonpath` confinement against the scanned project root or `.alastor_vault`.
  - Outbound AI HTTP calls use `urllib.request` with strict URL parsing (`scheme == "https"` against allowlisted provider hosts, or explicit `http://localhost` / `http://127.0.0.1` only when `provider == "openai_compatible"`), never `shell=True`, `eval`, or hardcoded credential literals.

---

## 6. Verification & Testing Strategy

1. **Backend Unit & Integration Tests (`backend/tests/test_v4_ai_and_graphs.py`):**
   - CPG Micro-Slicer token reduction test (verifying `>= 80%` token reduction on multi-hundred-line files).
   - SHA-256 cache hit test (`0` outbound calls on second invocation).
   - Multi-provider request/response adapter tests (mocked Gemini, OpenAI, Anthropic, and OpenAI-compatible responses + SSRF URL rejection test for `http://169.254.169.254`).
   - Key masking test (`GET /api/ai/config` never contains raw key bytes).
   - Batch auto-fix (`POST /api/remediate/batch-apply`) + post-batch rescan verification test.
   - Cross-file `IMPORTS`/`CALLS` extraction & single-node 3-step graph synthesis tests.
2. **Frontend & Full-Stack Verification:**
   - `npx tsc --noEmit` (`0` TypeScript errors) and `npm run build` (`0` Next.js production build errors).
   - `python verify_harness.py` (`20/20` baseline & synthetic assertions passing) + self-audit scan on `cpg-sast-platform` (`0` findings).
