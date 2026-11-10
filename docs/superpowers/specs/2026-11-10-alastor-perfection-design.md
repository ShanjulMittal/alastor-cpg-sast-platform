# ALASTOR (`Ἀλάστωρ`) v3.0 — Studio Perfection Design Specification

**Date:** 2026-11-10  
**Status:** Validated in Brainstorming / Grill-Me Session  
**Repository:** `cpg-sast-platform`  
**Roadmap Structure:** Two Phased Sub-Projects  
- **Phase 1 (Primary Scope of This Spec):** Studio UI/UX Redesign, 5-Pillar Precision IDE Shell, Bespoke Typography & Semantic Token System, Drag-Resizable Panes, Session Persistence, Keyboard Triage, and Live `"Sever the Thread"` Monaco Chokepoint Patch & CPG Re-Verification.  
- **Phase 2 (Follow-On Spec & Plan After Phase 1 Ships):** Real-Time 7-Pass `SSE` Compiler Telemetry Stream + Polyglot Tree-Sitter CPG & OSV Reachability Expansion (`Go`, `Rust`, `C`, `C++`, `Cargo.lock`, `go.sum`).

---

## 1. Problem Statement & Baseline Audit

ALASTOR `v2.6.2` has a deterministic, zero-false-positive 7-pass Code Property Graph (`AST + CFG + DFG + :CALLS`) backend passing `19 / 19` E2E assertions and `0` self-audit findings. However, a ground-truth audit of the frontend (`frontend/src/*`) identified four structural barriers preventing a studio-grade user experience:

1. **Vertical Chrome Compression (~200px Lost Height):** `frontend/src/app/page.tsx` stacks four horizontal bars (`AppMenuBar`, `TopMetricsBar`, `ActiveApplicationBanner`, and the Workbench Focus Bar) before rendering a single line of code or CPG node.
2. **Visual & Color Noise:** Seven competing accent colors (`cyan`, `indigo`, `emerald`, `amber`, `rose`, `violet`, `purple`) appear simultaneously across badges and headers; `frontend/src/app/globals.css` falls back to generic OS system fonts; and `frontend/src/components/LeftFunctionBar.tsx` hardcodes `#080b12` dark backgrounds even when Light Mode is active.
3. **Navigation Fragmentation & Refresh Friction:** `LeftFunctionBar.tsx` crowds 15 icon buttons into a `68px` rail with overlapping views (`STRIDE` duplicated across `Threats` and `ASPM`), while `showPortalGate` resets to `true` in memory on every `F5` reload—ejecting operators from their active code review.
4. **Read-Only Last-Mile Remediation:** `frontend/src/components/MonacoCodePane.tsx` computes the mathematical Best Fix Location (`BFL`) chokepoint and renders static `- Before` / `+ After` text, but forces operators to manually copy-paste fixes outside the IDE rather than previewing a real diff, applying the patch safely, and proving CPG path neutralization in one click.

---

## 2. `frontend-design` Studio Thesis

### 2.1 Visual Direction
**Forensic Instrument + Subtle Classical Mythic Engraving:** Precision security studio ergonomics (inspired by Linear, Cursor, and Palantir Foundry) paired with restrained Greek epigraphic accents (`Ἀλάστωρ`). Color is never decorative; every chromatic pixel encodes mathematical security proof (`Source`, `Chokepoint BFL`, `Sink`, or `Verified Severed`). Ornate sanctuary artwork is reserved for the Launch Hub (`AlastorPortalGate.tsx`) and optional subtle watermarks, keeping the code and graph workbench razor-sharp.

### 2.2 Semantic Color Token System (`frontend/src/app/globals.css`)
All components consume CSS custom properties mapped across ALASTOR's 6 curated themes (`alastor-infernal`, `stygian-abyss`, `hecate-arcane`, `olympian-light`, `athena-parchment`, `hyperborean-light`), eliminating hardcoded `#080b12` / `slate-900` leaks:

| Token | Default Dark (`alastor-infernal`) | Default Light (`olympian-light`) | Semantic Role |
| :--- | :---: | :---: | :--- |
| `--surface-void` | `#09090b` | `#f4f6fa` | App canvas & recessed gutter backdrop |
| `--surface-panel` | `#101014` | `#ffffff` | Primary rail, command header, explorer & status bar |
| `--surface-elevated` | `#17171d` | `#f8fafc` | Popovers, modals, hover cards & active tabs |
| `--border-hairline` | `rgba(255, 255, 255, 0.08)` | `rgba(15, 23, 42, 0.10)` | `1px` structural dividers (replaces heavy glow borders) |
| `--ink-primary` | `#f4f4f6` | `#0f172a` | Primary headings, code identifiers & active labels |
| `--ink-muted` | `#8e929f` | `#475569` | Secondary metadata, timestamps & inactive controls |
| `--sig-crimson` | `#e11d48` | `#be123c` | **Critical Violation / Taint Sink (`SINK`)** |
| `--sig-gold` | `#f59e0b` | `#b45309` | **`Ἀλάστωρ` Brand Engraving & Best Fix Chokepoint (`BFL`)** |
| `--sig-emerald` | `#10b981` | `#047857` | **AST-Verified Sanitizer / Severed Exploit (`0% FP`)** |
| `--sig-cyan` | `#06b6d4` | `#0e7490` | **Untrusted Ingress Entrypoint (`SOURCE`)** |

### 2.3 Typography Hierarchy (`frontend/src/app/layout.tsx`)
Loaded via `next/font/google` with CSS variables (`--font-display`, `--font-sans`, `--font-mono`):
- **Display Face (`Cinzel`, weights `600`, `700`):** Used strictly for the `ALASTOR` wordmark, Launch Hub title, and top-level workspace headings (`letter-spacing: 0.12em`).
- **UI & Dossier Body Face (`Plus Jakarta Sans`, weights `400`, `500`, `600`, `700`):** High x-height geometric sans optimized for dense `11px`–`14px` data tables, STRIDE matrices, and Plain-English executive dossiers.
- **Code & Telemetry Face (`JetBrains Mono`, weights `400`, `500`, `600`):** Used inside Monaco Editor, `DiffEditor`, CWE/CVE pills, SHA256 hashes, file:line breadcrumbs, and the `26px` status bar.

### 2.4 Signature Interaction (`"Sever the Thread"` — Swap-Test Verified)
A generic SaaS admin template cannot swap its logo onto ALASTOR because the centerpiece of the workbench is **coupling a live Monaco Chokepoint `DiffEditor` directly to a Neo4j CPG Attack-Path Edge**:
1. Selecting any finding highlights `SOURCE` (cyan) $\rightarrow$ `BFL CHOKEPOINT` (gold) $\rightarrow$ `SINK` (crimson) simultaneously in Monaco and ReactFlow.
2. Clicking **`Preview BFL Diff`** (or pressing `d`) switches Monaco into side-by-side/inline `DiffEditor` showing the exact surgical code replacement in full file context.
3. Clicking **`Apply Patch & Re-Verify CPG`** writes a SHA256-backed undo journal entry, applies the patch to the workspace file, re-runs the CPG verification pass, and transitions the CPG edge from crimson to an emerald severed state (`✓ THREAD SEVERED · 0 REACHABLE PATHS`) with an inline **`Undo Patch`** action.

### 2.5 Motion & Accessibility Floor
- **Stillness by Default:** Disable continuous background distractions during active code review; reserve animation for (a) the `"Sever the Thread"` CPG edge verification transition (`320ms` cubic-bezier) and (b) the 7-pass compiler stage bar during active scans.
- **Accessibility & Contrast:** Enforce `@media (prefers-reduced-motion: reduce)` fallbacks, visible `:focus-visible` `1.5px` gold/cyan keyboard outlines on all interactive controls, and WCAG AA contrast across all 3 Dark and 3 Light themes.

---

## 3. Shell, Navigation & Component Architecture

### 3.1 2-Bar Precision IDE Shell (`+135px` Reclaimed Vertical Space)
`frontend/src/app/page.tsx` replaces the 4 stacked horizontal headers with:

```text
+--------------------------------------------------------------------------------------------------+
| [Ἀ] [Menu▾] | [Repo: cpg-sast-platform ▾] [GitHub Scan] | [Ctrl+K Search...] | [Code|Split|Graph] [Scan▸] | <- 44px StudioCommandHeader
+------+-----------------------+---------------------------------------+---------------------------+
| Work | Flaw Explorer         |║ Monaco Editor / BFL DiffEditor       |║ ReactFlow CPG Canvas     |
| Thrt | [All|SAST|SCA|IaC|Key]|║ (File breadcrumbs + [Preview Diff])  |║ (7 Graph Modes:          |
| ASPM | ▸ CRITICAL · CWE-78   |║                                      |║  Attack Path, Spider 360,|
| Repo |   payment.py:L42      |║--------------------------------------|║  Call Graph, Entrypoints,|
| Engn |                       |║ Compact Dossier + [Apply & Re-Verify]|║  AST/CFG/DFG Unified)    |
+------+-----------------------+---------------------------------------+---------------------------+
| ● Neo4j CPG: Connected (1,420 nodes) | Δ Track: 2 Fixed · 0 New | Profile: Zero-Trust | View: Eng | <- 26px StudioStatusBar
+--------------------------------------------------------------------------------------------------+
```

1. **`StudioCommandHeader.tsx` (`44px` fixed height):**
   - **Left Cluster:** `Ἀ` Mythic Crest button (reopens the Launch Hub on click) + compact **`Menu ▾`** popover housing all 7 application menu categories (`File & Scan`, `Workspace`, `CPG & Graphs`, `Threat Model & Secrets`, `Rule Engine`, `Accounts`, `Reports & Exports`) + Active Repository selector pill (local browser, saved repos, ZIP upload) + **`GitHub Scan`** button (opening the Public URL / Private PAT modal).
   - **Center Cluster:** **`Ctrl+K` Omnibar** trigger for instant fuzzy jump across findings, files, workspaces, graph modes, and exports.
   - **Right Cluster:** Segmented **`Code | Split | Graph`** layout toggle (visible when `Workbench` is active), **`Scan Target`** primary button (morphing into a live **7-Pass Stage Pill** while scanning), and compact **Theme + Engineer/Executive Lens** popover.
2. **`StudioStatusBar.tsx` (`26px` fixed height):**
   - Houses live `Neo4j CPG` connection & node/edge telemetry, clickable **`Δ Track Changes`** delta summary (opening the Saved Scan / Fixed vs. New comparison drawer), active **Rule Profile** pill, active **Tenant Account / Operator** badge, keyboard shortcut hint (`j/k` flaws • `d` diff • `Ctrl+K`), and language coverage tags (including Phase 2 hooks for `Go`, `Rust`, `C/C++`).
3. **`ResizableSplitPane.tsx` (Zero-Dependency Pointer-Capture Drag Splitters):**
   - Provides smooth horizontal drag handles (`1px` hairline expanding to `3px` accent on hover/drag, double-click to reset) between `FlawExplorerSidebar` (`240px`–`480px`, collapsible) and the `MonacoCodePane` $\leftrightarrow$ `ReactFlowGraphPane` split (`25%`–`75%`), persisted in `localStorage`.

### 3.2 5-Workspace Left Activity Rail (`LeftFunctionBar.tsx`)
Redesigned to `56px` width using semantic CSS variables (`bg-[var(--surface-panel)] border-[var(--border-hairline)]`) so Light and Dark modes both look native. Consolidates all 8 legacy modules into **5 focused Studio Workspaces** with zero feature loss:

| Rail Icon & Label | Store Mode / Wrapper | Consolidated Capabilities (Sub-Tabs) |
| :--- | :--- | :--- |
| **1. `Workbench`** | `REMEDIATION_IDE` | Flaw Explorer, Secrets Quick-Filter, Web CVE Intel, Monaco Code + Live `BFL` `DiffEditor`, Storyboard, and all 7 CPG Graph Modes (`Attack Path`, `360° Spider`, `Call Graph`, `Entrypoints`, `AST`, `CFG`, `DFG`) |
| **2. `Threats`** | `THREAT_MODELING` | `STRIDE Verdict Matrix (OK vs Issue)`, `Cryptographic Secret Vault`, `Trust Boundary Zones`, and `Entrypoints & CI/CD PBOM` (`ThreatModelingView.tsx`) |
| **3. `ASPM`** | `EXECUTIVE_ASPM` (`ExecutiveAspmWorkspace.tsx`) | Unified studio sub-tabs composing: `1. Impact Translator`, `2. CycloneDX v1.5 SBOM`, `3. API Attack Surface`, `4. Compliance & Deep-Dive Analytics` (`DeepDiveDashboard.tsx`), `5. PMI/COBIT RACI Matrix` (`RaciGovernanceView.tsx`), `6. Remediation Roadmap`, and `7. Security Academy` (removing the duplicate STRIDE tab from `SastPlusSuiteView.tsx`) |
| **4. `Repos`** | `PROJECTS_HUB` | Local Auto-Discovery, Public URL / Private PAT GitHub Import, Scan Snapshots, and CI/CD Webhooks (`ProjectsHubView.tsx`) |
| **5. `Engine`** | `ENGINE_ACCESS` (`EngineAccessWorkspace.tsx`) | Unified studio sub-tabs composing: `1. Rule Profiles & 18-Rule Matrix` (`RuleEngineProfilesView.tsx`), `2. Sanitizer & Neo4j Cypher Studio`, `3. Multi-Tenant Accounts & RBAC` (`UserAccountProfileView.tsx`), and `4. Jira & GitHub Issue Sync` |

*Backward Compatibility:* Legacy `WorkspaceViewMode` values (`DEEP_DIVE`, `RACI_GOVERNANCE`, `SAST_PLUS_SUITE`, `RULE_ENGINE_PROFILES`, `USER_PROFILES`) remain valid in `useAuditStore.ts` and automatically route to the matching parent workspace + sub-tab so `Ctrl+K`, menu items, and existing tests continue working seamlessly.

### 3.3 Smart Session-Persisted Launch Hub (`AlastorPortalGate.tsx` & `useAuditStore.ts`)
- Hydrates `alastor_ui_prefs_v3` from `localStorage` on mount: `{ hasEnteredWorkspace, appTheme, backdropIntensity, workspaceViewMode, ideLayoutMode, explorerWidth, codeGraphRatio }`.
- First-time visitors get the sculptural `Ἀλάστωρ` Launch Hub (with 1-click Local Scan, Public/Private GitHub URL input, and Saved Scan resume).
- Once inside the app, pressing `F5` preserves the exact active workspace, theme, and split ratios without flashing the Portal Gate. Clicking the top-left `Ἀ` crest explicitly reopens the Launch Hub anytime.

### 3.4 Keyboard-First IDE Navigation (`useKeyboardNavigation.ts`)
Active inside `Workbench` whenever focus is not inside an `<input>`, `<textarea>`, `<select>`, or editable Monaco buffer:
- `j` / `k`: Select next / previous finding in the filtered Flaw Explorer list.
- `[` / `]`: Step backward / forward through the current finding's CPG `path_nodes` (`SOURCE` $\rightarrow$ `BFL` $\rightarrow$ `SINK`), syncing Monaco cursor line and ReactFlow node highlight.
- `d`: Toggle live Monaco `BFL` `DiffEditor` preview on the selected finding.
- `1` / `2` / `3`: Switch `Code Focus` / `Split (Code + Graph)` / `Graph Focus`.
- `b`: Collapse / expand `FlawExplorerSidebar`.

---

## 4. Backend Safe Remediation & Re-Verification API (`backend/`)

To power `"Sever the Thread"` while maintaining **`0` self-audit findings** across ALASTOR's 18 security rules (especially `RULE-10-PATH-TRAVERSAL`, `RULE-6-SHELL-INJECTION`, `RULE-8-HARDCODED-SECRET`, and `RULE-12-LOG-INJECTION`), we introduce a dedicated module `backend/engine/remediation_patcher.py` wired into `backend/main.py`:

### 4.1 Security & Confinement Invariants
1. **Server-Enumerated File Resolution Only:** Target files are never opened via raw user-supplied paths. `remediation_patcher.py` reuses the server-enumerated workspace file table (`os.walk` over the active authorized project root + `os.path.realpath` + `os.path.commonpath` confinement) and rejects any path outside the active scanned target or inside ALASTOR's own `backend/`/`frontend/` source when self-auditing unless explicitly authorized.
2. **Dot-Prefixed Undo Journal (`.alastor_patches/`):** Every applied patch first writes an atomic JSON backup (`patch_id`, `filepath`, `original_sha256`, `patched_sha256`, `original_content_b64`, `finding_id`, `applied_at`) into `<workspace>/.alastor_patches/<patch_id>.json` (`0600` permissions; ignored by `scanner.py` and `vuln_extractor.py` because of the leading dot, and added to `.gitignore`).
3. **Optimistic Concurrency Check:** `apply` verifies the current file's SHA256 matches `expected_sha256` from the preview response before writing, returning `HTTP 409 Conflict` if the file was modified externally.

### 4.2 Endpoints & Data Flow
- **`POST /api/remediate/preview`**
  - **Request:** `{ "finding_id": str, "filepath": str, "target_line": int, "rule_id": str }`
  - **Behavior:** Locates the exact source file via server-enumerated workspace lookup, inspects the AST/line slice around `best_fix_location` (or sink line), and synthesizes deterministic `original_content` + `patched_content` buffers (supporting `RULE-1-TAINT` / `RULE-6-SHELL-INJECTION` `shell=False` argv list conversion, `RULE-7-SQLI-FORMAT` parameterized query binding, `RULE-8-HARDCODED-SECRET` `os.environ.get(...)` extraction, `RULE-9-DOM-XSS` `textContent` replacement, `RULE-10-PATH-TRAVERSAL` `os.path.commonpath` confinement guard, `RULE-11-SSRF-URLOPEN` HTTPS + `ipaddress` guard, `RULE-12-LOG-INJECTION` CR/LF stripping, `RULE-13` `yaml.safe_load` / `sha256`, `SCA-1` SemVer pin cleanup, and `IAC-2` non-root `USER` / security headers, plus user-editable custom buffer support in the `DiffEditor`).
  - **Response:** `{ "can_auto_patch": bool, "filepath": str, "expected_sha256": str, "original_content": str, "patched_content": str, "fix_summary": str, "target_line": int }`
- **`POST /api/remediate/apply`**
  - **Request:** `{ "finding_id": str, "filepath": str, "rule_id": str, "expected_sha256": str, "patched_content": str }`
  - **Behavior:** Validates workspace confinement & `expected_sha256`, writes `.alastor_patches/<patch_id>.json`, atomically writes `patched_content`, triggers an immediate workspace re-scan + `Track Changes` snapshot delta update, and checks whether `finding_id` (or same `rule_id` at `filepath`) is eliminated.
  - **Response:** `{ "status": "applied", "patch_id": str, "verified_severed": bool, "remaining_findings_count": int, "fixed_delta_count": int }`
- **`POST /api/remediate/undo`**
  - **Request:** `{ "patch_id": str }`
  - **Behavior:** Restores exact `original_content_b64` from `.alastor_patches/<patch_id>.json`, removes the journal entry, re-runs the workspace scan, and restores CPG state.

---

## 5. Error Handling & Edge Cases

- **Read-Only / Unpatchable Targets:** If a target file is read-only or a rule requires architectural multi-file refactoring where single-file synthesis is advisory, `can_auto_patch` still opens the Monaco `DiffEditor` in **editable patch mode** so the engineer can refine the right-hand pane and click `Apply Patch & Re-Verify`, or download a standard `.patch` unified diff if the filesystem is read-only.
- **External File Modification (`409 Conflict`):** Displays a clear inline banner in `MonacoCodePane` (*"File changed on disk since diff preview was generated — Refresh Diff"*) with a 1-click refresh button.
- **Zero Hydration Mismatch:** `localStorage` preferences hydrate inside a post-mount `useEffect` (with CSS theme variables applied synchronously via a tiny inline theme-init script or smooth state sync) so Next.js SSR never throws hydration warnings.

---

## 6. Verification & Acceptance Criteria (`verify_harness.py` Assertion U)

Phase 1 is complete **only** when all of the following pass with fresh verification evidence:
1. **Frontend Production Build & Type Safety:** `npm run build` inside `frontend/` succeeds with `0` TypeScript or Next.js errors.
2. **20-Assertion Autonomous E2E Suite (`verify_harness.py`):**
   - Existing Assertions `A` through `T` (`19/19`) continue passing 100%.
   - **New `Assertion U` (`Live BFL Patch Preview, Apply, CPG Severing Proof & Undo`):** Runs against an isolated temporary copy of a vulnerable target file, calls `POST /api/remediate/preview`, applies the patch via `POST /api/remediate/apply`, asserts `verified_severed == True` and that the CPG finding count drops deterministically, then calls `POST /api/remediate/undo` and asserts byte-identical restoration.
   - **Self-Audit Zero-Finding Invariant:** Scanning ALASTOR's own `cpg-sast-platform` repository returns **`0` active findings** (`SAST: 0, SCA: 0, IaC: 0, Secrets: 0`).
3. **Visual Critique (`frontend-design` Step 5):** Live Playwright/browser Retina inspection across Desktop (`1600×1000`) and Compact Laptop (`1280×800`) in both **Dark (`Alastor Infernal`)** and **Light (`Olympian Daylight`)** modes confirming:
   - Single `44px` header + `26px` status bar (`+135px` reclaimed height),
   - `Cinzel` + `Plus Jakarta Sans` + `JetBrains Mono` typography active,
   - Zero `#080b12` dark leaks in Light mode and zero rainbow badge clutter,
   - Drag-resizable split panes, 5-Workspace rail, and `"Sever the Thread"` Monaco `DiffEditor` working smoothly.

---

## 7. Phase 2 Architectural Hooks (Next Sub-Project Spec)

Once Phase 1 is verified and merged, Phase 2 will follow its own spec $\rightarrow$ plan $\rightarrow$ TDD execution cycle to deliver:
1. **Real-Time 7-Pass `SSE` Compiler Stream (`GET /api/scan/stream`):** Push granular per-pass progress (`Pass 1 Tree-Sitter AST` $\rightarrow$ `Pass 7 OSV + STRIDE`) directly into Phase 1's `StudioCommandHeader` & `StudioStatusBar` stage indicators.
2. **Polyglot Systems & Cloud-Native CPG Pack (`Go` + `Rust` + `C/C++`):**
   - Add `tree-sitter-go`, `tree-sitter-rust`, `tree-sitter-c`, and `tree-sitter-cpp` to `scanner.py`, `ast_parser.py`, `cfg_builder.py`, `dfg_builder.py`, and `call_graph_builder.py`.
   - Extend AST-verified sanitizer summaries (`filepath.Clean` + prefix checks in Go, `Path::canonicalize` + `starts_with` in Rust, bounded buffer/execve patterns in C/C++) and unsafe memory/command/SQLi/SSRF sinks.
   - Extend `osv_lockfile_scanner.py` to parse `go.sum` (`Go` ecosystem) and `Cargo.lock` (`crates.io` ecosystem) with CPG `import` / `use` reachability proofs.
