# ALASTOR v3.0 Phase 1 Studio UI/UX & Live Chokepoint Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform ALASTOR into a precision forensic security studio with bespoke typography (`Cinzel` + `Plus Jakarta Sans` + `JetBrains Mono`), a unified `44px` Top Command Header + `26px` Bottom Telemetry Status Bar (+135px vertical workspace), a 5-workspace theme-aware rail, drag-resizable split panes, session-persisted refresh state, keyboard-first triage, and a live Monaco `DiffEditor` `"Sever the Thread"` 1-click patch + Neo4j CPG re-verification engine.

**Architecture:** On the backend, a new `backend/engine/remediation_patcher.py` synthesizes deterministic Chokepoint (`BFL`) patches, enforces server-enumerated `os.walk` + `os.path.commonpath` workspace confinement (preserving `0` self-audit findings), stores SHA256-verified backups in `.alastor_patches/`, and triggers immediate CPG re-verification via `/api/remediate/{preview,apply,undo}`. On the frontend, `layout.tsx` + `tailwind.config.ts` + `globals.css` establish semantic theme tokens across all 6 Dark/Light themes, while `page.tsx` replaces the 4 stacked headers with `StudioCommandHeader`, `StudioStatusBar`, `ResizableSplitPane`, 5-workspace composite wrappers (`ExecutiveAspmWorkspace`, `EngineAccessWorkspace`), keyboard navigation (`useKeyboardNavigation`), and live Monaco `DiffEditor` integration inside `MonacoCodePane` + `ReactFlowGraphPane`.

**Tech Stack:** Python 3.11+, FastAPI 0.115, Pydantic 2.9, Neo4j 5 + APOC, Tree-Sitter 0.23, Next.js 15.5.28, React 18.3, TypeScript 5.6, Tailwind CSS 3.4, Zustand 4.5, `@monaco-editor/react` 4.6 (`Editor` & `DiffEditor`), ReactFlow 11.11, Lucide React.

## Global Constraints

- Zero new npm or PyPI dependencies required in Phase 1 (`@monaco-editor/react` already exports `DiffEditor`, and `next/font/google` is built into Next.js 15.5.28).
- Self-Audit Zero-Finding Invariant: Scanning `cpg-sast-platform` MUST continue returning `0` findings across all 18 security rules (`RULE-1` through `RULE-13`, `SCA-1/2`, `IAC-1/2/3`). Never pass user-tainted path strings directly to `open()`, `os.remove()`, or `shutil.*`; always resolve through server-enumerated `os.walk` / `os.listdir` entries with `os.path.realpath` + `os.path.commonpath` confinement and strip `\r`/`\n` before logging.
- Never place realistic 36+ char `ghp_...` or `github_pat_...` strings in source, tests, or docs (`RULE-8-HARDCODED-SECRET`).
- All 6 themes (`alastor-infernal`, `stygian-abyss`, `hecate-arcane`, `olympian-light`, `athena-parchment`, `hyperborean-light`) MUST adapt cleanly with zero hardcoded `#080b12` dark sidebar leaks in Light Mode.
- Legacy `WorkspaceViewMode` IDs (`DEEP_DIVE`, `RACI_GOVERNANCE`, `SAST_PLUS_SUITE`, `RULE_ENGINE_PROFILES`, `USER_PROFILES`) MUST remain valid and route cleanly into their parent 5-pillar workspace sub-tab.
- Execute file edits sequentially on Windows to avoid hook lock contention.

---

### Task 1: Safe Backend Chokepoint Patch, Undo Journal & Instant CPG Re-Verification API

**Files:**
- Modify: `.gitignore`
- Modify: `backend/models.py`
- Create: `backend/engine/remediation_patcher.py`
- Modify: `backend/main.py`
- Create: `backend/tests/test_remediation_patcher.py`

**Interfaces:**
- Consumes: `Finding`, `BestFixLocation` in `backend/models.py`; `_resolve_allowed_scan_file`, `scan_project`, `ScanRequest` in `backend/main.py`.
- Produces:
  - Pydantic models in `backend/models.py`:
    - `RemediatePreviewRequest(finding_id: str, filepath: str, target_line: int = 1, rule_id: str = "", recommended_fix: Optional[str] = None)`
    - `RemediatePreviewResponse(can_auto_patch: bool, filepath: str, expected_sha256: str, original_content: str, patched_content: str, fix_summary: str, target_line: int)`
    - `RemediateApplyRequest(finding_id: str, filepath: str, rule_id: str = "", expected_sha256: str, patched_content: str)`
    - `RemediateApplyResponse(status: str, patch_id: str, filepath: str, verified_severed: bool, remaining_findings_count: int, fixed_delta_count: int, message: str)`
    - `RemediateUndoRequest(patch_id: str)`
    - `RemediateUndoResponse(status: str, patch_id: str, filepath: str, restored_sha256: str, active_findings_count: int, message: str)`
  - FastAPI endpoints in `backend/main.py`:
    - `POST /api/remediate/preview` -> `RemediatePreviewResponse`
    - `POST /api/remediate/apply` -> `RemediateApplyResponse`
    - `POST /api/remediate/undo` -> `RemediateUndoResponse`

- [ ] **Step 1: Write the failing unit tests for deterministic patch synthesis, SHA256 guard, and undo journal**

Create `backend/tests/test_remediation_patcher.py`:

```python
import hashlib
import os
import tempfile
import unittest

from engine.remediation_patcher import (
    apply_workspace_patch,
    generate_remediation_preview,
    undo_workspace_patch,
)


class RemediationPatcherTests(unittest.TestCase):
    def test_preview_apply_and_undo_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_file = os.path.join(tmpdir, "gateway.py")
            original = (
                "import os\n"
                "import subprocess\n\n"
                "def ping_host(host: str):\n"
                '    return subprocess.run(f"ping -c 1 {host}", shell=True)\n'
            )
            with open(vuln_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(original)

            orig_sha = hashlib.sha256(original.encode("utf-8")).hexdigest()

            preview = generate_remediation_preview(
                raw_filepath="gateway.py",
                allowed_roots=[tmpdir],
                rule_id="RULE-6-SHELL-INJECTION",
                target_line=5,
                recommended_fix=None,
            )
            self.assertIsNotNone(preview)
            self.assertTrue(preview["can_auto_patch"])
            self.assertEqual(preview["expected_sha256"], orig_sha)
            self.assertIn("shell=False", preview["patched_content"])
            self.assertNotIn("shell=True", preview["patched_content"])

            applied = apply_workspace_patch(
                raw_filepath="gateway.py",
                allowed_roots=[tmpdir],
                patch_vault_root=os.path.join(tmpdir, ".alastor_patches"),
                expected_sha256=orig_sha,
                patched_content=preview["patched_content"],
                finding_id="TEST-FINDING-1",
                rule_id="RULE-6-SHELL-INJECTION",
            )
            self.assertEqual(applied["status"], "applied")
            with open(vuln_file, "r", encoding="utf-8") as fh:
                self.assertIn("shell=False", fh.read())

            # Stale SHA256 must raise ValueError (409 conflict)
            with self.assertRaises(ValueError):
                apply_workspace_patch(
                    raw_filepath="gateway.py",
                    allowed_roots=[tmpdir],
                    patch_vault_root=os.path.join(tmpdir, ".alastor_patches"),
                    expected_sha256=orig_sha,
                    patched_content="# stale overwrite\n",
                    finding_id="TEST-FINDING-1",
                    rule_id="RULE-6-SHELL-INJECTION",
                )

            undone = undo_workspace_patch(
                patch_id=applied["patch_id"],
                allowed_roots=[tmpdir],
                patch_vault_root=os.path.join(tmpdir, ".alastor_patches"),
            )
            self.assertEqual(undone["restored_sha256"], orig_sha)
            with open(vuln_file, "r", encoding="utf-8") as fh:
                self.assertEqual(fh.read(), original)

    def test_rejects_path_traversal_outside_workspace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            res = generate_remediation_preview(
                raw_filepath="../../etc/passwd",
                allowed_roots=[tmpdir],
                rule_id="RULE-1-TAINT",
                target_line=1,
            )
            self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the unit test to verify it fails**

Run from `c:\Projects\Securecodereview\cpg-sast-platform\backend`:
`..\.venv\Scripts\python.exe -m unittest tests/test_remediation_patcher.py -v`
Expected: `ModuleNotFoundError: No module named 'engine.remediation_patcher'`

- [ ] **Step 3: Implement `.gitignore` entry, Pydantic models in `backend/models.py`, `backend/engine/remediation_patcher.py`, and endpoints in `backend/main.py`**

1. Append `.alastor_patches/` under `# Local Runtime State & Uploaded Scan Targets` in `.gitignore`.
2. Add the 6 `Remediate*` Pydantic models to `backend/models.py`:

```python
class RemediatePreviewRequest(BaseModel):
    finding_id: str
    filepath: str
    target_line: int = 1
    rule_id: str = ""
    recommended_fix: Optional[str] = None


class RemediatePreviewResponse(BaseModel):
    can_auto_patch: bool
    filepath: str
    expected_sha256: str
    original_content: str
    patched_content: str
    fix_summary: str
    target_line: int


class RemediateApplyRequest(BaseModel):
    finding_id: str
    filepath: str
    rule_id: str = ""
    expected_sha256: str
    patched_content: str


class RemediateApplyResponse(BaseModel):
    status: str
    patch_id: str
    filepath: str
    verified_severed: bool
    remaining_findings_count: int
    fixed_delta_count: int
    message: str


class RemediateUndoRequest(BaseModel):
    patch_id: str


class RemediateUndoResponse(BaseModel):
    status: str
    patch_id: str
    filepath: str
    restored_sha256: str
    active_findings_count: int
    message: str
```

3. Create `backend/engine/remediation_patcher.py` implementing:
   - `_locate_enumerated_workspace_file(raw_filepath: str, allowed_roots: List[str]) -> Optional[str]`: Strips `\r`/`\n`/`\0`, rejects `..` segments, verifies `os.path.realpath` + `os.path.commonpath([root_real, candidate_real]) == root_real`, and returns **only** the `server_entry` yielded by `os.walk(root_real)` (pruning `.git`, `node_modules`, `.venv`, `.next`, `__pycache__`, `.alastor_patches`, `.alastor_vault`) so zero user-tainted path strings ever reach `open()`.
   - `_synthesize_line_fix(lines: List[str], target_line: int, rule_id: str, recommended_fix: Optional[str]) -> Tuple[List[str], bool, str]`: Synthesizes deterministic in-place replacements for `RULE-6-SHELL-INJECTION` (`shell=True` -> `shlex.split` + `shell=False`), `RULE-1-TAINT` (`os.system(...)` -> `subprocess.run(shlex.split(...), shell=False, check=False)`, `eval(` -> `ast.literal_eval(`), `RULE-7-SQLI-FORMAT` (f-string `.execute` -> parameterized `?` / `%s` tuple), `RULE-8-HARDCODED-SECRET` (string literal -> `os.environ.get("ALASTOR_MANAGED_SECRET", "")` / `process.env.ALASTOR_MANAGED_SECRET || ""`), `RULE-9-DOM-XSS` (`.innerHTML` -> `.textContent`), `RULE-10-PATH-TRAVERSAL` (wraps path with `os.path.basename(...)`), `RULE-11-SSRF-URLOPEN` (enforces `https://` scheme guard), `RULE-12-LOG-INJECTION` (strips `\r` and `\n`), `RULE-13` (`yaml.load(` -> `yaml.safe_load(`, `hashlib.md5(`/`sha1(` -> `hashlib.sha256(`), `SCA-1-MANIFEST-AUDIT` (pins `^`/`~`/`>=` in manifest line), and `IAC-2-CONTAINER-ROOT` (appends `USER appuser` when missing in `Dockerfile`), falling back cleanly to commented `recommended_fix` insertion right above `target_line` so editable `DiffEditor` mode always has a valid concrete diff.
   - `generate_remediation_preview(...)`, `apply_workspace_patch(...)` (verifying `expected_sha256`, writing base64 backup to `<patch_vault_root>/<uuid_hex>.json` with `0o600` mode, writing `patched_content`), and `undo_workspace_patch(...)` (validating `patch_id` matches `^[0-9a-f]{24,32}$`, enumerating `os.listdir(vault_real)` to open the journal entry without user taint, restoring exact bytes via `_locate_enumerated_workspace_file`, and unlinking the journal entry).
4. Wire `POST /api/remediate/preview`, `POST /api/remediate/apply`, and `POST /api/remediate/undo` into `backend/main.py`:
   - `apply` invokes `scan_project(ScanRequest(target_path=current_scan_dir))` after writing the patch, checks if `req.finding_id` (or same `rule_id` + `filepath` + line) is eliminated from active findings, and returns `RemediateApplyResponse`.
   - `undo` restores the file, invokes `scan_project(ScanRequest(target_path=current_scan_dir))`, and returns `RemediateUndoResponse`.

- [ ] **Step 4: Run unit tests to verify they pass**

Run from `c:\Projects\Securecodereview\cpg-sast-platform\backend`:
`..\.venv\Scripts\python.exe -m unittest tests/test_remediation_patcher.py -v`
Expected: `Ran 2 tests ... OK`

- [ ] **Step 5: Commit Task 1**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add .gitignore backend/models.py backend/engine/remediation_patcher.py backend/main.py backend/tests/test_remediation_patcher.py
git commit -m "feat(remediate): add confined BFL patch preview, apply, SHA256 undo journal, and instant CPG re-verify API"
```

---

### Task 2: Studio Typography, Semantic Theme Tokens & Session Persistence

**Files:**
- Modify: `frontend/src/app/layout.tsx`
- Modify: `frontend/tailwind.config.ts`
- Modify: `frontend/src/app/globals.css`
- Modify: `frontend/src/types/cpg.ts`
- Modify: `frontend/src/store/useAuditStore.ts`

**Interfaces:**
- Consumes: `POST /api/remediate/{preview,apply,undo}` from Task 1.
- Produces:
  - CSS variables `--font-display`, `--font-sans`, `--font-mono`, `--surface-void`, `--surface-panel`, `--surface-elevated`, `--border-hairline`, `--ink-primary`, `--ink-muted`, `--sig-crimson`, `--sig-gold`, `--sig-emerald`, `--sig-cyan`.
  - Extended `WorkspaceViewMode` in `frontend/src/types/cpg.ts` adding `"EXECUTIVE_ASPM"` and `"ENGINE_ACCESS"` alongside existing 8 modes, plus `ExecutiveAspmTab`, `EngineAccessTab`, `RemediatePreviewResponse`, `RemediateApplyResponse`, `RemediateUndoResponse`.
  - Store state & actions in `frontend/src/store/useAuditStore.ts`:
    - `executiveAspmTab: ExecutiveAspmTab` & `setExecutiveAspmTab(tab)`
    - `engineAccessTab: EngineAccessTab` & `setEngineAccessTab(tab)`
    - `explorerWidth: number` (`240`..`480`, default `310`) & `setExplorerWidth(px)`
    - `codeGraphRatio: number` (`0.25`..`0.75`, default `0.52`) & `setCodeGraphRatio(ratio)`
    - `isDiffEditorOpen: boolean` & `setDiffEditorOpen(open)`
    - `activePathStepIndex: number` & `stepFindingPath(delta: 1 | -1)`
    - `remediationPreview: RemediatePreviewResponse | null`, `isApplyingPatch: boolean`, `lastAppliedPatch: { patchId: string; findingId: string; filepath: string; verifiedSevered: boolean } | null`
    - `fetchRemediationPreview(finding: Finding): Promise<void>`
    - `applyRemediationPatch(patchedContent: string): Promise<RemediateApplyResponse | null>`
    - `undoLastRemediationPatch(): Promise<boolean>`
    - `hydrateUiPreferences(): void` (loads `alastor_ui_prefs_v3` from `localStorage` so `F5` refreshes persist `showPortalGate`, `appTheme`, `backdropIntensity`, `workspaceViewMode`, `ideLayoutMode`, `explorerWidth`, `codeGraphRatio`).

- [ ] **Step 1: Load `Cinzel`, `Plus_Jakarta_Sans`, and `JetBrains_Mono` in `frontend/src/app/layout.tsx` and wire Tailwind tokens in `frontend/tailwind.config.ts`**

Update `frontend/src/app/layout.tsx`:

```tsx
import type { Metadata } from "next";
import { Cinzel, Plus_Jakarta_Sans, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const fontDisplay = Cinzel({
  subsets: ["latin"],
  weight: ["600", "700"],
  variable: "--font-display",
  display: "swap",
});

const fontSans = Plus_Jakarta_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-sans",
  display: "swap",
});

const fontMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "ALASTOR | Forensic Code Property Graph, SAST, SCA & ASPM Studio",
  description:
    "ALASTOR — Deterministic Code Property Graph (AST, CFG, DFG, Call Graph), Zero-FP SAST, Reachable OSV SCA, STRIDE & Executive ASPM Studio.",
  icons: {
    icon: "/alastor-demon-logo.png",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`dark ${fontDisplay.variable} ${fontSans.variable} ${fontMono.variable}`}
      data-theme="alastor-infernal"
      data-theme-mode="dark"
      suppressHydrationWarning
    >
      <body className="bg-[var(--surface-void)] text-[var(--ink-primary)] font-sans min-h-screen overflow-hidden antialiased">
        {children}
      </body>
    </html>
  );
}
```

Update `frontend/tailwind.config.ts` to add `fontFamily: { display: ["var(--font-display)", "Georgia", "serif"], sans: ["var(--font-sans)", "system-ui", "sans-serif"], mono: ["var(--font-mono)", "Consolas", "monospace"] }` and semantic studio color aliases (`studio-void`, `studio-panel`, `studio-elevated`, `studio-hairline`, `sig-crimson`, `sig-gold`, `sig-emerald`, `sig-cyan`).

- [ ] **Step 2: Upgrade `frontend/src/app/globals.css` with Studio Semantic Tokens, Focus Rings & Reduced-Motion Rules**

Add `--surface-void`, `--surface-panel`, `--surface-elevated`, `--border-hairline`, `--ink-primary`, `--ink-muted`, `--sig-crimson`, `--sig-gold`, `--sig-emerald`, and `--sig-cyan` across all 6 `[data-theme="..."]` blocks, update `body { font-family: var(--font-sans), sans-serif; }`, add `:focus-visible { outline: 1.5px solid var(--sig-gold); outline-offset: 2px; }`, add `@media (prefers-reduced-motion: reduce)` animation disabling, and add `.cpg-bfl-line-highlight` (gold chokepoint highlight) + `.cpg-severed-line-highlight` (emerald severed highlight).

- [ ] **Step 3: Extend `frontend/src/types/cpg.ts` and `frontend/src/store/useAuditStore.ts`**

1. In `frontend/src/types/cpg.ts`, add `"EXECUTIVE_ASPM" | "ENGINE_ACCESS"` to `WorkspaceViewMode`, add `ExecutiveAspmTab` (`"TRANSLATOR" | "SBOM" | "ATTACK_SURFACE" | "ANALYTICS" | "RACI" | "ROADMAP" | "ACADEMY"`), `EngineAccessTab` (`"RULE_PROFILES" | "CYPHER_SANITIZERS" | "ACCOUNTS_RBAC" | "ISSUE_CONNECTORS"`), and the 3 `Remediate*Response` interfaces.
2. In `frontend/src/store/useAuditStore.ts`:
   - Normalize `setWorkspaceViewMode` so legacy modes automatically activate the corresponding parent 5-pillar workspace and sub-tab (`"DEEP_DIVE"` -> `workspaceViewMode: "EXECUTIVE_ASPM", executiveAspmTab: "ANALYTICS"`; `"RACI_GOVERNANCE"` -> `"EXECUTIVE_ASPM" + "RACI"`; `"SAST_PLUS_SUITE"` -> `"EXECUTIVE_ASPM"`; `"RULE_ENGINE_PROFILES"` -> `"ENGINE_ACCESS" + "RULE_PROFILES"`; `"USER_PROFILES"` -> `"ENGINE_ACCESS" + "ACCOUNTS_RBAC"`).
   - Persist UI preferences to `localStorage` (`alastor_ui_prefs_v3`) whenever theme, portal gate entry, workspace, layout mode, or split-pane widths change, and expose `hydrateUiPreferences()`.
   - Implement `fetchRemediationPreview`, `applyRemediationPatch`, `undoLastRemediationPatch`, and `stepFindingPath`.

- [ ] **Step 4: Run TypeScript typecheck to verify zero type errors**

Run from `c:\Projects\Securecodereview\cpg-sast-platform\frontend`:
`npx.cmd tsc --noEmit`
Expected: Exit code `0` with zero errors.

- [ ] **Step 5: Commit Task 2**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add frontend/src/app/layout.tsx frontend/tailwind.config.ts frontend/src/app/globals.css frontend/src/types/cpg.ts frontend/src/store/useAuditStore.ts
git commit -m "feat(ui-tokens): add Cinzel/Jakarta/JetBrains typography, semantic theme tokens, localStorage persistence, and remediation store"
```

---

### Task 3: 2-Bar Precision IDE Shell (`StudioCommandHeader`, `StudioStatusBar`, `ResizableSplitPane`) & 5-Workspace Rail

**Files:**
- Create: `frontend/src/components/StudioCommandHeader.tsx`
- Create: `frontend/src/components/StudioStatusBar.tsx`
- Create: `frontend/src/components/ResizableSplitPane.tsx`
- Modify: `frontend/src/components/LeftFunctionBar.tsx`
- Modify: `frontend/src/components/AlastorBranding.tsx`

**Interfaces:**
- Consumes: Semantic CSS variables and `useAuditStore` selectors from Task 2; existing Target/GitHub Picker modal logic from `TopMetricsBar.tsx` and Track Changes drawer logic from `ActiveApplicationBanner.tsx`.
- Produces:
  - `StudioCommandHeader`: `44px` (`h-11`) unified top bar containing:
    - Left: `Ἀ` crest button (`onClick={() => setShowPortalGate(true)}`) + `ALASTOR` `font-display` wordmark + compact `Menu ▾` dropdown (all 7 application menu groups: `File & Scan`, `Workspace`, `CPG & Graphs`, `Threat Model & Secrets`, `Rule Engine`, `Accounts`, `Reports & Exports`) + Active Repository selector pill + `GitHub Scan` button (preserving the complete Open/Public `NO TOKEN` + Private `PAT` modal).
    - Center: `Ctrl+K` Omnibar search trigger (`Search findings, files, graphs, SARIF...`).
    - Right: Segmented `Code | Split | Graph` switch (when in `REMEDIATION_IDE`), live 7-pass scan stage indicator or `Scan` CTA button, and compact Theme + `Engineer / Executive` lens popover.
  - `StudioStatusBar`: `26px` (`h-[26px]`) bottom telemetry bar containing:
    - Left: Live `Neo4j CPG` status dot + node/edge count (`font-mono`), clickable `Δ Track Changes` pill (toggling the slide-up/popover Saved Scan & Fixed/New delta inspector), active Rule Profile chip (clicking jumps to `ENGINE_ACCESS -> RULE_PROFILES`).
    - Right: Keyboard hint (`j/k Flaws · d BFL Diff · [/] Hops`), active language/engine tags, Tenant Account badge, and `SARIF / SBOM` quick export trigger.
  - `ResizableSplitPane`: Zero-dependency pointer-drag horizontal split component (`left`, `right`, `initialLeftPx` or `ratio`, `onChange`, double-click divider to reset, `1px` `bg-[var(--border-hairline)]` turning `bg-[var(--sig-gold)]` while dragging).
  - `LeftFunctionBar`: `56px` (`w-14`) theme-aware (`bg-[var(--surface-panel)] border-r border-[var(--border-hairline)]`) 5-workspace vertical rail (`Workbench`, `Threats`, `ASPM`, `Repos`, `Engine`) + bottom quick-toggles (`Secrets`, `Explorer`, `Ctrl+K`, `Settings`) with strict semantic accents (gold active indicator, crimson critical badge only when findings > 0, zero `#080b12` hardcoding).

- [ ] **Step 1: Reststrain background ornament in `AlastorBranding.tsx` during IDE work**

Update `AlastorMythicBackground` in `frontend/src/components/AlastorBranding.tsx` so when `showPortalGate === false`, default intensity is ultra-subtle forensic restraint (no distracting high-opacity wallpaper competing with code/tables unless the user explicitly selects `VIVID` in theme settings) and respects `prefers-reduced-motion`.

- [ ] **Step 2: Create `ResizableSplitPane.tsx`**

Implement pointer-captured resize handles (`onPointerDown`, `onPointerMove`, `onPointerUp`) supporting both fixed-pixel sidebar sizing (`minPx=240`, `maxPx=480`, collapsible) and fractional `codeGraphRatio` (`0.25` to `0.75`) with keyboard arrow-key accessibility (`role="separator"`, `tabIndex={0}`).

- [ ] **Step 3: Create `StudioCommandHeader.tsx` (`44px`) and `StudioStatusBar.tsx` (`26px`), and upgrade `LeftFunctionBar.tsx` (`56px`, 5 Studio Workspaces)**

Ensure the complete Public/Private GitHub Repository Scanner modal, Local Folder Browser modal, File/ZIP Upload modal, 7-category Application Menu popover, and Track Changes Delta Drawer are seamlessly accessible from `StudioCommandHeader` and `StudioStatusBar`.

- [ ] **Step 4: Run TypeScript typecheck to verify clean compilation**

Run from `c:\Projects\Securecodereview\cpg-sast-platform\frontend`:
`npx.cmd tsc --noEmit`
Expected: Exit code `0`.

- [ ] **Step 5: Commit Task 3**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add frontend/src/components/AlastorBranding.tsx frontend/src/components/ResizableSplitPane.tsx frontend/src/components/StudioCommandHeader.tsx frontend/src/components/StudioStatusBar.tsx frontend/src/components/LeftFunctionBar.tsx
git commit -m "feat(shell): build 44px StudioCommandHeader, 26px StudioStatusBar, ResizableSplitPane, and 5-pillar theme-aware LeftFunctionBar"
```

---

### Task 4: Unified Studio Workspaces (`ExecutiveAspmWorkspace`, `EngineAccessWorkspace`), Launch Hub & `page.tsx` Shell Wiring

**Files:**
- Create: `frontend/src/components/ExecutiveAspmWorkspace.tsx`
- Create: `frontend/src/components/EngineAccessWorkspace.tsx`
- Modify: `frontend/src/components/SastPlusSuiteView.tsx`
- Modify: `frontend/src/components/AlastorPortalGate.tsx`
- Modify: `frontend/src/components/QuickCommandModal.tsx`
- Modify: `frontend/src/app/page.tsx`

**Interfaces:**
- Consumes: `StudioCommandHeader`, `StudioStatusBar`, `ResizableSplitPane`, `LeftFunctionBar` from Task 3; `executiveAspmTab`, `engineAccessTab`, `hydrateUiPreferences` from Task 2.
- Produces:
  - `ExecutiveAspmWorkspace`: Studio sub-tab bar (`1. Plain-English Impact`, `2. CycloneDX v1.5 SBOM`, `3. API Attack Surface`, `4. Compliance & Analytics`, `5. RACI Governance`, `6. Remediation Roadmap`, `7. Security Academy`) composing `SastPlusSuiteView` (with embedded duplicate header/STRIDE tab hidden via optional `embeddedActiveTab` prop), `DeepDiveDashboard`, and `RaciGovernanceView`.
  - `EngineAccessWorkspace`: Studio sub-tab bar (`1. Rule Profiles (18/18)`, `2. Sanitizer & Cypher Studio`, `3. Multi-Tenant RBAC`, `4. Jira & GitHub Sync`) composing `RuleEngineProfilesView`, `UserAccountProfileView`, inline Cypher/Sanitizer studio, and inline Issue Connector hub.
  - Updated `AlastorPortalGate.tsx`: Sculptural `Cinzel` epigraphic header, 1-click **Paste GitHub Repo URL** launch input right on the Launch Hub alongside **Resume Active Workspace** and **Saved Scan Delta**.
  - Updated `page.tsx`: Calls `hydrateUiPreferences()` on mount, replaces the 4 stacked headers with `StudioCommandHeader` + `LeftFunctionBar` + `ResizableSplitPane` + `StudioStatusBar`.

- [ ] **Step 1: Add `embeddedTab` prop support to `SastPlusSuiteView.tsx` and build `ExecutiveAspmWorkspace.tsx` + `EngineAccessWorkspace.tsx`**

Allow `SastPlusSuiteView` to run cleanly inside `ExecutiveAspmWorkspace` without rendering a duplicate giant banner or duplicate `THREAT_MODEL` tab, while composing `DeepDiveDashboard` (`ANALYTICS`) and `RaciGovernanceView` (`RACI`) under unified `36px` hairline studio sub-tabs. Build `EngineAccessWorkspace.tsx` composing `RuleEngineProfilesView`, `UserAccountProfileView`, and direct triggers/embeds for Cypher/Sanitizer Studio and Jira/GitHub Issue Connectors.

- [ ] **Step 2: Refine `AlastorPortalGate.tsx`, `QuickCommandModal.tsx`, and wire the new 2-Bar Studio Shell in `frontend/src/app/page.tsx`**

1. Upgrade `AlastorPortalGate.tsx` with `font-display` (`Cinzel`), disciplined semantic tokens (`--sig-gold`, `--sig-crimson`, `--sig-emerald`), and a direct **Quick GitHub URL Scan** bar right on the Launch Hub.
2. Update `QuickCommandModal.tsx` (`Ctrl+K`) so all 5 primary workspaces, all sub-tabs (`SBOM`, `RACI`, `Compliance`, `Rule Profiles`, `Accounts`, `STRIDE`, `Secret Vault`), and `"Toggle BFL Patch Diff (d)"` are searchable.
3. Rewrite `frontend/src/app/page.tsx` to render `StudioCommandHeader` (`44px`), the main workspace router with `ResizableSplitPane` around `FlawExplorerSidebar` + `MonacoCodePane` + `ReactFlowGraphPane`, and `StudioStatusBar` (`26px`).

- [ ] **Step 3: Run TypeScript check to verify zero errors**

Run from `c:\Projects\Securecodereview\cpg-sast-platform\frontend`:
`npx.cmd tsc --noEmit`
Expected: Exit code `0`.

- [ ] **Step 4: Commit Task 4**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add frontend/src/components/SastPlusSuiteView.tsx frontend/src/components/ExecutiveAspmWorkspace.tsx frontend/src/components/EngineAccessWorkspace.tsx frontend/src/components/AlastorPortalGate.tsx frontend/src/components/QuickCommandModal.tsx frontend/src/app/page.tsx
git commit -m "feat(workspaces): wire 2-bar Studio shell, 5-pillar composite workspaces, and Launch Hub GitHub quick-scan"
```

---

### Task 5: Signature `"Sever the Thread"` Live Monaco `DiffEditor`, Severed CPG Graph State & Keyboard Triage

**Files:**
- Create: `frontend/src/hooks/useKeyboardNavigation.ts`
- Modify: `frontend/src/components/MonacoCodePane.tsx`
- Modify: `frontend/src/components/ReactFlowGraphPane.tsx`
- Modify: `frontend/src/components/CustomGraphNode.tsx`
- Modify: `frontend/src/components/FlawExplorerSidebar.tsx`
- Modify: `frontend/src/app/page.tsx`

**Interfaces:**
- Consumes: `fetchRemediationPreview`, `applyRemediationPatch`, `undoLastRemediationPatch`, `isDiffEditorOpen`, `setDiffEditorOpen`, `remediationPreview`, `lastAppliedPatch`, `stepFindingPath` in `useAuditStore.ts`.
- Produces:
  - `useKeyboardNavigation()` hook mounted in `page.tsx`: handles `j`/`k` (next/prev finding), `[`/`]` (step backward/forward through CPG taint hops), `d` (toggle live Monaco `DiffEditor`), `1`/`2`/`3` (`Code` / `Split` / `Graph`), `b` (toggle Explorer), ignoring events inside inputs/textareas/editable editors.
  - Upgraded `MonacoCodePane.tsx`:
    - Uses `JetBrains Mono` inside Monaco (`fontFamily: "'JetBrains Mono', Consolas, monospace"`, `fontLigatures: true`).
    - Adds a signature gold **`Preview BFL Diff (d)`** toggle button in the file header bar whenever a finding is selected.
    - When `isDiffEditorOpen` is true, renders `@monaco-editor/react`'s `<DiffEditor>` (`original={remediationPreview.original_content}`, `modified={draftPatchedContent}`, editable modified buffer!) with a crisp action bar: **`⚡ Apply Patch & Re-Verify CPG`** (`Sever the Thread`), **`Download .patch`**, and **`Close Diff`**.
    - Displays an emerald **`✓ THREAD SEVERED · 0 REACHABLE PATHS`** banner with a 1-click **`Undo Patch`** button immediately after `applyRemediationPatch` succeeds!
  - Upgraded `ReactFlowGraphPane.tsx` & `CustomGraphNode.tsx`:
    - Harmonizes node/edge colors to strict semantic tokens (`SOURCE` = `--sig-cyan`, `BFL CHOKEPOINT` = `--sig-gold`, `SINK` = `--sig-crimson`, `VERIFIED SEVERED` = `--sig-emerald` dashed severed edge + shield badge when `lastAppliedPatch?.findingId === selectedFinding?.id && lastAppliedPatch.verifiedSevered`).
  - Decluttered `FlawExplorerSidebar.tsx`:
    - Replaces rainbow badge soup with crisp severity hairlines (`CRITICAL`/`HIGH` crimson, `MEDIUM` gold, `LOW` slate, `VERIFIED` emerald), `font-mono` `filepath:line`, and `j`/`k` active focus scroll-into-view.

- [ ] **Step 1: Create `frontend/src/hooks/useKeyboardNavigation.ts` and mount in `frontend/src/app/page.tsx`**

Implement keyboard navigation ignoring events when `document.activeElement` is `INPUT`, `TEXTAREA`, `SELECT`, `[contenteditable="true"]`, or inside `.monaco-editor textarea` when `isDiffEditorOpen` is editing.

- [ ] **Step 2: Upgrade `MonacoCodePane.tsx` with `JetBrains Mono`, Live `<DiffEditor>`, `"Apply Patch & Re-Verify CPG"`, `.patch` download, and `"Undo Patch"`**

Import `{ DiffEditor }` from `@monaco-editor/react`, wire `fetchRemediationPreview` automatically when `isDiffEditorOpen` becomes `true` (or when `selectedFinding` changes while diff is open), allow editing the modified right-hand buffer before clicking **`Apply Patch & Re-Verify CPG`**, and surface the emerald **`✓ THREAD SEVERED`** + **`Undo Patch`** bar.

- [ ] **Step 3: Upgrade `ReactFlowGraphPane.tsx`, `CustomGraphNode.tsx`, and `FlawExplorerSidebar.tsx` with semantic discipline & `"Severed"` CPG animation**

Render the emerald `"✓ THREAD SEVERED · 0 REACHABLE PATHS"` graph banner and emerald severed edge state in `ReactFlowGraphPane.tsx` upon remediation verification, and clean up `FlawExplorerSidebar.tsx` to match the Forensic Instrument token system in both Dark and Light modes.

- [ ] **Step 4: Run full production Next.js build (`npm run build`) to verify SSR, bundling, and TypeScript**

Run from `c:\Projects\Securecodereview\cpg-sast-platform\frontend`:
`npm.cmd run build`
Expected: `✓ Compiled successfully` and `✓ Generating static pages` with exit code `0`.

- [ ] **Step 5: Commit Task 5**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add frontend/src/hooks/useKeyboardNavigation.ts frontend/src/components/MonacoCodePane.tsx frontend/src/components/ReactFlowGraphPane.tsx frontend/src/components/CustomGraphNode.tsx frontend/src/components/FlawExplorerSidebar.tsx frontend/src/app/page.tsx
git commit -m "feat(sever-the-thread): add live Monaco DiffEditor BFL patching, CPG severed proof, and j/k keyboard triage"
```

---

### Task 6: Autonomous 20-Assertion E2E Verification (`Assertion U`), Zero-Finding Self-Audit & Live Visual Critique

**Files:**
- Modify: `verify_harness.py`

**Interfaces:**
- Consumes: Live Neo4j + FastAPI (`127.0.0.1:8000`) + Next.js (`localhost:3000`) stack from Tasks 1–5.
- Produces:
  - `Assertion U` (`20 / 20` total E2E assertions) in `verify_harness.py` testing end-to-end `POST /api/remediate/preview` -> `POST /api/remediate/apply` (proving `verified_severed == True` and finding elimination in Neo4j CPG) -> `POST /api/remediate/undo` (proving exact SHA256 restoration) on an isolated temporary target directory, followed by the final `cpg-sast-platform` self-audit (`0` findings).
  - Rendered Playwright visual critique across Desktop (`1600×1000`) and Compact Laptop (`1280×800`) in Dark (`alastor-infernal`) and Light (`olympian-light`) modes per `frontend-design` Step 5, fixing any visual/contrast/overflow mismatch inline.

- [ ] **Step 1: Add `Assertion U` to `verify_harness.py`**

Extend `verify_harness.py` to create a temporary workspace directory containing a Python module with an intentional `RULE-6-SHELL-INJECTION` (`subprocess.run(f"echo {user_cmd}", shell=True)`), scan it via `POST /api/scan`, verify at least 1 finding is detected, call `POST /api/remediate/preview`, call `POST /api/remediate/apply`, assert `verified_severed is True` and `remaining_findings_count == 0`, call `POST /api/remediate/undo`, assert `restored_sha256` matches the original SHA256, and then run the final self-audit scan of `cpg-sast-platform` asserting `0` findings!

- [ ] **Step 2: Start Neo4j, FastAPI Backend, and Next.js Production Frontend, and execute `verify_harness.py`**

Run from `c:\Projects\Securecodereview\cpg-sast-platform`:
`.\.venv\Scripts\python.exe verify_harness.py`
Expected:
- `20 / 20` E2E Enterprise Assertions `PASS` (100%)
- Self-Audit of `cpg-sast-platform`: `0` Active Findings (`SAST: 0, SCA: 0, IaC: 0, Secrets: 0`)

- [ ] **Step 3: Execute `frontend-design` Step 5 Visual Critique (Desktop + Laptop, Dark + Light, Live BFL DiffEditor)**

Capture live Playwright screenshots of:
1. Launch Hub (`AlastorPortalGate`)
2. 2-Bar Precision Workbench (`44px` Header + Resizable Split Panes + `26px` Status Bar) in `Alastor Infernal` Dark
3. Signature `"Sever the Thread"` live Monaco `DiffEditor` + CPG canvas
4. Unified `Executive ASPM` 7-tab workspace & `Engine & Access` 4-tab workspace
5. `Olympian Daylight` Light Mode across Workbench & Left Rail (verifying zero `#080b12` dark leaks and crisp contrast)
6. Compact `1280×800` viewport check (verifying zero header collision or text clipping)

Inspect every captured screenshot directly via `read_file` and fix any visual blemish immediately before final build & commit.

- [ ] **Step 4: Commit Task 6**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add verify_harness.py
git commit -m "test(e2e): add Assertion U (20/20) verifying live BFL patch, CPG severing proof, undo journal, and 0 self-audit findings"
```
