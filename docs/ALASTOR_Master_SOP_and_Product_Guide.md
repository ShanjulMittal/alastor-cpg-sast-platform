# ALASTOR (`Ἀλάστωρ`) v4.0.0 — Enterprise Product Guide, Feature Catalog & Master Standard Operating Procedure (SOP)

**Deterministic Code Property Graph (AST + CFG + DFG + Call Graph) • Guided 4-Stage High-Contrast WCAG AA Daylight Studio (`1. Scan & Repos · 2. Triage & Fix · 3. 360° Map & Threats · 4. ASPM, Rules & Reports`) • 100% Directional CPG, 360° Cross-File `IMPORTS ▶` & 4-Zone Trust Boundary Graphs with Flow Story Bar & Blast Radius • One-Click `"Fix All Safe Issues"` Atomic Batch Auto-Patcher + Live Monaco BFL `DiffEditor` • Token-Efficient Multi-Provider BYOK Frontier AI Copilot (`90–95%` Savings via CPG Micro-Slicing & SHA-256 Cache) • Public & Private GitHub Scanner • Live OSV.dev Reachable SCA • STRIDE Matrix • CycloneDX v1.5 SBOM • Multi-Tenant RBAC & PMI/COBIT RACI**

![ALASTOR Mythological Demon Crest](./screenshots/alastor_demon_logo.jpg)

> [!IMPORTANT]
> **Dual-Purpose Executive & Operator Document (Updated for Release v4.0.0)**:
> 1. **Part I & II (Executive Pitch & Competitive Differentiation)**: Designed for CISOs, VPs of Engineering, Enterprise Architects, and Procurement Leaders evaluating why ALASTOR `v4.0.0` outperforms Semgrep, legacy static analyzers, and expensive cloud scanners.
> 2. **Part III, IV & V (Complete 4-Stage Feature Reference & Master SOP)**: A step-by-step Standard Operating Procedure enabling Security Engineers, Developers, and Non-Coder Managers to master every stage, directional graph, Frontier AI workflow, batch auto-fix, keyboard shortcut, and REST API.
> 3. **Part VI (Version History & Release Changelog)**: Detailed breakdown from `v1.0.0` through `v4.0.0`.

---

## Part I: Executive Vision — Why ALASTOR `v4.0.0` Wins

Modern engineering organizations suffer from five systemic failures in Application Security (AppSec):
1. **Directionless Graph Hairballs**: Legacy visualizers draw lines into hidden center points without visible arrowheads, numbered steps, cross-file import edges, or blast-radius context.
2. **UI Complexity & Low-Contrast Eye Strain**: Nested 7-level menus and dark-on-dark palettes slow down triage and make executive reviews difficult to read.
3. **Runaway LLM Token Costs & Context Leaks**: Naive AI code scanners upload entire 1,000-line files on every prompt, burning token budgets and sending unrelated proprietary business logic off-machine.
4. **Alert Fatigue & Manual Patching Friction**: Regex scanners flood teams with false positives on custom sanitizers and force developers to fix issues one file at a time.
5. **Siloed Tools Across Personas**: Engineers need AST/DFG paths, Monaco diffs, and `.patch` files; CISOs need `STRIDE` verdicts, `CycloneDX v1.5` SBOMs, `OWASP/PCI/NIST/SOC 2` posture, and `RACI` governance.

### The ALASTOR `v4.0.0` Core Value Proposition

| Business Outcome | How ALASTOR `v4.0.0` Delivers It |
| :--- | :--- |
| **100% Directional Graphs & Blast Radius** | Perimeter-docked `18×18` outer-border arrowheads, `①`–`⑳` step badges, cross-file `IMPORTS ▶` / `CALLS ▶` arcs, 3-step single-node flow synthesis, a plain-English **Flow Story Bar**, **BFS Blast Radius** highlighting, and an interactive **4-Zone Trust Boundary ReactFlow Graph**. |
| **Guided 4-Stage WCAG AA Daylight UI** | Streamlined `44px` top workflow bar (**`1. Scan & Repos`** $\rightarrow$ **`2. Triage & Fix`** $\rightarrow$ **`3. 360° Map & Threats`** $\rightarrow$ **`4. ASPM, Rules & Reports`**) rendered exclusively in crisp **`>= 4.5:1` WCAG AA High-Contrast Daylight** palettes with **zero feature reduction**. |
| **90–95% Token-Saving BYOK Frontier AI** | Connect **Google Gemini**, **OpenAI**, **Anthropic Claude**, or **OpenAI-Compatible / Local Ollama** via a `0o600` `.alastor_vault` store. Deterministic **≤40-line CPG Micro-Slicing** + **SHA-256 Slice Caching** (`0` tokens on repeat hits) slash token usage while powering Batch TP/FP Validation, Monaco Selection Audits, AI Patching, and Graph Explanations. |
| **One-Click `"Fix All Safe Issues"` Batch Patcher** | `POST /api/remediate/batch-apply` applies non-overlapping AST-verified fixes bottom-up (`target_line DESC`), validates Python/JS syntax, rolls back atomically on conflict, exports a `git apply` `.patch`, and re-scans the CPG to prove severance. |
| **Mathematical Zero-Noise Precision (`21` Rules)** | Compiles source code via **Tree-Sitter** into **Neo4j 5 + APOC**, proving source-to-sink exploitability, verifying custom helper AST sanitizers (`0%` FP), and cross-checking live `OSV.dev` lockfile CVEs against AST `Import` reachability. |

---

## Part II: Competitive Benchmark — ALASTOR `v4.0.0` vs. Legacy & Cloud AppSec Tools

| Enterprise Capability | Legacy SAST (Checkmarx / Fortify) | Cloud SCA (Snyk / Dependabot) | Semgrep Pro | **ALASTOR `v4.0.0` (`Daylight Studio`)** |
| :--- | :---: | :---: | :---: | :---: |
| **True AST + CFG + DFG + Call Graph CPG (Neo4j)** | Partial (Proprietary) | ❌ No | ❌ No | ✅ **Yes (Open Cypher + Tree-Sitter)** |
| **Perimeter-Arrow Directional 360° & 4-Zone Trust Graphs** | ⚠️ Static taint tree | ❌ No | ❌ No | ✅ **Yes (`①②③` + Story Bar + Blast Radius)** |
| **Multi-Provider BYOK Frontier AI + CPG Micro-Slicing** | ☁️ Paid Cloud Add-On | ☁️ Vendor-Locked | ☁️ Vendor-Locked | ✅ **`Gemini`/`OpenAI`/`Claude`/`Ollama` (`90–95%` Saved)** |
| **One-Click Multi-File Batch Auto-Patcher + SHA-256 Undo** | ❌ No | Partial (PRs) | ⚠️ Single-finding AI | ✅ **Yes (Bottom-Up AST Batch + `.patch` + Undo)** |
| **Direct GitHub Scan (Public URL + Private PAT Header)** | ⚠️ Heavy Server Setup | ☁️ Cloud OAuth | ☁️ Cloud App | ✅ **Yes (Zero-Token Public + Ephemeral PAT)** |
| **AST-Verified Custom Sanitizer Body Summary (`0%` FP)** | ❌ No | ❌ No | ⚠️ Manual YAML | ✅ **Yes (`commonpath`, `ipaddress`, CRLF)** |
| **STRIDE Verdict Matrix + CycloneDX v1.5 SBOM + RACI** | ❌ No | Partial (SBOM only) | ❌ No | ✅ **Yes (All Built-In + Light HTML/CSV/SARIF)** |
| **100% Local Execution (Zero Mandatory Cloud Upload)** | ❌ Heavy Server | ❌ Cloud SaaS | ❌ Cloud Control Plane | ✅ **Yes (Self-Contained Local Stack, MIT)** |

---

## Part III: Visual Tour of the ALASTOR `v4.0.0` Daylight Studio (Live Screenshots)

````carousel
![1. ALASTOR v4.0 Daylight Launch Portal — Active Target, Saved Scan Delta & Neo4j Telemetry](./screenshots/alastor_01_portal_gate.png)
<!-- slide -->
![2. Stage 2 (Triage & Fix) — Split Light Monaco Inspector, Dossier, Flow Story Bar & Directional Attack Path](./screenshots/alastor_02_code_review_dossier.png)
<!-- slide -->
![3. Frontier AI BYOK Multi-Provider Vault & Live CPG Micro-Slice Token Efficiency Meter (93.4% Saved)](./screenshots/shot_27_frontier_ai_byok_vault.png)
<!-- slide -->
![4. Frontier AI Batch TP/FP Validation Digest & Per-Finding AI Confidence Chips](./screenshots/shot_27b_frontier_ai_validate_verdicts.png)
<!-- slide -->
![5. One-Click "Fix All Safe Issues" Batch Auto-Patcher & Unified .patch Verification Banner](./screenshots/shot_28_batch_autofix_and_patch.png)
<!-- slide -->
![6. Live BFL "Sever the Thread" Side-by-Side Light Monaco DiffEditor](./screenshots/alastor_10_before_after_diff_and_spider_map.png)
<!-- slide -->
![7. Stage 3 — 360° Architecture Spider Map with Cross-File IMPORTS ▶ Directional Arcs](./screenshots/shot_05_graph_spider_map_360.png)
<!-- slide -->
![8. Stage 3 — Interactive 4-Zone Directional Trust Boundary ReactFlow Graph](./screenshots/shot_11_trust_boundaries_map.png)
<!-- slide -->
![9. Stage 1 (Scan & Repos) — Multi-Repository Hub, Public/Private GitHub Import & Webhooks](./screenshots/alastor_04_projects_hub.png)
<!-- slide -->
![10. Stage 4 — Executive Compliance & SLA Analytics (OWASP Top 10, PCI-DSS v4.0, NIST, SOC 2)](./screenshots/alastor_05_deep_dive_analytics.png)
<!-- slide -->
![11. Stage 4 — Interactive PMI/COBIT RACI Security Governance Matrix](./screenshots/alastor_06_raci_governance_matrix.png)
<!-- slide -->
![12. Stage 4 — Live CycloneDX v1.5 Software Bill of Materials (SBOM)](./screenshots/alastor_09_live_sbom_cyclonedx.png)
````

---

## Part IV: Guided 4-Stage Studio Architecture & Feature Catalog

### Top Command Header (`StudioCommandHeader.tsx`, `44px`) & Status Bar (`StudioStatusBar.tsx`, `26px`)
- **Left Cluster**: `[Ἀ] ALASTOR` Launch Portal button + Active Repository Picker (`FOLDER` / `FILE` / `URL` / `UPLOAD`) + Instant Saved-Snapshot Switcher.
- **Center Guided 4-Stage Workflow Bar**:
  1. **`1. Scan & Repos`**: Quick path/GitHub URL scan bar, Target Picker launchers, Track Changes history, and `ProjectsHubView`.
  2. **`2. Triage & Fix`**: Resizable `FlawExplorerSidebar` (with **`Fix All Safe Issues`** + **`Batch AI Validate`**), `MonacoCodePane` (`theme="light"` + selection AI toolbar + BFL `DiffEditor`), and `ReactFlowGraphPane`.
  3. **`3. 360° Map & Threats`**: Full-width **`360° Architecture & Call Flows`** (`APP_TREE`, `CALL_GRAPH`, `ENTRYPOINT_GRAPH`, `DFG_ONLY`, `CFG_ONLY`, `FULL_CPG`) and **`Trust Boundaries, STRIDE & PBOM`** (`4-Zone Trust Boundary Flow Map`, `STRIDE Dossier`, `Secret Keys Vault`, `Entrypoints & PBOM`).
  4. **`4. ASPM, Rules & Reports`**: 5-pill governance center (`1. Executive Posture`, `2. SAST+ Suite & SBOM`, `3. Rules, Cypher & Web CVE Intel`, `4. Governance, RBAC & Connectors`, `5. Export Center`).
- **Right Cluster**: `Scan` button / live 7-pass progress pill, `+Fixed / +New` delta toggle, `⌘K` Omnibar, `⚙` Settings, **3-Palette Daylight Theme Switcher** (*Olympian Daylight*, *Athena Parchment*, *Hyperborean Frost*), and **`✨ Frontier AI`** Copilot drawer button.

---

## Part V: Master Standard Operating Procedure (SOP) — Step-by-Step User Manual

### SOP 1: Scanning a Local Folder or GitHub Repository (`Stage 1: 1. Scan & Repos`)
1. Open **`1. Scan & Repos`** (or click **`GitHub Repo (Public / PAT)`**).
2. **Open / Public GitHub Repo**: Paste `https://github.com/owner/repo` (or `owner/repo`) and click **`Scan Target`** / **`Clone & Scan Repo`** — zero token required.
3. **Private GitHub / GitLab / Bitbucket Repo**: Switch to **`Private Repository (AUTH REQUIRED)`**, paste your PAT (`ghp_...` or `github_pat_...`), optionally enable `.alastor_vault` persistence, and click **`Authenticate, Clone & Scan`**.

### SOP 2: Triage, One-Click Batch Auto-Fix & Single-Finding BFL Diff (`Stage 2: 2. Triage & Fix`)
1. Step through findings with **`j`** / **`k`** (or click any card) and step along directional CPG hops (`①` $\rightarrow$ `②` $\rightarrow$ `③`) with **`[`** / **`]`**.
2. **Batch Auto-Fix**: Click **`Fix All Safe Issues (N)`** at the top of the Flaw Explorer to atomically patch all safe findings bottom-up, re-verify CPG taint severance, and download the unified `.patch` file.
3. **Single-Finding BFL Diff & Undo**: Press **`d`** to inspect the side-by-side light **Monaco `DiffEditor`**, apply the patch to disk, or revert any applied fix via `.alastor_patches` SHA-256 undo.

### SOP 3: Connecting BYOK Frontier AI Copilot (`✨ Frontier AI` Drawer)
1. Click **`✨ Frontier AI`** in the top-right header and open the **`BYOK Vault`** tab.
2. Select **`Google Gemini`**, **`OpenAI`**, **`Anthropic Claude`**, or **`OpenAI-Compatible / Local Ollama`**, enter your API key (or local `http://127.0.0.1:11434/v1` base URL), click **`Test Connection`**, and save (`0o600` local permissions).
3. Use **`Batch AI Validate`** in Stage 2, highlight code lines in Monaco to click **`✨ AI Audit Selection`**, synthesize an **`AI Patch`** directly into the Monaco `DiffEditor`, or click **`✨ AI Explain Flow`** on any CPG/Trust-Boundary graph while monitoring real-time token savings in the **CPG Micro-Slice Token Efficiency Meter**.

### SOP 4: Exploring Directional 360° Architecture & 4-Zone Trust Boundaries (`Stage 3: 3. 360° Map & Threats`)
1. In **`360° Architecture & Call Flows`**, toggle **`Cross-File Flows`** to inspect purple `IMPORTS ▶` and blue `CALLS ▶` arcs across modules, and hover or click any node to lock its **Upstream & Downstream Blast Radius**.
2. Switch to **`Trust Boundaries, STRIDE & PBOM`** to inspect the interactive **4-Zone Trust Boundary Flow Map** (`Zone 1 Ingress -> Zone 2 Entrypoints -> Zone 3 Validation & BFL -> Zone 4 Critical Sinks & Secrets`), click any node to jump straight to its source line in Stage 2, or audit the **STRIDE Dossier**, **Secret Keys Vault**, and **CI/CD PBOM**.

---

## Part VI: Release History Summary

- **Version `4.0.0` (2026-11-11)**: 100% Directional CPG/360°/Trust-Boundary Graphs (perimeter arrowheads, step indices, cross-file `IMPORTS ▶`, 3-step single-node synthesis, Flow Story Bar, Blast Radius), Guided 4-Stage WCAG AA Daylight-Only Studio (`0` feature reduction), One-Click Atomic `"Fix All Safe Issues"` Batch Auto-Patcher, Token-Efficient Multi-Provider BYOK Frontier AI Copilot (`90–95%` Micro-Slice savings + SHA-256 cache), `31/31` pytest (`0` warnings), and `20/20` Self-Audit pass (`0` findings).
- **Version `3.0.0` (2026-11-10)**: Live BFL `"Sever the Thread"` Auto-Patcher (`preview`/`apply`/`undo`), `RULE-14`–`RULE-16` (`21/21` rules), CPG-Backed Zero-FP Web Intel, and `O(1)` UNWIND Neo4j ingestion.
- **Version `2.6.2`–`v1.0.0` (2026-10)**: Public/Private GitHub Scanner, AST-Verified Sanitizer Summaries, Live `OSV.dev` Reachable SCA, CI/CD Workflow Security (`IAC-3`), STRIDE Matrix, Secret Vault, Multi-Tenant RBAC, RACI Governance, CycloneDX v1.5 SBOM, and Core Tree-Sitter + Neo4j CPG Engine.
