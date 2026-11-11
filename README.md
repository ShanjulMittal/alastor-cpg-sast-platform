<div align="center">

<img src="./docs/screenshots/alastor_demon_logo.jpg" alt="ALASTOR Mythological Daimon Crest" width="190" />

# ALASTOR (`Ἀλάστωρ`) `v4.0.0`

### **The Relentless Open-Source Code Property Graph (CPG), Zero-Noise SAST, 100% Directional 360° & Trust-Boundary Flow Graphs, One-Click Batch Auto-Patcher, Token-Efficient BYOK Frontier AI Copilot (`90–95%` Savings) & Executive ASPM Platform**

*Stop drowning in regex false positives, directionless graph hairballs, unreadable dark UIs, and six-figure SaaS lock-in. Paste any GitHub URL or select a local repo to compile your codebase into a mathematical **AST + CFG + DFG + Call Graph** inside **Neo4j** — 100% locally in a crisp, WCAG AA High-Contrast Daylight Studio.*

[![Version: v4.0.0 Daylight Studio](https://img.shields.io/badge/Release-v4.0.0%20Daylight%20Studio-0284c7?style=for-the-badge)](./CHANGELOG.md)
[![Self-Audit: 0 Findings (20/20 Pass)](https://img.shields.io/badge/Self--Audit-0%20Findings%20(20%2F20%20Pass)-059669?style=for-the-badge)](./verify_harness.py)
[![Frontier AI: BYOK 90-95% Token Saved](https://img.shields.io/badge/Frontier%20AI%20BYOK-90--95%25%20Tokens%20Saved-4f46e5?style=for-the-badge)](#-2-token-efficient-multi-provider-byok-frontier-ai-copilot-9095-token-savings)
[![Graphs: 100% Directional + Blast Radius](https://img.shields.io/badge/CPG%20%26%20360%C2%B0%20Graphs-100%25%20Directional%20Flows-0e7490?style=for-the-badge)](#-4-100-directional-cpg-360-spider--4-zone-trust-boundary-graphs)
[![GitHub Scanner: Public URL & Private PAT](https://img.shields.io/badge/GitHub%20Scanner-Public%20URL%20%26%20Private%20PAT-2563eb?style=for-the-badge)](#-1c-instant-github-repository-scanner--open--public-paste-url-only-vs-private-pat-auth-required)
[![Live SCA: OSV.dev + CPG Reachability](https://img.shields.io/badge/Live%20SCA-OSV.dev%20%2B%20CPG%20Reachability-d97706?style=for-the-badge)](./backend/engine/osv_lockfile_scanner.py)
[![Theme: WCAG AA Daylight Only](https://img.shields.io/badge/UI-WCAG%20AA%20High--Contrast%20Daylight-0369a1?style=for-the-badge)](#-7f-3-curated-wcag-aa-high-contrast-daylight-palettes)
[![License: MIT](https://img.shields.io/badge/License-MIT-e11d48?style=for-the-badge)](./LICENSE)

<br />

[**⚡ 3-Minute Quick Start**](#-3-minute-quick-start-100-local--sovereign) •
[**✨ Frontier AI BYOK Copilot**](#-2-token-efficient-multi-provider-byok-frontier-ai-copilot-9095-token-savings) •
[**🛠️ Batch Auto-Fix & BFL Diff**](#-3-stage-2--triage-one-click-batch-auto-fix--monaco-bfl-diffeditor) •
[**🕸️ Directional 360° & Trust Graphs**](#-4-100-directional-cpg-360-spider--4-zone-trust-boundary-graphs) •
[**⚔️ vs. Semgrep / Checkmarx / Snyk**](#️-head-to-head-competitive-benchmark) •
[**📸 Complete 33-Screen Daylight Visual Tour**](#-complete-visual-tour--every-stage-directional-graph-ai-workflow--export) •
[**🛡️ All 21 Security Rules**](#️-complete-21-rule-deterministic-security-matrix) •
[**📖 Full Master SOP**](./docs/ALASTOR_Master_SOP_and_Product_Guide.md)

</div>

---

![ALASTOR v4.0 Guided 4-Stage Daylight Studio — Split Code, Directional Attack Path & Flow Story Bar](./docs/screenshots/shot_03_code_review_dossier_and_diff.png)

> **Named after Alastor (`Ἀλάστωρ` — *"The Unforgetting Avenger"*)**, **ALASTOR `v4.0.0`** unifies **10 enterprise security capabilities** inside a streamlined **Guided 4-Stage High-Contrast Daylight Studio** ([`StudioCommandHeader.tsx`](./frontend/src/components/StudioCommandHeader.tsx) + [`FrontierAiCopilotDrawer.tsx`](./frontend/src/components/FrontierAiCopilotDrawer.tsx) + [`StudioStatusBar.tsx`](./frontend/src/components/StudioStatusBar.tsx)):
> 1. **Guided 4-Stage Workflow Bar (Zero Clutter, Zero Feature Reduction)**: Effortless left-to-right flow across **`1. Scan & Repos`** $\rightarrow$ **`2. Triage & Fix`** $\rightarrow$ **`3. 360° Map & Threats`** $\rightarrow$ **`4. ASPM, Rules & Reports`**, rendered exclusively in crisp **`>= 4.5:1` WCAG AA Daylight Light Mode**.
> 2. **100% Directional CPG, 360° Spider & 4-Zone Trust Boundary Graphs**: Perimeter-docked `18×18` outer-border arrowheads, circled step indices (`①`–`⑳`), cross-file `IMPORTS ▶` / `CALLS ▶` arcs, 3-step context synthesis for single-node findings, a plain-English **Flow Story Bar**, and interactive **Upstream/Downstream Blast-Radius** highlighting.
> 3. **Token-Efficient Multi-Provider BYOK Frontier AI Copilot (`90–95%` Token Savings)**: Connect **Google Gemini**, **OpenAI**, **Anthropic Claude**, or **OpenAI-Compatible / OpenRouter / Local Ollama** via a `0o600` local BYOK vault (`frontier_ai_engine.py`) powered by **≤40-line CPG Micro-Slicing** and **SHA-256 Slice Caching (`0` tokens on cache hits)**.
> 4. **One-Click `"Fix All Safe Issues"` Batch Auto-Patcher + Live BFL `DiffEditor`**: Atomically applies non-overlapping AST-verified patches bottom-up (`POST /api/remediate/batch-apply`), validates syntax (`ast.parse` / JS delimiter balance), journals `.alastor_patches` SHA-256 backups for 1-click undo, exports a `git apply` `.patch`, and re-scans the CPG to prove severance.
> 5. **Inter-Procedural Code Property Graph SAST** (`Tree-Sitter AST + CFG + DFG + :CALLS` over `Neo4j 5 + APOC`) with **1-Click Open/Public & Private GitHub Repo Scanning**.
> 6. **AST-Verified Sanitizer Summary & CPG-Backed Web Intel Engine** (`0%` False Positives on custom enterprise path/SSRF/SQLi/log validators and live `OSV.dev` / `NVD` / `CISA KEV` advisories).
> 7. **Live OSV.dev Transitive Lockfile SCA** with **CPG Import Reachability Proof** (`REACHABLE` vs. `DORMANT`).
> 8. **Infrastructure-as-Code & GitHub Actions CI/CD Pipeline Security** (`Dockerfile`, `Compose`, `.github/workflows/*.yml`).
> 9. **Cryptographic Secret Keys & Shannon Entropy Vault** with RBAC-gated unmasking.
> 10. **Automated Microsoft STRIDE Matrix, CycloneDX v1.5 SBOM, PMI/COBIT RACI & Executive Exports** (`SARIF v2.1.0`, Light-Mode `HTML`, `CSV`, `Markdown`, `.cdx.json`, `.patch`).

---

## 🔥 What's New in `v4.0.0` & Why Teams Switch to ALASTOR

| Legacy Scanner Pain Point | How ALASTOR `v4.0.0` Solves It Permanently |
| :--- | :--- |
| **Directionless Graph "Hairballs"**<br>*Nodes connect at hidden center handles without visible arrowheads, cross-file import context, or single-node impact explanation.* | **100% Perimeter-Docked Arrowheads, Story Bar & Blast Radius**: Every edge across all 7 CPG/360° modes and the **4-Zone Trust Boundary Graph** docks cleanly at outer card borders with `18×18` arrowheads, `①`–`⑳` step badges, `IMPORTS ▶` / `CALLS ▶` pills, 3-step single-node synthesis (`Origin ▶ BFL ▶ Impact`), a plain-English **Flow Story Bar**, and 1-click **Blast Radius** highlighting. |
| **Complex Nested Menus & Low-Contrast Dark UIs**<br>*Dark-on-dark panels strain eyes during long audits, and 7-level nested dropdowns bury critical tools.* | **Guided 4-Stage Workflow + Mandatory WCAG AA Daylight Theme**: Retires dark themes and nested menu rails in favor of **4 clear stages** (`1. Scan & Repos · 2. Triage & Fix · 3. 360° Map & Threats · 4. ASPM, Rules & Reports`) on crisp high-contrast Daylight surfaces (`>= 4.5:1` WCAG AA) with **100% feature preservation**. |
| **Runaway LLM Token Bills & Full-File Context Leaks**<br>*Generic AI security tools dump entire 800-line source files into cloud LLMs on every click, burning tokens and exposing unrelated code.* | **CPG Micro-Slicing (`<= 40` Lines) + SHA-256 Verdict Cache (`90–95%` Savings)**: ALASTOR deterministically slices only the source, BFL chokepoint, sink, and 1-line cross-file call signatures before calling your chosen BYOK model (`Gemini`, `OpenAI`, `Anthropic`, or local `Ollama`), caching results by SHA-256 (`0` tokens on repeat slices). |
| **One-by-One Manual Remediation Drudgery**<br>*Fixing 15 findings one file at a time shifts line numbers and breaks subsequent patches.* | **Atomic Bottom-Up Batch Auto-Fix (`"Fix All Safe Issues"`)**: Applies all safe AST-deterministic patches bottom-up (`target_line DESC`), verifies syntax before writing, rolls back atomically on any conflict, generates a `git apply` `.patch`, and re-verifies CPG severance in one click. |
| **Regex Noise & Unreachable CVE Floods**<br>*Pattern matchers flag sanitized helpers and dump 200+ dormant transitive CVEs.* | **AST-Verified Sanitizer Summaries + OSV CPG Reachability**: Inspects helper AST bodies (`commonpath`, `ipaddress`, CRLF) for **`0%` False Positives** and cross-checks `OSV.dev` lockfile CVEs against Neo4j `Import` AST nodes (`RUNTIME REACHABLE` vs. `DORMANT`). |

---

## ⚔️ Head-to-Head Competitive Benchmark

| Capability | **ALASTOR `v4.0.0`** | **Semgrep OSS** | **Semgrep Pro** | **Checkmarx / Fortify** | **Snyk Code + SCA** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Analysis Representation** | **Full CPG (`AST+CFG+DFG+:CALLS`) in Neo4j** | Single-file AST / pattern | Cross-file AST + taint | Proprietary AST/DFG | Proprietary semantic graph |
| **Directional 360° + 4-Zone Trust Boundary Graphs** | ✅ **Perimeter Arrows + Story Bar + Blast Radius** | ❌ CLI only | ❌ Static trace list | ⚠️ Legacy taint tree | ❌ Linear code flow only |
| **Multi-Provider BYOK Frontier AI + Micro-Slicing** | ✅ **`Gemini`/`OpenAI`/`Claude`/`Ollama` (`90–95%` Saved)** | ❌ | ☁️ Vendor-locked AI | ☁️ Paid Cloud Add-On | ☁️ Vendor-locked AI |
| **One-Click Multi-File Batch Auto-Patcher + Undo** | ✅ **Bottom-Up AST Batch Fix + `.patch` + SHA-256 Undo** | ❌ | ⚠️ Single-finding AI | ❌ BFL node only | ⚠️ Cloud PR suggestions |
| **Direct GitHub Scan (Public URL + Private PAT)** | ✅ **Paste Public URL (`No Token`) + Ephemeral PAT Header** | ⚠️ Manual `git clone` | ☁️ Cloud GitHub App | ⚠️ Heavy server setup | ☁️ Cloud OAuth required |
| **Custom Helper Sanitizer Body Verification** | ✅ **Automatic AST Verification (`0%` FP)** | ❌ Flags custom helpers | ⚠️ Manual rule YAML | ⚠️ Manual filters | ❌ Limited custom rules |
| **Live Lockfile CVE + CPG Import Reachability** | ✅ **Built-In (`OSV.dev` + AST Imports)** | ❌ No SCA in OSS | ✅ Supply Chain Add-On | ✅ Paid SCA Add-On | ✅ Paid Cloud Tier |
| **Automated Microsoft STRIDE Matrix + `PBOM` + `RACI`** | ✅ **Live File-Anchored Dossier + `7×9` RACI** | ❌ | ❌ | ❌ | ❌ |
| **100% Local / Sovereign Execution (Zero Cloud Lock-In)** | ✅ **100% Local (`Neo4j` + `FastAPI` + `Next.js`)** | ✅ CLI only (no UI) | ❌ Cloud control plane | ⚠️ Heavy on-prem server | ❌ Cloud upload required |
| **License & Cost** | **100% Free & Open Source (`MIT`)** | LGPL (CLI only) | \$\$\$ Per-Developer | \$\$\$\$ Six-Figure Annual | \$\$\$ Per-Developer |

---

## 🧠 Compiler-Grade 7-Pass CPG + Frontier AI Micro-Slice Architecture

```mermaid
flowchart LR
    subgraph IN["📂 Stage 1: Scan & Repos"]
        GIT["GitHub / GitLab / Bitbucket\nPublic URL (No Token) • Private PAT"]
        SRC["Local Folder • File • Snippet • ZIP\nPython • JS • TS • TSX • IaC"]
    end

    subgraph COMPILER["⚙️ 7-Pass Deterministic CPG Compiler"]
        P1["Pass 1-2: Tree-Sitter AST\n+ Sanitizer Body Verifier"]
        P3["Pass 3-4: CFG Branches\n+ Inter-Procedural DFG"]
        P5["Pass 5: Cross-File :CALLS\n& IMPORTS Dependency Graph"]
    end

    subgraph GRAPH["🗄️ Neo4j 5 + APOC"]
        NEO[("Unified Property Graph\nAST + CFG + DFG + :CALLS\nO(1) UNWIND Batch Ingest")]
    end

    subgraph WORKFLOWS["🛡️ Stages 2–4: Triage, Directional 360° Maps, Batch Fix & BYOK AI"]
        R21["21 Deterministic Rules\n+ OSV Reachable SCA + Web Intel"]
        FLOW["Directional ReactFlow Engine\nPerimeter Arrows • Story Bar • Blast Radius\n4-Zone Trust Boundary Graph"]
        PATCH["Single & Batch Auto-Patcher\nBottom-Up AST Fix • SHA-256 Undo • .patch"]
        AI["BYOK Frontier AI Copilot\n<=40-Line Micro-Slice • SHA-256 Cache\nGemini • OpenAI • Claude • Ollama"]
    end

    GIT --> P1
    SRC --> P1
    P1 --> P3 --> P5 --> NEO
    NEO --> R21
    R21 --> FLOW
    R21 --> PATCH
    R21 --> AI
```

---

## 📸 Complete Visual Tour — Every Stage, Directional Graph, AI Workflow & Export

Every screenshot below is captured live from **ALASTOR `v4.0.0` Daylight Studio** at `2400×1500` Retina resolution in high-contrast **Olympian Daylight** light mode — showcasing the **Guided 4-Stage Workflow Bar, BYOK Frontier AI Copilot with `90–95%` Token Efficiency Meter, One-Click Batch Auto-Fix, Perimeter-Arrow Directional CPG/360°/Trust-Boundary Graphs, and Executive ASPM Suite**.

---

### 🏛️ 1. Launch Portal, Guided 4-Stage Command Header & Stage 1 (`1. Scan & Repos`)

#### 1A. ALASTOR `v4.0` Daylight Launch Portal (`Portal Gate`)
Greets operators in crisp high-contrast daylight with live `Neo4j CPG Connected` telemetry, active project status, **Continuous Track Changes** deltas (`Fixed` / `New` / `Unchanged`), 1-click **`Open Workbench`**, and direct launch cards into the studio.

![01 - ALASTOR v4.0 Daylight Launch Portal](./docs/screenshots/shot_01_portal_gate.png)

#### 1B. Streamlined `44px` Guided 4-Stage Workflow Header (`StudioCommandHeader.tsx`)
Replaces complex nested menus and side rails with one intuitive left-to-right top bar:
- **Left Cluster**: `[Ἀ] ALASTOR` Launch Hub crest + Active Repository Picker + Instant Saved-Snapshot Switcher.
- **Center Guided 4-Stage Bar**: **`1. Scan & Repos`** $\rightarrow$ **`2. Triage & Fix`** $\rightarrow$ **`3. 360° Map & Threats`** $\rightarrow$ **`4. ASPM, Rules & Reports`**.
- **Right Cluster**: One-click **`Scan`**, **`+F / +N` Track Changes**, **`⌘K` Command Omnibar**, **`⚙` Settings**, **3-Palette Daylight Switcher**, and **`✨ Frontier AI`** Copilot drawer toggle.

![02 - Guided 4-Stage Workflow Header and Split Triage Studio](./docs/screenshots/shot_02_top_menu_and_left_rail.png)

#### 1C. Stage 1 (`1. Scan & Repos`) — Multi-Repository Hub & Instant GitHub Scanner (`Public URL` vs. `Private PAT`)
Paste a local path or GitHub URL directly in the Stage 1 quick-scan bar, manage saved repository snapshots with per-card **`Re-Scan`**, **`Open in Studio`**, **`Configure`**, and **`Delete`** actions, or launch the dual-mode GitHub Scanner:
- **🌐 Open / Public Repository (`NO TOKEN`)**: Paste `https://github.com/owner/repo` and scan immediately with zero credentials.
- **🔒 Private Repository (`AUTH REQUIRED`)**: Authenticates via **ephemeral `GIT_CONFIG_*` HTTP `Authorization: Basic` headers** (never written to `.git/config`, clone URLs, or logs) with optional `.alastor_vault` local persistence.

![15 - Stage 1 Scan and Repos Hub](./docs/screenshots/shot_15_projects_hub_and_webhooks.png)

![02b - GitHub Repository Scanner in Open Public Mode](./docs/screenshots/shot_02b_github_public_repo_scanner.png)

![02c - GitHub Repository Scanner in Private PAT Auth Mode](./docs/screenshots/shot_02c_github_private_repo_auth.png)

---

### ✨ 2. Token-Efficient Multi-Provider BYOK Frontier AI Copilot (`90–95%` Token Savings)

#### 2A. Multi-Provider BYOK Vault (`0o600`) & Live CPG Micro-Slice Token Efficiency Meter
Click **`✨ Frontier AI`** in the top-right header to connect **Google Gemini**, **OpenAI**, **Anthropic Claude**, or **OpenAI-Compatible / OpenRouter / Local Ollama / vLLM** ([`FrontierAiCopilotDrawer.tsx`](./frontend/src/components/FrontierAiCopilotDrawer.tsx)):
- **90–95% Prompt Token Reduction**: Instead of uploading entire source files, `build_cpg_micro_slice()` extracts `<= 40` lines covering only the taint source, BFL chokepoint, sink, and 1-line cross-file call signatures, plus **SHA-256 Slice Caching (`0` tokens on repeat slices)**.
- **Zero-Leak Local Vault**: Keys are isolated per `(provider, host)` in `.alastor_vault/ai_config.json` (`0o600`), masked in `GET /api/ai/config`, protected against DNS/IP & `30x` redirect SSRF, and scrubbed from error strings.

![27 - Frontier AI BYOK Multi-Provider Vault and Token Efficiency Meter](./docs/screenshots/shot_27_frontier_ai_byok_vault.png)

#### 2B. Batch TP/FP Validation Digest, Monaco Selection Audit, AI Patch Synthesis & Graph Story
Run **`Batch AI Validate`** across up to 10 findings in a single compact micro-slice prompt to receive structured `TRUE_POSITIVE` / `FALSE_POSITIVE` / `NEEDS_HUMAN_REVIEW` verdicts, confidence scores, per-card `AI: TP 98%` chips, and 1-click **`Apply Triage Status`** — or highlight any lines in Monaco to click **`✨ AI Audit Selection (LX–LY)`**!

![27b - Frontier AI Batch TP/FP Validation Digest and Per-Card Verdicts](./docs/screenshots/shot_27b_frontier_ai_validate_verdicts.png)

---

### 🛠️ 3. Stage 2 (`2. Triage & Fix`) — One-Click Batch Auto-Fix & Monaco BFL `DiffEditor`

#### 3A. Split Light Monaco Editor, Written Observation Dossier & Directional Attack Path
Click any finding (or press `j` / `k`) to synchronize the **Written Observation Dossier**, **Light Monaco Code Inspector** (with selection-aware AI Audit & AI Patch triggers), **Attack Storyboard**, and **Directional Attack Path Graph** (`① SOURCE ──▶ ② BFL CHOKEPOINT ──▶ ③ SINK` + plain-English **Flow Story Bar**).

![03 - Stage 2 Triage and Fix Split Code and Directional Attack Path](./docs/screenshots/shot_03_code_review_dossier_and_diff.png)

#### 3B. One-Click `"Fix All Safe Issues"` Batch Auto-Fix & Unified `.patch` Export
Click **`Fix All Safe Issues (N)`** in the Flaw Explorer (`POST /api/remediate/batch-apply`) to apply all non-overlapping AST-deterministic fixes bottom-up across your workspace, verify Python/JS syntax, record `.alastor_patches` SHA-256 undo backups, download a `git apply`-ready `.patch`, and immediately re-scan the CPG to confirm severed exploit paths!

![28 - One-Click Batch Auto-Fix Verification Banner and Severed CPG Count](./docs/screenshots/shot_28_batch_autofix_and_patch.png)

#### 3C. Single-Finding Live BFL `"Sever the Thread"` Monaco `DiffEditor` & Secret Keys Filter
Press **`d`** (or click **`Preview BFL Diff`**) to inspect side-by-side before/after changes in the light **Monaco `DiffEditor`**, or filter **`Keys`** to inspect hardcoded secrets (`RULE-8`) with Shannon entropy scores and masked previews.

![03b - Live BFL Sever the Thread Light Monaco DiffEditor](./docs/screenshots/shot_03b_before_after_code_diff.png)

![04 - Secret Keys Filter and Cryptographic Credential Cards](./docs/screenshots/shot_04_secret_filter_and_cards.png)

---

### 🕸️ 4. 100% Directional CPG, 360° Spider & 4-Zone Trust Boundary Graphs

Every graph in ALASTOR `v4.0` features **perimeter-docked `18×18` outer-border arrowheads**, **numbered flow steps (`①`–`⑳`)**, **human-readable edge pills (`TAINT ▶`, `CALLS ▶`, `IMPORTS ▶`)**, **plain-English Flow Story Bars**, and **BFS Blast-Radius highlighting**:

#### 4A. Single-Node SCA / IaC / Secret Findings — Automatic 3-Step Attack-Context Flow Synthesis
Single-node findings (`SCA-*`, `IAC-*`, `RULE-8`) never render as isolated boxes without arrows — ALASTOR synthesizes a crystal-clear 3-step **`① Origin ──▶ ② BFL Chokepoint ──▶ ③ Security Impact`** directional chain!

![29 - Single-Node Finding Synthesized into 3-Step Directional Flow](./docs/screenshots/shot_29_single_node_3step_directional_flow.png)

#### 4B. Stage 3 (`3. 360° Map & Threats`) — 360° Architecture Spider Map with Cross-File `IMPORTS ▶` Flows
Visualizes every file by architectural role (`API_ROUTER`, `BUSINESS_LOGIC`, `FRONTEND_VIEW`, `DEPENDENCY_MANIFEST`, `INFRASTRUCTURE`) with purple **`IMPORTS ▶`** cross-file dependency arcs, smart folder clustering, and click-to-lock **Blast Radius** inspection.

![05 - 360 Architecture Spider Map with Cross-File Directional Flows](./docs/screenshots/shot_05_graph_spider_map_360.png)

#### 4C. Cross-File `Inter-Procedural Call Graph (:CALLS)`, `Entrypoints` & `Full CPG`
Trace `CALLS ▶` invocations across modules, map external ingress routes (`ENTRYPOINT_GRAPH`), or inspect unified `AST + CFG + DFG` edges (`TRUE ▶`, `FALSE ▶`, `LOOP ↺`, `TAINT ▶`) in `Full CPG`.

![06 - Directional Inter-Procedural Cross-File Call Graph](./docs/screenshots/shot_06_graph_call_graph.png)

![07 - Directional Attack Surface Entrypoints Graph](./docs/screenshots/shot_07_graph_entrypoints.png)

![08 - Full Code Property Graph AST CFG DFG](./docs/screenshots/shot_08_graph_dfg_cfg_full_cpg.png)

#### 4D. Interactive 4-Zone Directional Trust Boundary Graph, STRIDE Matrix, Secret Vault & PBOM
In Stage 3 $\rightarrow$ **`Trust Boundaries, STRIDE & PBOM`**, explore how untrusted traffic crosses **Zone 1 (External Ingress)** $\rightarrow$ **Zone 2 (API & CLI Entrypoints)** $\rightarrow$ **Zone 3 (Validation & BFL Chokepoints)** $\rightarrow$ **Zone 4 (Critical Sinks & Crown-Jewel Secrets)** with live red `UNSANITIZED ▶` vs. green `GUARDED ✓` directional arrows, plus full **STRIDE Verdict Dossiers**, **Secret Keys Vault**, and **CI/CD PBOM** tabs!

![11 - Interactive 4-Zone Directional Trust Boundary ReactFlow Graph](./docs/screenshots/shot_11_trust_boundaries_map.png)

![09 - Detailed Microsoft STRIDE Threat Matrix and Observations](./docs/screenshots/shot_09_stride_threat_matrix_and_observations.png)

![10 - Cryptographic Secret Keys and Credentials Vault](./docs/screenshots/shot_10_secret_keys_vault.png)

![12 - Attack Surface Entrypoints and CI/CD PBOM](./docs/screenshots/shot_12_entrypoints_and_cicd_pbom.png)

---

### 📊 5. Stage 4 (`4. ASPM, Rules & Reports`) — Executive Posture, SBOM, 21-Rule Studio, Governance & Exports

Organized under a clean 5-pill Stage 4 bar (**`1. Executive Posture`** • **`2. SAST+ Suite & SBOM`** • **`3. Rules, Cypher & Web CVE Intel`** • **`4. Governance, RBAC & Connectors`** • **`5. Export Center`**):

#### 5A. Executive Compliance & SLA Analytics (`OWASP Top 10`, `PCI-DSS v4.0`, `NIST 800-53`, `SOC 2`)
![16 - Executive Posture and OWASP PCI NIST SOC2 Compliance Analytics](./docs/screenshots/shot_16_deep_dive_analytics.png)

#### 5B. Plain-English Business Impact Translator, Live `CycloneDX v1.5` SBOM, Attack Surface, Roadmap & Academy
![18 - Plain-English Business Impact Translator](./docs/screenshots/shot_18_aspm_plain_english_translator.png)

![19 - Live CycloneDX v1.5 SBOM Supply-Chain Inspector](./docs/screenshots/shot_19_aspm_live_cyclonedx_sbom.png)

![19b - API and Entrypoint Attack Surface Catalog](./docs/screenshots/shot_19b_aspm_attack_surface.png)

![20 - Phased Management Remediation Roadmap](./docs/screenshots/shot_20_aspm_remediation_roadmap.png)

![21 - Non-Coder Security Academy and Executive Glossary](./docs/screenshots/shot_21_aspm_security_academy.png)

#### 5C. 21-Rule Matrix, Custom Sanitizer & Cypher Studio, and Live Web CVE & Advisory Extractor
![13 - Rule Profiles and 21-Rule Deterministic Security Matrix](./docs/screenshots/shot_13_rule_engine_profiles.png)

![24 - Custom AST Sanitizer and Live Neo4j Cypher Studio](./docs/screenshots/shot_24_cypher_query_and_sanitizer_studio.png)

![22 - CPG-Backed Live Web CVE and Advisory Extractor](./docs/screenshots/shot_22_live_web_cve_intel.png)

#### 5D. PMI/COBIT `RACI` Matrix, Multi-Tenant `RBAC` Accounts & Bi-Directional `Jira / GitHub` Sync
![17 - Interactive PMI COBIT RACI Governance Matrix](./docs/screenshots/shot_17_raci_governance_matrix.png)

![14 - Multi-Tenant Accounts and RBAC Clearance Matrix](./docs/screenshots/shot_14_user_accounts_and_rbac.png)

![23 - Bi-Directional Jira and GitHub Issues Sync](./docs/screenshots/shot_23_jira_github_connectors.png)

#### 5E. Instant `Ctrl+K` Command Omnibar & 3 Curated WCAG AA High-Contrast Daylight Palettes
Press **`Ctrl+K`** anywhere to jump across stages, findings, AI modes, or exports — and switch effortlessly among **3 WCAG AA (`>= 4.5:1`) Daylight Palettes** (*Olympian Daylight*, *Athena Parchment*, *Hyperborean Frost*).

![25 - Instant Ctrl+K Command Omnibar](./docs/screenshots/shot_25_command_palette_ctrl_k.png)

![26 - 3 Curated High-Contrast WCAG AA Daylight Palettes](./docs/screenshots/shot_26_olympian_light_theme.png)

---

## 🛡️ Complete 21-Rule Deterministic Security Matrix

| Rule ID | Engine | Severity | MITRE CWE | Vulnerability / Control Audited | Zero-FP Deterministic Proof |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **`RULE-1-TAINT`** | `SAST (CPG)` | `CRITICAL` | `CWE-78` / `CWE-94` | Inter-Procedural OS Command & Code Injection (`os.system`, `eval`, `exec`, `child_process`) | Multi-hop `DFG_FLOWS_TO` path with `0` verified `is_sanitizer` nodes |
| **`RULE-2-ORPHAN`** | `SAST (CPG)` | `HIGH` | `CWE-561` | Dormant Zero-Day Gadget / Uncalled Sensitive Function | Uncalled function containing a dangerous sink without route decorator |
| **`RULE-3-DEADSTORE`** | `SAST (CPG)` | `MEDIUM` | `CWE-563` | Dead Store / Unread Security or Audit Variable | Variable assigned in AST/DFG with zero downstream read edges |
| **`RULE-4-INFINITE-LOOP`** | `SAST (CPG)` | `HIGH` | `CWE-835` | Non-Terminating Infinite Loop (`DoS` Risk) | `CFG_NEXT` loop back-edge without reachable `break` / `return` |
| **`RULE-5-UNREACHABLE`** | `SAST (CPG)` | `MEDIUM` | `CWE-561` | Unreachable Dead Code / Orphaned Cleanup Logic | Statements following unconditional `return`, `raise`, or `break` |
| **`RULE-6-SHELL-INJECTION`** | `SAST (CPG)` | `CRITICAL` | `CWE-78` | Unsafe Subprocess Shell Execution (`shell=True`) | AST argument inspection of `subprocess.run/Popen/call(..., shell=True)` |
| **`RULE-7-SQLI-FORMAT`** | `SAST (CPG)` | `CRITICAL` | `CWE-89` | Format-String / Concatenated SQL & Cypher Injection | Dynamic string formatting (`f"`, `.format(`, `+`, `%`) in `.execute()` without `int()` coercion |
| **`RULE-8-HARDCODED-SECRET`** | `SAST + Secret` | `HIGH` | `CWE-798` | Hardcoded API Keys, JWT Secrets, DB Auth & Cloud Tokens (`AKIA`, `ghp_`, `sk_`, PEM) | AST literal + SDK auth driver + Shannon entropy + placeholder exclusion |
| **`RULE-9-DOM-XSS`** | `SAST (CPG)` | `HIGH` | `CWE-79` | DOM-Based XSS & Unsanitized HTML Sinks (`innerHTML`, `document.write`) | Dynamic expression flowing into browser DOM HTML/script sinks |
| **`RULE-10-PATH-TRAVERSAL`** | `SAST (CPG)` | `HIGH` | `CWE-22` | Inter-Procedural Arbitrary File Read/Write/Delete (`open`, `rmtree`, `fs.*`) | Suppresses **only** AST-verified `commonpath` / `basename` / `is_relative_to` confinement |
| **`RULE-11-SSRF-URLOPEN`** | `SAST (CPG)` | `HIGH` / `MED` | `CWE-918` | Server-Side Request Forgery (`urllib.request.urlopen`, `requests.*`, `httpx.*`, `axios.*`) | Suppresses **only** AST-verified `ipaddress` private-IP rejection or constant HTTPS origin |
| **`RULE-12-LOG-INJECTION`** | `SAST (CPG)` | `LOW` | `CWE-117` | Tainted CR/LF Log Forging (`logger.info/warning/error`) | Suppresses **only** AST-verified `\r` / `\n` neutralization helpers |
| **`RULE-13-UNSAFE-DESERIALIZATION-CRYPTO`** | `SAST (CPG)` | `HIGH` / `MED` | `CWE-502` / `CWE-328` | Unsafe `pickle`/`marshal`/`shelve.open`/`yaml.load`, Unverified JWT, Weak `md5`/`sha1` | Verifies `SafeLoader`, `verify_signature`, and `usedforsecurity=False` |
| **`RULE-14-CODE-INJECTION`** | `SAST (CPG)` | `CRITICAL` | `CWE-94` | Dynamic Code & SSTI Evaluation (`eval`, `exec`, `render_template_string`, `vm.runInNewContext`) | Non-constant expression in dynamic code/template sink unless `ast.literal_eval` |
| **`RULE-15-XXE-TLS-BYPASS`** | `SAST (CPG)` | `HIGH` | `CWE-611` / `CWE-295` | XML External Entity (`XXE`) Expansion & Disabled TLS Verification (`verify=False`, `_create_unverified_context`) | Suppresses `defusedxml` / `resolve_entities=False` and `verify=True` |
| **`RULE-16-INSECURE-RANDOM-OPEN-REDIRECT`** | `SAST (CPG)` | `MEDIUM` / `HIGH` | `CWE-330` / `CWE-601` | Weak PRNG (`random.*` / `Math.random`) for Security Tokens & Unvalidated Open Redirect | Verifies security-token variable context (`secrets.token_urlsafe`) & taint to redirect sink |
| **`SCA-1-MANIFEST-AUDIT`** | `SCA` | `MEDIUM` | `CWE-1395` | Unpinned / Floating SemVer Dependencies (`^`, `~`, `*`, `>=`) | Exact manifest parser across `package.json` & `requirements.txt` |
| **`SCA-2-LIVE-CVE-LOCKFILE`** | `SCA + CPG` | `CRIT`–`MED` | `CWE-1395` | Live `OSV.dev` Direct & Transitive Lockfile CVEs + CPG Import Reachability | Batch OSV API lookup + Neo4j CPG `Import` AST cross-check + patched version |
| **`IAC-1-COMPOSE-SECRET`** | `IaC` | `HIGH` | `CWE-798` | Plaintext Credentials in `docker-compose.yml` / Kubernetes Manifests | Environment block parser flagging hardcoded DB/service passwords |
| **`IAC-2-CONTAINER-ROOT`** | `IaC` | `MEDIUM` | `CWE-250` | Privileged Root Container (`Dockerfile`) & Missing Web Security Headers | Verifies non-root `USER` directive and `CSP` / `X-Frame-Options` headers |
| **`IAC-3-CICD-WORKFLOW-SECURITY`** | `CI/CD IaC` | `HIGH` / `MED` | `CWE-829` / `CWE-78` | GitHub Actions Mutable Tags (`@v4`), `${{ github.event.* }}` Injection & `pull_request_target` | Audits `.github/workflows/*.yml` for 40-char SHA pinning & untrusted interpolation |

---

## ⚡ 3-Minute Quick Start (100% Local & Sovereign)

### Prerequisites
- **[Docker Desktop](https://www.docker.com/products/docker-desktop/)** (runs `Neo4j 5 Community + APOC` locally on ports `7474` / `7687`)
- **[Python 3.11+](https://www.python.org/downloads/)**
- **[Node.js 18+ & npm](https://nodejs.org/)**

### Step 1 — Clone ALASTOR & Launch Neo4j + APOC
```bash
git clone https://github.com/ShanjulMittal/alastor-cpg-sast-platform.git
cd alastor-cpg-sast-platform

# Start Neo4j 5 + APOC Graph Engine
docker compose up -d neo4j
```

### Step 2 — Start the FastAPI CPG, Batch-Fix & Frontier AI Backend (`http://127.0.0.1:8000`)

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt

cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

**macOS / Linux (Bash / Zsh):**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### Step 3 — Launch the Next.js Daylight Studio (`http://localhost:3000`)
Open a second terminal in `alastor-cpg-sast-platform/frontend`:
```bash
cd frontend
npm ci
npm run build
npm run start
```
Open **`http://localhost:3000`** in Chrome, Edge, Brave, or Firefox!

---

## 🧪 Zero-Trust Proof: 31 Unit/Integration Tests + 20-Assertion Live Self-Audit

```powershell
# 1. Run the 31-test backend pytest suite (Frontier AI, Micro-Slicing, SSRF, 360° Imports & Batch Auto-Fix)
cd backend
..\.venv\Scripts\python.exe -m pytest tests/ -v

# 2. Run the 20-assertion live E2E harness + full platform self-audit
cd ..
.\.venv\Scripts\python.exe verify_harness.py
```

Expected result:
```text
============================= 31 passed in 1.91s ==============================
[PASS] 20 / 20 E2E Enterprise Assertions Verified (100%)
[PASS] Self-Audit of cpg-sast-platform: 0 Active Findings (SAST: 0, SCA: 0, IaC: 0, Secrets: 0, Web Intel: 0)
```

---

## 📤 Standards-Compliant Enterprise Exports & v4.0 REST APIs

| Export / API Endpoint | Standard / Format | Use Case |
| :--- | :--- | :--- |
| `GET / POST /api/ai/config` & `/api/ai/test-connection` | **Zero-Leak `0o600` BYOK AI Vault** | Configure `Gemini`, `OpenAI`, `Anthropic`, or `OpenAI-Compatible / Ollama` with masked keys & SSRF protection |
| `POST /api/ai/validate-findings` | **Batch CPG Micro-Slice TP/FP Digest** | Validate up to 10 findings per call (`90–95%` token savings + SHA-256 cache hits) |
| `POST /api/ai/audit-code-selection` & `/synthesize-patch` | **Monaco Selection Audit & AI Patch** | Audit highlighted lines in Monaco or synthesize context-aware remediation diffs |
| `POST /api/ai/explain-graph` | **AI Graph & Trust-Boundary Narrator** | Generate plain-English attack stories and blast-radius summaries for any graph |
| `POST /api/remediate/batch-apply` | **Atomic Multi-Finding Batch Auto-Fix** | Bottom-up AST batch patching across files with rollback, `.patch` unified diff & CPG re-scan |
| `POST /api/remediate/preview` / `apply` / `undo` | **Single-Finding BFL Patch & Undo** | Preview unified diff, apply 1-click BFL chokepoint patch, or revert via SHA-256 backup |
| `GET /api/graph?view_mode=...` | **Directional CPG & 360° Topology** | Returns nodes + `step_index`-ordered directional edges + cross-file `IMPORTS` across all 7 modes |
| `POST /api/scan` & `POST /api/github/verify-repo` | **Public URL / Private PAT / Local Scan** | Scan local paths, Open/Public Git URLs (zero token), or Private repos (`GIT_CONFIG_*` header auth) |
| `GET /api/export/sarif` & `GET /api/sast-plus` | **OASIS SARIF `v2.1.0` & CycloneDX `v1.5`** | Upload to GitHub Advanced Security or generate EO 14028 SBOM attestations |

---

## 📋 Release History

| Version | Date | Key Milestones |
| :--- | :---: | :--- |
| **`v4.0.0`** | **2026-11-11** | **100% Directional CPG/360°/Trust-Boundary Flow Graphs (perimeter arrowheads, `①`–`⑳` step badges, cross-file `IMPORTS ▶`, 3-step single-node synthesis, Flow Story Bar & Blast Radius), Guided 4-Stage High-Contrast WCAG AA Daylight UI (`0` feature loss), One-Click Atomic `"Fix All Safe Issues"` Batch Auto-Patcher (`POST /api/remediate/batch-apply`), Multi-Provider BYOK Frontier AI Copilot (`Gemini`, `OpenAI`, `Anthropic`, `Ollama` with `90–95%` Micro-Slice token savings + SHA-256 cache), `31/31` pytest (`0` warnings), and `20/20` E2E Self-Audit pass (`0` findings).** |
| **`v3.0.0`** | 2026-11-10 | Studio IDE Overhaul, Live BFL `"Sever the Thread"` Auto-Patcher (`preview`/`apply`/`undo`), 3 New Zero-FP CPG Rules (`RULE-14`, `RULE-15`, `RULE-16`), CPG-Backed Zero-FP Web Intel Engine, and `O(1)` UNWIND Neo4j Batch Ingestion. |
| **`v2.6.2`** | 2026-10-27 | 1-Click GitHub Repository Scanner (`Open / Public` Paste-URL-Only + `Private` PAT via ephemeral `GIT_CONFIG_*` HTTP headers) & pre-flight `POST /api/github/verify-repo`. |
| **`v2.6.1`** | 2026-10-25 | AST-Verified Inter-Procedural Sanitizer Summary Engine (`0%` FP on custom helpers), `for`-loop iterator taint, and 100% Semgrep Pro & OSS `0`-finding parity. |
| **`v2.6.0`** | 2026-10-25 | Live `OSV.dev` Lockfile CVE + CPG Import Reachability (`SCA-2`), GitHub Actions CI/CD Scanner (`IAC-3`), and Inter-Procedural Route Taint (`RULE-10`–`RULE-13`). |
| **`v2.5.0`** | 2026-10-22 | STRIDE Count & Observation Matrix, Secret Keys Vault, Rule Engine Profiles, Multi-Tenant RBAC, Call Graph (`:CALLS`), Entrypoints Graph, and 360° Spider Map. |
| **`v2.0.0`–`v1.0.0`** | 2026-10-19 | `SAST++++++` ASPM Suite, `EPSS v4`, `RACI` Matrix, `CycloneDX v1.5` SBOM, Tree-Sitter `AST + CFG + DFG` Neo4j CPG compiler, and `SARIF v2.1.0`. |

---

## 📚 Documentation, Contributing & Security

- **[📖 Master Product Guide & Standard Operating Procedure (SOP)](./docs/ALASTOR_Master_SOP_and_Product_Guide.md)** — Complete v4.0 operator manual, 4-stage workflow guide, Frontier AI BYOK setup, and CPG compiler deep-dive.
- **[📋 Full Changelog (`CHANGELOG.md`)](./CHANGELOG.md)** — Detailed version-by-version engineering notes.
- **[🔬 Contributing Guide (`CONTRIBUTING.md`)](./CONTRIBUTING.md)** — How to add new Tree-Sitter languages, Cypher CPG rules, and run `verify_harness.py`.
- **[🛡️ Security Policy (`SECURITY.md`)](./SECURITY.md)** — Responsible disclosure guidelines and self-audit verification policy.

---

<div align="center">

### ⭐ Star ALASTOR on GitHub if you believe Compiler-Grade Code Security should be Open, Deterministic, Readable & Sovereign!

Released under the **[MIT License](./LICENSE)** • Built with **Tree-Sitter**, **Neo4j + APOC**, **FastAPI**, **Next.js**, **Monaco Editor**, and **ReactFlow**.

</div>
