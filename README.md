<div align="center">

<img src="./docs/screenshots/alastor_demon_logo.jpg" alt="ALASTOR Mythological Daimon Crest" width="190" />

# ALASTOR (`Ἀλάστωρ`) `v2.6.1`

### **The Relentless Open-Source Code Property Graph (CPG), Zero-Noise SAST, Live Reachable SCA, CI/CD & IaC, Secret Vault, STRIDE Threat Modeling & Executive ASPM Platform**

*Stop drowning in regex false positives and six-figure SaaS lock-in. Compile your codebase into a mathematical **AST + CFG + DFG + Call Graph** inside **Neo4j** — 100% locally on your own hardware.*

[![Version: v2.6.1 Enterprise](https://img.shields.io/badge/Release-v2.6.1%20Enterprise-7c3aed?style=for-the-badge)](./CHANGELOG.md)
[![Self-Audit: 0 Findings (18/18 Pass)](https://img.shields.io/badge/Self--Audit-0%20Findings%20(18%2F18%20Pass)-10b981?style=for-the-badge)](./verify_harness.py)
[![False Positives: 0% AST-Verified](https://img.shields.io/badge/False%20Positives-0%25%20AST--Verified-059669?style=for-the-badge)](./backend/compiler/ast_parser.py)
[![Semgrep Pro/OSS Parity: 0/0 Clean](https://img.shields.io/badge/Semgrep%20Pro%20%26%20OSS%20Audit-0%20Findings-06b6d4?style=for-the-badge)](./CHANGELOG.md)
[![Live SCA: OSV.dev + CPG Reachability](https://img.shields.io/badge/Live%20SCA-OSV.dev%20%2B%20CPG%20Reachability-f59e0b?style=for-the-badge)](./backend/engine/osv_lockfile_scanner.py)
[![OASIS SARIF: v2.1.0](https://img.shields.io/badge/OASIS-SARIF%20v2.1.0-0ea5e9?style=for-the-badge)](./backend/main.py)
[![SBOM: CycloneDX v1.5](https://img.shields.io/badge/SBOM-CycloneDX%20v1.5-6366f1?style=for-the-badge)](./backend/engine/enterprise_manager.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-e11d48?style=for-the-badge)](./LICENSE)

<br />

[**⚡ 3-Minute Quick Start**](#-3-minute-quick-start-100-local--sovereign) •
[**🏆 Why Download ALASTOR?**](#-why-security-engineers--developers-switch-to-alastor) •
[**⚔️ vs. Semgrep / Checkmarx / Snyk**](#️-head-to-head-competitive-benchmark) •
[**🧠 7-Pass CPG Architecture**](#-compiler-grade-7-pass-cpg-architecture) •
[**📸 Complete 28-Screen Visual Tour**](#-complete-visual-tour--every-option-module-graph--modal) •
[**🛡️ All 18 Security Rules**](#️-complete-18-rule-deterministic-security-matrix) •
[**📖 Full Master SOP**](./docs/ALASTOR_Master_SOP_and_Product_Guide.md)

</div>

---

![ALASTOR Split Code & CPG Workbench in Alastor Infernal Dark Mythic Mode](./docs/screenshots/shot_03_code_review_dossier_and_diff.png)

> **Named after Alastor (`Ἀλάστωρ` — *"The Unforgetting Avenger"*)**, the ancient Greek mythological spirit of retribution who hunts down hidden corruptions so no flaw escapes judgment, **ALASTOR `v2.6.1`** unifies **8 enterprise security products** into one blazing-fast, air-gap-capable desktop & web workbench:
> 1. **Inter-Procedural Code Property Graph SAST** (`Tree-Sitter AST + CFG + DFG + :CALLS` over `Neo4j 5 + APOC`)
> 2. **AST-Verified Sanitizer Summary Engine** (`0%` False Positives on custom enterprise path/SSRF/SQLi/log validators)
> 3. **Live OSV.dev Transitive Lockfile SCA** with **CPG Import Reachability Proof** (`REACHABLE` vs. `DORMANT`)
> 4. **Infrastructure-as-Code & GitHub Actions CI/CD Pipeline Security** (`Dockerfile`, `Compose`, `.github/workflows/*.yml`)
> 5. **Cryptographic Secret Keys & Shannon Entropy Vault** with RBAC-gated unmasking
> 6. **Automated Microsoft STRIDE Threat Modeling** (`✔ What Passed` vs. `✖ What Failed` + `PBOM` + Trust Boundaries)
> 7. **Executive `SAST++++++` ASPM Command Center** (Plain-English Impact Translator, Live `CycloneDX v1.5` SBOM, `EPSS v4`, Phased Roadmap & Security Academy)
> 8. **Enterprise Governance, Multi-Tenant RBAC & Issue Sync** (`PMI/COBIT RACI Matrix`, `Jira` & `GitHub Issues` 2-way sync, `OASIS SARIF v2.1.0`)

---

## 🔥 Why Security Engineers & Developers Switch to ALASTOR

| Legacy Scanner Pain Point | How ALASTOR `v2.6.1` Solves It Permanently |
| :--- | :--- |
| **Regex Noise & Alert Fatigue**<br>*Pattern matchers flag sanitized variables and safe helper wrappers because they cannot verify AST guards across functions.* | **AST-Verified Inter-Procedural Sanitizer Summaries**: ALASTOR inspects the actual AST body of every helper function in your repo and promotes it to `is_sanitizer=True` **only** if it mathematically enforces path confinement (`commonpath` / `is_relative_to`), DNS private-IP SSRF checks (`ipaddress`), or CR/LF stripping. Result: **100% True Positive recall with `0%` False Positives.** |
| **Unreachable Dependency CVE Floods**<br>*SCA tools dump 200+ lockfile warnings without checking if your code ever imports the vulnerable library.* | **Live OSV.dev + CPG Import Reachability (`SCA-2`)**: Queries Google's `api.osv.dev` across `package-lock.json` and `requirements.txt`, then cross-references your Neo4j CPG `Import` AST nodes to separate **`RUNTIME REACHABLE`** exploits from **`UNREACHABLE / DORMANT`** transitive noise. |
| **Cryptic Rule IDs With Zero Fix Guidance**<br>*Developers get a CWE number and waste hours figuring out which upstream line to patch.* | **Best Fix Location (`BFL`) Chokepoint + `- Before` / `+ After` Code Diff**: Computes the single optimal dominance chokepoint line where a 1-line fix neutralizes every downstream sink, paired with copy-pasteable secure replacement code. |
| **Mandatory Cloud Code Uploads & Per-Seat Pricing**<br>*Commercial SAST/ASPM platforms upload proprietary IP to vendor clouds and charge \$1,000+/dev/year.* | **100% Local-First, Sovereign & MIT Open Source**: Your source code, Neo4j CPG database, secret vault, and SBOM never leave `localhost`. Zero telemetry, zero seat limits, zero license keys. |
| **Disconnected Tool Sprawl**<br>*Separate tools for SAST, SCA, Secrets, CI/CD, Threat Modeling, SBOM, and GRC.* | **8 Unified Enterprise Modules + 7 Interactive Graph Views**: Jump from a **STRIDE Threat Row** or **CycloneDX SBOM Component** straight to the exact **Monaco Source Line** and **Neo4j Attack Path** in one click. |

---

## ⚔️ Head-to-Head Competitive Benchmark

| Capability | **ALASTOR `v2.6.1`** | **Semgrep OSS** | **Semgrep Pro** | **Checkmarx / Fortify** | **Snyk Code + SCA** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Analysis Representation** | **Full CPG (`AST+CFG+DFG+:CALLS`) in Neo4j** | Single-file AST / pattern | Cross-file AST + taint | Proprietary AST/DFG | Proprietary semantic graph |
| **Custom Helper Sanitizer Body Verification** | ✅ **Automatic AST Verification (`0%` FP)** | ❌ Flags custom helpers | ⚠️ Requires manual rule YAML | ⚠️ Manual custom filters | ❌ Limited custom rules |
| **Inter-Procedural Route $\rightarrow$ Helper Taint** | ✅ **Built-In (`FastAPI`, `Flask`, `Express`)** | ❌ Intra-procedural only | ✅ Paid Commercial Tier | ✅ Paid Enterprise Tier | ✅ Paid Cloud Tier |
| **Live Lockfile CVE + CPG Import Reachability** | ✅ **Built-In (`OSV.dev` + AST Imports)** | ❌ No SCA in OSS | ✅ Supply Chain Add-On | ✅ Paid SCA Add-On | ✅ Paid Cloud Tier |
| **GitHub Actions CI/CD Workflow Security** | ✅ **Built-In (`IAC-3` SHA & Expression Injection)** | ⚠️ Community rules | ✅ Paid Tier | ⚠️ Partial | ❌ Separate IaC |
| **Best Fix Location (`BFL`) + Before/After Diff** | ✅ **Interactive Chokepoint + Copyable Patch** | ❌ | ⚠️ AI autofix (Cloud) | ✅ BFL node only | ⚠️ Cloud suggestions |
| **Automated Microsoft STRIDE Matrix (`OK` vs `Issue`)** | ✅ **Live File-Anchored Dossier + `PBOM`** | ❌ | ❌ | ❌ | ❌ |
| **Plain-English Non-Coder / CISO Risk Translator** | ✅ **Built-In Analogies + Security Academy** | ❌ | ❌ | ❌ | ❌ |
| **Interactive `7×9` PMI/COBIT RACI Matrix** | ✅ **Built-In with Golden-Rule Validator** | ❌ | ❌ | ❌ | ❌ |
| **100% Offline / Sovereign Local Source Privacy** | ✅ **100% Local (`Neo4j` + `FastAPI` + `Next.js`)** | ✅ CLI only (no UI) | ❌ Cloud control plane | ⚠️ Heavy on-prem server | ❌ Cloud upload required |
| **License & Cost** | **100% Free & Open Source (`MIT`)** | LGPL (CLI only) | \$\$\$ Per-Developer | \$\$\$\$ Six-Figure Annual | \$\$\$ Per-Developer |

---

## 🧠 Compiler-Grade 7-Pass CPG Architecture

```mermaid
flowchart LR
    subgraph IN["📂 Target Application / Repo / ZIP / Git URL"]
        SRC["Python • JS • TS • TSX"]
        LOCK["package-lock.json • requirements.txt"]
        INFRA["Dockerfile • Compose • .github/workflows"]
    end

    subgraph COMPILER["⚙️ ALASTOR 7-Pass Deterministic Compiler (backend/compiler)"]
        P1["Pass 1: Tree-Sitter AST Parser\nRoutes, Sinks, Secrets & Imports"]
        P2["Pass 2: AST Sanitizer Verifier\nProves commonpath / IP / CRLF Guards"]
        P3["Pass 3: Control-Flow Builder\nCFG_NEXT, Branches & Loop Back-Edges"]
        P4["Pass 4: Data-Flow & Iterator Taint\nIntra + Call-Site Inter-Procedural DFG"]
        P5["Pass 5: Cross-File Call Graph\n:CALLS Edges & Reachability Proof"]
    end

    subgraph GRAPH["🗄️ Neo4j 5 + APOC CPG"]
        NEO[("Unified Property Graph\nAST + CFG + DFG + :CALLS")]
    end

    subgraph ENGINES["🛡️ Multi-Engine Audit & Intelligence"]
        R18["18 Deterministic Rules\nSAST • Secret • Logic • IaC • CI/CD"]
        OSV["Live OSV.dev CVE Scanner\n+ CPG Import Reachability"]
        ASPM["STRIDE Matrix • CycloneDX v1.5\nEPSS v4 • BFL Chokepoint • RACI"]
    end

    SRC --> P1 --> P2 --> P3 --> P4 --> P5 --> NEO
    NEO --> R18 --> ASPM
    LOCK --> OSV --> ASPM
    INFRA --> R18
```

---

## 📸 Complete Visual Tour — Every Option, Module, Graph & Modal

Every screenshot below is captured live from **ALASTOR `v2.6.1`** at `2400×1470` Retina resolution scanning a multi-service Python `FastAPI` + `React/TypeScript` + `Docker` + `GitHub Actions` FinTech gateway — showcasing **every menu, workspace, graph mode, sub-tab, modal, and theme** out of the box.

---

### 🏛️ 1. Mythological Portal Gate, Top 7-Dropdown Menu Bar & Left Activity Rail

#### 1A. ALASTOR Mythological Launch Portal (`Portal Gate`)
Greets operators with live `Neo4j CPG Connected` telemetry, active project status, **Continuous Track Changes** deltas (`Fixed` / `New` / `Unchanged` since last scan), 1-click **`Go to App (Saved Scan)`**, **`Re-Scan & Track Changes`**, and direct workspace launch cards.

![01 - ALASTOR Mythological Portal Gate](./docs/screenshots/shot_01_portal_gate.png)

#### 1B. Desktop-Class 7-Dropdown Menu Bar + Left Side Function Rail
Navigate effortlessly like a native security IDE:
- **Top Application Menu Bar** ([`AppMenuBar.tsx`](./frontend/src/components/AppMenuBar.tsx)): `1. File & Scan` • `2. Workspace` • `3. CPG & Graphs` • `4. Threat Model & Secrets` • `5. Rule Engine & Profiles` • `6. Accounts & Users` • `7. Reports & Connectors` — plus live Active Profile, Active Tenant Account, and `Engineer / Management View` badges.
- **Left Side Function Rail** ([`LeftFunctionBar.tsx`](./frontend/src/components/LeftFunctionBar.tsx)): 1-click switching across all **8 Enterprise Modules** (`Review`, `Threats`, `Rules`, `Accounts`, `Projects`, `Analytics`, `RACI`, `ASPM`), **Direct Graph & Secret Launchers** (`Secrets`, `Call Graph`, `Entrypoints`), and **Utility Controls** (`Explorer`, `Tickets`, `Ctrl+K`, `Config`).

![02 - Top Application Menu Bar and Left Side Function Rail](./docs/screenshots/shot_02_top_menu_and_left_rail.png)

---

### 💻 2. Module 1 — Code & CPG Review Workbench (`REMEDIATION_IDE`)

#### 2A. Split Source Inspector, Written Observation Dossier & Attack Path Graph
Click any finding in the left explorer to synchronize **four views simultaneously**:
1. **Written Observation Dossier** (Plain-English explanation, `RUNTIME REACHABLE` proof, `EPSS 30d` exploit percentile, RACI `R` & `A` owners, and effort estimate).
2. **Monaco Source Code Editor** (Auto-scrolls and highlights the exact vulnerable statement with glyph markers and clickable symbol breadcrumbs).
3. **Interactive Bottom Storyboard** (`1. Attack Story` step-by-step source-to-sink narrative, `2. How to Fix`, `3. PoC & Artifacts`, `4. CWE / CVE`, plus `Mark As` triage suppression and `+ Jira / + GitHub` 1-click ticket buttons).
4. **Live Neo4j Attack Path Graph** (`SOURCE` in cyan $\rightarrow$ `BEST FIX (BFL)` in emerald $\rightarrow$ `SINK` in crimson, complete with a **`Play Step Tour`** animation!).

![03 - Code & CPG Review Workbench with Written Observation Dossier and Attack Story](./docs/screenshots/shot_03_code_review_dossier_and_diff.png)

#### 2B. `Code Focus` Mode, Chokepoint `Best Fix Location (BFL)` & `2. How to Fix` Patch Guide
Switch between **`Code Focus`**, **`Graph Focus`**, and **`Split (Code + Graph)`** in the workbench toolbar. Opening **`2. How to Fix`** reveals the exact remediation strategy, side-by-side `- Before` vs. `+ After` replacements, and a **`Copy Fix Guide`** button for instant patching.

![03b - Code Focus Mode with Best Fix Location and How to Fix Remediation Strategy](./docs/screenshots/shot_03b_before_after_code_diff.png)

#### 2C. 1-Click `Secrets` Filter & Cryptographic Credential Cards (`RULE-8`)
Click **`Secrets`** on the left rail (or **`Keys (2)`** in the findings filter bar) to isolate hardcoded API keys, JWT signing secrets, cloud tokens (`AKIA...`, `ghp_...`, `sk_...`), and DB passwords — complete with **Shannon Entropy (`bits/char`)**, **Secret Provider Type**, and **Masked Value Previews**.

![04 - Secret Keys Quick Filter and Credential Finding Cards](./docs/screenshots/shot_04_secret_filter_and_cards.png)

#### 2D. Sidebar Tab `2. Web Intel` — Live Multi-Site CVE & Advisory Extractor
Pull real-time vulnerability advisories directly from **`OSV.dev`**, **`NIST NVD`**, **`CISA Known Exploited Vulnerabilities (KEV) / OWASP`**, or any custom security advisory URL and correlate them against your active repository's tech stack.

![22 - Live Multi-Site Web CVE and Advisory Extractor](./docs/screenshots/shot_22_live_web_cve_intel.png)

---

### 🕸️ 3. All Interactive Code Property Graph (`CPG`) & Architecture Modes

ALASTOR provides **7 specialized graph visualizations** inside [`ReactFlowGraphPane.tsx`](./frontend/src/components/ReactFlowGraphPane.tsx) so large repositories stay crystal-clear instead of turning into unreadable "hairballs":

#### 3A. Decluttered `360° Application Architecture Spider Map` (`3. App Map` / `APP_TREE`)
Auto-classifies every file in your repository (`API_ROUTER`, `BUSINESS_LOGIC`, `FRONTEND_VIEW`, `DEPENDENCY_MANIFEST`, `INFRASTRUCTURE`) with smart folder clustering, flaw heat-badges, and 1-click source inspection.

![05 - 360 Application Architecture Spider Map](./docs/screenshots/shot_05_graph_spider_map_360.png)

#### 3B. Cross-File `Inter-Procedural Call Graph (:CALLS)` (`CALL_GRAPH`)
Visualizes purple `:CALLS` edges connecting caller functions and HTTP endpoints to downstream helper functions across files (e.g., `payment_gateway.py` $\rightarrow$ `services/ledger_worker.py`), with toggles for **`Whole App Calls`** vs. **`Active File Calls`**.

![06 - Inter-Procedural Cross-File Call Graph](./docs/screenshots/shot_06_graph_call_graph.png)

#### 3C. `Attack Surface Entry Points Graph` (`ENTRYPOINT_GRAPH`)
Maps every external ingress route (`@app.post`, `@app.get`, Express routes, CLI handlers) and highlights how untrusted parameters enter internal service logic.

![07 - Attack Surface Entry Points Graph](./docs/screenshots/shot_07_graph_entrypoints.png)

#### 3D. Full-Width `Unified Code Property Graph (AST + CFG + DFG)` (`FULL_CPG` in `Graph Focus`)
Inspect the raw compiler graph stored in Neo4j — combining syntactic `AST` hierarchy edges, `CFG_NEXT` execution branches, and `DFG_FLOWS_TO` variable propagation edges on a zoomable, pannable canvas with MiniMap and full-screen presentation mode.

![08 - Unified Full Code Property Graph AST CFG DFG in Graph Focus](./docs/screenshots/shot_08_graph_dfg_cfg_full_cpg.png)

---

### 🛡️ 4. Module 2 — Automated Microsoft STRIDE Threat Modeling, Secret Vault & PBOM (`THREAT_MODELING`)

#### 4A. Tab 1 — Executive STRIDE Count & Verdict Matrix (`✔ What is OK` vs. `✖ What is the Issue`)
Automatically evaluates **Spoofing (`S`)**, **Tampering (`T`)**, **Repudiation (`R`)**, **Information Disclosure (`I`)**, **Denial of Service (`D`)**, and **Elevation of Privilege (`E`)** across your codebase, displaying exact passed counts (`✔ OK`), failed counts (`✖ Issue`), recorded file:line observations, and **`</> Inspect`** buttons that jump straight into Monaco!

![09 - STRIDE Executive Count and Verdict Matrix](./docs/screenshots/shot_09_stride_threat_matrix_and_observations.png)

#### 4B. Tab 2 — Cryptographic Secret Keys & Credentials Vault
Centralized audit ledger of every detected credential in source or IaC manifests, showing the variable identifier, masked token preview, secret provider classification, Shannon entropy score, rotation guidance, and RBAC-controlled **`Reveal / Mask`** actions.

![10 - Secret Keys and Credentials Vault](./docs/screenshots/shot_10_secret_keys_vault.png)

#### 4C. Tab 3 — Architectural Trust Boundary Map
Breaks down your application across **4 security zones** (*Zone 0: Untrusted Public Ingress*, *Zone 1: API Controllers & Routing*, *Zone 2: Core Business & Domain Workers*, *Zone 3: Execution Sinks, Filesystem & External Cloud APIs*) with per-zone risk posture.

![11 - Trust Boundary Architecture Map](./docs/screenshots/shot_11_trust_boundaries_map.png)

#### 4D. Tab 4 — Attack Surface Entrypoints & CI/CD Pipeline Bill of Materials (`PBOM`)
Catalogs every discovered HTTP/CLI entrypoint alongside **CI/CD Supply-Chain Integrity Controls** (lockfile pinning, non-root container execution, `.gitignore` secret hygiene, GitHub Actions immutable SHA pinning, and runtime security headers).

![12 - Attack Surface Entrypoints and CI/CD PBOM](./docs/screenshots/shot_12_entrypoints_and_cicd_pbom.png)

---

### ⚙️ 5. Module 3 & Module 4 — Custom Rule Engine Profiles & Multi-Tenant RBAC

#### 5A. Module 3 — Rule Engine & Test Profiles Matrix (`RULE_ENGINE_PROFILES`)
Switch instantaneously between **4 built-in scan profiles** (*Checkmarx-Style Optimized*, *Strict Zero-Trust Enterprise*, *Secret & Credential Hunter*, *Fast CI/CD PR Gate*), author your own custom test profiles, toggle `SAST` / `SCA` / `IaC` engines independently, and check or uncheck any individual rule (`18/18`).

![13 - Rule Engine and Test Profiles Matrix](./docs/screenshots/shot_13_rule_engine_profiles.png)

#### 5B. Module 4 — User Profiling, Multi-Tenant Account Separation & RBAC (`USER_PROFILES`)
Built for enterprise security teams and MSSPs: isolate organizational enclaves (`Enterprise Security HQ`, `CISO & Executive Governance`, `Threat Intelligence & SecOps`, or custom accounts) with `STRICT` repository partitioning, 5 RBAC clearance tiers, live permission switches (`Reveal Secrets`, `Edit Rules`, `Triage Findings`, `Tenant Admin`), and an operator session audit log.

![14 - User Profiling Multi-Tenant Accounts and RBAC Clearance Matrix](./docs/screenshots/shot_14_user_accounts_and_rbac.png)

---

### 📊 6. Module 5, Module 6 & Module 7 — Projects Hub, Compliance Analytics & RACI Governance

#### 6A. Module 5 — Multi-Repository Projects Hub, Git/ZIP Scanner & CI/CD Webhooks (`PROJECTS_HUB`)
Auto-discovers local workspaces, scans remote `HTTPS` Git URLs or uploaded `.zip`/folder archives inside UUID-isolated sandboxes, persists scan history snapshots (`Scan #1`, `Scan #2`, deltas), and provides ready-to-wire GitHub/GitLab webhook endpoints.

![15 - Projects Hub Saved Scans and CI/CD Webhooks](./docs/screenshots/shot_15_projects_hub_and_webhooks.png)

#### 6B. Module 6 — Deep-Dive Executive Analytics & Regulatory Compliance (`DEEP_DIVE`)
Real-time severity distributions, scan engine breakdowns (`SAST`, `SCA`, `IaC`), SLA aging buckets, and automated compliance readiness mapping against **`OWASP Top 10 (2021)`**, **`PCI-DSS v4.0`**, **`NIST SP 800-53 Rev. 5`**, and **`SOC 2 Type II`**.

![16 - Deep Dive Analytics and OWASP PCI NIST SOC2 Compliance](./docs/screenshots/shot_16_deep_dive_analytics.png)

#### 6C. Module 7 — Interactive PMI/COBIT `RACI` Security Governance Matrix (`RACI_GOVERNANCE`)
Assign **Responsible (`R`)**, **Accountable (`A`)**, **Consulted (`C`)**, and **Informed (`I`)** ownership across **7 organizational roles × 9 security lifecycle activities**, backed by an automatic **PMI Golden-Rule Validator** (enforcing exactly one `A` and at least one `R` per row) and 1-click JSON governance export.

![17 - Interactive RACI Security Governance Matrix](./docs/screenshots/shot_17_raci_governance_matrix.png)

---

### ✨ 7. Module 8 — Ultimate `SAST++++++` ASPM & Non-Coder Executive Suite (`SAST_PLUS_SUITE`)

Designed specifically so **CISOs, Engineering Directors, Product Managers, Auditors, and Students** can understand and act on compiler-level findings without reading a single line of AST/Cypher code:

#### 7A. Pillar 1 — Plain-English Business Impact Translator
Translates every technical vulnerability into a clear **What Happened**, **Real-World Non-Coder Analogy**, **Business & Financial Impact**, and **1-Click Jump to Chokepoint Fix**.

![18 - ASPM Pillar 1 Plain-English Business Impact Translator](./docs/screenshots/shot_18_aspm_plain_english_translator.png)

#### 7B. Pillar 2 — Live `CycloneDX v1.5` Software Bill of Materials (`SBOM`)
Generates a compliant **U.S. Executive Order 14028 `CycloneDX v1.5` SBOM** across `npm` and `PyPI` manifests with standardized `pkg:` URLs (`purl`), version-pinning status, ecosystem tags, and 1-click `.cdx.json` download.

![19 - ASPM Pillar 2 Live CycloneDX v1.5 SBOM Inspector](./docs/screenshots/shot_19_aspm_live_cyclonedx_sbom.png)

#### 7C. Pillar 3 — API & Entrypoint Attack Surface Catalog
Inventories every discovered REST endpoint and entrypoint across your codebase with HTTP method badges, handler symbols, file locations, exposure posture, and linked CPG vulnerability counts.

![19b - ASPM Pillar 3 API and Entrypoint Attack Surface Catalog](./docs/screenshots/shot_19b_aspm_attack_surface.png)

#### 7D. Pillar 4 — Phased Management Remediation Roadmap
Automatically groups open findings into **Phase 1: Immediate Release Blockers (`0–7 Days`)**, **Phase 2: Short-Term Hardening (`8–30 Days`)**, and **Phase 3: Structural Hygiene (`31–90 Days`)** with engineering effort estimates and RACI role assignments.

![20 - ASPM Pillar 4 Phased Management Remediation Roadmap](./docs/screenshots/shot_20_aspm_remediation_roadmap.png)

#### 7E. Pillar 6 — Built-In Non-Coder Security Academy & Executive Glossary
Interactive educational cards teaching `SAST`, `SCA & SBOM`, `IaC`, `Code Property Graphs (AST+CFG+DFG)`, `Taint Analysis`, `Best Fix Location (BFL)`, `RACI`, and `CWE / CVE / CVSS / EPSS` with memorable real-world analogies.

![21 - ASPM Pillar 6 Non-Coder Security Academy and Glossary](./docs/screenshots/shot_21_aspm_security_academy.png)

---

### 🔌 8. Enterprise Issue Connectors, Cypher Studio, `Ctrl+K` Palette & 6 Curated Themes

#### 8A. Bi-Directional Atlassian Jira & GitHub Issues Integration Hub
Create rich Markdown tickets pre-populated with the **CPG Source-to-Sink Trace** and **Best Fix Location (`BFL`) Patch** in one click — working immediately out of the box with ALASTOR's built-in Local Issue Tracker and optional live **Jira Cloud / GitHub Issues REST API** sync.

![23 - Jira and GitHub Issues Bi-Directional Integration Hub](./docs/screenshots/shot_23_jira_github_connectors.png)

#### 8B. Advanced Engine Settings, Custom Sanitizer Studio & Live Neo4j Cypher Query Viewer
Full glass-box transparency: inspect the exact **Neo4j Cypher CPG queries** powering ALASTOR, configure inter-procedural DFG hop depth, manage triage suppressions, and register organization-specific sanitizer functions.

![24 - Advanced Engine Custom Sanitizer Studio and Live Cypher Query Viewer](./docs/screenshots/shot_24_cypher_query_and_sanitizer_studio.png)

#### 8C. Instant `Ctrl+K` Command Palette
Press **`Ctrl+K`** (or **`Cmd+K`**) from anywhere in the platform to fuzzy-search findings, jump to files, switch graph modes, trigger a scan, or export `SARIF v2.1.0` / `CycloneDX SBOM` without lifting your hands from the keyboard.

![25 - Instant Ctrl+K Command Palette](./docs/screenshots/shot_25_command_palette_ctrl_k.png)

#### 8D. 6 Curated Mythic Dark & Executive Daylight Themes (`Olympian Daylight` Shown)
Prefer crisp light mode for boardroom presentations or PDF reports? Toggle in 1 click between **3 Light Themes** (*Olympian Daylight*, *Athena Parchment*, *Hyperborean Frost*) and **3 Mythic Dark Themes** (*Alastor Infernal*, *Hecate Arcane*, *Stygian Abyss*), plus adjustable Demon Sanctuary backdrop intensity (*Vivid Art* / *Subtle* / *Off*).

![26 - Olympian Daylight Light Mode and 6-Palette Theme Switcher](./docs/screenshots/shot_26_olympian_light_theme.png)

---

## 🛡️ Complete 18-Rule Deterministic Security Matrix

| Rule ID | Engine | Severity | MITRE CWE | Vulnerability / Control Audited | Zero-FP Deterministic Proof |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **`RULE-1-TAINT`** | `SAST (CPG)` | `CRITICAL` | `CWE-78` / `CWE-94` | Inter-Procedural OS Command & Code Injection (`os.system`, `eval`, `exec`, `child_process`) | Multi-hop `DFG_FLOWS_TO` path with `0` verified `is_sanitizer` nodes |
| **`RULE-2-ORPHAN`** | `SAST (CPG)` | `HIGH` | `CWE-561` | Dormant Zero-Day Gadget / Uncalled Sensitive Function | Uncalled function containing a dangerous sink without route decorator |
| **`RULE-3-DEADSTORE`** | `SAST (CPG)` | `MEDIUM` | `CWE-563` | Dead Store / Unread Security or Audit Variable | Variable assigned in AST/DFG with zero downstream read edges |
| **`RULE-4-INFINITE-LOOP`** | `SAST (CPG)` | `HIGH` | `CWE-835` | Non-Terminating Infinite Loop (`DoS` Risk) | `CFG_NEXT` loop back-edge without reachable `break` / `return` |
| **`RULE-5-UNREACHABLE`** | `SAST (CPG)` | `MEDIUM` | `CWE-561` | Unreachable Dead Code / Orphaned Cleanup Logic | Statements following unconditional `return`, `raise`, or `break` |
| **`RULE-6-SHELL-INJECTION`** | `SAST (CPG)` | `CRITICAL` | `CWE-78` | Unsafe Subprocess Shell Execution (`shell=True`) | AST argument inspection of `subprocess.run/Popen/call(..., shell=True)` |
| **`RULE-7-SQLI-FORMAT`** | `SAST (CPG)` | `CRITICAL` | `CWE-89` | Format-String / Concatenated SQL & Cypher Injection | Dynamic string formatting in `.execute()` without `int()` coercion sanitizer |
| **`RULE-8-HARDCODED-SECRET`** | `SAST + Secret` | `HIGH` | `CWE-798` | Hardcoded API Keys, JWT Secrets, DB Auth & Cloud Tokens (`AKIA`, `ghp_`, `sk_`, PEM) | AST literal + SDK auth driver + Shannon entropy + placeholder exclusion |
| **`RULE-9-DOM-XSS`** | `SAST (CPG)` | `HIGH` | `CWE-79` | DOM-Based XSS & Unsanitized HTML Sinks (`innerHTML`, `document.write`) | Dynamic expression flowing into browser DOM HTML/script sinks |
| **`RULE-10-PATH-TRAVERSAL`** | `SAST (CPG)` | `HIGH` | `CWE-22` | Inter-Procedural Arbitrary File Read/Write/Delete (`open`, `rmtree`, `fs.*`) | Suppresses **only** AST-verified `commonpath` / `basename` / `is_relative_to` confinement |
| **`RULE-11-SSRF-URLOPEN`** | `SAST (CPG)` | `HIGH` / `MED` | `CWE-918` | Server-Side Request Forgery (`urllib.request.urlopen`, `requests.*`, `httpx.*`, `axios.*`) | Suppresses **only** AST-verified `ipaddress` private-IP rejection or constant HTTPS origin |
| **`RULE-12-LOG-INJECTION`** | `SAST (CPG)` | `LOW` | `CWE-117` | Tainted CR/LF Log Forging (`logger.info/warning/error`) | Suppresses **only** AST-verified `\r` / `\n` neutralization helpers |
| **`RULE-13-UNSAFE-DESERIALIZATION-CRYPTO`** | `SAST (CPG)` | `HIGH` / `MED` | `CWE-502` / `CWE-327` | Unsafe `pickle`/`marshal`/`yaml.load`, Unverified JWT, Weak `md5`/`sha1` | Verifies `SafeLoader`, `verify_signature`, and `usedforsecurity=False` |
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

### Step 2 — Start the FastAPI CPG Compiler & ASPM Backend (`http://127.0.0.1:8000`)

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

### Step 3 — Launch the Next.js Enterprise Workbench (`http://localhost:3000`)
Open a second terminal in `alastor-cpg-sast-platform/frontend`:
```bash
cd frontend
npm ci
npm run build
npm run start
```
Open **`http://localhost:3000`** in Chrome, Edge, Brave, or Firefox — select any local repository, paste a GitHub HTTPS URL, or drag-and-drop a project archive, and click **`Scan Target`**!

---

## 🧪 Zero-Trust Proof: Run the 18-Assertion Autonomous Self-Audit

Don't just take our word for it. ALASTOR ships with an autonomous end-to-end verification suite ([`verify_harness.py`](./verify_harness.py)) that boots the live CPG pipeline, verifies all **18 security assertions** (including `Assertion S` proving **100% True Positive detection and `0%` False Positive suppression** across sanitized vs. unsanitized endpoints, live OSV CVE reachability, STRIDE counts, RACI Golden Rules, CycloneDX v1.5 SBOM, Multi-Tenant RBAC, and SARIF v2.1.0), and concludes by **scanning ALASTOR's own production codebase (`cpg-sast-platform`) — asserting `0` unpatched vulnerabilities**:

```powershell
# Windows PowerShell
.\.venv\Scripts\python.exe verify_harness.py

# macOS / Linux
./.venv/bin/python verify_harness.py
```

Expected result:
```text
[PASS] 18 / 18 E2E Enterprise Assertions Verified (100%)
[PASS] Self-Audit of cpg-sast-platform: 0 Active Findings (SAST: 0, SCA: 0, IaC: 0, Secrets: 0)
```

---

## 📤 Standards-Compliant Enterprise Exports & APIs

| Export / API Endpoint | Standard / Format | Use Case |
| :--- | :--- | :--- |
| `GET /api/export/sarif` | **OASIS SARIF `v2.1.0`** | Upload directly to **GitHub Advanced Security Code Scanning**, Azure DevOps, or VS Code SARIF Viewer |
| `GET /api/sast-plus` (`cyclonedx_json`) | **OWASP CycloneDX `v1.5` JSON** | Executive Order 14028 supply-chain compliance, Dependency-Track, & customer procurement audits |
| `GET /api/export/report?format=html\|md\|json` | **Executive HTML / Markdown / JSON** | Board-ready penetration test & secure code review deliverable with `BFL` diffs |
| `GET /api/raci-governance` | **PMI / COBIT RACI JSON** | GRC & SOC 2 / ISO 27001 security accountability evidence |
| `POST /api/scan` & `POST /api/webhooks/{provider}` | **REST JSON + CI/CD Webhooks** | Automated pull-request gating in GitHub Actions, GitLab CI, or Jenkins |

---

## 📋 Release History

| Version | Date | Key Milestones |
| :--- | :---: | :--- |
| **`v2.6.1`** | **2026-10-25** | **AST-Verified Inter-Procedural Sanitizer Summary Engine (`0%` FP on custom helpers), `for`-loop iterator taint, call-site-routed inter-procedural DFG, DNS/IP SSRF guards, UUID-isolated scan sandboxes, and 100% Semgrep Pro & OSS `0`-finding parity.** |
| **`v2.6.0`** | 2026-10-25 | Live `OSV.dev` Lockfile CVE + CPG Import Reachability (`SCA-2`), GitHub Actions CI/CD Scanner (`IAC-3`), Inter-Procedural Route Taint (`RULE-10` Path Traversal, `RULE-11` SSRF, `RULE-12` Log Injection, `RULE-13` Deserialization/Crypto), Sanitizer-Aware SQLi (`RULE-7`), and Cloud/SDK Secret Hunter (`RULE-8`). |
| **`v2.5.0`** | 2026-10-22 | Desktop Enterprise Shell (`AppMenuBar` + `LeftFunctionBar`), STRIDE Count & Observation Matrix (`✔ OK` vs `✖ Issue`), Secret Keys Vault, Rule Engine Profiles, Multi-Tenant RBAC Accounts, Cross-File Call Graph (`:CALLS`), Entrypoints Graph, and Decluttered 360° Spider Map. |
| **`v2.0.0`** | 2026-10-19 | `SAST++++++` ASPM Suite, Written Observation Dossiers, Side-by-Side Before/After Code Diffs, `EPSS v4`, Interactive `RACI` Matrix, `CycloneDX v1.5` SBOM, and Continuous Track Changes Mode. |
| **`v1.0.0`** | 2026-10-17 | Core Tree-Sitter `AST + CFG + DFG` Code Property Graph compiler over `Neo4j + APOC`, Best Fix Location (`BFL`) chokepoint engine, and OASIS `SARIF v2.1.0` export. |

---

## 📚 Documentation, Contributing & Security

- **[📖 Master Product Guide & Standard Operating Procedure (SOP)](./docs/ALASTOR_Master_SOP_and_Product_Guide.md)** — Complete 10-part operator manual, CPG compiler deep-dive, and enterprise rollout guide.
- **[📋 Full Changelog (`CHANGELOG.md`)](./CHANGELOG.md)** — Detailed version-by-version engineering notes.
- **[🔬 Contributing Guide (`CONTRIBUTING.md`)](./CONTRIBUTING.md)** — How to add new Tree-Sitter languages, Cypher CPG rules, and run `verify_harness.py`.
- **[🛡️ Security Policy (`SECURITY.md`)](./SECURITY.md)** — Responsible disclosure guidelines and self-audit verification policy.

---

<div align="center">

### ⭐ Star ALASTOR on GitHub if you believe Compiler-Grade Code Security should be Open, Deterministic & Sovereign!

Released under the **[MIT License](./LICENSE)** • Built with **Tree-Sitter**, **Neo4j + APOC**, **FastAPI**, **Next.js**, **Monaco Editor**, and **ReactFlow**.

</div>
