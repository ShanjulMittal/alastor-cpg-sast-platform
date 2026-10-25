<div align="center">

# ALASTOR (`Ἀλάστωρ`) v2.6.0 — Enterprise Deterministic Code Property Graph (CPG), SAST, Live OSV SCA, CI/CD & IaC, STRIDE Threat Modeling & ASPM Platform

<img src="./docs/screenshots/alastor_demon_logo.jpg" alt="ALASTOR Demon Crest" width="180" />

**Open-Source Deterministic Code Property Graph (Tree-Sitter AST + CFG + DFG + Call Graph over Neo4j) • Inter-Procedural Multi-Framework SAST (`18` Built-In Rules, `0%` False Positives) • Live OSV.dev Transitive Lockfile CVE + CPG Import Reachability • CI/CD GitHub Actions Security • Cloud & SDK Secret Keys Vault • STRIDE Count & Observation Matrix • Multi-Tenant RBAC • EPSS v4 • CycloneDX v1.5 SBOM**

[![Version: 2.6.0](https://img.shields.io/badge/Version-v2.6.0%20Enterprise-violet.svg)](./CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-amber.svg)](./LICENSE)
[![Self-Audit: 0 Findings](https://img.shields.io/badge/Self--Audit-0%20Findings%20(18%2F18%20Assertions%20Pass)-emerald.svg)](./verify_harness.py)
[![SARIF: v2.1.0](https://img.shields.io/badge/OASIS-SARIF%20v2.1.0-cyan.svg)](./backend/main.py)
[![SBOM: CycloneDX v1.5](https://img.shields.io/badge/SBOM-CycloneDX%20v1.5-indigo.svg)](./backend/engine/enterprise_manager.py)

[**📖 Full Master Product Guide & Standard Operating Procedure (SOP)**](./docs/ALASTOR_Master_SOP_and_Product_Guide.md) • [**📋 Release History & Changelog (v2.6.0)**](./CHANGELOG.md) • [**🔬 Contributing Guide**](./CONTRIBUTING.md) • [**🛡️ Security Policy**](./SECURITY.md)

</div>

---

## 🔥 Overview

Named after **Alastor (`Ἀλάστωρ`)**, the relentless Greek mythological spirit of retribution who hunts down hidden corruptions, **ALASTOR v2.5.0** is a 100% local-first **Code Property Graph (CPG), Threat Modeling & Application Security Posture Management (ASPM)** platform built for **Security Researchers, AppSec Architects, Red Teamers, Developers, and CISOs**.

Unlike regex-based scanners that flood teams with false positives and cryptic rule IDs, ALASTOR compiles source code into a unified **Abstract Syntax Tree (AST)**, **Control-Flow Graph (CFG)**, **Data-Flow Graph (DFG)**, and **Inter-Procedural Call Graph (`:CALLS`)** inside **Neo4j + APOC**. Every finding is paired with a **Written Observation Dossier**, **Secret Key Entropy & Vault Unmasking**, **STRIDE Threat & Observation Counts**, **Call-Graph Reachability Proof**, **EPSS v4 30-Day Exploit Probability**, and a **Side-by-Side Before (`-`) vs. After (`+`) Code Diff**.

![ALASTOR Code & Graph Review with Written Observation Dossier](./docs/screenshots/alastor_02_code_review_dossier.png)

---

## 🚀 What's New in v2.5.0 (Enterprise Release)

1. **Streamlined Enterprise Shell (`Top Menu Bar` + `Left Side Function Bar`)**
   - **7-Dropdown Top Application Menu Bar** ([`AppMenuBar.tsx`](./frontend/src/components/AppMenuBar.tsx)): `File & Scan`, `Workspace`, `CPG & Graphs`, `Threat Model & Secrets`, `Rule Engine & Profiles`, `Accounts & Users`, and `Reports & Connectors`.
   - **Vertical Left Activity Rail** ([`LeftFunctionBar.tsx`](./frontend/src/components/LeftFunctionBar.tsx)): 1-click switching across all **8 Enterprise Modules** (`Review`, `Threats`, `Rules`, `Accounts`, `Projects`, `Analytics`, `RACI`, `ASPM`) plus direct launchers for `Secrets`, `Call Graph`, and `Entrypoints`.
2. **STRIDE Executive Count Matrix & File-Anchored Observations Dossier**
   - Available in both the dedicated **Threat Modeling** workspace ([`ThreatModelingView.tsx`](./frontend/src/components/ThreatModelingView.tsx)) and **SAST++++++ Suite Tab 5** ([`SastPlusSuiteView.tsx`](./frontend/src/components/SastPlusSuiteView.tsx)):
     - **Top STRIDE Count & Verdict Matrix Table**: Displays `Total Checks`, `✔ OK Count`, `✖ Issue Count`, `Observations Count`, `✔ What is OK (Summary)`, `✖ What is the Issue (Summary)`, and `STRIDE Verdict (PASS / FAIL)` across all 6 STRIDE domains (`S`, `T`, `R`, `I`, `D`, `E`) with a grand-total rollup row.
     - **Detailed STRIDE Observations Breakdown (`StrideObservationItem`)**: Every active SAST/SCA/IaC/Secret issue (`ISSUE`) and verified security control (`OK`) is itemized with `filepath:line`, live code snippet, *Why It Is an Issue / Why It Is OK*, *Risk & Business Impact*, *Corrective Action*, and a working **`Inspect Code`** button.
3. **Secret Keys Hunter & Cryptographic Vault (`RULE-8-HARDCODED-SECRET`)**
   - Detects hardcoded API keys, JWT secrets, cloud tokens, and container credentials (`CWE-798`), displaying the **Detected Secret Key Name**, **Masked Preview**, **Secret Provider Type**, and **Shannon Entropy** bits/char on finding cards instead of generic reachability badges, with RBAC-controlled **Reveal / Mask Raw Secret**.
4. **Rule Engine & Test Profiles Matrix (`RuleEngineProfilesView`)**
   - Switch between 4 built-in test profiles (`Checkmarx-Style Optimized`, `Strict Zero-Trust Enterprise`, `Secret & Credential Hunter`, `Fast CI/CD PR Gate`), create custom test profiles, toggle `SAST` / `SCA` / `IaC` engines, and check/uncheck individual security rules (`RULE-1` through `RULE-9`, `SCA-1`, `IAC-1`, `IAC-2`).
5. **User Profiling, RBAC & Multi-Tenant Account Separation (`UserAccountProfileView`)**
   - Manage isolated organizational tenant accounts (`Enterprise Security HQ`, `CISO & Executive Governance Division`, `Threat Intelligence & SecOps Division`, or custom enclaves), partition repositories across accounts, toggle live RBAC capabilities (`Reveal Secrets`, `Edit Rules`, `Triage Findings`, `Tenant Admin`), and audit operator session actions.
6. **7-Mode Decluttered Graph Canvas (`Call Graph`, `Entrypoints Graph` & `360° Spider Map`)**
   - Added **Inter-Procedural Call Graph (`CALL_GRAPH`)** and **Attack Surface Entry Points Graph (`ENTRYPOINT_GRAPH`)** alongside **Smart Folder-Clustered 360° Application Spider Map (`APP_TREE`)** so large applications remain crystal-clear.

---

## ✨ Core Platform Capabilities

| Module | Workspace ID | Key Capabilities |
| :--- | :--- | :--- |
| **1. Code & CPG Workbench** | `REMEDIATION_IDE` | Tree-Sitter `AST + CFG + DFG + Call Graph` in Neo4j, Written Observation Dossier, Best Fix Location (`BFL`), Side-by-Side Before/After Code Diff, 7 Graph Modes. |
| **2. Threat Modeling & Secret Vault** | `THREAT_MODELING` | Microsoft STRIDE Count & Verdict Matrix, `✔ What is OK` vs `✖ What is the Issue`, Detailed File-Anchored Observations, Secret Keys Vault, Trust Boundaries & Entrypoints, CI/CD PBOM. |
| **3. Rule Engine & Test Profiles** | `RULE_ENGINE_PROFILES` | Built-in & Custom Test Profiles, Per-Rule Checkbox Matrix (`12 SAST/SCA/IaC/Secret Rules`), Engine Toggles, Custom Sanitizers & Cypher Rule Editor. |
| **4. User Profiling & Accounts** | `USER_PROFILES` | Multi-Tenant Account Separation (`STRICT` / `SHARED_READ`), Repository Partitioning, 5 RBAC Operator Tiers, Live Permission Toggles & Audit Trail. |
| **5. Projects & Saved Scans Hub** | `PROJECTS_HUB` | Local Repository Auto-Discovery, Persistent Scan Snapshots (`Last Scanned`), Track Changes Deltas (`Fixed` / `New` / `Unchanged`), Live OSV/NVD/CISA Web Advisories. |
| **6. Deep Dive Analytics** | `DEEP_DIVE` | Severity & Ecosystem Breakdown, SLA Aging Buckets, OWASP Top 10 / PCI-DSS v4.0 / NIST 800-53 / SOC 2 Compliance Readiness, Unified Engine Table. |
| **7. RACI Governance Matrix** | `RACI_GOVERNANCE` | Interactive `7 Roles × 9 Security Lifecycle Activities` PMI/COBIT RACI Matrix with Golden Rule validation (`100% Governance Health Score`). |
| **8. SAST++++++ ASPM Suite** | `SAST_PLUS_SUITE` | Plain-English Risk Translator, Live CycloneDX v1.5 SBOM, API Attack Surface, Remediation Roadmap, STRIDE & PBOM, and Security Academy. |

---

## 🖼️ Platform Gallery

### 1. Side-by-Side Before (`-`) vs. After (`+`) Code Diff & 360° Architecture Spider Map
![Before vs After Code Diff and 360 Spider Map](./docs/screenshots/alastor_10_before_after_diff_and_spider_map.png)

### 2. Dark Mythic Theme (`Alastor Infernal`) — Split Code & CPG View
![Dark Mythic Theme](./docs/screenshots/alastor_11_dark_mythic_theme.png)

### 3. Automated Microsoft STRIDE Threat Model & CI/CD Pipeline BOM (PBOM)
![STRIDE Threat Model and CI/CD PBOM](./docs/screenshots/alastor_08_stride_threat_model_pbom.png)

### 4. Overview & Deep-Dive Analytics (Severity, SLA Aging & OWASP / PCI-DSS / NIST Compliance)
![Deep Dive Analytics](./docs/screenshots/alastor_05_deep_dive_analytics.png)

### 5. Interactive RACI Security Governance & Accountability Matrix
![RACI Governance Matrix](./docs/screenshots/alastor_06_raci_governance_matrix.png)

### 6. Live CycloneDX v1.5 SBOM & Supply-Chain Inspector
![Live CycloneDX SBOM](./docs/screenshots/alastor_09_live_sbom_cyclonedx.png)

---

## 🚀 Quick Start

### Prerequisites
- **Docker Desktop** (for Neo4j 5 + APOC graph database)
- **Python 3.11+**
- **Node.js 18+ & npm**

### 1. Start Neo4j + APOC
```bash
docker compose up -d neo4j
```

### 2. Start the FastAPI CPG & ASPM Backend (`http://127.0.0.1:8000`)
```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### 3. Start the Next.js Frontend (`http://localhost:3000`)
```bash
cd frontend
npm ci
npm run build
npm run start
```
Then open **`http://localhost:3000`** in your browser.

---

## 🧪 Running the 18-Assertion Autonomous Verification Suite

ALASTOR includes an end-to-end verification harness ([`verify_harness.py`](./verify_harness.py)) that tests Neo4j APOC, all 18 built-in CPG/SCA/IaC rules, inter-procedural FastAPI/Express taint & 0% false-positive sanitizer suppression (`Assertion S`), live OSV.dev lockfile CVE reachability, GitHub Actions CI/CD security, BFL, RACI, SBOM, STRIDE counts & observations, PBOM, Call Graph, Entrypoints Graph, Multi-Tenant RBAC Accounts, SARIF v2.1.0 export, Track Changes, and performs a **full self-audit of `cpg-sast-platform` asserting 0 unpatched findings**:

```bash
.\.venv\Scripts\python.exe verify_harness.py
```

---

## 📋 Version History & Changelog Summary

| Version | Date | Highlights |
| :--- | :--- | :--- |
| **`v2.6.0`** | **2026-10-25** | **Semgrep-Superiority Multi-Engine Release: Live OSV.dev Lockfile CVE + CPG Import Reachability (`SCA-2`), CI/CD GitHub Actions Scanner (`IAC-3`), Inter-Procedural Route Taint (`RULE-10` Path Traversal, `RULE-11` SSRF, `RULE-12` Log Injection, `RULE-13` Deserialization/Crypto), Sanitizer-Aware SQLi (`RULE-7`), SDK/Cloud Token Hunter (`RULE-8`), and Zero-CVE Platform Hardening.** |
| **`v2.5.0`** | 2026-10-22 | Enterprise Shell (`AppMenuBar` + `LeftFunctionBar`), STRIDE Count & Observation Matrix (`✔ OK` vs `✖ Issue`), Secret Keys Vault (`RULE-8`), Rule Engine Test Profiles (`RuleEngineProfilesView`), Multi-Tenant RBAC Accounts (`UserAccountProfileView`), Call Graph (`CALL_GRAPH`), Entrypoints Graph (`ENTRYPOINT_GRAPH`), and Decluttered 360° Spider Map. |
| **`v2.0.0`** | 2026-10-19 | SAST++++++ ASPM Suite, Written Observation Dossiers, Side-by-Side Before/After Code Diffs, Call-Graph Reachability, EPSS v4, RACI Matrix, CycloneDX v1.5 SBOM, and Continuous Track Changes Mode. |
| **`v1.0.0`** | 2026-10-17 | Core Tree-Sitter AST + CFG + DFG Code Property Graph over Neo4j + APOC, deterministic CPG taint & structural rules, BFL calculation, and OASIS SARIF v2.1.0 export. |

See [**`CHANGELOG.md`**](./CHANGELOG.md) for the complete release notes.

---

## 📚 Full Documentation & Standard Operating Procedure (SOP)

See [**`docs/ALASTOR_Master_SOP_and_Product_Guide.md`**](./docs/ALASTOR_Master_SOP_and_Product_Guide.md) for the complete competitive benchmark, architectural reference, and 10-part step-by-step operator manual.
