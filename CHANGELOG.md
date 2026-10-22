# Changelog — ALASTOR (`Ἀλάστωρ`) Deterministic CPG, SAST, SCA, IaC & ASPM Platform

All notable architectural upgrades, security engine rules, UI/UX enhancements, and bug fixes for **ALASTOR** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.5.0] — 2026-10-22 — Enterprise Navigation Shell, STRIDE Observation Dossier, Secret Keys Vault, Rule Engine Profiles, Multi-Tenant RBAC & Call/Entrypoint Graphs

### Added
- **Streamlined Enterprise Navigation Shell (`AppMenuBar` + `LeftFunctionBar`)**:
  - Introduced a structured 7-dropdown **Top Application Menu Bar** ([`AppMenuBar.tsx`](./frontend/src/components/AppMenuBar.tsx)): `1. File & Scan`, `2. Workspace`, `3. CPG & Graphs`, `4. Threat Model & Secrets`, `5. Rule Engine & Profiles`, `6. Accounts & Users`, and `7. Reports & Connectors`.
  - Introduced an always-visible vertical **Left Side Function Bar** ([`LeftFunctionBar.tsx`](./frontend/src/components/LeftFunctionBar.tsx)) providing 1-click access to all 8 enterprise modules (`Review`, `Threats`, `Rules`, `Accounts`, `Projects`, `Analytics`, `RACI`, `ASPM`) plus direct shortcuts for `Secrets`, `Call Graph`, and `Entrypoints`.
- **Microsoft STRIDE Count & Verdict Matrix + File-Anchored Observations Breakdown**:
  - Upgraded both Threat Modeling views ([`ThreatModelingView.tsx`](./frontend/src/components/ThreatModelingView.tsx) and [`SastPlusSuiteView.tsx`](./frontend/src/components/SastPlusSuiteView.tsx) Tab 5) with an **Executive STRIDE Count & Verdict Matrix Table** showing per-category and grand-total counts for `Total Checks`, `✔ OK Count`, `✖ Issue Count`, `Observations Count`, `✔ What is OK (Summary)`, `✖ What is the Issue (Summary)`, and `STRIDE Verdict (PASS / FAIL)`.
  - Added [`StrideObservationItem`](./backend/models.py) records generated dynamically in [`enterprise_manager.py`](./backend/engine/enterprise_manager.py) for every active SAST, SCA, IaC, and Secret finding as well as every verified workspace control (`Dockerfile` non-root `USER`, lockfiles, `.gitignore`/`.dockerignore` secret hygiene, CSP/HSTS headers, entrypoints, bounded loops).
  - Each observation card displays its verdict (`ISSUE` or `OK`), severity, control domain, `filepath:line`, live code snippet, *Why It Is an Issue / Why It Is OK*, *Risk & Business Impact*, *Corrective Action*, and a working **`Inspect Code`** button that opens the exact file and line in the Monaco Code & Dossier workbench.
- **Secret Keys Hunter & Cryptographic Vault (`RULE-8-HARDCODED-SECRET`)**:
  - Added `RULE-8-HARDCODED-SECRET` (`CWE-798`) and `RULE-9-DOM-XSS` (`CWE-79`) to the CPG rule engine.
  - Finding cards and the Threat Modeling **Secret Keys Vault** display the **Detected Secret Key Name**, **Masked Key Preview**, **Secret Provider Type**, and **Shannon Entropy** bits/char instead of generic runtime reachability badges, with RBAC-gated **Reveal / Mask Raw Secret** controls.
- **Rule Engine & Custom Test Profiles Matrix (`RuleEngineProfilesView`)**:
  - Dedicated workspace ([`RuleEngineProfilesView.tsx`](./frontend/src/components/RuleEngineProfilesView.tsx)) to switch between built-in test profiles (`Checkmarx-Style Optimized`, `Strict Zero-Trust Enterprise`, `Secret & Credential Hunter`, `Fast CI/CD PR Gate`), create custom test profiles (`POST /api/settings/presets`), toggle `SAST` / `SCA` / `IaC` engines, and check/uncheck individual security rules (`POST /api/settings/queries/batch-select`).
- **User Profiling, RBAC Clearance Matrix & Multi-Tenant Account Separation (`UserAccountProfileView`)**:
  - Dedicated workspace ([`UserAccountProfileView.tsx`](./frontend/src/components/UserAccountProfileView.tsx)) and backend endpoints (`GET /api/accounts`, `POST /api/accounts`, `POST /api/accounts/users`, `POST /api/accounts/switch`).
  - Supports isolated organizational tenant accounts (`Enterprise Security HQ`, `CISO & Executive Governance Division`, `Threat Intelligence & SecOps Division`, plus custom enclaves), interactive repository-to-account partitioning, live-toggleable RBAC capabilities (`can_reveal_secrets`, `can_edit_rules`, `can_triage_findings`, `can_manage_accounts`), and a persistent operator audit log.
- **Inter-Procedural Call Graph (`CALL_GRAPH`) & Attack Surface Entrypoints Graph (`ENTRYPOINT_GRAPH`)**:
  - Added [`call_graph_builder.py`](./backend/compiler/call_graph_builder.py) to emit `:CALLS` edges across functions/methods and added `CALL_GRAPH` and `ENTRYPOINT_GRAPH` modes to [`ReactFlowGraphPane.tsx`](./frontend/src/components/ReactFlowGraphPane.tsx).
- **Decluttered 360° Application Spider Map (`APP_TREE`)**:
  - Added Smart Clustering & Folder-First Progressive Disclosure in [`ReactFlowGraphPane.tsx`](./frontend/src/components/ReactFlowGraphPane.tsx) so large repositories (50+ to 1,000+ files) render cleanly without overlapping nodes.

### Fixed
- **Threat Modeling `Inspect Code` Navigation**:
  - Added [`openCodeLocationInIde`](./frontend/src/store/useAuditStore.ts) in `useAuditStore.ts` so clicking `Inspect Code` on any STRIDE threat, observation, entrypoint, or PBOM check switches cleanly to `REMEDIATION_IDE`, loads the exact file and line in Monaco, and selects the linked finding when present.
- **Accounts Page Runtime Crash & Schema Synchronization**:
  - Resolved `TypeError: Cannot read properties of undefined (reading 'includes')` on `acct.assigned_project_ids` by synchronizing `TenantAccount`, `UserProfileRecord`, `CreateAccountRequest`, and `CreateUserProfileRequest` across [`backend/models.py`](./backend/models.py), [`backend/engine/enterprise_manager.py`](./backend/engine/enterprise_manager.py), and [`UserAccountProfileView.tsx`](./frontend/src/components/UserAccountProfileView.tsx).
- **Cached SAST Findings & Web Runtime Header Checks Across Project Switches**:
  - Updated [`get_or_compute_findings`](./backend/main.py) to restore cached SAST findings from `scan_history_cache.json` when switching between previously scanned projects (`NewsLetter`, `FRR`, `cpg-sast-platform`).
  - Updated [`run_sca_and_iac_scanners`](./backend/engine/enterprise_manager.py) to inspect `next.config.ts` / `vite.config.ts` web runtime headers on target repositories even when a `Dockerfile` is also present.
- **Scan Subprocess Timeout & Non-Blocking Progress**:
  - Added strict per-command timeouts and non-blocking scan progress polling so large repositories (such as `FRR`) never hang the backend server.

---

## [2.0.0] — 2026-10-19 — SAST++++++ ASPM Suite, Written Observation Dossiers, Reachability, EPSS v4, RACI Matrix & Track Changes

### Added
- **Always-Visible Written Observation Dossier & Side-by-Side Code Diff (`MonacoCodePane`)**:
  - Every SAST, SCA, and IaC finding displays affected third-party software packages, lockfile-resolved versions, *What Is Wrong*, *Why It Matters*, *Real-World Analogy*, and a **Side-by-Side Before (`-`) vs. After (`+`) Remediation Code Diff** with 1-click copy.
- **Call-Graph Reachability & EPSS v4 Exploitability Scoring**:
  - Automatic classification into `REACHABLE` (`🎯 RUNTIME REACHABLE`), `CONDITIONALLY_REACHABLE` (`⚙️ BUILD / DEV REACHABLE`), and `UNREACHABLE_DORMANT` (`💤 DORMANT / UNREACHABLE`) with written proofs and 30-day EPSS probability scores.
- **Saved Scan Snapshots & Continuous Track Changes Mode (`/api/scan/track-changes`)**:
  - Persistent scan history with `Last Scanned` timestamps and automatic delta tracking (`✅ Fixed`, `🆕 New`, `⏳ Unchanged`).
- **Interactive PMI / COBIT RACI Security Governance Matrix (`RACI_GOVERNANCE`)**:
  - `7 Roles × 9 Security Lifecycle Activities` interactive RACI matrix with Golden Rule validation (`100% Governance Health Score`).
- **SAST++++++ ASPM Suite (`SAST_PLUS_SUITE`)**:
  - 6-pillar command center: Plain-English Impact Translator, Live CycloneDX v1.5 SBOM, API & Entrypoint Attack Surface, Management Remediation Roadmap, STRIDE Threat Model & CI/CD PBOM, and Non-Coder Security Academy.
- **6 Curated Light & Dark Mythological Themes**:
  - *Olympian Daylight*, *Athena Parchment*, *Hyperborean Frost*, *Alastor Infernal*, *Hecate Arcane*, and *Stygian Abyss*.

---

## [1.0.0] — 2026-10-17 — Core Deterministic CPG Engine & Neo4j APOC Foundation

### Added
- Multi-language **Tree-Sitter** AST normalizer, Control-Flow Graph (`CFGBuilder`), and reaching-definitions Data-Flow Graph (`DFGBuilder`) persisted in **Neo4j 5 + APOC**.
- Core deterministic CPG security rules (`RULE-1-TAINT` through `RULE-7-SQLI-FORMAT`), Best Fix Location (`BFL`) dominator chokepoint calculation, multi-site CVE advisory extractor (`OSV`, `NVD`, `CISA KEV`), Jira/GitHub Issues integration hub, and OASIS **SARIF v2.1.0** export.
