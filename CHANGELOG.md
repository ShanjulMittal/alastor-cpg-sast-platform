# Changelog — ALASTOR (`Ἀλάστωρ`) Deterministic CPG, SAST, SCA, IaC & ASPM Platform

All notable architectural upgrades, security engine rules, UI/UX enhancements, and bug fixes for **ALASTOR** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.6.2] — 2026-10-27 — Open / Public (Paste-URL-Only) & Private (Ephemeral PAT Header) GitHub Repository Scanner

### Added
- **Dual-Mode GitHub / GitLab / Bitbucket Repository Scanner ([`main.py`](./backend/main.py), [`models.py`](./backend/models.py), [`TopBar.tsx`](./frontend/src/components/TopBar.tsx), [`ProjectsHubView.tsx`](./frontend/src/components/ProjectsHubView.tsx), [`AppMenuBar.tsx`](./frontend/src/components/AppMenuBar.tsx))**:
  - **Open / Public Repository Mode (`repo_visibility="public"`)**: Paste any public GitHub URL (`https://github.com/owner/repo`, `.git`, `/tree/<branch>`, or `owner/repo` shorthand) and clone + run the full 7-pass CPG, OSV SCA, IaC, Secret, and STRIDE pipeline with **zero tokens or setup**. Automatically detects if a pasted URL is actually private (`HTTP 401`) and guides the operator to Private mode.
  - **Private Repository Mode (`repo_visibility="private"`)**: Enforces Personal Access Token (`PAT`) authentication (`HTTP 401` if omitted or invalid). Injects credentials **exclusively via ephemeral `GIT_CONFIG_*` HTTP `Authorization: Basic` headers** (`GIT_TERMINAL_PROMPT=0`) inside `_build_git_subprocess_env()` — ensuring tokens are **never** written into clone URLs, `.git/config`, process command-line arguments, or logs.
  - **Live Pre-Flight Verification Endpoint (`POST /api/github/verify-repo`)**: Probes GitHub API metadata and `git ls-remote --heads` (`_probe_git_remote_heads`) with full DNS/IP SSRF protection to report `visibility_detected` (`public` vs. `private`), `auth_required`, `default_branch`, `language`, and repository description before cloning.
  - **Local `.alastor_vault` Credential Store for 1-Click `Re-Scan & Track Changes`**: Optional local-only credential persistence (`chmod 0600`, `.gitignore`-excluded) enabling seamless 1-click **`Re-Scan & Track Changes`** on private repositories across commits.
- **19th E2E Verification Assertion (`Assertion T` in [`verify_harness.py`](./verify_harness.py))**:
  - Verifies live `POST /api/github/verify-repo` public detection, `401` rejection when `repo_visibility="private"` is called without a token, and end-to-end URL-only cloning + Neo4j CPG scanning of a live public GitHub repository (`19 / 19` assertions passing, `0` self-audit findings).

---

## [2.6.1] — 2026-10-25 — AST-Verified Inter-Procedural Sanitizer Summary, `for`-Loop Iterator Taint & 100% Semgrep Pro/OSS Zero-Finding Parity

### Added
- **AST-Verified Inter-Procedural Sanitizer Summary Engine ([`main.py`](./backend/main.py), [`ast_parser.py`](./backend/compiler/ast_parser.py), [`dfg_builder.py`](./backend/compiler/dfg_builder.py))**:
  - Replaced name-based custom helper assumptions in `SANITIZER_PATTERNS` with **compiler-grade AST body verification**: any helper function in any scanned codebase earns `is_sanitizer=True` **only** when its parsed AST body genuinely enforces stdlib path confinement (`os.path.commonpath`, `os.path.basename`, `Path.is_relative_to`, `secure_filename`), SSRF DNS/IP or constant-origin allowlist guards (`ipaddress.ip_address` private/loopback/link-local rejection or literal `https://...` prefix checks), or CR/LF log neutralization (`\r`/`\n` replacement).
  - Removed standalone `os.path.realpath` from unconditional `SANITIZER_PATTERNS` and added **inline guard scope verification** (`inline_path_guarded_scopes`), ensuring ALASTOR **catches** unguarded `open(os.path.realpath(user_input))` and weak/fake URL validators while achieving **0% False Positives** on genuine `commonpath` / `is_relative_to` confinement (where Semgrep OSS and Semgrep Pro produce false positives on custom helpers).
  - Added `for_statement` / `for_in_statement` iterator taint propagation (`for item in req.files:` propagates taint `req -> item`) and call-site-routed inter-procedural DFG edges (`arg -> Call -> param`) in [`dfg_builder.py`](./backend/compiler/dfg_builder.py).

### Fixed & Remediated (Eliminating Remaining 7 Semgrep Pro/OSS Observations)
- **Outbound SSRF & Trusted Code-Host Origin Construction ([`main.py`](./backend/main.py), [`enterprise_manager.py`](./backend/engine/enterprise_manager.py), [`vuln_extractor.py`](./backend/engine/vuln_extractor.py))**:
  - Upgraded `_validate_safe_remote_url()`, `_safe_integration_http_request()`, and `_validate_safe_advisory_url()` to enforce `https://`, `socket.getaddrinfo()`, `ipaddress.ip_address()` rejection of `is_private` / `is_loopback` / `is_link_local` / `is_reserved` / `is_multicast`, and `allow_redirects=False`.
  - Added `_build_trusted_https_fetch_url()` using constant HTTPS origin prefixes (`https://raw.githubusercontent.com/...`, `https://github.com/...`, `https://gitlab.com/...`, `https://bitbucket.org/...`) + `urllib.parse.quote` path segment encoding, completely severing user control over the outbound `requests.get()` origin.
- **UUID-Isolated Workspaces & Server-Enumerated File Reads ([`main.py`](./backend/main.py))**:
  - Replaced user-derived directory `shutil.rmtree` cleanup in `_resolve_remote_url_target()` and `upload_target_files()` with fresh UUID-isolated workspace directories (`remote_<uuid>`, `upload_<uuid>`), per-segment `os.path.basename()` + `Path.resolve()` `startswith` + `os.path.commonpath()` confinement in `_persist_uploaded_workspace_file()`, and server-enumerated `os.walk` file opening in `_read_authorized_workspace_file()` for `/api/file`.

---

## [2.6.0] — 2026-10-25 — Semgrep-Superiority Multi-Engine Release: Inter-Procedural Route Taint, Live OSV.dev Lockfile CVE + CPG Reachability, CI/CD Workflow Security & Zero-FP Hardening

### Added
- **Live OSV.dev Transitive Lockfile CVE + CPG Import Reachability Engine (`SCA-2-LIVE-CVE-LOCKFILE`)**:
  - Added [`osv_lockfile_scanner.py`](./backend/engine/osv_lockfile_scanner.py) (`run_live_osv_lockfile_scan`) automatically parsing all direct and transitive locked dependencies across `package-lock.json` (npm v2/v3) and `requirements.txt` (PyPI) during `/api/scan`.
  - Queries `https://api.osv.dev/v1/querybatch` and `/v1/vulns/{id}` with a 6-hour local disk cache, maps npm/PyPI package names against CPG AST `import`/`require` statements across all source files to compute deterministic reachability (`REACHABLE`, `CONDITIONALLY_REACHABLE`, or `UNREACHABLE_DORMANT`), and consolidates multi-advisory hits per package with exact patched versions (`fixed_version`).
- **CI/CD GitHub Actions Workflow Security Scanner (`IAC-3-CICD-WORKFLOW-SECURITY`)**:
  - Audits `.github/workflows/*.yml|*.yaml` for mutable third-party action tags (`uses: owner/repo@vX` instead of immutable 40-char commit SHAs, `CWE-829`), untrusted `${{ github.event.* }}` shell command interpolation (`CWE-78`), and `pull_request_target` untrusted PR checkouts (`CWE-269`).
- **Inter-Procedural Multi-Framework CPG Taint & 4 New Deterministic SAST Rules (`RULE-10` through `RULE-13`)**:
  - Automatic HTTP route decorator taint-source promotion (`@app.get/post/put/delete/patch`, `@router.*`) in [`ast_parser.py`](./backend/compiler/ast_parser.py) for FastAPI/Flask string & dict parameters (automatically excluding safe primitive `int`/`float`/`bool` coercions and DI dependencies).
  - Fixed Python class method `self`/`cls` formal parameter alignment in [`main.py`](./backend/main.py) (`func_params_map`) so inter-procedural DFG argument-to-parameter propagation aligns accurately on instance/class methods.
  - Added `is_secondary_security_sink` propagation in [`dfg_builder.py`](./backend/compiler/dfg_builder.py) and four new zero-false-positive Cypher CPG rules in [`rule_executor.py`](./backend/engine/rule_executor.py):
    - `RULE-10-PATH-TRAVERSAL` (`CWE-22`): Inter-procedural tainted path traversal into `open()`, `shutil.rmtree()`, `os.remove()`, `fs.readFile*`, `fs.writeFile*` with `os.path.realpath` + `os.path.commonpath` sanitizer suppression.
    - `RULE-11-SSRF-URLOPEN` (`CWE-918`): Dynamic `urllib.request.urlopen()` (`file://` + SSRF exposure) and tainted `requests.*` / `httpx.*` / `axios.*` outbound fetches without URL allowlist validation.
    - `RULE-12-LOG-INJECTION` (`CWE-117`): Untrusted route/request inputs interpolated into `logger.*` / `logging.*` without CR/LF control-character stripping.
    - `RULE-13-UNSAFE-DESERIALIZATION-CRYPTO` (`CWE-502` / `CWE-327`): Unsafe `pickle.loads`, `marshal.loads`, `yaml.load` without `SafeLoader`, `jwt.decode` with `verify_signature: False`, and `hashlib.md5`/`sha1` without `usedforsecurity=False`.
- **Sanitizer-Aware SQLi (`RULE-7`) & Cloud/SDK Credential Hunter (`RULE-8`)**:
  - Upgraded `RULE-7-SQLI-FORMAT` to verify CPG `is_sanitizer` DFG paths (`int()` coercion), eliminating false positives that trip regex SAST tools like Semgrep.
  - Extended `RULE-8-HARDCODED-SECRET` with Cypher SDK/DB driver credential checks (`GraphDatabase.driver(..., auth=("user", "pass"))`, `psycopg2.connect`, `mysql.connector.connect`, `jwt.encode`) plus Tier-1 Cloud/API Token regex signatures (`AKIA...`, `ghp_...`, `github_pat_...`, `sk-live-...`, `sk-proj-...`, `xoxb-...`, `AIza...`, PEM private keys).
- **18th E2E Verification Assertion (`Assertion S`)**:
  - Added `Assertion S` to [`verify_harness.py`](./verify_harness.py) validating 100% True Positive detection and 0% False Positive rate across sanitized vs. unsanitized FastAPI endpoints, live OSV CVE reachability, and GitHub Actions workflow checks.

### Fixed & Remediated (Self-Audit & Semgrep Zero-Finding Hardening)
- **Dependency CVE Remediation (`0` CVEs across `212` npm + Python packages)**:
  - Upgraded `next` (`15.1.6` -> `15.5.28`), `postcss` (`8.5.31`), `postcss-selector-parser` (`7.1.7` via overrides), `requests` (`2.32.3` -> `2.34.2`), and added `tree-sitter-typescript==0.23.2`.
- **Platform Security Hardening**:
  - Hardened [`backend/main.py`](./backend/main.py), [`backend/engine/vuln_extractor.py`](./backend/engine/vuln_extractor.py), [`backend/engine/enterprise_manager.py`](./backend/engine/enterprise_manager.py), and [`backend/database/neo4j_client.py`](./backend/database/neo4j_client.py) with `_safe_resolve_under` (`realpath` + `commonpath`), `_validate_safe_remote_url` (`https` + DNS private-IP SSRF blocking), `_sanitize_log` (CR/LF stripping), `git clone --`, runtime-only Neo4j auth resolution, `next.config.mjs` CSP/frame headers, immutable 40-char commit SHA pinning in [`.github/workflows/semgrep.yml`](./.github/workflows/semgrep.yml), and [`.semgrepignore`](./.semgrepignore) test-fixture scoping.

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
