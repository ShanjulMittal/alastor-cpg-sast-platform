# Changelog — ALASTOR (`Ἀλάστωρ`) Deterministic CPG, SAST, SCA, IaC & ASPM Platform

All notable architectural upgrades, security engine rules, UI/UX enhancements, and bug fixes for **ALASTOR** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [5.1.0] — 2026-11-23 — Multi-Turn ReAct CPG-Tool-Calling Agentic Hunter/Patcher & OS-Enforced Dual Docker Egress-Proxy Sandbox

### Added
- **Opt-In Multi-Turn ReAct CPG-Tool-Calling Agentic Hunter & Iterative S10→S11 Auto-Patcher ([`agentic_react_loop.py`](./backend/engine/agentic_react_loop.py), [`models.py`](./backend/models.py), [`CognitiveSecurityWorkbench.tsx`](./frontend/src/components/CognitiveSecurityWorkbench.tsx), [`FrontierAiCopilotDrawer.tsx`](./frontend/src/components/FrontierAiCopilotDrawer.tsx))**:
  - Built a provider-agnostic multi-turn ReAct agent (`run_agentic_react_hunt`, `run_agentic_react_patch`) on top of `FrontierAiEngine.dispatch_structured_json` with a full `$0` deterministic fallback trace when no BYOK API key is configured.
  - Added **7 strictly confined read-only CPG & code tools** (`list_repo_files`, `read_code_slice` capped at 120 lines, AST-ReDoS-validated `search_code_regex`, `query_cpg_callers`, `query_cpg_callees`, `get_function_context`, and terminal `submit_findings` / `submit_patch`) reading ONLY `PolyglotScopeWalker` clean files (blocking `.env*`, key material, `.git/`, hostile instruction files, and confined/escaping symlinks) with prompt-injection stripping, centralized raw-secret scrubbing, duplicate-call loop detection (`LOOP_DETECTED`), hallucination filtering, S6 verification, and iterative S10→S11 rejection feedback loops (up to 5 refinement rounds).
- **OS-Enforced Dual Docker Egress-Proxy Sandbox Images & Mediated-Egress Orchestrator ([`docker/sandbox/Dockerfile`](./docker/sandbox/Dockerfile), [`docker/sandbox/egress.Dockerfile`](./docker/sandbox/egress.Dockerfile), [`.dockerignore`](./.dockerignore), [`sandbox_orchestrator.py`](./backend/engine/sandbox_orchestrator.py), [`FleetCommandWorkbench.tsx`](./frontend/src/components/FleetCommandWorkbench.tsx))**:
  - Shipped hardened local-build Dockerfiles for `alastor-sandbox:local` (multi-stage `python:3.12-slim` rejecting private keys in `docker/sandbox/ca/`, pinned `GIT_CONFIG_COUNT=4` + `safe.directory /workspace`, setuid/setgid strip, `USER 65534:65534`, `socat` Unix-socket entrypoint) and `alastor-egress:local` (`ubuntu:24.04` with `squid` + `socat`, setuid/setgid strip, `USER 65534:65534`).
  - Added `generate_squid_egress_config` (deny-by-default `CONNECT` port `443` FQDN allowlist + anti-DNS-rebinding `acl blocked_dst dst` CIDR blocklist), `build_mediated_sandbox_plan` (scanner always runs `--network=none` bridged via Unix socket), `inspect_sandbox_images` drift checks inside `alastor doctor` / `GET /api/fleet/doctor`, `alastor scan --sandbox --egress none|mediated --allow-llm-host ...`, SDK wrappers (`agentic_hunt`, `agentic_patch`, `build_sandbox_plan`), and 3 confined sync routes (`POST /api/cognitive/agentic-hunt`, `POST /api/cognitive/agentic-patch`, `POST /api/fleet/sandbox-plan`).
- **Verification**: Expanded backend suite to **`533` passing pytest tests** (`0` TypeScript errors, `npm run build` green, `0` `dark:` classes, `0` DOM XSS sinks).

---

## [5.0.0] — 2026-11-23 — Full 5-Pillar Enterprise Evolution (18-Language Polyglot CPG, Cognitive Hunt/Verify/Chains/S11, Live EV + `ev-replay`, Hardened CLI/SDK + Fleet/6-Format Fusion, PR Delta Gate, Security TestGen, Compliance Autopilot + Custom Rules, Microservice Attack-Graph Stitching & PASTA/SAR Dossiers)

### Added
- **Pillar 1 — 18-Language Polyglot CPG Compiler, Dual Neo4j + SQLite WAL GraphStore & Leiden Communities ([`language_registry.py`](./backend/compiler/language_registry.py), [`scanner.py`](./backend/compiler/scanner.py), [`polyglot_rules.py`](./backend/engine/polyglot_rules.py), [`graph_store.py`](./backend/database/graph_store.py), [`community_detector.py`](./backend/engine/community_detector.py))**:
  - Upgraded from 4 to **18 offline Tree-Sitter languages** (`Python`, `JavaScript`, `TypeScript`, `TSX`, `Java`, `Go`, `Rust`, `C`, `C++`, `C#`, `PHP`, `Ruby`, `Kotlin`, `Swift`, `Scala`, `Dart`, `Solidity`, `SQL`) via `tree-sitter==0.26.1` + `tree-sitter-language-pack==0.13.0` (zero JVM!).
  - Added `.gitignore`-respecting Hostile-Repo Scope Walker, Generalized Domain-Aware Sanitizer Tracking, **12 new Polyglot Rule Packs (`RULE-22`–`RULE-33`)**, Dual-Engine `GraphStore` (`Neo4j APOC` primary + zero-Docker SQLite WAL `.alastor_vault/cpg_embedded.db` fallback), and deterministic Leiden `COMMUNITY_MAP` clustering.
- **Pillar 2 — 17-Lens Cognitive Security Hunter, S6 Adversarial Verifier, S8 Multi-Hop Exploit Chains & S11 3-Persona Patch Panel ([`security_playbooks.py`](./backend/engine/security_playbooks.py), [`adversarial_verifier.py`](./backend/engine/adversarial_verifier.py), [`exploit_chain_engine.py`](./backend/engine/exploit_chain_engine.py), [`CognitiveSecurityWorkbench.tsx`](./frontend/src/components/CognitiveSecurityWorkbench.tsx))**:
  - Added 17 specialist security playbooks, 6 repo-kind auto-baselines, prompt-injection stripping, centralized raw-secret + full-PEM scrubbing (`scrub_raw_secrets_text`), hybrid `$0` deterministic (`COG-1`–`COG-5`) + BYOK hunter, CPG sibling sweeps, S6 Adversarial Verifier (Exclusion Rules A–F + FIRST CVSS 3.1), S8 Multi-Hop Exploit Chains, S11 Dual-Verified 3-Persona Patch Panel (AST + hostile-patch post-gate + CPG severance + 3 personas), and 5 confined `/api/cognitive/*` routes.
- **Pillar 3 — Native `httpx` Live Exploit Verification (`EV`), Post-Fix `ev-replay`, Multi-Role IDOR Matrix & PASTA/SAR Blocker Promotion ([`exploit_verification_engine.py`](./backend/engine/exploit_verification_engine.py), [`pasta_threat_engine.py`](./backend/engine/pasta_threat_engine.py), [`sar_report_generator.py`](./backend/engine/sar_report_generator.py), [`LiveExploitVerificationConsole.tsx`](./frontend/src/components/LiveExploitVerificationConsole.tsx))**:
  - Added DNS-rebinding-proof IP-pinned `httpx` Live EV (loopback default + RFC1918/ULA staging opt-in, permanent public/cloud-metadata/redirect/self-port `:8000` blocks), Zero-Collection CPG Auto-Probing + OpenAPI 3.x/Swagger 2.0/Postman v2.1 import, 6 non-destructive probe families (`EV-IDOR-BOLA`, `EV-SQLI-ERROR-DIFF`, `EV-XSS-REFLECTED-CANARY`, `EV-CORS-CREDENTIAL-REFLECT`, `EV-OPEN-REDIRECT`, `EV-PATH-TRAVERSAL-HEADERS`), fail-closed `ev-replay` (`FIXED_VERIFIED` vs. `STILL_VULNERABLE`), runnable `curl` + `pytest` PoC generation (zero raw credentials), automatic **PASTA Stage VII Mandatory Pre-Go-Live Blocker** promotion, native Word (`.docx`) & PDF (`.pdf`) SAR Go-Live Dossiers, and 5 confined `/api/ev/*` routes.
- **Pillar 4 — Hostile-Repo Isolation, SQLite Stage Checkpoints (`--resume`), Universal 6-Format Scanner Fusion, CSV Fleet Runner & Embedded-First `alastor` CLI/SDK ([`hostile_repo_guard.py`](./backend/engine/hostile_repo_guard.py), [`checkpoint_store.py`](./backend/database/checkpoint_store.py), [`scanner_fusion_engine.py`](./backend/engine/scanner_fusion_engine.py), [`fleet_runner.py`](./backend/engine/fleet_runner.py), [`alastor_cli.py`](./backend/alastor_cli.py), [`alastor_sdk.py`](./backend/alastor_sdk.py), [`FleetCommandWorkbench.tsx`](./frontend/src/components/FleetCommandWorkbench.tsx))**:
  - Added `GIT_CONFIG_COUNT`-hardened git execution, repo-local `url.*.insteadOf` fail-closed blocking, target `.env`/config refusal, symlink/NTFS-junction-safe cleanup, SQLite WAL checkpoints with SHA-256 tamper rejection + host-produced scan provenance (`remediate --mode fix`), Universal 6-Format Scanner Fusion (**SARIF 2.1.0**, **CodeQL**, **Semgrep**, **Trivy**, **Gitleaks**, **Checkov**) onto ALASTOR's CPG (`corroborated_by`), CSV Multi-Repo Batch Fleet Runner (`--repo-file`, `--group-by-app`), embedded-first `alastor` CLI (`setup`, `doctor`, `estimate`, `scan`, `remediate`, `validate`, `ev-replay`, `gc`) + Typed Python SDK, and 8 confined `/api/fleet/*` & `/api/fusion/*` routes.
- **Pillar 5 — PR Delta Security Gate, Automated Security Regression Unit-Test Generator, 5-Framework Compliance Autopilot + ReDoS-Safe Custom Rule Studio & Cross-Repo Microservice Attack-Graph Stitching ([`pr_delta_gate.py`](./backend/engine/pr_delta_gate.py), [`security_test_generator.py`](./backend/engine/security_test_generator.py), [`compliance_and_rules_engine.py`](./backend/engine/compliance_and_rules_engine.py), [`microservice_stitcher.py`](./backend/engine/microservice_stitcher.py), [`NextGenAppSecStudio.tsx`](./frontend/src/components/NextGenAppSecStudio.tsx))**:
  - Added `alastor pr-gate` + `POST /api/nextgen/pr-gate` (`NEWLY_INTRODUCED` vs. `MODIFIED_CONTEXT` vs. `PRE_EXISTING`), deterministic `pytest`/`jest`/`vitest`/`go test` security regression test generator, **5-Framework Compliance Autopilot** (**PCI-DSS 4.0**, **SOC 2**, **ISO 27001**, **HIPAA**, **OWASP ASVS 5.0**), atomic ReDoS-AST-validated Custom Rule Studio + live sandbox, Cross-Repo Microservice Attack-Graph Stitching in ReactFlow, and 9 confined `/api/nextgen/*` routes.
- **Pre-Epic Foundations**: Native TruffleHog-grade Secret Scanner & Git-History Hunter (`secret_validator_engine.py`), Multi-Framework API Endpoints & Operations Tracer (`api_operations_engine.py`), and 7-Stage PASTA Threat Workbench (`PastaThreatWorkbench.tsx`) with native `.docx` & `.pdf` SAR Go-Live Dossiers.

---

## [4.0.0] — 2026-11-11 — Directional CPG & 360° Flow Graphs, Guided 4-Stage Daylight UI, One-Click Batch Auto-Fix & Token-Efficient Multi-Provider BYOK Frontier AI Copilot

### Added
- **100% Directional Graphs, 3-Step Single-Node Flow Synthesis, Flow Story Bar & 4-Zone Trust Boundary Graph ([`CustomGraphNode.tsx`](./frontend/src/components/CustomGraphNode.tsx), [`DirectionalFlowEdge.tsx`](./frontend/src/components/DirectionalFlowEdge.tsx), [`ReactFlowGraphPane.tsx`](./frontend/src/components/ReactFlowGraphPane.tsx), [`ThreatModelingView.tsx`](./frontend/src/components/ThreatModelingView.tsx), [`app_tree.py`](./backend/compiler/app_tree.py), [`remediation_patcher.py`](./backend/engine/remediation_patcher.py))**:
  - Replaced center-stacked handles with **4-way perimeter docking** (`Top`, `Bottom`, `Left`, `Right`, plus radial `atan2` perimeter docking in 360° Spider mode), custom `18×18` outer-border arrowheads, circled step badges (`①`–`⑳`), and directional `FLOWS ▶`, `TAINT ▶`, `CALLS ▶`, `IMPORTS ▶`, `TRUE ▶`, `FALSE ▶`, and `LOOP ↺` pills across all graph modes.
  - Added cross-file `IMPORTS` / `CALLS` extraction across Python (`import` / `from ... import`) and JS/TS (`import ... from`, `require(...)`, `@/...` aliases) in [`app_tree.py`](./backend/compiler/app_tree.py) and surfaced an interactive **`Cross-File Flows`** overlay in `360° App Map`.
  - Added deterministic **3-step Attack-Context Graph Synthesis** (`① Origin ──▶ ② BFL Chokepoint ──▶ ③ Security Impact`) for single-node SCA, IaC, Secret, and Web Intel findings so every finding has an unmistakable directional flow.
  - Added a plain-English **Flow Story Bar** above [`ReactFlowGraphPane.tsx`](./frontend/src/components/ReactFlowGraphPane.tsx), BFS **Upstream & Downstream Blast Radius** hover/click highlighting, and an interactive **4-Zone Directional Trust Boundary ReactFlow Graph** (`Zone 1 Ingress -> Zone 2 Entrypoints -> Zone 3 Validation & BFL -> Zone 4 Critical Sinks & Secrets`) in [`ThreatModelingView.tsx`](./frontend/src/components/ThreatModelingView.tsx).
- **Simplified 4-Stage Guided Workflow UI Shell with Zero Feature Reduction ([`StudioCommandHeader.tsx`](./frontend/src/components/StudioCommandHeader.tsx), [`page.tsx`](./frontend/src/app/page.tsx), [`QuickCommandModal.tsx`](./frontend/src/components/QuickCommandModal.tsx), [`useKeyboardNavigation.ts`](./frontend/src/hooks/useKeyboardNavigation.ts))**:
  - Reorganized navigation into **4 sequential workflow stages** inside the `44px` command header (**`1. Scan & Repos`**, **`2. Triage & Fix`**, **`3. 360° Map & Threats`**, **`4. ASPM, Rules & Reports`**), eliminating the nested 7-group menu popover and left icon rail while preserving 100% of existing engines, Target Picker modes, Cypher/Rule Studio, CycloneDX SBOM, STRIDE/PBOM, RACI, Multi-Tenant RBAC, Jira/GitHub sync, shortcuts (`Ctrl+K`, `j`/`k`, `[`/`]`, `d`), and export formats.
  - Centralized backend URL configuration in [`frontend/src/lib/api.ts`](./frontend/src/lib/api.ts) (`NEXT_PUBLIC_BACKEND_URL`) and added standalone light-mode **Executive HTML (`.html`)** and **RFC-4180 CSV (`.csv`)** exports enriched with Frontier AI verdicts.
- **One-Click Batch Auto-Fix (`"Fix All Safe Issues"`) with Atomic Rollback ([`remediation_patcher.py`](./backend/engine/remediation_patcher.py), [`main.py`](./backend/main.py), [`FlawExplorerSidebar.tsx`](./frontend/src/components/FlawExplorerSidebar.tsx))**:
  - Added `POST /api/remediate/batch-apply` (`batch_apply_workspace_patches`) sorting non-overlapping AST-deterministic fixes bottom-up (`target_line DESC`), validating Python `ast.parse` and JS/TS delimiter balance before writing, journaling `.alastor_patches` SHA-256 backups with mid-batch atomic rollback on conflict, exporting a `git apply`-ready unified `.patch`, and immediately re-scanning the CPG to report `verified_severed_count`.
- **Token-Efficient Multi-Provider BYOK Frontier AI Copilot (`90–95%` Prompt Token Savings) ([`frontier_ai_engine.py`](./backend/engine/frontier_ai_engine.py), [`FrontierAiCopilotDrawer.tsx`](./frontend/src/components/FrontierAiCopilotDrawer.tsx), [`MonacoCodePane.tsx`](./frontend/src/components/MonacoCodePane.tsx))**:
  - Added zero-SDK `urllib.request` adapters supporting **Google Gemini**, **OpenAI**, **Anthropic Claude**, and **OpenAI-Compatible / OpenRouter / Local Ollama / vLLM** (`GET/POST /api/ai/config`, `POST /api/ai/test-connection`, `POST /api/ai/validate-findings`, `POST /api/ai/audit-code-selection`, `POST /api/ai/synthesize-patch`, `POST /api/ai/explain-graph`).
  - Engineered **CPG Micro-Slicing** (`<= 40` lines of source/BFL/sink context + 1-line cross-file call signatures instead of full files) and **SHA-256 Slice Caching** (`0` tokens on repeat slices) with a live **Token Efficiency Meter**, `0o600` `.alastor_vault/ai_config.json` storage scoped per `(provider, host)`, DNS/IP + `30x` redirect SSRF blocking, and in-editor **Monaco Selection Auditing**.

### Changed & Hardened
- **Mandatory Light-Only High-Contrast Daylight Theme (`>= 4.5:1` WCAG AA) ([`globals.css`](./frontend/src/app/globals.css), [`layout.tsx`](./frontend/src/app/layout.tsx), [`AlastorBranding.tsx`](./frontend/src/components/AlastorBranding.tsx), [`MonacoCodePane.tsx`](./frontend/src/components/MonacoCodePane.tsx))**:
  - Retired all dark themes (`alastor-infernal`, `hecate-arcane`, `stygian-abyss`) and `vs-dark` Monaco instances; standardized exclusively on 3 high-visibility WCAG AA (`>= 4.5:1`) Daylight palettes (*Olympian Daylight*, *Athena Parchment*, *Hyperborean Frost*) with automatic `localStorage` migration.
- **Zero-Warning FastAPI `lifespan` & Test Suite Expansion ([`main.py`](./backend/main.py), [`neo4j_client.py`](./backend/database/neo4j_client.py), [`test_frontier_ai_engine.py`](./backend/tests/test_frontier_ai_engine.py), [`test_v4_graphs_and_batch_fix.py`](./backend/tests/test_v4_graphs_and_batch_fix.py))**:
  - Migrated FastAPI startup/shutdown to `@asynccontextmanager` `lifespan` with clean `Neo4jClient` driver lifecycle management; expanded unit & integration suite to **31 passing pytest tests (`0` warnings)** alongside **`20/20` `verify_harness.py` assertions** and **`0` self-audit findings** across all 57 platform files.

---

## [3.0.0] — 2026-11-10 — Studio IDE Overhaul, Live BFL "Sever the Thread" Auto-Patcher, CPG-Backed Zero-FP Web Intel & 21-Rule Matrix

### Added
- **2-Bar Studio IDE Shell & 5-Pillar Composite Workspaces ([`StudioCommandHeader.tsx`](./frontend/src/components/StudioCommandHeader.tsx), [`StudioStatusBar.tsx`](./frontend/src/components/StudioStatusBar.tsx), [`LeftFunctionBar.tsx`](./frontend/src/components/LeftFunctionBar.tsx), [`ResizableSplitPane.tsx`](./frontend/src/components/ResizableSplitPane.tsx))**:
  - Replaced legacy top bars with a unified `44px` `StudioCommandHeader`, `26px` `StudioStatusBar`, and 5-pillar navigation rail (`Code & Graph Studio`, `Threat & Secret Intelligence`, `Executive ASPM & Governance`, `Rule & Profile Studio`, `Repos, Accounts & Connectors`) with `Cinzel` / `Plus Jakarta Sans` / `JetBrains Mono` typography and 6 persisted themes.
  - Added per-card `Re-Scan`, `Open in Studio`, `Configure`, and `Delete` actions with live progress banner in [`ProjectsHubView.tsx`](./frontend/src/components/ProjectsHubView.tsx) and `O(1)` batched `UNWIND` Neo4j ingestion in [`ingestor.py`](./backend/database/ingestor.py).
- **Live Best Fix Location (`BFL`) "Sever the Thread" Auto-Patcher ([`remediation_patcher.py`](./backend/engine/remediation_patcher.py), [`MonacoCodePane.tsx`](./frontend/src/components/MonacoCodePane.tsx), [`GraphCanvas.tsx`](./frontend/src/components/GraphCanvas.tsx))**:
  - Added `POST /api/remediate/preview`, `POST /api/remediate/apply`, `POST /api/remediate/undo`, and `GET /api/remediate/history` with `os.path.realpath` + `os.path.commonpath` workspace confinement, `.alastor_patches` SHA-256 backup journal, live Monaco `DiffEditor`, instant CPG re-verification delta (`severed: true`), and `j`/`k`/`d`/`p`/`u` keyboard triage.
  - Added 20th E2E verification assertion (`Assertion U` in [`verify_harness.py`](./verify_harness.py)) validating `preview` $\rightarrow$ `apply` (`fixed_delta=1`, `remaining=0`) $\rightarrow$ `undo` (restoring exact pre-patch SHA-256).
- **3 New Zero-FP Deterministic CPG Security Rules (`RULE-14`, `RULE-15`, `RULE-16`) & Expanded `RULE-7` / `RULE-13` ([`rule_executor.py`](./backend/engine/rule_executor.py), [`ast_parser.py`](./backend/compiler/ast_parser.py), [`remediation_patcher.py`](./backend/engine/remediation_patcher.py))**:
  - **`RULE-14-CODE-INJECTION` (`CWE-94`)**: Detects `eval()`, `exec()`, `render_template_string()`, `vm.runInNewContext()`, `vm.runInThisContext()`, and `new Function()` on non-constant inputs unless sanitized by `ast.literal_eval`.
  - **`RULE-15-XXE-TLS-BYPASS` (`CWE-611` / `CWE-295`)**: Detects `XMLParser(..., resolve_entities=True)`, `xml.dom.minidom.parseString()`, `xml.sax.make_parser()` without `defusedxml`, outbound HTTP calls with `verify=False`, and `ssl._create_unverified_context()`.
  - **`RULE-16-INSECURE-RANDOM-OPEN-REDIRECT` (`CWE-330` / `CWE-601`)**: Detects `random.randint`/`random.choice`/`random.random`/`Math.random()` assigned to security token/secret/OTP/CSRF/nonce variables (suppressing `secrets.token_urlsafe`/`token_hex`), and unsanitized taint flows into `RedirectResponse`/`redirect`/`res.redirect`.
  - Refined `RULE-7-SQLI-FORMAT` (`CWE-89`) to require dynamic string interpolation (`f"`, `.format(`, `+`, `%`) and expanded `RULE-13-UNSAFE-DESERIALIZATION-CRYPTO` with `shelve.open`, `CryptoJS.MD5`, and `CryptoJS.SHA1`.
- **CPG-Backed Zero-FP Web Intel Engine ([`vuln_extractor.py`](./backend/engine/vuln_extractor.py), [`neo4j_client.py`](./backend/database/neo4j_client.py))**:
  - Upgraded `VulnExtractorEngine.identify_vulnerabilities_in_code` from substring matching to CPG AST/CFG/DFG verification (`_is_inside_quotes_or_comment`, `_cpg_node_matches_advisory`), eliminating all 163 false positives on `cpg-sast-platform` while expanding `CWE_SIGNATURE_CATALOG` with `CWE-918`, `CWE-611`, `CWE-295`, `CWE-330`, and `CWE-601`.
  - Hardened [`Neo4jClient.clear_database`](./backend/database/neo4j_client.py) fallback batch deletion with a bounded `for _ in range(1000):` loop (`CWE-835`) and parallelized OSV advisory hydration in [`osv_lockfile_scanner.py`](./backend/engine/osv_lockfile_scanner.py).

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
