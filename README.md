<div align="center">

<img src="./docs/screenshots/alastor_demon_logo.jpg" alt="ALASTOR Mythological Daimon Crest" width="190" />

# ALASTOR (`Ἀλάστωρ`) `v5.1.0`

### **The Sovereign 18-Language Code Property Graph (CPG), Multi-Turn ReAct CPG Agent, Live Exploit Verification (`EV` + `ev-replay`), Universal 6-Format Scanner Fusion, PR Delta Gate, Compliance Autopilot, Dual Docker Egress Sandbox & Executive ASPM Platform**

*Stop drowning in regex false positives, JVM-heavy graphs, mandatory LLM token bills, and six-figure SaaS lock-in. Run **ALASTOR `v5.1.0`** via the crisp **WCAG AA Daylight Web IDE**, the **9-Command Offline-First `alastor` CLI**, the **Typed Python SDK**, or **OS-Enforced Dual Docker Egress-Proxy Containers** — compiling **18 languages** into a mathematical **AST + CFG + DFG + Inter-Procedural Call Graph** backed by **Neo4j APOC or Zero-Docker SQLite WAL**.*

[![Version: v5.1.0 Sovereign Enterprise](https://img.shields.io/badge/Release-v5.1.0%20Sovereign%20Enterprise-0284c7?style=for-the-badge)](./CHANGELOG.md)
[![Tests: 533 Passing](https://img.shields.io/badge/Backend%20Suite-533%20Tests%20Passing-059669?style=for-the-badge)](./backend/tests/)
[![Languages: 18 Polyglot CPG](https://img.shields.io/badge/Polyglot%20CPG-18%20Languages%20%28Zero%20JVM%29-4f46e5?style=for-the-badge)](#-comprehensive-feature-catalog-alastor-v510)
[![Graph: Neo4j + SQLite WAL](https://img.shields.io/badge/Dual%20GraphStore-Neo4j%20%2B%20SQLite%20WAL-0e7490?style=for-the-badge)](./backend/database/graph_store.py)
[![Agents: 17 Playbooks + ReAct CPG](https://img.shields.io/badge/Cognitive%20Engine-17%20Playbooks%20%2B%20ReAct%20CPG-7c3aed?style=for-the-badge)](./backend/engine/agentic_react_loop.py)
[![Live EV: httpx + ev-replay + IDOR](https://img.shields.io/badge/Live%20EV-IP--Pinned%20httpx%20%2B%20ev--replay-d97706?style=for-the-badge)](./backend/engine/exploit_verification_engine.py)
[![Sandbox: Dual Docker Egress Proxy](https://img.shields.io/badge/Sandbox-Dual%20Docker%20Egress%20Proxy-0369a1?style=for-the-badge)](./docker/sandbox/)
[![License: MIT](https://img.shields.io/badge/License-MIT-e11d48?style=for-the-badge)](./LICENSE)

<br />

[**⚡ 3-Minute Quick Start (Web, CLI, SDK & Docker Sandbox)**](#-3-minute-quick-start-100-local--sovereign) •
[**✨ Detailed Feature Catalog**](#-comprehensive-feature-catalog-alastor-v510) •
[**🛡️ Complete 33-Rule & Engine Matrix**](#️-complete-33-rule--multi-engine-security-matrix) •
[**📸 Visual Daylight Studio Tour**](#-complete-visual-tour--every-stage-directional-graph-ai-workflow--export) •
[**📖 Complete Non-Technical & Technical Master SOP**](./docs/ALASTOR_Master_SOP_and_Product_Guide.md)

</div>

---

![ALASTOR Daylight Studio — Split Code, Directional Attack Path & Flow Story Bar](./docs/screenshots/shot_03_code_review_dossier_and_diff.png)

> **Named after Alastor (`Ἀλάστωρ` — *"The Unforgetting Avenger"*)**, **ALASTOR `v5.1.0`** unifies **15+ enterprise AppSec capabilities** in a single sovereign, offline-first platform (Zero SaaS lock-in, Zero JVM):
> 1. **18-Language Polyglot 4-Pass CPG Compiler + Dual `Neo4j APOC` / Zero-Docker `SQLite WAL` GraphStore**: Compiles `Python`, `JS`, `TS`, `TSX`, `Java`, `Go`, `Rust`, `C`, `C++`, `C#`, `PHP`, `Ruby`, `Kotlin`, `Swift`, `Scala`, `Dart`, `Solidity`, and `SQL` via `Tree-Sitter` into **AST + CFG + DFG + Call Graph** with **Domain-Aware Sanitizer Tracking**, **Leiden Communities**, and **33 deterministic rules (`RULE-1..33`, `SCA-1..2`, `IAC-1..3`)**.
> 2. **17-Lens Cognitive Security Playbooks + Multi-Turn ReAct CPG-Tool-Calling Agent**: Runs `$0` deterministic hunts (`COG-1..5`) + CPG sibling sweeps, OR opt-in BYOK multi-turn ReAct tool loops (`list_repo_files`, `read_code_slice`, ReDoS-safe `search_code_regex`, `query_cpg_callers`, `query_cpg_callees`, `get_function_context`) with prompt-injection stripping and centralized secret/PEM scrubbing.
> 3. **S6 Adversarial Verifier (`CVSS 3.1`), S8 Multi-Hop Exploit Chains & S11 Dual-Verified 3-Persona Patch Panel**: Applies Exclusion Rules A–F, links multi-step attack chains, and validates every remediation through AST syntax checks, hostile-patch post-gating, CPG severance proof, and 3 adversarial reviewer personas (plus iterative S10→S11 ReAct auto-refinement).
> 4. **IP-Pinned Native `httpx` Live Exploit Verification (`EV`), Post-Fix `ev-replay` & Multi-Role IDOR Matrix**: Auto-discovers API routes from ALASTOR's CPG + OpenAPI 3.x / Swagger 2.0 / Postman v2.1, runs 6 non-destructive deterministic probe families with DNS-rebinding-proof IP pinning, exports credential-free `curl` & `pytest` PoCs, and automatically promotes `RUNTIME_EXPLOIT_CONFIRMED` findings to **PASTA Stage VII Mandatory Pre-Go-Live Blockers**.
> 5. **7-Stage PASTA Threat Modeling, STRIDE, Native Word (`.docx`) & PDF (`.pdf`) SAR Go-Live Dossiers**: Generates board-ready Security Assessment Reports with Go-Live Release Gates, Attack Trees, CycloneDX 1.5 SBOM, and PMI/COBIT RACI.
> 6. **Hardened 9-Command `alastor` CLI + Typed Python SDK + SQLite `--resume` Checkpoints + CSV Fleet Runner**: Run `setup`, `doctor`, `estimate`, `scan`, `pr-gate`, `remediate` (with host-produced provenance gating), `validate`, `ev-replay`, and `gc` offline or against `--server`.
> 7. **Universal 6-Format Scanner Fusion into ALASTOR CPG**: Auto-detects and fuses **SARIF 2.1.0**, **CodeQL**, **Semgrep**, **Trivy**, **Gitleaks**, and **Checkov** reports onto ALASTOR's CPG with `corroborated_by` multi-engine agreement.
> 8. **PR / Git-Diff Delta Gate, Automated Security Regression Unit-Test Generator, 5-Framework Compliance Autopilot + ReDoS-Safe Custom Rule Studio & Cross-Repo Microservice Attack-Graph Stitching**: Separates `NEWLY_INTRODUCED` vs. `PRE_EXISTING` PR risk, generates AST-verified `pytest`/`jest`/`vitest`/`go test` regression tests, attests **PCI-DSS 4.0**, **SOC 2**, **ISO 27001**, **HIPAA**, and **OWASP ASVS 5.0**, authors ReDoS-safe custom rules, and stitches multi-repo microservice exploit paths in ReactFlow.
> 9. **Hostile-Repo Isolation & OS-Enforced Dual Docker Egress-Proxy Sandbox**: Neutralizes target git hooks/fsmonitor/filters/diffs, fails closed on `url.*.insteadOf`, refuses target `.env`/configs, and ships `alastor-sandbox:local` (`--network=none`, `--read-only`, `USER 65534:65534`) + `alastor-egress:local` (non-root Squid FQDN + anti-DNS-rebinding `blocked_dst` sidecar).

---

## ✨ Comprehensive Feature Catalog (ALASTOR `v5.1.0`)

Every capability below runs **100% locally and sovereignly** with zero mandatory cloud upload and a full **`$0` offline deterministic baseline** (optional BYOK LLMs are strictly opt-in). For step-by-step instructions tailored to both non-technical stakeholders and technical engineers, read the **[📖 Master SOP & Complete Application Guide](./docs/ALASTOR_Master_SOP_and_Product_Guide.md)**.

### 1. 18-Language Polyglot CPG Compiler & Dual GraphStore
- **Offline Multi-Language Compilation (Zero JVM):** Compiles **18 languages** (`Python`, `JavaScript`, `TypeScript`, `TSX`, `Java`, `Go`, `Rust`, `C`, `C++`, `C#`, `PHP`, `Ruby`, `Kotlin`, `Swift`, `Scala`, `Dart`, `Solidity`, `SQL`) via `tree-sitter==0.26.1` + `tree-sitter-language-pack==0.13.0` into a unified **AST + CFG + DFG + Inter-Procedural Call Graph (`:CALLS`)**.
- **Dual-Engine `GraphStore` (`Neo4j 5 APOC` + Zero-Docker `SQLite WAL`):** Automatically uses **Neo4j 5 + APOC** when available for large-scale Cypher traversals, and seamlessly falls back to an embedded **SQLite WAL** graph engine (`.alastor_vault/cpg_embedded.db`) so teams can run ALASTOR on any laptop or CI runner without Docker.
- **Hostile-Repo `.gitignore` Scope Walker:** Discovers scannable source files while respecting `.gitignore`, skipping build artifacts/vendored trees, and strictly refusing `.env*`, private key material, `.git/`, hostile agent instruction files, and escaping symlinks or NTFS junctions.
- **Generalized Domain-Aware Sanitizer Tracking:** Eliminates false positives by verifying exact AST sanitizer bodies per vulnerability domain (`commonpath`/`basename`/`is_relative_to` for Path Traversal, `ipaddress` private-IP checks for SSRF, parameterized queries/`int()` coercion for SQLi, CRLF stripping for Log Injection, `SafeLoader`/`defusedxml` for Deserialization & XXE).
- **Deterministic Leiden Community Detection (`COMMUNITY_MAP`):** Partitions large codebases into architectural functional clusters and computes **Best Fix Locations (BFL)** — the highest-leverage chokepoints where a single patch severs multiple attack paths.

### 2. Deterministic Security Rules, Secret Vault, Reachable SCA & CI/CD IaC
- **33 Deterministic SAST & Polyglot Rules (`RULE-1`–`RULE-33`):** Covers OS command injection, code/SSTI injection, SQL/Cypher injection, DOM XSS, path traversal, SSRF, unsafe deserialization, weak crypto, XXE, TLS bypass, open redirect, insecure PRNG, log injection, dead stores, infinite loops, unreachable code, orphan gadgets, plus **12 polyglot rule packs (`RULE-22`–`RULE-33`)** spanning Java, Go, Rust, C/C++, C#, PHP, Ruby, Kotlin, Swift, Scala, Dart, Solidity (reentrancy/tx.origin), and SQL.
- **Native Secret Scanner, Git-History Hunter & Secret Keys Vault:** Detects hardcoded API keys, cloud credentials (`AKIA`, `ghp_`, `sk_`, JWT secrets, PEM private keys) with Shannon entropy scoring, placeholder filtering, git-history scanning, and centralized raw-secret/PEM redaction before any logs, prompts, or reports are written.
- **Live Reachable SCA (`SCA-1`, `SCA-2`) & `CycloneDX v1.5` SBOM:** Audits floating SemVer manifests (`package.json`, `requirements.txt`, lockfiles), queries live **OSV.dev** vulnerability data, cross-checks every CVE against CPG `Import` AST reachability, and exports `CycloneDX v1.5` SBOMs.
- **Infrastructure & CI/CD Pipeline Security (`IAC-1`–`IAC-3` & PBOM):** Audits `Dockerfile` root containers and missing web security headers, `docker-compose.yml` / Kubernetes plaintext secrets, and GitHub Actions workflows (mutable `@v4` tags, `${{ github.event.* }}` script injection, `pull_request_target` abuse) with a full CI/CD Pipeline Bill of Materials (PBOM).

### 3. Cognitive Security Engine — 17 Specialist Playbooks, Multi-Turn ReAct CPG Agent & S6/S8/S11
- **17 Specialist Security Playbooks & 6 Auto-Baselines:** Automatically profiles repository type (Web API, Frontend SPA, Microservice, Smart Contract, CLI/Library, Infrastructure) and runs targeted playbooks covering auth/authz, business logic, multi-tenancy/IDOR, crypto, deserialization, SSRF, injection, file handling, secrets, and supply chain (`COG-1`–`COG-5` deterministic baseline + optional BYOK deep hunting + CPG sibling sweeps).
- **Opt-In Multi-Turn ReAct CPG-Tool-Calling Agent (`v5.1.0`):** Provider-agnostic ReAct loop (`run_agentic_react_hunt`, `run_agentic_react_patch`) with a **`$0` deterministic fallback trace** when no API key is configured. Operates exclusively through **7 strictly confined read-only tools** (`list_repo_files`, `read_code_slice` capped at 120 lines, AST-ReDoS-validated `search_code_regex`, `query_cpg_callers`, `query_cpg_callees`, `get_function_context`, and terminal `submit_findings` / `submit_patch`) with prompt-injection stripping, raw-secret scrubbing, duplicate-call loop detection (`LOOP_DETECTED`), and hallucination filtering.
- **S6 Adversarial Verifier (`FIRST CVSS 3.1`):** Applies deterministic **Exclusion Rules A–F** (test/mock files, dead unreachable paths, verified sanitizers, constant-only sinks, non-exploitable contexts) and calculates standardized **CVSS 3.1** base vectors and scores.
- **S8 Multi-Hop Exploit Chain Synthesis:** Links individual findings (e.g., Information Leak → Auth Bypass → SSRF/SQLi → RCE) into end-to-end composite attack chains ranked by cumulative impact.
- **S11 Dual-Verified 3-Persona Patch Panel & Iterative S10→S11 Auto-Patcher:** Every proposed fix passes **AST syntax validation**, **hostile-patch post-gating** (blocks patches that introduce new sinks/backdoors), **CPG taint-severance verification**, and **3 adversarial reviewer personas** (Security Architect, AppSec Reviewer, Reliability Engineer). In ReAct patch mode, rejected patches iteratively refine across up to 5 rounds using S11 critique feedback.

### 4. IP-Pinned Native `httpx` Live Exploit Verification (`EV`), Post-Fix `ev-replay` & Multi-Role IDOR
- **Zero-Collection CPG Auto-Probing + API Spec Import:** Automatically extracts HTTP routes, parameters, and auth context directly from ALASTOR's CPG, or imports **OpenAPI 3.x**, **Swagger 2.0**, and **Postman v2.1** collections.
- **DNS-Rebinding-Proof IP-Pinned `httpx` Transport:** Resolves DNS once, validates the resolved IP, and pins the socket connection to prevent DNS-rebinding SSRF. Restricts probing to **loopback (`127.0.0.1` / `::1`) by default**, supports explicit opt-in RFC1918/ULA staging networks, and **permanently blocks** public IPs, cloud metadata (`169.254.169.254`), cross-origin redirects, and ALASTOR's own API port (`:8000`).
- **6 Non-Destructive Probe Families & Multi-Role IDOR/BOLA Matrix:** Tests `EV-IDOR-BOLA` (cross-role authorization matrix), `EV-SQLI-ERROR-DIFF`, `EV-XSS-REFLECTED-CANARY`, `EV-CORS-CREDENTIAL-REFLECT`, `EV-OPEN-REDIRECT`, and `EV-PATH-TRAVERSAL-HEADERS` with zero-traffic `DRY_RUN_PLAN` previews before sending any live packet.
- **Fail-Closed Post-Fix `ev-replay` & Credential-Free PoCs:** Replays confirmed probes after a developer patches the bug to attest `FIXED_VERIFIED` vs. `STILL_VULNERABLE`, exports runnable `curl` and `pytest` PoCs (with zero raw credentials), and **automatically promotes** `RUNTIME_EXPLOIT_CONFIRMED` findings to **PASTA Stage VII Mandatory Pre-Go-Live Blockers**.

### 5. Threat Modeling, 7-Stage PASTA, Executive ASPM & Native Word/PDF SAR Dossiers
- **Interactive 4-Zone Directional Trust Boundary Graph & Microsoft STRIDE Matrix:** Visualizes traffic crossing **Zone 1 (External Ingress)** → **Zone 2 (API/CLI Entrypoints)** → **Zone 3 (Validation & BFL Chokepoints)** → **Zone 4 (Critical Sinks & Secrets)** alongside complete STRIDE threat verdicts.
- **7-Stage PASTA Threat Workbench & Attack Trees:** Captures business objectives, technical scope, decomposition, threat analysis, vulnerability mapping, attack trees, and risk/impact analysis with formal **Go-Live Release Gates** (`GO_LIVE_APPROVED`, `CONDITIONAL_GO_LIVE`, `NO_GO_HOLD_RELEASE`) and auditable executive risk waivers.
- **Native Word (`.docx`) & PDF (`.pdf`) SAR Go-Live Dossiers:** Generates board-ready Security Assessment Reports embedding executive summaries, Go-Live gate decisions, PASTA Stage VII blockers, Live EV runtime attestations, compliance posture, and remediation roadmaps — plus Light **Executive HTML (`.html`)**, **RFC-4180 CSV**, **OASIS SARIF `v2.1.0`**, and **CycloneDX `v1.5`** exports.
- **Non-Coder Risk Translator, PMI/COBIT RACI, Multi-Tenant RBAC & Jira/GitHub Sync:** Translates technical CWEs into plain-English business impact, maps organizational accountability in an interactive RACI matrix, manages RBAC roles, and syncs findings bi-directionally with Jira & GitHub Issues.

### 6. Next-Gen AppSec Suite — PR Delta Gate, Regression TestGen, Compliance Autopilot & Microservice Stitching
- **PR / Git-Diff Incremental Security Gate (`alastor pr-gate`):** Diffs `base_ref..head_ref` (or uncommitted `WORKTREE`), classifies findings into `NEWLY_INTRODUCED`, `MODIFIED_CONTEXT` (1-hop CPG neighbors of changed code), and `PRE_EXISTING`, enforces configurable fail-on-severity CI exit codes, and emits copy-ready PR review Markdown.
- **Automated Security Regression Unit-Test Generator:** Deterministically synthesizes AST-verified security regression unit tests in **`pytest`**, **`jest`**, **`vitest`**, or **`go test`** for patched findings, with preview or safe write to `tests/security/`.
- **5-Framework Continuous Compliance Autopilot:** Continuously evaluates live CPG findings, secrets, SCA, and Live EV attestations against **PCI-DSS 4.0**, **SOC 2**, **ISO/IEC 27001:2022**, **HIPAA**, and **OWASP ASVS 5.0** with control-level Pass/Fail/Warning evidence.
- **AST-ReDoS-Safe Custom Rule Studio:** Author, live-test in a sandbox, and persist declarative organization-specific security rules in `.alastor_vault/custom_rules.json` (`0o600`), protected by Python `re._parser` AST catastrophic-backtracking (ReDoS) validation.
- **Cross-Repo Microservice Attack-Graph Stitcher:** Correlates outbound HTTP, gRPC, and Message Queue client calls in one repository to inbound API routes/consumers in sibling repositories and renders end-to-end multi-repo attack paths interactively in ReactFlow.

### 7. Hardened 9-Command `alastor` CLI, Typed Python SDK, Checkpoints, Fleet Runner & 6-Format Fusion
- **Embedded-First 9-Command CLI (`alastor` / `python -m alastor_cli`) & Typed Python SDK (`alastor_sdk`):** Execute `setup`, `doctor`, `estimate`, `scan`, `pr-gate`, `remediate` (report-only or host-provenance-gated `fix`), `validate`, `ev-replay`, and `gc` fully offline or against a running `--server`.
- **SQLite WAL Stage Checkpoints (`--resume`) & Host Provenance:** Persists SHA-256 tamper-checked scan checkpoints per stage so interrupted enterprise scans resume cleanly, enforces host-produced scan provenance before allowing disk writes in `remediate --mode fix`, and provides retention cleanup (`gc`).
- **CSV Multi-Repo Fleet Runner (`--repo-file`, `--group-by-app`):** Scans entire portfolios from a CSV manifest with per-repo fault isolation and rolls up findings into Application-Group Go-Live posture dashboards.
- **Universal 6-Format External Scanner Fusion:** Auto-detects and ingests **SARIF 2.1.0**, **CodeQL**, **Semgrep JSON**, **Trivy JSON**, **Gitleaks JSON** (automatically secret-scrubbed), and **Checkov JSON**, mapping external alerts directly onto ALASTOR's CPG with multi-engine `corroborated_by` confidence boosts.

### 8. Hostile-Repo Isolation, Dual Docker Egress Sandbox, Daylight Web IDE & BYOK Frontier AI
- **Hostile-Repo Isolation Guard (`hostile_repo_guard.py`):** Neutralizes malicious git hooks (`core.hooksPath=/dev/null`), `core.fsmonitor`, `diff.external`, and smudge/clean filters via `GIT_CONFIG_COUNT`, fails closed on `url.*.insteadOf` credential hijacking, refuses target `.env`/config files, and performs symlink/NTFS-junction-safe cleanup.
- **OS-Enforced Dual Docker Egress-Proxy Sandbox (`v5.1.0`):** Ships two hardened non-root (`USER 65534:65534`, setuid/setgid-stripped) local-build images: **`alastor-sandbox:local`** (always runs `--network=none`, `--read-only`, private-key build rejection, `socat` Unix-socket client) and **`alastor-egress:local`** (non-root Squid `CONNECT :443` FQDN allowlist + anti-DNS-rebinding `blocked_dst` CIDR blocklist). `alastor doctor` automatically verifies local image version drift (`org.alastor.version=5.1.0`).
- **Guided 4-Stage WCAG AA Daylight Web IDE & Atomic Batch Auto-Fix:** Crisp light-only high-contrast UI (`>= 4.5:1` across *Olympian Daylight*, *Athena Parchment*, *Hyperborean Frost*), 100% directional perimeter-arrow ReactFlow graphs with Flow Story Bars and BFS Blast Radius, light Monaco Editor + BFL `DiffEditor`, and one-click bottom-up **`Fix All Safe Issues`** with `.alastor_patches` SHA-256 atomic rollback and unified `.patch` export.
- **Token-Efficient BYOK Frontier AI Copilot (`90–95%` Savings):** Zero-SDK adapters for **Google Gemini**, **OpenAI**, **Anthropic Claude**, and **OpenAI-Compatible / OpenRouter / Local Ollama / vLLM** backed by a `0o600` local vault, `<= 40`-line CPG Micro-Slicing, SHA-256 slice caching (`0` repeat tokens), Batch TP/FP Validation, and Monaco Selection Auditing.

---

## 🧠 Sovereign 18-Language CPG, ReAct Agent, Live EV & Dual-Sandbox Architecture

```mermaid
flowchart LR
    subgraph IN["📂 Stage 1: Scan, Fleet, Fusion & PR Gate"]
        GIT["Local • GitHub Public/Private • CSV Fleet\nPR Git-Diff Delta (alastor pr-gate)"]
        FUSE["6-Format Scanner Fusion\nSARIF • CodeQL • Semgrep • Trivy • Gitleaks • Checkov"]
    end

    subgraph COMPILER["⚙️ 18-Language Polyglot CPG + Hostile Guard"]
        P1["Tree-Sitter (18 Langs) • .gitignore Walker\nAST + CFG + DFG + :CALLS + Domain Sanitizers"]
        GRAPH[("Dual GraphStore\nNeo4j 5 APOC  OR  Zero-Docker SQLite WAL\n+ Leiden Communities + SQLite Checkpoints")]
    end

    subgraph ENGINES["🛡️ Cognitive, Live EV, Governance & Next-Gen Engines"]
        DET["33 Deterministic Rules + Secrets + OSV SCA + IaC\n+ ReDoS-Safe Custom Rule Studio"]
        AGENT["17-Lens Playbooks + Multi-Turn ReAct CPG Agent\nS6 CVSS Verifier • S8 Chains • S11 3-Persona Patch Panel"]
        EV["IP-Pinned Live EV + ev-replay + Multi-Role IDOR\ncurl/pytest PoCs • Auto Regression TestGen"]
        GOV["7-Stage PASTA • 5 Compliance Frameworks\nMicroservice Stitcher • Native .docx/.pdf SAR"]
    end

    subgraph EXEC["📦 Delivery Modes"]
        UI["WCAG AA Daylight Web IDE (:3000)"]
        CLI["9-Command alastor CLI + Typed Python SDK"]
        SBX["Dual Docker Sandbox (--network=none + Squid Egress)"]
    end

    GIT --> P1 --> GRAPH
    FUSE --> GRAPH
    GRAPH --> DET & AGENT & EV & GOV
    DET & AGENT & EV & GOV --> UI & CLI & SBX
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

## 🛡️ Complete 33-Rule & Multi-Engine Security Matrix

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
| **`RULE-22`–`RULE-33` (Polyglot Pack)** | `18-Lang CPG` | `CRIT`–`MED` | `CWE-89/78/79/22/918/502/611/327/639/841` | 12 Polyglot Rule Packs spanning **Java, Go, Rust, C/C++, C#, PHP, Ruby, Kotlin, Swift, Scala, Dart, Solidity & SQL** (SQLi, CMDi, unsafe memory/FFI, reentrancy, SSRF, deserialization, XXE, weak crypto, BOLA/IDOR) | Compiled via `tree-sitter-language-pack==0.13.0` with domain-aware sanitizer tracking (zero JVM) |
| **`COG-1`–`COG-5` & `17 Playbooks`** | `Cognitive / ReAct` | `CRIT`–`MED` | Multi-CWE | 17 Specialist Playbooks + Multi-Turn ReAct CPG-Tool-Calling Hunter (`$0` fallback or BYOK) | Grounded to scanned clean files, stripped of prompt injection, verified by S6 (`CVSS 3.1`) |
| **`EV-IDOR` .. `EV-PATH-TRAVERSAL`** | `Live EV (httpx)` | `CRIT`–`HIGH` | `CWE-639/89/79/942/601/22` | 6 Non-Destructive Live HTTP Probe Families + Multi-Role IDOR/BOLA Matrix + Post-Fix `ev-replay` | IP-pinned DNS-rebinding-proof transport; promotes confirmed hits to PASTA Stage VII blockers |

---

## ⚡ 3-Minute Quick Start (100% Local & Sovereign — Web, CLI, Python SDK & Dual Docker Sandbox)

### Prerequisites
- **[Python 3.11+](https://www.python.org/downloads/)** (required for CLI, SDK & FastAPI backend)
- **[Node.js 18+ & npm](https://nodejs.org/)** (for the Daylight Web Studio)
- **[Docker Desktop](https://www.docker.com/products/docker-desktop/)** *(Optional — ALASTOR automatically falls back to **Zero-Docker Embedded SQLite WAL** when Neo4j is stopped, and uses Docker for `Neo4j 5 APOC` or the Dual Egress-Proxy Sandbox)*

### Option A — Web IDE + FastAPI Backend (`http://localhost:3000` & `:8000`)
```bash
git clone https://github.com/ShanjulMittal/alastor-cpg-sast-platform.git
cd alastor-cpg-sast-platform

# (Optional) Start Neo4j 5 + APOC — or skip for Zero-Docker SQLite WAL mode
docker compose up -d neo4j

# Backend (:8000)
python -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
cd backend && python -m uvicorn main:app --host 127.0.0.1 --port 8000

# Frontend (:3000) — in a second terminal
cd frontend && npm ci && npm run build && npm run start
```
Open **`http://localhost:3000`**!

### Option B — Hardened 9-Command Offline-First `alastor` CLI & Typed Python SDK
```bash
cd backend
python -m alastor_cli setup --install-agents          # Readiness check ($0) + AGENTS.md guardrails
python -m alastor_cli doctor --json                   # Python, 18/18 parsers, GraphStore, Git, Docker images
python -m alastor_cli estimate --repo /path/to/repo   # $0 scope, LOC, language & token preview
python -m alastor_cli scan --repo /path/to/repo --resume --fusion-report semgrep.json --format sarif --out ./out
python -m alastor_cli scan --repo-file fleet.csv --group-by-app
python -m alastor_cli pr-gate --repo /path/to/repo --base main --head HEAD --out-md pr_review.md
python -m alastor_cli remediate --repo /path/to/repo --mode report-only
python -m alastor_cli validate --repo /path/to/repo
python -m alastor_cli ev-replay --repo /path/to/repo --target-url http://127.0.0.1:5000
python -m alastor_cli gc --older-than-days 30 --dry-run
```
```python
from alastor_sdk import ScanOptions, scan, pr_gate, agentic_hunt

result = scan(ScanOptions(repo="/path/to/repo", resume=True, fusion_reports=["semgrep.json"]))
gate = pr_gate("/path/to/repo", base_ref="main", head_ref="HEAD")
hunt = agentic_hunt("/path/to/repo", max_turns=8, use_byok_llm=False)
```

### Option C — OS-Enforced Dual Docker Egress-Proxy Sandbox (`v5.1.0`)
```bash
# Build both hardened non-root (UID 65534) images locally from repo root
docker build -f docker/sandbox/Dockerfile --build-arg ALASTOR_IMAGE_VERSION=5.1.0 -t alastor-sandbox:local .
docker build -f docker/sandbox/egress.Dockerfile --build-arg ALASTOR_IMAGE_VERSION=5.1.0 -t alastor-egress:local .

# Generate a networkless (--network=none) or mediated Squid FQDN egress plan
cd backend
python -m alastor_cli scan --repo /path/to/repo --sandbox --egress mediated --allow-llm-host api.openai.com --json
```

---

## 🧪 Zero-Trust Proof: 533 Automated Tests + Live Self-Audit

```powershell
# 1. Run the complete 533-test backend pytest suite (All 5 Pillars + v5.1 ReAct & Sandbox)
cd backend
..\.venv\Scripts\python.exe -m pytest -q

# 2. Type-check & build the Light-Only Daylight Next.js frontend
cd ..\frontend
npx tsc --noEmit && npm run build
```

Expected result:
```text
533 passed in ~140s
TSC_EXIT=0 • Next.js build passed • 0 dark: classes • 0 DOM XSS sinks
```

---

## 📤 Standards-Compliant Enterprise Exports & `v5.1.0` REST APIs

| Export / API Endpoint | Standard / Capability | Use Case |
| :--- | :--- | :--- |
| `POST /api/cognitive/hunt`, `/verify`, `/chains`, `/validate-patch`, `/agentic-hunt`, `/agentic-patch` | **17-Lens + Multi-Turn ReAct CPG Agent, S6/S8/S11** | `$0` or BYOK semantic hunting, multi-turn CPG tool calling, CVSS 3.1 verification, exploit chains & 3-persona patch validation |
| `POST /api/ev/plan`, `/run`, `/replay` & `GET/DELETE /api/ev/replays` | **IP-Pinned Live EV + `ev-replay` + Multi-Role IDOR** | Non-destructive live API verification, `curl`/`pytest` PoCs & PASTA Stage VII blocker auto-promotion |
| `GET /api/aspm/pasta` & `GET /api/export/sar-report?format=docx\|pdf\|json` | **7-Stage PASTA & Native Word/PDF SAR Dossiers** | Board-ready Security Assessment Reports with Go-Live release gates & runtime EV attestation |
| `GET /api/fleet/doctor`, `POST /api/fleet/estimate`, `/run`, `/gc`, `/sandbox-plan`, `GET /api/fleet/checkpoints`, `POST /api/fusion/import` | **Fleet Runner, Checkpoints, 6-Format Fusion & Sandbox** | Multi-repo CSV fleet scans, `--resume` SQLite checkpoints, SARIF/CodeQL/Semgrep/Trivy/Gitleaks/Checkov fusion & mediated Docker sandbox plans |
| `POST /api/nextgen/pr-gate`, `/generate-test`, `/compliance/evaluate`, `/custom-rules/*`, `/microservice-graph` | **PR Delta Gate, TestGen, 5-Framework Compliance & Stitcher** | Incremental PR merge gates, `pytest`/`jest`/`vitest`/`go test` generation, PCI/SOC2/ISO/HIPAA/ASVS attestation, ReDoS-safe custom rules & multi-repo microservice attack graphs |
| `GET / POST /api/ai/config` & `/api/ai/validate-findings` / `/audit-code-selection` / `/synthesize-patch` | **Zero-Leak `0o600` BYOK Frontier AI Vault** | `Gemini`, `OpenAI`, `Anthropic`, `Ollama` with `90–95%` CPG micro-slice token savings & SHA-256 cache |
| `POST /api/remediate/batch-apply`, `/preview`, `/apply`, `/undo` | **Atomic Bottom-Up Batch Auto-Fix & Undo** | AST-verified patching with `.alastor_patches` SHA-256 backups, `.patch` export & CPG severance re-scan |
| `GET /api/export/sarif` & `GET /api/sast-plus` | **OASIS SARIF `v2.1.0` & CycloneDX `v1.5`** | GitHub Advanced Security upload & EO 14028 SBOM attestations |

---

## 📋 Release History

| Version | Date | Key Milestones |
| :--- | :---: | :--- |
| **`v5.1.0`** | **2026-11-23** | **Multi-Turn ReAct CPG-Tool-Calling Agentic Hunter & Iterative S10→S11 Auto-Patcher (`agentic_react_loop.py`) + OS-Enforced Dual Docker Egress-Proxy Sandbox (`alastor-sandbox:local` `--network=none` + `alastor-egress:local` non-root Squid ACL/anti-rebinding sidecar + `doctor` image drift checks); `533/533` backend pytest tests passing.** |
| **`v5.0.0`** | **2026-11-23** | **5-Pillar Enterprise Evolution: 18-Language Polyglot CPG + Zero-Docker SQLite WAL GraphStore + Leiden Communities (`RULE-22..33`), 17-Lens Cognitive Playbooks + S6/S8/S11 Patch Panel, IP-Pinned Live EV + `ev-replay` + Multi-Role IDOR + PASTA 7-Stage & `.docx`/`.pdf` SAR Dossiers, Hostile-Repo Isolation + SQLite `--resume` Checkpoints + 6-Format Scanner Fusion + CSV Fleet Runner + 9-Command `alastor` CLI/SDK, PR Delta Gate (`alastor pr-gate`), Automated `pytest`/`jest`/`vitest`/`go test` Generator, 5-Framework Compliance Autopilot + AST-ReDoS-Safe Custom Rule Studio & Cross-Repo Microservice Attack-Graph Stitching.** |
| **`v4.0.0`** | 2026-11-11 | 100% Directional CPG/360°/Trust-Boundary Flow Graphs, Guided 4-Stage High-Contrast WCAG AA Daylight UI, One-Click Atomic `"Fix All Safe Issues"` Batch Auto-Patcher, and Token-Efficient Multi-Provider BYOK Frontier AI Copilot (`90–95%` Micro-Slice savings). |
| **`v3.0.0`** | 2026-11-10 | Studio IDE Overhaul, Live BFL `"Sever the Thread"` Auto-Patcher (`preview`/`apply`/`undo`), 3 New Zero-FP CPG Rules (`RULE-14`–`RULE-16`), CPG-Backed Zero-FP Web Intel Engine, and `O(1)` UNWIND Neo4j Batch Ingestion. |
| **`v2.6.2`** | 2026-10-27 | 1-Click GitHub Repository Scanner (`Open / Public` Paste-URL-Only + `Private` PAT via ephemeral `GIT_CONFIG_*` HTTP headers) & pre-flight `POST /api/github/verify-repo`. |
| **`v2.6.1`** | 2026-10-25 | AST-Verified Inter-Procedural Sanitizer Summary Engine (`0%` FP on custom helpers), `for`-loop iterator taint, and 100% Semgrep Pro & OSS `0`-finding parity. |
| **`v2.6.0`** | 2026-10-25 | Live `OSV.dev` Lockfile CVE + CPG Import Reachability (`SCA-2`), GitHub Actions CI/CD Scanner (`IAC-3`), and Inter-Procedural Route Taint (`RULE-10`–`RULE-13`). |
| **`v2.5.0`** | 2026-10-22 | STRIDE Count & Observation Matrix, Secret Keys Vault, Rule Engine Profiles, Multi-Tenant RBAC, Call Graph (`:CALLS`), Entrypoints Graph, and 360° Spider Map. |
| **`v2.0.0`–`v1.0.0`** | 2026-10-19 | `SAST++++++` ASPM Suite, `EPSS v4`, `RACI` Matrix, `CycloneDX v1.5` SBOM, Tree-Sitter `AST + CFG + DFG` Neo4j CPG compiler, and `SARIF v2.1.0`. |

---

## 📚 Documentation, Contributing & Security

- **[📖 Complete Master SOP & Application Handbook (`docs/ALASTOR_Master_SOP_and_Product_Guide.md`)](./docs/ALASTOR_Master_SOP_and_Product_Guide.md)** — Comprehensive end-to-end Standard Operating Procedure written for **both non-technical stakeholders** (plain-English mental model, business value, executive Go-Live gates, SAR dossiers, RACI & glossary) **and technical engineers** (architecture, 18-language CPG, 14 step-by-step SOPs, CLI/SDK, REST APIs, Live EV, ReAct Agent & Dual Docker Egress Sandbox).
- **[📋 Full Changelog (`CHANGELOG.md`)](./CHANGELOG.md)** — Detailed version-by-version engineering notes (`v1.0.0` through `v5.1.0`).
- **[📐 Architecture Specs & Plans (`docs/superpowers/`)](./docs/superpowers/)** — Detailed design specifications for PASTA, Pillars 1–5, and v5.1.
- **[🔬 Contributing Guide (`CONTRIBUTING.md`)](./CONTRIBUTING.md)** — How to add new Tree-Sitter languages, CPG rules, and run the 533-test suite.
- **[🛡️ Security Policy (`SECURITY.md`)](./SECURITY.md)** — Responsible disclosure guidelines, hostile-repo isolation guarantees, and sandbox security model.

---

<div align="center">

### ⭐ Star ALASTOR on GitHub if you believe Compiler-Grade Code Security should be Open, Deterministic, Readable & Sovereign!

Released under the **[MIT License](./LICENSE)** • Built with **Tree-Sitter**, **Neo4j + APOC**, **FastAPI**, **Next.js**, **Monaco Editor**, and **ReactFlow**.

</div>
