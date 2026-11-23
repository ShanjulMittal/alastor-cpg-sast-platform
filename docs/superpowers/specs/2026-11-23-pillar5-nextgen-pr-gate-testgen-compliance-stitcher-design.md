# ALASTOR v5.0 Pillar 5 Design Specification — PR Delta Security Gate, Automated Security Regression Unit-Test Generator, Continuous Compliance Autopilot + Custom Rule Studio & Cross-Repo Microservice Attack-Graph Stitching

**Date:** 2026-11-23  
**Status:** Approved — Executing via Subagent-Driven Development  
**Roadmap Context:** Pillar 5 of 5 (Grand Finale — Pure 300% Next-Gen AppSec beyond both VVAH and ALASTOR v4.0)  
**Target Codebase:** `cpg-sast-platform` (`backend/` FastAPI + Dual Neo4j/SQLite CPG Engine, `frontend/` Next.js + ReactFlow + Zustand Daylight UI)

---

## 1. Executive Summary & Goals

Pillar 5 completes **ALASTOR v5.0** with four `$0`-token deterministic-first Next-Gen AppSec capabilities:
1. **PR / Git-Diff Incremental Security Gate (`backend/engine/pr_delta_gate.py`):** Uses hardened host git (`run_hardened_git`) with strict git-ref validation to extract exact changed files and added/modified line hunks between `base_ref..head_ref`, walks 1-hop CPG call-graph neighbors for blast-radius awareness, classifies findings into **`NEWLY_INTRODUCED`**, **`MODIFIED_CONTEXT`**, and **`PRE_EXISTING`**, enforces merge-gate policy (`PASS` vs `BLOCK_MERGE`), outputs GitHub/GitLab PR review Markdown + inline annotations, and powers **`alastor pr-gate`** + `POST /api/nextgen/pr-gate`.
2. **Automated Security Regression Unit-Test Generator (`backend/engine/security_test_generator.py`):** Deterministically synthesizes runnable, zero-raw-secret security regression unit tests across **`pytest` (Python)**, **`jest`/`vitest` (JavaScript/TypeScript)**, and **`go test` (Go)**, validates generated Python tests with `ast.parse`, scrubs all text through `scrub_raw_secrets_text`, and supports preview-only OR strictly confined workspace write (`tests/security/test_alastor_<slug>.*`) with symlink/junction and overwrite protection.
3. **Continuous Compliance Autopilot + Custom Rule Studio (`backend/engine/compliance_and_rules_engine.py`):**
   - Evaluates live findings, EV runtime attestations, and SBOM posture across **5 enterprise compliance frameworks** (**PCI-DSS 4.0**, **SOC 2**, **ISO/IEC 27001:2022**, **HIPAA**, **OWASP ASVS 5.0**) into per-framework compliance scores (`0..100%`) and per-control `PASS`/`WARNING`/`FAIL` evidence rows.
   - Provides a **Custom Rule Studio** backed by atomic `.alastor_vault/custom_rules.json` (`0o700`/`0o600`) with full CRUD, **ReDoS safety validation** (rejecting catastrophic nested quantifiers, backreferences, lookarounds with quantifiers, and `> 400`-char regexes), live **Test-Rule Sandbox** (sample snippet or confined workspace), and automatic evaluation of enabled custom rules.
4. **Cross-Repo Microservice Attack-Graph Stitching (`backend/engine/microservice_stitcher.py`):** Extracts outbound HTTP/gRPC/queue calls and inbound API routes/consumers across 2+ confined repositories alongside per-service findings, stitches cross-service edges (`Service A caller` -> `Service B route`), discovers **multi-repo cross-service attack paths** with composite severity & hop count, and outputs ReactFlow-ready `nodes` + `edges` + attack paths.
5. **Confined `/api/nextgen/*` APIs, CLI/SDK Extensions & Unified Light-Only Daylight UI:** 9 workspace-confined FastAPI routes in `backend/main.py`, `alastor pr-gate` in `backend/alastor_cli.py`, 4 new SDK functions in `backend/alastor_sdk.py`, a Light-Only Daylight **`NextGenAppSecStudio.tsx`** mounted as a dedicated **`Next-Gen AppSec (v5)`** tab inside `ExecutiveAspmWorkspace.tsx`, and a 1-click **`Generate Security Test`** panel directly inside **`FrontierAiCopilotDrawer.tsx`**.

---

## 2. Architecture & Security Boundaries

### 2.1 PR Delta Security Gate (`pr_delta_gate.py`)
- **Ref Validation:** `validate_git_ref(ref: str)` rejects empty strings, leading `-`, C0/DEL control chars, whitespace, `..` range injection inside a single ref, `@{`, `~`/`^` abuse? (allow standard `HEAD~1`, `main`, `origin/main`, commit SHAs, branch/tag names matching `^[A-Za-z0-9._/~^@/-]{1,128}$` without leading `-`, `..`, `//`, `@{`, `\`, or trailing `.lock`).
- **Hardened Diff:** Calls `run_hardened_git(repo_path, ["diff", "--unified=0", "--no-renames", f"{base_ref}..{head_ref}"])` (or working-tree diff vs `base_ref` if `head_ref == "WORKTREE"`), parsing `+++ b/<path>` and `@@ -a,b +c,d @@` hunks into `Dict[str, Set[int]]` of added/modified lines.
- **Finding Classification:**
  - `NEWLY_INTRODUCED`: finding file is in `changed_files` AND (its line falls inside `added_lines[file]` +/- 2 lines OR file was newly added).
  - `MODIFIED_CONTEXT`: finding file is in `changed_files` (outside added lines) OR file is a 1-hop CPG call-graph neighbor of a changed function.
  - `PRE_EXISTING`: all other findings.
- **Merge Gate Decision:** `BLOCK_MERGE` if any `NEWLY_INTRODUCED` finding meets/exceeds `fail_on_new_severity` (default `"HIGH"`), OR (`block_on_new_secrets=True` and any new secret finding), OR (`block_on_new_ev_confirmed=True` and any new `RUNTIME_EXPLOIT_CONFIRMED` finding); otherwise `PASS`.

### 2.2 Automated Security Regression Unit-Test Generator (`security_test_generator.py`)
- Supports frameworks: `"pytest"`, `"jest"`, `"vitest"`, `"go_test"` (plus `"auto"` detection from finding filepath extension + repo manifest files).
- Templates tailored by CWE/vulnerability family (`CWE-89` SQLi, `CWE-78` Command Injection, `CWE-79` XSS, `CWE-22` Path Traversal, `CWE-918` SSRF, `CWE-639`/`IDOR`, `CWE-502` Deserialization, `CWE-798` Hardcoded Secrets, `CWE-942` CORS, plus generic CWE assertion fallback).
- **Safety Invariants:**
  - Scrubs all interpolated finding metadata via `scrub_raw_secrets_text` BEFORE code generation (never embeds raw secret values!).
  - Validates Python output with `ast.parse(code)` (`syntax_valid: bool`).
  - Optional `write_to_workspace=True` writes ONLY inside `<real_repo>/tests/security/` (or Go package `*_security_test.go` inside confined repo dir), verifying `commonpath`, zero symlinks/junctions on every ancestor/leaf, safe sanitized filename (`[a-z0-9_]`), and refusing overwrite unless `overwrite=True`.

### 2.3 Continuous Compliance Autopilot & Custom Rule Studio (`compliance_and_rules_engine.py`)
- **5 Frameworks (`PCI_DSS_4_0`, `SOC2`, `ISO_27001`, `HIPAA`, `OWASP_ASVS_5_0`):** Each framework declares 5–7 concrete controls with `control_id`, `title`, `mapped_cwes`, `mapped_rule_prefixes`, `requires_no_ev_confirmed`, and `requires_clean_sca`.
- **Custom Rule ReDoS Guard (`validate_custom_rule_regex`):**
  - Max pattern length `400` chars; rejects backreferences (`\1`..`\9`, `(?P=...)`), catastrophic nested quantifiers (`(\w+)+`, `(a*)*`, `(a+)*`, `(.*a){n}`), and compiles with `re.compile` catching `re.error`.
  - Runs line-by-line (capped at 10,000 lines/file, 2,000 chars/line) with optional `anti_pattern` suppression (also ReDoS-validated!).
- **Atomic Vault Persistence:** `.alastor_vault/custom_rules.json` with `threading.Lock`, PID/TID temp file + `flush` + `os.fsync` + `os.replace`, `0o700`/`0o600`.

### 2.4 Cross-Repo Microservice Attack-Graph Stitching (`microservice_stitcher.py`)
- Accepts 2+ confined local repo specs (`service_name`, `repo_path`, optional `base_url_hint`).
- Extracts:
  - **Inbound Routes:** FastAPI/Flask (`@app.get`/`@router.post`), Django (`path(...)`), Express/Next.js (`app.get`, `router.post`), Spring (`@GetMapping`/`@RequestMapping`), Go (`HandleFunc`/`r.GET`), gRPC (`rpc ...`), Queue consumers (`@kafka_listener`, `subscribe(...)`).
  - **Outbound Calls:** `requests.*`, `httpx.*`, `fetch(...)`, `axios.*`, `http.Get`/`http.Post`, `RestTemplate`/`WebClient`, gRPC client calls, queue publish calls (`producer.send`, `publish(...)`).
- Normalizes URL/path templates (`/api/orders/{id}` == `/api/orders/:id` == `/api/orders/${orderId}` -> `/api/orders/:param`) and matches outbound service/path hints to inbound routes across distinct services, attaching per-service findings to build **Cross-Service Attack Paths** + ReactFlow `nodes` & `edges`!

### 2.5 REST APIs, CLI/SDK & Daylight UI
- **9 Confined FastAPI Routes (`backend/main.py`):** `/api/nextgen/pr-gate`, `/api/nextgen/generate-test`, `/api/nextgen/compliance/evaluate`, `/api/nextgen/custom-rules` (`GET`/`POST`), `/api/nextgen/custom-rules/{rule_id}` (`PUT`/`DELETE`), `/api/nextgen/custom-rules/test`, `/api/nextgen/microservice-graph`.
- **Daylight UI:** `NextGenAppSecStudio.tsx` mounted as `NEXTGEN_V5` tab in `ExecutiveAspmWorkspace.tsx` + 1-click **Generate Security Test** section in `FrontierAiCopilotDrawer.tsx`, strictly `#f8fafc`/`#ffffff` WCAG AA `>= 4.5:1`, zero `dark:` classes, zero DOM XSS sinks, `_nextgenEpoch`-guarded Zustand slice.
