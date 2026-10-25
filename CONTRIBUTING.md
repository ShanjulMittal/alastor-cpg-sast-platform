# Contributing to ALASTOR (`Ἀλάστωρ`) v2.6.1 — Guide for Security Researchers

Thank you for contributing to **ALASTOR v2.6.1**, the open-source Deterministic Code Property Graph (CPG), SAST, Live OSV SCA, CI/CD & IaC, STRIDE Threat Modeling & ASPM Security Platform! We welcome contributions from security researchers, compiler engineers, vulnerability hunters, and AppSec practitioners.

---

## 🔬 How Security Researchers Can Contribute

1. **New CPG Cypher & AST Security Rules (`SAST` & `Secret Keys Hunter`)**
   - Add new inter-procedural taint sources, sanitizers, or sinks in [`backend/compiler/ast_parser.py`](./backend/compiler/ast_parser.py), [`backend/engine/rule_executor.py`](./backend/engine/rule_executor.py), and [`backend/compiler/dfg_builder.py`](./backend/compiler/dfg_builder.py).
   - Add new graph-structural queries beyond the built-in `RULE-1-TAINT` through `RULE-13-UNSAFE-DESERIALIZATION-CRYPTO` (e.g., prototype pollution, IDOR/broken access control, GraphQL batch abuse).
2. **Inter-Procedural Call Graph & Reachability Analysis**
   - Enhance `:CALLS` resolution in [`backend/compiler/call_graph_builder.py`](./backend/compiler/call_graph_builder.py) and live OSV transitive dependency reachability proofs in [`backend/engine/osv_lockfile_scanner.py`](./backend/engine/osv_lockfile_scanner.py).
3. **STRIDE Threat Modeling & File-Anchored Observation Signatures**
   - Extend the 6-category Microsoft STRIDE engine and `StrideObservationItem` generators in [`backend/engine/enterprise_manager.py`](./backend/engine/enterprise_manager.py) (`get_sast_plus_suite`).
4. **SCA Supply-Chain & IaC Hardening Rules**
   - Expand manifest/lockfile parsers (`Cargo.lock`, `go.mod`, `pom.xml`, `Gemfile.lock`, `composer.lock`) and Kubernetes/Terraform/Dockerfile/GitHub Actions/Next.js header rules.
5. **Automated Remediation Code Diffs (`Before` vs. `After`)**
   - Contribute deterministic AST/line-level autofix templates in `compute_best_fix_location()` so every new rule includes a ready-to-copy secure code patch.

---

## 🧪 Mandatory Verification Gate (`verify_harness.py`)

Every Pull Request **must** pass all 18 deterministic assertions (`Assertion A` through `Assertion S`) in [`verify_harness.py`](./verify_harness.py), including **Assertion S** (100% True Positive detection + 0% False Positives across sanitized negative tests) and **Assertion P** (full self-audit of `cpg-sast-platform` with **0 findings**):

```bash
# 1. Start Neo4j + APOC container
docker compose up -d neo4j

# 2. Run the autonomous 18-assertion verification suite
.venv/Scripts/python.exe verify_harness.py
```

### Self-Audit Cleanliness Rules (`Assertion P`)
Because ALASTOR scans its own codebase during `Assertion P`:
- Do **not** leave unused local variables in Python/TypeScript functions (triggers `RULE-3-DEADSTORE`).
- Do **not** use `subprocess.*(..., shell=True)` (triggers `RULE-6-SHELL-INJECTION`).
- Do **not** assign hardcoded string literals to variable names containing `secret`, `password`, `api_key`, or `token` (triggers `RULE-8-HARDCODED-SECRET`).
- Pin exact versions in `frontend/package.json` and `backend/requirements.txt` (triggers `SCA-1-MANIFEST-AUDIT`).

---

## 📖 Documentation

Before submitting major UI or engine changes, please review the [Master Product Guide & Standard Operating Procedure (SOP)](./docs/ALASTOR_Master_SOP_and_Product_Guide.md) and [CHANGELOG.md](./CHANGELOG.md).
