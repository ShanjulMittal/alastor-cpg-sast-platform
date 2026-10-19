# Contributing to ALASTOR (`Ἀλάστωρ`) — Guide for Security Researchers

Thank you for contributing to **ALASTOR**, the open-source Deterministic Code Property Graph (CPG), SAST, SCA, IaC & ASPM Security Platform! We welcome contributions from security researchers, compiler engineers, vulnerability hunters, and AppSec practitioners.

---

## 🔬 How Security Researchers Can Contribute

1. **New CPG Cypher & AST Security Rules (`SAST`)**
   - Add new inter-procedural taint sources, sanitizers, or sinks in [`backend/engine/scanner.py`](./backend/engine/scanner.py) and [`backend/compiler/cpg_builder.py`](./backend/compiler/cpg_builder.py).
   - Add new graph-structural queries (e.g., race conditions, SSRF, insecure deserialization, prototype pollution, IDOR/broken access control).
2. **Call-Graph Reachability & Exploitability Heuristics**
   - Enhance entrypoint-to-sink and transitive dependency reachability analysis in [`backend/engine/enterprise_manager.py`](./backend/engine/enterprise_manager.py) (`populate_plain_english_and_raci`).
3. **SCA Supply-Chain & IaC Hardening Rules**
   - Expand manifest/lockfile parsers (`Cargo.lock`, `go.mod`, `pom.xml`, `Gemfile.lock`, `composer.lock`) and Kubernetes/Terraform/Dockerfile rules.
4. **Automated Remediation Code Diffs (`Before` vs. `After`)**
   - Contribute deterministic AST/line-level autofix templates in `compute_best_fix_location()` so every new rule includes a ready-to-copy secure code patch.
5. **STRIDE Threat Modeling & CI/CD PBOM Checks**
   - Add new architectural threat signatures and pipeline verification rules in `get_sast_plus_suite()`.

---

## 🧪 Mandatory Verification Gate (`verify_harness.py`)

Every Pull Request **must** pass all 17 deterministic assertions in [`verify_harness.py`](./verify_harness.py), including **Assertion P** (full self-audit of `cpg-sast-platform` with **0 findings**):

```bash
# 1. Start Neo4j + APOC container
docker compose up -d neo4j

# 2. Run the autonomous 17-assertion verification suite
.venv/Scripts/python.exe verify_harness.py
```

### Self-Audit Cleanliness Rules (`Assertion P`)
Because ALASTOR scans its own codebase during `Assertion P`:
- Do **not** leave unused local variables in Python/TypeScript functions (triggers `RULE-3-DEADSTORE`).
- Do **not** use `subprocess.*(..., shell=True)` (triggers `RULE-6-SHELL-INJECTION`).
- Pin exact versions in `frontend/package.json` and `backend/requirements.txt` (triggers `SCA-1-MANIFEST-AUDIT`).

---

## 📖 Documentation

Before submitting major UI or engine changes, please review the [Master Product Guide & Standard Operating Procedure (SOP)](./docs/ALASTOR_Master_SOP_and_Product_Guide.md).
