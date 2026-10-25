# Security Policy & Responsible Disclosure (ALASTOR v2.6.1)

## Dogfooding & Self-Audit Guarantee (`0 Unpatched Findings`)

**ALASTOR v2.6.1** continuously audits its own backend (`FastAPI` / `Python`), frontend (`Next.js` / `TypeScript`), dependency lockfiles (`package-lock.json` / `requirements.txt`), and GitHub Actions workflows (`.github/workflows/`) via **Assertion P** in [`verify_harness.py`](./verify_harness.py), enforcing **0 unpatched findings** across all **18 built-in rules**: SAST (`RULE-1` through `RULE-13` with AST-Verified Inter-Procedural Sanitizer Summaries), Secret Keys & Cloud Token Hunter (`RULE-8-HARDCODED-SECRET`), Live OSV.dev Lockfile CVE & CPG Reachability (`SCA-1-MANIFEST-AUDIT`, `SCA-2-LIVE-CVE-LOCKFILE`), and IaC / CI/CD (`IAC-1-COMPOSE-SECRET`, `IAC-2-CONTAINER-ROOT`, `IAC-3-CICD-WORKFLOW-SECURITY`) on every release.

## Supported Versions

| Version | Supported | Status |
| :--- | :--- | :--- |
| **`2.6.x`** | ✅ Yes | Current Enterprise Release (Semgrep-Superiority Multi-Engine, Live OSV CVE Reachability, Inter-Procedural Route Taint, CI/CD Security, Zero-CVE Stack) |
| **`2.5.x`** | ✅ Yes | Enterprise Shell, STRIDE Observation Matrix, Secret Vault, Rule Profiles, Multi-Tenant RBAC, Call/Entrypoint Graphs |
| **`2.0.x`** | ✅ Yes | SAST++++++ ASPM Release |
| **`1.0.x`** | ⚠️ Security Fixes Only | Initial Core CPG Release |

## Reporting a Vulnerability

If you discover a security vulnerability or false-negative bypass in ALASTOR:
1. Please open a **GitHub Security Advisory** on this repository or submit an issue with a minimal reproducible code snippet (which can also be added to `synthetic_test_target/`).
2. Include the expected CPG path (`AST` / `CFG` / `DFG` / `CALL_GRAPH`), STRIDE category, CWE identifier, and suggested remediation pattern.
