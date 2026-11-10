# Security Policy & Responsible Disclosure (ALASTOR v3.0.0)

## Dogfooding & Self-Audit Guarantee (`0 Unpatched Findings`)

**ALASTOR v3.0.0** continuously audits its own backend (`FastAPI` / `Python`), frontend (`Next.js` / `TypeScript`), dependency lockfiles (`package-lock.json` / `requirements.txt`), and GitHub Actions workflows (`.github/workflows/`) via **Assertion P** in [`verify_harness.py`](./verify_harness.py), enforcing **0 unpatched findings** across all **21 built-in rules**:
- **SAST (`RULE-1` through `RULE-16`)**: Inter-Procedural Taint, Dormant Gadgets, Dead Stores, Infinite Loops, Unreachable Code, Shell Injection, Sanitizer-Aware SQL/Cypher Injection, Hardcoded Secrets, DOM XSS, Path Traversal, SSRF, Log Injection, Unsafe Deserialization/Weak Crypto, Dynamic Code/SSTI Injection (`RULE-14`), XXE/TLS Bypass (`RULE-15`), and Weak PRNG/Open Redirect (`RULE-16`) — backed by AST-Verified Inter-Procedural Sanitizer Summaries (`0%` FP).
- **Live OSV.dev Lockfile CVE & CPG Reachability (`SCA-1-MANIFEST-AUDIT`, `SCA-2-LIVE-CVE-LOCKFILE`)** and **CPG-Backed Zero-FP Web Intel**.
- **IaC / CI/CD (`IAC-1-COMPOSE-SECRET`, `IAC-2-CONTAINER-ROOT`, `IAC-3-CICD-WORKFLOW-SECURITY`)**.

## Supported Versions

| Version | Supported | Status |
| :--- | :---: | :--- |
| **`3.0.x`** | ✅ Yes | **Current Studio Enterprise Release** (2-Bar Studio IDE, 5-Pillar Composite Workspaces, Live BFL `"Sever the Thread"` Auto-Patcher with SHA-256 Undo, 21-Rule Matrix, CPG-Backed Zero-FP Web Intel, `20/20` Self-Audit Pass) |
| **`2.6.x`** | ✅ Yes | Public/Private GitHub Repo Scanner, AST-Verified Sanitizers, Live OSV CVE Reachability, CI/CD Security |
| **`2.5.x`** | ⚠️ Security Fixes Only | Enterprise Shell, STRIDE Observation Matrix, Secret Vault, Rule Profiles, Multi-Tenant RBAC |
| **`2.0.x` / `1.0.x`** | ❌ End of Life | Upgrade to `v3.0.0` |

## Reporting a Vulnerability

If you discover a security vulnerability or false-negative bypass in ALASTOR:
1. Please open a **GitHub Security Advisory** on this repository or submit an issue with a minimal reproducible code snippet (which can also be added to `synthetic_test_target/`).
2. Include the expected CPG path (`AST` / `CFG` / `DFG` / `CALL_GRAPH`), STRIDE category, CWE identifier, and suggested BFL remediation pattern.
