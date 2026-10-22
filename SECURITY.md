# Security Policy & Responsible Disclosure (ALASTOR v2.5.0)

## Dogfooding & Self-Audit Guarantee (`0 Unpatched Findings`)

**ALASTOR v2.5.0** continuously audits its own backend (`FastAPI` / `Python`) and frontend (`Next.js` / `TypeScript`) via **Assertion P** in [`verify_harness.py`](./verify_harness.py), enforcing **0 unpatched findings** across SAST (`RULE-1` through `RULE-9`), Secret Keys Hunter (`RULE-8-HARDCODED-SECRET`), SCA (`SCA-1-MANIFEST-AUDIT`), and IaC (`IAC-1-COMPOSE-SECRET`, `IAC-2-CONTAINER-ROOT`) on every release.

## Supported Versions

| Version | Supported | Status |
| :--- | :--- | :--- |
| **`2.5.x`** | ✅ Yes | Current Enterprise Release (STRIDE Observation Matrix, Secret Vault, Rule Profiles, Multi-Tenant RBAC, Call/Entrypoint Graphs) |
| **`2.0.x`** | ✅ Yes | SAST++++++ ASPM Release |
| **`1.0.x`** | ⚠️ Security Fixes Only | Initial Core CPG Release |

## Reporting a Vulnerability

If you discover a security vulnerability or false-negative bypass in ALASTOR:
1. Please open a **GitHub Security Advisory** on this repository or submit an issue with a minimal reproducible code snippet (which can also be added to `synthetic_test_target/`).
2. Include the expected CPG path (`AST` / `CFG` / `DFG` / `CALL_GRAPH`), STRIDE category, CWE identifier, and suggested remediation pattern.
