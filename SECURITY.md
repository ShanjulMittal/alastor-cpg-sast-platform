# Security Policy & Responsible Disclosure

## Dogfooding & Self-Audit Guarantee (`0 Unpatched Findings`)

**ALASTOR** continuously audits its own backend (`FastAPI` / `Python`) and frontend (`Next.js` / `TypeScript`) via **Assertion P** in [`verify_harness.py`](./verify_harness.py), enforcing **0 unpatched findings** across SAST, SCA, and IaC on every release.

## Reporting a Vulnerability

If you discover a security vulnerability or false-negative bypass in ALASTOR:
1. Please open a **GitHub Security Advisory** on this repository or submit an issue with a minimal reproducible code snippet (which can also be added to `synthetic_test_target/`).
2. Include the expected CPG path (`AST` / `CFG` / `DFG`), CWE identifier, and suggested remediation pattern.
