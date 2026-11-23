# ALASTOR v5.0 Pillar 5 — PR Delta Security Gate, Security Regression Unit-Test Generator, Compliance Autopilot + Custom Rule Studio & Cross-Repo Microservice Attack-Graph Stitching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver ALASTOR v5.0 Pillar 5 (Pure 300% Next-Gen AppSec): PR/Git-Diff Incremental Security Gate (`pr_delta_gate.py` + `alastor pr-gate`), Automated Security Regression Unit-Test Generator (`security_test_generator.py` for `pytest`/`jest`/`vitest`/`go test`), Continuous Compliance Autopilot (PCI-DSS 4.0, SOC 2, ISO 27001, HIPAA, OWASP ASVS 5.0) + ReDoS-safe Custom Rule Studio (`compliance_and_rules_engine.py`), Cross-Repo Microservice Attack-Graph Stitching (`microservice_stitcher.py`), 9 confined `/api/nextgen/*` endpoints, and Light-Only Daylight `NextGenAppSecStudio.tsx` + `FrontierAiCopilotDrawer.tsx` test-gen integration.

**Architecture:** 4 decoupled `$0` deterministic engines under `backend/engine/`, Section 18 Pydantic v2 models in `backend/models.py`, unified SDK/CLI bindings in `alastor_sdk.py`/`alastor_cli.py`, 9 workspace-confined routes in `backend/main.py`, and Light-Only Daylight UI mounted in `ExecutiveAspmWorkspace.tsx` + `FrontierAiCopilotDrawer.tsx`.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, `click`, Next.js 15 / React 19, TypeScript, Zustand, `reactflow` `11.11.4`, Tailwind CSS (Light-Only Daylight WCAG AA `>= 4.5:1`).

## Global Constraints

- **Work on `main` only** in `c:\Projects\Securecodereview\cpg-sast-platform`; preserve all 371 existing backend tests.
- **Hostile-Repo & ReDoS Safety:** Validate git refs strictly & execute git ONLY via `run_hardened_git`; enforce ReDoS validation on every custom rule regex (`<= 400` chars, no nested quantifiers/backreferences); confine every workspace file read/write with symlink/junction checks; scrub all secrets via `scrub_raw_secrets_text`.
- **Light-Only Daylight UI (`>= 4.5:1` WCAG AA):** Strictly `#f8fafc` / `#ffffff`, zero `dark:` classes, zero DOM XSS sinks, `_nextgenEpoch`-guarded Zustand slice, module-scoped `nodeTypes`/`edgeTypes` inside `<ReactFlowProvider>`.
- **Zero Production Self-Audit Findings:** Never touch or stage `.superpowers/` or `synthetic_test_target/.vvaharness/`. Stage explicit paths only.

---

### Task 1: Pillar 5 Models (`models.py`), PR Delta Gate (`pr_delta_gate.py`) & Security Regression Test Generator (`security_test_generator.py`) + TDD Suite

**Files:**
- Modify: `backend/models.py`
- Create: `backend/engine/pr_delta_gate.py`
- Create: `backend/engine/security_test_generator.py`
- Create: `backend/tests/test_pr_gate_and_test_generator.py`

- [ ] **Step 1–5 (TDD):** Add Section 18 Pillar 5 models in `backend/models.py`; write failing tests covering git-ref injection blocks, real multi-commit temp git repo PR diff separating `NEWLY_INTRODUCED` vs `PRE_EXISTING` findings + `BLOCK_MERGE`/`PASS` + PR Markdown & annotations, and `pytest` (`ast.parse`-verified)/`jest`/`vitest`/`go_test` regression test generation + zero raw secret leakage + safe confined write/no-overwrite -> implement -> verify GREEN -> commit.

---

### Task 2: Continuous Compliance Autopilot + Custom Rule Studio (`compliance_and_rules_engine.py`) & Cross-Repo Microservice Attack-Graph Stitcher (`microservice_stitcher.py`) + TDD Suite

**Files:**
- Create: `backend/engine/compliance_and_rules_engine.py`
- Create: `backend/engine/microservice_stitcher.py`
- Create: `backend/tests/test_compliance_rules_and_microservice_stitcher.py`

- [ ] **Step 1–5 (TDD):** Write failing tests covering all 5 compliance frameworks (PCI-DSS 4.0, SOC 2, ISO 27001, HIPAA, OWASP ASVS 5.0), Custom Rule CRUD atomic vault persistence (`0o600`), ReDoS regex rejection (`(a+)+`, backreferences, oversized patterns), live custom rule sandbox testing + anti-pattern suppression, and Cross-Repo Microservice Attack-Graph stitching across 2+ temp services (`api-gateway` -> `billing-service` HTTP/queue chain + ReactFlow nodes/edges + multi-repo attack paths) -> implement -> verify GREEN -> commit.

---

### Task 3: 9 Confined `/api/nextgen/*` FastAPI Routes (`main.py`), CLI `alastor pr-gate` (`alastor_cli.py`) & SDK (`alastor_sdk.py`) + TDD Suite

**Files:**
- Modify: `backend/alastor_sdk.py`
- Modify: `backend/alastor_cli.py`
- Modify: `backend/main.py`
- Create: `backend/tests/test_nextgen_api_and_cli.py`

- [ ] **Step 1–5 (TDD):** Write failing tests covering all 9 confined `/api/nextgen/*` routes (including HTTP `400` on path traversal, bad git refs, ReDoS regexes, and symlink escapes), `alastor pr-gate` CLI exit codes (`0`/`1`/`2`), and SDK wrappers -> implement -> verify GREEN -> commit.

---

### Task 4: Light-Only Daylight `NextGenAppSecStudio.tsx`, `ExecutiveAspmWorkspace.tsx` Tab, `FrontierAiCopilotDrawer.tsx` Test-Gen Integration & Store/API Wiring

**Files:**
- Modify: `frontend/src/types/cpg.ts`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/store/useAuditStore.ts`
- Create: `frontend/src/components/NextGenAppSecStudio.tsx`
- Modify: `frontend/src/components/ExecutiveAspmWorkspace.tsx`
- Modify: `frontend/src/components/FrontierAiCopilotDrawer.tsx`

- [ ] **Step 1–4:** Add 1-to-1 TypeScript interfaces, 9 API helpers, `_nextgenEpoch`-guarded Zustand slice/actions, build Light-Only Daylight `NextGenAppSecStudio.tsx` (4 sub-views: PR Delta Gate, Continuous Compliance Autopilot, Custom Rule Studio + Live Sandbox, and Cross-Repo Microservice Attack Graph inside `<ReactFlowProvider>`), mount as `NEXTGEN_V5` tab in `ExecutiveAspmWorkspace.tsx`, add 1-click **Generate Security Test** panel inside `FrontierAiCopilotDrawer.tsx`, verify `npx tsc --noEmit` (`0` errors) + `npm run build` + `0` `dark:` / DOM-XSS findings + full `pytest -q`, and commit.
