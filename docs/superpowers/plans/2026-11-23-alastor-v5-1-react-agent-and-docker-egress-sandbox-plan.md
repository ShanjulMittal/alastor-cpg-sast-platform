# ALASTOR v5.1 — Multi-Turn ReAct CPG-Tool-Calling Agentic Hunter/Patcher & Dual Docker Egress-Proxy Sandbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close the final two edges versus VVAH v1.6.0 by shipping (1) an opt-in multi-turn ReAct CPG-tool-calling agentic hunter & iterative S10→S11 auto-patcher (`agentic_react_loop.py`) and (2) hardened dual Docker egress-proxy sandbox images (`docker/sandbox/Dockerfile`, `docker/sandbox/egress.Dockerfile`) + Squid ACL/mediated-egress orchestrator (`sandbox_orchestrator.py`) with `doctor` image-version drift checks, APIs, CLI/SDK, and Daylight UI controls.

**Tech Stack:** Python 3.12, Pydantic v2, FastAPI, `click`, Dockerfiles (`python:3.12-slim`, `ubuntu:24.04` + `squid`/`socat`), Next.js 15 / React 19, TypeScript, Zustand, Tailwind CSS (Light-Only Daylight WCAG AA `>= 4.5:1`).

## Global Constraints
- **Work on `main` only** in `c:\Projects\Securecodereview\cpg-sast-platform`; preserve all 511 existing backend tests.
- **Strict Tool & Sandbox Security:** ReAct tools read ONLY `PolyglotScopeWalker` scanned clean files (zero `.env`/private keys/symlink escapes), apply `strip_hostile_target_instructions` + `scrub_raw_secrets_text`, validate search regexes via `validate_custom_rule_regex`, and enforce `max_turns`/`max_tool_calls`/duplicate-call guards. Squid egress allowlists reject cloud metadata, private/loopback/link-local IPs, wildcards, and CRLF/Squid-config injection.
- **Light-Only Daylight UI (`>= 4.5:1` WCAG AA):** Strictly `#f8fafc` / `#ffffff`, zero `dark:` classes, zero DOM XSS sinks, epoch-guarded Zustand actions.
- **Zero Production Self-Audit Findings:** Never touch or stage `.superpowers/` or `synthetic_test_target/.vvaharness/`. Stage explicit paths only.

---

### Task 1: v5.1 Models (`models.py`), Multi-Turn ReAct CPG Agent (`agentic_react_loop.py`) & TDD Suite
**Files:**
- Modify: `backend/models.py`
- Create: `backend/engine/agentic_react_loop.py`
- Create: `backend/tests/test_agentic_react_loop.py`
- [ ] **Step 1–5 (TDD):** Add Section 19 v5.1 models (`AgenticTraceStep`, `AgenticHuntRequest`, `AgenticHuntResponse`, `AgenticPatchRequest`, `AgenticPatchResponse`, `SandboxImageInfo`, `SandboxImageStatus`, `SandboxPlanRequest`, `SandboxExecutionPlan`); implement the 7 confined read-only CPG/code tools, bounded multi-turn `run_agentic_react_hunt` (with deterministic `$0` fallback + mocked multi-turn BYOK tool-calling tests + S6 verification) and `run_agentic_react_patch` (iterative S10→S11 feedback loop up to 3 rounds) -> verify GREEN -> commit.

---

### Task 2: Dual Docker Egress-Proxy Sandbox Images (`docker/sandbox/`), `sandbox_orchestrator.py`, Confined APIs & CLI/SDK Wiring + TDD Suite
**Files:**
- Create: `docker/sandbox/Dockerfile`
- Create: `docker/sandbox/egress.Dockerfile`
- Create: `docker/sandbox/ca/.gitkeep`
- Create: `backend/engine/sandbox_orchestrator.py`
- Modify: `backend/alastor_sdk.py`
- Modify: `backend/alastor_cli.py`
- Modify: `backend/main.py`
- Create: `backend/tests/test_sandbox_orchestrator_and_v51_api.py`
- [ ] **Step 1–5 (TDD):** Author hardened `docker/sandbox/Dockerfile` & `docker/sandbox/egress.Dockerfile`; implement `generate_squid_egress_config`, `build_mediated_sandbox_plan`, `inspect_sandbox_images`; wire into `alastor_sdk.doctor()` / `alastor_sdk.agentic_hunt()` / `alastor_sdk.agentic_patch()` / `alastor_sdk.build_sandbox_plan()`, CLI `alastor scan --sandbox --egress none|mediated --allow-llm-host ...`, and 3 confined FastAPI routes (`POST /api/cognitive/agentic-hunt`, `POST /api/cognitive/agentic-patch`, `POST /api/fleet/sandbox-plan`) -> verify GREEN -> commit.

---

### Task 3: Light-Only Daylight UI Wiring (`CognitiveSecurityWorkbench.tsx`, `FrontierAiCopilotDrawer.tsx`, `FleetCommandWorkbench.tsx` + TS/API/Store)
**Files:**
- Modify: `frontend/src/types/cpg.ts`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/store/useAuditStore.ts`
- Modify: `frontend/src/components/CognitiveSecurityWorkbench.tsx`
- Modify: `frontend/src/components/FrontierAiCopilotDrawer.tsx`
- Modify: `frontend/src/components/FleetCommandWorkbench.tsx`
- [ ] **Step 1–4:** Add 1-to-1 Section 19 TS types, 3 API helpers, epoch-guarded Zustand actions, add Multi-Turn ReAct CPG Hunt + Trace viewer in `CognitiveSecurityWorkbench.tsx`, Iterative ReAct S10→S11 Auto-Patch button in `FrontierAiCopilotDrawer.tsx`, and Mediated-Egress Docker Sandbox Plan generator & image drift badges in `FleetCommandWorkbench.tsx`; verify `npx tsc --noEmit`, `npm run build`, `0` `dark:`/DOM-XSS, and full `pytest -q`, then commit.
