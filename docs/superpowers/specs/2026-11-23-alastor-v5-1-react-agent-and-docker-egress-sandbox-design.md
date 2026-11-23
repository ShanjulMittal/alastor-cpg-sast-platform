# ALASTOR v5.1 Design Specification — Multi-Turn ReAct CPG-Tool-Calling Agentic Hunter/Patcher & Dual Docker Egress-Proxy Sandbox

**Date:** 2026-11-23  
**Status:** Approved — Executing via Subagent-Driven Development  
**Target Codebase:** `cpg-sast-platform` (`backend/`, `docker/sandbox/`, `frontend/`)

---

## 1. Executive Summary & Goals

ALASTOR v5.1 closes the final two architectural gaps between ALASTOR v5.0 and VVAH v1.6.0 so ALASTOR achieves **100.0% VVAH parity + 300% beyond** with zero caveats:
1. **Opt-In Multi-Turn ReAct CPG-Tool-Calling Agentic Hunter & Iterative Patcher (`backend/engine/agentic_react_loop.py`):**
   - Built natively on ALASTOR's provider-agnostic `FrontierAiEngine.dispatch_structured_json(...)` with a deterministic `\$0` offline fallback trace when no BYOK API key is configured.
   - Exposes **7 read-only sandboxed CPG & code investigation tools** (`list_repo_files`, `read_code_slice`, `search_code_regex`, `query_cpg_callers`, `query_cpg_callees`, `get_function_context`, plus terminal `submit_findings` / `submit_patch`) strictly confined to `PolyglotScopeWalker` scanned clean files — never reading `.env`, private keys, or symlink/junction escapes — with prompt-injection stripping (`strip_hostile_target_instructions`), ReDoS AST regex validation (`validate_custom_rule_regex`), and raw-secret scrubbing (`scrub_raw_secrets_text`) on every observation.
   - Strict anti-loop budgets: `max_turns <= 20`, `max_tool_calls <= 40`, duplicate tool-call detection, and full auditable redacted tool trace (`AgenticTraceStep[]`).
   - Supports **Deep Multi-Turn Hunt (`run_agentic_react_hunt`)** feeding grounded findings into S6 Adversarial Verifier AND **Iterative S10→S11 Auto-Patcher (`run_agentic_react_patch`)** feeding S11 rejection rationale back into up to 3 refinement rounds.
2. **Dual Docker Egress-Proxy Sandbox Images & Mediated-Egress Orchestrator (`docker/sandbox/` + `backend/engine/sandbox_orchestrator.py`):**
   - Ships two hardened local-build Dockerfiles: `docker/sandbox/Dockerfile` (`alastor-sandbox:local` with private-key-rejecting CA stage, pinned `git` system hardening, setuid/setgid strip, `LABEL org.alastor.version="5.1.0"`, `USER 65534:65534`) and `docker/sandbox/egress.Dockerfile` (`alastor-egress:local` minimal `ubuntu:24.04` with `squid` + `socat`, setuid/setgid strip, `LABEL org.alastor.version="5.1.0"`, `USER 65534:65534`).
   - Generates deny-by-default Squid ACL configs (`generate_squid_egress_config`) allowing `CONNECT` strictly to port `443` on validated public LLM API domains (blocking cloud metadata IPs, RFC1918/ULA/loopback IPs, wildcards, and CRLF/Squid-directive injection).
   - Builds complete single-container (`egress_mode="none"`) and dual-container Unix-socket-bridged (`egress_mode="mediated"`, scanner runs `--network=none` at kernel level!) execution plans (`build_mediated_sandbox_plan`), integrates Docker image presence & version-drift checks (`inspect_sandbox_images`) into `alastor doctor` / `GET /api/fleet/doctor`, adds `alastor scan --sandbox --egress mediated --allow-llm-host ...`, exposes `POST /api/cognitive/agentic-hunt`, `POST /api/cognitive/agentic-patch`, and `POST /api/fleet/sandbox-plan`, and integrates cleanly into ALASTOR's Light-Only Daylight UI (`CognitiveSecurityWorkbench.tsx`, `FrontierAiCopilotDrawer.tsx`, `FleetCommandWorkbench.tsx`).
