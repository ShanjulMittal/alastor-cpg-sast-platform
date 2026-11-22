# ALASTOR v5.0 Pillar 3 Design Specification — Native `httpx` Live Exploit Verification (`EV`), Post-Fix `ev-replay`, Multi-Role IDOR/BOLA Probing & PASTA/SAR Blocker Promotion

**Date:** 2026-11-22  
**Status:** Approved — Executing via Subagent-Driven Development  
**Roadmap Context:** Pillar 3 of 5 in the ALASTOR v5.0 ("100% VVAH Parity + 300% Beyond") architecture evolution  
**Target Codebase:** `cpg-sast-platform` (`backend/` FastAPI + Dual Neo4j/SQLite CPG Engine, `frontend/` Next.js + ReactFlow + Monaco + Zustand)

---

## 1. Executive Summary & Goals

Pillar 3 delivers **100% of VVAH's Live Exploit Verification (`EV`) and post-fix `ev-replay`** capabilities and extends **300% beyond VVAH** with:
1. **Zero-Collection Auto-Probing + OpenAPI/Postman Import:** Discovers target API routes automatically from ALASTOR's CPG-backed `ApiOperationsReportResponse` AND parses uploaded/pasted **OpenAPI 3.x / Swagger 2.0** or **Postman v2.1** JSON collections.
2. **Hardened Loopback-First Safety Policy:** Restricts live HTTP traffic to DNS-verified loopback (`localhost`/`127.0.0.1`/`[::1]`) by default, supports an explicit opt-in RFC1918 staging host allowlist (`allow_private_staging_host=True` + `authorized_staging_hosts`), and **permanently blocks** public internet IPs, cloud metadata IPs (`169.254.169.254`, `100.100.100.200`, link-local), embedded URL credentials, HTTP redirects (`follow_redirects=False`), and ALASTOR's own backend port (`:8000` self-attack guard). Requires explicit `armed=True` (otherwise runs in zero-traffic `DRY_RUN_PLAN` mode) and defaults `safe_mode=True`.
3. **6 Non-Destructive Deterministic Probe Families + Multi-Role IDOR/BOLA Matrix (`$0` tokens):**
   - `EV-IDOR-BOLA`: Multi-role matrix comparing `User A` credentials against `User B`'s resource ID vs. unauthenticated baseline.
   - `EV-SQLI-ERROR-DIFF`: Non-destructive SQL syntax/boolean differential canaries.
   - `EV-XSS-REFLECTED-CANARY`: Harmless unique canary checking unescaped reflection in `text/html`.
   - `EV-CORS-CREDENTIAL-REFLECT`: External `Origin` reflection with `Access-Control-Allow-Credentials: true`.
   - `EV-OPEN-REDIRECT`: External `Location` header check with redirects disabled.
   - `EV-PATH-TRAVERSAL-HEADERS`: Safe path-traversal probe markers and missing security headers (`CSP`, `HSTS`, `X-Content-Type-Options`, cookie `HttpOnly`/`Secure`).
4. **Atomic Persisted `ev-replay` Bundles & Runnable `curl`/`pytest` PoC Export:** Stores confirmed probe records in `.alastor_vault/ev_replays.json` (`0o600`, stripping raw auth/Cookie headers to `<USER_A_TOKEN>` placeholders), supports 1-click post-fix `ev-replay` (`FIXED_VERIFIED` vs. `STILL_VULNERABLE`), and generates copy-ready `curl` + `pytest` (`httpx`) regression scripts with zero raw credentials.
5. **Active DAST-to-CPG Correlation & PASTA/SAR Blocker Promotion:** Tags confirmed findings `ev_status="RUNTIME_EXPLOIT_CONFIRMED"`, automatically promotes them to **Mandatory Pre-Go-Live Blockers** in PASTA Stage VII (`pasta_threat_engine.py`), renders runtime verification evidence in Section 6 of `.docx`/`.pdf` SAR Dossiers (`sar_report_generator.py`), and exposes a Light-Only Daylight **Live EV & Replay Console** (`LiveExploitVerificationConsole.tsx`) inside `ThreatModelingView.tsx`.

---

## 2. Architecture & Security Boundaries

### 2.1 Target Egress Validator (`validate_ev_target_url`)
- Accepts `http://` or `https://` URLs only; rejects CR/LF/NUL/whitespace and embedded `user:pass@` credentials.
- Resolves every DNS record via `socket.getaddrinfo(host, port)` (handling literal IPv4/IPv6 directly) and validates every resolved IP via `ipaddress.ip_address`:
  - **Permanently forbidden:** `ip.is_link_local`, `ip.is_multicast`, `ip.is_unspecified`, `169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`, and any global/public IP (`not ip.is_loopback and not ip.is_private`).
  - **Default (`allow_private_staging_host=False`):** EVERY resolved IP MUST satisfy `ip.is_loopback`.
  - **Staging opt-in (`allow_private_staging_host=True`):** Host must appear in `authorized_staging_hosts` (normalized lowercase) AND every resolved IP MUST be `ip.is_loopback or ip.is_private` (RFC1918 only, never link-local/cloud metadata!).
  - **Self-Attack Guard:** Rejects loopback targets whose port equals `int(os.environ.get("ALASTOR_SELF_PORT", "8000"))` unless a custom ASGI test transport is explicitly injected in Python unit tests.

### 2.2 Vault Redaction & Replay Storage (`.alastor_vault/ev_replays.json`)
- Thread-safe atomic persistence (`PID/TID` temp file + `flush` + `os.fsync` + `os.replace`, `0o700` dir / `0o600` file).
- Every sensitive header (`Authorization`, `Cookie`, `X-API-Key`, `X-Auth-Token`) is masked to `<USER_A_TOKEN>` / `<REDACTED_HEADER>` before storing on disk, returning in API JSON, or embedding in generated `curl` / `pytest` PoC scripts. Response excerpts are capped at 600 chars and scrubbed via `scrub_raw_secrets_text(...)`.

### 2.3 PASTA Stage VII & SAR `.docx`/`.pdf` Blocker Promotion
- `Finding` gains optional `ev_status: Optional[Literal["RUNTIME_EXPLOIT_CONFIRMED", "FIXED_VERIFIED", "NOT_REPRODUCED", "DRY_RUN_PLANNED"]] = None` and `ev_evidence_summary: Optional[str] = None`.
- In `PastaThreatEngine._classify_default_finding_gate(finding)`: if `finding.ev_status == "RUNTIME_EXPLOIT_CONFIRMED"`, ALWAYS classify as `MANDATORY_PRE_GO_LIVE` (`PRE_LAUNCH`) regardless of original static severity (`MEDIUM`/`LOW` promoted automatically!), with explicit rationale citing live runtime proof.
- In `sar_report_generator.py`: surface `RUNTIME CONFIRMED` / `FIXED VERIFIED` evidence badges in Section 6 (Mandatory Pre-Go-Live Blockers) and include `ev_replays` summary inside `SarReportBundle` (strictly scrubbed through `sanitize_bundle_for_export`).

### 2.4 REST API & Daylight UI
- **5 Confined FastAPI Routes (`backend/main.py`):**
  - `POST /api/ev/plan` (`EvRunRequest` -> `EvPlanResponse`) — zero network traffic; parses OpenAPI/Postman + CPG routes and returns planned probes.
  - `POST /api/ev/run` (`EvRunRequest` -> `EvRunResponse`) — requires `armed=True` + valid target URL; runs probes, persists confirmed bundles, correlates with active findings.
  - `POST /api/ev/replay` (`EvReplayRequest` -> `EvReplayResponse`) — replays persisted confirmed bundles (`FIXED_VERIFIED` vs `STILL_VULNERABLE`).
  - `GET /api/ev/replays?project_path=...` -> `EvReplayListResponse`
  - `DELETE /api/ev/replays/{replay_id}?project_path=...` -> `{"deleted": True, "replay_id": ...}`
- **Light-Only Daylight UI (`frontend/src/components/LiveExploitVerificationConsole.tsx`):** Mounted as the 4th sub-tab inside `ThreatModelingView.tsx` (`STRIDE` | `PASTA 7-Stage & Attack Trees` | `Cognitive Hunt & Chains` | `Live EV & Replay Console`), strictly `#f8fafc`/`#ffffff` WCAG AA `>= 4.5:1`, zero `dark:` classes.
