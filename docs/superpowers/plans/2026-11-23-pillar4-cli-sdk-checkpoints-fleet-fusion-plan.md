# ALASTOR v5.0 Pillar 4 — Hardened `alastor` CLI + SDK, SQLite Stage Checkpoints (`--resume`), CSV Fleet Runner, Universal 6-Format Scanner Fusion, Hostile-Repo Isolation & Daylight Fleet Hub Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver Hostile-Repo Isolation, SQLite WAL Stage Checkpoints (`--resume` + host-provenance + `gc`), Universal 6-Format Scanner Fusion (SARIF 2.1.0, Semgrep, CodeQL, Trivy, Gitleaks, Checkov into ALASTOR CPG), CSV Multi-Repo Batch Fleet Runner (`--repo-file`, `--group-by-app`), Embedded-First Hardened `alastor` CLI (8 commands) + Typed Python SDK, 8 confined `/api/fleet/*` & `/api/fusion/*` FastAPI endpoints, and a Light-Only Daylight `FleetCommandWorkbench.tsx` mounted in `ProjectsHubView.tsx`.

**Architecture:** 4 decoupled backend engine/storage modules (`hostile_repo_guard.py`, `checkpoint_store.py`, `scanner_fusion_engine.py`, `fleet_runner.py`) unified by `alastor_sdk.py` and exposed identically through `alastor_cli.py` (embedded-first + optional `--server` mode) and `main.py` REST routes, with a Daylight UI workbench tab inside `ProjectsHubView.tsx`.

**Tech Stack:** Python 3.12, `click`, `httpx==0.27.2`, `sqlite3` (WAL), Pydantic v2, FastAPI, Next.js 15 / React 19, TypeScript, Zustand, Tailwind CSS (Light-Only Daylight WCAG AA `>= 4.5:1`).

## Global Constraints

- **Work on `main` only** in `c:\Projects\Securecodereview\cpg-sast-platform`; preserve all 286 existing backend tests.
- **Hostile-Repo Safety:** Never execute target git hooks, `core.fsmonitor`, `core.sshCommand`, `filter.*`, or `diff.*` drivers; refuse target `.env`/`.alastor.yaml`/`config.yaml`; restrict clone URLs to `http`/`https`/`ssh` (no `file://`, `ext::`, leading `-`); never follow symlinks on workspace cleanup.
- **Strict SQLite & Secret Safety:** 100% parameterized `?` queries in `checkpoint_store.py`; `0o700`/`0o600` vault permissions; scrub every imported scanner finding (especially Gitleaks/Trivy secrets) through `scrub_raw_secrets_text` before storage or return; never echo API keys or tokens in `doctor` / CLI / API responses.
- **Light-Only Daylight UI (`>= 4.5:1` WCAG AA):** Strictly `#f8fafc` / `#ffffff`, zero `dark:` classes, zero DOM XSS sinks, `_fleetEpoch`-guarded Zustand actions.
- **Zero Production Self-Audit Findings:** Never touch or stage `.superpowers/` or `synthetic_test_target/.vvaharness/`. Stage explicit paths only.

---

### Task 1: Pillar 4 Models (`models.py`), Hostile-Repo Isolation (`hostile_repo_guard.py`) & SQLite Stage Checkpoints (`checkpoint_store.py`) + TDD Suite

**Files:**
- Modify: `backend/models.py`
- Create: `backend/engine/hostile_repo_guard.py`
- Create: `backend/database/checkpoint_store.py`
- Create: `backend/tests/test_hostile_guard_and_checkpoints.py`

**Interfaces:**
- Produces in `backend/models.py`:
  - Optional `source_engine: Optional[str] = None` and `corroborated_by: List[str] = Field(default_factory=list)` on `Finding`.
  - Section 17 Pillar 4 models: `DoctorCheckItem`, `DoctorReport`, `EstimateReport`, `StageCheckpointItem`, `ScanRunCheckpointSummary`, `ScannerFusionRequest`, `ScannerFusionResponse`, `FleetRepoSpec`, `FleetRepoResult`, `FleetAppGroupRollup`, `FleetRunRequest`, `FleetRunResponse`, `FleetRunListResponse`, `GcRequest`, `GcReport`.
- Produces in `backend/engine/hostile_repo_guard.py`:
  - `HostileRepoError`, `HardenedGitCommand`, `build_hardened_git_env_and_argv`, `run_hardened_git`, `assert_safe_config_source`, `validate_clone_url`, `safe_cleanup_workspace`, `build_sandbox_docker_command`.
- Produces in `backend/database/checkpoint_store.py`:
  - `CheckpointStore(vault_dir: str)` with `create_or_get_run`, `save_stage`, `get_stage`, `list_runs`, `get_run`, `mark_run_status`, `verify_host_provenance`, `save_fleet_run`, `list_fleet_runs`, `gc`.

- [ ] **Step 1–5 (TDD):** Write failing tests covering hostile git config driver neutralization (`core.fsmonitor`, `core.hooksPath`, `filter.*.smudge`, `diff.*.textconv`), target `.env`/`config.yaml` refusal, clone URL scheme validation (`file://`/`ext::`/`-` blocked, `https`/`ssh` allowed), symlink-escape-proof cleanup, Docker sandbox argv, SQLite WAL checkpoint round-trip + SHA-256 tamper rejection + `--resume` stage reuse + host provenance validation + `gc` -> implement -> verify GREEN -> commit.

---

### Task 2: Universal 6-Format Scanner Fusion (`scanner_fusion_engine.py`) & CSV Batch Fleet Runner (`fleet_runner.py`) + TDD Suite

**Files:**
- Create: `backend/engine/scanner_fusion_engine.py`
- Create: `backend/engine/fleet_runner.py`
- Create: `backend/tests/test_scanner_fusion_and_fleet.py`

**Interfaces:**
- Produces in `backend/engine/scanner_fusion_engine.py`:
  - `detect_scanner_format(payload: Any) -> str`
  - `parse_external_scanner_report(report_json: str, source_format: Optional[str] = None, repo_root: Optional[str] = None) -> Tuple[str, List[Finding]]`
  - `fuse_findings_with_cpg(imported: List[Finding], native_findings: List[Finding], graph_store: Optional[Any] = None, project_path: Optional[str] = None, run_s6_verify: bool = False) -> ScannerFusionResponse`
- Produces in `backend/engine/fleet_runner.py`:
  - `parse_fleet_csv(csv_text: str) -> List[FleetRepoSpec]`
  - `FleetRunner(vault_dir: str, checkpoint_store: CheckpointStore, workspace_confinement_fn=None)`:
    - `run_fleet(req: FleetRunRequest) -> FleetRunResponse` (supports `repo_specs`, `csv_content`, `group_by_app`, `resume`, per-repo isolation, persisted rollups).

- [ ] **Step 1–5 (TDD):** Write failing tests covering all 6 scanner formats (SARIF 2.1.0, CodeQL SARIF, Semgrep JSON, Trivy JSON, Gitleaks JSON with strict raw-secret scrubbing, Checkov JSON), CPG enrichment + native deduplication (`corroborated_by`), S6 verification pass-through, CSV fleet manifest parsing (rejecting unsafe clone URLs / traversal), `--group-by-app` Go-Live rollups, and `--resume` skipping completed stages -> implement -> verify GREEN -> commit.

---

### Task 3: Embedded-First Hardened `alastor` CLI (`alastor_cli.py`), Typed Python SDK (`alastor_sdk.py`), `pyproject.toml` & 8 Confined `/api/fleet/*` + `/api/fusion/*` FastAPI Routes + TDD Suite

**Files:**
- Create: `backend/alastor_sdk.py`
- Create: `backend/alastor_cli.py`
- Create: `backend/pyproject.toml`
- Modify: `backend/main.py`
- Create: `backend/tests/test_cli_sdk_and_fleet_api.py`

**Interfaces:**
- Produces in `backend/alastor_sdk.py`: `ScanOptions`, `FleetOptions`, `ScanResult`, `doctor()`, `estimate()`, `scan()`, `run_fleet()`, `inject_findings()`, `fuse_scanner_report()`, `remediate()`, `validate()`, `ev_replay()`, `gc()`.
- Produces in `backend/alastor_cli.py`: `click` CLI `alastor` with all 8 commands (`setup`, `doctor`, `estimate`, `scan`, `remediate`, `validate`, `ev-replay`, `gc`), `--server` remote mode, `--json`, deterministic exit codes (`0`/`1`/`2`).
- Produces in `backend/main.py`: 8 workspace-confined endpoints (`GET /api/fleet/doctor`, `POST /api/fleet/estimate`, `POST /api/fusion/import`, `POST /api/fleet/run`, `GET /api/fleet/runs`, `GET /api/fleet/checkpoints`, `POST /api/fleet/checkpoints/{run_id}/resume`, `POST /api/fleet/gc`).

- [ ] **Step 1–5 (TDD):** Write failing tests covering all 8 CLI commands via `click.testing.CliRunner` (including `setup --install-agents`, `doctor --json`, `estimate`, `scan --resume --fusion-report --stop-after`, `remediate --mode fix` host-provenance rejection for forged findings vs allowed for local checkpoint, `validate`, `ev-replay`, `gc --dry-run`), SDK `inject_findings`/`scan`/`run_fleet`, and all 8 FastAPI `/api/fleet/*` + `/api/fusion/*` routes (including HTTP `400` on path traversal & hostile targets) -> implement -> verify GREEN -> commit.

---

### Task 4: Light-Only Daylight `FleetCommandWorkbench.tsx`, `ProjectsHubView.tsx` Tab & Store/API Wiring

**Files:**
- Modify: `frontend/src/types/cpg.ts`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/store/useAuditStore.ts`
- Create: `frontend/src/components/FleetCommandWorkbench.tsx`
- Modify: `frontend/src/components/ProjectsHubView.tsx`

- [ ] **Step 1–4:** Add 1-to-1 TypeScript interfaces, 8 API helpers, `_fleetEpoch`-guarded Zustand slice/actions, build Light-Only Daylight `FleetCommandWorkbench.tsx` (System Doctor & Hardening Posture card, `$0` Scope Estimator, Universal 6-Format Scanner Import & CPG Fusion dropzone/paste panel, CSV Fleet Manifest Runner + App-Group Go-Live Rollup Table, SQLite Stage Checkpoints with 1-click Resume, and Vault `GC` panel), mount as 2nd sub-tab in `ProjectsHubView.tsx`, verify `npx tsc --noEmit` (`0` errors) + `npm run build` + `0` `dark:` / DOM-XSS findings + full `pytest -q`, and commit.
