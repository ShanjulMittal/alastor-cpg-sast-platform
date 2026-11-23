# ALASTOR v5.0 Pillar 4 Design Specification — Hardened `alastor` CLI + Typed Python SDK, SQLite Stage Checkpoints (`--resume`), CSV Batch Fleet Runner, Universal 6-Format Scanner Fusion, Hostile-Repo Isolation & Daylight Fleet Command Dashboard

**Date:** 2026-11-23  
**Status:** Approved — Executing via Subagent-Driven Development  
**Roadmap Context:** Pillar 4 of 5 in the ALASTOR v5.0 ("100% VVAH Parity + 300% Beyond") architecture evolution  
**Target Codebase:** `cpg-sast-platform` (`backend/` FastAPI + Dual Neo4j/SQLite CPG Engine, `frontend/` Next.js + Zustand + Tailwind Daylight UI)

---

## 1. Executive Summary & Goals

Pillar 4 delivers **100% of VVAH v1.6.0's CLI, SDK, operational resilience, batch runner, and hostile-repo hardening** capabilities and extends **300% beyond VVAH** with:
1. **Hostile-Repo Isolation (`backend/engine/hostile_repo_guard.py`):** Hardened host `git` execution (`GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n` neutralizing `core.fsmonitor`, `core.hooksPath=/dev/null`, `core.sshCommand=false`, `diff.external=""`, and every `filter.*.(clean|smudge|process|required)` and `diff.*.(textconv|command)`), refusal to load `.env`/`.alastor.yaml`/`config.yaml` inside target repos, strict remote clone URL scheme validation (`http`/`https`/`ssh` only, blocking `file://`, `ext::`, leading `-` flags, CRLF/NUL), symlink-escape-safe workspace cleanup, and an opt-in Docker egress sandbox command builder (`--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--network=none` or explicit endpoint allowlist, `:ro` repo mount).
2. **SQLite WAL Stage Checkpoints & Provenance (`backend/database/checkpoint_store.py`):** Parameterized SQLite WAL persistence (`.alastor_vault/checkpoints.db`, `0o700`/`0o600`, `threading.Lock`) tracking runs (`run_id`, `repo_path`, `commit_sha`, `app_group`, `status`) and stage checkpoints (`S0_CPG`..`S11_VALIDATE`, `EV_VERIFY`) with SHA-256 payload digests for deterministic `--resume`, host-produced scan provenance validation for `alastor remediate --mode fix`, and symlink-safe garbage collection (`gc`).
3. **Universal 6-Format Scanner Fusion (`backend/engine/scanner_fusion_engine.py`):** Auto-detects and normalizes **SARIF 2.1.0**, **Semgrep JSON**, **CodeQL SARIF**, **Trivy JSON**, **Gitleaks JSON** (scrubbing raw secrets immediately via `scrub_raw_secrets_text`), and **Checkov JSON** into ALASTOR `Finding` records, enriches them against ALASTOR's CPG (matching file/line/community/call-graph reachability), deduplicates against native ALASTOR findings (`corroborated_by` multi-engine agreement), and feeds them directly into S6 Adversarial Verifier, S8 Exploit Chains, PASTA Stage VII, and SAR `.docx`/`.pdf` exports.
4. **CSV Multi-Repo Batch Fleet Runner (`backend/engine/fleet_runner.py`):** Parses CSV manifests (`repo,app_group,branch,fusion_reports,profile`) with strict validation, runs per-repo checkpointed scans with failure isolation and `--resume` support, and persists **`--group-by-app`** rollups (Go-Live gate status per app, severity counts, corroborated multi-scanner count, runtime-confirmed EV count, top chains) into SQLite.
5. **Embedded-First Hardened `alastor` CLI + Typed Python SDK (`backend/alastor_sdk.py`, `backend/alastor_cli.py`, `backend/pyproject.toml`):** All 8 CLI subcommands (`setup`, `doctor`, `estimate`, `scan`, `remediate`, `validate`, `ev-replay`, `gc`) running offline directly against ALASTOR's engines (zero server required) with optional `--server <url>` remote mode via `httpx` and deterministic CI exit codes (`0` pass, `1` findings/blockers exceeded or `STILL_VULNERABLE`, `2` usage/config/hostile-repo error). Typed Python SDK (`ScanOptions`, `FleetOptions`, `scan`, `run_fleet`, `inject_findings`, `fuse_scanner_report`, `doctor`, `estimate`, `ev_replay`, `gc`) that never auto-loads target `.env`.
6. **Confined `/api/fleet/*` & `/api/fusion/*` FastAPI Endpoints + Light-Only Daylight `FleetCommandWorkbench.tsx`:** 8 workspace-confined routes integrated into `backend/main.py` and a clean 2nd sub-tab inside `frontend/src/components/ProjectsHubView.tsx` (`Portfolio Projects` | `Fleet Command, Checkpoints & Scanner Fusion`) adhering strictly to `#f8fafc`/`#ffffff` WCAG AA `>= 4.5:1` with zero `dark:` classes and zero DOM XSS sinks.

---

## 2. Architecture & Security Boundaries

### 2.1 Hostile-Repo Isolation (`hostile_repo_guard.py`)
- `build_hardened_git_env_and_argv(repo_path, environ=None) -> HardenedGitCommand`:
  - Strips all `GIT_*` environment variables except pre-configured `GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n` pins.
  - Injects `core.fsmonitor=""`, `core.hooksPath=/dev/null`, `core.sshCommand=false`, `diff.external=""`.
  - Runs `git -C <repo> config --null --list` with those pins; parses every `filter.<name>.(clean|smudge|process|required)` and `diff.<name>.(textconv|command)` key and appends no-op overrides (`""` / `"false"`). Raises `HostileRepoError` if config listing fails.
- `assert_safe_config_source(config_path, repo_root) -> str`:
  - Resolves realpaths (`os.path.realpath`); refuses any `.env`, `.alastor.yaml`, `config.yaml`, or config file located inside `repo_root` (or symlinked into `repo_root`), raising `HostileRepoError`.
- `validate_clone_url(url) -> str`:
  - Rejects empty strings, leading `-`, CR/LF/NUL/whitespace, `file://`, `ext::`, `fd::`, `git::`, or embedded raw secrets in logs; accepts strictly `https://`, `http://`, `ssh://`, or standard `git@host:org/repo(.git)` SCP-style SSH URLs (validating host chars safely).
- `safe_cleanup_workspace(workspace_dir, allowed_parent) -> int`:
  - Confirms `workspace_dir` is strictly inside `allowed_parent` via `os.path.realpath` and walks children using `os.lstat` / `os.path.islink` without ever following symlinks out of `allowed_parent` (removing symlink entries themselves without traversing their targets).
- `build_sandbox_docker_command(repo_path, output_dir, image="alastor-scanner:v5", allow_egress_hosts=None, cli_args=None) -> List[str]`:
  - Produces an argv list with `--rm`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--pids-limit=256`, `--memory=2g`, `--network=none` (default when `allow_egress_hosts` is empty), bind-mounting target repo `:ro` and isolated output dir `:rw`.

### 2.2 SQLite Stage Checkpoints & Host Provenance (`checkpoint_store.py`)
- Schema in `<vault_dir>/checkpoints.db` (WAL mode, `busy_timeout=5000`, `foreign_keys=ON`, `0o700` dir / `0o600` file, `threading.Lock`, strictly parameterized `?` queries):
  - `scan_runs(run_id PRIMARY KEY, repo_path, commit_sha, app_group, host_fingerprint, status, options_json, summary_json, created_at, updated_at)`
  - `stage_checkpoints(run_id, stage_name, status, payload_json, payload_sha256, duration_ms, updated_at, PRIMARY KEY (run_id, stage_name))`
  - `fleet_runs(fleet_run_id PRIMARY KEY, manifest_name, status, total_repos, completed_repos, failed_repos, summary_json, created_at, updated_at)`
- `host_fingerprint`: deterministic SHA-256 of `(socket.gethostname(), os.path.realpath(vault_dir))` so `verify_host_provenance(run_id, repo_path, current_commit_sha)` proves the scan was produced on THIS host for THIS repository and THIS commit SHA before `alastor remediate --mode fix` applies edits!
- `gc(older_than_days=30, keep_last=20, dry_run=False, temp_workspaces_parent=None) -> GcReport`: prunes expired runs/checkpoints (preserving the latest `keep_last`) and safely cleans orphaned temp directories inside `temp_workspaces_parent` using `safe_cleanup_workspace`.

### 2.3 Universal 6-Format Scanner Fusion (`scanner_fusion_engine.py`)
- Auto-detects format from JSON structure (`SARIF_2_1`, `CODEQL_SARIF`, `SEMGREP_JSON`, `TRIVY_JSON`, `GITLEAKS_JSON`, `CHECKOV_JSON`) with explicit `source_format` override supported.
- Normalizes every external alert into ALASTOR `Finding` (`source_engine`, `corroborated_by`, `cwe_id`, `severity`, `file_path`, `line`, `title`, `description`, `rule_id`), immediately scrubbing all text/snippets/secret fields through `scrub_raw_secrets_text(...)`.
- Enriches onto ALASTOR's CPG (matching normalized relative path + line window to `GraphStore` nodes / Leiden community ID / call-graph callers) and deduplicates against existing ALASTOR findings by `(norm_path, line_bucket, canonical_cwe_or_rule)` — merging matching findings by appending the external scanner name to `corroborated_by` and boosting confidence!

### 2.4 Embedded-First `alastor` CLI, SDK & Confined FastAPI Routes
- `backend/alastor_sdk.py`: Public typed API (`ScanOptions`, `FleetOptions`, `ScanResult`, `FleetResult`, `DoctorReport`, `EstimateReport`, `FusionResult`, `GcReport`, `scan()`, `run_fleet()`, `inject_findings()`, `fuse_scanner_report()`, `doctor()`, `estimate()`, `ev_replay()`, `gc()`).
- `backend/alastor_cli.py`: `click` CLI group (`alastor`) exposing all 8 commands (`setup`, `doctor`, `estimate`, `scan`, `remediate`, `validate`, `ev-replay`, `gc`) with `--json`, `--server`, `--resume`, `--fusion-report`, `--repo-file`, `--group-by-app`, `--sandbox`, and strict CI exit codes (`0`/`1`/`2`).
- `backend/pyproject.toml`: PEP 621 entry point `[project.scripts] alastor = "alastor_cli:main"`.
- `backend/main.py`: 8 workspace-confined endpoints (`/api/fleet/doctor`, `/api/fleet/estimate`, `/api/fusion/import`, `/api/fleet/run`, `/api/fleet/runs`, `/api/fleet/checkpoints`, `/api/fleet/checkpoints/{run_id}/resume`, `/api/fleet/gc`).
- `frontend/`: Types in `cpg.ts`, helpers in `api.ts`, `_fleetEpoch`-guarded Zustand slice in `useAuditStore.ts`, Light-Only Daylight `FleetCommandWorkbench.tsx` mounted as a 2nd sub-tab inside `ProjectsHubView.tsx`.
