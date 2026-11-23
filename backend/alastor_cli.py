"""
ALASTOR v5.0 Pillar 4 — Embedded-First Hardened CLI (`alastor`).

Supports both 100% offline embedded execution via `alastor_sdk` and optional
validated `--server <http(s)://...>` remote dispatch, with deterministic CI exit codes:
  - 0: Pass / Clean / All EV replays FIXED_VERIFIED
  - 1: Severity threshold breached / NO_GO_HOLD_RELEASE / EV STILL_VULNERABLE
  - 2: Usage error, missing path, hostile-repo policy violation, or failed host provenance
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List, NoReturn, Optional, Tuple
from urllib.parse import quote as url_quote, urlsplit

import click
import httpx

import alastor_sdk
from engine.frontier_ai_engine import scrub_raw_secrets_text
from engine.hostile_repo_guard import (
    HostileRepoError,
    assert_safe_config_source,
    build_sandbox_docker_command,
    is_link_or_junction,
)
from engine.pr_delta_gate import validate_git_ref
from models import (
    DoctorReport,
    EstimateReport,
    EvReplayRequest,
    EvReplayResponse,
    FleetRepoResult,
    FleetRepoSpec,
    FleetRunRequest,
    FleetRunResponse,
    GcReport,
    GcRequest,
    PrDeltaGateRequest,
    PrDeltaGateResponse,
)

_AGENTS_BEGIN = "<!-- ALASTOR:BEGIN -->"
_AGENTS_END = "<!-- ALASTOR:END -->"
_AGENTS_MANAGED_BLOCK = f"""{_AGENTS_BEGIN}
## ALASTOR Security Scanner Guardrails

When auditing or remediating code in this workspace with ALASTOR:

1. **Pre-flight Cost & Scope Check:** Run `alastor estimate --repo . --json` before full scans (`$0` spend).
2. **Deterministic Scan & Resume:** Run `alastor scan --repo . --resume --json` (add `--fusion-report <file>` to fuse SARIF/Semgrep/Trivy/Gitleaks/Checkov reports).
3. **Hostile-Repo Safety:** NEVER load `.env`, `.alastor.yaml`, `config.yaml`, or git hooks from untrusted target repositories.
4. **Provenance-Gated Remediation:** Always preview via `alastor remediate --repo . --mode report-only --json` and validate patches via `alastor validate --repo . --json` before running `alastor remediate --repo . --mode fix --run-id <id>`.
5. **Post-Fix Exploit Replay:** Verify fixes against staging via `alastor ev-replay --repo . --json`.
{_AGENTS_END}
"""

_SEVERITY_CHOICES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_FORMAT_CHOICES = ["json", "sarif", "docx", "pdf"]
_SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def _emit_json(data: Any) -> None:
    if hasattr(data, "model_dump"):
        payload = data.model_dump()
    else:
        payload = data
    click.echo(json.dumps(payload, indent=2))


def _fail_exit2(message: str, as_json: bool = False) -> NoReturn:
    safe_message = scrub_raw_secrets_text(str(message))
    if as_json:
        click.echo(json.dumps({"error": safe_message, "exit_code": 2}, indent=2))
    else:
        click.echo(f"Error: {safe_message}", err=True)
    raise SystemExit(2)


def _validate_out_md_target(raw_path: str) -> Tuple[str, str]:
    cleaned = alastor_sdk._validate_clean_path_arg(raw_path, "out-md")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        raise ValueError("--out-md contains forbidden control characters")
    if alastor_sdk._has_traversal_segment(cleaned):
        raise ValueError(f"Path traversal '..' rejected in --out-md: {raw_path}")
    if alastor_sdk._is_dotenv_filename(cleaned):
        raise HostileRepoError(f"Refused writing --out-md to restricted .env target: {raw_path}")

    abs_target = os.path.abspath(cleaned)
    if os.path.lexists(abs_target):
        if is_link_or_junction(abs_target):
            raise HostileRepoError(f"Refusing to write --out-md through symlink/junction: {raw_path}")
        if os.path.isdir(abs_target):
            raise ValueError(f"--out-md target is a directory: {raw_path}")

    parent_dir = os.path.dirname(abs_target)
    probe = parent_dir
    while probe and not os.path.lexists(probe):
        next_probe = os.path.dirname(probe)
        if next_probe == probe:
            break
        probe = next_probe
    if probe and os.path.lexists(probe) and is_link_or_junction(probe):
        raise HostileRepoError(f"Refusing to write --out-md under symlink/junction directory: {raw_path}")

    parent_real = os.path.realpath(parent_dir)
    real_target = os.path.realpath(abs_target)
    try:
        if os.path.commonpath([parent_real, real_target]) != parent_real:
            raise HostileRepoError(f"Refusing symlink escape in --out-md path: {raw_path}")
    except ValueError as exc:
        raise HostileRepoError(f"Refusing escaping --out-md path: {raw_path}") from exc
    return abs_target, real_target


def _write_out_md_file(raw_path: str, content: str) -> str:
    abs_target, real_target = _validate_out_md_target(raw_path)
    parent_real = os.path.dirname(real_target)
    os.makedirs(parent_real, exist_ok=True)
    if os.path.lexists(abs_target) and is_link_or_junction(abs_target):
        raise HostileRepoError(f"Refusing to write --out-md through symlink/junction: {raw_path}")
    if os.path.lexists(real_target) and is_link_or_junction(real_target):
        raise HostileRepoError(f"Refusing to write --out-md through symlink/junction: {raw_path}")
    with open(real_target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    return real_target


def _validate_server_url(raw_url: str) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("Server URL must be a non-empty string")
    if any(ch in raw_url for ch in ("\r", "\n", "\x00")) or any(ch.isspace() for ch in raw_url):
        raise ValueError("Server URL contains forbidden control or whitespace characters")
    cleaned = raw_url.strip()
    if cleaned.startswith("-"):
        raise ValueError("Server URL cannot start with '-'")
    parsed = urlsplit(cleaned)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported --server scheme '{scheme}'; only http:// and https:// are allowed")
    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise ValueError("Embedded credentials in --server URL are forbidden")
    if not parsed.hostname:
        raise ValueError("Server URL is missing a valid hostname")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in --server URL: {exc}") from exc
    if parsed.query or parsed.fragment:
        raise ValueError("Server base URL cannot contain query strings or fragments")
    return cleaned.rstrip("/")


def _remote_request(
    server_url: str,
    method: str,
    path: str,
    json_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    base_url = _validate_server_url(server_url)
    with httpx.Client(base_url=base_url, timeout=60.0, follow_redirects=False) as client:
        if method.upper() == "GET":
            resp = client.get(path)
        else:
            resp = client.post(path, json=json_body or {})
        status_code = getattr(resp, "status_code", None)
        if (isinstance(status_code, int) and 300 <= status_code < 400) or (
            getattr(resp, "is_redirect", False) is True
        ):
            raise ValueError(
                f"Refused HTTP {status_code} redirect from remote server endpoint {path}"
            )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError(f"Unexpected response payload from server endpoint {path}")
        return data


def _compute_remote_repo_exit_code(
    repo_res: FleetRepoResult,
    norm_fail_on: Optional[str],
) -> int:
    if repo_res.status == "FAILED":
        return 2
    if repo_res.go_live_decision == "NO_GO_HOLD_RELEASE":
        return 1
    if norm_fail_on:
        sev_counts = {
            "CRITICAL": repo_res.critical_count,
            "HIGH": repo_res.high_count,
            "MEDIUM": repo_res.medium_count,
            "LOW": repo_res.low_count,
        }
        thresh = _SEVERITY_RANK[norm_fail_on]
        return (
            1
            if any(_SEVERITY_RANK[s] >= thresh and cnt > 0 for s, cnt in sev_counts.items())
            else 0
        )
    return 0


def _install_agents_md(target_dir: str, force: bool = False) -> Tuple[str, str]:
    if not target_dir or any(ch in target_dir for ch in ("\r", "\n", "\x00")):
        raise ValueError("Invalid target_dir for AGENTS.md installation")
    real_dir = os.path.realpath(target_dir)
    if not os.path.isdir(real_dir):
        raise ValueError(f"Target directory does not exist: {target_dir}")

    agents_path = os.path.join(real_dir, "AGENTS.md")
    if os.path.lexists(agents_path) and is_link_or_junction(agents_path):
        raise HostileRepoError(f"Refusing to write AGENTS.md through symlink/junction: {agents_path}")

    if not os.path.lexists(agents_path):
        with open(agents_path, "w", encoding="utf-8") as fh:
            fh.write(_AGENTS_MANAGED_BLOCK)
        return os.path.realpath(agents_path), "created"

    with open(agents_path, "r", encoding="utf-8", errors="replace") as fh:
        existing = fh.read()

    begin_idx = existing.find(_AGENTS_BEGIN)
    end_idx = existing.find(_AGENTS_END)
    if begin_idx != -1 and end_idx != -1 and begin_idx < end_idx:
        after_end = end_idx + len(_AGENTS_END)
        if after_end < len(existing) and existing[after_end] == "\n":
            after_end += 1
        updated = existing[:begin_idx] + _AGENTS_MANAGED_BLOCK + existing[after_end:]
        with open(agents_path, "w", encoding="utf-8") as fh:
            fh.write(updated)
        return os.path.realpath(agents_path), "updated"

    if not force:
        raise HostileRepoError(
            "AGENTS.md already exists without ALASTOR-managed markers; re-run with --force to append guardrails."
        )

    sep = "\n" if existing.endswith("\n") or not existing else "\n\n"
    updated = existing + sep + _AGENTS_MANAGED_BLOCK
    with open(agents_path, "w", encoding="utf-8") as fh:
        fh.write(updated)
    return os.path.realpath(agents_path), "appended"


def _run_sandbox_docker(argv: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )


@click.group(help="ALASTOR v5.0 Enterprise Deterministic CPG, Scanner Fusion & Fleet Security CLI")
def cli() -> None:
    """ALASTOR v5.0 CLI root group."""


@cli.command("setup")
@click.option("--install-agents", is_flag=True, default=False, help="Install ALASTOR guardrails block into AGENTS.md.")
@click.option("--target-dir", default=".", show_default=True, help="Directory in which to install AGENTS.md.")
@click.option("--force", is_flag=True, default=False, help="Allow updating an existing AGENTS.md lacking ALASTOR markers.")
@click.option("--vault-dir", default=None, help="Host vault directory override.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON output.")
def setup_cmd(
    install_agents: bool,
    target_dir: str,
    force: bool,
    vault_dir: Optional[str],
    as_json: bool,
) -> None:
    """Inspects local ALASTOR readiness ($0 spend) and optionally installs AGENTS.md guardrails."""
    try:
        doc = alastor_sdk.doctor(vault_dir=vault_dir, check_neo4j=False)
        agents_installed = False
        agents_path: Optional[str] = None
        agents_action: Optional[str] = None
        if install_agents:
            agents_path, agents_action = _install_agents_md(target_dir=target_dir, force=force)
            agents_installed = True
    except (HostileRepoError, ValueError, OSError) as exc:
        _fail_exit2(str(exc), as_json=as_json)

    payload: Dict[str, Any] = {
        "doctor": doc.model_dump(),
        "agents_installed": agents_installed,
        "agents_path": agents_path,
        "agents_action": agents_action,
    }
    if as_json:
        _emit_json(payload)
    else:
        click.echo(
            f"ALASTOR Setup: status={doc.overall_status} parsers={doc.parsers_ready}/{doc.parsers_total} "
            f"backend={doc.graph_backend} vault_writable={doc.vault_writable}"
        )
        if agents_installed and agents_path:
            click.echo(f"AGENTS.md {agents_action} at {agents_path}")
    raise SystemExit(2 if doc.overall_status == "ERROR" else 0)


@cli.command("doctor")
@click.option("--vault-dir", default=None, help="Host vault directory override.")
@click.option("--server", "server_url", default=None, help="Optional remote ALASTOR server URL.")
@click.option("--check-neo4j", is_flag=True, default=False, help="Probe Neo4j connectivity if configured.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON output.")
def doctor_cmd(
    vault_dir: Optional[str],
    server_url: Optional[str],
    check_neo4j: bool,
    as_json: bool,
) -> None:
    """Checks Python, 18-language parsers, GraphStore backend, git, docker, vault, and BYOK presence."""
    try:
        if server_url:
            doc_path = "/api/fleet/doctor?check_neo4j=true" if check_neo4j else "/api/fleet/doctor"
            raw = _remote_request(server_url, "GET", doc_path)
            doc = DoctorReport.model_validate(raw)
        else:
            doc = alastor_sdk.doctor(vault_dir=vault_dir, check_neo4j=check_neo4j)
    except (httpx.HTTPError, ValueError, OSError) as exc:
        _fail_exit2(str(exc), as_json=as_json)

    if as_json:
        _emit_json(doc)
    else:
        click.echo(
            f"ALASTOR Doctor: {doc.overall_status} | Python {doc.python_version} | "
            f"Parsers {doc.parsers_ready}/{doc.parsers_total} | Graph {doc.graph_backend}"
        )
        for chk in doc.checks:
            click.echo(f"  - [{chk.status}] {chk.name}: {chk.detail}")
    raise SystemExit(2 if doc.overall_status == "ERROR" else 0)


@cli.command("estimate")
@click.option("--repo", required=True, help="Target repository directory to estimate.")
@click.option("--vault-dir", default=None, help="Host vault directory override.")
@click.option("--server", "server_url", default=None, help="Optional remote ALASTOR server URL.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON output.")
def estimate_cmd(
    repo: str,
    vault_dir: Optional[str],
    server_url: Optional[str],
    as_json: bool,
) -> None:
    """Estimates scannable files, LOC, languages, runtime, and AI cost at $0 spend."""
    try:
        if server_url:
            raw = _remote_request(server_url, "POST", "/api/fleet/estimate", {"project_path": repo})
            est = EstimateReport.model_validate(raw)
        else:
            est = alastor_sdk.estimate(repo, vault_dir=vault_dir)
    except (httpx.HTTPError, HostileRepoError, ValueError, OSError) as exc:
        _fail_exit2(str(exc), as_json=as_json)

    if as_json:
        _emit_json(est)
    else:
        click.echo(
            f"ALASTOR Estimate ({est.project_path}): files={est.total_files}, loc={est.total_loc}, "
            f"skipped={est.skipped_files}, est_det_s={est.estimated_deterministic_seconds}s, "
            f"profile={est.recommended_profile}, kinds={','.join(est.repo_kind_hints)}"
        )
    raise SystemExit(0)


@cli.command("scan")
@click.option("--repo", default=None, help="Local repository directory to scan.")
@click.option("--repo-file", default=None, help="CSV fleet manifest path (repo,app_group,branch,fusion_reports,profile).")
@click.option("--app-group", default="default", show_default=True, help="Application group label for single-repo scan.")
@click.option("--group-by-app/--no-group-by-app", default=True, show_default=True, help="Compute App-Group Go-Live rollups.")
@click.option("--resume/--no-resume", default=True, show_default=True, help="Reuse SHA-256 verified SQLite stage checkpoints.")
@click.option("--run-id", default=None, help="Explicit checkpoint run_id to resume or create.")
@click.option("--fusion-report", "fusion_reports", multiple=True, help="External scanner JSON/SARIF report(s) to fuse.")
@click.option("--profile", default="deterministic", show_default=True, help="Rule profile (deterministic, fast-ci, secrets-hunt).")
@click.option("--stop-after", default=None, help="Stop pipeline after stage (e.g. s0, s1, s2, s3, s6, s8, s9).")
@click.option("--sandbox", is_flag=True, default=False, help="Build hardened Docker sandbox command.")
@click.option("--execute-sandbox", is_flag=True, default=False, help="Execute the hardened Docker sandbox command.")
@click.option("--sandbox-image", default="alastor-scanner:v5", show_default=True, help="Docker image for --sandbox.")
@click.option("--fail-on", "fail_on_severity", type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False), default=None, help="Fail with exit 1 if active findings meet or exceed severity.")
@click.option("--format", "output_format", type=click.Choice(_FORMAT_CHOICES, case_sensitive=False), default="json", show_default=True, help="Artifact output format when --out is specified.")
@click.option("--out", "out_dir", default=None, help="Output directory for generated report artifact.")
@click.option("--config", "config_file", default=None, help="External host config file (inside-repo configs are refused).")
@click.option("--server", "server_url", default=None, help="Optional remote ALASTOR server URL.")
@click.option("--vault-dir", default=None, help="Host vault directory override.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON output.")
def scan_cmd(
    repo: Optional[str],
    repo_file: Optional[str],
    app_group: str,
    group_by_app: bool,
    resume: bool,
    run_id: Optional[str],
    fusion_reports: Tuple[str, ...],
    profile: str,
    stop_after: Optional[str],
    sandbox: bool,
    execute_sandbox: bool,
    sandbox_image: str,
    fail_on_severity: Optional[str],
    output_format: str,
    out_dir: Optional[str],
    config_file: Optional[str],
    server_url: Optional[str],
    vault_dir: Optional[str],
    as_json: bool,
) -> None:
    """Runs deterministic CPG/SAST/SCA/IaC + Scanner Fusion scan on a repo or fleet CSV."""
    if not repo and not repo_file:
        _fail_exit2("Either --repo or --repo-file must be supplied.", as_json=as_json)
    if repo and repo_file:
        _fail_exit2("Specify either --repo or --repo-file, not both.", as_json=as_json)

    norm_fmt = output_format.lower()
    norm_fail_on = fail_on_severity.upper() if fail_on_severity else None

    if sandbox:
        if not repo:
            _fail_exit2("--sandbox requires --repo.", as_json=as_json)
        try:
            if config_file:
                assert_safe_config_source(config_file, repo)
            real_repo = alastor_sdk._resolve_existing_repo_dir(repo)
            eff_out = os.path.realpath(out_dir) if out_dir else os.path.abspath("alastor-out")
            cli_args: List[str] = [
                "scan",
                "--repo",
                "/workspace",
                "--out",
                "/out",
                "--profile",
                profile,
                "--format",
                norm_fmt,
            ]
            if not resume:
                cli_args.append("--no-resume")
            if stop_after:
                cli_args.extend(["--stop-after", stop_after])
            if norm_fail_on:
                cli_args.extend(["--fail-on", norm_fail_on])
            argv = build_sandbox_docker_command(
                repo_path=real_repo,
                output_dir=eff_out,
                image=sandbox_image,
                cli_args=cli_args,
            )
            if not execute_sandbox:
                payload = {
                    "sandbox_dry_run": True,
                    "docker_argv": argv,
                    "command": " ".join(argv),
                }
                if as_json:
                    _emit_json(payload)
                else:
                    click.echo(" ".join(argv))
                raise SystemExit(0)

            proc = _run_sandbox_docker(argv)
            if as_json:
                _emit_json(
                    {
                        "sandbox_dry_run": False,
                        "docker_argv": argv,
                        "returncode": proc.returncode,
                        "stdout": proc.stdout,
                        "stderr": proc.stderr,
                    }
                )
            else:
                if proc.stdout:
                    click.echo(proc.stdout, nl=False)
                if proc.stderr:
                    click.echo(proc.stderr, err=True, nl=False)
            raise SystemExit(proc.returncode if proc.returncode in (0, 1, 2) else 2)
        except SystemExit:
            raise
        except (HostileRepoError, ValueError, OSError) as exc:
            _fail_exit2(str(exc), as_json=as_json)

    if server_url and out_dir:
        _fail_exit2(
            "--out is not supported with --server; run locally or export via /api/export/sar-report.",
            as_json=as_json,
        )

    # Fleet CSV mode
    if repo_file:
        if run_id:
            _fail_exit2("--run-id cannot be combined with --repo-file.", as_json=as_json)
        try:
            if server_url:
                csv_text = alastor_sdk._read_confined_host_file(repo_file, label="repo-file")
                req_obj = FleetRunRequest(
                    manifest_name=os.path.basename(os.path.realpath(repo_file)),
                    csv_content=csv_text,
                    group_by_app=group_by_app,
                    resume=resume,
                    stop_after=stop_after,
                )
                raw = _remote_request(server_url, "POST", "/api/fleet/run", req_obj.model_dump())
                fleet_resp = FleetRunResponse.model_validate(raw)
            else:
                fleet_resp = alastor_sdk.run_fleet(
                    alastor_sdk.FleetOptions(
                        csv_path=repo_file,
                        manifest_name=os.path.basename(repo_file),
                        group_by_app=group_by_app,
                        resume=resume,
                        stop_after=stop_after,
                        vault_dir=vault_dir,
                    )
                )
        except (httpx.HTTPError, HostileRepoError, ValueError, OSError) as exc:
            _fail_exit2(str(exc), as_json=as_json)

        if as_json:
            _emit_json(fleet_resp)
        else:
            click.echo(
                f"ALASTOR Fleet ({fleet_resp.fleet_run_id}): status={fleet_resp.status} "
                f"completed={fleet_resp.completed_repos}/{fleet_resp.total_repos} failed={fleet_resp.failed_repos}"
            )
            for rollup in fleet_resp.app_rollups:
                click.echo(
                    f"  - [{rollup.app_group}] {rollup.go_live_decision} "
                    f"(repos={rollup.repo_count}, findings={rollup.total_findings})"
                )

        if fleet_resp.status == "FAILED":
            raise SystemExit(2)
        if fleet_resp.failed_repos > 0 or any(
            _compute_remote_repo_exit_code(r, norm_fail_on) != 0
            for r in fleet_resp.repo_results
        ):
            raise SystemExit(1)
        raise SystemExit(0)

    # Single-repo mode
    assert repo is not None
    try:
        if server_url:
            if config_file:
                assert_safe_config_source(config_file, repo)
            if run_id is not None:
                if fusion_reports:
                    raise ValueError("--fusion-report cannot be combined with --run-id in --server mode")
                clean_run_id = run_id.strip()
                if (
                    not clean_run_id
                    or any(ch in clean_run_id for ch in ("\r", "\n", "\x00", "/", "\\"))
                    or ".." in clean_run_id
                ):
                    raise ValueError("Invalid --run-id for remote checkpoint resume")
                raw = _remote_request(
                    server_url,
                    "POST",
                    f"/api/fleet/checkpoints/{url_quote(clean_run_id, safe='')}/resume",
                    {"stop_after": stop_after},
                )
                repo_res = FleetRepoResult.model_validate(raw)
            else:
                real_repo = os.path.realpath(repo)
                for rp in fusion_reports:
                    cleaned_rp = alastor_sdk._validate_clean_path_arg(rp, "fusion_report")
                    if alastor_sdk._has_traversal_segment(cleaned_rp):
                        raise ValueError(f"Path traversal '..' rejected in --fusion-report: {rp}")
                    if os.path.isdir(real_repo):
                        in_repo_cand = alastor_sdk._validate_repo_relative_no_links(cleaned_rp, real_repo)
                        if in_repo_cand is None:
                            raise ValueError(
                                f"Out-of-repo --fusion-report '{rp}' is not supported with --server; "
                                "pass a repo-relative path or call /api/fusion/import."
                            )
                    elif os.path.isabs(cleaned_rp):
                        raise ValueError(
                            f"Absolute --fusion-report '{rp}' is not supported with --server when repo is remote; "
                            "pass a repo-relative path or call /api/fusion/import."
                        )
                req_obj = FleetRunRequest(
                    manifest_name=f"cli-{os.path.basename(os.path.abspath(repo))}",
                    repos=[
                        FleetRepoSpec(
                            repo=repo,
                            app_group=app_group,
                            fusion_reports=list(fusion_reports),
                            profile=profile,
                        )
                    ],
                    group_by_app=group_by_app,
                    resume=resume,
                    stop_after=stop_after,
                )
                raw = _remote_request(server_url, "POST", "/api/fleet/run", req_obj.model_dump())
                fleet_resp = FleetRunResponse.model_validate(raw)
                if not fleet_resp.repo_results:
                    _fail_exit2("Remote server returned no repository results.", as_json=as_json)
                repo_res = fleet_resp.repo_results[0]

            exit_code = _compute_remote_repo_exit_code(repo_res, norm_fail_on)
            if as_json:
                _emit_json(repo_res)
            else:
                click.echo(
                    f"ALASTOR Remote Scan ({repo_res.run_id}): status={repo_res.status} "
                    f"findings={repo_res.total_findings} decision={repo_res.go_live_decision}"
                )
            raise SystemExit(exit_code)

        scan_res = alastor_sdk.scan(
            alastor_sdk.ScanOptions(
                repo=repo,
                app_group=app_group,
                profile=profile,
                resume=resume,
                run_id=run_id,
                stop_after=stop_after,
                fusion_reports=list(fusion_reports),
                fail_on_severity=norm_fail_on,  # type: ignore[arg-type]
                out_dir=out_dir,
                output_format=norm_fmt,  # type: ignore[arg-type]
                vault_dir=vault_dir,
                config_file=config_file,
            )
        )
    except SystemExit:
        raise
    except (httpx.HTTPError, HostileRepoError, ValueError, OSError) as exc:
        _fail_exit2(str(exc), as_json=as_json)

    if as_json:
        _emit_json(scan_res)
    else:
        click.echo(
            f"ALASTOR Scan ({scan_res.run_id}): status={scan_res.status} "
            f"findings={scan_res.total_findings} corroborated={scan_res.corroborated_count} "
            f"decision={scan_res.go_live_decision}"
        )
        for out_p in scan_res.output_files:
            click.echo(f"  Artifact: {out_p}")
    raise SystemExit(scan_res.exit_code)


@cli.command("remediate")
@click.option("--repo", required=True, help="Target repository directory.")
@click.option("--mode", type=click.Choice(["report-only", "fix"], case_sensitive=False), default="report-only", show_default=True, help="Report remediation plan only or apply host-provenance-verified patches.")
@click.option("--run-id", default=None, help="Host scan run_id (mandatory for --mode fix).")
@click.option("--finding-id", default=None, help="Optional single finding ID to remediate.")
@click.option("--vault-dir", default=None, help="Host vault directory override.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON output.")
def remediate_cmd(
    repo: str,
    mode: str,
    run_id: Optional[str],
    finding_id: Optional[str],
    vault_dir: Optional[str],
    as_json: bool,
) -> None:
    """Proposes or applies deterministic BFL patches with strict host-provenance enforcement."""
    norm_mode = mode.lower()
    try:
        res = alastor_sdk.remediate(
            repo_path=repo,
            run_id=run_id,
            mode=norm_mode,  # type: ignore[arg-type]
            finding_id=finding_id,
            vault_dir=vault_dir,
        )
    except (HostileRepoError, ValueError, OSError) as exc:
        _fail_exit2(str(exc), as_json=as_json)

    if as_json:
        _emit_json(res)
    else:
        click.echo(
            f"ALASTOR Remediate ({res['mode']}): findings={res['total_findings']}, "
            f"applied={res['applied_count']}, provenance_verified={res['provenance_verified']}"
        )
    raise SystemExit(0)


@cli.command("validate")
@click.option("--repo", required=True, help="Target repository directory.")
@click.option("--run-id", default=None, help="Checkpoint run_id to load findings from.")
@click.option("--finding-id", default=None, help="Optional single finding ID to validate.")
@click.option("--vault-dir", default=None, help="Host vault directory override.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON output.")
def validate_cmd(
    repo: str,
    run_id: Optional[str],
    finding_id: Optional[str],
    vault_dir: Optional[str],
    as_json: bool,
) -> None:
    """Runs the S11 dual-verified 3-persona patch validation panel ($0 deterministic default)."""
    try:
        res = alastor_sdk.validate(
            repo_path=repo,
            run_id=run_id,
            finding_id=finding_id,
            vault_dir=vault_dir,
        )
    except (HostileRepoError, ValueError, OSError) as exc:
        _fail_exit2(str(exc), as_json=as_json)

    if as_json:
        _emit_json(res)
    else:
        click.echo(
            f"ALASTOR Validate: status={res['overall_status']} validated={res['validated_count']} "
            f"approved={res['approved_count']} revisions={res['revisions_required_count']} rejected={res['rejected_count']}"
        )
    raise SystemExit(0)


@cli.command("ev-replay")
@click.option("--repo", required=True, help="Target repository directory.")
@click.option("--target-url", default=None, help="Optional staging target URL override.")
@click.option("--replay-id", "replay_ids", multiple=True, help="Specific EV replay bundle ID(s) to replay.")
@click.option("--allow-private-staging-host", is_flag=True, default=False, help="Permit RFC1918 private staging hosts.")
@click.option("--authorized-staging-host", "authorized_staging_hosts", multiple=True, help="Allowlisted staging hostname(s).")
@click.option("--server", "server_url", default=None, help="Optional remote ALASTOR server URL.")
@click.option("--vault-dir", default=None, help="Host vault directory override.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON output.")
def ev_replay_cmd(
    repo: str,
    target_url: Optional[str],
    replay_ids: Tuple[str, ...],
    allow_private_staging_host: bool,
    authorized_staging_hosts: Tuple[str, ...],
    server_url: Optional[str],
    vault_dir: Optional[str],
    as_json: bool,
) -> None:
    """Replays persisted EV bundles post-fix to verify remediation (`FIXED_VERIFIED` vs `STILL_VULNERABLE`)."""
    try:
        if server_url:
            req_obj = EvReplayRequest(
                project_path=repo,
                target_url=target_url,
                replay_ids=list(replay_ids) if replay_ids else None,
                allow_private_staging_host=allow_private_staging_host,
                authorized_staging_hosts=list(authorized_staging_hosts),
            )
            raw = _remote_request(server_url, "POST", "/api/ev/replay", req_obj.model_dump())
            resp = EvReplayResponse.model_validate(raw)
        else:
            resp = alastor_sdk.ev_replay(
                repo_path=repo,
                target_url=target_url,
                replay_ids=list(replay_ids) if replay_ids else None,
                allow_private_staging_host=allow_private_staging_host,
                authorized_staging_hosts=list(authorized_staging_hosts),
                vault_dir=vault_dir,
            )
    except (httpx.HTTPError, HostileRepoError, ValueError, OSError) as exc:
        _fail_exit2(str(exc), as_json=as_json)

    if as_json:
        _emit_json(resp)
    else:
        click.echo(
            f"ALASTOR EV-Replay: replayed={resp.replayed_count} fixed_verified={resp.fixed_verified_count} "
            f"still_vulnerable={resp.still_vulnerable_count} errors={resp.error_count}"
        )

    if resp.still_vulnerable_count > 0:
        raise SystemExit(1)
    if resp.error_count > 0:
        raise SystemExit(2)
    raise SystemExit(0)


@cli.command("gc")
@click.option("--older-than-days", type=int, default=30, show_default=True, help="Prune runs older than N days.")
@click.option("--keep-last", type=int, default=20, show_default=True, help="Always retain the N most recent runs.")
@click.option("--dry-run", is_flag=True, default=False, help="Preview GC deletions without modifying disk.")
@click.option("--server", "server_url", default=None, help="Optional remote ALASTOR server URL.")
@click.option("--vault-dir", default=None, help="Host vault directory override.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON output.")
def gc_cmd(
    older_than_days: int,
    keep_last: int,
    dry_run: bool,
    server_url: Optional[str],
    vault_dir: Optional[str],
    as_json: bool,
) -> None:
    """Prunes expired SQLite scan checkpoints and orphaned temp CPG workspaces."""
    try:
        if server_url:
            req_obj = GcRequest(
                older_than_days=older_than_days,
                keep_last=keep_last,
                dry_run=dry_run,
            )
            raw = _remote_request(server_url, "POST", "/api/fleet/gc", req_obj.model_dump())
            rep = GcReport.model_validate(raw)
        else:
            rep = alastor_sdk.gc(
                older_than_days=older_than_days,
                keep_last=keep_last,
                dry_run=dry_run,
                vault_dir=vault_dir,
            )
    except (httpx.HTTPError, ValueError, OSError) as exc:
        _fail_exit2(str(exc), as_json=as_json)

    if as_json:
        _emit_json(rep)
    else:
        click.echo(
            f"ALASTOR GC ({'DRY-RUN' if rep.dry_run else 'APPLIED'}): pruned_runs={rep.pruned_runs}, "
            f"pruned_checkpoints={rep.pruned_checkpoints}, pruned_temp_dirs={rep.pruned_temp_dirs}, "
            f"reclaimed_bytes={rep.reclaimed_bytes}, kept_runs={rep.kept_runs}"
        )
    raise SystemExit(0)


@cli.command("pr-gate")
@click.option("--repo", required=True, help="Target local git repository directory.")
@click.option("--base", "base_ref", default="HEAD~1", show_default=True, help="Base git ref for PR delta diff.")
@click.option("--head", "head_ref", default="HEAD", show_default=True, help="Head git ref (or WORKTREE) for PR delta diff.")
@click.option("--fail-on", "fail_on_severity", type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False), default="HIGH", show_default=True, help="Block merge if newly introduced findings meet or exceed severity.")
@click.option("--no-block-secrets", is_flag=True, default=False, help="Do not block merge on newly introduced secret findings below severity threshold.")
@click.option("--no-block-ev", is_flag=True, default=False, help="Do not block merge on newly introduced EV-confirmed findings below severity threshold.")
@click.option("--no-cpg-neighbors", is_flag=True, default=False, help="Disable 1-hop CPG blast-radius neighbor analysis.")
@click.option("--out-md", "out_md_path", default=None, help="Optional Markdown file path to write PR summary.")
@click.option("--server", "server_url", default=None, help="Optional remote ALASTOR server URL.")
@click.option("--vault-dir", default=None, help="Host vault directory override.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON output.")
def pr_gate_cmd(
    repo: str,
    base_ref: str,
    head_ref: str,
    fail_on_severity: str,
    no_block_secrets: bool,
    no_block_ev: bool,
    no_cpg_neighbors: bool,
    out_md_path: Optional[str],
    server_url: Optional[str],
    vault_dir: Optional[str],
    as_json: bool,
) -> None:
    """Evaluates PR/git-diff security delta gate (0=PASS, 1=BLOCK_MERGE, 2=ERROR)."""
    norm_fail_on = fail_on_severity.upper()
    try:
        validate_git_ref(base_ref)
        validate_git_ref(head_ref)
        if base_ref == "WORKTREE":
            raise ValueError("--base cannot be 'WORKTREE'; provide a valid commit or branch ref")
        if out_md_path is not None:
            _validate_out_md_target(out_md_path)

        if server_url:
            req_obj = PrDeltaGateRequest(
                project_path=repo,
                base_ref=base_ref,
                head_ref=head_ref,
                fail_on_new_severity=norm_fail_on,  # type: ignore[arg-type]
                block_on_new_secrets=not no_block_secrets,
                block_on_new_ev_confirmed=not no_block_ev,
                include_cpg_neighbors=not no_cpg_neighbors,
            )
            raw = _remote_request(server_url, "POST", "/api/nextgen/pr-gate", req_obj.model_dump())
            resp = PrDeltaGateResponse.model_validate(raw)
        else:
            resp = alastor_sdk.pr_gate(
                repo_path=repo,
                base_ref=base_ref,
                head_ref=head_ref,
                fail_on_new_severity=norm_fail_on,  # type: ignore[arg-type]
                block_on_new_secrets=not no_block_secrets,
                block_on_new_ev_confirmed=not no_block_ev,
                include_cpg_neighbors=not no_cpg_neighbors,
                vault_dir=vault_dir,
            )

        written_md: Optional[str] = None
        if out_md_path is not None:
            written_md = _write_out_md_file(out_md_path, resp.pr_markdown_summary)
    except (httpx.HTTPError, HostileRepoError, ValueError, OSError) as exc:
        _fail_exit2(str(exc), as_json=as_json)

    if as_json:
        _emit_json(resp)
    else:
        click.echo(
            f"ALASTOR PR-Gate ({resp.base_ref}..{resp.head_ref}): decision={resp.gate_decision} "
            f"new={resp.newly_introduced_count} blocking={resp.blocking_count} "
            f"modified_ctx={resp.modified_context_count} pre_existing={resp.pre_existing_count}"
        )
        click.echo(f"  Reason: {resp.gate_reason}")
        if written_md:
            click.echo(f"  Markdown Summary: {written_md}")

    raise SystemExit(1 if resp.gate_decision == "BLOCK_MERGE" else 0)


def main() -> None:
    cli(standalone_mode=True)


if __name__ == "__main__":
    main()
