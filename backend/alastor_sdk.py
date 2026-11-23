"""
ALASTOR v5.0 Pillar 4 — Embedded-First Typed Python SDK.

Provides offline-first programmatic orchestration over ALASTOR's CPG, SAST/SCA/IaC,
Universal 6-Format Scanner Fusion, SQLite WAL Stage Checkpoints, S6/S11 Adversarial
Verification, EV Replay, and Retention GC engines without auto-loading any `.env`
or config inside scanned target repositories.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import platform
import re
import shutil
import tempfile
import uuid
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field

from compiler.language_registry import list_language_capabilities
from compiler.scanner import scan_directory_with_telemetry
from database.checkpoint_store import CheckpointStore
from database.graph_store import EmbeddedGraphStore, GraphStoreManager
from database.neo4j_client import Neo4jClient
from engine.adversarial_verifier import validate_patch_with_panel
from engine.api_operations_engine import ApiOperationsEngine
from engine.enterprise_manager import EnterpriseManager
from engine.exploit_chain_engine import synthesize_exploit_chains
from engine.exploit_verification_engine import ExploitVerificationEngine
from engine.fleet_runner import (
    FleetRunner,
    _build_cpg_for_repo,
    _map_pasta_verdict_to_fleet,
    _normalize_stop_after,
)
from engine.frontier_ai_engine import FrontierAiEngine, scrub_raw_secrets_text
from engine.hostile_repo_guard import (
    HostileRepoError,
    assert_safe_config_source,
    find_hostile_target_configs,
    get_repo_commit_sha,
    is_link_or_junction,
)
from engine.pasta_threat_engine import PastaThreatEngine
from engine.remediation_patcher import (
    batch_apply_workspace_patches,
    preview_finding_remediation,
)
from engine.sar_report_generator import (
    SarReportBundle,
    generate_sar_docx_bytes,
    generate_sar_pdf_bytes,
    sanitize_bundle_for_export,
)
from engine.scanner_fusion_engine import (
    fuse_findings_with_cpg,
    parse_external_scanner_report,
    scrub_finding_secrets,
)
from engine.security_playbooks import classify_repo_kinds_and_baselines
from models import (
    DoctorCheckItem,
    DoctorReport,
    EstimateReport,
    EvReplayRequest,
    EvReplayResponse,
    Finding,
    FleetRepoSpec,
    FleetRunRequest,
    FleetRunResponse,
    GcReport,
    MetricsResponse,
    PatchPanelValidateRequest,
    ScannerFormatType,
    ScannerFusionResponse,
)

_MAX_REPORT_BYTES = 50 * 1024 * 1024
_SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


class ScanOptions(BaseModel):
    repo: str
    app_group: str = "default"
    profile: str = "deterministic"
    resume: bool = True
    run_id: Optional[str] = None
    stop_after: Optional[str] = None
    fusion_reports: List[str] = Field(default_factory=list)
    injected_findings: List[Finding] = Field(default_factory=list)
    fail_on_severity: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]] = None
    out_dir: Optional[str] = None
    output_format: Literal["json", "sarif", "docx", "pdf"] = "json"
    vault_dir: Optional[str] = None
    config_file: Optional[str] = None


class FleetOptions(BaseModel):
    csv_path: Optional[str] = None
    csv_content: Optional[str] = None
    repos: List[FleetRepoSpec] = Field(default_factory=list)
    manifest_name: str = "fleet-manifest"
    group_by_app: bool = True
    resume: bool = True
    max_workers: int = Field(default=2, ge=1, le=8)
    stop_after: Optional[str] = None
    vault_dir: Optional[str] = None


class ScanResult(BaseModel):
    exit_code: int
    run_id: str
    repo_path: str
    commit_sha: str = ""
    status: str
    go_live_decision: str
    total_findings: int
    corroborated_count: int = 0
    resumed_stages: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    output_files: List[str] = Field(default_factory=list)
    error: Optional[str] = None


def _validate_clean_path_arg(raw: str, label: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{label} must be a non-empty path string")
    if any(ch in raw for ch in ("\r", "\n", "\x00")):
        raise ValueError(f"{label} contains forbidden control characters")
    cleaned = raw.strip()
    if cleaned.startswith("-"):
        raise ValueError(f"{label} cannot start with '-'")
    return cleaned


def _has_traversal_segment(raw: str) -> bool:
    parts = [p for p in re.split(r"[\\/]+", raw.strip()) if p]
    return any(p == ".." for p in parts)


def _is_dotenv_filename(path_str: str) -> bool:
    base = os.path.basename(path_str).lower()
    return base == ".env" or base.startswith(".env.") or base.endswith(".env")


def _resolve_vault_dir(vault_dir: Optional[str]) -> str:
    if vault_dir is not None and vault_dir.strip():
        cleaned = _validate_clean_path_arg(vault_dir, "vault_dir")
        return os.path.realpath(cleaned)
    env_vault = os.environ.get("ALASTOR_VAULT_DIR", "").strip()
    if env_vault:
        cleaned = _validate_clean_path_arg(env_vault, "ALASTOR_VAULT_DIR")
        return os.path.realpath(cleaned)
    platform_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.realpath(os.path.join(platform_root, ".alastor_vault"))


def _resolve_existing_repo_dir(repo_path: str) -> str:
    cleaned = _validate_clean_path_arg(repo_path, "repo_path")
    if "://" in cleaned:
        raise HostileRepoError("Remote URL must be cloned locally before offline analysis")
    real_repo = os.path.realpath(cleaned)
    if not os.path.isdir(real_repo):
        raise ValueError(f"Repository path does not exist or is not a directory: {repo_path}")
    return real_repo


def _load_safe_external_config(config_file: str, repo_path: str) -> Dict[str, Any]:
    """
    Enforces `assert_safe_config_source(config_file, repo_path)` so target `.env` /
    `.alastor.yaml` / `config.yaml` files are NEVER loaded, and parses only safe JSON
    defaults outside the target repository.
    """
    safe_cfg = assert_safe_config_source(config_file, repo_path)
    if not os.path.isfile(safe_cfg):
        raise ValueError(f"Configuration file not found: {config_file}")
    if _is_dotenv_filename(safe_cfg):
        raise HostileRepoError(f"Refused loading dotenv file as ALASTOR config: {config_file}")
    if os.path.getsize(safe_cfg) > 1_000_000:
        raise ValueError("Configuration file exceeds 1MB limit")
    if safe_cfg.lower().endswith(".json"):
        with open(safe_cfg, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("External JSON configuration must be an object")
        return data
    return {}


def _is_strictly_inside_without_links(candidate_path: str, real_repo: str) -> bool:
    abs_cand = os.path.abspath(candidate_path)
    try:
        if os.path.commonpath([real_repo, abs_cand]) != real_repo:
            return False
    except ValueError:
        return False
    rel = os.path.relpath(abs_cand, real_repo)
    if rel in (".", "") or rel.startswith(".."):
        return False
    cursor = real_repo
    for part in rel.split(os.sep):
        if not part or part == ".":
            continue
        cursor = os.path.join(cursor, part)
        if os.path.lexists(cursor) and is_link_or_junction(cursor):
            return False
    real_cand = os.path.realpath(abs_cand)
    try:
        return os.path.commonpath([real_repo, real_cand]) == real_repo and real_cand != real_repo
    except ValueError:
        return False


def _validate_external_report_file(raw_report: str, real_repo: str) -> Tuple[str, bool]:
    cleaned = _validate_clean_path_arg(raw_report, "fusion_report")
    if _has_traversal_segment(cleaned):
        raise ValueError(f"Path traversal '..' rejected in fusion report path: {raw_report}")
    cand = cleaned if os.path.isabs(cleaned) else os.path.join(real_repo, cleaned)
    if not os.path.exists(cand) and not os.path.isabs(cleaned):
        cand_cwd = os.path.abspath(cleaned)
        if os.path.exists(cand_cwd):
            cand = cand_cwd
    real_cand = os.path.realpath(cand)
    if _is_dotenv_filename(real_cand):
        raise ValueError(f"Refused reading restricted .env file as fusion report: {raw_report}")
    if not os.path.isfile(real_cand):
        raise ValueError(f"Fusion report file not found: {raw_report}")
    if os.path.getsize(real_cand) > _MAX_REPORT_BYTES:
        raise ValueError(f"Fusion report exceeds 50MB limit: {raw_report}")
    inside_repo = _is_strictly_inside_without_links(cand, real_repo)
    return real_cand, inside_repo


def _build_sarif_2_1_dict(findings: List[Finding]) -> Dict[str, Any]:
    sarif_rules: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []
    for raw_f in findings:
        f = scrub_finding_secrets(raw_f, clear_raw_secret=True)
        first_node = f.path_nodes[0] if f.path_nodes else {"filepath": "workspace", "start_line": 1}
        bfl_fp = (
            f.best_fix_location.filepath
            if f.best_fix_location and f.best_fix_location.filepath
            else str(first_node.get("filepath") or "workspace")
        )
        bfl_ln = (
            max(1, int(f.best_fix_location.line))
            if f.best_fix_location and f.best_fix_location.line
            else max(1, int(first_node.get("start_line") or 1))
        )
        if f.rule_id not in sarif_rules:
            sarif_rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title[:80],
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.plain_english_summary or f.title},
                "help": {"text": f.remediation or "Apply recommended fix."},
                "properties": {
                    "cwe": f.cwe_id,
                    "owasp": f.owasp_category,
                    "engine": f.scan_engine,
                    "security-severity": str(f.cvss_score or 7.0),
                },
            }
        thread_locations = [
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(n.get("filepath") or bfl_fp)},
                        "region": {"startLine": max(1, int(n.get("start_line") or 1))},
                    },
                    "message": {"text": f"{n.get('name') or n.get('label')}: {n.get('code') or ''}"},
                }
            }
            for n in (f.path_nodes or [])
            if isinstance(n, dict)
        ]
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": "error" if f.severity in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": f"{f.title} — {f.description}".strip(" —")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": bfl_fp},
                            "region": {"startLine": bfl_ln},
                        }
                    }
                ],
                "codeFlows": [{"threadFlows": [{"locations": thread_locations}]}] if thread_locations else [],
                "properties": {
                    "finding_id": f.id,
                    "severity": f.severity,
                    "source_engine": f.source_engine or "ALASTOR",
                    "corroborated_by": list(f.corroborated_by or []),
                    "reachability_status": f.reachability_status,
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ALASTOR SAST++++++ CPG & ASPM Engine",
                        "version": "5.0.0",
                        "rules": list(sarif_rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def _write_scan_artifact(
    out_dir: str,
    output_format: Literal["json", "sarif", "docx", "pdf"],
    repo_path: str,
    run_id: str,
    commit_sha: str,
    status: str,
    go_live_decision: str,
    corroborated_count: int,
    findings: List[Finding],
    vault_dir: str,
) -> List[str]:
    clean_out = _validate_clean_path_arg(out_dir, "out_dir")
    if _has_traversal_segment(clean_out):
        raise ValueError(f"Path traversal '..' rejected in out_dir: {out_dir}")
    if os.path.lexists(clean_out) and is_link_or_junction(clean_out):
        raise HostileRepoError(f"Refusing to write artifacts through symlink/junction out_dir: {out_dir}")
    real_out = os.path.realpath(clean_out)
    os.makedirs(real_out, exist_ok=True)

    safe_findings = [scrub_finding_secrets(f, clear_raw_secret=True) for f in findings]

    if output_format == "json":
        target_file = os.path.join(real_out, "findings.json")
        payload = {
            "run_id": run_id,
            "repo_path": repo_path,
            "commit_sha": commit_sha,
            "status": status,
            "go_live_decision": go_live_decision,
            "total_findings": len(safe_findings),
            "corroborated_count": corroborated_count,
            "findings": [f.model_dump() for f in safe_findings],
        }
        with open(target_file, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return [os.path.realpath(target_file)]

    if output_format == "sarif":
        target_file = os.path.join(real_out, "alastor.sarif.json")
        sarif_doc = _build_sarif_2_1_dict(safe_findings)
        with open(target_file, "w", encoding="utf-8") as fh:
            json.dump(sarif_doc, fh, indent=2)
        return [os.path.realpath(target_file)]

    # DOCX / PDF Go-Live SAR Dossier using isolated EnterpriseManager state
    with tempfile.TemporaryDirectory() as tmp_em_dir:
        local_em = EnterpriseManager()
        local_em.data_dir = tmp_em_dir
        local_em.state_file = os.path.join(tmp_em_dir, "integration_hub_state.json")
        local_em.scan_cache_file = os.path.join(tmp_em_dir, "scan_history_cache.json")
        local_em.vault_dir = vault_dir
        local_em.pasta_engine = PastaThreatEngine(vault_dir=vault_dir)

        app_tree, _, all_nodes, all_edges, comm_map = _build_cpg_for_repo(repo_path)
        api_ops = ApiOperationsEngine().analyze_workspace_api_operations(repo_path, safe_findings)
        s8_chains = synthesize_exploit_chains(
            target_dir=repo_path,
            findings=safe_findings,
            api_ops=api_ops,
            community_map=comm_map,
            use_ai=False,
            max_chains=10,
        )
        sast_plus = local_em.get_sast_plus_suite(repo_path, safe_findings, community_map=comm_map)
        pasta = sast_plus.pasta_assessment or local_em.pasta_engine.evaluate_pasta(
            target_dir=repo_path,
            findings=safe_findings,
            app_tree=app_tree,
            api_ops=api_ops,
            exploit_chains=s8_chains.chains,
        )
        raci = local_em.get_raci_governance(safe_findings)
        crit = sum(1 for f in safe_findings if f.severity == "CRITICAL")
        high = sum(1 for f in safe_findings if f.severity == "HIGH")
        med = sum(1 for f in safe_findings if f.severity == "MEDIUM")
        low = sum(1 for f in safe_findings if f.severity in ("LOW", "INFO"))
        metrics = MetricsResponse(
            total_nodes=len(all_nodes),
            total_edges=len(all_edges),
            total_findings=len(safe_findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            total_app_files=app_tree.total_files,
            categories=app_tree.category_counts,
            tech_stack=app_tree.detected_tech_stack,
            graph_engine_mode="EMBEDDED_SQLITE",
            communities_count=comm_map.total_communities,
        )
        ev_replays = ExploitVerificationEngine(vault_dir=vault_dir).list_replays(repo_path).replays
        app_name = pasta.application_name or os.path.basename(repo_path) or "alastor_target"
        bundle = sanitize_bundle_for_export(
            SarReportBundle(
                application_name=app_name,
                project_path=repo_path,
                generated_at=pasta.generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                pasta=pasta,
                sast_plus=sast_plus,
                raci=raci,
                metrics=metrics,
                findings=safe_findings,
                exploit_chains=s8_chains.chains,
                ev_replays=ev_replays,
            )
        )
        slug = re.sub(r"[^A-Za-z0-9_-]+", "_", app_name).strip("_") or "alastor_target"
        ext = "docx" if output_format == "docx" else "pdf"
        target_file = os.path.join(real_out, f"ALASTOR_SAR_GoLive_{slug}.{ext}")
        raw_bytes = (
            generate_sar_docx_bytes(bundle)
            if output_format == "docx"
            else generate_sar_pdf_bytes(bundle)
        )
        with open(target_file, "wb") as fh:
            fh.write(raw_bytes)
        return [os.path.realpath(target_file)]


def _load_findings_for_repo_or_run(
    store: CheckpointStore,
    real_repo: str,
    run_id: Optional[str] = None,
) -> Tuple[Optional[str], List[Finding]]:
    resolved_run_id = run_id
    if resolved_run_id is None:
        runs = store.list_runs(repo_path=real_repo, limit=1)
        if runs:
            resolved_run_id = runs[0].run_id

    if resolved_run_id:
        for stage_name in ("S3_FUSION", "S2_SECRETS_SCA", "S1_RULES"):
            ckpt = store.get_stage(resolved_run_id, stage_name)
            if ckpt is None or ckpt[0].status != "COMPLETED":
                continue
            payload = ckpt[1]
            raw_list = payload.get("findings") if isinstance(payload, dict) else payload
            if isinstance(raw_list, list):
                return resolved_run_id, [Finding.model_validate(item) for item in raw_list]

    # Deterministic in-memory fallback scan (zero writes to checkpoints or target repo)
    with tempfile.TemporaryDirectory() as tmp_dir:
        gstore = EmbeddedGraphStore(os.path.join(tmp_dir, "cpg.db"))
        try:
            app_tree, scanned_files, all_nodes, all_edges, _ = _build_cpg_for_repo(real_repo)
            gstore.init_schema()
            gstore.ingest_app_tree(app_tree)
            if all_nodes or all_edges:
                gstore.ingest_cpg(all_nodes, all_edges)
            raw_sast = gstore.run_cpg_rules(scanned_files=scanned_files) if scanned_files else []
            local_em = EnterpriseManager()
            local_em.data_dir = tmp_dir
            local_em.state_file = os.path.join(tmp_dir, "state.json")
            local_em.scan_cache_file = os.path.join(tmp_dir, "cache.json")
            for q in local_em.queries:
                if q.id == "SCA-2-LIVE-CVE-LOCKFILE":
                    q.enabled = False
            sca_iac = local_em.run_sca_and_iac_scanners(real_repo)
            enriched = local_em.enrich_findings(list(raw_sast) + list(sca_iac))
            return resolved_run_id, [scrub_finding_secrets(f, clear_raw_secret=True) for f in enriched]
        finally:
            gstore.close()


# ---------------------------------------------------------------------------
# Public SDK API
# ---------------------------------------------------------------------------
def doctor(vault_dir: Optional[str] = None, check_neo4j: bool = False) -> DoctorReport:
    """Inspects runtime readiness across Python, 18 parsers, GraphStore, git, docker, vault, and BYOK presence."""
    vdir = _resolve_vault_dir(vault_dir)
    py_ver = platform.python_version()

    caps = list_language_capabilities()
    parsers_ready = caps.ready_parsers
    parsers_total = caps.total_languages

    git_available = shutil.which("git") is not None
    docker_available = shutil.which("docker") is not None

    vault_writable = False
    vault_detail = "writable"
    try:
        os.makedirs(vdir, exist_ok=True)
        probe_path = os.path.join(vdir, f".doctor_probe_{uuid.uuid4().hex[:8]}")
        with open(probe_path, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe_path)
        vault_writable = True
    except OSError as exc:
        vault_writable = False
        vault_detail = f"unwritable: {exc}"

    graph_backend = "EMBEDDED_SQLITE_WAL"
    if check_neo4j:
        neo = Neo4jClient()
        try:
            if neo.verify_connectivity_and_apoc():
                graph_backend = "NEO4J"
        except Exception:
            graph_backend = "EMBEDDED_SQLITE_WAL"
        finally:
            neo.close()
    elif GraphStoreManager._instance is not None and GraphStoreManager._instance._active_store is not None:
        if GraphStoreManager._instance._active_store.mode == "NEO4J_APOC":
            graph_backend = "NEO4J"

    # Boolean presence only — NEVER read or expose raw or masked keys
    pub_ai = FrontierAiEngine(vault_dir=vdir).get_public_config()
    has_key = bool(pub_ai.has_api_key)

    checks: List[DoctorCheckItem] = [
        DoctorCheckItem(
            name="python",
            status="OK" if tuple(int(p) for p in py_ver.split(".")[:2]) >= (3, 11) else "FAIL",
            detail=f"Python {py_ver}",
        ),
        DoctorCheckItem(
            name="parsers",
            status="OK" if parsers_ready >= parsers_total and parsers_total >= 18 else "WARN",
            detail=f"{parsers_ready}/{parsers_total} tree-sitter language parsers ready",
        ),
        DoctorCheckItem(
            name="graph_store",
            status="OK",
            detail=f"Active backend: {graph_backend}",
        ),
        DoctorCheckItem(
            name="git",
            status="OK" if git_available else "WARN",
            detail="git available on PATH" if git_available else "git not found on PATH",
        ),
        DoctorCheckItem(
            name="docker",
            status="OK" if docker_available else "WARN",
            detail="docker available for --sandbox" if docker_available else "docker not found (optional)",
        ),
        DoctorCheckItem(
            name="vault",
            status="OK" if vault_writable else "FAIL",
            detail=f"Vault directory {vault_detail}",
        ),
        DoctorCheckItem(
            name="byok_ai",
            status="OK",
            detail=f"provider={pub_ai.provider}, has_key={has_key}",
        ),
    ]

    if not vault_writable or parsers_ready == 0:
        overall: Literal["READY", "DEGRADED", "ERROR"] = "ERROR"
    elif parsers_ready < parsers_total or not git_available:
        overall = "DEGRADED"
    else:
        overall = "READY"

    return DoctorReport(
        overall_status=overall,
        python_version=py_ver,
        parsers_ready=parsers_ready,
        parsers_total=parsers_total,
        graph_backend=graph_backend,
        git_available=git_available,
        docker_available=docker_available,
        vault_path=vdir,
        vault_writable=vault_writable,
        checks=checks,
    )


def estimate(repo_path: str, vault_dir: Optional[str] = None) -> EstimateReport:
    """Estimates file count, LOC, language breakdown, repo kinds, and runtime/AI cost at $0 spend."""
    _ = _resolve_vault_dir(vault_dir)
    real_repo = _resolve_existing_repo_dir(repo_path)

    scanned_files, telemetry = scan_directory_with_telemetry(real_repo)
    total_files = len(scanned_files)
    total_loc = sum(len(sf.content_bytes.splitlines()) for sf in scanned_files)
    skipped_files = (
        telemetry.gitignore_excluded
        + telemetry.generated_excluded
        + telemetry.tests_excluded
        + telemetry.symlinks_dropped
        + telemetry.build_dirs_excluded
    )

    # Check hostile target configs without ever reading or executing them
    _hostile_configs = find_hostile_target_configs(real_repo)

    cb = classify_repo_kinds_and_baselines(
        target_dir=real_repo,
        scanned_files=scanned_files,
        active_findings=[],
        api_ops=None,
        ai_available=False,
    )

    est_seconds = round(max(0.1, total_files * 0.08 + total_loc * 0.0005), 2)
    est_tokens = int(total_files * 150 + total_loc * 0.6) if total_files > 0 else 0
    est_cost_usd = round(est_tokens * 0.000003, 4)
    rec_profile = "fast-ci" if (total_files > 500 or total_loc > 50000) else "deterministic"

    return EstimateReport(
        project_path=real_repo,
        total_files=total_files,
        total_loc=total_loc,
        languages=dict(telemetry.languages_breakdown),
        skipped_files=skipped_files,
        estimated_deterministic_seconds=est_seconds,
        estimated_ai_tokens=est_tokens,
        estimated_ai_cost_usd=est_cost_usd,
        recommended_profile=rec_profile,
        repo_kind_hints=list(cb.repo_kinds),
    )


def scan(options: ScanOptions) -> ScanResult:
    """Runs deterministic CPG/SAST/SCA/IaC/Secret + Scanner Fusion + PASTA scan with SQLite checkpoints."""
    if options.config_file:
        _load_safe_external_config(options.config_file, options.repo)

    real_repo = _resolve_existing_repo_dir(options.repo)
    vdir = _resolve_vault_dir(options.vault_dir)
    commit_sha = get_repo_commit_sha(real_repo)

    in_repo_reports: List[str] = []
    out_repo_imported: List[Finding] = []
    for rp in options.fusion_reports:
        resolved_rp, inside_repo = _validate_external_report_file(rp, real_repo)
        if inside_repo:
            in_repo_reports.append(os.path.relpath(resolved_rp, real_repo).replace("\\", "/"))
        else:
            with open(resolved_rp, "r", encoding="utf-8", errors="replace") as fh:
                report_text = fh.read()
            _, parsed = parse_external_scanner_report(report_text, repo_root=real_repo)
            out_repo_imported.extend(parsed)

    store = CheckpointStore(vdir)
    try:
        runner = FleetRunner(vault_dir=vdir, checkpoint_store=store)
        spec = FleetRepoSpec(
            repo=real_repo,
            app_group=options.app_group,
            fusion_reports=in_repo_reports,
            profile=options.profile,
        )
        repo_res, findings = runner.run_single_repo(
            spec=spec,
            resume=options.resume,
            stop_after=options.stop_after,
            run_id=options.run_id,
        )
    finally:
        store.close()

    if repo_res.status == "FAILED":
        return ScanResult(
            exit_code=2,
            run_id=repo_res.run_id,
            repo_path=real_repo,
            commit_sha=commit_sha,
            status=repo_res.status,
            go_live_decision="NO_GO_HOLD_RELEASE",
            total_findings=0,
            corroborated_count=0,
            resumed_stages=list(repo_res.resumed_stages),
            findings=[],
            output_files=[],
            error=repo_res.error or "Scan failed",
        )

    corroborated_count = repo_res.corroborated_count
    go_live_decision = repo_res.go_live_decision
    extra_external = list(out_repo_imported) + list(options.injected_findings)
    if extra_external:
        fusion_resp = fuse_findings_with_cpg(
            imported=extra_external,
            native_findings=findings,
            graph_store=None,
            project_path=real_repo,
            run_s6_verify=True,
            correlate_cpg=True,
        )
        findings = [scrub_finding_secrets(f, clear_raw_secret=True) for f in fusion_resp.findings]
        corroborated_count += fusion_resp.corroborated_count
        if go_live_decision != "NO_GO_HOLD_RELEASE" and _normalize_stop_after(options.stop_after) is None:
            pasta_resp = PastaThreatEngine(vault_dir=vdir).evaluate_pasta(
                target_dir=real_repo,
                findings=findings,
            )
            go_live_decision = _map_pasta_verdict_to_fleet(pasta_resp.golive_verdict)
            active = [f for f in findings if f.triage_status not in ("NOT_EXPLOITABLE", "RESOLVED")]
            if any(f.ev_status == "RUNTIME_EXPLOIT_CONFIRMED" or f.severity == "CRITICAL" for f in active):
                go_live_decision = "NO_GO_HOLD_RELEASE"

    safe_findings = [scrub_finding_secrets(f, clear_raw_secret=True) for f in findings]
    active_findings = [f for f in safe_findings if f.triage_status not in ("NOT_EXPLOITABLE", "RESOLVED")]

    output_files: List[str] = []
    if options.out_dir:
        output_files = _write_scan_artifact(
            out_dir=options.out_dir,
            output_format=options.output_format,
            repo_path=real_repo,
            run_id=repo_res.run_id,
            commit_sha=commit_sha,
            status=repo_res.status,
            go_live_decision=go_live_decision,
            corroborated_count=corroborated_count,
            findings=safe_findings,
            vault_dir=vdir,
        )

    threshold_breached = False
    if options.fail_on_severity:
        thresh_rank = _SEVERITY_RANK[options.fail_on_severity]
        threshold_breached = any(
            _SEVERITY_RANK.get(f.severity, 0) >= thresh_rank for f in active_findings
        )

    exit_code = 1 if (threshold_breached or go_live_decision == "NO_GO_HOLD_RELEASE") else 0

    return ScanResult(
        exit_code=exit_code,
        run_id=repo_res.run_id,
        repo_path=real_repo,
        commit_sha=commit_sha,
        status=repo_res.status,
        go_live_decision=go_live_decision,
        total_findings=len(active_findings),
        corroborated_count=corroborated_count,
        resumed_stages=list(repo_res.resumed_stages),
        findings=safe_findings,
        output_files=output_files,
        error=None,
    )


def _read_confined_host_file(raw_path: str, label: str = "file") -> str:
    """Reads a host file confined to its canonical parent directory, rejecting traversal, symlinks, and .env."""
    cleaned = _validate_clean_path_arg(raw_path, label)
    if _has_traversal_segment(cleaned):
        raise ValueError(f"Path traversal '..' rejected in {label}: {raw_path}")
    abs_target = os.path.abspath(cleaned)
    parent_real = os.path.realpath(os.path.dirname(abs_target))
    real_target = os.path.realpath(abs_target)
    if os.path.commonpath([parent_real, real_target]) != parent_real:
        raise ValueError(f"Symlink or path escape rejected in {label}: {raw_path}")
    if is_link_or_junction(abs_target) or _is_dotenv_filename(real_target):
        raise HostileRepoError(f"Refused reading restricted or symlinked file for {label}: {raw_path}")
    if not os.path.isfile(real_target):
        raise ValueError(f"File not found for {label}: {raw_path}")
    if os.path.getsize(real_target) > _MAX_REPORT_BYTES:
        raise ValueError(f"File exceeds 50MB limit for {label}: {raw_path}")
    with open(real_target, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def run_fleet(
    options: FleetOptions,
    workspace_confinement_fn: Optional[Callable[[str], str]] = None,
) -> FleetRunResponse:
    """Runs multi-repository fleet analysis from a CSV manifest and/or FleetRepoSpec list."""
    vdir = _resolve_vault_dir(options.vault_dir)
    merged_csv = options.csv_content

    if options.csv_path:
        file_csv = _read_confined_host_file(options.csv_path, label="csv_path")
        merged_csv = f"{file_csv}\n{merged_csv}" if merged_csv else file_csv

    store = CheckpointStore(vdir)
    try:
        runner = FleetRunner(
            vault_dir=vdir,
            checkpoint_store=store,
            workspace_confinement_fn=workspace_confinement_fn,
        )
        req = FleetRunRequest(
            manifest_name=options.manifest_name,
            csv_content=merged_csv,
            repos=list(options.repos),
            group_by_app=options.group_by_app,
            resume=options.resume,
            max_workers=options.max_workers,
            stop_after=options.stop_after,
        )
        return runner.run_fleet(req)
    finally:
        store.close()


def inject_findings(
    repo_path: str,
    external_findings: List[Finding],
    native_findings: Optional[List[Finding]] = None,
    run_s6_verify: bool = True,
) -> ScannerFusionResponse:
    """Programmatically injects typed external `Finding` objects through CPG fusion & S6 verification."""
    real_repo = _resolve_existing_repo_dir(repo_path)
    return fuse_findings_with_cpg(
        imported=list(external_findings),
        native_findings=list(native_findings or []),
        graph_store=None,
        project_path=real_repo,
        run_s6_verify=run_s6_verify,
        correlate_cpg=True,
    )


def fuse_scanner_report(
    repo_path: str,
    report_json: str,
    source_format: Optional[ScannerFormatType] = None,
    native_findings: Optional[List[Finding]] = None,
    graph_store: Optional[Any] = None,
    run_s6_verify: bool = False,
    correlate_cpg: bool = True,
) -> ScannerFusionResponse:
    """Parses any of the 6 supported scanner formats, scrubs secrets, and fuses with CPG findings."""
    real_repo = _resolve_existing_repo_dir(repo_path)
    det_fmt, imported = parse_external_scanner_report(
        report_json,
        source_format=source_format,
        repo_root=real_repo,
    )
    return fuse_findings_with_cpg(
        imported=imported,
        native_findings=list(native_findings or []),
        graph_store=graph_store,
        project_path=real_repo,
        run_s6_verify=run_s6_verify,
        detected_format=det_fmt,
        correlate_cpg=correlate_cpg,
        imported_raw_count=len(imported),
    )


def remediate(
    repo_path: str,
    run_id: Optional[str] = None,
    mode: Literal["report-only", "fix"] = "report-only",
    finding_id: Optional[str] = None,
    vault_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Proposes remediation plans (`mode="report-only"`) or applies deterministic BFL patches
    (`mode="fix"`) strictly after verifying host-produced scan provenance in `CheckpointStore`.
    """
    real_repo = _resolve_existing_repo_dir(repo_path)
    vdir = _resolve_vault_dir(vault_dir)
    if mode not in ("report-only", "fix"):
        raise ValueError(f"Unsupported remediation mode '{mode}'; expected 'report-only' or 'fix'")

    store = CheckpointStore(vdir)
    try:
        provenance_verified = False
        if mode == "fix":
            if not run_id or not run_id.strip():
                raise HostileRepoError("remediate --mode fix requires a valid host-produced --run-id")
            current_sha = get_repo_commit_sha(real_repo)
            ok, reason = store.verify_host_provenance(run_id.strip(), real_repo, current_sha)
            if not ok:
                raise HostileRepoError(f"Host provenance verification failed: {reason}")
            provenance_verified = True
        elif run_id and run_id.strip():
            current_sha = get_repo_commit_sha(real_repo)
            ok, _ = store.verify_host_provenance(run_id.strip(), real_repo, current_sha)
            provenance_verified = ok

        resolved_run_id, findings = _load_findings_for_repo_or_run(store, real_repo, run_id=run_id)
    finally:
        store.close()

    active_findings = [
        scrub_finding_secrets(f, clear_raw_secret=True)
        for f in findings
        if f.triage_status not in ("NOT_EXPLOITABLE", "RESOLVED")
    ]
    if finding_id:
        active_findings = [f for f in active_findings if f.id == finding_id]

    if mode == "report-only":
        plans: List[Dict[str, Any]] = []
        for f in active_findings:
            prev = preview_finding_remediation(f, [real_repo])
            if prev is None:
                continue
            plans.append(
                {
                    "finding_id": f.id,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "filepath": prev["filepath"],
                    "target_line": prev["target_line"],
                    "can_auto_patch": bool(prev["can_auto_patch"]),
                    "fix_summary": scrub_raw_secrets_text(str(prev["fix_summary"])),
                    "expected_sha256": prev["expected_sha256"],
                }
            )
        return {
            "mode": "report-only",
            "repo_path": real_repo,
            "run_id": resolved_run_id,
            "provenance_verified": provenance_verified,
            "total_findings": len(active_findings),
            "plans_count": len(plans),
            "auto_patchable_count": sum(1 for p in plans if p["can_auto_patch"]),
            "applied_count": 0,
            "plans": plans,
        }

    patch_vault = os.path.join(vdir, "patches")
    batch_res = batch_apply_workspace_patches(
        findings=active_findings,
        allowed_roots=[real_repo],
        patch_vault_root=patch_vault,
    )
    return {
        "mode": "fix",
        "repo_path": real_repo,
        "run_id": resolved_run_id,
        "provenance_verified": True,
        "total_findings": len(active_findings),
        "applied_count": int(batch_res["applied_count"]),
        "skipped_count": int(batch_res["skipped_count"]),
        "applied_patch_ids": list(batch_res["applied_patch_ids"]),
        "patched_files": list(batch_res["patched_files"]),
        "applied_finding_ids": list(batch_res["applied_finding_ids"]),
        "unified_diff": scrub_raw_secrets_text(str(batch_res["unified_diff"])),
    }


def validate(
    repo_path: str,
    run_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    patched_code: Optional[str] = None,
    vault_dir: Optional[str] = None,
    use_ai: bool = False,
) -> Dict[str, Any]:
    """Runs the S11 dual-verified 3-persona patch validation panel on proposed remediation patches."""
    real_repo = _resolve_existing_repo_dir(repo_path)
    vdir = _resolve_vault_dir(vault_dir)

    store = CheckpointStore(vdir)
    try:
        resolved_run_id, findings = _load_findings_for_repo_or_run(store, real_repo, run_id=run_id)
    finally:
        store.close()

    active_findings = [
        scrub_finding_secrets(f, clear_raw_secret=True)
        for f in findings
        if f.triage_status not in ("NOT_EXPLOITABLE", "RESOLVED")
    ]
    if finding_id:
        active_findings = [f for f in active_findings if f.id == finding_id]

    ai_engine = FrontierAiEngine(vault_dir=vdir) if use_ai else None
    results: List[Dict[str, Any]] = []
    approved_count = 0
    revisions_count = 0
    rejected_count = 0

    for f in active_findings:
        prev = preview_finding_remediation(f, [real_repo])
        if prev is None:
            continue
        proposed = patched_code if patched_code is not None else str(prev["patched_content"])
        req = PatchPanelValidateRequest(
            project_path=real_repo,
            finding_id=f.id,
            filepath=str(prev["filepath"]),
            original_code=str(prev["original_content"]),
            proposed_code=proposed,
            cwe_id=f.cwe_id,
            use_ai=bool(use_ai and ai_engine is not None and ai_engine.has_usable_credentials()),
        )
        panel_resp = validate_patch_with_panel(
            target_dir=real_repo,
            req=req,
            finding=f,
            ai_engine=ai_engine,
        )
        if panel_resp.overall_verdict == "APPROVED":
            approved_count += 1
        elif panel_resp.overall_verdict == "REVISIONS_REQUIRED":
            revisions_count += 1
        else:
            rejected_count += 1

        item = panel_resp.model_dump()
        item["finding_id"] = f.id
        item["filepath"] = str(prev["filepath"])
        results.append(item)

    if not results:
        overall_status = "CLEAN_NO_PATCHES_REQUIRED"
    elif rejected_count > 0:
        overall_status = "REJECTED"
    elif revisions_count > 0:
        overall_status = "REVISIONS_REQUIRED"
    else:
        overall_status = "APPROVED"

    return {
        "repo_path": real_repo,
        "run_id": resolved_run_id,
        "overall_status": overall_status,
        "validated_count": len(results),
        "approved_count": approved_count,
        "revisions_required_count": revisions_count,
        "rejected_count": rejected_count,
        "results": results,
    }


def ev_replay(
    repo_path: str,
    target_url: Optional[str] = None,
    replay_ids: Optional[List[str]] = None,
    allow_private_staging_host: bool = False,
    authorized_staging_hosts: Optional[List[str]] = None,
    vault_dir: Optional[str] = None,
    http_client: Optional[Any] = None,
) -> EvReplayResponse:
    """Replays persisted EV bundles post-fix to verify remediation (`FIXED_VERIFIED` vs `STILL_VULNERABLE`)."""
    real_repo = _resolve_existing_repo_dir(repo_path)
    vdir = _resolve_vault_dir(vault_dir)
    ev = ExploitVerificationEngine(vault_dir=vdir)
    req = EvReplayRequest(
        project_path=real_repo,
        target_url=target_url,
        replay_ids=replay_ids,
        allow_private_staging_host=allow_private_staging_host,
        authorized_staging_hosts=list(authorized_staging_hosts or []),
    )
    return ev.replay_confirmed(real_repo, req, http_client=http_client)


def gc(
    older_than_days: int = 30,
    keep_last: int = 20,
    dry_run: bool = False,
    vault_dir: Optional[str] = None,
) -> GcReport:
    """Prunes expired SQLite scan checkpoints and orphaned temp CPG workspaces."""
    vdir = _resolve_vault_dir(vault_dir)
    store = CheckpointStore(vdir)
    try:
        return store.gc(
            older_than_days=older_than_days,
            keep_last=keep_last,
            dry_run=dry_run,
            temp_workspaces_parent=os.path.join(vdir, "_fleet_cpg_tmp"),
        )
    finally:
        store.close()


__all__ = [
    "FleetOptions",
    "ScanOptions",
    "ScanResult",
    "doctor",
    "estimate",
    "ev_replay",
    "fuse_scanner_report",
    "gc",
    "inject_findings",
    "remediate",
    "run_fleet",
    "scan",
    "validate",
]
