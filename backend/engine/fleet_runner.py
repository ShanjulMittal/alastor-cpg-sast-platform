"""
ALASTOR v5.0 Pillar 4 — CSV Batch Fleet Runner, Stage Checkpointing & App-Group Go-Live Rollups.

Executes ALASTOR's deterministic CPG, SAST/SCA/IaC, Secret, Universal Scanner Fusion,
S6 Adversarial Verification, S8 Exploit Chain, and PASTA Go-Live Gate pipeline across
multi-repository fleets with:
  - Hardened CSV manifest parsing (CSV formula injection, option injection & URL guards)
  - Hostile-repo isolation (`validate_clone_url`, `get_repo_commit_sha`, confined paths,
    never loading target `.env`/`.alastor.yaml`/`config.yaml`)
  - Per-repo isolated `EmbeddedGraphStore` instances (thread-safe across bounded workers)
  - SQLite WAL SHA-256 stage checkpoints (`--resume` & `--stop-after`)
  - Per-repo failure isolation & fail-closed `FleetAppGroupRollup` Go-Live decisions
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timezone
import io
import logging
import os
import re
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from compiler.app_tree import AppTreeAnalyzer
from compiler.ast_parser import ASTNormalizer
from compiler.call_graph_builder import CallGraphBuilder
from compiler.cfg_builder import CFGBuilder
from compiler.dfg_builder import DFGBuilder
from compiler.scanner import ScannedFile, scan_directory_with_telemetry
from database.checkpoint_store import CheckpointStore
from database.graph_store import EmbeddedGraphStore
from engine.adversarial_verifier import verify_findings_adversarially
from engine.api_operations_engine import ApiOperationsEngine
from engine.community_detector import detect_code_communities
from engine.enterprise_manager import (
    EnterpriseManager,
    compute_best_fix_location,
    infer_language_from_filepath,
    populate_plain_english_and_raci,
)
from engine.exploit_chain_engine import synthesize_exploit_chains
from engine.exploit_verification_engine import ExploitVerificationEngine
from engine.frontier_ai_engine import scrub_raw_secrets_text
from engine.hostile_repo_guard import (
    HostileRepoError,
    find_hostile_target_configs,
    get_repo_commit_sha,
    is_link_or_junction,
    safe_cleanup_workspace,
    validate_clone_url,
)
from engine.pasta_threat_engine import PastaThreatEngine
from engine.scanner_fusion_engine import (
    fuse_findings_with_cpg,
    parse_external_scanner_report,
    scrub_finding_secrets,
)
from engine.secret_validator_engine import SecretValidatorEngine
from models import (
    AppTreeSummary,
    CPGEdge,
    CPGNode,
    CommunityMapResponse,
    Finding,
    FleetAppGroupRollup,
    FleetRepoResult,
    FleetRepoSpec,
    FleetRunRequest,
    FleetRunResponse,
)

logger = logging.getLogger("cpg-sast.fleet-runner")

_MAX_REPORT_BYTES = 50 * 1024 * 1024
_WIN_DRIVE_RX = re.compile(r"^[A-Za-z]:[\\/]")
_CSV_FORMULA_PREFIXES = ("=", "+", "@", "\t")

_STAGE_ORDER: Tuple[str, ...] = (
    "S0_CPG",
    "S1_RULES",
    "S2_SECRETS_SCA",
    "S3_FUSION",
    "S6_VERIFY",
    "S8_CHAINS",
    "S9_REPORTS",
)

_STOP_AFTER_ALIASES: Dict[str, str] = {
    "S0": "S0_CPG",
    "S0_CPG": "S0_CPG",
    "S1": "S1_RULES",
    "S1_RULES": "S1_RULES",
    "S2": "S2_SECRETS_SCA",
    "S2_SECRETS": "S2_SECRETS_SCA",
    "S2_SECRETS_SCA": "S2_SECRETS_SCA",
    "S3": "S3_FUSION",
    "S3_FUSION": "S3_FUSION",
    "S6": "S6_VERIFY",
    "S6_VERIFY": "S6_VERIFY",
    "S8": "S8_CHAINS",
    "S8_CHAINS": "S8_CHAINS",
    "S9": "S9_REPORTS",
    "S9_REPORTS": "S9_REPORTS",
    "PASTA": "S9_REPORTS",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _has_control_chars(val: str) -> bool:
    return any(ch in val for ch in ("\r", "\n", "\x00"))


def _has_traversal_segment(path_str: str) -> bool:
    parts = [p for p in re.split(r"[\\/]+", path_str.strip()) if p]
    return any(p == ".." for p in parts)


def _is_remote_repo_syntax(repo_val: str) -> bool:
    low = repo_val.lower()
    if "://" in repo_val:
        return True
    if low.startswith(("ext::", "fd::", "git::")):
        return True
    if "::" in repo_val and not _WIN_DRIVE_RX.match(repo_val):
        return True
    if "@" in repo_val and ":" in repo_val and "\\" not in repo_val and not _WIN_DRIVE_RX.match(repo_val):
        return True
    return False


def _validate_csv_text_field(val: str, label: str, allow_leading_dash: bool = False) -> str:
    if _has_control_chars(val):
        raise ValueError(f"CSV field '{label}' contains forbidden control characters")
    cleaned = val.strip()
    if not cleaned:
        return ""
    if cleaned.startswith(_CSV_FORMULA_PREFIXES) or (not allow_leading_dash and cleaned.startswith("-")):
        raise ValueError(f"CSV field '{label}' starts with forbidden formula/option prefix: {cleaned}")
    return cleaned


def _normalize_stop_after(stop_after: Optional[str]) -> Optional[str]:
    if stop_after is None:
        return None
    clean = str(stop_after).strip().upper()
    if not clean:
        return None
    resolved = _STOP_AFTER_ALIASES.get(clean)
    if resolved is None:
        raise ValueError(
            f"Unknown stop_after stage '{stop_after}'. Expected one of: {', '.join(_STAGE_ORDER)}"
        )
    return resolved


def parse_fleet_csv(csv_text: str) -> List[FleetRepoSpec]:
    """
    Parses a CSV fleet manifest (`repo,app_group,branch,fusion_reports,profile`)
    with strict validation against URL/option/formula/traversal injection.
    """
    if not isinstance(csv_text, str) or not csv_text.strip():
        raise ValueError("Fleet CSV manifest must be a non-empty string")

    non_comment_lines: List[str] = []
    for raw_line in csv_text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        non_comment_lines.append(raw_line)

    if not non_comment_lines:
        raise ValueError("Fleet CSV manifest contains no header or repository rows")

    reader = csv.DictReader(io.StringIO("\n".join(non_comment_lines)))
    if not reader.fieldnames:
        raise ValueError("Fleet CSV manifest is missing a header row")

    normalized_headers = [str(h).strip().lower() for h in reader.fieldnames if h is not None]
    if "repo" not in normalized_headers:
        raise ValueError("Fleet CSV manifest missing required 'repo' column")

    specs: List[FleetRepoSpec] = []
    for row_idx, raw_row in enumerate(reader, start=1):
        row: Dict[str, str] = {}
        for k, v in raw_row.items():
            if k is None:
                # Extra unkeyed trailing columns indicate malformed CSV
                if v:
                    raise ValueError(f"Malformed CSV row {row_idx}: unexpected extra columns")
                continue
            key_norm = str(k).strip().lower()
            val_str = str(v) if v is not None else ""
            if _has_control_chars(val_str):
                raise ValueError(f"CSV row {row_idx} field '{key_norm}' contains control characters")
            row[key_norm] = val_str.strip()

        raw_repo = row.get("repo", "")
        if not raw_repo:
            raise ValueError(f"CSV row {row_idx} has empty 'repo' value")
        if raw_repo.startswith("-") or raw_repo.startswith(_CSV_FORMULA_PREFIXES):
            raise ValueError(f"CSV row {row_idx} 'repo' starts with forbidden option/formula prefix")

        if _is_remote_repo_syntax(raw_repo):
            repo_clean = validate_clone_url(raw_repo)
        else:
            if _has_traversal_segment(raw_repo):
                raise ValueError(f"CSV row {row_idx} 'repo' contains disallowed '..' traversal segment")
            repo_clean = raw_repo

        app_group = _validate_csv_text_field(row.get("app_group", ""), "app_group") or "default"
        profile = _validate_csv_text_field(row.get("profile", ""), "profile") or "deterministic"

        raw_branch = row.get("branch", "")
        branch_clean: Optional[str] = None
        if raw_branch:
            branch_clean = _validate_csv_text_field(raw_branch, "branch")
            if any(ch.isspace() for ch in branch_clean) or ".." in branch_clean:
                raise ValueError(f"CSV row {row_idx} contains unsafe branch name '{branch_clean}'")

        raw_reports = row.get("fusion_reports", "")
        fusion_reports: List[str] = []
        if raw_reports:
            for part in re.split(r"[;|]", raw_reports):
                cleaned_rp = _validate_csv_text_field(part, "fusion_reports")
                if not cleaned_rp:
                    continue
                if _has_traversal_segment(cleaned_rp):
                    raise ValueError(
                        f"CSV row {row_idx} fusion_reports contains disallowed '..' traversal segment: {cleaned_rp}"
                    )
                fusion_reports.append(cleaned_rp)

        specs.append(
            FleetRepoSpec(
                repo=repo_clean,
                app_group=app_group,
                branch=branch_clean,
                fusion_reports=fusion_reports,
                profile=profile,
            )
        )

    return specs


def _build_cpg_for_repo(
    local_path: str,
) -> Tuple[AppTreeSummary, List[ScannedFile], List[CPGNode], List[CPGEdge], CommunityMapResponse]:
    app_tree = AppTreeAnalyzer(local_path).analyze()
    scanned_files, _ = scan_directory_with_telemetry(local_path)
    if not scanned_files:
        empty_comm = detect_code_communities([], [], app_tree, [], graph_engine_mode="EMBEDDED_SQLITE")
        return app_tree, [], [], [], empty_comm

    all_nodes: List[CPGNode] = []
    all_edges: List[CPGEdge] = []
    node_map: Dict[str, CPGNode] = {}
    file_nodes_map: Dict[str, List[CPGNode]] = {}
    func_params_map: Dict[str, List[CPGNode]] = {}
    func_returns_map: Dict[str, List[CPGNode]] = {}

    for sf in scanned_files:
        try:
            normalizer = ASTNormalizer(sf)
            f_nodes, f_edges = normalizer.normalize()
            all_nodes.extend(f_nodes)
            all_edges.extend(f_edges)
            node_map.update(normalizer.node_map)
            file_nodes_map[sf.filepath] = f_nodes

            params_by_scope: Dict[str, List[CPGNode]] = {}
            for pn in f_nodes:
                if pn.label == "Parameter" and pn.ast_type not in ("parameters", "formal_parameters"):
                    params_by_scope.setdefault(pn.scope_id, []).append(pn)

            for n in f_nodes:
                if n.label == "Function":
                    params = params_by_scope.get(n.id, [])
                    unique_params: List[CPGNode] = []
                    seen_names: Set[str] = set()
                    for p in params:
                        if p.name not in seen_names and p.name not in ("self", "cls") and not p.name.startswith("("):
                            seen_names.add(p.name)
                            unique_params.append(p)
                    func_params_map[n.name] = unique_params
                elif n.label == "Return":
                    fn = node_map.get(n.scope_id)
                    if fn and fn.label == "Function":
                        func_returns_map.setdefault(fn.name, []).append(n)
        except Exception as exc:
            logger.warning("Skipping AST normalization for %s: %s", sf.filepath, str(exc)[:120])

    for sf in scanned_files:
        try:
            f_nodes = file_nodes_map.get(sf.filepath, [])
            cfg_edges = CFGBuilder(
                filepath=sf.filepath,
                content_bytes=sf.content_bytes,
                language=sf.language,
                nodes=f_nodes,
                node_map=node_map,
            ).build()
            all_edges.extend(cfg_edges)
        except Exception as exc:
            logger.warning("Skipping CFG build for %s: %s", sf.filepath, str(exc)[:120])

    # Inter-procedural AST-verified sanitizer summary (matching main.py Pass 3)
    verified_sanitizer_func_domains: Dict[str, List[str]] = {}
    inline_path_guarded_scopes: Set[str] = set()
    inline_ssrf_guarded_scopes: Set[str] = set()
    for fn_node in all_nodes:
        if fn_node.label == "Function" and fn_node.code and fn_node.name:
            fn_src = fn_node.code
            has_path_conf = (
                "os.path.commonpath(" in fn_src
                or "os.path.basename(" in fn_src
                or ".is_relative_to(" in fn_src
                or "secure_filename(" in fn_src
            )
            if (
                "os.path.commonpath(" in fn_src
                or ".is_relative_to(" in fn_src
                or "os.path.basename(" in fn_src
            ) and ("raise " in fn_src or "return " in fn_src or "os.path.basename(" in fn_src):
                inline_path_guarded_scopes.add(fn_node.id)

            has_ssrf_conf = (
                "ipaddress.ip_address(" in fn_src
                or ("is_private" in fn_src and "is_loopback" in fn_src)
                or bool(re.search(r'\.startswith\(\s*["\']https://', fn_src))
            )
            if (
                bool(re.search(r'\.startswith\(\s*["\']https://', fn_src))
                and ("raise " in fn_src or "throw " in fn_src)
            ):
                inline_ssrf_guarded_scopes.add(fn_node.id)

            has_crlf = "\\n" in fn_src and "\\r" in fn_src and (".replace(" in fn_src or "re.sub(" in fn_src)
            helper_domains: List[str] = []
            if has_path_conf:
                helper_domains.append("PATH")
            if has_ssrf_conf:
                helper_domains.append("URL")
            if has_crlf:
                helper_domains.append("LOG")
            if helper_domains:
                existing_domains = verified_sanitizer_func_domains.setdefault(fn_node.name, [])
                for dom in helper_domains:
                    if dom not in existing_domains:
                        existing_domains.append(dom)

    if verified_sanitizer_func_domains or inline_path_guarded_scopes or inline_ssrf_guarded_scopes:
        for call_node in all_nodes:
            if call_node.label != "Call":
                continue
            short_callee = call_node.name.split(".")[-1] if "." in call_node.name else call_node.name
            matched_domains: List[str] = []
            if call_node.name in verified_sanitizer_func_domains:
                matched_domains.extend(verified_sanitizer_func_domains[call_node.name])
            if short_callee in verified_sanitizer_func_domains:
                matched_domains.extend(verified_sanitizer_func_domains[short_callee])
            if matched_domains:
                call_node.is_sanitizer = True
                call_node.is_sink = False
                call_node.sanitizer_domains = list(
                    dict.fromkeys([*(call_node.sanitizer_domains or []), *matched_domains])
                )
            elif call_node.scope_id in inline_path_guarded_scopes and short_callee in ("realpath", "resolve", "basename"):
                call_node.is_sanitizer = True
                call_node.is_sink = False
                call_node.sanitizer_domains = list(dict.fromkeys([*(call_node.sanitizer_domains or []), "PATH"]))
            elif call_node.scope_id in inline_ssrf_guarded_scopes and (
                short_callee in ("urlopen", "urlretrieve")
                or call_node.name
                in (
                    "requests.get",
                    "requests.post",
                    "requests.put",
                    "requests.delete",
                    "requests.request",
                    "http_requests.get",
                    "http_requests.post",
                    "http_requests.request",
                    "httpx.get",
                    "httpx.post",
                    "axios.get",
                    "axios.post",
                )
            ):
                call_node.is_sanitizer = True
                call_node.is_sink = False
                call_node.sanitizer_domains = list(dict.fromkeys([*(call_node.sanitizer_domains or []), "URL"]))

    for sf in scanned_files:
        try:
            f_nodes = file_nodes_map.get(sf.filepath, [])
            dfg_edges = DFGBuilder(
                filepath=sf.filepath,
                content_bytes=sf.content_bytes,
                language=sf.language,
                nodes=f_nodes,
                node_map=node_map,
                function_params_map=func_params_map,
                function_returns_map=func_returns_map,
            ).build()
            all_edges.extend(dfg_edges)
        except Exception as exc:
            logger.warning("Skipping DFG build for %s: %s", sf.filepath, str(exc)[:120])

    try:
        call_edges = CallGraphBuilder(all_nodes).resolve_calls()
        all_edges.extend(call_edges)
    except Exception as exc:
        logger.warning("Skipping CallGraph resolution: %s", str(exc)[:120])

    comm_map = detect_code_communities(
        all_nodes,
        all_edges,
        app_tree,
        [],
        graph_engine_mode="EMBEDDED_SQLITE",
    )
    return app_tree, scanned_files, all_nodes, all_edges, comm_map


def _map_pasta_verdict_to_fleet(pasta_verdict: str) -> str:
    if pasta_verdict == "APPROVED_FOR_GO_LIVE":
        return "GO_LIVE_APPROVED"
    if pasta_verdict in ("CONDITIONAL_GO_LIVE", "NO_GO_HOLD_RELEASE"):
        return pasta_verdict
    return "CONDITIONAL_GO_LIVE"


def _compute_fallback_go_live(findings: List[Finding]) -> str:
    active = [f for f in findings if f.triage_status not in ("NOT_EXPLOITABLE", "RESOLVED")]
    if any(f.ev_status == "RUNTIME_EXPLOIT_CONFIRMED" or f.severity in ("CRITICAL", "HIGH") for f in active):
        return "NO_GO_HOLD_RELEASE"
    if any(f.severity in ("MEDIUM", "LOW") for f in active):
        return "CONDITIONAL_GO_LIVE"
    return "GO_LIVE_APPROVED"


class FleetRunner:
    """
    Thread-safe, hostile-repo-guarded multi-repository scanner orchestrator backed
    by SQLite WAL stage checkpoints and App-Group Go-Live rollups.
    """

    def __init__(
        self,
        vault_dir: str,
        checkpoint_store: CheckpointStore,
        workspace_confinement_fn: Optional[Callable[[str], str]] = None,
    ):
        self.vault_dir = os.path.realpath(vault_dir)
        os.makedirs(self.vault_dir, exist_ok=True)
        self.checkpoint_store = checkpoint_store
        self.workspace_confinement_fn = workspace_confinement_fn

    def _resolve_fusion_report_path(self, report_path: str, local_repo_path: str) -> str:
        raw = str(report_path or "").strip()
        if not raw or _has_control_chars(raw):
            raise ValueError(f"Invalid fusion report path: {report_path!r}")
        if _has_traversal_segment(raw):
            raise ValueError(f"Path traversal rejected in fusion report path: {report_path}")

        real_repo = os.path.realpath(local_repo_path)
        repo_candidate = os.path.join(real_repo, raw) if not os.path.isabs(raw) else ""

        if self.workspace_confinement_fn is not None:
            if repo_candidate and os.path.lexists(repo_candidate):
                if is_link_or_junction(repo_candidate):
                    real_cand = os.path.realpath(repo_candidate)
                    if os.path.commonpath([real_repo, real_cand]) != real_repo:
                        raise ValueError(f"Symlink/junction escape rejected in fusion report: {report_path}")
                resolved = os.path.realpath(repo_candidate)
                if os.path.commonpath([real_repo, resolved]) != real_repo:
                    raise ValueError(f"Fusion report escapes repository root: {report_path}")
            else:
                resolved = os.path.realpath(self.workspace_confinement_fn(raw))
        else:
            if repo_candidate and os.path.lexists(repo_candidate):
                resolved = os.path.realpath(repo_candidate)
                if os.path.commonpath([real_repo, resolved]) != real_repo:
                    raise ValueError(f"Fusion report escapes repository root: {report_path}")
            else:
                abs_p = os.path.abspath(raw)
                if is_link_or_junction(abs_p):
                    raise ValueError(f"Symlink/junction fusion report rejected: {report_path}")
                resolved = os.path.realpath(abs_p)

        base_lower = os.path.basename(resolved).lower()
        if base_lower == ".env" or base_lower.startswith(".env."):
            raise ValueError(f"Refused reading restricted .env file as fusion report: {report_path}")
        if not os.path.isfile(resolved):
            raise ValueError(f"Fusion report file not found: {report_path}")
        if os.path.getsize(resolved) > _MAX_REPORT_BYTES:
            raise ValueError(f"Fusion report exceeds 50MB limit: {report_path}")
        return resolved

    def _resolve_enabled_rule_ids_for_profile(
        self,
        em: EnterpriseManager,
        profile: str,
    ) -> Optional[Set[str]]:
        prof_low = (profile or "deterministic").strip().lower()
        if prof_low in ("fast-ci", "fast_ci", "ci"):
            preset = next((p for p in em.presets if p.id == "preset-fast-ci"), None)
            if preset:
                return set(preset.enabled_rule_ids)
        elif prof_low in ("secrets", "secrets-hunt", "preset-secrets-hunt"):
            preset = next((p for p in em.presets if p.id == "preset-secrets-hunt"), None)
            if preset:
                return set(preset.enabled_rule_ids)
        return {q.id for q in em.queries if q.enabled}

    def _enrich_findings_isolated(
        self,
        em: EnterpriseManager,
        raw_findings: List[Finding],
        enabled_rule_ids: Optional[Set[str]],
        local_path: str,
    ) -> List[Finding]:
        query_overrides = {q.id: q for q in em.queries}
        enriched: List[Finding] = []
        for raw_f in raw_findings:
            f = raw_f.model_copy(deep=True)
            is_cred_rule = f.rule_id.startswith("SECRET-") and (
                enabled_rule_ids is None
                or "RULE-8-HARDCODED-SECRET" in enabled_rule_ids
                or f.rule_id in enabled_rule_ids
            )
            if (
                enabled_rule_ids is not None
                and not f.rule_id.startswith("EXT-")
                and not is_cred_rule
                and f.rule_id not in enabled_rule_ids
            ):
                continue

            q_rule = query_overrides.get(f.rule_id)
            if q_rule:
                f.scan_engine = q_rule.engine
            if getattr(f, "secret_validation_status", None) == "VERIFIED_ACTIVE":
                f.severity = "CRITICAL"
                f.cvss_score = max(float(f.cvss_score or 0.0), 9.8)

            last_fp = f.path_nodes[-1].get("filepath", "") if f.path_nodes else ""
            if f.scan_engine == "SAST" or not f.language or f.language == "Python":
                f.language = infer_language_from_filepath(str(last_fp), f.rule_id)
            f.best_fix_location = compute_best_fix_location(f)
            if f.best_fix_location and f.best_fix_location.filepath:
                cand_file = os.path.join(local_path, f.best_fix_location.filepath)
                if os.path.isfile(cand_file):
                    try:
                        mtime = os.path.getmtime(cand_file)
                        dt = datetime.fromtimestamp(mtime)
                        f.first_seen_at = dt.strftime("%Y-%m-%d")
                        f.age_days = max(0, (datetime.now() - dt).days)
                    except OSError:
                        pass
            populate_plain_english_and_raci(f)
            enriched.append(f)
        return enriched

    def run_single_repo(
        self,
        spec: FleetRepoSpec,
        resume: bool = True,
        stop_after: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> Tuple[FleetRepoResult, List[Finding]]:
        """
        Executes ALASTOR's deterministic scan + fusion + S6/S8/PASTA pipeline on a single
        repository with SQLite stage checkpoints and hostile-repo isolation.
        """
        started_t = time.perf_counter()
        raw_repo = str(spec.repo or "").strip()
        effective_run_id = run_id or f"run-failed-{uuid.uuid4().hex[:10]}"

        try:
            target_stop_stage = _normalize_stop_after(stop_after)
        except ValueError as exc:
            return (
                FleetRepoResult(
                    repo=raw_repo,
                    app_group=spec.app_group,
                    run_id=effective_run_id,
                    status="FAILED",
                    go_live_decision="NO_GO_HOLD_RELEASE",
                    duration_ms=round((time.perf_counter() - started_t) * 1000.0, 2),
                    error=str(exc),
                ),
                [],
            )

        if not raw_repo or _has_control_chars(raw_repo) or raw_repo.startswith("-"):
            return (
                FleetRepoResult(
                    repo=raw_repo,
                    app_group=spec.app_group,
                    run_id=effective_run_id,
                    status="FAILED",
                    go_live_decision="NO_GO_HOLD_RELEASE",
                    duration_ms=round((time.perf_counter() - started_t) * 1000.0, 2),
                    error="Repository path is empty, contains control characters, or starts with '-'",
                ),
                [],
            )

        if _is_remote_repo_syntax(raw_repo):
            try:
                validate_clone_url(raw_repo)
                err_msg = (
                    "Remote URL cloning is disabled in offline FleetRunner mode "
                    "(supply a local confined repository path)"
                )
            except HostileRepoError as exc:
                err_msg = str(exc)
            return (
                FleetRepoResult(
                    repo=raw_repo,
                    app_group=spec.app_group,
                    run_id=effective_run_id,
                    status="FAILED",
                    go_live_decision="NO_GO_HOLD_RELEASE",
                    duration_ms=round((time.perf_counter() - started_t) * 1000.0, 2),
                    error=err_msg,
                ),
                [],
            )

        if _has_traversal_segment(raw_repo):
            return (
                FleetRepoResult(
                    repo=raw_repo,
                    app_group=spec.app_group,
                    run_id=effective_run_id,
                    status="FAILED",
                    go_live_decision="NO_GO_HOLD_RELEASE",
                    duration_ms=round((time.perf_counter() - started_t) * 1000.0, 2),
                    error=f"Path traversal '..' rejected in repository path: {raw_repo}",
                ),
                [],
            )

        try:
            confined_path = (
                self.workspace_confinement_fn(raw_repo)
                if self.workspace_confinement_fn is not None
                else raw_repo
            )
            local_path = os.path.realpath(confined_path)
            if not os.path.isdir(local_path):
                raise ValueError(f"Repository path does not exist or is not a directory: {raw_repo}")
            commit_sha = get_repo_commit_sha(local_path)
        except Exception as exc:
            return (
                FleetRepoResult(
                    repo=raw_repo,
                    app_group=spec.app_group,
                    run_id=effective_run_id,
                    status="FAILED",
                    go_live_decision="NO_GO_HOLD_RELEASE",
                    duration_ms=round((time.perf_counter() - started_t) * 1000.0, 2),
                    error=scrub_raw_secrets_text(str(exc)),
                ),
                [],
            )

        run_summary = self.checkpoint_store.create_or_get_run(
            repo_path=local_path,
            commit_sha=commit_sha,
            app_group=spec.app_group,
            run_id=run_id,
            resume=resume,
            options={"profile": spec.profile, "stop_after": target_stop_stage},
        )
        effective_run_id = run_summary.run_id

        fleet_tmp_parent = os.path.join(self.vault_dir, "_fleet_cpg_tmp")
        os.makedirs(fleet_tmp_parent, exist_ok=True)
        repo_tmp_dir = os.path.join(fleet_tmp_parent, f"{effective_run_id}-{uuid.uuid4().hex[:8]}")
        os.makedirs(repo_tmp_dir, exist_ok=True)
        gstore = EmbeddedGraphStore(os.path.join(repo_tmp_dir, "cpg.db"))

        resumed_stages: List[str] = []
        current_findings: List[Finding] = []
        corroborated_count = 0
        go_live_decision = "CONDITIONAL_GO_LIVE"
        stopped_early = False

        app_tree: Optional[AppTreeSummary] = None
        scanned_files: Optional[List[ScannedFile]] = None
        all_nodes: List[CPGNode] = []
        all_edges: List[CPGEdge] = []
        comm_map: Optional[CommunityMapResponse] = None
        cpg_hydrated = False

        def _ensure_cpg_hydrated() -> None:
            nonlocal app_tree, scanned_files, all_nodes, all_edges, comm_map, cpg_hydrated
            if cpg_hydrated:
                return
            app_tree, scanned_files, all_nodes, all_edges, comm_map = _build_cpg_for_repo(local_path)
            gstore.clear_database()
            gstore.init_schema()
            gstore.ingest_app_tree(app_tree)
            if all_nodes or all_edges:
                gstore.ingest_cpg(all_nodes, all_edges)
            gstore.save_communities(comm_map)
            cpg_hydrated = True

        def _load_completed_stage(stage_name: str) -> Optional[Any]:
            if not resume:
                return None
            ckpt = self.checkpoint_store.get_stage(effective_run_id, stage_name)
            if ckpt is not None and ckpt[0].status == "COMPLETED":
                resumed_stages.append(stage_name)
                return ckpt[1]
            return None

        try:
            local_em = EnterpriseManager()
            local_em.data_dir = self.vault_dir
            local_em.vault_dir = self.vault_dir
            enabled_rule_ids = self._resolve_enabled_rule_ids_for_profile(local_em, spec.profile)

            # ---------------------------------------------------------------
            # Stage S0_CPG
            # ---------------------------------------------------------------
            s0_t = time.perf_counter()
            s0_cached = _load_completed_stage("S0_CPG")
            if s0_cached is None:
                hostile_configs = find_hostile_target_configs(local_path)
                _ensure_cpg_hydrated()
                assert app_tree is not None
                self.checkpoint_store.save_stage(
                    effective_run_id,
                    "S0_CPG",
                    "COMPLETED",
                    payload={
                        "files_scanned": len(scanned_files or []),
                        "total_app_files": app_tree.total_files,
                        "nodes_created": len(all_nodes),
                        "edges_created": len(all_edges),
                        "hostile_configs_detected": hostile_configs,
                    },
                    duration_ms=round((time.perf_counter() - s0_t) * 1000.0, 2),
                    metadata={"profile": spec.profile},
                )
            if target_stop_stage == "S0_CPG":
                stopped_early = True

            # ---------------------------------------------------------------
            # Stage S1_RULES
            # ---------------------------------------------------------------
            if not stopped_early:
                s1_t = time.perf_counter()
                s1_cached = _load_completed_stage("S1_RULES")
                if s1_cached is not None and isinstance(s1_cached, list):
                    current_findings = [Finding.model_validate(item) for item in s1_cached]
                else:
                    _ensure_cpg_hydrated()
                    raw_sast = (
                        gstore.run_cpg_rules(
                            scanned_files=scanned_files,
                            enabled_rule_ids=enabled_rule_ids,
                        )
                        if scanned_files
                        else []
                    )
                    sast_verified: List[Finding] = []
                    for sf_item in raw_sast:
                        fp = sf_item.path_nodes[-1].get("filepath", "") if sf_item.path_nodes else ""
                        if fp and os.path.exists(os.path.join(local_path, fp)):
                            sast_verified.append(sf_item)
                    current_findings = sast_verified
                    s1_checkpoint_payload = [
                        scrub_finding_secrets(f, clear_raw_secret=True).model_dump()
                        for f in current_findings
                    ]
                    self.checkpoint_store.save_stage(
                        effective_run_id,
                        "S1_RULES",
                        "COMPLETED",
                        payload=s1_checkpoint_payload,
                        duration_ms=round((time.perf_counter() - s1_t) * 1000.0, 2),
                        metadata={"native_sast_count": len(current_findings)},
                    )
                if target_stop_stage == "S1_RULES":
                    stopped_early = True

            # ---------------------------------------------------------------
            # Stage S2_SECRETS_SCA
            # ---------------------------------------------------------------
            if not stopped_early:
                s2_t = time.perf_counter()
                s2_cached = _load_completed_stage("S2_SECRETS_SCA")
                if s2_cached is not None and isinstance(s2_cached, list):
                    current_findings = [Finding.model_validate(item) for item in s2_cached]
                else:
                    sca_iac_findings: List[Finding] = []
                    try:
                        sca_iac_findings = local_em.run_sca_and_iac_scanners(local_path)
                    except Exception as sca_err:
                        logger.warning("Non-fatal SCA/IaC error on %s: %s", local_path, str(sca_err)[:120])

                    sv_engine = SecretValidatorEngine(platform_root=self.vault_dir)
                    sv_engine._live_enabled = False
                    # Guard against hostile .git/config execution by never invoking unhardened git log
                    sv_engine._scan_git_history = False

                    combined_s2 = sv_engine.scan_and_validate_workspace(
                        local_path,
                        list(current_findings) + list(sca_iac_findings),
                        allow_live=False,
                    )
                    enriched_s2 = self._enrich_findings_isolated(
                        local_em,
                        combined_s2,
                        enabled_rule_ids=enabled_rule_ids,
                        local_path=local_path,
                    )
                    # Never persist raw secret literals into SQLite checkpoints or returned findings
                    enriched_s2 = [
                        scrub_finding_secrets(f, clear_raw_secret=True)
                        for f in enriched_s2
                    ]

                    ev_map = ExploitVerificationEngine(self.vault_dir).get_confirmed_status_map(local_path)
                    if ev_map:
                        ev_synced: List[Finding] = []
                        for f in enriched_s2:
                            if f.id in ev_map:
                                ev_st, ev_sum = ev_map[f.id]
                                extra_raw = [f.secret_value_raw] if f.secret_value_raw else None
                                safe_sum = scrub_raw_secrets_text(ev_sum or "", extra_raw_secrets=extra_raw)
                                ev_synced.append(
                                    f.model_copy(
                                        deep=True,
                                        update={"ev_status": ev_st, "ev_evidence_summary": safe_sum},
                                    )
                                )
                            else:
                                ev_synced.append(f)
                        enriched_s2 = ev_synced

                    current_findings = enriched_s2
                    self.checkpoint_store.save_stage(
                        effective_run_id,
                        "S2_SECRETS_SCA",
                        "COMPLETED",
                        payload=[f.model_dump() for f in current_findings],
                        duration_ms=round((time.perf_counter() - s2_t) * 1000.0, 2),
                        metadata={"findings_count": len(current_findings)},
                    )
                if target_stop_stage == "S2_SECRETS_SCA":
                    stopped_early = True

            # ---------------------------------------------------------------
            # Stage S3_FUSION
            # ---------------------------------------------------------------
            if not stopped_early:
                s3_t = time.perf_counter()
                s3_cached = _load_completed_stage("S3_FUSION")
                if s3_cached is not None and isinstance(s3_cached, dict):
                    raw_flist = s3_cached.get("findings") or []
                    current_findings = [Finding.model_validate(item) for item in raw_flist]
                    corroborated_count = int(s3_cached.get("corroborated_count") or 0)
                else:
                    fusion_warnings: List[str] = []
                    if spec.fusion_reports:
                        _ensure_cpg_hydrated()
                        for rpath in spec.fusion_reports:
                            resolved_rp = self._resolve_fusion_report_path(rpath, local_path)
                            with open(resolved_rp, "r", encoding="utf-8", errors="replace") as fh:
                                report_text = fh.read()
                            det_fmt, imported = parse_external_scanner_report(
                                report_text,
                                repo_root=local_path,
                            )
                            fusion_resp = fuse_findings_with_cpg(
                                imported=imported,
                                native_findings=current_findings,
                                graph_store=gstore,
                                project_path=local_path,
                                run_s6_verify=False,
                                detected_format=det_fmt,
                                correlate_cpg=True,
                            )
                            current_findings = fusion_resp.findings
                            corroborated_count += fusion_resp.corroborated_count
                            fusion_warnings.extend(fusion_resp.warnings)

                    current_findings = [
                        scrub_finding_secrets(f, clear_raw_secret=True)
                        for f in current_findings
                    ]
                    self.checkpoint_store.save_stage(
                        effective_run_id,
                        "S3_FUSION",
                        "COMPLETED",
                        payload={
                            "findings": [f.model_dump() for f in current_findings],
                            "corroborated_count": corroborated_count,
                            "warnings": fusion_warnings,
                        },
                        duration_ms=round((time.perf_counter() - s3_t) * 1000.0, 2),
                        metadata={
                            "fusion_reports_count": len(spec.fusion_reports),
                            "corroborated_count": corroborated_count,
                        },
                    )
                if target_stop_stage == "S3_FUSION":
                    stopped_early = True

            # ---------------------------------------------------------------
            # Stage S6_VERIFY
            # ---------------------------------------------------------------
            if not stopped_early:
                s6_t = time.perf_counter()
                s6_cached = _load_completed_stage("S6_VERIFY")
                if s6_cached is None:
                    s6_ids = [f.id for f in current_findings] if len(current_findings) > 50 else None
                    s6_resp = verify_findings_adversarially(
                        target_dir=local_path,
                        findings=current_findings,
                        ai_engine=None,
                        finding_ids=s6_ids,
                        use_ai=False,
                        max_batch=max(1, min(50, len(current_findings) or 1)),
                    )
                    self.checkpoint_store.save_stage(
                        effective_run_id,
                        "S6_VERIFY",
                        "COMPLETED",
                        payload=s6_resp.model_dump(),
                        duration_ms=round((time.perf_counter() - s6_t) * 1000.0, 2),
                        metadata={"total_verified": s6_resp.total_verified},
                    )
                if target_stop_stage == "S6_VERIFY":
                    stopped_early = True

            # ---------------------------------------------------------------
            # Stage S8_CHAINS
            # ---------------------------------------------------------------
            s8_chains: List[Any] = []
            api_ops = None
            if not stopped_early:
                s8_t = time.perf_counter()
                s8_cached = _load_completed_stage("S8_CHAINS")
                if s8_cached is not None and isinstance(s8_cached, dict):
                    s8_chains = s8_cached.get("chains") or []
                else:
                    _ensure_cpg_hydrated()
                    api_ops = ApiOperationsEngine().analyze_workspace_api_operations(local_path, current_findings)
                    s8_resp = synthesize_exploit_chains(
                        target_dir=local_path,
                        findings=current_findings,
                        api_ops=api_ops,
                        community_map=comm_map,
                        ai_engine=None,
                        use_ai=False,
                    )
                    s8_chains = s8_resp.chains
                    self.checkpoint_store.save_stage(
                        effective_run_id,
                        "S8_CHAINS",
                        "COMPLETED",
                        payload=s8_resp.model_dump(),
                        duration_ms=round((time.perf_counter() - s8_t) * 1000.0, 2),
                        metadata={"total_chains": s8_resp.total_chains},
                    )
                if target_stop_stage == "S8_CHAINS":
                    stopped_early = True

            # ---------------------------------------------------------------
            # Stage S9_REPORTS (PASTA Go-Live Gate Evaluation)
            # ---------------------------------------------------------------
            if not stopped_early:
                s9_t = time.perf_counter()
                s9_cached = _load_completed_stage("S9_REPORTS")
                if s9_cached is not None and isinstance(s9_cached, dict):
                    go_live_decision = str(s9_cached.get("go_live_decision") or "CONDITIONAL_GO_LIVE")
                else:
                    if app_tree is None:
                        app_tree = AppTreeAnalyzer(local_path).analyze()
                    if api_ops is None:
                        api_ops = ApiOperationsEngine().analyze_workspace_api_operations(local_path, current_findings)
                    from models import ExploitChainItem

                    typed_chains = [
                        c if isinstance(c, ExploitChainItem) else ExploitChainItem.model_validate(c)
                        for c in s8_chains
                    ]
                    pasta_resp = PastaThreatEngine(vault_dir=self.vault_dir).evaluate_pasta(
                        target_dir=local_path,
                        findings=current_findings,
                        app_tree=app_tree,
                        api_ops=api_ops,
                        exploit_chains=typed_chains,
                    )
                    go_live_decision = _map_pasta_verdict_to_fleet(pasta_resp.golive_verdict)
                    self.checkpoint_store.save_stage(
                        effective_run_id,
                        "S9_REPORTS",
                        "COMPLETED",
                        payload={
                            "go_live_decision": go_live_decision,
                            "golive_verdict": pasta_resp.golive_verdict,
                            "residual_risk_score": pasta_resp.residual_risk_score,
                            "mandatory_pre_golive_count": pasta_resp.mandatory_pre_golive_count,
                        },
                        duration_ms=round((time.perf_counter() - s9_t) * 1000.0, 2),
                        metadata={"go_live_decision": go_live_decision},
                    )
            else:
                go_live_decision = _compute_fallback_go_live(current_findings)

            # Scrub raw secret literals before returning Findings from FleetRunner
            safe_findings = [
                scrub_finding_secrets(f, clear_raw_secret=True)
                for f in current_findings
            ]
            active = [f for f in safe_findings if f.triage_status not in ("NOT_EXPLOITABLE", "RESOLVED")]
            crit_cnt = sum(1 for f in active if f.severity == "CRITICAL")
            high_cnt = sum(1 for f in active if f.severity == "HIGH")
            med_cnt = sum(1 for f in active if f.severity == "MEDIUM")
            low_cnt = sum(1 for f in active if f.severity in ("LOW", "INFO"))
            ev_cnt = sum(1 for f in active if f.ev_status == "RUNTIME_EXPLOIT_CONFIRMED")
            if corroborated_count == 0:
                corroborated_count = sum(len(f.corroborated_by) for f in safe_findings if f.corroborated_by)
            if ev_cnt > 0 or crit_cnt > 0:
                go_live_decision = "NO_GO_HOLD_RELEASE"

            self.checkpoint_store.mark_run_status(
                effective_run_id,
                "PARTIAL" if stopped_early else "COMPLETED",
                summary={
                    "total_findings": len(active),
                    "critical_count": crit_cnt,
                    "high_count": high_cnt,
                    "medium_count": med_cnt,
                    "low_count": low_cnt,
                    "corroborated_count": corroborated_count,
                    "ev_confirmed_count": ev_cnt,
                    "go_live_decision": go_live_decision,
                    "resumed_stages": resumed_stages,
                },
            )

            repo_status = "RESUMED_COMPLETED" if resumed_stages else "COMPLETED"
            result = FleetRepoResult(
                repo=raw_repo,
                app_group=spec.app_group,
                run_id=effective_run_id,
                status=repo_status,  # type: ignore[arg-type]
                total_findings=len(active),
                critical_count=crit_cnt,
                high_count=high_cnt,
                medium_count=med_cnt,
                low_count=low_cnt,
                corroborated_count=corroborated_count,
                ev_confirmed_count=ev_cnt,
                go_live_decision=go_live_decision,
                resumed_stages=resumed_stages,
                duration_ms=round((time.perf_counter() - started_t) * 1000.0, 2),
                error=None,
            )
            return result, safe_findings

        except Exception as exc:
            err_clean = scrub_raw_secrets_text(str(exc))
            try:
                self.checkpoint_store.mark_run_status(
                    effective_run_id,
                    "FAILED",
                    summary={"error": err_clean},
                )
            except Exception:
                pass
            return (
                FleetRepoResult(
                    repo=raw_repo,
                    app_group=spec.app_group,
                    run_id=effective_run_id,
                    status="FAILED",
                    go_live_decision="NO_GO_HOLD_RELEASE",
                    resumed_stages=resumed_stages,
                    duration_ms=round((time.perf_counter() - started_t) * 1000.0, 2),
                    error=err_clean,
                ),
                [],
            )
        finally:
            gstore.close()
            try:
                safe_cleanup_workspace(repo_tmp_dir, fleet_tmp_parent)
            except Exception:
                pass

    def _compute_app_rollups(self, results: List[FleetRepoResult]) -> List[FleetAppGroupRollup]:
        groups: Dict[str, List[FleetRepoResult]] = {}
        for res in results:
            groups.setdefault(res.app_group or "default", []).append(res)

        rollups: List[FleetAppGroupRollup] = []
        for grp_name, grp_items in groups.items():
            completed_cnt = sum(1 for r in grp_items if r.status in ("COMPLETED", "RESUMED_COMPLETED"))
            failed_cnt = sum(1 for r in grp_items if r.status == "FAILED")
            total_f = sum(r.total_findings for r in grp_items)
            crit_c = sum(r.critical_count for r in grp_items)
            high_c = sum(r.high_count for r in grp_items)
            med_c = sum(r.medium_count for r in grp_items)
            corr_c = sum(r.corroborated_count for r in grp_items)
            ev_c = sum(r.ev_confirmed_count for r in grp_items)

            if (
                failed_cnt > 0
                or ev_c > 0
                or crit_c > 0
                or any(r.go_live_decision == "NO_GO_HOLD_RELEASE" for r in grp_items)
            ):
                decision = "NO_GO_HOLD_RELEASE"
            elif (
                high_c > 0
                or med_c > 0
                or any(r.go_live_decision == "CONDITIONAL_GO_LIVE" for r in grp_items)
            ):
                decision = "CONDITIONAL_GO_LIVE"
            else:
                decision = "GO_LIVE_APPROVED"

            rollups.append(
                FleetAppGroupRollup(
                    app_group=grp_name,
                    repo_count=len(grp_items),
                    completed_repos=completed_cnt,
                    failed_repos=failed_cnt,
                    total_findings=total_f,
                    critical_count=crit_c,
                    high_count=high_c,
                    corroborated_count=corr_c,
                    ev_confirmed_count=ev_c,
                    go_live_decision=decision,  # type: ignore[arg-type]
                )
            )
        return rollups

    def run_fleet(self, req: FleetRunRequest) -> FleetRunResponse:
        """
        Executes a multi-repository batch fleet scan (merging `req.repos` + `req.csv_content`),
        persists the resulting `FleetRunResponse` into `CheckpointStore`, and computes
        `FleetAppGroupRollup` decisions when `req.group_by_app` is True.
        """
        specs: List[FleetRepoSpec] = list(req.repos or [])
        if req.csv_content and req.csv_content.strip():
            specs.extend(parse_fleet_csv(req.csv_content))

        if not specs:
            raise ValueError("FleetRunRequest must specify at least one repository via 'repos' or 'csv_content'")

        norm_stop = _normalize_stop_after(req.stop_after)

        def _exec_one(spec: FleetRepoSpec) -> FleetRepoResult:
            res, _ = self.run_single_repo(
                spec=spec,
                resume=req.resume,
                stop_after=norm_stop,
            )
            return res

        workers = min(max(1, int(req.max_workers)), len(specs))
        if workers == 1 or len(specs) == 1:
            repo_results = [_exec_one(sp) for sp in specs]
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                repo_results = list(pool.map(_exec_one, specs))

        completed_repos = sum(1 for r in repo_results if r.status in ("COMPLETED", "RESUMED_COMPLETED"))
        failed_repos = sum(1 for r in repo_results if r.status == "FAILED")

        if failed_repos == 0 and completed_repos == len(specs):
            fleet_status = "COMPLETED"
        elif completed_repos > 0:
            fleet_status = "PARTIAL"
        else:
            fleet_status = "FAILED"

        app_rollups = self._compute_app_rollups(repo_results) if req.group_by_app else []

        response = FleetRunResponse(
            fleet_run_id=f"fleet-{uuid.uuid4().hex[:12]}",
            manifest_name=req.manifest_name or "fleet-manifest",
            status=fleet_status,  # type: ignore[arg-type]
            total_repos=len(specs),
            completed_repos=completed_repos,
            failed_repos=failed_repos,
            created_at=_utc_now_iso(),
            repo_results=repo_results,
            app_rollups=app_rollups,
        )
        self.checkpoint_store.save_fleet_run(response)
        return response


__all__ = [
    "parse_fleet_csv",
    "FleetRunner",
]
