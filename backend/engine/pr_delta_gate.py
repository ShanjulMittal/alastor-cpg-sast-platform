"""
ALASTOR v5.0 Pillar 5 — PR / Git-Diff Incremental Security Gate.

Computes exact git diff deltas via hardened host git (`run_hardened_git`), inspects
1-hop CPG callers/callees for blast-radius awareness, classifies findings into
`NEWLY_INTRODUCED`, `MODIFIED_CONTEXT`, and `PRE_EXISTING`, enforces fail-closed
merge-gate policies, and outputs scrubbed GitHub/GitLab Markdown summaries and annotations.
"""
from __future__ import annotations

import logging
import os
import re
import tempfile
from typing import Dict, List, Optional, Sequence, Set, Tuple

from database.graph_store import EmbeddedGraphStore
from engine.enterprise_manager import (
    EnterpriseManager,
    infer_language_from_filepath,
    preserve_or_compute_best_fix_location,
)
from engine.exploit_verification_engine import ExploitVerificationEngine
from engine.fleet_runner import _build_cpg_for_repo
from engine.frontier_ai_engine import scrub_raw_secrets_text
from engine.hostile_repo_guard import HostileRepoError, run_hardened_git
from engine.scanner_fusion_engine import scrub_finding_secrets
from engine.secret_validator_engine import SecretValidatorEngine
from models import (
    CPGEdge,
    CPGNode,
    Finding,
    PrDeltaAnnotation,
    PrDeltaClassification,
    PrDeltaGateRequest,
    PrDeltaGateResponse,
)

logger = logging.getLogger("cpg-sast.pr-delta-gate")

_VALID_REF_RE = re.compile(r"^[A-Za-z0-9._/~^@-]{1,128}$")
_TILDE_ABUSE_RE = re.compile(r"~(?![0-9]*(?:$|\^))")
_CARET_ABUSE_RE = re.compile(r"\^(?![0-9]*(?:$|\^|~))")
_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

_SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

_CLASSIFICATION_ORDER: Dict[str, int] = {
    "NEWLY_INTRODUCED": 0,
    "MODIFIED_CONTEXT": 1,
    "PRE_EXISTING": 2,
}


def validate_git_ref(ref: str) -> str:
    """
    Strictly validates a git revision/ref (or special `WORKTREE` sentinel) against
    option injection, range injection (`..`), reflog syntax (`@{`), whitespace,
    control characters, backslashes, and malformed tilde/caret expressions.
    """
    if not isinstance(ref, str) or not ref:
        raise HostileRepoError("Git ref must be a non-empty string")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in ref):
        raise HostileRepoError("Git ref contains forbidden control characters")
    if any(ch.isspace() for ch in ref):
        raise HostileRepoError("Git ref cannot contain whitespace")
    if len(ref) > 128 or not _VALID_REF_RE.match(ref):
        raise HostileRepoError(f"Git ref contains disallowed characters or length: {ref!r}")
    if ref.startswith(("-", ".", "/", "~", "^")):
        raise HostileRepoError(f"Git ref cannot start with '{ref[0]}': {ref!r}")
    if ref.endswith((".", "/", ".lock")):
        raise HostileRepoError(f"Git ref has forbidden trailing sequence: {ref!r}")
    if ".." in ref or "//" in ref or "@{" in ref or "/." in ref or ".lock/" in ref:
        raise HostileRepoError(f"Git ref contains forbidden sequence: {ref!r}")
    if _TILDE_ABUSE_RE.search(ref) or _CARET_ABUSE_RE.search(ref):
        raise HostileRepoError(f"Git ref contains invalid revision suffix: {ref!r}")
    return ref


def _unquote_diff_path(raw_path: str) -> str:
    """Decodes git C-quoted diff paths (with UTF-8 octal escapes) and strips `a/`/`b/` prefixes."""
    text = raw_path.rstrip("\r")
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        inner = text[1:-1]
        buf = bytearray()
        idx = 0
        length = len(inner)
        escape_map = {
            "a": b"\a",
            "b": b"\b",
            "f": b"\f",
            "n": b"\n",
            "r": b"\r",
            "t": b"\t",
            "v": b"\v",
            "\\": b"\\",
            '"': b'"',
        }
        while idx < length:
            ch = inner[idx]
            if ch == "\\" and idx + 1 < length:
                nxt = inner[idx + 1]
                if nxt in "01234567":
                    oct_digits = inner[idx + 1 : idx + 4]
                    oct_len = 0
                    for d in oct_digits:
                        if d in "01234567":
                            oct_len += 1
                        else:
                            break
                    buf.append(int(inner[idx + 1 : idx + 1 + oct_len], 8) & 0xFF)
                    idx += 1 + oct_len
                    continue
                if nxt in escape_map:
                    buf.extend(escape_map[nxt])
                    idx += 2
                    continue
                buf.extend(nxt.encode("utf-8", errors="replace"))
                idx += 2
                continue
            buf.extend(ch.encode("utf-8", errors="replace"))
            idx += 1
        text = buf.decode("utf-8", errors="replace")

    if text.startswith(("a/", "b/")):
        text = text[2:]
    text = text.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def parse_unified_diff_added_lines(
    diff_text: str,
) -> Tuple[List[str], Dict[str, Set[int]], Set[str]]:
    """
    Parses `git diff --unified=0 --no-renames` output into:
      `(changed_files, added_lines_by_file, newly_added_files)`
    Handles `--- /dev/null`, `+++ b/...`, `+++ /dev/null`, C-quoted paths,
    omitted hunk counts (defaulting to 1), and pure-deletion hunks (`+c,0`).
    """
    changed_files: List[str] = []
    changed_seen: Set[str] = set()
    added_lines_by_file: Dict[str, Set[int]] = {}
    newly_added_files: Set[str] = set()

    current_file: Optional[str] = None
    current_is_new = False
    rem_del = 0
    rem_add = 0

    for raw_line in (diff_text or "").splitlines():
        line = raw_line.rstrip("\r")

        if rem_del > 0 or rem_add > 0:
            if line.startswith("diff --git "):
                rem_del = 0
                rem_add = 0
            elif rem_del > 0 and line.startswith("-"):
                rem_del -= 1
                continue
            elif rem_add > 0 and line.startswith("+"):
                rem_add -= 1
                continue
            elif line.startswith(" "):
                if rem_del > 0:
                    rem_del -= 1
                if rem_add > 0:
                    rem_add -= 1
                continue
            elif line.startswith("\\"):
                continue
            else:
                # Header-only diff snippets without hunk body lines fall through cleanly
                rem_del = 0
                rem_add = 0

        if line.startswith("diff --git "):
            current_file = None
            current_is_new = False
            continue
        if line.startswith("new file mode "):
            current_is_new = True
            continue
        if line.startswith("deleted file mode "):
            current_is_new = False
            continue
        if line.startswith("--- "):
            src_raw = line[4:]
            current_is_new = src_raw.strip() == "/dev/null"
            continue
        if line.startswith("+++ "):
            dst_raw = line[4:]
            if dst_raw.strip() == "/dev/null":
                current_file = None
                continue
            norm_path = _unquote_diff_path(dst_raw)
            if not norm_path:
                current_file = None
                continue
            current_file = norm_path
            if norm_path not in changed_seen:
                changed_seen.add(norm_path)
                changed_files.append(norm_path)
            added_lines_by_file.setdefault(norm_path, set())
            if current_is_new:
                newly_added_files.add(norm_path)
            continue

        hunk_match = _HUNK_HEADER_RE.match(line)
        if hunk_match:
            old_count = int(hunk_match.group(2)) if hunk_match.group(2) is not None else 1
            new_start = int(hunk_match.group(3))
            new_count = int(hunk_match.group(4)) if hunk_match.group(4) is not None else 1
            rem_del = old_count
            rem_add = new_count
            if current_file is not None and new_count > 0:
                added_lines_by_file.setdefault(current_file, set()).update(
                    range(new_start, new_start + new_count)
                )

    return changed_files, added_lines_by_file, newly_added_files


def _normalize_repo_relpath(raw_path: str, real_repo: str) -> str:
    cleaned = str(raw_path or "").replace("\\", "/").strip()
    if not cleaned:
        return ""
    repo_norm = real_repo.replace("\\", "/").rstrip("/")
    if cleaned.lower().startswith(repo_norm.lower() + "/"):
        cleaned = cleaned[len(repo_norm) + 1 :]
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.lstrip("/")


def _validate_repo_dir(project_path: str) -> str:
    if not isinstance(project_path, str) or not project_path.strip():
        raise HostileRepoError("project_path must be a non-empty directory path")
    if any(ch in project_path for ch in ("\r", "\n", "\x00")):
        raise HostileRepoError("project_path contains forbidden control characters")
    cleaned = project_path.strip()
    if cleaned.startswith("-"):
        raise HostileRepoError("project_path cannot start with '-'")
    if "://" in cleaned:
        raise HostileRepoError("Remote URLs are not supported; supply a local repository path")
    parts = [p for p in re.split(r"[\\/]+", cleaned) if p]
    if any(p == ".." for p in parts):
        raise HostileRepoError("Path traversal '..' is forbidden in project_path")
    real_repo = os.path.realpath(cleaned)
    if not os.path.isdir(real_repo):
        raise ValueError(f"Repository path does not exist or is not a directory: {project_path}")
    return real_repo


def _extract_finding_location(finding: Finding, real_repo: str) -> Tuple[str, int, List[int]]:
    """
    Returns `(primary_filepath, primary_line, same_file_node_lines)` for classification.
    """
    primary_fp = ""
    primary_line = 1
    if finding.best_fix_location and finding.best_fix_location.filepath:
        primary_fp = _normalize_repo_relpath(finding.best_fix_location.filepath, real_repo)
        primary_line = max(1, int(finding.best_fix_location.line or 1))
    elif finding.path_nodes:
        sink_node = finding.path_nodes[-1] if isinstance(finding.path_nodes[-1], dict) else {}
        primary_fp = _normalize_repo_relpath(str(sink_node.get("filepath") or ""), real_repo)
        primary_line = max(1, int(sink_node.get("start_line") or 1))

    same_file_lines: List[int] = [primary_line]
    if finding.path_nodes:
        last_node = finding.path_nodes[-1]
        if isinstance(last_node, dict):
            last_fp = _normalize_repo_relpath(str(last_node.get("filepath") or ""), real_repo)
            if last_fp and last_fp == primary_fp:
                last_ln = max(1, int(last_node.get("start_line") or 1))
                if last_ln not in same_file_lines:
                    same_file_lines.append(last_ln)

    return primary_fp, primary_line, same_file_lines


def _node_touches_changed_lines(
    node: CPGNode,
    node_fp: str,
    node_by_id: Dict[str, CPGNode],
    added_lines_by_file: Dict[str, Set[int]],
    newly_added_files: Set[str],
) -> bool:
    if node_fp in newly_added_files:
        return True
    added_lines = added_lines_by_file.get(node_fp)
    if not added_lines:
        # File had pure deletions / header modifications; any call/function inside it is in-context
        return True
    span_node = node
    if node.label != "Function" and node.scope_id and node.scope_id in node_by_id:
        scoped = node_by_id[node.scope_id]
        if scoped.label == "Function" and _normalize_repo_relpath(scoped.filepath, "") == node_fp:
            span_node = scoped
    lo = max(1, int(span_node.start_line or 1) - 1)
    hi = max(lo, int(span_node.end_line or span_node.start_line or 1) + 1)
    return any(lo <= ln <= hi for ln in added_lines)


def _compute_impacted_neighbor_files(
    all_nodes: Sequence[CPGNode],
    all_edges: Sequence[CPGEdge],
    changed_files_set: Set[str],
    added_lines_by_file: Dict[str, Set[int]],
    newly_added_files: Set[str],
    real_repo: str,
) -> List[str]:
    if not changed_files_set or not all_nodes or not all_edges:
        return []

    node_by_id: Dict[str, CPGNode] = {n.id: n for n in all_nodes}
    neighbors: Set[str] = set()

    for edge in all_edges:
        if edge.edge_type not in ("CALLS", "DFG_FLOWS_TO"):
            continue
        src_node = node_by_id.get(edge.source_id)
        tgt_node = node_by_id.get(edge.target_id)
        if src_node is None or tgt_node is None:
            continue
        src_fp = _normalize_repo_relpath(src_node.filepath, real_repo)
        tgt_fp = _normalize_repo_relpath(tgt_node.filepath, real_repo)
        if not src_fp or not tgt_fp or src_fp == tgt_fp:
            continue

        if tgt_fp in changed_files_set and src_fp not in changed_files_set:
            if _node_touches_changed_lines(
                tgt_node, tgt_fp, node_by_id, added_lines_by_file, newly_added_files
            ):
                neighbors.add(src_fp)
        elif src_fp in changed_files_set and tgt_fp not in changed_files_set:
            if _node_touches_changed_lines(
                src_node, src_fp, node_by_id, added_lines_by_file, newly_added_files
            ):
                neighbors.add(tgt_fp)

    return sorted(neighbors)


def _run_standalone_deterministic_scan(
    real_repo: str,
    vault_dir: Optional[str] = None,
) -> Tuple[List[Finding], List[CPGNode], List[CPGEdge]]:
    """
    Runs ALASTOR's isolated deterministic CPG + SAST/SCA/IaC + offline Secret scan
    without mutating or writing anything inside `real_repo`.
    """
    app_tree, scanned_files, all_nodes, all_edges, comm_map = _build_cpg_for_repo(real_repo)

    with tempfile.TemporaryDirectory(prefix="alastor_prgate_") as tmpdir:
        em_data_dir = os.path.join(tmpdir, "em_data")
        sv_root = os.path.join(tmpdir, "sv_root")
        os.makedirs(em_data_dir, exist_ok=True)
        os.makedirs(sv_root, exist_ok=True)

        gstore = EmbeddedGraphStore(os.path.join(tmpdir, "cpg.db"))
        try:
            gstore.init_schema()
            gstore.ingest_app_tree(app_tree)
            if all_nodes or all_edges:
                gstore.ingest_cpg(all_nodes, all_edges)
            gstore.save_communities(comm_map)

            local_em = EnterpriseManager()
            local_em.data_dir = em_data_dir
            local_em.vault_dir = tmpdir
            if os.environ.get("ALASTOR_FLEET_LIVE_OSV", "").strip() != "1":
                for q in local_em.queries:
                    if q.id == "SCA-2-LIVE-CVE-LOCKFILE":
                        q.enabled = False
            enabled_rule_ids = {q.id for q in local_em.queries if q.enabled}
            query_overrides = {q.id: q for q in local_em.queries}

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
                if fp and os.path.exists(os.path.join(real_repo, fp)):
                    sast_verified.append(sf_item)

            sca_iac_findings: List[Finding] = []
            try:
                sca_iac_findings = local_em.run_sca_and_iac_scanners(real_repo)
            except Exception as exc:
                logger.warning("Non-fatal SCA/IaC error during PR delta scan: %s", str(exc)[:120])

            sv_engine = SecretValidatorEngine(platform_root=sv_root)
            sv_engine._live_enabled = False
            sv_engine._scan_git_history = False
            combined = sv_engine.scan_and_validate_workspace(
                real_repo,
                list(sast_verified) + list(sca_iac_findings),
                allow_live=False,
            )

            ev_map: Dict[str, Tuple[str, str]] = {}
            if vault_dir and os.path.isdir(os.path.realpath(vault_dir)):
                try:
                    ev_map = ExploitVerificationEngine(os.path.realpath(vault_dir)).get_confirmed_status_map(
                        real_repo
                    )
                except Exception as exc:
                    logger.warning("Non-fatal EV map lookup error: %s", str(exc)[:120])

            enriched: List[Finding] = []
            for raw_f in combined:
                f = raw_f.model_copy(deep=True)
                q_rule = query_overrides.get(f.rule_id)
                if q_rule:
                    f.scan_engine = q_rule.engine
                last_fp = f.path_nodes[-1].get("filepath", "") if f.path_nodes else ""
                if f.scan_engine == "SAST" or not f.language or f.language == "Python":
                    f.language = infer_language_from_filepath(str(last_fp), f.rule_id)
                f.best_fix_location = preserve_or_compute_best_fix_location(f)
                if f.id in ev_map:
                    ev_st, ev_sum = ev_map[f.id]
                    extra_raw = [f.secret_value_raw] if f.secret_value_raw else None
                    f.ev_status = ev_st  # type: ignore[assignment]
                    f.ev_evidence_summary = scrub_raw_secrets_text(
                        ev_sum or "",
                        extra_raw_secrets=extra_raw,
                    )
                enriched.append(f)

            return enriched, all_nodes, all_edges
        finally:
            gstore.close()


def _is_blocking_new_finding(
    finding: Finding,
    req: PrDeltaGateRequest,
) -> bool:
    if finding.triage_status in ("NOT_EXPLOITABLE", "RESOLVED"):
        return False
    sev_rank = _SEVERITY_RANK.get(str(finding.severity or "INFO").upper(), 0)
    threshold_rank = _SEVERITY_RANK.get(req.fail_on_new_severity, 3)
    if sev_rank >= threshold_rank:
        return True
    is_secret = bool(
        finding.is_secret_finding
        or (finding.rule_id or "").upper().startswith("SECRET-")
        or (finding.cwe_id or "").upper() == "CWE-798"
    )
    if req.block_on_new_secrets and is_secret:
        return True
    if req.block_on_new_ev_confirmed and finding.ev_status == "RUNTIME_EXPLOIT_CONFIRMED":
        return True
    return False


def _build_pr_markdown_summary(
    *,
    gate_decision: str,
    gate_reason: str,
    base_ref: str,
    head_ref: str,
    changed_files: Sequence[str],
    impacted_neighbor_files: Sequence[str],
    newly_introduced_count: int,
    modified_context_count: int,
    pre_existing_count: int,
    blocking_count: int,
    annotations: Sequence[PrDeltaAnnotation],
    extra_raw_secrets: Sequence[str],
) -> str:
    badge = "BLOCK_MERGE" if gate_decision == "BLOCK_MERGE" else "PASS"
    lines: List[str] = [
        f"## ALASTOR PR Delta Security Gate: `{badge}`",
        "",
        f"- **Refs:** `{base_ref}` -> `{head_ref}`",
        f"- **Changed Files:** {len(changed_files)} | **Impacted CPG Neighbors:** {len(impacted_neighbor_files)}",
        (
            f"- **Findings Delta:** `{newly_introduced_count}` Newly Introduced "
            f"(`{blocking_count}` Blocking) | `{modified_context_count}` Modified Context | "
            f"`{pre_existing_count}` Pre-Existing"
        ),
        f"- **Verdict Reason:** {gate_reason}",
        "",
    ]

    delta_rows = [
        a for a in annotations if a.classification in ("NEWLY_INTRODUCED", "MODIFIED_CONTEXT")
    ]
    if delta_rows:
        lines.extend(
            [
                "| Classification | Severity | Rule | CWE | Location | Title |",
                "|---|---|---|---|---|---|",
            ]
        )
        for ann in delta_rows[:30]:
            cwe_label = ann.cwe_id or "-"
            safe_title = ann.title.replace("|", "\\|").replace("\n", " ").strip()
            lines.append(
                f"| `{ann.classification}` | **{ann.severity}** | `{ann.rule_id}` | "
                f"`{cwe_label}` | `{ann.filepath}:{ann.line}` | {safe_title} |"
            )
    else:
        lines.append("_No newly introduced or modified-context findings detected in this PR delta._")

    if impacted_neighbor_files:
        preview_neighbors = ", ".join(f"`{nf}`" for nf in impacted_neighbor_files[:10])
        suffix = f" (+{len(impacted_neighbor_files) - 10} more)" if len(impacted_neighbor_files) > 10 else ""
        lines.extend(["", f"**1-Hop CPG Blast Radius Neighbors:** {preview_neighbors}{suffix}"])

    return scrub_raw_secrets_text("\n".join(lines), extra_raw_secrets=extra_raw_secrets)


def evaluate_pr_delta_gate(
    req: PrDeltaGateRequest,
    findings: Optional[List[Finding]] = None,
    vault_dir: Optional[str] = None,
) -> PrDeltaGateResponse:
    """
    Evaluates a PR/git-diff delta against ALASTOR security findings and enforces
    merge-gate policies with hostile-repo safety and zero raw-secret leakage.
    """
    real_repo = _validate_repo_dir(req.project_path)
    base_ref = validate_git_ref(req.base_ref)
    head_ref = validate_git_ref(req.head_ref)

    if head_ref == "WORKTREE":
        diff_args = ["diff", "--unified=0", "--no-renames", base_ref, "--"]
    else:
        diff_args = ["diff", "--unified=0", "--no-renames", f"{base_ref}..{head_ref}", "--"]

    diff_proc = run_hardened_git(real_repo, diff_args)
    if diff_proc.returncode != 0:
        err_detail = scrub_raw_secrets_text(
            (diff_proc.stderr or diff_proc.stdout or "").strip()
        )
        raise ValueError(
            f"Hardened git diff failed (exit {diff_proc.returncode}) for {base_ref}..{head_ref}: {err_detail}"
        )

    changed_files, added_lines_by_file, newly_added_files = parse_unified_diff_added_lines(
        diff_proc.stdout or ""
    )
    changed_files_set = set(changed_files)

    all_nodes: List[CPGNode] = []
    all_edges: List[CPGEdge] = []

    if findings is None:
        raw_findings, all_nodes, all_edges = _run_standalone_deterministic_scan(
            real_repo=real_repo,
            vault_dir=vault_dir,
        )
    else:
        raw_findings = [f.model_copy(deep=True) for f in findings]
        if req.include_cpg_neighbors and changed_files_set:
            try:
                _, _, all_nodes, all_edges, _ = _build_cpg_for_repo(real_repo)
            except Exception as exc:
                logger.warning("Non-fatal CPG neighbor build error: %s", str(exc)[:120])

    impacted_neighbor_files: List[str] = []
    if req.include_cpg_neighbors and changed_files_set:
        impacted_neighbor_files = _compute_impacted_neighbor_files(
            all_nodes=all_nodes,
            all_edges=all_edges,
            changed_files_set=changed_files_set,
            added_lines_by_file=added_lines_by_file,
            newly_added_files=newly_added_files,
            real_repo=real_repo,
        )
    neighbor_set = set(impacted_neighbor_files)

    extra_raw_secrets = [
        f.secret_value_raw
        for f in raw_findings
        if isinstance(f.secret_value_raw, str) and len(f.secret_value_raw) >= 4
    ]

    annotations: List[PrDeltaAnnotation] = []
    newly_introduced_findings: List[Finding] = []
    newly_introduced_count = 0
    modified_context_count = 0
    pre_existing_count = 0
    blocking_count = 0

    for raw_f in raw_findings:
        filepath, line_num, candidate_lines = _extract_finding_location(raw_f, real_repo)

        classification: PrDeltaClassification
        if filepath in changed_files_set:
            added_lines = added_lines_by_file.get(filepath, set())
            is_within_added = filepath in newly_added_files or any(
                abs(cand_ln - added_ln) <= 2
                for cand_ln in candidate_lines
                for added_ln in added_lines
            )
            if is_within_added:
                classification = "NEWLY_INTRODUCED"
            else:
                classification = "MODIFIED_CONTEXT"
        elif filepath in neighbor_set:
            classification = "MODIFIED_CONTEXT"
        else:
            classification = "PRE_EXISTING"

        scrubbed_f = scrub_finding_secrets(
            raw_f,
            extra_raw_secrets=extra_raw_secrets,
            clear_raw_secret=True,
        )

        if classification == "NEWLY_INTRODUCED":
            newly_introduced_count += 1
            newly_introduced_findings.append(scrubbed_f)
            if _is_blocking_new_finding(raw_f, req):
                blocking_count += 1
        elif classification == "MODIFIED_CONTEXT":
            modified_context_count += 1
        else:
            pre_existing_count += 1

        raw_msg = (
            f"[{classification}] {scrubbed_f.description or scrubbed_f.title}"
            + (f" — Fix: {scrubbed_f.remediation}" if scrubbed_f.remediation else "")
        )
        annotations.append(
            PrDeltaAnnotation(
                finding_id=scrubbed_f.id,
                classification=classification,
                severity=str(scrubbed_f.severity),
                rule_id=scrubbed_f.rule_id,
                cwe_id=scrubbed_f.cwe_id or "",
                filepath=filepath,
                line=line_num,
                title=scrub_raw_secrets_text(scrubbed_f.title, extra_raw_secrets=extra_raw_secrets),
                message=scrub_raw_secrets_text(raw_msg, extra_raw_secrets=extra_raw_secrets)[:500],
            )
        )

    annotations.sort(
        key=lambda a: (
            _CLASSIFICATION_ORDER.get(a.classification, 9),
            -_SEVERITY_RANK.get(a.severity.upper(), 0),
            a.filepath,
            a.line,
            a.rule_id,
        )
    )

    if blocking_count > 0:
        gate_decision = "BLOCK_MERGE"
        gate_reason = (
            f"Blocked merge: {blocking_count} newly introduced finding(s) violate PR gate policy "
            f"(severity>={req.fail_on_new_severity}, secrets={req.block_on_new_secrets}, "
            f"ev_confirmed={req.block_on_new_ev_confirmed})."
        )
    else:
        gate_decision = "PASS"
        gate_reason = (
            f"Passed PR delta gate: 0 blocking newly introduced findings "
            f"({newly_introduced_count} newly introduced, {modified_context_count} modified-context, "
            f"{pre_existing_count} pre-existing)."
        )

    gate_reason = scrub_raw_secrets_text(gate_reason, extra_raw_secrets=extra_raw_secrets)
    pr_markdown_summary = _build_pr_markdown_summary(
        gate_decision=gate_decision,
        gate_reason=gate_reason,
        base_ref=base_ref,
        head_ref=head_ref,
        changed_files=changed_files,
        impacted_neighbor_files=impacted_neighbor_files,
        newly_introduced_count=newly_introduced_count,
        modified_context_count=modified_context_count,
        pre_existing_count=pre_existing_count,
        blocking_count=blocking_count,
        annotations=annotations,
        extra_raw_secrets=extra_raw_secrets,
    )

    return PrDeltaGateResponse(
        project_path=real_repo,
        base_ref=base_ref,
        head_ref=head_ref,
        gate_decision=gate_decision,  # type: ignore[arg-type]
        gate_reason=gate_reason,
        changed_files=changed_files,
        impacted_neighbor_files=impacted_neighbor_files,
        newly_introduced_count=newly_introduced_count,
        modified_context_count=modified_context_count,
        pre_existing_count=pre_existing_count,
        blocking_count=blocking_count,
        annotations=annotations,
        newly_introduced_findings=newly_introduced_findings,
        pr_markdown_summary=pr_markdown_summary,
    )
