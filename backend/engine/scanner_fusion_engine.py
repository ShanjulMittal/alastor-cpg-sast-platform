"""
ALASTOR v5.0 Pillar 4 — Universal 6-Format Scanner Fusion & CPG Corroboration Engine.

Supports auto-detection, strict workspace-confined path normalization, mandatory raw-secret
scrubbing, CPG node/function/community enrichment, cross-engine deduplication (`corroborated_by`),
and optional deterministic S6 Adversarial Verification across:
  1. SARIF 2.1.0 (`SARIF_2_1`)
  2. CodeQL SARIF (`CODEQL_SARIF`)
  3. Semgrep JSON (`SEMGREP_JSON`)
  4. Trivy JSON (`TRIVY_JSON` — Vulnerabilities, Misconfigurations, Secrets)
  5. Gitleaks JSON (`GITLEAKS_JSON`)
  6. Checkov JSON (`CHECKOV_JSON` — single-dict and multi-framework list)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote, urlsplit

from compiler.ast_parser import ASTNormalizer
from compiler.language_registry import resolve_language_for_filename
from compiler.scanner import ScannedFile, _is_confined, _is_link_or_junction
from engine.adversarial_verifier import verify_findings_adversarially
from engine.enterprise_manager import compute_best_fix_location, infer_language_from_filepath
from engine.frontier_ai_engine import scrub_raw_secrets_text
from models import (
    BestFixLocation,
    CPGNode,
    CommunityMapResponse,
    Finding,
    ScannerFormatType,
    ScannerFusionResponse,
)

logger = logging.getLogger("cpg-sast.scanner-fusion")

_MAX_REPORT_BYTES = 50 * 1024 * 1024
_REDACTED_MARKER = "[REDACTED_" + "SECRET]"

_VALID_SCANNER_FORMATS: Set[str] = {
    "SARIF_2_1",
    "CODEQL_SARIF",
    "SEMGREP_JSON",
    "TRIVY_JSON",
    "GITLEAKS_JSON",
    "CHECKOV_JSON",
}

_SOURCE_ENGINE_BY_FORMAT: Dict[ScannerFormatType, str] = {
    "SARIF_2_1": "SARIF",
    "CODEQL_SARIF": "CODEQL",
    "SEMGREP_JSON": "SEMGREP",
    "TRIVY_JSON": "TRIVY",
    "GITLEAKS_JSON": "GITLEAKS",
    "CHECKOV_JSON": "CHECKOV",
}

_FORMAT_BY_SOURCE_ENGINE: Dict[str, ScannerFormatType] = {
    v: k for k, v in _SOURCE_ENGINE_BY_FORMAT.items()
}

_CWE_RX = re.compile(r"(?:^|[^A-Za-z0-9])cwe[-_:/]?0*(\d+)\b", re.IGNORECASE)
_CVE_RX = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.IGNORECASE)
_QUOTED_TOKEN_RX = re.compile(r"""['"]([A-Za-z0-9_./+=:@-]{6,})['"]""")
_ASSIGN_RHS_RX = re.compile(r"""=\s*['"]?([A-Za-z0-9_./+=:@-]{6,})['"]?""")
_WIN_DRIVE_RX = re.compile(r"^[A-Za-z]:[\\/]")

_CANONICAL_CWE_GROUPS: Dict[str, str] = {
    "CWE-77": "CWE-78",
    "CWE-78": "CWE-78",
    "CWE-89": "CWE-89",
    "CWE-79": "CWE-79",
    "CWE-1336": "CWE-79",
    "CWE-22": "CWE-22",
    "CWE-23": "CWE-22",
    "CWE-73": "CWE-22",
    "CWE-918": "CWE-918",
    "CWE-798": "CWE-798",
    "CWE-259": "CWE-798",
    "CWE-321": "CWE-798",
    "CWE-502": "CWE-502",
    "CWE-611": "CWE-611",
    "CWE-94": "CWE-94",
    "CWE-327": "CWE-328",
    "CWE-328": "CWE-328",
    "CWE-601": "CWE-601",
    "CWE-352": "CWE-352",
}


def _scrub(text: Any, extra_raw_secrets: Optional[Sequence[str]] = None) -> str:
    if text is None:
        return ""
    out = scrub_raw_secrets_text(str(text), extra_raw_secrets=extra_raw_secrets)
    if extra_raw_secrets:
        for raw in sorted({s for s in extra_raw_secrets if isinstance(s, str) and len(s) >= 4}, key=len, reverse=True):
            if raw in out:
                out = out.replace(raw, _REDACTED_MARKER)
    return out.replace("\x00", "")


def scrub_finding_secrets(
    finding: Finding,
    extra_raw_secrets: Optional[Sequence[str]] = None,
    clear_raw_secret: bool = True,
) -> Finding:
    """
    Returns a deep copy of `finding` with all text, path_node, and best_fix_location
    fields scrubbed against `extra_raw_secrets`, `finding.secret_value_raw`, and
    all known credential regexes.
    """
    f = finding.model_copy(deep=True)
    raw_tokens: List[str] = list(extra_raw_secrets or ())
    if f.secret_value_raw and len(f.secret_value_raw) >= 4:
        raw_tokens.append(f.secret_value_raw)

    for attr in (
        "title",
        "description",
        "remediation",
        "plain_english_summary",
        "non_coder_analogy",
        "business_impact",
        "reachability_reason",
        "ev_evidence_summary",
        "secret_validation_message",
    ):
        val = getattr(f, attr, None)
        if isinstance(val, str) and val:
            setattr(f, attr, _scrub(val, raw_tokens))

    if f.management_action_steps:
        f.management_action_steps = [_scrub(step, raw_tokens) for step in f.management_action_steps]

    for node in f.path_nodes or []:
        if isinstance(node, dict):
            for n_key in ("code", "name"):
                if isinstance(node.get(n_key), str) and node[n_key]:
                    node[n_key] = _scrub(node[n_key], raw_tokens)

    if f.best_fix_location is not None:
        for bfl_attr in (
            "code_snippet",
            "explanation",
            "recommended_fix",
            "before_code_block",
            "after_code_block",
        ):
            bval = getattr(f.best_fix_location, bfl_attr, None)
            if isinstance(bval, str) and bval:
                setattr(f.best_fix_location, bfl_attr, _scrub(bval, raw_tokens))

    if clear_raw_secret:
        f.secret_value_raw = None
    return f


def _collect_secret_candidates_from_match(raw_val: Any, out_secrets: Set[str]) -> None:
    if not isinstance(raw_val, str):
        return
    cleaned = raw_val.strip()
    if len(cleaned) >= 4:
        out_secrets.add(cleaned)
    for m in _QUOTED_TOKEN_RX.finditer(cleaned):
        tok = m.group(1).strip()
        if len(tok) >= 4:
            out_secrets.add(tok)
    for m in _ASSIGN_RHS_RX.finditer(cleaned):
        tok = m.group(1).strip()
        if len(tok) >= 4:
            out_secrets.add(tok)


def _normalize_severity(raw_sev: Any, security_severity: Any = None) -> str:
    if security_severity is not None and not isinstance(security_severity, bool):
        try:
            score = float(security_severity)
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            if score > 0.0:
                return "LOW"
            return "INFO"
        except (TypeError, ValueError):
            pass

    up = str(raw_sev or "").strip().upper()
    if up in ("CRITICAL", "CRIT", "BLOCKER"):
        return "CRITICAL"
    if up in ("HIGH", "ERROR", "ERR"):
        return "HIGH"
    if up in ("MEDIUM", "MED", "MODERATE", "WARNING", "WARN"):
        return "MEDIUM"
    if up in ("LOW", "NOTE", "MINOR"):
        return "LOW"
    if up in ("INFO", "INFORMATIONAL", "NONE", "UNKNOWN"):
        return "INFO"
    return "MEDIUM"


def _extract_cwe(*sources: Any) -> Optional[str]:
    queue: List[Any] = list(sources)
    while queue:
        item = queue.pop(0)
        if item is None:
            continue
        if isinstance(item, (list, tuple, set)):
            queue.extend(item)
            continue
        if isinstance(item, dict):
            queue.extend(item.values())
            continue
        text = str(item)
        m = _CWE_RX.search(text)
        if m:
            return f"CWE-{int(m.group(1))}"
    return None


def _infer_cwe_from_keywords(*texts: Any) -> Optional[str]:
    combined = " ".join(str(t or "") for t in texts).lower()
    if not combined.strip():
        return None
    if any(k in combined for k in ("sql-injection", "sql injection", "sqli", "formatted-sql", "sql_injection")):
        return "CWE-89"
    if any(k in combined for k in ("command-line-injection", "command-injection", "command injection", "os-command", "shell=true", "cmdi")):
        return "CWE-78"
    if any(k in combined for k in ("cross-site scripting", "dom-xss", "innerhtml", "xss")):
        return "CWE-79"
    if any(k in combined for k in ("path-traversal", "path traversal", "directory traversal")):
        return "CWE-22"
    if "ssrf" in combined or "server-side request forgery" in combined:
        return "CWE-918"
    if any(k in combined for k in ("deserial", "pickle", "yaml.load", "objectinputstream")):
        return "CWE-502"
    if "xxe" in combined or "external entity" in combined:
        return "CWE-611"
    if any(k in combined for k in ("hardcoded", "access key", "secret", "credential", "api-key", "api_key", "token")):
        return "CWE-798"
    if any(k in combined for k in ("open redirect", "open-redirect")):
        return "CWE-601"
    return None


def _infer_checkov_cwe(check_id: str, check_name: str, resource: str) -> str:
    explicit = _extract_cwe(check_id, check_name)
    if explicit:
        return explicit
    combined = f"{check_id} {check_name} {resource}".lower()
    if any(k in combined for k in ("user ", "root", "privileged", "uid 0", "sudo")):
        return "CWE-250"
    if any(k in combined for k in ("secret", "password", "token", "credential", "api key")):
        return "CWE-798"
    if any(k in combined for k in ("public", "acl", "iam", "policy", "permission", "role", "0.0.0.0/0", "access")):
        return "CWE-732"
    if any(k in combined for k in ("encrypt", "kms", "tls", "ssl", "https", "cipher")):
        return "CWE-311"
    return "CWE-16"


def _normalize_external_path(raw_path: Any, repo_root: Optional[str] = None) -> str:
    text = str(raw_path or "").strip()
    if not text:
        return "workspace"
    if any(ch in text for ch in ("\r", "\n", "\x00")):
        raise ValueError("External report location contains forbidden control characters")

    if text.lower().startswith("file://"):
        parsed = urlsplit(text)
        netloc = unquote(parsed.netloc or "")
        uri_path = unquote(parsed.path or "")
        if netloc and netloc.lower() != "localhost":
            if re.match(r"^[A-Za-z]:$", netloc):
                text = f"{netloc}{uri_path}"
            elif uri_path:
                text = f"{netloc.rstrip('/')}/{uri_path.lstrip('/')}"
            else:
                text = netloc
        else:
            text = uri_path
        if re.match(r"^/[A-Za-z]:[\\/]", text):
            text = text[1:]
    else:
        text = unquote(text) if "%" in text else text

    slash_path = text.replace("\\", "/")
    raw_segments = [seg for seg in slash_path.split("/") if seg]
    if any(seg == ".." for seg in raw_segments):
        raise ValueError(f"Path traversal '..' segment rejected in external scanner report: {raw_path}")

    if repo_root:
        abs_root = os.path.abspath(repo_root).replace("\\", "/").rstrip("/")
        real_root = os.path.realpath(repo_root).replace("\\", "/").rstrip("/")
        roots = [r for r in (real_root, abs_root) if r]
        for root_cand in roots:
            if os.name == "nt":
                low_p = slash_path.lower()
                low_r = root_cand.lower()
                if low_p == low_r:
                    return "workspace"
                if low_p.startswith(low_r + "/"):
                    slash_path = slash_path[len(root_cand) + 1 :]
                    break
            else:
                if slash_path == root_cand:
                    return "workspace"
                if slash_path.startswith(root_cand + "/"):
                    slash_path = slash_path[len(root_cand) + 1 :]
                    break

        if _WIN_DRIVE_RX.match(slash_path):
            raise ValueError(f"External report path escapes repository root: {raw_path}")

    while slash_path.startswith("./"):
        slash_path = slash_path[2:]
    slash_path = slash_path.lstrip("/")
    if not slash_path or slash_path == ".":
        return "workspace"

    clean_parts = [p for p in slash_path.split("/") if p and p != "."]
    if any(p == ".." for p in clean_parts):
        raise ValueError(f"Path traversal '..' segment rejected in external scanner report: {raw_path}")
    return "/".join(clean_parts) or "workspace"


def _make_finding_id(engine: str, rule_id: str, filepath: str, line: int, index: int) -> str:
    material = f"{engine}|{rule_id}|{filepath}|{line}|{index}".encode("utf-8", errors="replace")
    return f"ext-{hashlib.sha256(material).hexdigest()[:14]}"


def _is_checkov_dict(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    if "check_type" in item:
        return True
    res = item.get("results")
    return isinstance(res, dict) and any(
        k in res for k in ("failed_checks", "passed_checks", "skipped_checks")
    )


def _is_gitleaks_item(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    return "RuleID" in item and ("Secret" in item or "Match" in item or "Fingerprint" in item)


def detect_scanner_format(payload: Any) -> ScannerFormatType:
    """
    Auto-detects the external security scanner JSON format across:
    SARIF_2_1, CODEQL_SARIF, SEMGREP_JSON, TRIVY_JSON, GITLEAKS_JSON, and CHECKOV_JSON.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed scanner JSON payload: {exc}") from exc

    if isinstance(payload, list):
        if not payload:
            raise ValueError("Empty JSON list cannot be unambiguously detected without explicit source_format")
        if all(_is_checkov_dict(item) for item in payload):
            return "CHECKOV_JSON"
        if any(_is_gitleaks_item(item) for item in payload) and all(isinstance(item, dict) for item in payload):
            return "GITLEAKS_JSON"
        raise ValueError("Unrecognizable list scanner report format")

    if not isinstance(payload, dict):
        raise ValueError("Scanner payload must be a JSON object or array")

    # 1. SARIF 2.1.0 / CodeQL SARIF
    runs = payload.get("runs")
    schema_str = str(payload.get("$schema") or "").lower()
    version_str = str(payload.get("version") or "").strip()
    if isinstance(runs, list) and (
        "sarif" in schema_str
        or version_str == "2.1.0"
        or (runs and isinstance(runs[0], dict) and ("tool" in runs[0] or "results" in runs[0]))
    ):
        for run in runs:
            if not isinstance(run, dict):
                continue
            driver_name = str((((run.get("tool") or {}).get("driver") or {}).get("name")) or "").lower()
            if "codeql" in driver_name:
                return "CODEQL_SARIF"
        return "SARIF_2_1"

    # 2. Checkov JSON (dict variant)
    if _is_checkov_dict(payload):
        return "CHECKOV_JSON"

    # 3. Trivy JSON
    if isinstance(payload.get("Results"), list) or (
        "SchemaVersion" in payload and ("ArtifactName" in payload or "ArtifactType" in payload)
    ):
        return "TRIVY_JSON"

    # 4. Semgrep JSON
    semgrep_results = payload.get("results")
    if isinstance(semgrep_results, list) and (
        any(isinstance(r, dict) and "check_id" in r for r in semgrep_results)
        or "errors" in payload
        or "version" in payload
        or "paths" in payload
    ):
        return "SEMGREP_JSON"

    raise ValueError("Unrecognizable scanner JSON format")


def _validate_explicit_format(payload: Any, fmt: ScannerFormatType) -> None:
    if fmt not in _VALID_SCANNER_FORMATS:
        raise ValueError(f"Unsupported source_format '{fmt}'")

    if fmt in ("SARIF_2_1", "CODEQL_SARIF"):
        if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
            raise ValueError(f"Payload is not valid {fmt} (expected object with 'runs' array)")
    elif fmt == "SEMGREP_JSON":
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise ValueError("Payload is not valid SEMGREP_JSON (expected object with 'results' array)")
    elif fmt == "TRIVY_JSON":
        if not isinstance(payload, dict) or not (
            isinstance(payload.get("Results"), list) or "SchemaVersion" in payload
        ):
            raise ValueError("Payload is not valid TRIVY_JSON (expected object with 'Results' array)")
    elif fmt == "GITLEAKS_JSON":
        if not isinstance(payload, list) or not all(isinstance(x, dict) for x in payload):
            raise ValueError("Payload is not valid GITLEAKS_JSON (expected array of objects)")
    elif fmt == "CHECKOV_JSON":
        if isinstance(payload, dict):
            if not _is_checkov_dict(payload):
                raise ValueError("Payload is not valid CHECKOV_JSON")
        elif isinstance(payload, list):
            if not payload or not all(_is_checkov_dict(x) for x in payload):
                raise ValueError("Payload is not valid CHECKOV_JSON list")
        else:
            raise ValueError("Payload is not valid CHECKOV_JSON")


def _build_sarif_rule_index(run: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
    driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
    rules_list: List[Dict[str, Any]] = []
    by_id: Dict[str, Dict[str, Any]] = {}

    raw_driver_rules = driver.get("rules")
    if isinstance(raw_driver_rules, list):
        for r in raw_driver_rules:
            if isinstance(r, dict):
                rules_list.append(r)
                if r.get("id"):
                    by_id[str(r["id"])] = r

    raw_exts = tool.get("extensions")
    if isinstance(raw_exts, list):
        for ext in raw_exts:
            if not isinstance(ext, dict):
                continue
            for r in ext.get("rules") or []:
                if isinstance(r, dict) and r.get("id"):
                    by_id.setdefault(str(r["id"]), r)

    return by_id, rules_list


def _extract_sarif_location(
    loc_obj: Any,
    repo_root: Optional[str],
    raw_secrets: Set[str],
) -> Tuple[str, int, int, int, int, str]:
    if not isinstance(loc_obj, dict):
        return "workspace", 1, 1, 0, 0, ""
    phys = loc_obj.get("physicalLocation") if isinstance(loc_obj.get("physicalLocation"), dict) else {}
    art = phys.get("artifactLocation") if isinstance(phys.get("artifactLocation"), dict) else {}
    uri = art.get("uri") or art.get("uriBaseId") or "workspace"
    rel_fp = _normalize_external_path(uri, repo_root=repo_root)

    reg = phys.get("region") if isinstance(phys.get("region"), dict) else {}
    start_line = max(1, int(reg.get("startLine") or 1))
    end_line = max(start_line, int(reg.get("endLine") or start_line))
    start_col = max(0, int(reg.get("startColumn") or 0))
    end_col = max(0, int(reg.get("endColumn") or 0))
    snippet_obj = reg.get("snippet") if isinstance(reg.get("snippet"), dict) else {}
    snippet = _scrub(snippet_obj.get("text") or "", list(raw_secrets))
    return rel_fp, start_line, end_line, start_col, end_col, snippet


def _parse_sarif_findings(
    payload: Dict[str, Any],
    fmt: ScannerFormatType,
    repo_root: Optional[str],
) -> List[Finding]:
    source_engine = _SOURCE_ENGINE_BY_FORMAT[fmt]
    findings: List[Finding] = []
    runs = payload.get("runs") or []
    idx_counter = 0

    for run in runs:
        if not isinstance(run, dict):
            continue
        rules_by_id, rules_list = _build_sarif_rule_index(run)
        driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run.get("tool"), dict) else {}
        tool_name = str(driver.get("name") or source_engine)

        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            idx_counter += 1
            raw_rule_id = str(res.get("ruleId") or "").strip()
            rule_meta: Dict[str, Any] = {}
            if raw_rule_id and raw_rule_id in rules_by_id:
                rule_meta = rules_by_id[raw_rule_id]
            elif isinstance(res.get("ruleIndex"), int) and 0 <= res["ruleIndex"] < len(rules_list):
                rule_meta = rules_list[res["ruleIndex"]]
                if not raw_rule_id:
                    raw_rule_id = str(rule_meta.get("id") or "RULE")
            if not raw_rule_id:
                raw_rule_id = "RULE"

            res_props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
            rule_props = rule_meta.get("properties") if isinstance(rule_meta.get("properties"), dict) else {}
            sec_sev = res_props.get("security-severity") or rule_props.get("security-severity")
            default_level = ((rule_meta.get("defaultConfiguration") or {}).get("level")) if isinstance(rule_meta.get("defaultConfiguration"), dict) else None
            severity = _normalize_severity(res.get("level") or default_level or "warning", security_severity=sec_sev)

            cvss_val: Optional[float] = None
            if sec_sev is not None and not isinstance(sec_sev, bool):
                try:
                    cvss_val = max(0.0, min(10.0, round(float(sec_sev), 1)))
                except (TypeError, ValueError):
                    cvss_val = None

            msg_obj = res.get("message") if isinstance(res.get("message"), dict) else {}
            msg_text = str(msg_obj.get("text") or msg_obj.get("markdown") or "").strip()
            short_desc = ((rule_meta.get("shortDescription") or {}).get("text")) if isinstance(rule_meta.get("shortDescription"), dict) else ""
            full_desc = ((rule_meta.get("fullDescription") or {}).get("text")) if isinstance(rule_meta.get("fullDescription"), dict) else ""
            help_obj = rule_meta.get("help") if isinstance(rule_meta.get("help"), dict) else {}
            help_text = str(help_obj.get("text") or help_obj.get("markdown") or "").strip()

            cwe_id = _extract_cwe(
                res_props.get("tags"),
                res_props.get("cwe"),
                rule_props.get("tags"),
                rule_props.get("cwe"),
                rule_meta.get("relationships"),
                raw_rule_id,
                rule_meta.get("name"),
                short_desc,
                msg_text,
            ) or _infer_cwe_from_keywords(raw_rule_id, short_desc, msg_text)

            locs = res.get("locations") if isinstance(res.get("locations"), list) else []
            prim_loc = locs[0] if locs else {}
            rel_fp, start_line, end_line, start_col, end_col, snippet = _extract_sarif_location(
                prim_loc, repo_root=repo_root, raw_secrets=set()
            )

            path_nodes: List[Dict[str, Any]] = []
            code_flows = res.get("codeFlows") if isinstance(res.get("codeFlows"), list) else []
            for cf in code_flows[:1]:
                if not isinstance(cf, dict):
                    continue
                tfs = cf.get("threadFlows") if isinstance(cf.get("threadFlows"), list) else []
                for tf in tfs[:1]:
                    if not isinstance(tf, dict):
                        continue
                    tf_locs = tf.get("locations") if isinstance(tf.get("locations"), list) else []
                    for step_idx, tfl in enumerate(tf_locs):
                        if not isinstance(tfl, dict):
                            continue
                        step_loc = tfl.get("location") if isinstance(tfl.get("location"), dict) else {}
                        s_fp, s_ln, s_eln, s_col, s_ecol, s_snip = _extract_sarif_location(
                            step_loc, repo_root=repo_root, raw_secrets=set()
                        )
                        s_msg = _scrub(((step_loc.get("message") or {}).get("text")) or "")
                        is_first = step_idx == 0
                        is_last = step_idx == len(tf_locs) - 1
                        path_nodes.append(
                            {
                                "id": f"{source_engine.lower()}-flow-{idx_counter}-{step_idx}",
                                "label": "Call" if is_last else "Variable",
                                "ast_type": "sarif_threadflow_step",
                                "name": s_msg or (s_snip[:60] if s_snip else raw_rule_id),
                                "code": _scrub(s_snip or s_msg or raw_rule_id),
                                "filepath": s_fp,
                                "start_line": s_ln,
                                "end_line": s_eln,
                                "start_col": s_col,
                                "end_col": s_ecol,
                                "scope_id": "sarif_flow",
                                "is_source": is_first,
                                "is_sink": is_last,
                                "is_sanitizer": False,
                            }
                        )

            if not path_nodes:
                path_nodes.append(
                    {
                        "id": f"{source_engine.lower()}-node-{idx_counter}",
                        "label": "Call",
                        "ast_type": "sarif_location",
                        "name": raw_rule_id,
                        "code": _scrub(snippet or msg_text or raw_rule_id)[:300],
                        "filepath": rel_fp,
                        "start_line": start_line,
                        "end_line": end_line,
                        "start_col": start_col,
                        "end_col": end_col,
                        "scope_id": "external_sarif",
                        "is_source": False,
                        "is_sink": True,
                        "is_sanitizer": False,
                    }
                )
            else:
                path_nodes[-1]["filepath"] = rel_fp
                path_nodes[-1]["start_line"] = start_line
                path_nodes[-1]["is_sink"] = True

            fid = _make_finding_id(source_engine, raw_rule_id, rel_fp, start_line, idx_counter)
            safe_title = _scrub(short_desc or rule_meta.get("name") or msg_text or raw_rule_id)[:220]
            safe_desc = _scrub(msg_text or full_desc or short_desc or safe_title)
            safe_rem = _scrub(help_text) or None
            safe_snip = _scrub(snippet or msg_text or raw_rule_id)[:300]
            rule_id = raw_rule_id if raw_rule_id.startswith("EXT-") else f"EXT-{source_engine}-{raw_rule_id}"
            lang = infer_language_from_filepath(rel_fp, rule_id)
            bfl = BestFixLocation(
                node_id=str(path_nodes[-1]["id"]),
                filepath=rel_fp,
                line=start_line,
                column=start_col,
                code_snippet=safe_snip,
                explanation=f"Imported from {tool_name} ({raw_rule_id}) at {rel_fp}:L{start_line}.",
                recommended_fix=(safe_rem or "")[:300],
            )
            findings.append(
                Finding(
                    id=fid,
                    rule_id=rule_id,
                    severity=severity,  # type: ignore[arg-type]
                    title=safe_title,
                    description=safe_desc,
                    cwe_id=cwe_id,
                    cvss_score=cvss_val,
                    remediation=safe_rem,
                    source_site=tool_name,
                    reference_url=rule_meta.get("helpUri") if isinstance(rule_meta.get("helpUri"), str) else None,
                    path_nodes=path_nodes,
                    path_edges=[],
                    scan_engine="SAST",
                    language=lang,
                    best_fix_location=bfl,
                    source_engine=source_engine,
                    corroborated_by=[],
                )
            )
    return findings


def _parse_semgrep_findings(
    payload: Dict[str, Any],
    repo_root: Optional[str],
) -> List[Finding]:
    findings: List[Finding] = []
    results = payload.get("results") or []
    for idx, res in enumerate(results, start=1):
        if not isinstance(res, dict):
            continue
        raw_rule_id = str(res.get("check_id") or "semgrep-rule").strip()
        rel_fp = _normalize_external_path(res.get("path") or "workspace", repo_root=repo_root)
        start_obj = res.get("start") if isinstance(res.get("start"), dict) else {}
        end_obj = res.get("end") if isinstance(res.get("end"), dict) else {}
        start_line = max(1, int(start_obj.get("line") or 1))
        end_line = max(start_line, int(end_obj.get("line") or start_line))
        start_col = max(0, int(start_obj.get("col") or 0))
        end_col = max(0, int(end_obj.get("col") or 0))

        extra = res.get("extra") if isinstance(res.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        severity = _normalize_severity(extra.get("severity") or metadata.get("severity") or "WARNING")
        raw_msg = str(extra.get("message") or raw_rule_id).strip()
        raw_lines = str(extra.get("lines") or "").strip()
        raw_fix = str(extra.get("fix") or metadata.get("fix") or "").strip()

        cwe_id = _extract_cwe(
            metadata.get("cwe"),
            metadata.get("cwe2021"),
            metadata.get("cwe2022"),
            raw_rule_id,
            raw_msg,
        ) or _infer_cwe_from_keywords(raw_rule_id, raw_msg)

        owasp_raw = metadata.get("owasp")
        owasp_cat: Optional[str] = None
        if isinstance(owasp_raw, list) and owasp_raw:
            owasp_cat = _scrub(owasp_raw[0])
        elif isinstance(owasp_raw, str) and owasp_raw.strip():
            owasp_cat = _scrub(owasp_raw.strip())

        is_secret = cwe_id == "CWE-798" or "secret" in raw_rule_id.lower()
        extra_secrets: Set[str] = set()
        if is_secret and raw_lines:
            _collect_secret_candidates_from_match(raw_lines, extra_secrets)

        safe_msg = _scrub(raw_msg, list(extra_secrets))
        safe_lines = _scrub(raw_lines, list(extra_secrets))[:300]
        safe_fix = _scrub(raw_fix, list(extra_secrets)) or None
        rule_id = raw_rule_id if raw_rule_id.startswith("EXT-") else f"EXT-SEMGREP-{raw_rule_id}"
        fid = _make_finding_id("SEMGREP", raw_rule_id, rel_fp, start_line, idx)
        lang = infer_language_from_filepath(rel_fp, rule_id)
        node_id = f"semgrep-node-{idx}"

        findings.append(
            Finding(
                id=fid,
                rule_id=rule_id,
                severity=severity,  # type: ignore[arg-type]
                title=_scrub(f"{raw_rule_id}: {safe_msg}", list(extra_secrets))[:220],
                description=safe_msg,
                cwe_id=cwe_id,
                owasp_category=owasp_cat,
                remediation=safe_fix,
                source_site="Semgrep",
                path_nodes=[
                    {
                        "id": node_id,
                        "label": "Call",
                        "ast_type": "semgrep_match",
                        "name": raw_rule_id,
                        "code": safe_lines or safe_msg[:200],
                        "filepath": rel_fp,
                        "start_line": start_line,
                        "end_line": end_line,
                        "start_col": start_col,
                        "end_col": end_col,
                        "scope_id": "semgrep",
                        "is_source": False,
                        "is_sink": True,
                        "is_sanitizer": False,
                    }
                ],
                path_edges=[],
                scan_engine="SAST",
                language=lang,
                best_fix_location=BestFixLocation(
                    node_id=node_id,
                    filepath=rel_fp,
                    line=start_line,
                    column=start_col,
                    code_snippet=safe_lines or safe_msg[:200],
                    explanation=f"Semgrep matched `{raw_rule_id}` at {rel_fp}:L{start_line}.",
                    recommended_fix=(safe_fix or "")[:300],
                ),
                is_secret_finding=is_secret,
                secret_value_raw=None,
                secret_value_masked=_REDACTED_MARKER if is_secret else None,
                source_engine="SEMGREP",
                corroborated_by=[],
            )
        )
    return findings


def _parse_trivy_findings(
    payload: Dict[str, Any],
    repo_root: Optional[str],
) -> List[Finding]:
    results = payload.get("Results") or []
    raw_secrets: Set[str] = set()
    for res in results:
        if not isinstance(res, dict):
            continue
        for sec in res.get("Secrets") or []:
            if not isinstance(sec, dict):
                continue
            _collect_secret_candidates_from_match(sec.get("Secret"), raw_secrets)
            _collect_secret_candidates_from_match(sec.get("Match"), raw_secrets)
            code_obj = sec.get("Code") if isinstance(sec.get("Code"), dict) else {}
            for ln in code_obj.get("Lines") or []:
                if isinstance(ln, dict):
                    _collect_secret_candidates_from_match(ln.get("Content"), raw_secrets)

    secret_list = list(raw_secrets)
    findings: List[Finding] = []
    idx_counter = 0

    for res in results:
        if not isinstance(res, dict):
            continue
        rel_fp = _normalize_external_path(res.get("Target") or payload.get("ArtifactName") or "workspace", repo_root=repo_root)

        # 1. Vulnerabilities (SCA)
        for vuln in res.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            idx_counter += 1
            vid = str(vuln.get("VulnerabilityID") or "TRIVY-VULN").strip()
            pkg = str(vuln.get("PkgName") or "package").strip()
            inst_ver = str(vuln.get("InstalledVersion") or "").strip()
            fixed_ver = str(vuln.get("FixedVersion") or "").strip()
            sev = _normalize_severity(vuln.get("Severity") or "HIGH")
            cwe_id = _extract_cwe(vuln.get("CweIDs"), vuln.get("Description"), vuln.get("Title"))
            cve_match = _CVE_RX.search(vid)
            cve_id = cve_match.group(1).upper() if cve_match else None

            cvss_score: Optional[float] = None
            cvss_map = vuln.get("CVSS")
            if isinstance(cvss_map, dict):
                for entry in cvss_map.values():
                    if isinstance(entry, dict) and entry.get("V3Score") is not None:
                        try:
                            cvss_score = max(0.0, min(10.0, round(float(entry["V3Score"]), 1)))
                            break
                        except (TypeError, ValueError):
                            pass

            cause = vuln.get("CauseMetadata") if isinstance(vuln.get("CauseMetadata"), dict) else {}
            start_line = max(1, int(cause.get("StartLine") or 1))
            title = _scrub(vuln.get("Title") or f"{vid} in {pkg}@{inst_ver}", secret_list)[:220]
            desc = _scrub(vuln.get("Description") or title, secret_list)
            rem = (
                _scrub(f"Upgrade `{pkg}` from `{inst_ver}` to `{fixed_ver}`.", secret_list)
                if fixed_ver
                else f"Upgrade or mitigate vulnerable package `{pkg}` ({vid})."
            )
            rule_id = f"EXT-TRIVY-{vid}"
            fid = _make_finding_id("TRIVY", vid, rel_fp, start_line, idx_counter)
            node_id = f"trivy-sca-{idx_counter}"
            code_snip = _scrub(f"{pkg}=={inst_ver}" if inst_ver else pkg, secret_list)

            findings.append(
                Finding(
                    id=fid,
                    rule_id=rule_id,
                    severity=sev,  # type: ignore[arg-type]
                    title=title,
                    description=desc,
                    cwe_id=cwe_id,
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    remediation=rem,
                    source_site="Trivy",
                    reference_url=vuln.get("PrimaryURL") if isinstance(vuln.get("PrimaryURL"), str) else None,
                    path_nodes=[
                        {
                            "id": node_id,
                            "label": "Literal",
                            "ast_type": "trivy_vulnerability",
                            "name": f"{pkg} ({vid})",
                            "code": code_snip,
                            "filepath": rel_fp,
                            "start_line": start_line,
                            "end_line": start_line,
                            "start_col": 0,
                            "end_col": len(code_snip),
                            "scope_id": "trivy_sca",
                            "is_source": False,
                            "is_sink": True,
                            "is_sanitizer": False,
                        }
                    ],
                    path_edges=[],
                    scan_engine="SCA",
                    language="Dependencies (SCA)",
                    best_fix_location=BestFixLocation(
                        node_id=node_id,
                        filepath=rel_fp,
                        line=start_line,
                        column=0,
                        code_snippet=code_snip,
                        explanation=f"Trivy SCA detected {vid} in {pkg} ({rel_fp}).",
                        recommended_fix=rem[:300],
                    ),
                    source_engine="TRIVY",
                    corroborated_by=[],
                )
            )

        # 2. Misconfigurations (IaC)
        for misc in res.get("Misconfigurations") or []:
            if not isinstance(misc, dict):
                continue
            idx_counter += 1
            mid = str(misc.get("ID") or misc.get("AVDID") or "TRIVY-MISCONFIG").strip()
            sev = _normalize_severity(misc.get("Severity") or "MEDIUM")
            cause = misc.get("CauseMetadata") if isinstance(misc.get("CauseMetadata"), dict) else {}
            start_line = max(1, int(cause.get("StartLine") or 1))
            end_line = max(start_line, int(cause.get("EndLine") or start_line))
            title = _scrub(misc.get("Title") or misc.get("Message") or mid, secret_list)[:220]
            desc = _scrub(misc.get("Description") or misc.get("Message") or title, secret_list)
            rem = _scrub(misc.get("Resolution") or "Harden IaC configuration.", secret_list)
            cwe_id = _extract_cwe(misc.get("CweIDs"), desc, title) or _infer_checkov_cwe(mid, title, rel_fp)
            code_snip = _scrub(misc.get("Message") or title, secret_list)[:300]
            rule_id = f"EXT-TRIVY-{mid}"
            fid = _make_finding_id("TRIVY", mid, rel_fp, start_line, idx_counter)
            node_id = f"trivy-iac-{idx_counter}"

            findings.append(
                Finding(
                    id=fid,
                    rule_id=rule_id,
                    severity=sev,  # type: ignore[arg-type]
                    title=title,
                    description=desc,
                    cwe_id=cwe_id,
                    remediation=rem,
                    source_site="Trivy",
                    reference_url=misc.get("PrimaryURL") if isinstance(misc.get("PrimaryURL"), str) else None,
                    path_nodes=[
                        {
                            "id": node_id,
                            "label": "Call",
                            "ast_type": "trivy_misconfig",
                            "name": mid,
                            "code": code_snip,
                            "filepath": rel_fp,
                            "start_line": start_line,
                            "end_line": end_line,
                            "start_col": 0,
                            "end_col": 0,
                            "scope_id": "trivy_iac",
                            "is_source": False,
                            "is_sink": True,
                            "is_sanitizer": False,
                        }
                    ],
                    path_edges=[],
                    scan_engine="IaC",
                    language=infer_language_from_filepath(rel_fp, rule_id),
                    best_fix_location=BestFixLocation(
                        node_id=node_id,
                        filepath=rel_fp,
                        line=start_line,
                        column=0,
                        code_snippet=code_snip,
                        explanation=f"Trivy IaC misconfiguration {mid} at {rel_fp}:L{start_line}.",
                        recommended_fix=rem[:300],
                    ),
                    source_engine="TRIVY",
                    corroborated_by=[],
                )
            )

        # 3. Secrets (strict scrubbing!)
        for sec in res.get("Secrets") or []:
            if not isinstance(sec, dict):
                continue
            idx_counter += 1
            s_rule = str(sec.get("RuleID") or "trivy-secret").strip()
            sev = _normalize_severity(sec.get("Severity") or "CRITICAL")
            start_line = max(1, int(sec.get("StartLine") or 1))
            end_line = max(start_line, int(sec.get("EndLine") or start_line))
            raw_title = sec.get("Title") or f"Hardcoded {sec.get('Category') or 'Secret'} ({s_rule})"
            safe_title = _scrub(raw_title, secret_list)[:220]

            code_lines_txt = ""
            code_obj = sec.get("Code") if isinstance(sec.get("Code"), dict) else {}
            if isinstance(code_obj.get("Lines"), list):
                code_lines_txt = "\n".join(
                    str(ln.get("Content") or "") for ln in code_obj["Lines"] if isinstance(ln, dict)
                )
            safe_snippet = _scrub(code_lines_txt or sec.get("Match") or _REDACTED_MARKER, secret_list)[:300]
            if not safe_snippet.strip():
                safe_snippet = _REDACTED_MARKER

            safe_desc = _scrub(
                f"Trivy detected hardcoded secret ({s_rule}) in `{rel_fp}` at Line {start_line}: {safe_snippet}",
                secret_list,
            )
            safe_rem = (
                f"Revoke and rotate the exposed `{s_rule}` credential immediately and inject secrets via "
                "environment variables or a secret manager."
            )
            rule_id = f"EXT-TRIVY-{s_rule}"
            fid = _make_finding_id("TRIVY", s_rule, rel_fp, start_line, idx_counter)
            node_id = f"trivy-sec-{idx_counter}"

            findings.append(
                Finding(
                    id=fid,
                    rule_id=rule_id,
                    severity=sev,  # type: ignore[arg-type]
                    title=safe_title,
                    description=safe_desc,
                    cwe_id="CWE-798",
                    remediation=safe_rem,
                    source_site="Trivy",
                    path_nodes=[
                        {
                            "id": node_id,
                            "label": "Assignment",
                            "ast_type": "trivy_secret",
                            "name": s_rule,
                            "code": safe_snippet,
                            "filepath": rel_fp,
                            "start_line": start_line,
                            "end_line": end_line,
                            "start_col": 0,
                            "end_col": 0,
                            "scope_id": "trivy_secret",
                            "is_source": False,
                            "is_sink": True,
                            "is_sanitizer": False,
                        }
                    ],
                    path_edges=[],
                    scan_engine="SAST",
                    language=infer_language_from_filepath(rel_fp, rule_id),
                    best_fix_location=BestFixLocation(
                        node_id=node_id,
                        filepath=rel_fp,
                        line=start_line,
                        column=0,
                        code_snippet=safe_snippet,
                        explanation=f"Remove hardcoded secret ({s_rule}) at {rel_fp}:L{start_line}.",
                        recommended_fix=safe_rem,
                    ),
                    is_secret_finding=True,
                    secret_detector_id=s_rule,
                    secret_type=str(sec.get("Category") or s_rule),
                    secret_value_raw=None,
                    secret_value_masked=_REDACTED_MARKER,
                    source_engine="TRIVY",
                    corroborated_by=[],
                )
            )
    return findings


def _parse_gitleaks_findings(
    payload: List[Dict[str, Any]],
    repo_root: Optional[str],
) -> List[Finding]:
    raw_secrets: Set[str] = set()
    for item in payload:
        _collect_secret_candidates_from_match(item.get("Secret"), raw_secrets)
        _collect_secret_candidates_from_match(item.get("Match"), raw_secrets)
    secret_list = list(raw_secrets)

    findings: List[Finding] = []
    for idx, item in enumerate(payload, start=1):
        g_rule = str(item.get("RuleID") or "gitleaks-secret").strip()
        rel_fp = _normalize_external_path(item.get("File") or "workspace", repo_root=repo_root)
        start_line = max(1, int(item.get("StartLine") or 1))
        end_line = max(start_line, int(item.get("EndLine") or start_line))
        start_col = max(0, int(item.get("StartColumn") or 0))
        end_col = max(0, int(item.get("EndColumn") or 0))
        sev = _normalize_severity(item.get("Severity") or "HIGH")

        raw_desc_lbl = str(item.get("Description") or g_rule)
        safe_title = _scrub(f"Hardcoded Secret ({g_rule}): {raw_desc_lbl}", secret_list)[:220]
        safe_snippet = _scrub(item.get("Match") or _REDACTED_MARKER, secret_list)[:300]
        if not safe_snippet.strip():
            safe_snippet = _REDACTED_MARKER
        commit_sha = str(item.get("Commit") or "").strip()[:40] or None
        author = _scrub(item.get("Author") or "", secret_list) or None
        safe_desc = _scrub(
            f"Gitleaks detected `{g_rule}` ({raw_desc_lbl}) in `{rel_fp}` at Line {start_line}. Match: {safe_snippet}",
            secret_list,
        )
        safe_rem = (
            f"Revoke and rotate the `{g_rule}` credential immediately, remove it from `{rel_fp}`, "
            "and load secrets via runtime environment variables or a secret vault."
        )
        entropy_val: Optional[float] = None
        if item.get("Entropy") is not None and not isinstance(item.get("Entropy"), bool):
            try:
                entropy_val = round(float(item["Entropy"]), 3)
            except (TypeError, ValueError):
                entropy_val = None

        rule_id = f"EXT-GITLEAKS-{g_rule}"
        fid = _make_finding_id("GITLEAKS", g_rule, rel_fp, start_line, idx)
        node_id = f"gitleaks-node-{idx}"

        findings.append(
            Finding(
                id=fid,
                rule_id=rule_id,
                severity=sev,  # type: ignore[arg-type]
                title=safe_title,
                description=safe_desc,
                cwe_id="CWE-798",
                remediation=safe_rem,
                source_site="Gitleaks",
                path_nodes=[
                    {
                        "id": node_id,
                        "label": "Assignment",
                        "ast_type": "gitleaks_secret",
                        "name": g_rule,
                        "code": safe_snippet,
                        "filepath": rel_fp,
                        "start_line": start_line,
                        "end_line": end_line,
                        "start_col": start_col,
                        "end_col": end_col,
                        "scope_id": "gitleaks",
                        "is_source": False,
                        "is_sink": True,
                        "is_sanitizer": False,
                    }
                ],
                path_edges=[],
                scan_engine="SAST",
                language=infer_language_from_filepath(rel_fp, rule_id),
                best_fix_location=BestFixLocation(
                    node_id=node_id,
                    filepath=rel_fp,
                    line=start_line,
                    column=start_col,
                    code_snippet=safe_snippet,
                    explanation=f"Remove hardcoded secret ({g_rule}) at {rel_fp}:L{start_line}.",
                    recommended_fix=safe_rem,
                ),
                is_secret_finding=True,
                secret_detector_id=g_rule,
                secret_type=_scrub(raw_desc_lbl, secret_list),
                secret_entropy=entropy_val,
                secret_value_raw=None,
                secret_value_masked=_REDACTED_MARKER,
                secret_source="GIT_HISTORY" if commit_sha else "WORKING_TREE",
                secret_commit_sha=commit_sha,
                secret_commit_author=author,
                source_engine="GITLEAKS",
                corroborated_by=[],
            )
        )
    return findings


def _parse_checkov_findings(
    payload: Any,
    repo_root: Optional[str],
) -> List[Finding]:
    blocks = payload if isinstance(payload, list) else [payload]
    findings: List[Finding] = []
    idx_counter = 0

    for block in blocks:
        if not isinstance(block, dict):
            continue
        check_type = str(block.get("check_type") or "iac").strip()
        res_obj = block.get("results") if isinstance(block.get("results"), dict) else {}
        failed_checks = res_obj.get("failed_checks") or []
        for chk in failed_checks:
            if not isinstance(chk, dict):
                continue
            idx_counter += 1
            chk_id = str(chk.get("check_id") or chk.get("bc_check_id") or "CHECKOV-RULE").strip()
            chk_name = str(chk.get("check_name") or chk_id).strip()
            resource = str(chk.get("resource") or "").strip()

            raw_fp = chk.get("file_path") or chk.get("file_abs_path") or "workspace"
            rel_fp = _normalize_external_path(raw_fp, repo_root=repo_root)

            line_range = chk.get("file_line_range") if isinstance(chk.get("file_line_range"), list) else []
            start_line = max(1, int(line_range[0])) if len(line_range) >= 1 and line_range[0] is not None else 1
            end_line = max(start_line, int(line_range[1])) if len(line_range) >= 2 and line_range[1] is not None else start_line

            code_block = chk.get("code_block")
            snippet_parts: List[str] = []
            if isinstance(code_block, list):
                for entry in code_block[:8]:
                    if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                        snippet_parts.append(str(entry[1]).rstrip())
                    elif isinstance(entry, str):
                        snippet_parts.append(entry.rstrip())
            raw_snippet = "\n".join(snippet_parts).strip() or resource or chk_name

            cwe_id = _infer_checkov_cwe(chk_id, chk_name, resource)
            default_sev = "HIGH" if cwe_id in ("CWE-732", "CWE-798", "CWE-250", "CWE-311") else "MEDIUM"
            sev = _normalize_severity(chk.get("severity") or default_sev)
            guideline = chk.get("guideline") if isinstance(chk.get("guideline"), str) else None

            safe_title = _scrub(f"{chk_id}: {chk_name}")[:220]
            safe_snippet = _scrub(raw_snippet)[:300]
            safe_desc = _scrub(
                f"Checkov ({check_type}) failed check `{chk_id}` on resource `{resource or rel_fp}`: {chk_name}"
            )
            safe_rem = (
                f"Remediate IaC policy `{chk_id}` in `{rel_fp}` (Lines {start_line}-{end_line})"
                + (f" per {guideline}" if guideline else ".")
            )
            rule_id = f"EXT-CHECKOV-{chk_id}"
            fid = _make_finding_id("CHECKOV", chk_id, rel_fp, start_line, idx_counter)
            node_id = f"checkov-node-{idx_counter}"

            findings.append(
                Finding(
                    id=fid,
                    rule_id=rule_id,
                    severity=sev,  # type: ignore[arg-type]
                    title=safe_title,
                    description=safe_desc,
                    cwe_id=cwe_id,
                    remediation=_scrub(safe_rem),
                    source_site="Checkov",
                    reference_url=guideline,
                    path_nodes=[
                        {
                            "id": node_id,
                            "label": "Call",
                            "ast_type": "checkov_iac_resource",
                            "name": resource or chk_id,
                            "code": safe_snippet,
                            "filepath": rel_fp,
                            "start_line": start_line,
                            "end_line": end_line,
                            "start_col": 0,
                            "end_col": 0,
                            "scope_id": f"checkov_{check_type}",
                            "is_source": False,
                            "is_sink": True,
                            "is_sanitizer": False,
                        }
                    ],
                    path_edges=[],
                    scan_engine="IaC",
                    language=infer_language_from_filepath(rel_fp, rule_id),
                    best_fix_location=BestFixLocation(
                        node_id=node_id,
                        filepath=rel_fp,
                        line=start_line,
                        column=0,
                        code_snippet=safe_snippet,
                        explanation=f"Checkov IaC policy {chk_id} failed at {rel_fp}:L{start_line}.",
                        recommended_fix=_scrub(safe_rem)[:300],
                    ),
                    source_engine="CHECKOV",
                    corroborated_by=[],
                )
            )
    return findings


def parse_external_scanner_report(
    report_json: str,
    source_format: Optional[ScannerFormatType] = None,
    repo_root: Optional[str] = None,
) -> Tuple[ScannerFormatType, List[Finding]]:
    """
    Parses, validates, scrubs raw secrets from, and normalizes an external scanner report
    into ALASTOR `Finding` objects.
    """
    if not isinstance(report_json, str) or not report_json.strip():
        raise ValueError("Scanner report JSON must be a non-empty string")
    if len(report_json.encode("utf-8", errors="replace")) > _MAX_REPORT_BYTES:
        raise ValueError("Scanner report exceeds maximum 50MB size limit")

    try:
        payload = json.loads(report_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed scanner JSON report: {exc}") from exc

    if source_format is not None:
        _validate_explicit_format(payload, source_format)
        detected: ScannerFormatType = source_format
    else:
        detected = detect_scanner_format(payload)

    if detected in ("SARIF_2_1", "CODEQL_SARIF"):
        return detected, _parse_sarif_findings(payload, detected, repo_root=repo_root)
    if detected == "SEMGREP_JSON":
        return detected, _parse_semgrep_findings(payload, repo_root=repo_root)
    if detected == "TRIVY_JSON":
        return detected, _parse_trivy_findings(payload, repo_root=repo_root)
    if detected == "GITLEAKS_JSON":
        return detected, _parse_gitleaks_findings(payload, repo_root=repo_root)
    if detected == "CHECKOV_JSON":
        return detected, _parse_checkov_findings(payload, repo_root=repo_root)

    raise ValueError(f"Unsupported scanner format: {detected}")


def _extract_finding_fp_line(finding: Finding) -> Tuple[str, int]:
    if finding.path_nodes:
        sink = next(
            (n for n in reversed(finding.path_nodes) if isinstance(n, dict) and n.get("is_sink")),
            finding.path_nodes[-1],
        )
        if isinstance(sink, dict) and sink.get("filepath"):
            return (
                _normalize_external_path(sink["filepath"]),
                max(1, int(sink.get("start_line") or 1)),
            )
    if finding.best_fix_location and finding.best_fix_location.filepath:
        return (
            _normalize_external_path(finding.best_fix_location.filepath),
            max(1, int(finding.best_fix_location.line or 1)),
        )
    return "workspace", 1


def _canonical_category(finding: Finding) -> str:
    cwe = (finding.cwe_id or "").strip().upper()
    if cwe:
        m = _CWE_RX.search(cwe)
        if m:
            norm = f"CWE-{int(m.group(1))}"
            return _CANONICAL_CWE_GROUPS.get(norm, norm)
    inferred = _infer_cwe_from_keywords(finding.rule_id, finding.title, finding.description)
    if inferred:
        return _CANONICAL_CWE_GROUPS.get(inferred, inferred)
    return (finding.rule_id or finding.title or "UNKNOWN").strip().upper()


def _paths_match(fp_a: str, fp_b: str) -> bool:
    if not fp_a or not fp_b:
        return False
    a = fp_a.replace("\\", "/").lstrip("./")
    b = fp_b.replace("\\", "/").lstrip("./")
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _find_matching_existing(
    imp: Finding,
    existing_list: Sequence[Finding],
) -> Optional[Finding]:
    imp_fp, imp_ln = _extract_finding_fp_line(imp)
    imp_cat = _canonical_category(imp)
    for cand in existing_list:
        cand_fp, cand_ln = _extract_finding_fp_line(cand)
        if not _paths_match(imp_fp, cand_fp):
            continue
        if abs(imp_ln - cand_ln) > 3:
            continue
        if _canonical_category(cand) == imp_cat:
            return cand
    return None


def _safe_read_confined_source_file(project_path: str, rel_fp: str) -> Optional[Tuple[str, bytes]]:
    if not project_path or not os.path.isdir(project_path):
        return None
    clean_rel = rel_fp.replace("\\", "/").lstrip("/")
    if not clean_rel or ".." in clean_rel.split("/"):
        return None
    real_root = os.path.realpath(project_path)
    joined = os.path.join(real_root, clean_rel)
    if _is_link_or_junction(joined) and not _is_confined(real_root, joined):
        return None
    real_target = os.path.realpath(joined)
    try:
        if os.path.commonpath([real_root, real_target]) != real_root:
            return None
    except ValueError:
        return None
    if real_target == real_root or not os.path.isfile(real_target):
        return None
    if os.path.basename(real_target).lower().startswith(".env"):
        return None
    try:
        if os.path.getsize(real_target) > 2_000_000:
            return None
        with open(real_target, "rb") as fh:
            return clean_rel, fh.read()
    except OSError:
        return None


def _query_graph_store_nodes_for_file(
    graph_store: Any,
    rel_fp: str,
    warnings: List[str],
) -> Tuple[List[CPGNode], Optional[str]]:
    if graph_store is None:
        return [], None

    matched_nodes: List[CPGNode] = []
    community_label: Optional[str] = None

    target_store = graph_store
    if hasattr(graph_store, "_embedded_store") and getattr(graph_store, "mode", None) == "EMBEDDED_SQLITE":
        target_store = graph_store._embedded_store

    # 1. EmbeddedGraphStore path
    if hasattr(target_store, "_nodes_by_file") and hasattr(target_store, "_ensure_loaded"):
        try:
            lock = getattr(target_store, "_lock", None)
            if lock is not None:
                with lock:
                    target_store._ensure_loaded()
                    for n_fp, n_list in target_store._nodes_by_file.items():
                        if _paths_match(n_fp, rel_fp):
                            matched_nodes.extend(n_list)
            else:
                target_store._ensure_loaded()
                for n_fp, n_list in target_store._nodes_by_file.items():
                    if _paths_match(n_fp, rel_fp):
                        matched_nodes.extend(n_list)
        except Exception as exc:
            warnings.append(f"Embedded CPG lookup fallback triggered: {exc}")

    # 2. Neo4j / Neo4jGraphStore path (only if embedded cache yielded nothing)
    if not matched_nodes and hasattr(graph_store, "neo4j_client"):
        try:
            client = graph_store.neo4j_client
            driver = getattr(client, "driver", None)
            if driver is not None:
                with driver.session() as session:
                    recs = session.run(
                        "MATCH (n:CPGNode) WHERE n.filepath ENDS WITH $fp RETURN properties(n) AS p LIMIT 80",
                        fp=rel_fp,
                    )
                    for rec in recs:
                        props = rec.get("p")
                        if isinstance(props, dict) and props.get("id"):
                            matched_nodes.append(
                                CPGNode(
                                    id=str(props["id"]),
                                    label=str(props.get("label") or "Call"),  # type: ignore[arg-type]
                                    ast_type=str(props.get("ast_type") or "statement"),
                                    name=str(props.get("name") or "node"),
                                    code=str(props.get("code") or ""),
                                    filepath=str(props.get("filepath") or rel_fp),
                                    start_line=max(1, int(props.get("start_line") or 1)),
                                    end_line=max(1, int(props.get("end_line") or 1)),
                                    start_col=int(props.get("start_col") or 0),
                                    end_col=int(props.get("end_col") or 0),
                                    scope_id=str(props.get("scope_id") or "global"),
                                    language=str(props.get("language") or "python"),
                                )
                            )
        except Exception as exc:
            warnings.append(f"Neo4j CPG lookup unavailable ({exc}); falling back to local AST/file context.")

    # 3. Community lookup
    if hasattr(graph_store, "get_communities"):
        try:
            cm: CommunityMapResponse = graph_store.get_communities()
            for comm in getattr(cm, "communities", []) or []:
                if any(_paths_match(cf, rel_fp) for cf in (comm.files or [])):
                    community_label = comm.label
                    break
        except Exception:
            pass

    return matched_nodes, community_label


def _enrich_finding_with_cpg(
    finding: Finding,
    graph_store: Any,
    project_path: Optional[str],
    warnings: List[str],
) -> bool:
    rel_fp, line = _extract_finding_fp_line(finding)
    cpg_nodes, comm_label = _query_graph_store_nodes_for_file(graph_store, rel_fp, warnings)

    # Fallback: parse single confined source file with ALASTOR ASTNormalizer when graph_store lacks nodes
    file_grounded = False
    if not cpg_nodes and project_path:
        loaded = _safe_read_confined_source_file(project_path, rel_fp)
        if loaded is not None:
            clean_rel, raw_bytes = loaded
            file_grounded = True
            lang = resolve_language_for_filename(os.path.basename(clean_rel))
            if lang:
                try:
                    sf = ScannedFile(
                        filepath=clean_rel,
                        full_path=os.path.realpath(os.path.join(project_path, clean_rel)),
                        sha256=hashlib.sha256(raw_bytes).hexdigest(),
                        language=lang,
                        content_bytes=raw_bytes,
                    )
                    cpg_nodes, _ = ASTNormalizer(sf).normalize()
                except Exception:
                    cpg_nodes = []

    if not cpg_nodes and not file_grounded:
        return False

    enclosing_fn: Optional[CPGNode] = None
    fn_candidates = [
        n
        for n in cpg_nodes
        if n.label in ("Function", "Class") and n.start_line <= line <= max(n.end_line, n.start_line)
    ]
    if fn_candidates:
        enclosing_fn = min(fn_candidates, key=lambda n: (max(0, n.end_line - n.start_line), n.start_line))

    nearest_node: Optional[CPGNode] = None
    near_candidates = [n for n in cpg_nodes if abs(n.start_line - line) <= 3]
    if near_candidates:
        nearest_node = min(near_candidates, key=lambda n: (abs(n.start_line - line), 0 if n.label == "Call" else 1))

    ctx_parts: List[str] = []
    if enclosing_fn is not None:
        ctx_parts.append(f"function `{enclosing_fn.name}` (L{enclosing_fn.start_line}-L{enclosing_fn.end_line})")
        fn_dict = enclosing_fn.model_dump()
        if not any(isinstance(pn, dict) and pn.get("id") == enclosing_fn.id for pn in finding.path_nodes):
            finding.path_nodes.insert(0, fn_dict)
    if nearest_node is not None:
        ctx_parts.append(f"CPG {nearest_node.label} `{nearest_node.name}`@L{nearest_node.start_line}")
        if finding.path_nodes and isinstance(finding.path_nodes[-1], dict):
            finding.path_nodes[-1].setdefault("cpg_node_id", nearest_node.id)
            finding.path_nodes[-1]["scope_id"] = nearest_node.scope_id
            if enclosing_fn is not None:
                finding.path_nodes[-1]["enclosing_function"] = enclosing_fn.name
    if comm_label:
        ctx_parts.append(f"community `{comm_label}`")
    if not ctx_parts and file_grounded:
        ctx_parts.append(f"workspace file `{rel_fp}`:L{line}")

    ctx_summary = _scrub(f"CPG Context: {', '.join(ctx_parts)}.")
    if ctx_summary not in (finding.reachability_reason or ""):
        finding.reachability_reason = (
            f"{finding.reachability_reason} {ctx_summary}".strip()
            if finding.reachability_reason
            else ctx_summary
        )

    if cpg_nodes and cpg_nodes[0].language and finding.language == "Python":
        finding.language = infer_language_from_filepath(rel_fp, finding.rule_id)

    if finding.best_fix_location is None:
        finding.best_fix_location = compute_best_fix_location(finding)

    return True


def fuse_findings_with_cpg(
    imported: List[Finding],
    native_findings: List[Finding],
    graph_store: Optional[Any] = None,
    project_path: Optional[str] = None,
    run_s6_verify: bool = False,
    detected_format: Optional[ScannerFormatType] = None,
    correlate_cpg: bool = True,
    imported_raw_count: Optional[int] = None,
) -> ScannerFusionResponse:
    """
    Fuses normalized external scanner findings into ALASTOR's native findings with:
    - Proximity + CWE/category deduplication & `corroborated_by` enrichment
    - CPG node/function/community grounding
    - Optional deterministic ($0) S6 Adversarial Verification
    """
    merged: List[Finding] = [f.model_copy(deep=True) for f in (native_findings or [])]
    warnings: List[str] = []

    eff_format: ScannerFormatType = detected_format or "SARIF_2_1"
    if detected_format is None and imported:
        first_src = (imported[0].source_engine or "").upper()
        if first_src in _FORMAT_BY_SOURCE_ENGINE:
            eff_format = _FORMAT_BY_SOURCE_ENGINE[first_src]

    corroborated_count = 0
    new_unique_count = 0
    cpg_enriched_count = 0

    for raw_imp in imported or []:
        imp = scrub_finding_secrets(raw_imp, clear_raw_secret=True)

        imp_engine = (imp.source_engine or _SOURCE_ENGINE_BY_FORMAT[eff_format]).strip().upper()
        if not imp.source_engine:
            imp.source_engine = imp_engine

        match = _find_matching_existing(imp, merged)
        if match is not None:
            existing_eng = (match.source_engine or "").strip().upper()
            if imp_engine and imp_engine != existing_eng and imp_engine not in match.corroborated_by:
                match.corroborated_by.append(imp_engine)
            corroborated_count += 1
            note = _scrub(f"[Corroborated by {imp_engine}: {imp.rule_id}]")
            if note not in (match.description or ""):
                match.description = f"{match.description} {note}".strip()
            continue

        if correlate_cpg:
            if _enrich_finding_with_cpg(imp, graph_store=graph_store, project_path=project_path, warnings=warnings):
                cpg_enriched_count += 1

        new_unique_count += 1
        merged.append(imp)

    s6_verified_count = 0
    if run_s6_verify and merged:
        target_dir_eff = project_path or "."
        s6_ids = [f.id for f in merged] if len(merged) > 50 else None
        s6_resp = verify_findings_adversarially(
            target_dir=target_dir_eff,
            findings=merged,
            ai_engine=None,
            finding_ids=s6_ids,
            use_ai=False,
            max_batch=max(1, min(50, len(merged))),
        )
        s6_verified_count = s6_resp.total_verified
        verdict_by_id = {v.finding_id: v for v in s6_resp.verdicts}
        for f in merged:
            v = verdict_by_id.get(f.id)
            if v is None:
                continue
            if f.cvss_score is None:
                f.cvss_score = v.cvss_score
            s6_tag = _scrub(f"[S6 {v.verdict}: conf={v.confidence}%, CVSS={v.cvss_score:.1f}]")
            if s6_tag not in (f.reachability_reason or ""):
                f.reachability_reason = f"{f.reachability_reason} {s6_tag}".strip()

    raw_cnt = len(imported or []) if imported_raw_count is None else int(imported_raw_count)
    dedup_warnings = list(dict.fromkeys(_scrub(w) for w in warnings if w))

    return ScannerFusionResponse(
        project_path=_scrub(project_path or ""),
        detected_format=eff_format,
        imported_raw_count=raw_cnt,
        normalized_count=len(imported or []),
        corroborated_count=corroborated_count,
        new_unique_count=new_unique_count,
        cpg_enriched_count=cpg_enriched_count,
        s6_verified_count=s6_verified_count,
        findings=merged,
        warnings=dedup_warnings,
    )


__all__ = [
    "detect_scanner_format",
    "parse_external_scanner_report",
    "fuse_findings_with_cpg",
    "scrub_finding_secrets",
]
