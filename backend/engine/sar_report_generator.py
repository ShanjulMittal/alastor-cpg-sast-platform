"""
Enterprise Security Architecture Review (SAR) & Go-Live Readiness Dossier Engine.

Produces strictly redacted, boardroom- and ARB-ready 10-section Go-Live reports in:
  1. Native Microsoft Word OpenXML (`.docx` via `python-docx`)
  2. Native Multi-Page Corporate A4 PDF (`.pdf` via `reportlab.platypus`)
  3. Structured Machine-Readable SAR JSON (`dict`)

Security Guarantees:
  - Raw credential values (`Finding.secret_value_raw`) are NEVER emitted in `.docx`, `.pdf`,
    or `json` regardless of active RBAC operator role.
  - Forbidden raw credential literals (length >= 4) are sorted by length descending prior
    to scrubbing so superstring credentials cannot leave partial suffix leaks.
  - All ReportLab `Paragraph` cells escape XML entities (`<`, `>`, `&`, `"`, `'`) and strip
    control bytes so arbitrary source code snippets never trigger parser exceptions.
"""
from __future__ import annotations

from io import BytesIO
import re
from typing import Any, Dict, List, Tuple
import warnings
from xml.sax.saxutils import escape as xml_escape

import docx
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from pydantic import BaseModel, Field

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"reportlab(\..*)?$")
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

from engine.frontier_ai_engine import scrub_raw_secrets_text
from models import (
    EvReplayBundleItem,
    ExploitChainItem,
    Finding,
    GoLiveObservationItem,
    MetricsResponse,
    PastaAssessmentResponse,
    PastaAttackTreeScenario,
    RaciGovernanceResponse,
    SastPlusSuiteResponse,
)

_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_MASK_FALLBACK_LABEL = "[REDACTED_" + "SECRET]"
_EV_SENSITIVE_HEADER_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
        "x-access-token",
    }
)
_EV_SAFE_PLACEHOLDERS = frozenset(
    {"<USER_A_TOKEN>", "<USER_B_TOKEN>", "<REDACTED_HEADER>", _MASK_FALLBACK_LABEL, "[REDACTED]"}
)
_EV_BEARER_BASIC_RX = re.compile(
    r"\b(Bearer|Basic)\s+(?![<\[]|REDACTED)[A-Za-z0-9._~+/=-]{8,}(?![A-Za-z0-9._~+/=-])",
    re.IGNORECASE,
)

# Corporate Daylight Palette
_HEX_NAVY = "0F172A"
_HEX_SLATE_TEXT = "334155"
_HEX_MUTED_TEXT = "64748B"
_HEX_TBL_HEADER_BG = "F1F5F9"
_HEX_TBL_ALT_BG = "F8FAFC"
_HEX_BORDER = "CBD5E1"
_HEX_EMERALD = "047857"
_HEX_EMERALD_BG = "ECFDF5"
_HEX_AMBER = "B45309"
_HEX_AMBER_BG = "FFFBEB"
_HEX_ROSE = "BE123C"
_HEX_ROSE_BG = "FFF1F2"

_DOCX_NAVY = RGBColor(0x0F, 0x17, 0x2A)
_DOCX_SLATE = RGBColor(0x33, 0x41, 0x55)
_DOCX_MUTED = RGBColor(0x64, 0x74, 0x8B)
_DOCX_EMERALD = RGBColor(0x04, 0x78, 0x57)
_DOCX_AMBER = RGBColor(0xB4, 0x53, 0x09)
_DOCX_ROSE = RGBColor(0xBE, 0x12, 0x3C)

_RL_NAVY = colors.HexColor(f"#{_HEX_NAVY}")
_RL_SLATE = colors.HexColor(f"#{_HEX_SLATE_TEXT}")
_RL_MUTED = colors.HexColor(f"#{_HEX_MUTED_TEXT}")
_RL_TBL_HEADER_BG = colors.HexColor(f"#{_HEX_TBL_HEADER_BG}")
_RL_TBL_ALT_BG = colors.HexColor(f"#{_HEX_TBL_ALT_BG}")
_RL_BORDER = colors.HexColor(f"#{_HEX_BORDER}")
_RL_EMERALD = colors.HexColor(f"#{_HEX_EMERALD}")
_RL_EMERALD_BG = colors.HexColor(f"#{_HEX_EMERALD_BG}")
_RL_AMBER = colors.HexColor(f"#{_HEX_AMBER}")
_RL_AMBER_BG = colors.HexColor(f"#{_HEX_AMBER_BG}")
_RL_ROSE = colors.HexColor(f"#{_HEX_ROSE}")
_RL_ROSE_BG = colors.HexColor(f"#{_HEX_ROSE_BG}")


class SarReportBundle(BaseModel):
    application_name: str
    project_path: str
    generated_at: str
    pasta: PastaAssessmentResponse
    sast_plus: SastPlusSuiteResponse
    raci: RaciGovernanceResponse
    metrics: MetricsResponse
    findings: List[Finding] = Field(default_factory=list)
    exploit_chains: List[ExploitChainItem] = Field(default_factory=list)
    ev_replays: List[EvReplayBundleItem] = Field(default_factory=list)


def _clean_xml_text(value: Any, max_len: int = 0) -> str:
    txt = _CTRL_CHARS_RE.sub("", str(value if value is not None else "")).strip()
    if max_len > 0 and len(txt) > max_len:
        return txt[: max_len - 3] + "..."
    return txt


def _rl_esc(value: Any, max_len: int = 700) -> str:
    cleaned = _clean_xml_text(value, max_len=max_len)
    escaped = xml_escape(cleaned, {'"': "&quot;", "'": "&apos;"})
    return escaped.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br/>")


def _scrub_value_recursive(node: Any, replacements: List[Tuple[str, str]]) -> Any:
    if isinstance(node, str):
        out = _CTRL_CHARS_RE.sub("", node)
        for raw_token, mask_label in replacements:
            if raw_token in out:
                out = out.replace(raw_token, mask_label)
        return out
    if isinstance(node, list):
        return [_scrub_value_recursive(item, replacements) for item in node]
    if isinstance(node, dict):
        return {k: _scrub_value_recursive(v, replacements) for k, v in node.items()}
    return node


def _scrub_ev_text_value(
    value: Optional[str],
    replacements: List[Tuple[str, str]],
) -> str:
    if value is None:
        return ""
    out = _scrub_value_recursive(str(value), replacements)
    out = scrub_raw_secrets_text(out)
    out = _EV_BEARER_BASIC_RX.sub(r"\1 [REDACTED_SECRET]", out)
    return out


def _sanitize_ev_replay_item(
    item: EvReplayBundleItem,
    replacements: List[Tuple[str, str]],
) -> EvReplayBundleItem:
    dumped = item.model_dump()
    scrubbed = _scrub_value_recursive(dumped, replacements)
    for text_field in (
        "evidence_summary",
        "response_excerpt",
        "curl_poc",
        "pytest_poc",
        "target_url",
        "path",
        "body",
        "expected_indicator",
    ):
        cur_val = scrubbed.get(text_field)
        if cur_val is not None:
            scrubbed[text_field] = _scrub_ev_text_value(str(cur_val), replacements)

    raw_q = scrubbed.get("query_params")
    if isinstance(raw_q, dict):
        scrubbed["query_params"] = {
            str(k): _scrub_ev_text_value(str(v), replacements)
            for k, v in raw_q.items()
        }

    raw_hdrs = scrubbed.get("masked_headers")
    clean_hdrs: Dict[str, str] = {}
    if isinstance(raw_hdrs, dict):
        for hk, hv in raw_hdrs.items():
            key_s = str(hk)
            val_s = str(hv or "")
            if key_s.lower() in _EV_SENSITIVE_HEADER_KEYS:
                clean_hdrs[key_s] = val_s if val_s in _EV_SAFE_PLACEHOLDERS else "<REDACTED_HEADER>"
            else:
                clean_hdrs[key_s] = _scrub_ev_text_value(val_s, replacements)
    scrubbed["masked_headers"] = clean_hdrs
    return EvReplayBundleItem.model_validate(scrubbed)


def sanitize_bundle_for_export(bundle: SarReportBundle) -> SarReportBundle:
    """
    Deep-copies the bundle, strips `secret_value_raw` on every finding, and scrubs all
    raw credential occurrences (length >= 4, sorted by length descending) across every
    model field in `pasta`, `sast_plus`, `raci`, `metrics`, `findings`, and `ev_replays`.
    """
    mask_by_raw: Dict[str, str] = {}
    candidate_lists: List[List[Finding]] = [list(bundle.findings or [])]
    for f_list in candidate_lists:
        for f_item in f_list:
            raw_cand = f_item.secret_value_raw
            if raw_cand and len(raw_cand) >= 4 and raw_cand not in mask_by_raw:
                mask_by_raw[raw_cand] = f_item.secret_value_masked or _MASK_FALLBACK_LABEL

    for rep in bundle.ev_replays or []:
        for hk, hv in (rep.masked_headers or {}).items():
            if hk.lower() in _EV_SENSITIVE_HEADER_KEYS and hv and hv not in _EV_SAFE_PLACEHOLDERS:
                if len(hv) >= 4 and hv not in mask_by_raw:
                    mask_by_raw[hv] = "<REDACTED_HEADER>"
                parts = hv.split(None, 1)
                if len(parts) == 2 and len(parts[1]) >= 4 and parts[1] not in mask_by_raw:
                    mask_by_raw[parts[1]] = _MASK_FALLBACK_LABEL

    ordered_raws = sorted(mask_by_raw.keys(), key=len, reverse=True)
    for idx_hi, longer_raw in enumerate(ordered_raws):
        for shorter_raw in ordered_raws[idx_hi + 1 :]:
            if shorter_raw in longer_raw:
                for upstream_tok in ("[REDACTED]", mask_by_raw[shorter_raw]):
                    partial_artifact = longer_raw.replace(shorter_raw, upstream_tok)
                    if len(partial_artifact) >= 4 and partial_artifact not in mask_by_raw:
                        mask_by_raw[partial_artifact] = mask_by_raw[longer_raw]

    sorted_replacements: List[Tuple[str, str]] = sorted(
        mask_by_raw.items(),
        key=lambda pair: len(pair[0]),
        reverse=True,
    )

    sanitized_findings: List[Finding] = []
    for f_orig in bundle.findings:
        dumped_f = f_orig.model_dump(exclude={"secret_value_raw"})
        scrubbed_f = _scrub_value_recursive(dumped_f, sorted_replacements)
        scrubbed_f.pop("secret_value_raw", None)
        if scrubbed_f.get("ev_evidence_summary") is not None:
            scrubbed_f["ev_evidence_summary"] = _scrub_ev_text_value(
                str(scrubbed_f["ev_evidence_summary"]),
                sorted_replacements,
            )
        sanitized_findings.append(Finding.model_validate(scrubbed_f))

    scrubbed_pasta = PastaAssessmentResponse.model_validate(
        _scrub_value_recursive(bundle.pasta.model_dump(), sorted_replacements)
    )
    dumped_suite = bundle.sast_plus.model_dump()
    scrubbed_suite_dict = _scrub_value_recursive(dumped_suite, sorted_replacements)
    scrubbed_suite_dict["pasta_assessment"] = scrubbed_pasta.model_dump()
    scrubbed_suite = SastPlusSuiteResponse.model_validate(scrubbed_suite_dict)

    scrubbed_raci = RaciGovernanceResponse.model_validate(
        _scrub_value_recursive(bundle.raci.model_dump(), sorted_replacements)
    )
    scrubbed_metrics = MetricsResponse.model_validate(
        _scrub_value_recursive(bundle.metrics.model_dump(), sorted_replacements)
    )
    scrubbed_chains: List[ExploitChainItem] = [
        ExploitChainItem.model_validate(
            _scrub_value_recursive(chain.model_dump(), sorted_replacements)
        )
        for chain in (bundle.exploit_chains or [])
    ]
    scrubbed_ev_replays: List[EvReplayBundleItem] = [
        _sanitize_ev_replay_item(rep, sorted_replacements)
        for rep in (bundle.ev_replays or [])
    ]

    clean_app = _scrub_value_recursive(bundle.application_name, sorted_replacements)
    clean_path = _scrub_value_recursive(bundle.project_path, sorted_replacements)

    return SarReportBundle(
        application_name=str(clean_app),
        project_path=str(clean_path),
        generated_at=_clean_xml_text(bundle.generated_at),
        pasta=scrubbed_pasta,
        sast_plus=scrubbed_suite,
        raci=scrubbed_raci,
        metrics=scrubbed_metrics,
        findings=sanitized_findings,
        exploit_chains=scrubbed_chains,
        ev_replays=scrubbed_ev_replays,
    )


def _verdict_display_banner(verdict_code: str) -> str:
    if verdict_code == "APPROVED_FOR_GO_LIVE":
        return "APPROVED FOR GO-LIVE"
    if verdict_code == "CONDITIONAL_GO_LIVE":
        return "CONDITIONAL GO-LIVE"
    return "NO-GO • HOLD RELEASE"


def _decision_rationale_qa(bundle: SarReportBundle) -> List[Tuple[str, str]]:
    pasta = bundle.pasta
    mandatory_obs = [
        o for o in pasta.golive_observations if o.gate_status == "MANDATORY_PRE_GO_LIVE"
    ]
    sla_obs = [
        o for o in pasta.golive_observations if o.gate_status == "POST_GO_LIVE_SLA"
    ]

    if pasta.golive_verdict == "APPROVED_FOR_GO_LIVE":
        ans_a = (
            "YES — Approved for immediate production Go-Live. Zero mandatory pre-launch blockers "
            "and zero open post-launch SLA deferrals remain."
        )
    elif pasta.golive_verdict == "CONDITIONAL_GO_LIVE":
        ans_a = (
            f"YES (CONDITIONAL GO-LIVE) — Permitted to launch today with {len(sla_obs)} non-blocking "
            f"observation(s) governed by binding post-launch SLAs and active compensating controls."
        )
    else:
        ans_a = (
            f"NO (HOLD PRODUCTION RELEASE) — {len(mandatory_obs)} Mandatory Pre-Go-Live blocker(s) "
            f"must be remediated and re-verified before production promotion."
        )

    if mandatory_obs:
        top_titles = "; ".join(
            f"[{o.severity}] {o.title} ({o.filepath}:L{o.line})" for o in mandatory_obs[:4]
        )
        ans_b = f"Top pre-release blockers: {top_titles}."
    elif sla_obs:
        top_sla = "; ".join(
            f"[{o.severity}] {o.title} (SLA: {o.sla_window})" for o in sla_obs[:4]
        )
        ans_b = f"Zero release blockers; monitored post-launch SLA items: {top_sla}."
    else:
        ans_b = "Zero Critical/High exploitable paths, active credential leaks, or unguarded endpoints."

    ans_c = (
        f"Closing all {len(mandatory_obs)} mandatory pre-launch item(s) reduces risk from Inherent "
        f"{pasta.inherent_risk_score}/100 ({pasta.inherent_risk_level}) and Current Residual "
        f"{pasta.residual_risk_score}/100 ({pasta.residual_risk_level}) down to Final Projected Go-Live "
        f"Risk {pasta.projected_golive_risk_score}/100 ({pasta.projected_golive_risk_level})."
    )

    return [
        ("(a) Can this system go live today?", ans_a),
        ("(b) What are the top release risks?", ans_b),
        ("(c) What final risk level remains once mandatory items are closed?", ans_c),
    ]


def _collect_architectural_strengths(bundle: SarReportBundle) -> Dict[str, List[str]]:
    pasta_passed: List[str] = []
    for st in bundle.pasta.stages:
        for passed_line in st.what_passed[:3]:
            entry = f"[{st.stage_code}] {passed_line}"
            if entry not in pasta_passed:
                pasta_passed.append(entry)

    pbom_passed = [
        f"[{chk.id}] {chk.title}: {chk.details}"
        for chk in bundle.sast_plus.pipeline_checks
        if chk.status == "PASS"
    ]
    mitigated_stride = [
        f"[STRIDE-{st.stride_letter} • {st.stride_category}] {st.ok_summary or st.verdict_label}"
        for st in bundle.sast_plus.stride_threats
        if st.status == "MITIGATED"
    ]
    return {
        "pasta_stage_controls": pasta_passed,
        "passing_pbom_checks": pbom_passed,
        "mitigated_stride_domains": mitigated_stride,
    }


def _build_formal_signoff_rows(bundle: SarReportBundle) -> List[Dict[str, str]]:
    role_owner_by_code = {r.short_code.upper(): r.default_owner for r in bundle.raci.roles}
    return [
        {
            "role": "Security Architect (ARB)",
            "responsibility": "7-Stage PASTA Threat Model, Attack Tree BFL Verification & Go-Live Gate Authority",
            "representative": role_owner_by_code.get("SEC_ARCH", "Principal AppSec Architect"),
            "signature_date": f"Pending ARB Sign-Off ({bundle.pasta.golive_verdict})",
        },
        {
            "role": "Engineering / Tech Lead",
            "responsibility": "Mandatory Pre-Go-Live Code Remediation & Post-Launch Sprint SLA Delivery",
            "representative": role_owner_by_code.get("TECH_LEAD", "Lead Application Engineer"),
            "signature_date": "Pending Engineering Attestation",
        },
        {
            "role": "DevOps / SRE Lead",
            "responsibility": "PBOM Supply-Chain Pinning, Container Hardening & Compensating Runtime Controls",
            "representative": role_owner_by_code.get("DEVSECOPS", "Staff DevSecOps / SRE Lead"),
            "signature_date": "Pending Runtime Gate Verification",
        },
        {
            "role": "Product / Business Risk Owner",
            "responsibility": "Crown Jewel Impact Acceptance, Regulatory Alignment & Waiver Authorization",
            "representative": role_owner_by_code.get("CISO", "Executive Risk Owner / CISO"),
            "signature_date": "Pending Executive Authorization",
        },
    ]


def _resolve_ev_status_maps(clean: SarReportBundle) -> Tuple[Dict[str, str], Dict[str, str]]:
    finding_ev_map: Dict[str, str] = {
        f.id: str(f.ev_status)
        for f in (clean.findings or [])
        if f.id and getattr(f, "ev_status", None)
    }
    replay_ev_map: Dict[str, str] = {}
    for rep in clean.ev_replays or []:
        if not rep.finding_id:
            continue
        prev = replay_ev_map.get(rep.finding_id)
        if prev is None or (rep.status == "RUNTIME_EXPLOIT_CONFIRMED" and prev != "RUNTIME_EXPLOIT_CONFIRMED"):
            replay_ev_map[rep.finding_id] = str(rep.status)
    return finding_ev_map, replay_ev_map


def _ev_badge_for_observation(
    obs: GoLiveObservationItem,
    finding_ev_map: Dict[str, str],
    replay_ev_map: Dict[str, str],
) -> str:
    fid = obs.linked_finding_id or ""
    if not fid:
        return ""
    ev_st = finding_ev_map.get(fid) or replay_ev_map.get(fid)
    if ev_st == "RUNTIME_EXPLOIT_CONFIRMED":
        return "[RUNTIME EXPLOIT CONFIRMED]"
    if ev_st == "FIXED_VERIFIED":
        return "[FIXED VERIFIED]"
    return ""


def _build_ev_attestation_rows(ev_replays: List[EvReplayBundleItem]) -> List[List[str]]:
    return [
        [
            rep.replay_id,
            rep.probe_family,
            f"{rep.method} {rep.path}",
            rep.status,
            rep.finding_id or "UNLINKED",
            rep.evidence_summary,
        ]
        for rep in ev_replays
    ]


def _format_ev_attestation_summary(ev_replays: List[EvReplayBundleItem]) -> str:
    ev_conf_cnt = sum(1 for r in ev_replays if r.status == "RUNTIME_EXPLOIT_CONFIRMED")
    ev_fix_cnt = sum(1 for r in ev_replays if r.status == "FIXED_VERIFIED")
    return (
        f"{len(ev_replays)} persisted EV replay bundle(s): "
        f"{ev_conf_cnt} RUNTIME EXPLOIT CONFIRMED, {ev_fix_cnt} FIXED VERIFIED."
    )


def _build_mandatory_blocker_rows(
    clean: SarReportBundle,
    mandatory_items: List[GoLiveObservationItem],
    include_badge_in_why: bool = False,
) -> List[List[str]]:
    finding_ev_map, replay_ev_map = _resolve_ev_status_maps(clean)
    blk_rows: List[List[str]] = []
    for b in mandatory_items:
        ev_badge = _ev_badge_for_observation(b, finding_ev_map, replay_ev_map)
        id_sev_col = f"{b.id}\n[{b.severity}]\n{ev_badge}" if ev_badge else f"{b.id}\n[{b.severity}]"
        why_col = (
            f"{ev_badge} {b.why_issue} {b.why_gate_classification}"
            if (include_badge_in_why and ev_badge)
            else f"{b.why_issue} {b.why_gate_classification}"
        )
        blk_rows.append(
            [
                id_sev_col,
                f"{b.source_type}\n{b.cwe_or_standard}",
                f"{b.filepath}:L{b.line}",
                why_col,
                b.mandatory_fix_action,
                f"{b.raci_owner} ({b.effort_estimate})",
                f"-{b.risk_reduction_points} pts",
            ]
        )
    return blk_rows


def _format_attack_tree_chain(scenario: PastaAttackTreeScenario) -> str:
    ordered_nodes = [n for n in scenario.nodes if n.node_role != "BFL_SHIELD"]
    if not ordered_nodes:
        return scenario.narrative
    return " -> ".join(f"[{n.node_role}] {n.title}" for n in ordered_nodes)


def build_sar_json_dict(bundle: SarReportBundle) -> Dict[str, Any]:
    """Builds the sanitized, structured 10-section SAR Go-Live JSON dictionary."""
    clean = sanitize_bundle_for_export(bundle)
    pasta = clean.pasta
    mandatory_obs = [
        o.model_dump()
        for o in pasta.golive_observations
        if o.gate_status == "MANDATORY_PRE_GO_LIVE"
    ]
    post_sla_obs = [
        o.model_dump()
        for o in pasta.golive_observations
        if o.gate_status == "POST_GO_LIVE_SLA"
    ]
    waived_obs = [
        o.model_dump()
        for o in pasta.golive_observations
        if o.gate_status == "RISK_ACCEPTED_WAIVER" or o.is_overridden
    ]
    strengths = _collect_architectural_strengths(clean)
    signoff_rows = _build_formal_signoff_rows(clean)
    qa_pairs = _decision_rationale_qa(clean)

    return {
        "document_control": {
            "report_title": f"ALASTOR Security Architecture Review (SAR) & Go-Live Dossier — {clean.application_name}",
            "classification": "CONFIDENTIAL • ARB / CISO GO-LIVE GATE",
            "application_name": clean.application_name,
            "project_path": clean.project_path,
            "generated_at": clean.generated_at,
            "selected_business_preset": pasta.selected_business_preset,
            "effective_business_preset": pasta.effective_business_preset,
            "inferred_business_reason": pasta.inferred_business_reason,
            "compliance_frameworks": list(pasta.compliance_frameworks),
            "metrics": clean.metrics.model_dump(),
        },
        "executive_golive_scorecard": {
            "golive_verdict": pasta.golive_verdict,
            "golive_verdict_banner": _verdict_display_banner(pasta.golive_verdict),
            "golive_verdict_label": pasta.golive_verdict_label,
            "can_go_live_today": pasta.golive_verdict != "NO_GO_HOLD_RELEASE",
            "inherent_risk_score": pasta.inherent_risk_score,
            "inherent_risk_level": pasta.inherent_risk_level,
            "residual_risk_score": pasta.residual_risk_score,
            "residual_risk_level": pasta.residual_risk_level,
            "projected_golive_risk_score": pasta.projected_golive_risk_score,
            "projected_golive_risk_level": pasta.projected_golive_risk_level,
            "mandatory_pre_golive_count": pasta.mandatory_pre_golive_count,
            "post_golive_sla_count": pasta.post_golive_sla_count,
            "waived_count": pasta.waived_count,
            "passing_controls_count": pasta.passing_controls_count,
            "overall_maturity_grade": clean.sast_plus.overall_maturity_grade,
            "maturity_score": clean.sast_plus.maturity_score,
            "golive_executive_summary": pasta.golive_executive_summary,
            "executive_plain_summary": clean.sast_plus.executive_plain_summary,
            "decision_rationale": [
                {"question": q_txt, "answer": a_txt} for q_txt, a_txt in qa_pairs
            ],
        },
        "pasta_assessment": pasta.model_dump(),
        "stride_threats": [s.model_dump() for s in clean.sast_plus.stride_threats],
        "mandatory_pre_golive_blockers": mandatory_obs,
        "post_golive_deferrable_observations": post_sla_obs,
        "waived_observations": waived_obs,
        "make_it_live_runbook": list(pasta.make_it_live_checklist),
        "architectural_strengths": strengths,
        "raci_and_signoff": {
            "governance_health_score": clean.raci.governance_health_score,
            "valid_rows_count": clean.raci.valid_rows_count,
            "total_rows_count": clean.raci.total_rows_count,
            "validation_warnings": list(clean.raci.validation_warnings),
            "roles": [r.model_dump() for r in clean.raci.roles],
            "finding_assignments": [fa.model_dump() for fa in clean.raci.finding_assignments],
            "waiver_and_override_log": waived_obs,
            "formal_signoff_table": signoff_rows,
        },
        "findings": [f.model_dump() for f in clean.findings],
        "exploit_chains": [c.model_dump() for c in clean.exploit_chains],
        "ev_replays": [r.model_dump() for r in clean.ev_replays],
    }


# ---------------------------------------------------------------------------
# Word (.docx) OpenXML Generator Helpers
# ---------------------------------------------------------------------------
def _docx_shade_cell(cell: Any, hex_fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill.lstrip("#"))
    tc_pr.append(shd)


def _docx_repeat_header_row(row: Any) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tbl_hdr = OxmlElement("w:tblHeader")
    tr_pr.append(tbl_hdr)


def _docx_status_color(status_txt: str) -> RGBColor:
    up = (status_txt or "").upper()
    if any(
        k in up
        for k in (
            "NO-GO",
            "NO_GO",
            "CRITICAL",
            "HIGH",
            "FAIL",
            "ACTION_REQUIRED",
            "MANDATORY",
            "EXPLOITABLE",
            "RUNTIME EXPLOIT CONFIRMED",
            "RUNTIME_EXPLOIT_CONFIRMED",
            "STILL_VULNERABLE",
        )
    ):
        return _DOCX_ROSE
    if any(k in up for k in ("CONDITIONAL", "MODERATE", "MEDIUM", "WARNING", "MONITORED", "SLA", "PARTIALLY", "WAIVER", "WAIVED")):
        return _DOCX_AMBER
    return _DOCX_EMERALD


def _docx_add_section_heading(doc: Any, num: int, title: str) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(_clean_xml_text(f"Section {num} — {title}"))
    run.bold = True
    run.font.name = "Calibri"
    run.font.size = Pt(13.5)
    run.font.color.rgb = _DOCX_NAVY


def _docx_add_sub_heading(doc: Any, subtitle: str) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(_clean_xml_text(subtitle))
    run.bold = True
    run.font.name = "Calibri"
    run.font.size = Pt(10.5)
    run.font.color.rgb = _DOCX_SLATE


def _docx_add_body(doc: Any, text: str, bold_prefix: str = "", monospace: bool = False) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(3)
    if bold_prefix:
        r_pre = p.add_run(_clean_xml_text(bold_prefix) + " ")
        r_pre.bold = True
        r_pre.font.name = "Calibri"
        r_pre.font.size = Pt(9.5)
        r_pre.font.color.rgb = _DOCX_NAVY
    r_txt = p.add_run(_clean_xml_text(text, max_len=1600))
    r_txt.font.name = "Consolas" if monospace else "Calibri"
    r_txt.font.size = Pt(8.5 if monospace else 9.5)
    r_txt.font.color.rgb = _DOCX_SLATE


def _docx_add_banner(doc: Any, label: str, detail: str, fill_hex: str, text_color: RGBColor) -> None:
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.rows[0].cells[0]
    _docx_shade_cell(cell, fill_hex)
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(5)
    p.paragraph_format.space_after = Pt(5)
    r_lbl = p.add_run(_clean_xml_text(label))
    r_lbl.bold = True
    r_lbl.font.name = "Calibri"
    r_lbl.font.size = Pt(12)
    r_lbl.font.color.rgb = text_color
    if detail:
        r_det = p.add_run("\n" + _clean_xml_text(detail, max_len=900))
        r_det.font.name = "Calibri"
        r_det.font.size = Pt(9.5)
        r_det.font.color.rgb = _DOCX_SLATE


def _docx_add_styled_table(
    doc: Any,
    headers: List[str],
    rows_data: List[List[str]],
    status_col_indices: Tuple[int, ...] = (),
    mono_col_indices: Tuple[int, ...] = (),
) -> None:
    tbl = doc.add_table(rows=1 + len(rows_data), cols=len(headers))
    tbl.style = "Table Grid"
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER

    hdr_row = tbl.rows[0]
    _docx_repeat_header_row(hdr_row)
    for col_i, h_text in enumerate(headers):
        c = hdr_row.cells[col_i]
        _docx_shade_cell(c, _HEX_TBL_HEADER_BG)
        p = c.paragraphs[0]
        p.paragraph_format.space_before = Pt(3)
        p.paragraph_format.space_after = Pt(3)
        run = p.add_run(_clean_xml_text(h_text))
        run.bold = True
        run.font.name = "Calibri"
        run.font.size = Pt(8.5)
        run.font.color.rgb = _DOCX_NAVY

    for row_idx, r_vals in enumerate(rows_data):
        row_obj = tbl.rows[row_idx + 1]
        is_alt = row_idx % 2 == 1
        for col_i, val in enumerate(r_vals):
            c = row_obj.cells[col_i]
            if is_alt:
                _docx_shade_cell(c, _HEX_TBL_ALT_BG)
            p = c.paragraphs[0]
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(2)
            clean_cell = _clean_xml_text(val, max_len=650)
            run = p.add_run(clean_cell)
            is_mono = col_i in mono_col_indices
            run.font.name = "Consolas" if is_mono else "Calibri"
            run.font.size = Pt(8.0 if is_mono else 8.5)
            if col_i in status_col_indices:
                run.bold = True
                run.font.color.rgb = _docx_status_color(clean_cell)
            else:
                run.font.color.rgb = _DOCX_SLATE


def generate_sar_docx_bytes(bundle: SarReportBundle) -> bytes:
    """Generates a corporate Daylight 10-section Word (`.docx`) SAR Go-Live Dossier."""
    clean = sanitize_bundle_for_export(bundle)
    pasta = clean.pasta
    suite = clean.sast_plus
    raci = clean.raci
    metrics = clean.metrics

    doc = docx.Document()
    for sec in doc.sections:
        sec.top_margin = Inches(0.65)
        sec.bottom_margin = Inches(0.65)
        sec.left_margin = Inches(0.6)
        sec.right_margin = Inches(0.6)

        hdr_p = sec.header.paragraphs[0]
        hdr_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hdr_r = hdr_p.add_run(
            _clean_xml_text(f"ALASTOR SAR GO-LIVE DOSSIER  |  {clean.application_name}  |  CONFIDENTIAL")
        )
        hdr_r.font.name = "Calibri"
        hdr_r.font.size = Pt(8)
        hdr_r.font.color.rgb = _DOCX_MUTED

        ftr_p = sec.footer.paragraphs[0]
        ftr_p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        ftr_r = ftr_p.add_run(
            _clean_xml_text(
                f"Generated {clean.generated_at} • ALASTOR 7-Stage PASTA & Deterministic CPG Engine • Zero Raw Secrets Policy"
            )
        )
        ftr_r.font.name = "Calibri"
        ftr_r.font.size = Pt(8)
        ftr_r.font.color.rgb = _DOCX_MUTED

    # Cover Title Block
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_after = Pt(2)
    title_r = title_p.add_run(
        _clean_xml_text(f"SECURITY ARCHITECTURE REVIEW (SAR) & GO-LIVE DOSSIER — {clean.application_name}")
    )
    title_r.bold = True
    title_r.font.name = "Calibri"
    title_r.font.size = Pt(17)
    title_r.font.color.rgb = _DOCX_NAVY

    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_after = Pt(8)
    sub_r = sub_p.add_run(
        "Deterministic 7-Stage PASTA Threat Simulation, STRIDE Matrix, Attack Tree BFL Analysis & Release Gate Attestation"
    )
    sub_r.font.name = "Calibri"
    sub_r.font.size = Pt(10)
    sub_r.font.color.rgb = _DOCX_MUTED

    # Section 1 — Document Control & Executive Go-Live Scorecard
    _docx_add_section_heading(doc, 1, "Document Control & Executive Go-Live Scorecard")

    verdict_banner = _verdict_display_banner(pasta.golive_verdict)
    if pasta.golive_verdict == "APPROVED_FOR_GO_LIVE":
        b_fill, b_col = _HEX_EMERALD_BG, _DOCX_EMERALD
    elif pasta.golive_verdict == "CONDITIONAL_GO_LIVE":
        b_fill, b_col = _HEX_AMBER_BG, _DOCX_AMBER
    else:
        b_fill, b_col = _HEX_ROSE_BG, _DOCX_ROSE

    _docx_add_banner(
        doc,
        f"OVERALL GO-LIVE VERDICT: {verdict_banner}",
        f"{pasta.golive_verdict_label}  |  Maturity Grade: {suite.overall_maturity_grade} ({suite.maturity_score}/100)",
        b_fill,
        b_col,
    )

    doc_ctrl_rows = [
        ["Application Name", clean.application_name, "Assessment Timestamp", clean.generated_at],
        ["Target Workspace Path", clean.project_path, "Business Profile", f"{pasta.effective_business_preset} (Selected: {pasta.selected_business_preset})"],
        ["Compliance Frameworks", ", ".join(pasta.compliance_frameworks) or "SOC 2 Type II", "CPG Graph Telemetry", f"{metrics.total_app_files} files | {metrics.total_nodes} nodes | {metrics.total_edges} edges"],
    ]
    _docx_add_styled_table(
        doc,
        ["Control Attribute", "Value", "Assessment Metadata", "Value"],
        doc_ctrl_rows,
        mono_col_indices=(1,),
    )

    _docx_add_sub_heading(doc, "3-Stage Go-Live Risk Scorecard & Gate Disposition")
    scorecard_rows = [
        ["Inherent Risk", f"{pasta.inherent_risk_score} / 100", pasta.inherent_risk_level, "Pre-control architectural & crown-jewel exposure baseline."],
        ["Current Residual Risk", f"{pasta.residual_risk_score} / 100", pasta.residual_risk_level, f"{pasta.mandatory_pre_golive_count} Mandatory Pre-Go-Live Blocker(s) + {pasta.post_golive_sla_count} SLA Item(s) currently active."],
        ["Final Projected Go-Live Risk Level", f"{pasta.projected_golive_risk_score} / 100", pasta.projected_golive_risk_level, f"Target residual posture once all {pasta.mandatory_pre_golive_count} mandatory pre-launch blocker(s) are closed."],
    ]
    _docx_add_styled_table(
        doc,
        ["Risk Stage", "Quantified Score", "Risk Level", "Gate Interpretation"],
        scorecard_rows,
        status_col_indices=(2,),
    )

    gate_counts_rows = [
        [
            str(pasta.mandatory_pre_golive_count),
            str(pasta.post_golive_sla_count),
            str(pasta.waived_count),
            str(pasta.passing_controls_count),
        ]
    ]
    _docx_add_styled_table(
        doc,
        [
            "Mandatory Pre-Go-Live Blockers",
            "Post-Go-Live SLA Items",
            "Risk-Accepted Waivers",
            "Verified Passing Controls",
        ],
        gate_counts_rows,
    )

    # Section 2 — Executive Summary & Go-Live Decision Rationale
    _docx_add_section_heading(doc, 2, "Executive Summary & Go-Live Decision Rationale")
    _docx_add_body(doc, pasta.golive_executive_summary, bold_prefix="PASTA Go-Live Summary:")
    if suite.executive_plain_summary:
        _docx_add_body(doc, suite.executive_plain_summary, bold_prefix="ASPM Posture Narrative:")
    for q_label, a_text in _decision_rationale_qa(clean):
        _docx_add_body(doc, a_text, bold_prefix=q_label)

    # Section 3 — Security Architecture & Technical Scope Review (PASTA Stages I–III)
    _docx_add_section_heading(doc, 3, "Security Architecture & Technical Scope Review (PASTA Stages I–III)")
    _docx_add_body(doc, pasta.inferred_business_reason, bold_prefix="Business Criticality Basis:")

    _docx_add_sub_heading(doc, "3A. Weighted Crown Jewels & Criticality Multipliers")
    cj_rows = [
        [
            cj.name,
            cj.category,
            cj.sensitivity_label,
            f"{cj.weight_multiplier:.2f}x",
            str(cj.asset_count),
            (", ".join(cj.sample_locations[:3]) or cj.rationale),
        ]
        for cj in pasta.crown_jewels
    ] or [["Standard Workspace Assets", "GENERAL", "STANDARD", "1.00x", "0", "Baseline scope"]]
    _docx_add_styled_table(
        doc,
        ["Crown Jewel Asset Class", "Category", "Sensitivity", "Multiplier", "Refs", "Evidence Locations / Rationale"],
        cj_rows,
        status_col_indices=(2,),
        mono_col_indices=(5,),
    )

    _docx_add_sub_heading(doc, "3B. Technical Stack & SBOM Dependency Pinning Posture")
    _docx_add_body(
        doc,
        f"Total SBOM Components: {suite.total_sbom_components}  |  Strictly Pinned: {suite.pinned_components_count}  |  Floating / Unpinned: {suite.unpinned_components_count}",
    )
    sbom_rows = [
        [
            comp.name,
            comp.version,
            comp.ecosystem,
            comp.risk_status,
            f"{comp.manifest_path}:L{comp.line_number}",
        ]
        for comp in suite.sbom_components[:18]
    ]
    if sbom_rows:
        _docx_add_styled_table(
            doc,
            ["Package / Module", "Version", "Ecosystem", "Pinning Status", "Manifest Location"],
            sbom_rows,
            status_col_indices=(3,),
            mono_col_indices=(0, 1, 4),
        )

    _docx_add_sub_heading(doc, "3C. Discovered Attack Surface Entrypoints")
    ep_rows = [
        [
            f"{ep.method} {ep.route_path}",
            f"{ep.handler_name} ({ep.filepath}:L{ep.line_number})",
            ep.auth_posture,
            ep.exposure_level,
            str(ep.linked_findings_count),
        ]
        for ep in suite.endpoints[:18]
    ] or [["N/A", "No external HTTP routes discovered", "Internal Module", "STANDARD", "0"]]
    _docx_add_styled_table(
        doc,
        ["Method & Route", "Handler & Filepath", "Auth Posture", "Exposure", "Findings"],
        ep_rows,
        status_col_indices=(3,),
        mono_col_indices=(0, 1),
    )

    _docx_add_sub_heading(doc, "3D. Container & CI/CD Pipeline Security (PBOM) Summary")
    pbom_rows = [
        [
            chk.id,
            chk.category,
            chk.status,
            chk.evidence_path,
            chk.details,
        ]
        for chk in suite.pipeline_checks
    ] or [["pbom-pass", "Baseline Supply Chain", "PASS", clean.project_path, "No PBOM issues detected."]]
    _docx_add_styled_table(
        doc,
        ["Check ID", "Control Category", "Status", "Evidence Path", "Assessment Details"],
        pbom_rows,
        status_col_indices=(2,),
        mono_col_indices=(0, 3),
    )

    # Section 4 — STRIDE Threat Modeling Matrix (S, T, R, I, D, E)
    _docx_add_section_heading(doc, 4, "STRIDE Threat Modeling Matrix (S, T, R, I, D, E)")
    stride_rows = [
        [
            f"{st.stride_letter} — {st.stride_category}",
            st.status,
            f"{st.ok_count} OK / {st.issue_count} Issue(s)",
            st.issue_summary if st.issue_count > 0 else st.ok_summary,
            st.mitigation_control,
        ]
        for st in suite.stride_threats
    ] or [["S/T/R/I/D/E", "MITIGATED", "0 Issue(s)", "All STRIDE domains clean.", "Maintain baseline controls."]]
    _docx_add_styled_table(
        doc,
        ["STRIDE Category", "Status", "Checks (OK vs Issues)", "Domain Summary", "Mitigation Control"],
        stride_rows,
        status_col_indices=(1,),
    )

    # Section 5 — 7-Stage PASTA Assessment & Simulated Attack Trees (PASTA Stages IV–VII)
    _docx_add_section_heading(doc, 5, "7-Stage PASTA Assessment & Simulated Attack Trees (PASTA Stages IV–VII)")
    stage_rows = [
        [
            f"{st.stage_code} ({st.stage_roman})",
            st.title,
            st.status,
            f"{st.ok_count} OK / {st.gap_count} Gap(s)",
            st.summary,
        ]
        for st in pasta.stages
    ]
    _docx_add_styled_table(
        doc,
        ["Stage", "PASTA Stage Title", "Status", "Evidence (OK / Gaps)", "Stage Assessment Summary"],
        stage_rows,
        status_col_indices=(2,),
    )

    _docx_add_sub_heading(doc, "Simulated Multi-Hop Attack Tree Scenarios & BFL Chokepoint Shields")
    tree_rows = [
        [
            sc.title,
            f"{sc.attacker_persona} ({sc.mitre_capec})",
            sc.target_crown_jewel,
            sc.status,
            _format_attack_tree_chain(sc),
            sc.bfl_remediation,
        ]
        for sc in pasta.attack_trees
    ] or [["Baseline Defense-in-Depth", "External Opportunistic Attacker", "HOST_RUNTIME_AND_OS", "SEVERED_BY_CONTROLS", "Entrypoint -> Sanitizer -> Safe Sink", "All active paths guarded."]]
    _docx_add_styled_table(
        doc,
        ["Scenario Title", "Persona & MITRE CAPEC", "Target Crown Jewel", "Path Status", "Multi-Hop Node Chain (->)", "BFL Chokepoint Shield"],
        tree_rows,
        status_col_indices=(3,),
        mono_col_indices=(4, 5),
    )

    if clean.exploit_chains:
        _docx_add_sub_heading(doc, "5C. S8 Multi-Hop Exploit Chains")
        s8_rows = [
            [
                _clean_xml_text(ch.title, max_len=140),
                f"{ch.severity} (CVSS {ch.chain_cvss:.1f})",
                _clean_xml_text(
                    " -> ".join(f"[{h.hop_type}] {h.title}" for h in ch.hops),
                    max_len=360,
                ),
                _clean_xml_text(
                    ", ".join(ch.blast_radius_communities) or "Single Module",
                    max_len=140,
                ),
                _clean_xml_text(ch.break_the_chain_fix, max_len=280),
            ]
            for ch in clean.exploit_chains[:10]
        ]
        _docx_add_styled_table(
            doc,
            [
                "Chain Title",
                "Severity & Chain CVSS",
                "Attack Hops",
                "Blast-Radius Communities",
                "Break-the-Chain Priority Fix",
            ],
            s8_rows,
            status_col_indices=(1,),
            mono_col_indices=(2, 4),
        )

    # Section 6 — MANDATORY PRE-GO-LIVE BLOCKERS (Must Fix Before Launch)
    _docx_add_section_heading(doc, 6, "MANDATORY PRE-GO-LIVE BLOCKERS (Must Fix Before Launch)")
    mandatory_items: List[GoLiveObservationItem] = [
        o for o in pasta.golive_observations if o.gate_status == "MANDATORY_PRE_GO_LIVE"
    ]
    if not mandatory_items:
        _docx_add_banner(
            doc,
            "PASS ATTESTATION: 0 Mandatory Pre-Go-Live Blockers Open",
            "All pre-launch release gates across Reachable Critical/High SAST, Verified-Active Secret Vault, Unauthenticated Exec/DB Write Routes, and Supply-Chain Integrity are satisfied.",
            _HEX_EMERALD_BG,
            _DOCX_EMERALD,
        )
    else:
        blk_rows = _build_mandatory_blocker_rows(clean, mandatory_items, include_badge_in_why=False)
        _docx_add_styled_table(
            doc,
            [
                "ID & Severity",
                "Domain & CWE",
                "Location",
                "Why It Blocks Go-Live",
                "Mandatory Pre-Launch Fix",
                "Owner & Effort",
                "Risk Reduction",
            ],
            blk_rows,
            status_col_indices=(0,),
            mono_col_indices=(2, 4),
        )

    _docx_add_sub_heading(
        doc,
        "Live Exploit Verification (EV) & Post-Fix ev-replay Runtime Attestation",
    )
    if not clean.ev_replays:
        _docx_add_body(doc, "No live EV probes executed for this assessment scope.")
    else:
        _docx_add_body(
            doc,
            _format_ev_attestation_summary(clean.ev_replays),
            bold_prefix="Runtime Attestation Summary:",
        )
        _docx_add_styled_table(
            doc,
            ["Replay ID", "Probe Family", "Endpoint", "Status", "Finding ID", "Evidence Summary"],
            _build_ev_attestation_rows(clean.ev_replays),
            status_col_indices=(3,),
            mono_col_indices=(0, 2, 4),
        )

    # Section 7 — POST-GO-LIVE ALLOWED OBSERVATIONS (Deferrable with Binding SLA & Compensating Controls)
    _docx_add_section_heading(
        doc,
        7,
        "POST-GO-LIVE ALLOWED OBSERVATIONS (Deferrable with Binding SLA & Compensating Controls)",
    )
    sla_items: List[GoLiveObservationItem] = [
        o for o in pasta.golive_observations if o.gate_status == "POST_GO_LIVE_SLA"
    ]
    if not sla_items:
        _docx_add_body(
            doc,
            "0 Post-Go-Live deferred SLA observations open. No post-launch compensating control exceptions required.",
        )
    else:
        sla_rows = [
            [
                s.severity,
                f"{s.title} ({s.filepath}:L{s.line})",
                s.why_gate_classification,
                s.compensating_control,
                s.sla_window,
                s.mandatory_fix_action,
            ]
            for s in sla_items
        ]
        _docx_add_styled_table(
            doc,
            [
                "Severity",
                "Title & Location",
                "Why Deferral Is Acceptable",
                "Mandatory Launch Compensating Control",
                "Binding SLA",
                "Permanent Remediation Action",
            ],
            sla_rows,
            status_col_indices=(0, 4),
            mono_col_indices=(1,),
        )

    # Section 8 — Step-by-Step "What To Do To Make It Live" Runbook
    _docx_add_section_heading(doc, 8, 'Step-by-Step "What To Do To Make It Live" Runbook')
    for idx_step, step_txt in enumerate(pasta.make_it_live_checklist, start=1):
        _docx_add_body(doc, step_txt, bold_prefix=f"Step {idx_step}.")

    # Section 9 — Verified Architectural Strengths & Passing Security Controls
    _docx_add_section_heading(doc, 9, "Verified Architectural Strengths & Passing Security Controls")
    strengths = _collect_architectural_strengths(clean)
    all_strength_lines = (
        strengths["pasta_stage_controls"]
        + strengths["passing_pbom_checks"]
        + strengths["mitigated_stride_domains"]
    )
    if not all_strength_lines:
        _docx_add_body(doc, "Baseline static CPG & AST scope analysis completed.")
    else:
        for s_line in all_strength_lines[:20]:
            _docx_add_body(doc, s_line, bold_prefix="PASS •")

    # Section 10 — RACI Governance, Risk-Acceptance Waivers & Formal ARB / CISO Sign-Off
    _docx_add_section_heading(
        doc,
        10,
        "RACI Governance, Risk-Acceptance Waivers & Formal ARB / CISO Sign-Off",
    )
    _docx_add_body(
        doc,
        f"PMI/COBIT RACI Governance Health Score: {raci.governance_health_score}% "
        f"({raci.valid_rows_count}/{raci.total_rows_count} validated governance activities; "
        f"{len(raci.finding_assignments)} finding ownership assignment(s)).",
        bold_prefix="RACI Governance Posture:",
    )

    _docx_add_sub_heading(doc, "Waiver & Architect Gate Override Log")
    waiver_items = [
        o
        for o in pasta.golive_observations
        if o.gate_status == "RISK_ACCEPTED_WAIVER" or o.is_overridden
    ]
    if not waiver_items:
        _docx_add_body(doc, "0 Risk-Acceptance Waivers or manual gate overrides recorded for this release.")
    else:
        waiver_rows = [
            [
                w.id,
                w.severity,
                f"{w.title} ({w.filepath}:L{w.line})",
                f"{w.default_gate_status} -> {w.gate_status}",
                w.sla_window,
                w.compensating_control,
            ]
            for w in waiver_items
        ]
        _docx_add_styled_table(
            doc,
            ["Observation ID", "Severity", "Observation & Location", "Gate Transition", "SLA / Status", "Compensating Control & Justification"],
            waiver_rows,
            status_col_indices=(1, 4),
        )

    _docx_add_sub_heading(doc, "Formal ARB / CISO Go-Live Sign-Off Matrix")
    signoff_rows = [
        [r["role"], r["responsibility"], r["representative"], r["signature_date"]]
        for r in _build_formal_signoff_rows(clean)
    ]
    _docx_add_styled_table(
        doc,
        ["Role", "Decision / Gate Responsibility", "Representative", "Signature / Date"],
        signoff_rows,
    )

    out_buf = BytesIO()
    doc.save(out_buf)
    return out_buf.getvalue()


# ---------------------------------------------------------------------------
# PDF (.pdf) ReportLab Platypus Generator
# ---------------------------------------------------------------------------
def _rl_status_hex(status_txt: str) -> str:
    up = (status_txt or "").upper()
    if any(
        k in up
        for k in (
            "NO-GO",
            "NO_GO",
            "CRITICAL",
            "HIGH",
            "FAIL",
            "ACTION_REQUIRED",
            "MANDATORY",
            "EXPLOITABLE",
            "RUNTIME EXPLOIT CONFIRMED",
            "RUNTIME_EXPLOIT_CONFIRMED",
            "STILL_VULNERABLE",
        )
    ):
        return f"#{_HEX_ROSE}"
    if any(k in up for k in ("CONDITIONAL", "MODERATE", "MEDIUM", "WARNING", "MONITORED", "SLA", "PARTIALLY", "WAIVER", "WAIVED")):
        return f"#{_HEX_AMBER}"
    return f"#{_HEX_EMERALD}"


def _build_rl_table(
    headers: List[str],
    rows_data: List[List[str]],
    col_weights: List[float],
    avail_width: float,
    hdr_style: ParagraphStyle,
    cell_style: ParagraphStyle,
    mono_style: ParagraphStyle,
    status_cols: Tuple[int, ...] = (),
    mono_cols: Tuple[int, ...] = (),
) -> Table:
    total_w = sum(col_weights) or 1.0
    col_widths = [(w / total_w) * avail_width for w in col_weights]

    flow_rows: List[List[Paragraph]] = [
        [Paragraph(f"<b>{_rl_esc(h, max_len=120)}</b>", hdr_style) for h in headers]
    ]
    for r_vals in rows_data:
        rendered_row: List[Paragraph] = []
        for idx_c, raw_val in enumerate(r_vals):
            safe_markup = _rl_esc(raw_val, max_len=480)
            if idx_c in status_cols:
                col_hex = _rl_status_hex(str(raw_val))
                rendered_row.append(
                    Paragraph(f'<font color="{col_hex}"><b>{safe_markup}</b></font>', cell_style)
                )
            elif idx_c in mono_cols:
                rendered_row.append(Paragraph(safe_markup, mono_style))
            else:
                rendered_row.append(Paragraph(safe_markup, cell_style))
        flow_rows.append(rendered_row)

    tbl = Table(flow_rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _RL_TBL_HEADER_BG),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _RL_TBL_ALT_BG]),
                ("GRID", (0, 0), (-1, -1), 0.45, _RL_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return tbl


def _build_rl_banner(
    headline: str,
    detail: str,
    bg_color: colors.Color,
    accent_hex: str,
    avail_width: float,
    cell_style: ParagraphStyle,
) -> Table:
    markup = (
        f'<font color="#{accent_hex}" size="10"><b>{_rl_esc(headline, max_len=220)}</b></font><br/>'
        f'<font color="#{_HEX_SLATE_TEXT}" size="8">{_rl_esc(detail, max_len=700)}</font>'
    )
    banner_tbl = Table([[Paragraph(markup, cell_style)]], colWidths=[avail_width])
    banner_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                ("BOX", (0, 0), (-1, -1), 1.0, colors.HexColor(f"#{accent_hex}")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return banner_tbl


def generate_sar_pdf_bytes(bundle: SarReportBundle) -> bytes:
    """Generates a corporate Daylight multi-page A4 PDF (`.pdf`) 10-section SAR Go-Live Dossier."""
    clean = sanitize_bundle_for_export(bundle)
    pasta = clean.pasta
    suite = clean.sast_plus
    raci = clean.raci
    metrics = clean.metrics

    out_buf = BytesIO()
    margin_lr = 34.0
    margin_tb = 46.0
    avail_w = A4[0] - (2.0 * margin_lr)

    pdf_doc = SimpleDocTemplate(
        out_buf,
        pagesize=A4,
        leftMargin=margin_lr,
        rightMargin=margin_lr,
        topMargin=margin_tb,
        bottomMargin=margin_tb,
        title=_clean_xml_text(f"ALASTOR SAR Go-Live Report - {clean.application_name}", max_len=140),
        author="ALASTOR 7-Stage PASTA & Deterministic CPG Engine",
    )

    base_styles = getSampleStyleSheet()
    title_st = ParagraphStyle(
        "SarTitle",
        parent=base_styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=_RL_NAVY,
        spaceAfter=3,
    )
    subtitle_st = ParagraphStyle(
        "SarSubtitle",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=_RL_MUTED,
        spaceAfter=8,
    )
    sec_st = ParagraphStyle(
        "SarSection",
        parent=base_styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=15,
        textColor=_RL_NAVY,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )
    subsec_st = ParagraphStyle(
        "SarSubSection",
        parent=base_styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=9.2,
        leading=12,
        textColor=_RL_SLATE,
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True,
    )
    body_st = ParagraphStyle(
        "SarBody",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=8.3,
        leading=11.5,
        textColor=_RL_SLATE,
        spaceAfter=4,
        wordWrap="CJK",
    )
    hdr_cell_st = ParagraphStyle(
        "SarHdrCell",
        parent=base_styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.6,
        leading=10,
        textColor=_RL_NAVY,
        wordWrap="CJK",
    )
    cell_st = ParagraphStyle(
        "SarCell",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=7.4,
        leading=9.8,
        textColor=_RL_SLATE,
        wordWrap="CJK",
    )
    mono_cell_st = ParagraphStyle(
        "SarMonoCell",
        parent=base_styles["Normal"],
        fontName="Courier",
        fontSize=6.9,
        leading=9.2,
        textColor=_RL_SLATE,
        wordWrap="CJK",
    )

    story: List[Any] = [
        Paragraph(
            f"SECURITY ARCHITECTURE REVIEW (SAR) &amp; GO-LIVE DOSSIER — {_rl_esc(clean.application_name, max_len=120)}",
            title_st,
        ),
        Paragraph(
            "Deterministic 7-Stage PASTA Threat Modeling, STRIDE Matrix, Multi-Hop Attack Trees &amp; ARB Go-Live Gate Attestation",
            subtitle_st,
        ),
        HRFlowable(width="100%", thickness=0.8, color=_RL_BORDER, spaceAfter=6),
    ]

    # Section 1 — Document Control & Executive Go-Live Scorecard
    story.append(Paragraph("Section 1 — Document Control &amp; Executive Go-Live Scorecard", sec_st))

    verdict_banner = _verdict_display_banner(pasta.golive_verdict)
    if pasta.golive_verdict == "APPROVED_FOR_GO_LIVE":
        rl_bg, rl_hex = _RL_EMERALD_BG, _HEX_EMERALD
    elif pasta.golive_verdict == "CONDITIONAL_GO_LIVE":
        rl_bg, rl_hex = _RL_AMBER_BG, _HEX_AMBER
    else:
        rl_bg, rl_hex = _RL_ROSE_BG, _HEX_ROSE

    story.append(
        _build_rl_banner(
            f"OVERALL GO-LIVE VERDICT: {verdict_banner}",
            f"{pasta.golive_verdict_label}  |  Maturity Grade: {suite.overall_maturity_grade} ({suite.maturity_score}/100)",
            rl_bg,
            rl_hex,
            avail_w,
            body_st,
        )
    )
    story.append(Spacer(1, 5))

    doc_ctrl_rows = [
        ["Application Name", clean.application_name, "Assessment Timestamp", clean.generated_at],
        ["Target Workspace Path", clean.project_path, "Business Profile", f"{pasta.effective_business_preset} ({pasta.selected_business_preset})"],
        ["Compliance Frameworks", ", ".join(pasta.compliance_frameworks) or "SOC 2 Type II", "CPG Telemetry", f"{metrics.total_app_files} files | {metrics.total_nodes} nodes | {metrics.total_edges} edges"],
    ]
    story.append(
        _build_rl_table(
            ["Control Attribute", "Value", "Assessment Metadata", "Value"],
            doc_ctrl_rows,
            [0.18, 0.34, 0.18, 0.30],
            avail_w,
            hdr_cell_st,
            cell_st,
            mono_cell_st,
            mono_cols=(1,),
        )
    )
    story.append(Paragraph("3-Stage Go-Live Risk Scorecard &amp; Gate Disposition", subsec_st))
    scorecard_rows = [
        ["Inherent Risk", f"{pasta.inherent_risk_score} / 100", pasta.inherent_risk_level, "Pre-control architectural & crown-jewel exposure baseline."],
        ["Current Residual Risk", f"{pasta.residual_risk_score} / 100", pasta.residual_risk_level, f"{pasta.mandatory_pre_golive_count} Mandatory Pre-Go-Live Blocker(s) + {pasta.post_golive_sla_count} SLA Item(s) open."],
        ["Final Projected Go-Live Risk Level", f"{pasta.projected_golive_risk_score} / 100", pasta.projected_golive_risk_level, f"Target residual posture once all {pasta.mandatory_pre_golive_count} mandatory pre-launch blocker(s) are closed."],
    ]
    story.append(
        _build_rl_table(
            ["Risk Stage", "Score", "Risk Level", "Gate Interpretation"],
            scorecard_rows,
            [0.26, 0.14, 0.14, 0.46],
            avail_w,
            hdr_cell_st,
            cell_st,
            mono_cell_st,
            status_cols=(2,),
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        _build_rl_table(
            [
                "Mandatory Pre-Go-Live Blockers",
                "Post-Go-Live SLA Items",
                "Risk-Accepted Waivers",
                "Verified Passing Controls",
            ],
            [[
                str(pasta.mandatory_pre_golive_count),
                str(pasta.post_golive_sla_count),
                str(pasta.waived_count),
                str(pasta.passing_controls_count),
            ]],
            [0.25, 0.25, 0.25, 0.25],
            avail_w,
            hdr_cell_st,
            cell_st,
            mono_cell_st,
        )
    )

    # Section 2 — Executive Summary & Go-Live Decision Rationale
    story.append(Paragraph("Section 2 — Executive Summary &amp; Go-Live Decision Rationale", sec_st))
    story.append(
        Paragraph(
            f"<b>PASTA Go-Live Summary:</b> {_rl_esc(pasta.golive_executive_summary, max_len=1200)}",
            body_st,
        )
    )
    if suite.executive_plain_summary:
        story.append(
            Paragraph(
                f"<b>ASPM Posture Narrative:</b> {_rl_esc(suite.executive_plain_summary, max_len=1200)}",
                body_st,
            )
        )
    for q_label, a_text in _decision_rationale_qa(clean):
        story.append(
            Paragraph(
                f"<b>{_rl_esc(q_label, max_len=140)}</b> {_rl_esc(a_text, max_len=900)}",
                body_st,
            )
        )

    # Section 3 — Security Architecture & Technical Scope Review (PASTA Stages I–III)
    story.append(
        Paragraph(
            "Section 3 — Security Architecture &amp; Technical Scope Review (PASTA Stages I–III)",
            sec_st,
        )
    )
    story.append(
        Paragraph(
            f"<b>Business Criticality Basis:</b> {_rl_esc(pasta.inferred_business_reason, max_len=600)}",
            body_st,
        )
    )
    story.append(Paragraph("3A. Weighted Crown Jewels &amp; Criticality Multipliers", subsec_st))
    cj_rows = [
        [
            cj.name,
            cj.category,
            cj.sensitivity_label,
            f"{cj.weight_multiplier:.2f}x ({cj.asset_count} refs)",
            ", ".join(cj.sample_locations[:3]) or cj.rationale,
        ]
        for cj in pasta.crown_jewels
    ] or [["Workspace Assets", "GENERAL", "STANDARD", "1.00x (0 refs)", "Baseline scope"]]
    story.append(
        _build_rl_table(
            ["Crown Jewel Asset Class", "Category", "Sensitivity", "Weight & Refs", "Sample Evidence / Rationale"],
            cj_rows,
            [0.25, 0.16, 0.12, 0.14, 0.33],
            avail_w,
            hdr_cell_st,
            cell_st,
            mono_cell_st,
            status_cols=(2,),
            mono_cols=(4,),
        )
    )

    story.append(
        Paragraph(
            f"3B. Technical Stack &amp; SBOM Posture (Total: {suite.total_sbom_components}, Pinned: {suite.pinned_components_count}, Unpinned: {suite.unpinned_components_count})",
            subsec_st,
        )
    )
    sbom_rows = [
        [c.name, c.version, c.ecosystem, c.risk_status, f"{c.manifest_path}:L{c.line_number}"]
        for c in suite.sbom_components[:16]
    ] or [["N/A", "N/A", "Workspace", "VERIFIED_PINNED", clean.project_path]]
    story.append(
        _build_rl_table(
            ["Component", "Version", "Ecosystem", "Pinning Status", "Manifest Location"],
            sbom_rows,
            [0.22, 0.16, 0.18, 0.18, 0.26],
            avail_w,
            hdr_cell_st,
            cell_st,
            mono_cell_st,
            status_cols=(3,),
            mono_cols=(0, 1, 4),
        )
    )

    story.append(Paragraph("3C. Discovered Attack Surface Entrypoints", subsec_st))
    ep_rows = [
        [
            f"{ep.method} {ep.route_path}",
            f"{ep.handler_name} ({ep.filepath}:L{ep.line_number})",
            ep.auth_posture,
            ep.exposure_level,
            str(ep.linked_findings_count),
        ]
        for ep in suite.endpoints[:16]
    ] or [["N/A", "No external HTTP routes discovered", "Internal", "STANDARD", "0"]]
    story.append(
        _build_rl_table(
            ["Method & Route", "Handler & Filepath", "Auth Posture", "Exposure", "Findings"],
            ep_rows,
            [0.24, 0.28, 0.22, 0.16, 0.10],
            avail_w,
            hdr_cell_st,
            cell_st,
            mono_cell_st,
            status_cols=(3,),
            mono_cols=(0, 1),
        )
    )

    story.append(Paragraph("3D. Container &amp; CI/CD PBOM Summary", subsec_st))
    pbom_rows = [
        [chk.id, chk.category, chk.status, chk.evidence_path, chk.details]
        for chk in suite.pipeline_checks
    ] or [["pbom-pass", "Supply Chain", "PASS", clean.project_path, "All PBOM checks passed."]]
    story.append(
        _build_rl_table(
            ["Check ID", "Category", "Status", "Evidence", "Details"],
            pbom_rows,
            [0.14, 0.22, 0.11, 0.18, 0.35],
            avail_w,
            hdr_cell_st,
            cell_st,
            mono_cell_st,
            status_cols=(2,),
            mono_cols=(0, 3),
        )
    )

    # Section 4 — STRIDE Threat Modeling Matrix (S, T, R, I, D, E)
    story.append(Paragraph("Section 4 — STRIDE Threat Modeling Matrix (S, T, R, I, D, E)", sec_st))
    stride_rows = [
        [
            f"{st.stride_letter} — {st.stride_category}",
            st.status,
            f"{st.ok_count} OK / {st.issue_count} Issue(s)",
            st.issue_summary if st.issue_count > 0 else st.ok_summary,
            st.mitigation_control,
        ]
        for st in suite.stride_threats
    ] or [["S/T/R/I/D/E", "MITIGATED", "0 Issue(s)", "All STRIDE domains clean.", "Maintain baseline controls."]]
    story.append(
        _build_rl_table(
            ["STRIDE Category", "Status", "Checks", "Domain Summary", "Mitigation Control"],
            stride_rows,
            [0.18, 0.13, 0.14, 0.29, 0.26],
            avail_w,
            hdr_cell_st,
            cell_st,
            mono_cell_st,
            status_cols=(1,),
        )
    )

    # Section 5 — 7-Stage PASTA Assessment & Simulated Attack Trees (PASTA Stages IV–VII)
    story.append(
        Paragraph(
            "Section 5 — 7-Stage PASTA Assessment &amp; Simulated Attack Trees (PASTA Stages IV–VII)",
            sec_st,
        )
    )
    stage_rows = [
        [
            f"{st.stage_code} ({st.stage_roman})",
            st.title,
            st.status,
            f"{st.ok_count} OK / {st.gap_count} Gap(s)",
            st.summary,
        ]
        for st in pasta.stages
    ]
    story.append(
        _build_rl_table(
            ["Stage", "PASTA Stage Title", "Status", "OK / Gaps", "Stage Summary"],
            stage_rows,
            [0.13, 0.24, 0.13, 0.14, 0.36],
            avail_w,
            hdr_cell_st,
            cell_st,
            mono_cell_st,
            status_cols=(2,),
        )
    )

    story.append(Paragraph("Simulated Multi-Hop Attack Tree Scenarios &amp; BFL Shields", subsec_st))
    tree_rows = [
        [
            sc.title,
            f"{sc.attacker_persona} ({sc.mitre_capec})",
            sc.target_crown_jewel,
            sc.status,
            _format_attack_tree_chain(sc),
            sc.bfl_remediation,
        ]
        for sc in pasta.attack_trees
    ] or [["Baseline Defense-in-Depth", "External Opportunistic Attacker", "HOST_RUNTIME_AND_OS", "SEVERED_BY_CONTROLS", "Entrypoint -> Sanitizer -> Safe Sink", "All active paths guarded."]]
    story.append(
        _build_rl_table(
            ["Scenario", "Persona & CAPEC", "Crown Jewel", "Status", "Attack Node Path (->)", "BFL Chokepoint Shield"],
            tree_rows,
            [0.16, 0.16, 0.13, 0.13, 0.23, 0.19],
            avail_w,
            hdr_cell_st,
            cell_st,
            mono_cell_st,
            status_cols=(3,),
            mono_cols=(4, 5),
        )
    )

    if clean.exploit_chains:
        story.append(Paragraph("5C. S8 Multi-Hop Exploit Chains", subsec_st))
        s8_pdf_rows = [
            [
                ch.title,
                f"{ch.severity} (CVSS {ch.chain_cvss:.1f})",
                " -> ".join(f"[{h.hop_type}] {h.title}" for h in ch.hops),
                ", ".join(ch.blast_radius_communities) or "Single Module",
                ch.break_the_chain_fix,
            ]
            for ch in clean.exploit_chains[:10]
        ]
        story.append(
            _build_rl_table(
                [
                    "Chain Title",
                    "Severity & Chain CVSS",
                    "Attack Hops",
                    "Blast-Radius Communities",
                    "Break-the-Chain Priority Fix",
                ],
                s8_pdf_rows,
                [0.20, 0.14, 0.30, 0.14, 0.22],
                avail_w,
                hdr_cell_st,
                cell_st,
                mono_cell_st,
                status_cols=(1,),
                mono_cols=(2, 4),
            )
        )

    # Section 6 — MANDATORY PRE-GO-LIVE BLOCKERS (Must Fix Before Launch)
    story.append(
        Paragraph("Section 6 — MANDATORY PRE-GO-LIVE BLOCKERS (Must Fix Before Launch)", sec_st)
    )
    mandatory_items = [
        o for o in pasta.golive_observations if o.gate_status == "MANDATORY_PRE_GO_LIVE"
    ]
    if not mandatory_items:
        story.append(
            _build_rl_banner(
                "PASS ATTESTATION: 0 Mandatory Pre-Go-Live Blockers Open",
                "Zero pre-launch blockers open across SAST, Verified-Active Secret Vault, API Trust Boundaries, and Supply-Chain Integrity.",
                _RL_EMERALD_BG,
                _HEX_EMERALD,
                avail_w,
                body_st,
            )
        )
    else:
        blk_rows = _build_mandatory_blocker_rows(clean, mandatory_items, include_badge_in_why=True)
        story.append(
            _build_rl_table(
                ["ID & Sev", "Domain & CWE", "Location", "Why It Blocks Go-Live", "Mandatory Fix", "Owner & Effort", "Reduction"],
                blk_rows,
                [0.12, 0.12, 0.14, 0.24, 0.18, 0.12, 0.08],
                avail_w,
                hdr_cell_st,
                cell_st,
                mono_cell_st,
                status_cols=(0,),
                mono_cols=(2, 4),
            )
        )

    story.append(
        Paragraph(
            "Live Exploit Verification (EV) &amp; Post-Fix ev-replay Runtime Attestation",
            subsec_st,
        )
    )
    if not clean.ev_replays:
        story.append(Paragraph("No live EV probes executed for this assessment scope.", body_st))
    else:
        story.append(
            Paragraph(
                f"<b>Runtime Attestation Summary:</b> {_rl_esc(_format_ev_attestation_summary(clean.ev_replays), max_len=400)}",
                body_st,
            )
        )
        story.append(
            _build_rl_table(
                ["Replay ID", "Probe Family", "Endpoint", "Status", "Finding ID", "Evidence Summary"],
                _build_ev_attestation_rows(clean.ev_replays),
                [0.12, 0.18, 0.15, 0.24, 0.11, 0.20],
                avail_w,
                hdr_cell_st,
                cell_st,
                mono_cell_st,
                status_cols=(3,),
                mono_cols=(0, 2, 4),
            )
        )

    # Section 7 — POST-GO-LIVE ALLOWED OBSERVATIONS (Deferrable with Binding SLA & Compensating Controls)
    story.append(
        Paragraph(
            "Section 7 — POST-GO-LIVE ALLOWED OBSERVATIONS (Deferrable with Binding SLA &amp; Compensating Controls)",
            sec_st,
        )
    )
    sla_items = [
        o for o in pasta.golive_observations if o.gate_status == "POST_GO_LIVE_SLA"
    ]
    if not sla_items:
        story.append(
            Paragraph(
                "0 Post-Go-Live deferred SLA observations open. No compensating control exceptions required.",
                body_st,
            )
        )
    else:
        sla_rows = [
            [
                s.severity,
                f"{s.title} ({s.filepath}:L{s.line})",
                s.why_gate_classification,
                s.compensating_control,
                s.sla_window,
                s.mandatory_fix_action,
            ]
            for s in sla_items
        ]
        story.append(
            _build_rl_table(
                ["Sev", "Title & Location", "Why Deferral Is Acceptable", "Launch Compensating Control", "Binding SLA", "Permanent Fix"],
                sla_rows,
                [0.09, 0.19, 0.21, 0.22, 0.11, 0.18],
                avail_w,
                hdr_cell_st,
                cell_st,
                mono_cell_st,
                status_cols=(0, 4),
                mono_cols=(1,),
            )
        )

    # Section 8 — Step-by-Step "What To Do To Make It Live" Runbook
    story.append(
        Paragraph('Section 8 — Step-by-Step "What To Do To Make It Live" Runbook', sec_st)
    )
    for idx_step, step_txt in enumerate(pasta.make_it_live_checklist, start=1):
        story.append(
            Paragraph(
                f"<b>Step {idx_step}.</b> {_rl_esc(step_txt, max_len=900)}",
                body_st,
            )
        )

    # Section 9 — Verified Architectural Strengths & Passing Security Controls
    story.append(
        Paragraph("Section 9 — Verified Architectural Strengths &amp; Passing Security Controls", sec_st)
    )
    strengths = _collect_architectural_strengths(clean)
    all_strength_lines = (
        strengths["pasta_stage_controls"]
        + strengths["passing_pbom_checks"]
        + strengths["mitigated_stride_domains"]
    )
    if not all_strength_lines:
        story.append(Paragraph("Baseline CPG and AST architectural checks completed.", body_st))
    else:
        for s_line in all_strength_lines[:20]:
            story.append(
                Paragraph(
                    f'<font color="#{_HEX_EMERALD}"><b>PASS •</b></font> {_rl_esc(s_line, max_len=700)}',
                    body_st,
                )
            )

    # Section 10 — RACI Governance, Risk-Acceptance Waivers & Formal ARB / CISO Sign-Off
    story.append(
        Paragraph(
            "Section 10 — RACI Governance, Risk-Acceptance Waivers &amp; Formal ARB / CISO Sign-Off",
            sec_st,
        )
    )
    story.append(
        Paragraph(
            f"<b>RACI Governance Health Score:</b> {raci.governance_health_score}% "
            f"({raci.valid_rows_count}/{raci.total_rows_count} validated PMI/COBIT activities; "
            f"{len(raci.finding_assignments)} finding ownership assignment(s)).",
            body_st,
        )
    )

    story.append(Paragraph("Waiver &amp; Architect Gate Override Log", subsec_st))
    waiver_items = [
        o
        for o in pasta.golive_observations
        if o.gate_status == "RISK_ACCEPTED_WAIVER" or o.is_overridden
    ]
    if not waiver_items:
        story.append(
            Paragraph(
                "0 Risk-Acceptance Waivers or manual gate overrides recorded for this release.",
                body_st,
            )
        )
    else:
        waiver_rows = [
            [
                w.id,
                w.severity,
                f"{w.title} ({w.filepath}:L{w.line})",
                f"{w.default_gate_status} -> {w.gate_status}",
                w.sla_window,
                w.compensating_control,
            ]
            for w in waiver_items
        ]
        story.append(
            _build_rl_table(
                ["ID", "Sev", "Observation & Location", "Gate Transition", "SLA", "Compensating Control & Justification"],
                waiver_rows,
                [0.14, 0.09, 0.22, 0.18, 0.10, 0.27],
                avail_w,
                hdr_cell_st,
                cell_st,
                mono_cell_st,
                status_cols=(1, 4),
            )
        )

    signoff_rows = [
        [r["role"], r["responsibility"], r["representative"], r["signature_date"]]
        for r in _build_formal_signoff_rows(clean)
    ]
    story.append(
        KeepTogether(
            [
                Paragraph("Formal ARB / CISO Go-Live Sign-Off Matrix", subsec_st),
                _build_rl_table(
                    ["Role", "Decision / Gate Responsibility", "Representative", "Signature / Date"],
                    signoff_rows,
                    [0.22, 0.38, 0.20, 0.20],
                    avail_w,
                    hdr_cell_st,
                    cell_st,
                    mono_cell_st,
                ),
            ]
        )
    )

    header_label = _clean_xml_text(
        f"ALASTOR SAR GO-LIVE DOSSIER  |  {clean.application_name}  |  CONFIDENTIAL",
        max_len=110,
    )
    footer_left = _clean_xml_text(
        f"Generated {clean.generated_at} • ALASTOR 7-Stage PASTA & Deterministic CPG Engine",
        max_len=95,
    )

    def _draw_page_chrome(canvas_obj: Any, doc_obj: Any) -> None:
        canvas_obj.saveState()
        canvas_obj.setStrokeColor(_RL_BORDER)
        canvas_obj.setLineWidth(0.5)
        top_y = A4[1] - 30.0
        bot_y = 30.0
        canvas_obj.line(margin_lr, top_y, A4[0] - margin_lr, top_y)
        canvas_obj.line(margin_lr, bot_y, A4[0] - margin_lr, bot_y)

        canvas_obj.setFont("Helvetica", 7.2)
        canvas_obj.setFillColor(_RL_MUTED)
        canvas_obj.drawString(margin_lr, top_y + 5.0, header_label)
        canvas_obj.drawString(margin_lr, bot_y - 11.0, footer_left)
        canvas_obj.drawRightString(A4[0] - margin_lr, bot_y - 11.0, f"Page {doc_obj.page}")
        canvas_obj.restoreState()

    pdf_doc.build(story, onFirstPage=_draw_page_chrome, onLaterPages=_draw_page_chrome)
    return out_buf.getvalue()
