"""
Deterministic 7-Stage PASTA (Process for Attack Simulation and Threat Analysis) Engine,
Interactive Multi-Hop Attack Tree Synthesizer, and SAR Go-Live Gate Policy Evaluator.

Implements all 7 PASTA stages grounded in live CPG findings, inter-procedural API operations,
SBOM/PBOM supply-chain telemetry, and TruffleHog-grade Secret Vault verification:
  - Stage I   (PASTA-1): Define Objectives (DO) — Business Preset Auto-Inference & 5 Crown Jewels
  - Stage II  (PASTA-2): Define Technical Scope (DTS) — Stack, File Inventory, SBOM & PBOM Scope
  - Stage III (PASTA-3): Application Decomposition (AD) — Trust Boundaries, Auth & API Operations
  - Stage IV  (PASTA-4): Threat Analysis (TA) — Personas, MITRE ATT&CK / CAPEC & STRIDE Mapping
  - Stage V   (PASTA-5): Weakness & Vulnerability Analysis (WVA) — CWEs, Reachability & BFLs
  - Stage VI  (PASTA-6): Attack Modeling & Simulation (AMS) — Multi-Hop Attack Trees & BFL Shields
  - Stage VII (PASTA-7): Risk & Impact Analysis (RIA) — Inherent/Residual/Projected Risk & Go-Live Gate
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

from compiler.app_tree import AppTreeAnalyzer
from engine.api_operations_engine import ApiOperationsEngine
from models import (
    ApiEndpointOperationDossier,
    ApiOperationsReportResponse,
    AppTreeSummary,
    AttackSurfaceEndpoint,
    DirectoryTreeNode,
    ExploitChainItem,
    Finding,
    GoLiveGateStatus,
    GoLiveObservationItem,
    GoLiveSlaWindow,
    GoLiveVerdict,
    PastaAssessmentResponse,
    PastaAttackTreeEdge,
    PastaAttackTreeNode,
    PastaAttackTreeScenario,
    PastaBusinessPreset,
    PastaCrownJewelItem,
    PastaEvidenceItem,
    PastaGateOverrideRequest,
    PastaProfileUpdateRequest,
    PastaStageItem,
    PipelineSecurityCheck,
    SbomComponentItem,
    StrideThreatItem,
)

logger = logging.getLogger("cpg-sast.pasta-engine")

_PROFILES_FILENAME = "pasta_profiles.json"

_PRESET_MULTIPLIERS: Dict[str, float] = {
    "FINTECH_PAYMENTS": 1.35,
    "HEALTHCARE_PHI": 1.35,
    "AI_SAAS_PUBLIC": 1.20,
    "ENTERPRISE_INTERNAL": 1.00,
}

_PRESET_FRAMEWORKS: Dict[str, List[str]] = {
    "FINTECH_PAYMENTS": [
        "PCI-DSS v4.0",
        "SOX",
        "SOC 2 Type II",
        "OWASP ASVS L2",
    ],
    "HEALTHCARE_PHI": [
        "HIPAA Security Rule",
        "HITECH",
        "SOC 2 Type II",
        "OWASP ASVS L2",
    ],
    "AI_SAAS_PUBLIC": [
        "OWASP Top 10 for LLM",
        "SOC 2 Type II",
        "ISO/IEC 27001",
        "OWASP API Top 10",
    ],
    "ENTERPRISE_INTERNAL": [
        "SOC 2 Type II",
        "ISO/IEC 27001",
        "OWASP ASVS L1/L2",
    ],
}

_PRESET_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "FINTECH_PAYMENTS": (
        "stripe",
        "payment",
        "billing",
        "invoice",
        "ledger",
        "wallet",
        "checkout",
        "bank",
        "card",
    ),
    "HEALTHCARE_PHI": (
        "patient",
        "fhir",
        "hl7",
        "hipaa",
        "clinical",
        "medical",
        "diagnosis",
        "prescription",
        "ehr",
    ),
    "AI_SAAS_PUBLIC": (
        "openai",
        "anthropic",
        "gemini",
        "langchain",
        "llm",
        "prompt",
        "vector",
    ),
}

_CROWN_JEWEL_DEFAULTS: Tuple[Tuple[str, str, str, float, str], ...] = (
    (
        "DATABASE_STORES",
        "Transactional & Graph Database Stores",
        "DATA_PERSISTENCE",
        1.5,
        "Core relational/graph persistence backing customer records, ledgers, and state integrity.",
    ),
    (
        "SECRETS_AND_CREDENTIALS",
        "Cryptographic Keys, API Credentials & Vault Material",
        "CREDENTIAL_VAULT",
        1.8,
        "Signing keys, cloud IAM tokens, and third-party provider credentials governing trust boundaries.",
    ),
    (
        "AI_AND_EXTERNAL_APIS",
        "Frontier AI Providers & Third-Party Egress APIs",
        "EXTERNAL_INTEGRATION",
        1.2,
        "Outbound HTTPS integrations, webhook targets, and LLM inference endpoints.",
    ),
    (
        "HOST_RUNTIME_AND_OS",
        "Underlying Host OS, Filesystem & Container Runtime",
        "COMPUTE_RUNTIME",
        1.7,
        "Server compute processes, container isolation boundaries, and confined workspace filesystems.",
    ),
    (
        "AUTH_AND_SESSION_BOUNDARY",
        "Authentication Guards, JWT Sessions & RBAC Boundaries",
        "IDENTITY_ACCESS",
        1.4,
        "Route authentication dependencies, session verification middleware, and tenant access controls.",
    ),
)

_DEFAULT_AVG_JEWEL_WEIGHT: float = sum(item[3] for item in _CROWN_JEWEL_DEFAULTS) / float(
    len(_CROWN_JEWEL_DEFAULTS)
)

_EXCLUDED_WALK_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        ".next",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        "out",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".alastor_patches",
        ".alastor_vault",
        ".superpowers",
        "uploaded_scans",
        "scratch",
    }
)

_SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "PASS": 5,
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slugify(value: str, max_len: int = 36) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    return (cleaned or "item")[:max_len].rstrip("-") or "item"


def _tokenize_identifier(text: str) -> List[str]:
    if not text:
        return []
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return [tok for tok in re.split(r"[^a-zA-Z0-9]+", camel_split.lower()) if tok]


def _matches_domain_keyword(tokens: List[str], kw: str) -> bool:
    for tok in tokens:
        if tok == kw or tok == f"{kw}s":
            return True
        if len(kw) >= 5 and tok.startswith(kw):
            return True
    return False


def _score_to_risk_level(score: int) -> Literal["CRITICAL", "HIGH", "MODERATE", "LOW"]:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MODERATE"
    return "LOW"


def _sensitivity_from_weight(weight: float) -> str:
    if weight >= 1.65:
        return "CRITICAL"
    if weight >= 1.30:
        return "HIGH"
    if weight >= 1.05:
        return "ELEVATED"
    return "STANDARD"


def _normalize_severity(raw_sev: str) -> Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    up = (raw_sev or "MEDIUM").upper()
    if up == "CRITICAL":
        return "CRITICAL"
    if up == "HIGH":
        return "HIGH"
    if up == "MEDIUM":
        return "MEDIUM"
    return "LOW"


def _redact_sensitive_text(text: str, forbidden_values: Set[str]) -> str:
    safe_txt = (text or "").replace("\x00", "").strip()
    if not safe_txt or not forbidden_values:
        return safe_txt
    for raw_val in sorted(forbidden_values, key=len, reverse=True):
        if raw_val and raw_val in safe_txt:
            safe_txt = safe_txt.replace(raw_val, "[REDACTED]")
    return safe_txt


def _finding_location(f: Finding) -> Tuple[str, int, str]:
    if f.best_fix_location and f.best_fix_location.filepath:
        return (
            f.best_fix_location.filepath.replace("\\", "/"),
            max(1, int(f.best_fix_location.line or 1)),
            (f.best_fix_location.code_snippet or "").strip(),
        )
    if f.path_nodes:
        last_n = f.path_nodes[-1]
        if isinstance(last_n, dict):
            fp = str(last_n.get("filepath") or "workspace").replace("\\", "/")
            ln = max(1, int(last_n.get("start_line") or 1))
            snip = str(last_n.get("code") or last_n.get("name") or "").strip()
            return fp, ln, snip
    return "workspace", 1, ""


def _classify_threat_taxonomy(f: Finding) -> Tuple[str, str, str, str, str]:
    """
    Maps a Finding onto `(mitre_capec, stride_letter, stride_label, crown_jewel_id, attacker_persona)`.
    """
    cwe = (f.cwe_id or "").upper()
    rule_up = (f.rule_id or "").upper()
    is_cred = bool(f.is_secret_finding or cwe == "CWE-798")

    if is_cred:
        return (
            "CAPEC-560 / T1552",
            "I",
            "STRIDE-I (Information Disclosure & Spoofing)",
            "SECRETS_AND_CREDENTIALS",
            "Credential Harvesting & Cloud Takeover Actor",
        )
    if cwe in ("CWE-78", "CWE-94"):
        return (
            "CAPEC-88 / T1190",
            "E",
            "STRIDE-E (Elevation of Privilege)",
            "HOST_RUNTIME_AND_OS",
            "External RCE / Public-Facing Exploit Adversary",
        )
    if cwe == "CWE-89" or "SQLI" in rule_up or (("SQL" in rule_up) and ("INJECTION" in rule_up)):
        return (
            "CAPEC-66 / T1190",
            "T",
            "STRIDE-T (Tampering & Data Exfiltration)",
            "DATABASE_STORES",
            "Database Exfiltration & Ledger Manipulation Actor",
        )
    if cwe in ("CWE-79", "CWE-601") or "XSS" in rule_up:
        return (
            "CAPEC-63 / T1189",
            "S",
            "STRIDE-S (Spoofing & Session Hijacking)",
            "AUTH_AND_SESSION_BOUNDARY",
            "Client-Side Session Hijacking Adversary",
        )
    if cwe == "CWE-22" or "TRAVERSAL" in rule_up:
        return (
            "CAPEC-126 / T1083",
            "I",
            "STRIDE-I (Information Disclosure)",
            "HOST_RUNTIME_AND_OS",
            "Filesystem Traversal & Config Extraction Actor",
        )
    if cwe == "CWE-918" or "SSRF" in rule_up:
        return (
            "CAPEC-194 / T1567",
            "E",
            "STRIDE-E (Server-Side Egress & Metadata Pivot)",
            "AI_AND_EXTERNAL_APIS",
            "Cloud Metadata & Internal Network Pivot Actor",
        )
    if f.scan_engine == "SCA" or cwe == "CWE-1395" or "SCA" in rule_up:
        return (
            "CAPEC-438 / T1195",
            "T",
            "STRIDE-T (Supply-Chain Tampering)",
            "HOST_RUNTIME_AND_OS",
            "Software Supply-Chain Compromiser",
        )
    if cwe == "CWE-835" or "LOOP" in rule_up:
        return (
            "CAPEC-125 / T1499",
            "D",
            "STRIDE-D (Denial of Service)",
            "HOST_RUNTIME_AND_OS",
            "Resource Exhaustion & Service Disruption Actor",
        )
    if cwe == "CWE-117" or "LOG" in rule_up:
        return (
            "CAPEC-93 / T1070",
            "R",
            "STRIDE-R (Repudiation & Audit Forging)",
            "AUTH_AND_SESSION_BOUNDARY",
            "Audit Trail Evasion Actor",
        )
    if f.scan_engine == "IaC" or cwe in ("CWE-250", "CWE-611", "CWE-295"):
        return (
            "CAPEC-88 / T1190",
            "E",
            "STRIDE-E (Runtime Misconfiguration & Privilege Escalation)",
            "HOST_RUNTIME_AND_OS",
            "Container & Runtime Infrastructure Adversary",
        )
    if cwe in ("CWE-502", "CWE-327", "CWE-330"):
        return (
            "CAPEC-88 / T1190",
            "T",
            "STRIDE-T (Cryptographic / Deserialization Integrity)",
            "AUTH_AND_SESSION_BOUNDARY",
            "Token Forgery & Payload Tampering Actor",
        )
    if ("TAINT" in rule_up) or (("INJECTION" in rule_up) and ("SQL" not in rule_up) and ("LOG" not in rule_up)):
        return (
            "CAPEC-88 / T1190",
            "E",
            "STRIDE-E (Elevation of Privilege)",
            "HOST_RUNTIME_AND_OS",
            "External RCE / Public-Facing Exploit Adversary",
        )
    return (
        "CAPEC-88 / T1190",
        "T",
        "STRIDE-T (Application Integrity)",
        "HOST_RUNTIME_AND_OS",
        "External Opportunistic Attacker",
    )


def _read_confined_workspace_file(root_real: str, candidate_path: str) -> str:
    try:
        cand_real = os.path.realpath(candidate_path)
        if os.path.commonpath([root_real, cand_real]) != root_real:
            return ""
        with open(cand_real, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(256 * 1024)
    except OSError:
        return ""


class PastaThreatEngine:
    """
    Deterministic 7-Stage PASTA Threat Modeling, Multi-Hop Attack Tree,
    and SAR Go-Live Gate Engine backed by `.alastor_vault/pasta_profiles.json`.
    """

    def __init__(self, vault_dir: Optional[str] = None):
        if vault_dir:
            self.vault_dir = os.path.realpath(vault_dir)
        else:
            self.vault_dir = os.path.realpath(
                os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "..",
                    ".alastor_vault",
                )
            )
        self._lock = threading.RLock()

    def _project_key(self, target_dir: str) -> str:
        raw_dir = (target_dir or ".").strip() or "."
        return os.path.normcase(os.path.realpath(raw_dir)).replace("\\", "/")

    def _resolve_profiles_path(self) -> Tuple[str, str]:
        vault_real = os.path.realpath(self.vault_dir)
        os.makedirs(vault_real, mode=0o700, exist_ok=True)
        try:
            os.chmod(vault_real, 0o700)
        except OSError:
            pass
        cfg_real = os.path.realpath(os.path.join(vault_real, _PROFILES_FILENAME))
        if os.path.commonpath([vault_real, cfg_real]) != vault_real:
            raise ValueError("PASTA vault profile path confinement violation.")
        return vault_real, cfg_real

    def _load_all_profiles_locked(self) -> Dict[str, Dict[str, Any]]:
        try:
            vault_real, cfg_real = self._resolve_profiles_path()
            if os.path.commonpath([vault_real, cfg_real]) != vault_real:
                return {}
            if not os.path.isfile(cfg_real):
                return {}
            with open(cfg_real, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                return {
                    str(k): dict(v)
                    for k, v in loaded.items()
                    if isinstance(v, dict)
                }
        except Exception as exc:
            safe_msg = str(exc).replace("\r", " ").replace("\n", " ")[:160]
            logger.warning("Unable to read PASTA vault profiles: %s", safe_msg)
        return {}

    def _save_all_profiles_locked(self, profiles_map: Dict[str, Dict[str, Any]]) -> None:
        vault_real, cfg_real = self._resolve_profiles_path()
        tmp_name = f"{_PROFILES_FILENAME}.tmp.{os.getpid()}.{threading.get_ident()}"
        tmp_real = os.path.realpath(os.path.join(vault_real, tmp_name))
        if os.path.commonpath([vault_real, tmp_real]) != vault_real:
            raise ValueError("PASTA vault temp path confinement violation.")
        serialized = json.dumps(profiles_map, indent=2, sort_keys=True)
        with open(tmp_real, "w", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp_real, cfg_real)
        try:
            os.chmod(cfg_real, 0o600)
        except OSError:
            pass

    def get_profile_state(self, target_dir: str) -> Dict[str, Any]:
        key = self._project_key(target_dir)
        with self._lock:
            all_profiles = self._load_all_profiles_locked()
            entry = dict(all_profiles.get(key) or {})
            return {
                "project_key": key,
                "business_preset": entry.get("business_preset", "AUTO_INFERRED"),
                "crown_jewel_weights": dict(entry.get("crown_jewel_weights") or {}),
                "gate_overrides": dict(entry.get("gate_overrides") or {}),
                "updated_at": entry.get("updated_at"),
            }

    def update_profile(self, target_dir: str, req: PastaProfileUpdateRequest) -> Dict[str, Any]:
        eff_dir = (target_dir or req.project_path or ".").strip()
        key = self._project_key(eff_dir)
        now_iso = _utc_now_iso()
        with self._lock:
            all_profiles = self._load_all_profiles_locked()
            existing = dict(all_profiles.get(key) or {})
            preserved_overrides = dict(existing.get("gate_overrides") or {})

            if req.reset_defaults:
                updated_entry: Dict[str, Any] = {
                    "business_preset": "AUTO_INFERRED",
                    "crown_jewel_weights": {},
                    "gate_overrides": preserved_overrides,
                    "updated_at": now_iso,
                }
            else:
                merged_weights: Dict[str, float] = dict(existing.get("crown_jewel_weights") or {})
                for cj_id, raw_w in (req.crown_jewel_weights or {}).items():
                    clamped_w = round(max(0.8, min(2.0, float(raw_w))), 2)
                    merged_weights[str(cj_id)] = clamped_w
                updated_entry = {
                    "business_preset": req.business_preset,
                    "crown_jewel_weights": merged_weights,
                    "gate_overrides": preserved_overrides,
                    "updated_at": now_iso,
                }

            all_profiles[key] = updated_entry
            self._save_all_profiles_locked(all_profiles)
            return {
                "project_key": key,
                **updated_entry,
            }

    def update_gate_override(self, target_dir: str, req: PastaGateOverrideRequest) -> Dict[str, Any]:
        eff_dir = (target_dir or req.project_path or ".").strip()
        key = self._project_key(eff_dir)
        now_iso = _utc_now_iso()
        obs_id = (req.observation_id or "").strip()
        with self._lock:
            all_profiles = self._load_all_profiles_locked()
            existing = dict(all_profiles.get(key) or {})
            gate_overrides: Dict[str, Any] = dict(existing.get("gate_overrides") or {})

            if req.reset_override:
                gate_overrides.pop(obs_id, None)
            elif obs_id:
                gate_overrides[obs_id] = {
                    "gate_status": req.gate_status,
                    "sla_window": req.sla_window,
                    "compensating_control_note": (req.compensating_control_note or "").strip(),
                    "updated_at": now_iso,
                }

            updated_entry: Dict[str, Any] = {
                "business_preset": existing.get("business_preset", "AUTO_INFERRED"),
                "crown_jewel_weights": dict(existing.get("crown_jewel_weights") or {}),
                "gate_overrides": gate_overrides,
                "updated_at": now_iso,
            }
            all_profiles[key] = updated_entry
            self._save_all_profiles_locked(all_profiles)
            return {
                "project_key": key,
                **updated_entry,
            }

    def _discover_basic_sbom(self, target_dir: str) -> List[SbomComponentItem]:
        if not target_dir or not os.path.exists(target_dir):
            return []
        root_dir = os.path.dirname(target_dir) if os.path.isfile(target_dir) else target_dir
        root_real = os.path.realpath(root_dir)
        items: List[SbomComponentItem] = []
        seen_keys: Set[str] = set()

        manifest_files: List[Tuple[str, str]] = []
        for cur_root, dirs, files in os.walk(root_real):
            dirs[:] = [d for d in dirs if d not in _EXCLUDED_WALK_DIRS]
            for fn in sorted(files):
                if fn in ("requirements.txt", "package.json"):
                    full_p = os.path.join(cur_root, fn)
                    rel_p = os.path.relpath(full_p, root_real).replace("\\", "/")
                    manifest_files.append((rel_p, full_p))
            if len(manifest_files) >= 16:
                break

        for rel_p, full_p in manifest_files:
            content = _read_confined_workspace_file(root_real, full_p)
            if not content:
                continue
            base = os.path.basename(rel_p)
            if base == "requirements.txt":
                for idx, raw_ln in enumerate(content.splitlines(), start=1):
                    clean = raw_ln.strip()
                    if not clean or clean.startswith("#") or clean.startswith("-"):
                        continue
                    clean_no_comment = clean.split("#", 1)[0].strip()
                    is_pinned = "==" in clean_no_comment
                    parts = re.split(r"[=<>~!]+", clean_no_comment, maxsplit=1)
                    pkg_name = parts[0].split("[", 1)[0].strip()
                    if not pkg_name:
                        continue
                    pkg_ver = parts[1].strip() if len(parts) > 1 else "unpinned"
                    comp_key = f"pypi:{pkg_name.lower()}"
                    if comp_key in seen_keys:
                        continue
                    seen_keys.add(comp_key)
                    items.append(
                        SbomComponentItem(
                            id=f"sbom-{len(items) + 1}",
                            name=pkg_name,
                            version=pkg_ver,
                            ecosystem="PyPI (Python)",
                            manifest_path=rel_p,
                            line_number=idx,
                            is_pinned=is_pinned,
                            risk_status="VERIFIED_PINNED" if is_pinned else "FLOATING_VERSION",
                            plain_english_role=f"Python dependency declared in {rel_p}.",
                        )
                    )
            elif base == "package.json":
                try:
                    pkg_json = json.loads(content)
                except Exception:
                    continue
                if not isinstance(pkg_json, dict):
                    continue
                merged_deps: Dict[str, Any] = {}
                if isinstance(pkg_json.get("dependencies"), dict):
                    merged_deps.update(pkg_json["dependencies"])
                if isinstance(pkg_json.get("devDependencies"), dict):
                    merged_deps.update(pkg_json["devDependencies"])
                pkg_lines = content.splitlines()
                for pkg_name, ver_spec in list(merged_deps.items())[:40]:
                    ver_str = str(ver_spec).strip()
                    is_pinned = bool(ver_str) and not ver_str.startswith(("^", "~", "*", ">", "<", "latest"))
                    comp_key = f"npm:{pkg_name.lower()}"
                    if comp_key in seen_keys:
                        continue
                    seen_keys.add(comp_key)
                    dep_ln = 1
                    for ln_i, ln_txt in enumerate(pkg_lines, start=1):
                        if f'"{pkg_name}"' in ln_txt:
                            dep_ln = ln_i
                            break
                    items.append(
                        SbomComponentItem(
                            id=f"sbom-{len(items) + 1}",
                            name=pkg_name,
                            version=ver_str,
                            ecosystem="npm (JavaScript/TS)",
                            manifest_path=rel_p,
                            line_number=dep_ln,
                            is_pinned=is_pinned,
                            risk_status="VERIFIED_PINNED" if is_pinned else "FLOATING_VERSION",
                            plain_english_role=f"npm dependency declared in {rel_p}.",
                        )
                    )
        return items

    def _infer_business_preset(
        self,
        target_dir: str,
        app_tree: AppTreeSummary,
        api_ops: ApiOperationsReportResponse,
        sbom_items: List[SbomComponentItem],
        endpoints: List[AttackSurfaceEndpoint],
        active_findings: List[Finding],
    ) -> Tuple[PastaBusinessPreset, str]:
        preset_hits: Dict[str, List[str]] = {
            "FINTECH_PAYMENTS": [],
            "HEALTHCARE_PHI": [],
            "AI_SAAS_PUBLIC": [],
        }

        def _record_signal(preset_name: str, evidence_label: str) -> None:
            bucket = preset_hits[preset_name]
            if evidence_label not in bucket and len(bucket) < 6:
                bucket.append(evidence_label)

        def _inspect_text(raw_text: str, source_tag: str) -> None:
            toks = _tokenize_identifier(raw_text)
            if not toks:
                return
            for preset_name, kw_tuple in _PRESET_KEYWORDS.items():
                for kw in kw_tuple:
                    if _matches_domain_keyword(toks, kw):
                        _record_signal(preset_name, f"{source_tag} '{raw_text}' ({kw})")
                        break

        _inspect_text(os.path.basename(os.path.abspath(target_dir or ".")), "workspace")

        for fi in app_tree.flat_files:
            _inspect_text(fi.filepath, "file")
            for el in fi.elements[:20]:
                _inspect_text(el.name, "symbol")

        for comp in sbom_items:
            _inspect_text(comp.name, "dependency")

        for ep in api_ops.endpoints:
            _inspect_text(ep.route_path, "route")
            _inspect_text(ep.handler_name, "handler")
            if "EXTERNAL_HTTP_OR_AI" in ep.operation_categories:
                for op in ep.operations:
                    if op.category == "EXTERNAL_HTTP_OR_AI":
                        op_toks = _tokenize_identifier(f"{op.operation_verb} {op.target_resource} {op.function_name}")
                        if any(_matches_domain_keyword(op_toks, kw) for kw in _PRESET_KEYWORDS["FINTECH_PAYMENTS"]):
                            _record_signal("FINTECH_PAYMENTS", f"payment egress '{op.target_resource}'")
                        else:
                            _record_signal("AI_SAAS_PUBLIC", f"external/AI operation '{op.operation_verb} -> {op.target_resource}'")

        for surf_ep in endpoints:
            _inspect_text(surf_ep.route_path, "endpoint")
            _inspect_text(surf_ep.handler_name, "handler")

        for f in active_findings:
            fp, _, _ = _finding_location(f)
            _inspect_text(fp, "finding-path")
            det_id = (f.secret_detector_id or "").lower()
            if det_id == "stripe_key":
                _record_signal("FINTECH_PAYMENTS", "detector 'stripe_key'")
            elif det_id in ("openai_key", "anthropic_key", "gemini_key", "huggingface_token"):
                _record_signal("AI_SAAS_PUBLIC", f"detector '{det_id}'")

        priority_order: Tuple[PastaBusinessPreset, ...] = (
            "FINTECH_PAYMENTS",
            "HEALTHCARE_PHI",
            "AI_SAAS_PUBLIC",
        )
        best_preset: PastaBusinessPreset = "ENTERPRISE_INTERNAL"
        best_score = 0
        for cand in priority_order:
            cnt = len(preset_hits[cand])
            if cnt > best_score:
                best_score = cnt
                best_preset = cand

        if best_score > 0:
            mult = _PRESET_MULTIPLIERS[best_preset]
            signals_str = ", ".join(preset_hits[best_preset][:4])
            return (
                best_preset,
                f"Auto-inferred {best_preset} ({mult:.2f}x business criticality) from codebase telemetry: {signals_str}.",
            )
        return (
            "ENTERPRISE_INTERNAL",
            "Auto-inferred ENTERPRISE_INTERNAL (1.00x baseline) — no specialized PCI/PHI/LLM domain markers detected.",
        )

    def _build_crown_jewels(
        self,
        saved_weights: Dict[str, float],
        app_tree: AppTreeSummary,
        api_ops: ApiOperationsReportResponse,
        sbom_items: List[SbomComponentItem],
        active_findings: List[Finding],
    ) -> List[PastaCrownJewelItem]:
        locs_by_jewel: Dict[str, List[str]] = {item[0]: [] for item in _CROWN_JEWEL_DEFAULTS}

        def _add_loc(jewel_id: str, loc: str) -> None:
            clean_loc = (loc or "").strip()
            if clean_loc and clean_loc not in locs_by_jewel[jewel_id] and len(locs_by_jewel[jewel_id]) < 8:
                locs_by_jewel[jewel_id].append(clean_loc)

        for fi in app_tree.flat_files:
            low_fp = fi.filepath.lower()
            cat_up = (fi.category or "").upper()
            if any(k in low_fp for k in ("db", "database", "repo", "ledger", "model", "migration", "neo4j", "sql")):
                _add_loc("DATABASE_STORES", fi.filepath)
            if any(k in low_fp for k in (".env", "vault", "credential", "token", "crypto", "key")):
                _add_loc("SECRETS_AND_CREDENTIALS", fi.filepath)
            if any(k in low_fp for k in ("ai", "llm", "client", "webhook", "gateway", "openai", "gemini")):
                _add_loc("AI_AND_EXTERNAL_APIS", fi.filepath)
            if "DOCKER" in cat_up or "INFRA" in cat_up or any(
                k in low_fp for k in ("dockerfile", "docker-compose", "worker", "compiler", "runtime")
            ):
                _add_loc("HOST_RUNTIME_AND_OS", fi.filepath)
            if any(k in low_fp for k in ("auth", "session", "jwt", "rbac", "middleware", "guard", "permission")):
                _add_loc("AUTH_AND_SESSION_BOUNDARY", fi.filepath)

        for ep in api_ops.endpoints:
            ep_loc = f"{ep.method} {ep.route_path} ({ep.filepath}:L{ep.start_line})"
            if ep.auth_status == "AUTHENTICATED" or "AUTH_GUARD" in ep.operation_categories:
                _add_loc("AUTH_AND_SESSION_BOUNDARY", ep_loc)
            for op in ep.operations:
                op_loc = f"{op.filepath}:L{op.line_number} ({op.operation_verb})"
                if op.category in ("DATABASE_READ", "DATABASE_WRITE"):
                    _add_loc("DATABASE_STORES", op_loc)
                elif op.category == "SECRET_OR_CRYPTO":
                    _add_loc("SECRETS_AND_CREDENTIALS", op_loc)
                elif op.category == "EXTERNAL_HTTP_OR_AI":
                    _add_loc("AI_AND_EXTERNAL_APIS", op_loc)
                elif op.category in ("OS_COMMAND_EXEC", "FILESYSTEM_IO"):
                    _add_loc("HOST_RUNTIME_AND_OS", op_loc)

        for comp in sbom_items:
            low_name = comp.name.lower()
            if low_name in ("sqlalchemy", "psycopg2", "pymongo", "redis", "neo4j", "prisma", "typeorm"):
                _add_loc("DATABASE_STORES", f"{comp.manifest_path} ({comp.name})")
            elif low_name in ("openai", "anthropic", "langchain", "requests", "httpx", "axios", "stripe"):
                _add_loc("AI_AND_EXTERNAL_APIS", f"{comp.manifest_path} ({comp.name})")
            elif low_name in ("pyjwt", "python-jose", "bcrypt", "passlib", "cryptography"):
                _add_loc("AUTH_AND_SESSION_BOUNDARY", f"{comp.manifest_path} ({comp.name})")

        for f in active_findings:
            _, _, _, jewel_id, _ = _classify_threat_taxonomy(f)
            fp, ln, _ = _finding_location(f)
            _add_loc(jewel_id, f"{fp}:L{ln}")

        jewels: List[PastaCrownJewelItem] = []
        for j_id, j_name, j_cat, default_w, base_rationale in _CROWN_JEWEL_DEFAULTS:
            eff_w = round(max(0.8, min(2.0, float(saved_weights.get(j_id, default_w)))), 2)
            locs = locs_by_jewel[j_id]
            jewels.append(
                PastaCrownJewelItem(
                    id=j_id,
                    name=j_name,
                    category=j_cat,
                    asset_count=len(locs),
                    weight_multiplier=eff_w,
                    sensitivity_label=_sensitivity_from_weight(eff_w),
                    rationale=base_rationale,
                    sample_locations=locs[:5],
                )
            )
        return jewels

    def _classify_default_finding_gate(
        self,
        f: Finding,
    ) -> Tuple[GoLiveGateStatus, GoLiveSlaWindow, str, str, int]:
        """
        Applies the deterministic Go-Live Gate policy to an active Finding.
        Returns `(gate_status, sla_window, why_classification, compensating_control, risk_reduction_pts)`.
        """
        sev = _normalize_severity(f.severity)
        cwe = (f.cwe_id or "").upper()
        is_cred = bool(f.is_secret_finding or cwe == "CWE-798")
        val_status = f.secret_validation_status or ""
        cred_origin = f.secret_source or "WORKING_TREE"
        reach = f.reachability_status or "REACHABLE"

        # 1. Verified active live credentials always block Go-Live
        if val_status == "VERIFIED_ACTIVE":
            return (
                "MANDATORY_PRE_GO_LIVE",
                "PRE_LAUNCH",
                "Live provider verification confirmed this credential is active (`VERIFIED_ACTIVE`); immediate rotation is mandatory prior to Go-Live.",
                "Rotate/revoke active token immediately in provider IAM console and inject replacement exclusively via runtime secret manager.",
                28,
            )

        # 2. Test / placeholder credentials -> 90_DAYS backlog hygiene
        if is_cred and val_status == "TEST_OR_PLACEHOLDER":
            return (
                "POST_GO_LIVE_SLA",
                "90_DAYS",
                "Credential matches non-production sandbox/placeholder signature (`TEST_OR_PLACEHOLDER`); tracked under 90-day hygiene SLA.",
                "Track in sprint hardening backlog with CI lockfile/header monitoring within 90 days.",
                3,
            )

        # 3. Critical severity findings always block Go-Live
        if sev == "CRITICAL":
            return (
                "MANDATORY_PRE_GO_LIVE",
                "PRE_LAUNCH",
                "Critical severity weakness (`CRITICAL`) poses direct Crown Jewel compromise risk and blocks production release.",
                "No post-launch deferral permitted without CISO waiver; apply Best Fixed Location (BFL) patch before release.",
                25,
            )

        # 4. Git-history non-active credentials -> 14_DAYS SLA
        if is_cred and cred_origin == "GIT_HISTORY":
            return (
                "POST_GO_LIVE_SLA",
                "14_DAYS",
                "Historical `.git` commit credential is not present in the active working tree and not verified live; governed by 14-day history purge SLA.",
                "Verify token revocation in provider console, monitor audit logs, and purge commit history via git filter-repo within 14 days.",
                8,
            )

        # 5. Working-tree HIGH secrets (not revoked/placeholder) -> Mandatory Pre-Go-Live
        if (
            is_cred
            and sev == "HIGH"
            and cred_origin != "GIT_HISTORY"
            and val_status not in ("REVOKED_OR_INVALID", "TEST_OR_PLACEHOLDER")
        ):
            return (
                "MANDATORY_PRE_GO_LIVE",
                "PRE_LAUNCH",
                "High-severity working-tree credential (`WORKING_TREE`, structurally valid/unrevoked) blocks production deployment until externalized.",
                "Externalize credential to vault/environment configuration and rotate key prior to launch.",
                20,
            )

        # 6. Reachable HIGH non-secret findings -> Mandatory Pre-Go-Live
        if not is_cred and sev == "HIGH" and reach == "REACHABLE":
            return (
                "MANDATORY_PRE_GO_LIVE",
                "PRE_LAUNCH",
                "High-severity weakness sits on a `REACHABLE` runtime execution path and must be remediated pre-launch.",
                "Apply Best Fixed Location (BFL) sanitization/parameterization prior to production cutover.",
                18,
            )

        # 7. Dormant / conditionally-reachable HIGH findings -> 7_DAYS SLA
        if not is_cred and sev == "HIGH" and reach != "REACHABLE":
            return (
                "POST_GO_LIVE_SLA",
                "7_DAYS",
                f"High-severity weakness is `{reach}` (not on an active entrypoint call chain); eligible for 7-day post-launch SLA with compensating controls.",
                "Enforce WAF virtual patch, restrict internal route ACL, and keep feature path disabled until patched within 7 days.",
                9,
            )

        # 8. MEDIUM findings (or revoked working-tree credentials) -> 30_DAYS SLA
        if sev in ("MEDIUM", "HIGH"):
            return (
                "POST_GO_LIVE_SLA",
                "30_DAYS",
                "Medium-risk exposure requires defense-in-depth runtime monitoring and remediation within the 30-day sprint SLA.",
                "Apply API gateway rate-limiting, WAF inspection, and runtime anomaly alerting; patch within 30 days.",
                6,
            )

        # 9. LOW findings -> 90_DAYS SLA
        return (
            "POST_GO_LIVE_SLA",
            "90_DAYS",
            "Low-severity hardening observation scheduled for standard 90-day engineering hygiene window.",
            "Track in sprint hardening backlog with CI lockfile/header monitoring within 90 days.",
            3,
        )

    def _build_golive_observations(
        self,
        active_findings: List[Finding],
        api_ops: ApiOperationsReportResponse,
        endpoints: List[AttackSurfaceEndpoint],
        pipeline_checks: List[PipelineSecurityCheck],
        gate_overrides: Dict[str, Any],
        forbidden_raw_values: Set[str],
    ) -> List[GoLiveObservationItem]:
        observations: List[GoLiveObservationItem] = []
        used_ids: Set[str] = set()
        covered_files: Set[str] = set()
        covered_finding_ids: Set[str] = {f.id for f in active_findings}

        has_active_cred = any(f.is_secret_finding or (f.cwe_id or "").upper() == "CWE-798" for f in active_findings)
        has_active_sca = any(f.scan_engine == "SCA" or (f.cwe_id or "").upper() == "CWE-1395" for f in active_findings)
        has_active_iac = any(f.scan_engine == "IaC" for f in active_findings)
        has_active_reachable = any(f.reachability_status == "REACHABLE" or f.severity == "CRITICAL" for f in active_findings)

        def _unique_obs_id(prefix_kind: str, raw_slug: str) -> str:
            base_id = f"obs-{prefix_kind}-{_slugify(raw_slug)}"
            cand = base_id
            seq = 2
            while cand in used_ids:
                cand = f"{base_id}-{seq}"
                seq += 1
            used_ids.add(cand)
            return cand

        sorted_findings = sorted(
            active_findings,
            key=lambda item: (
                _SEVERITY_ORDER.get(item.severity, 9),
                0 if item.reachability_status == "REACHABLE" else 1,
                item.id,
            ),
        )

        # 1. Observations from active Findings
        for f in sorted_findings:
            fp, ln, _ = _finding_location(f)
            covered_files.add(fp.lower())
            cwe_up = (f.cwe_id or "").upper()
            is_cred = bool(f.is_secret_finding or cwe_up == "CWE-798")

            if is_cred:
                src_type: Literal["SAST", "SCA", "IAC", "SECRET_VAULT", "API_EXPOSURE", "PBOM", "STRIDE_GAP"] = "SECRET_VAULT"
                kind_tok = "secret"
                stage_num = 5
            elif f.scan_engine == "SCA":
                src_type = "SCA"
                kind_tok = "sca"
                stage_num = 2
            elif f.scan_engine == "IaC":
                src_type = "IAC"
                kind_tok = "iac"
                stage_num = 2
            else:
                src_type = "SAST"
                kind_tok = "sast"
                stage_num = 5

            obs_id = _unique_obs_id(kind_tok, f.id or f"{fp}-{ln}")
            mitre_capec, stride_let, _, _, _ = _classify_threat_taxonomy(f)
            def_gate, def_sla, why_gate, comp_ctrl, red_pts = self._classify_default_finding_gate(f)

            eff_sev = _normalize_severity("CRITICAL" if f.secret_validation_status == "VERIFIED_ACTIVE" else f.severity)
            bfl_fix = (
                f.best_fix_location.recommended_fix
                if f.best_fix_location and f.best_fix_location.recommended_fix
                else (f.remediation or f"Apply security control at {fp}:L{ln}.")
            )
            why_issue_txt = _redact_sensitive_text(
                f.plain_english_summary or f.description or f"{f.title} detected at {fp}:L{ln}.",
                forbidden_raw_values,
            )

            observations.append(
                GoLiveObservationItem(
                    id=obs_id,
                    source_type=src_type,
                    title=_redact_sensitive_text(f.title, forbidden_raw_values),
                    severity=eff_sev,
                    cwe_or_standard=f"{f.cwe_id or f.rule_id} • {mitre_capec}",
                    pasta_stage=stage_num,
                    stride_letter=stride_let,
                    filepath=fp,
                    line=ln,
                    reachability_status=f.reachability_status or "REACHABLE",
                    gate_status=def_gate,
                    default_gate_status=def_gate,
                    is_overridden=False,
                    sla_window=def_sla,
                    why_issue=why_issue_txt[:420],
                    why_gate_classification=why_gate,
                    mandatory_fix_action=_redact_sensitive_text(bfl_fix, forbidden_raw_values)[:320],
                    compensating_control=comp_ctrl,
                    effort_estimate=f.effort_estimate or "~25 mins",
                    raci_owner=f.raci_responsible or (
                        "DevOps / Infra Lead (DEVOPS_LEAD)"
                        if src_type in ("SCA", "IAC", "SECRET_VAULT")
                        else "Lead Developer (TECH_LEAD)"
                    ),
                    risk_reduction_points=red_pts,
                    linked_finding_id=f.id,
                )
            )

        # 2. Unauthenticated mutating / OS_COMMAND_EXEC API endpoints not already covered by a finding on same route/file
        seen_routes: Set[str] = set()
        for ep in api_ops.endpoints:
            route_key = f"{ep.method.upper()}:{ep.route_path}"
            seen_routes.add(route_key)
            has_exec = "OS_COMMAND_EXEC" in ep.operation_categories
            if ep.auth_status != "UNAUTHENTICATED" or not (ep.is_mutating or has_exec):
                continue
            if any(fid in covered_finding_ids for fid in ep.linked_finding_ids):
                continue
            if ep.filepath.replace("\\", "/").lower() in covered_files:
                continue

            obs_id = _unique_obs_id("api", f"{ep.method}-{ep.route_path}-{ep.handler_name}")
            if has_exec:
                def_gate = "MANDATORY_PRE_GO_LIVE"
                def_sla = "PRE_LAUNCH"
                ep_sev: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "HIGH"
                why_gate = "Unauthenticated endpoint invokes an `OS_COMMAND_EXEC` process sink (`CWE-306` / `CAPEC-88`) and blocks Go-Live until guarded."
                comp_ctrl = "Block external ingress to this route at API Gateway / reverse proxy until authentication and strict command allowlisting are enforced."
                red_pts = 20
                stride_let = "E"
            else:
                def_gate = "POST_GO_LIVE_SLA"
                def_sla = "30_DAYS"
                ep_sev = "MEDIUM"
                why_gate = "Unauthenticated state-mutating route (`POST`/`PUT`/`DELETE`/`PATCH`) requires authentication guard hardening within 30 days."
                comp_ctrl = "Apply API gateway rate-limiting, WAF inspection, and runtime anomaly alerting; patch within 30 days."
                red_pts = 7
                stride_let = "S"

            observations.append(
                GoLiveObservationItem(
                    id=obs_id,
                    source_type="API_EXPOSURE",
                    title=f"Unauthenticated {'Command-Exec' if has_exec else 'Mutating'} Endpoint: {ep.method} {ep.route_path} ({ep.handler_name})",
                    severity=ep_sev,
                    cwe_or_standard="CWE-306 • OWASP API2:2023",
                    pasta_stage=3,
                    stride_letter=stride_let,
                    filepath=ep.filepath,
                    line=max(1, ep.start_line),
                    reachability_status="REACHABLE",
                    gate_status=def_gate,
                    default_gate_status=def_gate,
                    is_overridden=False,
                    sla_window=def_sla,
                    why_issue=f"Route `{ep.method} {ep.route_path}` in `{ep.filepath}:L{ep.start_line}` executes without authentication middleware.",
                    why_gate_classification=why_gate,
                    mandatory_fix_action=f"Attach JWT/session authentication dependency (`Depends(...)` / auth guard) to `{ep.handler_name}` at `{ep.filepath}:L{ep.start_line}`.",
                    compensating_control=comp_ctrl,
                    effort_estimate="~20 mins",
                    raci_owner="Lead Developer (TECH_LEAD)",
                    risk_reduction_points=red_pts,
                    linked_finding_id=None,
                )
            )

        for surf_ep in endpoints:
            route_key = f"{surf_ep.method.upper()}:{surf_ep.route_path}"
            if route_key in seen_routes:
                continue
            is_unauth = "unauthenticated" in (surf_ep.auth_posture or "").lower()
            is_mut = surf_ep.method.upper() in ("POST", "PUT", "DELETE", "PATCH")
            if not (is_unauth and is_mut):
                continue
            if surf_ep.filepath.replace("\\", "/").lower() in covered_files or surf_ep.linked_findings_count > 0:
                continue
            obs_id = _unique_obs_id("api", f"{surf_ep.method}-{surf_ep.route_path}-{surf_ep.handler_name}")
            observations.append(
                GoLiveObservationItem(
                    id=obs_id,
                    source_type="API_EXPOSURE",
                    title=f"Unauthenticated Mutating Endpoint: {surf_ep.method} {surf_ep.route_path} ({surf_ep.handler_name})",
                    severity="MEDIUM",
                    cwe_or_standard="CWE-306 • OWASP API2:2023",
                    pasta_stage=3,
                    stride_letter="S",
                    filepath=surf_ep.filepath,
                    line=max(1, surf_ep.line_number),
                    reachability_status="REACHABLE",
                    gate_status="POST_GO_LIVE_SLA",
                    default_gate_status="POST_GO_LIVE_SLA",
                    is_overridden=False,
                    sla_window="30_DAYS",
                    why_issue=f"Mutating route `{surf_ep.method} {surf_ep.route_path}` lacks verified authentication posture.",
                    why_gate_classification="Unauthenticated mutating API route classified under 30-day hardening SLA.",
                    mandatory_fix_action=f"Enforce authentication guard on `{surf_ep.handler_name}` (`{surf_ep.filepath}:L{surf_ep.line_number}`).",
                    compensating_control="Apply API gateway rate-limiting, WAF inspection, and runtime anomaly alerting; patch within 30 days.",
                    effort_estimate="~20 mins",
                    raci_owner="Lead Developer (TECH_LEAD)",
                    risk_reduction_points=6,
                    linked_finding_id=None,
                )
            )

        # 3. Failed / Warning PipelineSecurityCheck (PBOM) items not duplicating secret/SCA/IaC/reachability findings
        for chk in pipeline_checks:
            if chk.status not in ("FAIL", "WARNING"):
                continue
            chk_id_low = (chk.id or "").lower()
            chk_cat_low = (chk.category or "").lower()
            if has_active_cred and (chk_id_low == "pbom-3-secrets" or "secret" in chk_cat_low):
                continue
            if has_active_sca and (chk_id_low == "pbom-1-pinning" or "dependency version pinning" in chk_cat_low):
                continue
            if has_active_iac and chk_id_low == "pbom-4-runtime":
                continue
            if has_active_reachable and chk_id_low == "pbom-5-reachability":
                continue

            obs_id = _unique_obs_id("pbom", chk.id or chk.title)
            if chk.status == "FAIL":
                def_gate = "MANDATORY_PRE_GO_LIVE"
                def_sla = "PRE_LAUNCH"
                pb_sev: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "HIGH"
                why_gate = "CI/CD & Supply-Chain PBOM check returned `FAIL`; mandatory pipeline integrity fix required before Go-Live."
                comp_ctrl = "Freeze automated external release promotion and require manual signed build verification until PBOM control passes."
                red_pts = 16
            else:
                def_gate = "POST_GO_LIVE_SLA"
                def_sla = "90_DAYS"
                pb_sev = "LOW"
                why_gate = "PBOM warning (`WARNING`) tracked under 90-day supply-chain hardening backlog."
                comp_ctrl = "Track in sprint hardening backlog with CI lockfile/header monitoring within 90 days."
                red_pts = 4

            pb_fp = (chk.primary_filepath or chk.evidence_path or "workspace").replace("\\", "/")
            observations.append(
                GoLiveObservationItem(
                    id=obs_id,
                    source_type="PBOM",
                    title=_redact_sensitive_text(chk.title, forbidden_raw_values),
                    severity=pb_sev,
                    cwe_or_standard="CWE-1395 • CAPEC-438 / T1195",
                    pasta_stage=2,
                    stride_letter="T",
                    filepath=pb_fp,
                    line=max(1, int(chk.primary_line or 1)),
                    reachability_status="REACHABLE",
                    gate_status=def_gate,
                    default_gate_status=def_gate,
                    is_overridden=False,
                    sla_window=def_sla,
                    why_issue=_redact_sensitive_text(chk.details or chk.why_issue_or_not or chk.title, forbidden_raw_values)[:400],
                    why_gate_classification=why_gate,
                    mandatory_fix_action=_redact_sensitive_text(chk.remediation or f"Remediate PBOM control in {pb_fp}.", forbidden_raw_values)[:320],
                    compensating_control=comp_ctrl,
                    effort_estimate="~20 mins",
                    raci_owner="DevOps / Infra Lead (DEVOPS_LEAD)",
                    risk_reduction_points=red_pts,
                    linked_finding_id=None,
                )
            )

        # Apply saved gate_overrides deterministically
        for obs in observations:
            ov = gate_overrides.get(obs.id)
            if not isinstance(ov, dict):
                continue
            ov_gate: GoLiveGateStatus = ov.get("gate_status") or obs.gate_status
            raw_sla = ov.get("sla_window")
            if raw_sla in ("PRE_LAUNCH", "7_DAYS", "14_DAYS", "30_DAYS", "90_DAYS", "WAIVED"):
                ov_sla: GoLiveSlaWindow = raw_sla
            elif ov_gate == "MANDATORY_PRE_GO_LIVE":
                ov_sla = "PRE_LAUNCH"
            elif ov_gate == "RISK_ACCEPTED_WAIVER":
                ov_sla = "WAIVED"
            else:
                ov_sla = "30_DAYS"

            obs.gate_status = ov_gate
            obs.sla_window = ov_sla
            obs.is_overridden = True
            note = _redact_sensitive_text(str(ov.get("compensating_control_note") or ""), forbidden_raw_values)
            if note:
                obs.compensating_control = (
                    f"{note} (Baseline policy: {obs.compensating_control})"
                    if obs.compensating_control
                    else note
                )
            obs.why_gate_classification = (
                f"Architect Gate Override applied (`{obs.default_gate_status}` -> `{ov_gate}`, SLA `{ov_sla}`). "
                f"{obs.why_gate_classification}"
            )

        return observations

    def _build_attack_trees(
        self,
        active_findings: List[Finding],
        api_ops: ApiOperationsReportResponse,
        app_tree: AppTreeSummary,
        crown_jewels: List[PastaCrownJewelItem],
        forbidden_raw_values: Set[str],
    ) -> List[PastaAttackTreeScenario]:
        jewel_map: Dict[str, PastaCrownJewelItem] = {cj.id: cj for cj in crown_jewels}
        scenarios: List[PastaAttackTreeScenario] = []

        # Index endpoints by linked finding ID and by normalized filepath
        ep_by_finding: Dict[str, ApiEndpointOperationDossier] = {}
        ep_by_file: Dict[str, ApiEndpointOperationDossier] = {}
        for ep in api_ops.endpoints:
            norm_fp = ep.filepath.replace("\\", "/").lower()
            if norm_fp not in ep_by_file:
                ep_by_file[norm_fp] = ep
            for fid in ep.linked_finding_ids:
                if fid not in ep_by_finding:
                    ep_by_finding[fid] = ep

        prioritized_findings = sorted(
            active_findings,
            key=lambda item: (
                0 if item.secret_validation_status == "VERIFIED_ACTIVE" else 1,
                _SEVERITY_ORDER.get(item.severity, 9),
                0 if item.reachability_status == "REACHABLE" else 1,
                item.id,
            ),
        )

        for idx, f in enumerate(prioritized_findings[:6], start=1):
            mitre_capec, stride_let, _, jewel_id, persona = _classify_threat_taxonomy(f)
            jewel = jewel_map.get(jewel_id) or crown_jewels[0]
            sink_fp, sink_ln, sink_snip = _finding_location(f)
            bfl_fp = f.best_fix_location.filepath.replace("\\", "/") if (f.best_fix_location and f.best_fix_location.filepath) else sink_fp
            bfl_ln = max(1, int(f.best_fix_location.line or sink_ln)) if f.best_fix_location else sink_ln
            bfl_fix = _redact_sensitive_text(
                (f.best_fix_location.recommended_fix if f.best_fix_location else "") or f.remediation or f"Patch {bfl_fp}:L{bfl_ln}",
                forbidden_raw_values,
            )

            # Determine entrypoint & propagation hop
            matched_ep = ep_by_finding.get(f.id)
            if matched_ep is None and f.path_nodes:
                first_node = f.path_nodes[0]
                if isinstance(first_node, dict):
                    first_fp = str(first_node.get("filepath") or "").replace("\\", "/").lower()
                    matched_ep = ep_by_file.get(first_fp)
            if matched_ep is None:
                matched_ep = ep_by_file.get(sink_fp.lower())

            if matched_ep is not None:
                entry_title = f"{matched_ep.method} {matched_ep.route_path}"
                entry_sub = f"{matched_ep.framework} ({matched_ep.auth_status})"
                entry_fp = matched_ep.filepath
                entry_ln = max(1, matched_ep.start_line)
            elif f.path_nodes and isinstance(f.path_nodes[0], dict):
                n0 = f.path_nodes[0]
                entry_fp = str(n0.get("filepath") or sink_fp).replace("\\", "/")
                entry_ln = max(1, int(n0.get("start_line") or 1))
                entry_title = f"Source: {str(n0.get('name') or os.path.basename(entry_fp))[:48]}"
                entry_sub = f"{entry_fp}:L{entry_ln}"
            else:
                entry_fp = sink_fp
                entry_ln = sink_ln
                entry_title = f"Workspace Entry ({os.path.basename(sink_fp)})"
                entry_sub = f"{sink_fp}:L{sink_ln}"

            if len(f.path_nodes) >= 3 and isinstance(f.path_nodes[1], dict):
                mid_n = f.path_nodes[1]
                prop_fp = str(mid_n.get("filepath") or sink_fp).replace("\\", "/")
                prop_ln = max(1, int(mid_n.get("start_line") or sink_ln))
                prop_title = _redact_sensitive_text(
                    f"Flow: {str(mid_n.get('name') or mid_n.get('code') or 'Data Propagation')[:48]}",
                    forbidden_raw_values,
                )
            elif matched_ep is not None:
                prop_fp = matched_ep.filepath
                prop_ln = max(1, matched_ep.start_line)
                prop_title = f"Handler: {matched_ep.handler_name}()"
            else:
                prop_fp = sink_fp
                prop_ln = sink_ln
                prop_title = f"Scope Propagation ({os.path.basename(sink_fp)})"

            is_cred = bool(f.is_secret_finding or (f.cwe_id or "").upper() == "CWE-798")
            is_dormant_or_guarded = (
                (not is_cred and f.reachability_status != "REACHABLE")
                or (is_cred and (f.secret_source == "GIT_HISTORY" or f.secret_validation_status in ("REVOKED_OR_INVALID", "TEST_OR_PLACEHOLDER")) and f.secret_validation_status != "VERIFIED_ACTIVE")
            )
            tree_status: Literal["EXPLOITABLE_PATH", "PARTIALLY_GUARDED", "SEVERED_BY_CONTROLS"] = (
                "PARTIALLY_GUARDED" if is_dormant_or_guarded else "EXPLOITABLE_PATH"
            )
            eff_sev = _normalize_severity("CRITICAL" if f.secret_validation_status == "VERIFIED_ACTIVE" else f.severity)
            sc_id = f"atree-{idx}-{_slugify(f.id or f.title, 20)}"

            n_entry_id = f"{sc_id}-entry"
            n_capec_id = f"{sc_id}-capec"
            n_prop_id = f"{sc_id}-prop"
            n_sink_id = f"{sc_id}-sink"
            n_bfl_id = f"{sc_id}-bfl"
            n_jewel_id = f"{sc_id}-jewel"
            n_goal_id = f"{sc_id}-goal"

            sink_sub = _redact_sensitive_text(sink_snip or f"{sink_fp}:L{sink_ln}", forbidden_raw_values)[:80]
            nodes = [
                PastaAttackTreeNode(
                    id=n_entry_id,
                    node_role="ENTRYPOINT",
                    title=entry_title,
                    subtitle=entry_sub,
                    severity=eff_sev,
                    filepath=entry_fp,
                    line=entry_ln,
                    cwe_or_capec=f.cwe_id or "",
                    is_severed=False,
                    linked_finding_id=f.id,
                ),
                PastaAttackTreeNode(
                    id=n_capec_id,
                    node_role="CAPEC_VECTOR",
                    title=mitre_capec,
                    subtitle=persona,
                    severity=eff_sev,
                    filepath=entry_fp,
                    line=entry_ln,
                    cwe_or_capec=mitre_capec,
                    is_severed=False,
                    linked_finding_id=f.id,
                ),
                PastaAttackTreeNode(
                    id=n_prop_id,
                    node_role="PROPAGATION",
                    title=prop_title,
                    subtitle=f"{prop_fp}:L{prop_ln}",
                    severity=eff_sev,
                    filepath=prop_fp,
                    line=prop_ln,
                    cwe_or_capec=f.cwe_id or "",
                    is_severed=is_dormant_or_guarded,
                    linked_finding_id=f.id,
                ),
                PastaAttackTreeNode(
                    id=n_sink_id,
                    node_role="VULN_SINK",
                    title=_redact_sensitive_text(f.title, forbidden_raw_values)[:64],
                    subtitle=sink_sub,
                    severity=eff_sev,
                    filepath=sink_fp,
                    line=sink_ln,
                    cwe_or_capec=f.cwe_id or f.rule_id,
                    is_severed=False,
                    linked_finding_id=f.id,
                ),
                PastaAttackTreeNode(
                    id=n_bfl_id,
                    node_role="BFL_SHIELD",
                    title=f"BFL Chokepoint ({os.path.basename(bfl_fp)}:L{bfl_ln})",
                    subtitle=bfl_fix[:90],
                    severity="PASS",
                    filepath=bfl_fp,
                    line=bfl_ln,
                    cwe_or_capec=f.cwe_id or "",
                    is_severed=True,
                    linked_finding_id=f.id,
                ),
                PastaAttackTreeNode(
                    id=n_jewel_id,
                    node_role="CROWN_JEWEL",
                    title=jewel.name,
                    subtitle=f"{jewel.id} ({jewel.weight_multiplier:.2f}x)",
                    severity=eff_sev,
                    filepath=sink_fp,
                    line=sink_ln,
                    cwe_or_capec=mitre_capec,
                    is_severed=False,
                    linked_finding_id=f.id,
                ),
                PastaAttackTreeNode(
                    id=n_goal_id,
                    node_role="GOAL",
                    title=f"Compromise {jewel.name}",
                    subtitle=f"STRIDE-{stride_let} Objective",
                    severity=eff_sev,
                    filepath=sink_fp,
                    line=sink_ln,
                    cwe_or_capec=mitre_capec,
                    is_severed=False,
                    linked_finding_id=f.id,
                ),
            ]

            edges = [
                PastaAttackTreeEdge(
                    id=f"{sc_id}-e1",
                    source=n_entry_id,
                    target=n_capec_id,
                    label="ADVERSARY VECTOR",
                    is_blocked=False,
                ),
                PastaAttackTreeEdge(
                    id=f"{sc_id}-e2",
                    source=n_capec_id,
                    target=n_prop_id,
                    label="CPG PROPAGATION",
                    is_blocked=False,
                ),
                PastaAttackTreeEdge(
                    id=f"{sc_id}-e3",
                    source=n_prop_id,
                    target=n_sink_id,
                    label="DORMANT PATH" if is_dormant_or_guarded else "TAINT REACHES SINK",
                    is_blocked=is_dormant_or_guarded,
                ),
                PastaAttackTreeEdge(
                    id=f"{sc_id}-e4-bfl",
                    source=n_bfl_id,
                    target=n_sink_id,
                    label="SEVERS AT BFL",
                    is_blocked=True,
                ),
                PastaAttackTreeEdge(
                    id=f"{sc_id}-e5",
                    source=n_sink_id,
                    target=n_jewel_id,
                    label="THREATENS ASSET",
                    is_blocked=is_dormant_or_guarded,
                ),
                PastaAttackTreeEdge(
                    id=f"{sc_id}-e6",
                    source=n_jewel_id,
                    target=n_goal_id,
                    label="BUSINESS BREACH",
                    is_blocked=is_dormant_or_guarded,
                ),
            ]

            _, _, _, _, red_pts = self._classify_default_finding_gate(f)
            scenarios.append(
                PastaAttackTreeScenario(
                    id=sc_id,
                    title=_redact_sensitive_text(f"{f.title} -> {jewel.name}", forbidden_raw_values),
                    attacker_persona=persona,
                    mitre_capec=mitre_capec,
                    stride_letter=stride_let,
                    target_crown_jewel=jewel.id,
                    status=tree_status,
                    severity=eff_sev,
                    narrative=_redact_sensitive_text(
                        f"{persona} leverages {mitre_capec} via `{entry_title}` (`{entry_fp}:L{entry_ln}`), "
                        f"propagating through `{prop_title}` into `{sink_fp}:L{sink_ln}` ({f.cwe_id or f.rule_id}) "
                        f"to impact Crown Jewel `{jewel.name}` ({jewel.weight_multiplier:.2f}x).",
                        forbidden_raw_values,
                    ),
                    bfl_remediation=bfl_fix,
                    projected_risk_reduction=red_pts,
                    linked_finding_id=f.id,
                    primary_filepath=sink_fp,
                    primary_line=sink_ln,
                    nodes=nodes,
                    edges=edges,
                )
            )

        # Add exposed unauthenticated risky routes if slots remain (< 6)
        if len(scenarios) < 6:
            covered_fps = {sc.primary_filepath.lower() for sc in scenarios}
            for ep in api_ops.endpoints:
                if len(scenarios) >= 6:
                    break
                has_exec = "OS_COMMAND_EXEC" in ep.operation_categories
                if ep.auth_status != "UNAUTHENTICATED" or not (ep.is_mutating or has_exec):
                    continue
                if ep.filepath.replace("\\", "/").lower() in covered_fps:
                    continue
                idx_ep = len(scenarios) + 1
                sc_id = f"atree-api-{idx_ep}-{_slugify(ep.handler_name, 18)}"
                jewel_id = "HOST_RUNTIME_AND_OS" if has_exec else "AUTH_AND_SESSION_BOUNDARY"
                jewel = jewel_map.get(jewel_id) or crown_jewels[0]
                capec_str = "CAPEC-88 / T1190" if has_exec else "CAPEC-126 / T1083"
                ep_sev: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "HIGH" if has_exec else "MEDIUM"

                n_entry_id = f"{sc_id}-entry"
                n_capec_id = f"{sc_id}-capec"
                n_prop_id = f"{sc_id}-prop"
                n_sink_id = f"{sc_id}-sink"
                n_bfl_id = f"{sc_id}-bfl"
                n_jewel_id = f"{sc_id}-jewel"
                n_goal_id = f"{sc_id}-goal"

                scenarios.append(
                    PastaAttackTreeScenario(
                        id=sc_id,
                        title=f"Unauthenticated {ep.method} {ep.route_path} -> {jewel.name}",
                        attacker_persona="External Unauthenticated API Adversary",
                        mitre_capec=capec_str,
                        stride_letter="E" if has_exec else "S",
                        target_crown_jewel=jewel.id,
                        status="EXPLOITABLE_PATH",
                        severity=ep_sev,
                        narrative=(
                            f"Unauthenticated caller invokes `{ep.method} {ep.route_path}` (`{ep.filepath}:L{ep.start_line}`) "
                            f"without an authentication dependency guard, reaching `{ep.handler_name}()`."
                        ),
                        bfl_remediation=f"Enforce authentication guard middleware on `{ep.handler_name}` at `{ep.filepath}:L{ep.start_line}`.",
                        projected_risk_reduction=18 if has_exec else 7,
                        linked_finding_id=None,
                        primary_filepath=ep.filepath,
                        primary_line=max(1, ep.start_line),
                        nodes=[
                            PastaAttackTreeNode(
                                id=n_entry_id,
                                node_role="ENTRYPOINT",
                                title=f"{ep.method} {ep.route_path}",
                                subtitle=f"{ep.framework} (UNAUTHENTICATED)",
                                severity=ep_sev,
                                filepath=ep.filepath,
                                line=max(1, ep.start_line),
                                cwe_or_capec="CWE-306",
                            ),
                            PastaAttackTreeNode(
                                id=n_capec_id,
                                node_role="CAPEC_VECTOR",
                                title=capec_str,
                                subtitle="Missing Authentication Guard",
                                severity=ep_sev,
                                filepath=ep.filepath,
                                line=max(1, ep.start_line),
                                cwe_or_capec=capec_str,
                            ),
                            PastaAttackTreeNode(
                                id=n_prop_id,
                                node_role="PROPAGATION",
                                title=f"Handler {ep.handler_name}()",
                                subtitle=f"{ep.filepath}:L{ep.start_line}",
                                severity=ep_sev,
                                filepath=ep.filepath,
                                line=max(1, ep.start_line),
                            ),
                            PastaAttackTreeNode(
                                id=n_sink_id,
                                node_role="VULN_SINK",
                                title="Unguarded State / Process Operation",
                                subtitle=", ".join(ep.operation_categories) or "Mutating Handler",
                                severity=ep_sev,
                                filepath=ep.filepath,
                                line=max(1, ep.start_line),
                                cwe_or_capec="CWE-306",
                            ),
                            PastaAttackTreeNode(
                                id=n_bfl_id,
                                node_role="BFL_SHIELD",
                                title=f"Auth Guard Chokepoint ({os.path.basename(ep.filepath)}:L{ep.start_line})",
                                subtitle="Attach JWT/Session Auth Dependency",
                                severity="PASS",
                                filepath=ep.filepath,
                                line=max(1, ep.start_line),
                                is_severed=True,
                            ),
                            PastaAttackTreeNode(
                                id=n_jewel_id,
                                node_role="CROWN_JEWEL",
                                title=jewel.name,
                                subtitle=f"{jewel.id} ({jewel.weight_multiplier:.2f}x)",
                                severity=ep_sev,
                                filepath=ep.filepath,
                                line=max(1, ep.start_line),
                            ),
                            PastaAttackTreeNode(
                                id=n_goal_id,
                                node_role="GOAL",
                                title=f"Unauthorized Mutation of {jewel.name}",
                                subtitle="STRIDE Boundary Breach",
                                severity=ep_sev,
                                filepath=ep.filepath,
                                line=max(1, ep.start_line),
                            ),
                        ],
                        edges=[
                            PastaAttackTreeEdge(id=f"{sc_id}-e1", source=n_entry_id, target=n_capec_id, label="UNAUTH REQUEST"),
                            PastaAttackTreeEdge(id=f"{sc_id}-e2", source=n_capec_id, target=n_prop_id, label="BYPASSES AUTH"),
                            PastaAttackTreeEdge(id=f"{sc_id}-e3", source=n_prop_id, target=n_sink_id, label="REACHES OPERATION"),
                            PastaAttackTreeEdge(id=f"{sc_id}-e4-bfl", source=n_bfl_id, target=n_sink_id, label="SEVERS AT BFL", is_blocked=True),
                            PastaAttackTreeEdge(id=f"{sc_id}-e5", source=n_sink_id, target=n_jewel_id, label="IMPACTS ASSET"),
                            PastaAttackTreeEdge(id=f"{sc_id}-e6", source=n_jewel_id, target=n_goal_id, label="UNAUTHORIZED ACCESS"),
                        ],
                    )
                )

        # Baseline Clean/Severed simulation when 0 exploitable/active scenarios exist
        if not scenarios:
            sample_fp = app_tree.flat_files[0].filepath if app_tree.flat_files else "workspace"
            sample_ep = api_ops.endpoints[0] if api_ops.endpoints else None
            entry_lbl = (
                f"{sample_ep.method} {sample_ep.route_path}"
                if sample_ep is not None
                else f"Entrypoint ({os.path.basename(sample_fp)})"
            )
            entry_fp = sample_ep.filepath if sample_ep is not None else sample_fp
            entry_ln = max(1, sample_ep.start_line) if sample_ep is not None else 1
            top_jewel = max(crown_jewels, key=lambda cj: cj.weight_multiplier) if crown_jewels else PastaCrownJewelItem(
                id="SECRETS_AND_CREDENTIALS",
                name="Cryptographic Keys & Credentials",
                category="CREDENTIAL_VAULT",
                weight_multiplier=1.8,
            )

            scenarios.append(
                PastaAttackTreeScenario(
                    id="atree-baseline-severed",
                    title="Baseline Defense-in-Depth Attack Simulation",
                    attacker_persona="External Opportunistic Attacker",
                    mitre_capec="CAPEC-88 / T1190",
                    stride_letter="E",
                    target_crown_jewel=top_jewel.id,
                    status="SEVERED_BY_CONTROLS",
                    severity="LOW",
                    narrative=(
                        f"Simulated external adversary probe against `{entry_lbl}` (`{entry_fp}:L{entry_ln}`) "
                        f"is deterministically severed by verified authentication, parameterized execution, and "
                        f"input sanitization controls before reaching `{top_jewel.name}`."
                    ),
                    bfl_remediation="Maintain defense-in-depth authentication guards, parameterized queries, and CI secret scanning.",
                    projected_risk_reduction=0,
                    linked_finding_id=None,
                    primary_filepath=entry_fp,
                    primary_line=entry_ln,
                    nodes=[
                        PastaAttackTreeNode(
                            id="atree-base-entry",
                            node_role="ENTRYPOINT",
                            title=entry_lbl,
                            subtitle=f"{entry_fp}:L{entry_ln}",
                            severity="LOW",
                            filepath=entry_fp,
                            line=entry_ln,
                            cwe_or_capec="CAPEC-88 / T1190",
                            is_severed=False,
                        ),
                        PastaAttackTreeNode(
                            id="atree-base-capec",
                            node_role="CAPEC_VECTOR",
                            title="CAPEC-88 / T1190 Probe",
                            subtitle="Simulated Injection & Auth Probe",
                            severity="LOW",
                            filepath=entry_fp,
                            line=entry_ln,
                            cwe_or_capec="CAPEC-88 / T1190",
                            is_severed=False,
                        ),
                        PastaAttackTreeNode(
                            id="atree-base-shield",
                            node_role="BFL_SHIELD",
                            title="Verified Auth & Input Sanitization",
                            subtitle="0 Exploitable Sink Paths Open",
                            severity="PASS",
                            filepath=entry_fp,
                            line=entry_ln,
                            cwe_or_capec="OWASP ASVS",
                            is_severed=True,
                        ),
                        PastaAttackTreeNode(
                            id="atree-base-jewel",
                            node_role="CROWN_JEWEL",
                            title=f"Protected: {top_jewel.name}",
                            subtitle=f"{top_jewel.id} ({top_jewel.weight_multiplier:.2f}x)",
                            severity="PASS",
                            filepath=entry_fp,
                            line=entry_ln,
                            is_severed=True,
                        ),
                        PastaAttackTreeNode(
                            id="atree-base-goal",
                            node_role="GOAL",
                            title="Adversary Objective Neutralized",
                            subtitle="Attack Path Severed",
                            severity="PASS",
                            filepath=entry_fp,
                            line=entry_ln,
                            is_severed=True,
                        ),
                    ],
                    edges=[
                        PastaAttackTreeEdge(
                            id="atree-base-e1",
                            source="atree-base-entry",
                            target="atree-base-capec",
                            label="EXTERNAL PROBE",
                            is_blocked=False,
                        ),
                        PastaAttackTreeEdge(
                            id="atree-base-e2",
                            source="atree-base-capec",
                            target="atree-base-shield",
                            label="INTERCEPTED BY GUARD",
                            is_blocked=True,
                        ),
                        PastaAttackTreeEdge(
                            id="atree-base-e3",
                            source="atree-base-shield",
                            target="atree-base-jewel",
                            label="SEVERS AT BFL",
                            is_blocked=True,
                        ),
                        PastaAttackTreeEdge(
                            id="atree-base-e4",
                            source="atree-base-jewel",
                            target="atree-base-goal",
                            label="PROTECTED",
                            is_blocked=True,
                        ),
                    ],
                )
            )

        return scenarios

    def _finalize_stage(
        self,
        stage_number: int,
        stage_code: str,
        stage_roman: str,
        title: str,
        methodology_goal: str,
        summary: str,
        evidence_items: List[PastaEvidenceItem],
    ) -> PastaStageItem:
        ok_items = [ev for ev in evidence_items if ev.verdict == "OK"]
        gap_items = [ev for ev in evidence_items if ev.verdict == "GAP"]
        has_high_gap = any(ev.severity in ("CRITICAL", "HIGH") for ev in gap_items)
        if has_high_gap:
            st_status: Literal["PASS", "MONITORED", "ACTION_REQUIRED"] = "ACTION_REQUIRED"
        elif gap_items:
            st_status = "MONITORED"
        else:
            st_status = "PASS"

        what_passed = [f"{ev.title}: {ev.detail}"[:220] for ev in ok_items[:6]]
        if not what_passed:
            what_passed = [f"Completed {stage_code} ({title}) deterministic evaluation."]
        what_failed = [f"[{ev.severity}] {ev.title}: {ev.detail}"[:220] for ev in gap_items[:6]]

        return PastaStageItem(
            stage_number=stage_number,
            stage_code=stage_code,
            stage_roman=stage_roman,
            title=title,
            methodology_goal=methodology_goal,
            status=st_status,
            ok_count=len(ok_items),
            gap_count=len(gap_items),
            summary=summary,
            what_passed=what_passed,
            what_failed=what_failed,
            evidence_items=evidence_items,
        )

    def _convert_exploit_chains_to_attack_trees(
        self,
        exploit_chains: Optional[List[ExploitChainItem]],
        crown_jewels: List[PastaCrownJewelItem],
        forbidden_raw_values: Set[str],
    ) -> List[PastaAttackTreeScenario]:
        """Converts up to top 3 confirmed S8 Multi-Hop Exploit Chains into Stage VI attack tree scenarios."""
        if not exploit_chains:
            return []

        jewel_ids = {cj.id for cj in crown_jewels}
        converted: List[PastaAttackTreeScenario] = []

        for chain in list(exploit_chains)[:3]:
            raw_cid = (chain.id or "").strip()
            if raw_cid.startswith("s8-chain-"):
                sc_id = raw_cid
            elif raw_cid.startswith("chain-"):
                sc_id = f"s8-{raw_cid}"
            else:
                sc_id = f"s8-chain-{_slugify(raw_cid or chain.title, 24)}"

            eff_sev = _normalize_severity(chain.severity)
            hops = list(chain.hops or [])
            vuln_indices = [
                idx for idx, h in enumerate(hops) if h.hop_type == "VULNERABILITY"
            ]
            last_vuln_idx = vuln_indices[-1] if vuln_indices else -1

            # Infer target Crown Jewel ID and STRIDE letter from hops
            combined_meta = " ".join(
                f"{h.hop_type} {h.title} {h.cwe_or_rule}" for h in hops
            ).upper()
            if any(k in combined_meta for k in ("HOST", "RUNTIME", "CWE-78", "CWE-502", "CWE-120", "CWE-416")):
                target_cj = "HOST_RUNTIME_AND_OS"
                stride_let = "E"
            elif any(k in combined_meta for k in ("LEAKED_SECRET", "CREDENTIAL", "CWE-798", "VAULT")):
                target_cj = "SECRETS_AND_CREDENTIALS"
                stride_let = "I"
            elif any(k in combined_meta for k in ("DATABASE", "SQL", "LEDGER", "TREASURY", "PII", "CWE-89")):
                target_cj = "DATABASE_STORES"
                stride_let = "T"
            elif any(k in combined_meta for k in ("SSRF", "CWE-918", "METADATA")):
                target_cj = "AI_AND_EXTERNAL_APIS"
                stride_let = "I"
            else:
                target_cj = "AUTH_AND_SESSION_BOUNDARY"
                stride_let = "S"
            if jewel_ids and target_cj not in jewel_ids:
                target_cj = crown_jewels[0].id

            cwe_tokens: List[str] = []
            for h in hops:
                if h.cwe_or_rule and h.cwe_or_rule not in cwe_tokens:
                    cwe_tokens.append(h.cwe_or_rule)
            capec_lbl = f"S8_EXPLOIT_CHAIN ({', '.join(cwe_tokens[:3])})" if cwe_tokens else "S8_EXPLOIT_CHAIN"

            primary_hop = next(
                (h for h in hops if h.hop_type in ("VULNERABILITY", "LEAKED_SECRET") and h.filepath),
                hops[0] if hops else None,
            )
            primary_fp = primary_hop.filepath if primary_hop and primary_hop.filepath else "workspace"
            primary_ln = max(1, int(primary_hop.line or 1)) if primary_hop else 1

            tree_nodes: List[PastaAttackTreeNode] = []
            for idx, h in enumerate(hops):
                if h.hop_type == "ENTRYPOINT":
                    n_role: Literal[
                        "GOAL",
                        "CAPEC_VECTOR",
                        "ENTRYPOINT",
                        "PROPAGATION",
                        "VULN_SINK",
                        "BFL_SHIELD",
                        "CROWN_JEWEL",
                    ] = "ENTRYPOINT"
                elif h.hop_type == "LEAKED_SECRET":
                    n_role = "CAPEC_VECTOR"
                elif h.hop_type == "COMMUNITY_BRIDGE":
                    n_role = "PROPAGATION"
                elif h.hop_type == "CROWN_JEWEL":
                    n_role = "CROWN_JEWEL"
                else:
                    n_role = "VULN_SINK" if idx == last_vuln_idx else "PROPAGATION"

                tree_nodes.append(
                    PastaAttackTreeNode(
                        id=f"{sc_id}-n{idx + 1}",
                        node_role=n_role,
                        title=_redact_sensitive_text(h.title, forbidden_raw_values)[:80],
                        subtitle=_redact_sensitive_text(
                            f"{h.filepath}:L{max(1, int(h.line or 1))}" if h.filepath else h.hop_type,
                            forbidden_raw_values,
                        ),
                        severity=eff_sev,
                        filepath=h.filepath or primary_fp,
                        line=max(1, int(h.line or 1)),
                        cwe_or_capec=_redact_sensitive_text(h.cwe_or_rule or h.hop_type, forbidden_raw_values),
                        is_severed=False,
                        linked_finding_id=h.linked_finding_id,
                    )
                )

            bfl_node_id = f"{sc_id}-bfl"
            clean_bfl = _redact_sensitive_text(
                chain.break_the_chain_fix or "Sever earliest chain hop with auth guard and BFL remediation.",
                forbidden_raw_values,
            )
            tree_nodes.append(
                PastaAttackTreeNode(
                    id=bfl_node_id,
                    node_role="BFL_SHIELD",
                    title="S8 Break-the-Chain BFL Shield",
                    subtitle=clean_bfl[:96],
                    severity="PASS",
                    filepath=primary_fp,
                    line=primary_ln,
                    cwe_or_capec="S8-BFL",
                    is_severed=True,
                    linked_finding_id=chain.linked_finding_ids[0] if chain.linked_finding_ids else None,
                )
            )

            tree_edges: List[PastaAttackTreeEdge] = []
            hop_node_count = len(hops)
            for idx in range(max(0, hop_node_count - 1)):
                src_h = hops[idx]
                dst_h = hops[idx + 1]
                tree_edges.append(
                    PastaAttackTreeEdge(
                        id=f"{sc_id}-e{idx + 1}",
                        source=f"{sc_id}-n{idx + 1}",
                        target=f"{sc_id}-n{idx + 2}",
                        label=f"{src_h.hop_type} -> {dst_h.hop_type}",
                        is_blocked=False,
                    )
                )
            if hop_node_count >= 2:
                tree_edges.append(
                    PastaAttackTreeEdge(
                        id=f"{sc_id}-e-bfl",
                        source=bfl_node_id,
                        target=f"{sc_id}-n2",
                        label="SEVERS AT BFL",
                        is_blocked=True,
                    )
                )

            clean_title = _redact_sensitive_text(
                chain.title if chain.title.startswith("[S8 Chain]") else f"[S8 Chain] {chain.title}",
                forbidden_raw_values,
            )
            clean_narrative = _redact_sensitive_text(
                chain.narrative or f"S8 multi-hop exploit chain (CVSS {chain.chain_cvss:.1f}) targeting {target_cj}.",
                forbidden_raw_values,
            )

            converted.append(
                PastaAttackTreeScenario(
                    id=sc_id,
                    title=clean_title,
                    attacker_persona="Chained Multi-Hop Adversary (S8)",
                    mitre_capec=capec_lbl,
                    stride_letter=stride_let,
                    target_crown_jewel=target_cj,
                    status="EXPLOITABLE_PATH",
                    severity=eff_sev,
                    narrative=clean_narrative,
                    bfl_remediation=clean_bfl,
                    projected_risk_reduction=max(12, min(35, int(round(float(chain.chain_cvss or 7.5) * 3)))),
                    linked_finding_id=chain.linked_finding_ids[0] if chain.linked_finding_ids else None,
                    primary_filepath=primary_fp,
                    primary_line=primary_ln,
                    nodes=tree_nodes,
                    edges=tree_edges,
                )
            )

        return converted

    def evaluate_pasta(
        self,
        target_dir: str,
        findings: List[Finding],
        app_tree: Optional[AppTreeSummary] = None,
        api_ops: Optional[ApiOperationsReportResponse] = None,
        sbom_components: Optional[List[SbomComponentItem]] = None,
        endpoints: Optional[List[AttackSurfaceEndpoint]] = None,
        stride_threats: Optional[List[StrideThreatItem]] = None,
        pipeline_checks: Optional[List[PipelineSecurityCheck]] = None,
        extra_forbidden_values: Optional[Set[str]] = None,
        forbidden_raw_secrets: Optional[Set[str]] = None,
        exploit_chains: Optional[List[ExploitChainItem]] = None,
    ) -> PastaAssessmentResponse:
        eff_target = (target_dir or ".").strip() or "."
        abs_target = os.path.abspath(eff_target)
        app_name = os.path.basename(abs_target) or abs_target
        now_iso = _utc_now_iso()

        # Collect raw credential values strictly for defensive output scrubbing (never persisted/logged)
        forbidden_raw_values: Set[str] = {
            f.secret_value_raw
            for f in (findings or [])
            if f.secret_value_raw and len(f.secret_value_raw) >= 4
        }
        for extra_vals in (extra_forbidden_values, forbidden_raw_secrets):
            if extra_vals:
                forbidden_raw_values.update(
                    val for val in extra_vals if isinstance(val, str) and len(val) >= 5
                )

        active_findings: List[Finding] = [
            f for f in (findings or [])
            if f.triage_status not in ("NOT_EXPLOITABLE", "RESOLVED")
        ]
        excluded_findings: List[Finding] = [
            f for f in (findings or [])
            if f.triage_status in ("NOT_EXPLOITABLE", "RESOLVED")
        ]

        # Lazily compute app_tree, api_ops, and SBOM if not supplied
        if app_tree is None:
            if os.path.exists(abs_target):
                raw_tree = AppTreeAnalyzer(abs_target).analyze()
                eff_app_tree = AppTreeSummary.model_validate(raw_tree.model_dump())
            else:
                eff_app_tree = AppTreeSummary(
                    root_path=abs_target,
                    total_files=0,
                    total_directories=0,
                    total_lines=0,
                    category_counts={},
                    detected_tech_stack=[],
                    tree=DirectoryTreeNode(name=app_name, path=""),
                    flat_files=[],
                    cross_file_edges=[],
                )
        elif isinstance(app_tree, AppTreeSummary):
            eff_app_tree = app_tree
        else:
            eff_app_tree = AppTreeSummary.model_validate(app_tree.model_dump())

        if api_ops is None:
            if os.path.exists(abs_target):
                eff_api_ops = ApiOperationsEngine().analyze_workspace_api_operations(
                    abs_target,
                    findings=active_findings,
                )
            else:
                eff_api_ops = ApiOperationsReportResponse(
                    project_path=abs_target,
                    total_endpoints=0,
                    authenticated_count=0,
                    unauthenticated_count=0,
                    mutating_endpoints_count=0,
                    db_endpoints_count=0,
                    external_http_endpoints_count=0,
                    exec_or_fs_endpoints_count=0,
                    vulnerable_endpoints_count=0,
                    frameworks_detected=[],
                    endpoints=[],
                )
        else:
            eff_api_ops = api_ops

        eff_sbom: List[SbomComponentItem] = (
            list(sbom_components)
            if sbom_components is not None
            else self._discover_basic_sbom(abs_target)
        )
        eff_endpoints: List[AttackSurfaceEndpoint] = list(endpoints or [])
        eff_stride: List[StrideThreatItem] = list(stride_threats or [])
        eff_pbom: List[PipelineSecurityCheck] = list(pipeline_checks or [])

        # Load persisted vault profile & gate overrides
        prof_state = self.get_profile_state(abs_target)
        selected_preset: PastaBusinessPreset = prof_state["business_preset"]
        saved_weights: Dict[str, float] = prof_state["crown_jewel_weights"]
        gate_overrides: Dict[str, Any] = prof_state["gate_overrides"]

        inferred_preset, inferred_reason = self._infer_business_preset(
            abs_target,
            eff_app_tree,
            eff_api_ops,
            eff_sbom,
            eff_endpoints,
            active_findings,
        )
        if selected_preset == "AUTO_INFERRED":
            effective_preset: PastaBusinessPreset = inferred_preset
            business_reason = inferred_reason
        else:
            effective_preset = selected_preset
            mult_sel = _PRESET_MULTIPLIERS.get(effective_preset, 1.0)
            business_reason = (
                f"Architect-selected preset {effective_preset} ({mult_sel:.2f}x) active "
                f"(auto-inference baseline: {inferred_preset})."
            )

        frameworks = list(_PRESET_FRAMEWORKS.get(effective_preset, _PRESET_FRAMEWORKS["ENTERPRISE_INTERNAL"]))
        crown_jewels = self._build_crown_jewels(
            saved_weights,
            eff_app_tree,
            eff_api_ops,
            eff_sbom,
            active_findings,
        )
        jewel_weight_map: Dict[str, float] = {cj.id: cj.weight_multiplier for cj in crown_jewels}

        # Build Go-Live Observation Register & Attack Trees
        golive_observations = self._build_golive_observations(
            active_findings=active_findings,
            api_ops=eff_api_ops,
            endpoints=eff_endpoints,
            pipeline_checks=eff_pbom,
            gate_overrides=gate_overrides,
            forbidden_raw_values=forbidden_raw_values,
        )

        attack_trees = self._build_attack_trees(
            active_findings=active_findings,
            api_ops=eff_api_ops,
            app_tree=eff_app_tree,
            crown_jewels=crown_jewels,
            forbidden_raw_values=forbidden_raw_values,
        )
        s8_chain_trees = self._convert_exploit_chains_to_attack_trees(
            exploit_chains=exploit_chains,
            crown_jewels=crown_jewels,
            forbidden_raw_values=forbidden_raw_values,
        )
        if s8_chain_trees:
            existing_tree_ids = {t.id for t in attack_trees}
            for s8_sc in s8_chain_trees:
                if s8_sc.id not in existing_tree_ids:
                    attack_trees.append(s8_sc)
                    existing_tree_ids.add(s8_sc.id)

        # Compute Risk Scores & Go-Live Verdict with strict invariants
        preset_mult = _PRESET_MULTIPLIERS.get(effective_preset, 1.0)
        avg_jewel_w = (
            sum(cj.weight_multiplier for cj in crown_jewels) / float(len(crown_jewels))
            if crown_jewels
            else _DEFAULT_AVG_JEWEL_WEIGHT
        )
        cj_scale = avg_jewel_w / _DEFAULT_AVG_JEWEL_WEIGHT

        mandatory_obs = [o for o in golive_observations if o.gate_status == "MANDATORY_PRE_GO_LIVE"]
        sla_obs = [o for o in golive_observations if o.gate_status == "POST_GO_LIVE_SLA"]
        waived_obs = [o for o in golive_observations if o.gate_status == "RISK_ACCEPTED_WAIVER"]

        mandatory_count = len(mandatory_obs)
        sla_count = len(sla_obs)
        waived_count = len(waived_obs)

        surface_pts = min(14, eff_api_ops.total_endpoints * 2 + eff_api_ops.mutating_endpoints_count * 2)
        inherent_raw = 18.0 * preset_mult * cj_scale + float(surface_pts)
        for obs in golive_observations:
            base_obs_w = {"CRITICAL": 24.0, "HIGH": 15.0, "MEDIUM": 8.0, "LOW": 3.5}.get(obs.severity, 6.0)
            inherent_raw += base_obs_w * preset_mult * min(1.35, cj_scale)

        residual_raw = 9.0 * preset_mult * cj_scale
        projected_raw = 7.0 * preset_mult * cj_scale
        for obs in golive_observations:
            if obs.gate_status == "MANDATORY_PRE_GO_LIVE":
                m_pts = {"CRITICAL": 26.0, "HIGH": 18.0, "MEDIUM": 11.0, "LOW": 6.0}.get(obs.severity, 15.0)
                residual_raw += m_pts * preset_mult * min(1.3, cj_scale)
                # Mandatory items are resolved before launch -> 0 pts added to projected_raw
            elif obs.gate_status == "POST_GO_LIVE_SLA":
                sla_res_map = {"7_DAYS": 9.0, "14_DAYS": 7.5, "30_DAYS": 6.0, "90_DAYS": 3.0}
                s_pts = sla_res_map.get(obs.sla_window, 6.0)
                residual_raw += s_pts * min(1.25, preset_mult)
                projected_raw += (s_pts * 0.45) * min(1.2, preset_mult)
            else:  # RISK_ACCEPTED_WAIVER
                w_pts = 5.5 if obs.severity in ("CRITICAL", "HIGH") else 3.0
                residual_raw += w_pts
                projected_raw += w_pts

        inherent_score = max(0, min(100, int(round(inherent_raw))))
        residual_score = max(0, min(100, int(round(residual_raw))))
        projected_score = max(0, min(100, int(round(projected_raw))))

        if mandatory_count > 0:
            golive_verdict: GoLiveVerdict = "NO_GO_HOLD_RELEASE"
            golive_verdict_label = "NO-GO • HOLD RELEASE (MANDATORY BLOCKERS OPEN)"
            residual_score = max(65, residual_score)
        elif sla_count > 0 or waived_count > 0:
            golive_verdict = "CONDITIONAL_GO_LIVE"
            golive_verdict_label = "CONDITIONAL GO-LIVE (APPROVED WITH SLA & COMPENSATING CONTROLS)"
        else:
            golive_verdict = "APPROVED_FOR_GO_LIVE"
            golive_verdict_label = "APPROVED FOR GO-LIVE (CLEAN POSTURE)"

        # Enforce strict ordering invariant: 0 <= projected <= residual <= inherent <= 100
        projected_score = max(0, min(100, projected_score))
        residual_score = max(projected_score, min(100, residual_score))
        inherent_score = max(residual_score, min(100, inherent_score))

        inherent_level = _score_to_risk_level(inherent_score)
        residual_level = _score_to_risk_level(residual_score)
        projected_level = _score_to_risk_level(projected_score)

        # -------------------------------------------------------------------
        # Synthesize All 7 Deterministic PASTA Stages (PASTA-1 .. PASTA-7)
        # -------------------------------------------------------------------
        sample_root_fp = eff_app_tree.flat_files[0].filepath if eff_app_tree.flat_files else "workspace"

        # Stage 1: Define Objectives (DO)
        s1_ev: List[PastaEvidenceItem] = [
            PastaEvidenceItem(
                id="p1-ev-profile",
                stage_number=1,
                verdict="OK",
                severity="PASS",
                title=f"Business Risk Profile: {effective_preset} ({preset_mult:.2f}x)",
                detail=f"{business_reason} Regulatory frameworks: {', '.join(frameworks)}.",
                filepath=sample_root_fp,
                line=1,
                cwe_or_capec=", ".join(frameworks[:2]),
                stride_cross_ref="GOVERNANCE",
            ),
            PastaEvidenceItem(
                id="p1-ev-jewels",
                stage_number=1,
                verdict="OK",
                severity="PASS",
                title=f"Cataloged {len(crown_jewels)} Weighted Crown Jewel Asset Classes",
                detail=", ".join(
                    f"{cj.id}={cj.weight_multiplier:.2f}x ({cj.asset_count} refs)"
                    for cj in crown_jewels
                ),
                filepath=sample_root_fp,
                line=1,
                cwe_or_capec="PASTA-DO",
                stride_cross_ref="CIA-TRIAD",
            ),
        ]
        if mandatory_count > 0:
            top_blk = mandatory_obs[0]
            s1_ev.append(
                PastaEvidenceItem(
                    id="p1-ev-objective-gap",
                    stage_number=1,
                    verdict="GAP",
                    severity=top_blk.severity,
                    title=f"{mandatory_count} Mandatory Release Blocker(s) Threaten {frameworks[0]} Objectives",
                    detail=f"Lead blocker `{top_blk.title}` at `{top_blk.filepath}:L{top_blk.line}` violates pre-launch risk tolerance.",
                    filepath=top_blk.filepath,
                    line=top_blk.line,
                    cwe_or_capec=top_blk.cwe_or_standard,
                    stride_cross_ref=f"STRIDE-{top_blk.stride_letter}",
                    linked_finding_id=top_blk.linked_finding_id,
                )
            )
        stage_1 = self._finalize_stage(
            1,
            "PASTA-1",
            "I",
            "Define Objectives (DO)",
            "Establish business criticality multipliers, regulatory compliance mandates, and Crown Jewel asset weights.",
            f"Profile `{effective_preset}` ({preset_mult:.2f}x) aligned to {', '.join(frameworks)} across 5 Crown Jewels.",
            s1_ev,
        )

        # Stage 2: Define Technical Scope (DTS)
        pinned_sbom = sum(1 for c in eff_sbom if c.is_pinned)
        unpinned_sbom = sum(1 for c in eff_sbom if not c.is_pinned)
        stack_str = ", ".join(eff_app_tree.detected_tech_stack) or "Multi-Language Workspace"
        s2_ev: List[PastaEvidenceItem] = [
            PastaEvidenceItem(
                id="p2-ev-stack",
                stage_number=2,
                verdict="OK",
                severity="PASS",
                title=f"Technical Scope Mapped: {eff_app_tree.total_files} File(s), {eff_app_tree.total_lines} LOC",
                detail=f"Detected technology stack: {stack_str}. Intra-repo import edges: {len(eff_app_tree.cross_file_edges)}.",
                filepath=sample_root_fp,
                line=1,
                cwe_or_capec="SBOM / CPG",
                stride_cross_ref="SCOPE",
            ),
        ]
        if unpinned_sbom > 0:
            first_unpinned = next(c for c in eff_sbom if not c.is_pinned)
            s2_ev.append(
                PastaEvidenceItem(
                    id="p2-ev-sbom-unpinned",
                    stage_number=2,
                    verdict="GAP",
                    severity="MEDIUM",
                    title=f"{unpinned_sbom} Floating SBOM Dependency Range(s) Detected ({pinned_sbom} Pinned)",
                    detail=f"Example unpinned package `{first_unpinned.name}` (`{first_unpinned.version}`) in `{first_unpinned.manifest_path}:L{first_unpinned.line_number}`.",
                    filepath=first_unpinned.manifest_path,
                    line=first_unpinned.line_number,
                    cwe_or_capec="CWE-1395 / CAPEC-438",
                    stride_cross_ref="STRIDE-T",
                )
            )
        else:
            s2_ev.append(
                PastaEvidenceItem(
                    id="p2-ev-sbom-pinned",
                    stage_number=2,
                    verdict="OK",
                    severity="PASS",
                    title=f"SBOM Pinning Hygiene Verified ({pinned_sbom} Pinned, 0 Floating)",
                    detail="All discovered third-party manifest components specify deterministic version pins.",
                    filepath=eff_sbom[0].manifest_path if eff_sbom else sample_root_fp,
                    line=1,
                    cwe_or_capec="OWASP A06:2021",
                    stride_cross_ref="STRIDE-T",
                )
            )
        for chk in eff_pbom:
            if chk.status in ("FAIL", "WARNING"):
                s2_ev.append(
                    PastaEvidenceItem(
                        id=f"p2-ev-{_slugify(chk.id, 20)}",
                        stage_number=2,
                        verdict="GAP",
                        severity="HIGH" if chk.status == "FAIL" else "LOW",
                        title=f"PBOM {chk.status}: {chk.title}",
                        detail=_redact_sensitive_text(chk.details, forbidden_raw_values)[:220],
                        filepath=chk.primary_filepath or chk.evidence_path or sample_root_fp,
                        line=max(1, chk.primary_line),
                        cwe_or_capec="CAPEC-438 / T1195",
                        stride_cross_ref="STRIDE-T",
                    )
                )
        stage_2 = self._finalize_stage(
            2,
            "PASTA-2",
            "II",
            "Define Technical Scope (DTS)",
            "Inventory languages, frameworks, scanned workspace files, SBOM dependency pinning, and CI/CD PBOM checks.",
            f"Scoped {eff_app_tree.total_files} file(s) ({stack_str}) and {len(eff_sbom)} SBOM package(s) ({pinned_sbom} pinned, {unpinned_sbom} floating).",
            s2_ev,
        )

        # Stage 3: Application Decomposition (AD)
        op_cat_counts: Dict[str, int] = {}
        for ep in eff_api_ops.endpoints:
            for cat in ep.operation_categories:
                op_cat_counts[cat] = op_cat_counts.get(cat, 0) + 1
        cat_summary = (
            ", ".join(f"{k}={v}" for k, v in sorted(op_cat_counts.items()))
            if op_cat_counts
            else "No external HTTP route handlers detected"
        )
        s3_ev: List[PastaEvidenceItem] = [
            PastaEvidenceItem(
                id="p3-ev-trust-boundaries",
                stage_number=3,
                verdict="OK",
                severity="PASS",
                title=(
                    f"Trust Boundaries Decomposed: {eff_api_ops.total_endpoints} Endpoint(s) "
                    f"({eff_api_ops.authenticated_count} Auth, {eff_api_ops.unauthenticated_count} Unauth)"
                ),
                detail=f"Frameworks: {', '.join(eff_api_ops.frameworks_detected) or 'Internal Modules'}. Operations: {cat_summary}.",
                filepath=eff_api_ops.endpoints[0].filepath if eff_api_ops.endpoints else sample_root_fp,
                line=eff_api_ops.endpoints[0].start_line if eff_api_ops.endpoints else 1,
                cwe_or_capec="OWASP API Top 10",
                stride_cross_ref="STRIDE-S / STRIDE-E",
            ),
        ]
        for ep in eff_api_ops.endpoints:
            has_exec = "OS_COMMAND_EXEC" in ep.operation_categories
            if ep.auth_status == "UNAUTHENTICATED" and (ep.is_mutating or has_exec):
                s3_ev.append(
                    PastaEvidenceItem(
                        id=f"p3-ev-ep-{_slugify(ep.id, 20)}",
                        stage_number=3,
                        verdict="GAP",
                        severity="HIGH" if has_exec else "MEDIUM",
                        title=f"Unauthenticated {'Exec' if has_exec else 'Mutating'} Boundary: {ep.method} {ep.route_path}",
                        detail=f"Handler `{ep.handler_name}` in `{ep.filepath}:L{ep.start_line}` performs {', '.join(ep.operation_categories) or 'state mutation'} without auth guard.",
                        filepath=ep.filepath,
                        line=max(1, ep.start_line),
                        cwe_or_capec="CWE-306",
                        stride_cross_ref="STRIDE-E" if has_exec else "STRIDE-S",
                    )
                )
        stage_3 = self._finalize_stage(
            3,
            "PASTA-3",
            "III",
            "Application Decomposition (AD)",
            "Map HTTP entrypoints, authentication trust boundaries, and inter-procedural CPG sink operations.",
            f"Decomposed {eff_api_ops.total_endpoints} HTTP endpoint(s) ({eff_api_ops.authenticated_count} authenticated, {eff_api_ops.unauthenticated_count} unauthenticated) and {len(op_cat_counts)} operation class(es).",
            s3_ev,
        )

        # Stage 4: Threat Analysis (TA)
        s4_ev: List[PastaEvidenceItem] = [
            PastaEvidenceItem(
                id="p4-ev-catalog",
                stage_number=4,
                verdict="OK",
                severity="PASS",
                title="MITRE ATT&CK, CAPEC & 6-Domain STRIDE Threat Matrix Correlated",
                detail="Evaluated CAPEC-88/T1190, CAPEC-66/T1190, CAPEC-63/T1189, CAPEC-126/T1083, CAPEC-194/T1567, CAPEC-560/T1552, and CAPEC-438/T1195 across S/T/R/I/D/E.",
                filepath=sample_root_fp,
                line=1,
                cwe_or_capec="CAPEC-88 / T1190",
                stride_cross_ref="S/T/R/I/D/E",
            ),
        ]
        seen_capec_vectors: Set[Tuple[str, str]] = set()
        for f in sorted(active_findings, key=lambda item: _SEVERITY_ORDER.get(item.severity, 9)):
            mitre_capec, stride_let, stride_lbl, jewel_id, persona = _classify_threat_taxonomy(f)
            vec_key = (mitre_capec, f.id)
            if vec_key in seen_capec_vectors or len(s4_ev) >= 12:
                continue
            seen_capec_vectors.add(vec_key)
            fp, ln, _ = _finding_location(f)
            s4_ev.append(
                PastaEvidenceItem(
                    id=f"p4-ev-{_slugify(f.id, 20)}",
                    stage_number=4,
                    verdict="GAP",
                    severity=_normalize_severity("CRITICAL" if f.secret_validation_status == "VERIFIED_ACTIVE" else f.severity),
                    title=_redact_sensitive_text(f"{mitre_capec} ({persona}) -> {jewel_id}", forbidden_raw_values),
                    detail=_redact_sensitive_text(f"{f.title} at `{fp}:L{ln}` maps to {stride_lbl}.", forbidden_raw_values),
                    filepath=fp,
                    line=ln,
                    cwe_or_capec=mitre_capec,
                    stride_cross_ref=stride_lbl,
                    linked_finding_id=f.id,
                )
            )
        for st_item in eff_stride:
            if st_item.status == "ACTION_REQUIRED" and len(s4_ev) < 14:
                s4_ev.append(
                    PastaEvidenceItem(
                        id=f"p4-ev-stride-{st_item.stride_letter.lower()}",
                        stage_number=4,
                        verdict="GAP",
                        severity=st_item.severity,
                        title=_redact_sensitive_text(
                            f"STRIDE-{st_item.stride_letter} ({st_item.stride_category}): {st_item.title}",
                            forbidden_raw_values,
                        ),
                        detail=_redact_sensitive_text(st_item.issue_summary or st_item.threat_scenario, forbidden_raw_values)[:220],
                        filepath=st_item.primary_filepath or sample_root_fp,
                        line=max(1, st_item.primary_line),
                        cwe_or_capec=st_item.compliance_mapping[:48],
                        stride_cross_ref=f"STRIDE-{st_item.stride_letter}",
                    )
                )
        stage_4 = self._finalize_stage(
            4,
            "PASTA-4",
            "IV",
            "Threat Analysis (TA)",
            "Correlate adversary personas, MITRE ATT&CK techniques, CAPEC vectors, and STRIDE categories against Crown Jewels.",
            f"Mapped {max(0, len(s4_ev) - 1)} active adversary threat vector(s) across MITRE CAPEC/ATT&CK and STRIDE S/T/R/I/D/E.",
            s4_ev,
        )

        # Stage 5: Weakness & Vulnerability Analysis (WVA)
        reachable_cnt = sum(1 for f in active_findings if f.reachability_status == "REACHABLE")
        dormant_cnt = sum(1 for f in active_findings if f.reachability_status != "REACHABLE")
        active_cred_cnt = sum(1 for f in active_findings if f.secret_validation_status == "VERIFIED_ACTIVE")
        git_hist_cnt = sum(1 for f in active_findings if f.secret_source == "GIT_HISTORY")

        s5_ev: List[PastaEvidenceItem] = [
            PastaEvidenceItem(
                id="p5-ev-engine-pass",
                stage_number=5,
                verdict="OK",
                severity="PASS",
                title=(
                    f"CPG Reachability & Secret Vault Triage Complete "
                    f"({reachable_cnt} Reachable, {dormant_cnt} Dormant, {len(excluded_findings)} Suppressed)"
                ),
                detail=(
                    f"Active findings: {len(active_findings)} "
                    f"(Verified-Active secrets: {active_cred_cnt}, Git-History secrets: {git_hist_cnt})."
                ),
                filepath=sample_root_fp,
                line=1,
                cwe_or_capec="CPG-DFG / CWE",
                stride_cross_ref="REACHABILITY",
            ),
        ]
        for f in sorted(active_findings, key=lambda item: _SEVERITY_ORDER.get(item.severity, 9))[:15]:
            fp, ln, _ = _finding_location(f)
            mitre_capec, stride_let, _, _, _ = _classify_threat_taxonomy(f)
            cred_tag = (
                f", secret_status={f.secret_validation_status or 'DETECTED'}, origin={f.secret_source or 'WORKING_TREE'}"
                if (f.is_secret_finding or (f.cwe_id or "").upper() == "CWE-798")
                else ""
            )
            bfl_desc = (
                f"BFL `{f.best_fix_location.filepath}:L{f.best_fix_location.line}`"
                if f.best_fix_location and f.best_fix_location.filepath
                else f"Location `{fp}:L{ln}`"
            )
            s5_ev.append(
                PastaEvidenceItem(
                    id=f"p5-ev-f-{_slugify(f.id, 22)}",
                    stage_number=5,
                    verdict="GAP",
                    severity=_normalize_severity("CRITICAL" if f.secret_validation_status == "VERIFIED_ACTIVE" else f.severity),
                    title=_redact_sensitive_text(f"[{f.scan_engine}] {f.title} ({f.cwe_id or f.rule_id})", forbidden_raw_values),
                    detail=_redact_sensitive_text(
                        f"Reachability={f.reachability_status}{cred_tag}; {bfl_desc}.",
                        forbidden_raw_values,
                    ),
                    filepath=fp,
                    line=ln,
                    cwe_or_capec=f.cwe_id or mitre_capec,
                    stride_cross_ref=f"STRIDE-{stride_let}",
                    linked_finding_id=f.id,
                )
            )
        stage_5 = self._finalize_stage(
            5,
            "PASTA-5",
            "V",
            "Weakness & Vulnerability Analysis (WVA)",
            "Analyze SAST, SCA, IaC, and Secret Vault weaknesses with call-graph reachability and Best Fixed Locations (BFL).",
            f"Evaluated {len(active_findings)} active weakness(es) ({reachable_cnt} reachable, {dormant_cnt} dormant) and {len(excluded_findings)} triaged-excluded item(s).",
            s5_ev,
        )

        # Stage 6: Attack Modeling & Simulation (AMS)
        exploitable_trees = [t for t in attack_trees if t.status == "EXPLOITABLE_PATH"]
        guarded_trees = [t for t in attack_trees if t.status == "PARTIALLY_GUARDED"]
        severed_trees = [t for t in attack_trees if t.status == "SEVERED_BY_CONTROLS"]
        s6_ev: List[PastaEvidenceItem] = [
            PastaEvidenceItem(
                id="p6-ev-bfl-shields",
                stage_number=6,
                verdict="OK",
                severity="PASS",
                title=f"Synthesized {len(attack_trees)} Multi-Hop Attack Tree Simulation(s) with BFL Shields",
                detail=(
                    f"Exploitable paths: {len(exploitable_trees)}, Partially guarded: {len(guarded_trees)}, "
                    f"Severed by controls: {len(severed_trees)}."
                ),
                filepath=attack_trees[0].primary_filepath if attack_trees else sample_root_fp,
                line=attack_trees[0].primary_line if attack_trees else 1,
                cwe_or_capec="PASTA-AMS",
                stride_cross_ref="BFL-SHIELD",
            ),
        ]
        for sc in attack_trees:
            if sc.status in ("EXPLOITABLE_PATH", "PARTIALLY_GUARDED"):
                s6_ev.append(
                    PastaEvidenceItem(
                        id=f"p6-ev-{_slugify(sc.id, 22)}",
                        stage_number=6,
                        verdict="GAP",
                        severity=sc.severity if sc.status == "EXPLOITABLE_PATH" else "MEDIUM",
                        title=f"[{sc.status}] {sc.title}",
                        detail=sc.narrative[:240],
                        filepath=sc.primary_filepath,
                        line=sc.primary_line,
                        cwe_or_capec=sc.mitre_capec,
                        stride_cross_ref=f"STRIDE-{sc.stride_letter}",
                        linked_finding_id=sc.linked_finding_id,
                    )
                )
        stage_6 = self._finalize_stage(
            6,
            "PASTA-6",
            "VI",
            "Attack Modeling & Simulation (AMS)",
            "Construct multi-hop Entrypoint -> CAPEC -> Propagation -> Sink -> Crown Jewel attack trees and BFL severance points.",
            f"Simulated {len(attack_trees)} scenario(s): {len(exploitable_trees)} exploitable, {len(guarded_trees)} partially guarded, {len(severed_trees)} severed.",
            s6_ev,
        )

        # Stage 7: Risk & Impact Analysis (RIA)
        s7_ev: List[PastaEvidenceItem] = [
            PastaEvidenceItem(
                id="p7-ev-risk-progression",
                stage_number=7,
                verdict="OK" if mandatory_count == 0 else "GAP",
                severity="PASS" if mandatory_count == 0 else ("CRITICAL" if residual_score >= 75 else "HIGH"),
                title=(
                    f"Verdict: {golive_verdict_label} "
                    f"(Inherent {inherent_score} -> Residual {residual_score} -> Projected {projected_score})"
                ),
                detail=(
                    f"Mandatory Pre-Go-Live blockers: {mandatory_count}; "
                    f"Post-Go-Live SLA items: {sla_count}; Risk-accepted waivers: {waived_count}."
                ),
                filepath=sample_root_fp,
                line=1,
                cwe_or_capec=effective_preset,
                stride_cross_ref="GO-LIVE-GATE",
            ),
        ]
        if mandatory_count == 0:
            s7_ev.append(
                PastaEvidenceItem(
                    id="p7-ev-gate-clear",
                    stage_number=7,
                    verdict="OK",
                    severity="PASS",
                    title="Zero Mandatory Pre-Go-Live Blockers Open",
                    detail="All remaining observations (if any) are governed by post-launch SLA windows and compensating controls.",
                    filepath=sample_root_fp,
                    line=1,
                    cwe_or_capec="SAR-GATE",
                    stride_cross_ref="PASS",
                )
            )
        else:
            for blk in mandatory_obs[:8]:
                s7_ev.append(
                    PastaEvidenceItem(
                        id=f"p7-ev-blk-{_slugify(blk.id, 20)}",
                        stage_number=7,
                        verdict="GAP",
                        severity=blk.severity,
                        title=f"[PRE_LAUNCH BLOCKER] {blk.title}",
                        detail=f"`{blk.filepath}:L{blk.line}` — {blk.mandatory_fix_action[:180]}",
                        filepath=blk.filepath,
                        line=blk.line,
                        cwe_or_capec=blk.cwe_or_standard,
                        stride_cross_ref=f"STRIDE-{blk.stride_letter}",
                        linked_finding_id=blk.linked_finding_id,
                    )
                )
        stage_7 = self._finalize_stage(
            7,
            "PASTA-7",
            "VII",
            "Risk & Impact Analysis (RIA)",
            "Quantify Inherent, Residual, and Projected Go-Live risk across weighted Crown Jewels and enforce Go-Live Gate SLAs.",
            f"{golive_verdict_label}: Inherent={inherent_score}/100 ({inherent_level}), Residual={residual_score}/100 ({residual_level}), Projected={projected_score}/100 ({projected_level}).",
            s7_ev,
        )

        stages = [stage_1, stage_2, stage_3, stage_4, stage_5, stage_6, stage_7]
        passing_controls_count = sum(st.ok_count for st in stages)

        # Build ordered "Make It Live" Checklist (Phase A + Phase B + Final Verification Gate)
        checklist: List[str] = []
        if mandatory_obs:
            for idx_m, blk in enumerate(mandatory_obs, start=1):
                checklist.append(
                    f"[Phase A • Pre-Launch Mandatory #{idx_m}] Remediate `{blk.title}` at `{blk.filepath}:L{blk.line}` "
                    f"({blk.cwe_or_standard}) — {blk.mandatory_fix_action} [Owner: {blk.raci_owner}]."
                )
        else:
            checklist.append(
                "[Phase A • Pre-Launch Mandatory] PASS — 0 Mandatory Pre-Go-Live blockers open; pre-launch code gate satisfied."
            )

        if sla_obs:
            for idx_s, s_item in enumerate(sla_obs, start=1):
                checklist.append(
                    f"[Phase B • Post-Go-Live SLA ({s_item.sla_window}) #{idx_s}] Activate compensating control for "
                    f"`{s_item.title}` (`{s_item.filepath}:L{s_item.line}`): {s_item.compensating_control} [Owner: {s_item.raci_owner}]."
                )
        else:
            checklist.append(
                "[Phase B • Post-Go-Live SLA] PASS — 0 deferred Post-Go-Live SLA items pending."
            )

        if waived_obs:
            checklist.append(
                f"[Phase B • Governance Waiver] Verify documented CISO risk-acceptance sign-off and telemetry alerts for "
                f"{waived_count} waived observation(s)."
            )

        checklist.append(
            f"[Final Verification Gate] Re-run ALASTOR 7-Stage PASTA + Secret Vault scan to verify residual risk "
            f"reaches projected target ({projected_score}/100 {projected_level}) and archive signed SAR Go-Live Report ({golive_verdict_label})."
        )

        exec_summary = (
            f"7-Stage PASTA Security Assessment for `{app_name}` under `{effective_preset}` ({', '.join(frameworks[:3])}): "
            f"Inherent Risk {inherent_score}/100 ({inherent_level}) -> Current Residual Risk {residual_score}/100 ({residual_level}) -> "
            f"Projected Go-Live Risk {projected_score}/100 ({projected_level}). "
            f"Gate Verdict: {golive_verdict_label} ({mandatory_count} Mandatory Pre-Launch, {sla_count} Post-Go-Live SLA, "
            f"{waived_count} Waived, {passing_controls_count} Passing Control Checks; Crown Jewel peak weight "
            f"{max(jewel_weight_map.values()) if jewel_weight_map else 1.8:.2f}x)."
        )

        return PastaAssessmentResponse(
            project_path=abs_target,
            application_name=app_name,
            generated_at=now_iso,
            selected_business_preset=selected_preset,
            effective_business_preset=effective_preset,
            inferred_business_reason=business_reason,
            compliance_frameworks=frameworks,
            crown_jewels=crown_jewels,
            inherent_risk_score=inherent_score,
            inherent_risk_level=inherent_level,
            residual_risk_score=residual_score,
            residual_risk_level=residual_level,
            projected_golive_risk_score=projected_score,
            projected_golive_risk_level=projected_level,
            golive_verdict=golive_verdict,
            golive_verdict_label=golive_verdict_label,
            golive_executive_summary=exec_summary,
            mandatory_pre_golive_count=mandatory_count,
            post_golive_sla_count=sla_count,
            waived_count=waived_count,
            passing_controls_count=passing_controls_count,
            stages=stages,
            attack_trees=attack_trees,
            golive_observations=golive_observations,
            make_it_live_checklist=checklist,
        )


_default_pasta_engine: Optional[PastaThreatEngine] = None


def get_pasta_threat_engine() -> PastaThreatEngine:
    global _default_pasta_engine
    if _default_pasta_engine is None:
        _default_pasta_engine = PastaThreatEngine()
    return _default_pasta_engine
