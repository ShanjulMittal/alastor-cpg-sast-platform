"""
ALASTOR v5.0 Pillar 5 — Continuous Compliance Autopilot & Custom Rule Studio.

Provides:
1. Deterministic Continuous Compliance Autopilot across 5 frameworks:
   - PCI-DSS v4.0 (`PCI_DSS_4_0`)
   - SOC 2 Type II (`SOC2`)
   - ISO/IEC 27001:2022 (`ISO_27001`)
   - HIPAA Security Rule (`HIPAA`)
   - OWASP ASVS 5.0 (`OWASP_ASVS_5_0`)
   Uses exact canonical `CWE-\\d+` token matching (never substring matching such as
   `CWE-79` inside `CWE-798`), boundary-safe rule prefix matching, EV runtime exploit
   confirmation enforcement, and clean-SCA enforcement.
2. ReDoS-safe regex validator (`validate_custom_rule_regex`) blocking oversized patterns,
   backreferences, nested quantifiers, overlapping quantified alternations, and
   quantified/quantifier-bearing lookarounds.
3. Atomic vault persistence & live sandbox/workspace evaluation (`CustomRuleEngine`)
   with `PolyglotScopeWalker` (`scan_directory_with_telemetry`), symlink/junction
   confinement, anti-pattern suppression, and `scrub_raw_secrets_text` redaction.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from compiler.language_registry import LANGUAGE_SPECS
from compiler.scanner import ScannedFile, scan_directory_with_telemetry
from engine.enterprise_manager import infer_language_from_filepath
from engine.frontier_ai_engine import scrub_raw_secrets_text
from engine.hostile_repo_guard import HostileRepoError, is_link_or_junction
from models import (
    BestFixLocation,
    ComplianceControlResult,
    ComplianceEvaluateResponse,
    ComplianceFrameworkId,
    ComplianceFrameworkReport,
    CustomRuleMatchItem,
    CustomRuleTestRequest,
    CustomRuleTestResponse,
    CustomSecurityRule,
    Finding,
)

logger = logging.getLogger("cpg-sast.compliance-rules")

_CUSTOM_RULES_FILENAME = "custom_rules.json"
_MAX_REGEX_LENGTH = 400
_MAX_SCAN_LINES_PER_FILE = 10_000
_MAX_SCAN_CHARS_PER_LINE = 2_000
_MAX_TEST_MATCHES = 500
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
_CWE_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])CWE-0*(\d+)(?!\d)", re.IGNORECASE)

_re_parser = getattr(re, "_parser", None)
if _re_parser is None:  # pragma: no cover
    import sre_parse as _re_parser  # type: ignore[no-redef]

_REPEAT_OPS = frozenset(
    op
    for op in (
        getattr(_re_parser, "MAX_REPEAT", None),
        getattr(_re_parser, "MIN_REPEAT", None),
        getattr(_re_parser, "POSSESSIVE_REPEAT", None),
    )
    if op is not None
)
_BACKREF_OPS = frozenset(
    op
    for op in (
        getattr(_re_parser, "GROUPREF", None),
        getattr(_re_parser, "GROUPREF_EXISTS", None),
        getattr(_re_parser, "GROUPREF_IGNORE", None),
        getattr(_re_parser, "GROUPREF_LOC_IGNORE", None),
        getattr(_re_parser, "GROUPREF_UNI_IGNORE", None),
    )
    if op is not None
)
_LOOKAROUND_OPS = frozenset(
    op
    for op in (
        getattr(_re_parser, "ASSERT", None),
        getattr(_re_parser, "ASSERT_NOT", None),
    )
    if op is not None
)
_LITERAL_OPS = frozenset(
    op
    for op in (
        getattr(_re_parser, "LITERAL", None),
        getattr(_re_parser, "LITERAL_IGNORE", None),
        getattr(_re_parser, "LITERAL_LOC_IGNORE", None),
        getattr(_re_parser, "LITERAL_UNI_IGNORE", None),
    )
    if op is not None
)
_NOT_LITERAL_OPS = frozenset(
    op
    for op in (
        getattr(_re_parser, "NOT_LITERAL", None),
        getattr(_re_parser, "NOT_LITERAL_IGNORE", None),
        getattr(_re_parser, "NOT_LITERAL_LOC_IGNORE", None),
        getattr(_re_parser, "NOT_LITERAL_UNI_IGNORE", None),
    )
    if op is not None
)
_SUBPATTERN_OP = getattr(_re_parser, "SUBPATTERN")
_BRANCH_OP = getattr(_re_parser, "BRANCH")
_ANY_OP = getattr(_re_parser, "ANY")
_IN_OP = getattr(_re_parser, "IN")
_CATEGORY_OP = getattr(_re_parser, "CATEGORY")
_RANGE_OP = getattr(_re_parser, "RANGE")
_NEGATE_OP = getattr(_re_parser, "NEGATE")
_AT_OP = getattr(_re_parser, "AT")
_ATOMIC_GROUP_OP = getattr(_re_parser, "ATOMIC_GROUP", None)
_MAXREPEAT = _re_parser.MAXREPEAT
_IGNORECASE_FLAG = getattr(re, "IGNORECASE", 2)

_LANGUAGE_ALIASES: Dict[str, Tuple[str, ...]] = {
    "python": ("python",),
    "py": ("python",),
    "javascript": ("javascript",),
    "js": ("javascript",),
    "typescript": ("typescript", "tsx"),
    "ts": ("typescript", "tsx"),
    "tsx": ("tsx", "typescript"),
    "go": ("go",),
    "golang": ("go",),
    "java": ("java",),
    "c": ("c",),
    "cpp": ("cpp", "c"),
    "c++": ("cpp", "c"),
    "csharp": ("csharp",),
    "c#": ("csharp",),
    "rust": ("rust",),
    "ruby": ("ruby",),
    "php": ("php",),
    "kotlin": ("kotlin",),
    "swift": ("swift",),
    "solidity": ("solidity",),
    "terraform": ("hcl", "terraform"),
    "hcl": ("hcl",),
    "yaml": ("yaml",),
    "dockerfile": ("dockerfile",),
    "shell": ("bash", "shell"),
    "bash": ("bash",),
    "html": ("web_template", "html"),
    "web_template": ("web_template",),
}

_LANGUAGE_TO_SAMPLE_EXT: Dict[str, str] = {
    "python": "py",
    "javascript": "js",
    "typescript": "ts",
    "tsx": "tsx",
    "go": "go",
    "java": "java",
    "c": "c",
    "cpp": "cpp",
    "csharp": "cs",
    "rust": "rs",
    "ruby": "rb",
    "php": "php",
    "kotlin": "kt",
    "swift": "swift",
    "solidity": "sol",
    "yaml": "yml",
    "bash": "sh",
    "shell": "sh",
}

_DEFAULT_FRAMEWORKS_ORDER: Tuple[ComplianceFrameworkId, ...] = (
    "PCI_DSS_4_0",
    "SOC2",
    "ISO_27001",
    "HIPAA",
    "OWASP_ASVS_5_0",
)


@dataclass(frozen=True)
class _ComplianceControlSpec:
    control_id: str
    title: str
    description: str
    mapped_cwes: FrozenSet[str]
    mapped_rule_prefixes: Tuple[str, ...] = ()
    requires_no_ev_confirmed: bool = False
    requires_clean_sca: bool = False


@dataclass(frozen=True)
class _ComplianceFrameworkSpec:
    framework_id: ComplianceFrameworkId
    framework_name: str
    version: str
    controls: Tuple[_ComplianceControlSpec, ...]


COMPLIANCE_FRAMEWORK_CATALOGS: Dict[ComplianceFrameworkId, _ComplianceFrameworkSpec] = {
    "PCI_DSS_4_0": _ComplianceFrameworkSpec(
        framework_id="PCI_DSS_4_0",
        framework_name="PCI-DSS v4.0",
        version="4.0",
        controls=(
            _ComplianceControlSpec(
                control_id="PCI-6.2.4",
                title="Prevention of Common Injection & SSRF Attacks",
                description="Prevent SQL injection, OS command injection, code injection, XXE, and SSRF across payment paths.",
                mapped_cwes=frozenset({"CWE-89", "CWE-78", "CWE-94", "CWE-77", "CWE-611", "CWE-918"}),
                mapped_rule_prefixes=("RULE-1-", "RULE-6-", "RULE-7-", "RULE-11-", "RULE-14-", "RULE-15-", "RULE-26-", "RULE-27-", "RULE-29-"),
            ),
            _ComplianceControlSpec(
                control_id="PCI-6.4.1",
                title="Web-Facing Script Integrity & XSS Output Encoding",
                description="Enforce contextual output encoding, CSP/CSRF defenses, and DOM sanitization against XSS and SSTI.",
                mapped_cwes=frozenset({"CWE-79", "CWE-1336", "CWE-352", "CWE-942"}),
                mapped_rule_prefixes=("RULE-9-", "RULE-32-", "RULE-33-", "COG-3-"),
            ),
            _ComplianceControlSpec(
                control_id="PCI-6.3.1",
                title="Third-Party Component & Dependency Vulnerability Management",
                description="Maintain pinned, CVE-free third-party dependencies and lockfiles via continuous SCA auditing.",
                mapped_cwes=frozenset({"CWE-1395", "CWE-1104"}),
                mapped_rule_prefixes=("SCA-",),
                requires_clean_sca=True,
            ),
            _ComplianceControlSpec(
                control_id="PCI-8.6.2",
                title="Prohibition of Hardcoded Passwords & Cryptographic Keys",
                description="Eliminate embedded secrets, API credentials, weak ciphers, and improper TLS verification.",
                mapped_cwes=frozenset({"CWE-798", "CWE-259", "CWE-321", "CWE-327", "CWE-328", "CWE-330", "CWE-295", "CWE-200", "CWE-532"}),
                mapped_rule_prefixes=("RULE-8-", "RULE-16-", "SECRET-", "COG-4-"),
            ),
            _ComplianceControlSpec(
                control_id="PCI-2.2.1",
                title="Secure System, Access Control & IaC Configuration",
                description="Enforce path confinement, authorization checks, safe deserialization, and least-privilege IaC.",
                mapped_cwes=frozenset({"CWE-22", "CWE-250", "CWE-284", "CWE-287", "CWE-639", "CWE-16", "CWE-502"}),
                mapped_rule_prefixes=("RULE-10-", "RULE-13-", "RULE-28-", "IAC-", "COG-1-"),
            ),
            _ComplianceControlSpec(
                control_id="PCI-11.3.1",
                title="Exploit Verification & High-Risk Code Elimination",
                description="Confirm zero runtime-exploitable vulnerabilities and remove dormant backdoors, unbounded loops, and memory flaws.",
                mapped_cwes=frozenset({"CWE-489", "CWE-561", "CWE-563", "CWE-835", "CWE-120", "CWE-787"}),
                mapped_rule_prefixes=("RULE-2-", "RULE-3-", "RULE-4-", "RULE-5-", "RULE-22-"),
                requires_no_ev_confirmed=True,
            ),
        ),
    ),
    "SOC2": _ComplianceFrameworkSpec(
        framework_id="SOC2",
        framework_name="SOC 2 Type II (Trust Services Criteria)",
        version="2017/2022",
        controls=(
            _ComplianceControlSpec(
                control_id="CC6.1",
                title="Logical Access Security & Secret Protection",
                description="Protect credentials, API keys, and object-level authorization boundaries against unauthorized access.",
                mapped_cwes=frozenset({"CWE-798", "CWE-287", "CWE-284", "CWE-639", "CWE-259", "CWE-321"}),
                mapped_rule_prefixes=("RULE-8-", "SECRET-", "COG-1-"),
            ),
            _ComplianceControlSpec(
                control_id="CC6.6",
                title="Boundary Protection Against Injection & Traversal",
                description="Protect system boundaries from SQL injection, command execution, SSRF, XXE, and path traversal.",
                mapped_cwes=frozenset({"CWE-89", "CWE-78", "CWE-94", "CWE-918", "CWE-611", "CWE-22"}),
                mapped_rule_prefixes=("RULE-1-", "RULE-6-", "RULE-7-", "RULE-10-", "RULE-11-", "RULE-14-", "RULE-15-", "RULE-26-", "RULE-27-"),
            ),
            _ComplianceControlSpec(
                control_id="CC6.7",
                title="Transmission Confidentiality & Cryptographic Integrity",
                description="Enforce strong cryptography, TLS certificate verification, and sensitive data redaction in logs.",
                mapped_cwes=frozenset({"CWE-295", "CWE-327", "CWE-328", "CWE-330", "CWE-200", "CWE-532"}),
                mapped_rule_prefixes=("RULE-12-", "RULE-16-", "COG-4-"),
            ),
            _ComplianceControlSpec(
                control_id="CC6.8",
                title="Malicious Input, XSS & Deserialization Controls",
                description="Prevent cross-site scripting, template injection, CSRF, and untrusted object deserialization.",
                mapped_cwes=frozenset({"CWE-79", "CWE-1336", "CWE-352", "CWE-502", "CWE-942"}),
                mapped_rule_prefixes=("RULE-9-", "RULE-13-", "RULE-28-", "RULE-32-", "RULE-33-", "COG-3-"),
            ),
            _ComplianceControlSpec(
                control_id="CC7.1",
                title="Vulnerability & Supply-Chain Component Monitoring",
                description="Detect vulnerable third-party packages and insecure infrastructure-as-code definitions.",
                mapped_cwes=frozenset({"CWE-1395", "CWE-1104", "CWE-250", "CWE-16"}),
                mapped_rule_prefixes=("SCA-", "IAC-"),
                requires_clean_sca=True,
            ),
            _ComplianceControlSpec(
                control_id="CC7.2",
                title="Runtime Exploitability & Business-Logic Assurance",
                description="Ensure zero confirmed runtime exploits, race conditions, or availability denial defects.",
                mapped_cwes=frozenset({"CWE-362", "CWE-400", "CWE-835", "CWE-840"}),
                mapped_rule_prefixes=("RULE-4-", "COG-2-"),
                requires_no_ev_confirmed=True,
            ),
        ),
    ),
    "ISO_27001": _ComplianceFrameworkSpec(
        framework_id="ISO_27001",
        framework_name="ISO/IEC 27001:2022",
        version="2022",
        controls=(
            _ComplianceControlSpec(
                control_id="A.8.24",
                title="Use of Cryptography & Key Management",
                description="Protect cryptographic keys, credentials, and randomness generators against disclosure or weak ciphers.",
                mapped_cwes=frozenset({"CWE-798", "CWE-259", "CWE-321", "CWE-327", "CWE-328", "CWE-330", "CWE-295"}),
                mapped_rule_prefixes=("RULE-8-", "RULE-16-", "SECRET-"),
            ),
            _ComplianceControlSpec(
                control_id="A.8.26",
                title="Application Security Requirements (Injection & Integrity)",
                description="Enforce parameterized queries, safe command execution, SSRF guards, and safe deserialization.",
                mapped_cwes=frozenset({"CWE-89", "CWE-78", "CWE-94", "CWE-22", "CWE-918", "CWE-611", "CWE-502"}),
                mapped_rule_prefixes=("RULE-1-", "RULE-6-", "RULE-7-", "RULE-10-", "RULE-11-", "RULE-13-", "RULE-14-", "RULE-15-", "RULE-26-", "RULE-27-", "RULE-28-"),
            ),
            _ComplianceControlSpec(
                control_id="A.8.28",
                title="Secure Coding & Client-Side Output Validation",
                description="Apply secure coding standards eliminating XSS, SSTI, CSRF, and native memory safety flaws.",
                mapped_cwes=frozenset({"CWE-79", "CWE-1336", "CWE-352", "CWE-942", "CWE-120", "CWE-134", "CWE-416", "CWE-242"}),
                mapped_rule_prefixes=("RULE-9-", "RULE-22-", "RULE-23-", "RULE-24-", "RULE-25-", "RULE-32-", "RULE-33-", "COG-3-"),
            ),
            _ComplianceControlSpec(
                control_id="A.8.3",
                title="Information Access Restriction & Authorization",
                description="Enforce object-level authorization and prevent sensitive data leakage in responses or logs.",
                mapped_cwes=frozenset({"CWE-284", "CWE-287", "CWE-639", "CWE-200", "CWE-532"}),
                mapped_rule_prefixes=("COG-1-", "COG-4-", "RULE-31-"),
            ),
            _ComplianceControlSpec(
                control_id="A.8.8",
                title="Management of Technical Vulnerabilities",
                description="Remediate known vulnerable third-party libraries and container/IaC misconfigurations.",
                mapped_cwes=frozenset({"CWE-1395", "CWE-1104", "CWE-250", "CWE-16"}),
                mapped_rule_prefixes=("SCA-", "IAC-"),
                requires_clean_sca=True,
            ),
            _ComplianceControlSpec(
                control_id="A.8.29",
                title="Security Testing in Development & Verification",
                description="Verify absence of runtime-exploitable flaws, race conditions, dead stores, and infinite loops.",
                mapped_cwes=frozenset({"CWE-489", "CWE-561", "CWE-563", "CWE-835", "CWE-362"}),
                mapped_rule_prefixes=("RULE-2-", "RULE-3-", "RULE-4-", "RULE-5-", "COG-2-"),
                requires_no_ev_confirmed=True,
            ),
        ),
    ),
    "HIPAA": _ComplianceFrameworkSpec(
        framework_id="HIPAA",
        framework_name="HIPAA Security Rule",
        version="45 CFR Part 164",
        controls=(
            _ComplianceControlSpec(
                control_id="164.312(a)(1)",
                title="Access Control & ePHI Boundary Protection",
                description="Prevent unauthorized ePHI extraction via SQL injection, path traversal, or missing authorization checks.",
                mapped_cwes=frozenset({"CWE-284", "CWE-287", "CWE-639", "CWE-22", "CWE-89"}),
                mapped_rule_prefixes=("RULE-7-", "RULE-10-", "RULE-26-", "COG-1-"),
            ),
            _ComplianceControlSpec(
                control_id="164.312(a)(2)(iv)",
                title="Encryption, Secrets & Cryptographic Safeguards",
                description="Protect ePHI secrets and keys by prohibiting hardcoded credentials and weak cryptographic primitives.",
                mapped_cwes=frozenset({"CWE-798", "CWE-259", "CWE-321", "CWE-327", "CWE-328", "CWE-330"}),
                mapped_rule_prefixes=("RULE-8-", "RULE-16-", "SECRET-"),
            ),
            _ComplianceControlSpec(
                control_id="164.312(b)",
                title="Audit Controls & Sensitive ePHI Disclosure Prevention",
                description="Prevent log injection and accidental exposure of sensitive ePHI or credentials in telemetry.",
                mapped_cwes=frozenset({"CWE-117", "CWE-200", "CWE-532"}),
                mapped_rule_prefixes=("RULE-12-", "COG-4-"),
            ),
            _ComplianceControlSpec(
                control_id="164.312(c)(1)",
                title="Integrity Controls (Code Execution, XSS & Deserialization)",
                description="Ensure electronic PHI is not improperly altered via XSS, command injection, or unsafe deserialization.",
                mapped_cwes=frozenset({"CWE-79", "CWE-1336", "CWE-502", "CWE-94", "CWE-78", "CWE-611"}),
                mapped_rule_prefixes=("RULE-1-", "RULE-6-", "RULE-9-", "RULE-13-", "RULE-14-", "RULE-15-", "RULE-27-", "RULE-28-", "RULE-32-"),
            ),
            _ComplianceControlSpec(
                control_id="164.312(e)(1)",
                title="Transmission Security & Network Isolation",
                description="Enforce TLS certificate validation, origin restrictions, CSRF protection, and SSRF controls.",
                mapped_cwes=frozenset({"CWE-295", "CWE-918", "CWE-942", "CWE-352"}),
                mapped_rule_prefixes=("RULE-11-", "RULE-33-", "COG-3-"),
            ),
            _ComplianceControlSpec(
                control_id="164.308(a)(8)",
                title="Technical Evaluation, SCA & Runtime Exploit Assurance",
                description="Maintain clean third-party dependencies, hardened runtime containers, and zero confirmed exploits.",
                mapped_cwes=frozenset({"CWE-1395", "CWE-1104", "CWE-250", "CWE-835"}),
                mapped_rule_prefixes=("SCA-", "IAC-", "RULE-4-"),
                requires_no_ev_confirmed=True,
                requires_clean_sca=True,
            ),
        ),
    ),
    "OWASP_ASVS_5_0": _ComplianceFrameworkSpec(
        framework_id="OWASP_ASVS_5_0",
        framework_name="OWASP ASVS",
        version="5.0",
        controls=(
            _ComplianceControlSpec(
                control_id="V2.1",
                title="Authentication & Credential Storage Architecture",
                description="Verify absence of hardcoded secrets, default passwords, and broken authentication mechanisms.",
                mapped_cwes=frozenset({"CWE-798", "CWE-259", "CWE-287", "CWE-321"}),
                mapped_rule_prefixes=("RULE-8-", "SECRET-"),
            ),
            _ComplianceControlSpec(
                control_id="V4.1",
                title="Access Control & Anti-IDOR/BOLA Design",
                description="Verify function-level and object-level access controls, path confinement, CORS, and CSRF protections.",
                mapped_cwes=frozenset({"CWE-284", "CWE-639", "CWE-22", "CWE-352", "CWE-942"}),
                mapped_rule_prefixes=("RULE-10-", "RULE-33-", "COG-1-", "COG-3-"),
            ),
            _ComplianceControlSpec(
                control_id="V5.3",
                title="Injection Prevention (SQLi, CMDi, Code, SSRF, Deserialization)",
                description="Verify parameterized data access, safe process invocation, XXE/deserialization safety, and SSRF guards.",
                mapped_cwes=frozenset({"CWE-89", "CWE-78", "CWE-94", "CWE-77", "CWE-918", "CWE-611", "CWE-502"}),
                mapped_rule_prefixes=("RULE-1-", "RULE-6-", "RULE-7-", "RULE-11-", "RULE-13-", "RULE-14-", "RULE-15-", "RULE-26-", "RULE-27-", "RULE-28-", "RULE-29-"),
            ),
            _ComplianceControlSpec(
                control_id="V5.2",
                title="Sanitization, Client-Side XSS & Template Escaping",
                description="Verify contextual output encoding and DOM sanitization to eliminate reflected, stored, and DOM XSS.",
                mapped_cwes=frozenset({"CWE-79", "CWE-1336"}),
                mapped_rule_prefixes=("RULE-9-", "RULE-32-", "COG-5-"),
            ),
            _ComplianceControlSpec(
                control_id="V6.2",
                title="Cryptography, Randomness & Sensitive Data Protection",
                description="Verify modern cryptography, CSPRNG usage, TLS verification, and redaction of sensitive data.",
                mapped_cwes=frozenset({"CWE-327", "CWE-328", "CWE-330", "CWE-295", "CWE-200", "CWE-532"}),
                mapped_rule_prefixes=("RULE-16-", "COG-4-"),
            ),
            _ComplianceControlSpec(
                control_id="V14.2",
                title="Dependency Supply Chain, Configuration & Exploit Verification",
                description="Verify clean lockfile dependencies, hardened deployment manifests, and zero runtime-exploitable defects.",
                mapped_cwes=frozenset({"CWE-1395", "CWE-1104", "CWE-250", "CWE-16", "CWE-400", "CWE-835"}),
                mapped_rule_prefixes=("SCA-", "IAC-", "RULE-4-"),
                requires_no_ev_confirmed=True,
                requires_clean_sca=True,
            ),
        ),
    ),
}


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_canonical_cwes(cwe_raw: Optional[str]) -> Set[str]:
    if not cwe_raw:
        return set()
    return {f"CWE-{int(num)}" for num in _CWE_TOKEN_RE.findall(str(cwe_raw).upper())}


def _matches_rule_prefix(rule_id: Optional[str], prefixes: Tuple[str, ...]) -> bool:
    if not rule_id or not prefixes:
        return False
    rule_up = str(rule_id).strip().upper()
    for raw_prefix in prefixes:
        pref = raw_prefix.strip().upper()
        if not pref:
            continue
        if pref.endswith(("-", "_")):
            if rule_up.startswith(pref):
                return True
        elif rule_up == pref or rule_up.startswith(f"{pref}-") or rule_up.startswith(f"{pref}_"):
            return True
    return False


def _evaluate_control(
    spec: _ComplianceControlSpec,
    active_findings: Sequence[Finding],
    extra_raw_secrets: Sequence[str],
) -> ComplianceControlResult:
    matched: List[Finding] = []
    matched_cwes: Set[str] = set()

    for finding in active_findings:
        f_cwes = _extract_canonical_cwes(finding.cwe_id)
        cwe_hit = f_cwes & spec.mapped_cwes
        prefix_hit = _matches_rule_prefix(finding.rule_id, spec.mapped_rule_prefixes)
        ev_hit = spec.requires_no_ev_confirmed and finding.ev_status == "RUNTIME_EXPLOIT_CONFIRMED"
        sca_hit = spec.requires_clean_sca and (
            finding.scan_engine == "SCA" or (finding.rule_id or "").upper().startswith("SCA-")
        )

        if cwe_hit or prefix_hit or ev_hit or sca_hit:
            matched.append(finding)
            matched_cwes.update(cwe_hit)

    if not matched:
        return ComplianceControlResult(
            control_id=spec.control_id,
            title=spec.title,
            description=spec.description,
            status="PASS",
            matched_finding_ids=[],
            matched_cwes=[],
            evidence_summary="No active security findings violate this control.",
        )

    is_fail = any(
        str(f.severity or "").upper() in ("CRITICAL", "HIGH")
        or f.ev_status == "RUNTIME_EXPLOIT_CONFIRMED"
        for f in matched
    )
    status = "FAIL" if is_fail else "WARNING"

    matched_ids = [f.id for f in matched]
    sorted_cwes = sorted(matched_cwes)
    sample_parts: List[str] = []
    for f in matched[:5]:
        sev = str(f.severity or "MEDIUM").upper()
        ev_tag = " [RUNTIME_EXPLOIT_CONFIRMED]" if f.ev_status == "RUNTIME_EXPLOIT_CONFIRMED" else ""
        safe_title = scrub_raw_secrets_text(f.title or f.rule_id, extra_raw_secrets=extra_raw_secrets)
        sample_parts.append(f"{f.rule_id} ({sev}{ev_tag}): {safe_title}")
    suffix = f" (+{len(matched) - 5} more)" if len(matched) > 5 else ""
    raw_summary = f"{len(matched)} finding(s) impacted [{'; '.join(sample_parts)}{suffix}]"
    evidence_summary = scrub_raw_secrets_text(raw_summary, extra_raw_secrets=extra_raw_secrets)[:600]

    return ComplianceControlResult(
        control_id=spec.control_id,
        title=spec.title,
        description=spec.description,
        status=status,  # type: ignore[arg-type]
        matched_finding_ids=matched_ids,
        matched_cwes=sorted_cwes,
        evidence_summary=evidence_summary,
    )


def evaluate_compliance(
    project_path: str,
    findings: Optional[Sequence[Finding]] = None,
    frameworks: Optional[List[ComplianceFrameworkId]] = None,
) -> ComplianceEvaluateResponse:
    """
    Deterministically evaluates active findings against 5 enterprise compliance
    frameworks (PCI-DSS 4.0, SOC 2, ISO 27001, HIPAA, OWASP ASVS 5.0).
    """
    if not isinstance(project_path, str) or not project_path.strip():
        raise ValueError("project_path must be a non-empty string.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in project_path):
        raise HostileRepoError("project_path contains forbidden control characters.")

    requested_ids: List[ComplianceFrameworkId] = []
    if frameworks:
        seen_fw: Set[str] = set()
        for fw_id in frameworks:
            if fw_id not in COMPLIANCE_FRAMEWORK_CATALOGS:
                raise ValueError(f"Unsupported compliance framework: {fw_id!r}")
            if fw_id not in seen_fw:
                seen_fw.add(fw_id)
                requested_ids.append(fw_id)
    else:
        requested_ids = list(_DEFAULT_FRAMEWORKS_ORDER)

    all_findings = list(findings or ())
    active_findings = [
        f for f in all_findings if f.triage_status not in ("NOT_EXPLOITABLE", "RESOLVED")
    ]
    extra_raw_secrets = [
        f.secret_value_raw
        for f in all_findings
        if isinstance(f.secret_value_raw, str) and len(f.secret_value_raw) >= 4
    ]

    reports: List[ComplianceFrameworkReport] = []
    for fw_id in requested_ids:
        fw_spec = COMPLIANCE_FRAMEWORK_CATALOGS[fw_id]
        control_results = [
            _evaluate_control(ctrl_spec, active_findings, extra_raw_secrets)
            for ctrl_spec in fw_spec.controls
        ]
        total_controls = len(control_results)
        passed_controls = sum(1 for c in control_results if c.status == "PASS")
        warning_controls = sum(1 for c in control_results if c.status == "WARNING")
        failed_controls = sum(1 for c in control_results if c.status == "FAIL")

        score_percent = round(
            ((passed_controls + 0.5 * warning_controls) / max(1, total_controls)) * 100.0,
            1,
        )
        if failed_controls > 0:
            fw_status = "NON_COMPLIANT"
        elif warning_controls > 0:
            fw_status = "AT_RISK"
        else:
            fw_status = "COMPLIANT"

        reports.append(
            ComplianceFrameworkReport(
                framework_id=fw_spec.framework_id,
                framework_name=fw_spec.framework_name,
                version=fw_spec.version,
                score_percent=score_percent,
                status=fw_status,  # type: ignore[arg-type]
                passed_controls=passed_controls,
                warning_controls=warning_controls,
                failed_controls=failed_controls,
                total_controls=total_controls,
                controls=control_results,
            )
        )

    overall_score = round(
        sum(r.score_percent for r in reports) / max(1, len(reports)),
        1,
    )

    return ComplianceEvaluateResponse(
        project_path=project_path.strip(),
        evaluated_at=_utc_iso_now(),
        total_findings_evaluated=len(all_findings),
        overall_score_percent=overall_score,
        frameworks=reports,
    )


# ---------------------------------------------------------------------------
# ReDoS-Safe Regex AST Validator (`re._parser` / `sre_parse`)
# ---------------------------------------------------------------------------
def _has_repeat_in_items(items: Sequence[Any]) -> bool:
    for op, av in items:
        if op in _REPEAT_OPS:
            return True
        if op == _SUBPATTERN_OP and _has_repeat_in_items(av[3]):
            return True
        if op == _BRANCH_OP and any(_has_repeat_in_items(arm) for arm in av[1]):
            return True
        if op in _LOOKAROUND_OPS and _has_repeat_in_items(av[1]):
            return True
        if _ATOMIC_GROUP_OP is not None and op == _ATOMIC_GROUP_OP and _has_repeat_in_items(av):
            return True
    return False


def _extract_branch_literal_prefix(
    branch_items: Sequence[Any],
    effective_flags: int,
) -> Optional[str]:
    """
    Extracts the normalized leading literal sequence for an alternation arm inside a
    quantified group. Returns `None` if the arm is empty or starts with a wildcard,
    character class, anchor, nested branch, or repeat (which cannot be proven disjoint).
    """
    items = list(branch_items)
    flags = effective_flags
    while len(items) == 1 and items[0][0] == _SUBPATTERN_OP:
        _, add_flags, del_flags, sub = items[0][1]
        flags = (flags | add_flags) & ~del_flags
        items = list(sub)

    if not items:
        return None

    chars: List[str] = []
    for idx, (op, av) in enumerate(items):
        if op == _SUBPATTERN_OP and idx == 0:
            sub_prefix = _extract_branch_literal_prefix(av[3], (flags | av[1]) & ~av[2])
            if not sub_prefix:
                return None
            return sub_prefix
        if op in _LITERAL_OPS:
            ch = chr(av)
            chars.append(ch.casefold() if (flags & _IGNORECASE_FLAG) else ch)
        elif idx == 0:
            return None
        else:
            break
    return "".join(chars) if chars else None


def _has_overlapping_ast_branches(branches: Sequence[Sequence[Any]], effective_flags: int) -> bool:
    if len(branches) <= 1:
        return False

    first_chars: Set[str] = set()
    prefixes: List[str] = []

    for arm in branches:
        prefix = _extract_branch_literal_prefix(arm, effective_flags)
        if not prefix:
            return True
        lead = prefix[0]
        if lead in first_chars:
            return True
        first_chars.add(lead)
        prefixes.append(prefix)

    for idx_a, pref_a in enumerate(prefixes):
        for idx_b, pref_b in enumerate(prefixes):
            if idx_a != idx_b and pref_b.startswith(pref_a):
                return True
    return False


def _match_category(cat_val: Any, ch: str) -> bool:
    name = str(cat_val)
    if "NOT_SPACE" in name:
        return not ch.isspace()
    if "SPACE" in name:
        return ch.isspace()
    if "NOT_DIGIT" in name:
        return not ch.isdigit()
    if "DIGIT" in name:
        return ch.isdigit()
    if "NOT_WORD" in name:
        return not (ch.isalnum() or ch == "_")
    if "WORD" in name:
        return ch.isalnum() or ch == "_"
    if "NOT_LINEBREAK" in name:
        return ch != "\n"
    if "LINEBREAK" in name:
        return ch == "\n"
    return True


def _atom_matches_char(op: Any, av: Any, ch: str, flags: int) -> bool:
    code = ord(ch)
    icase = bool(flags & _IGNORECASE_FLAG)
    if op == _ANY_OP:
        return True
    if op in _LITERAL_OPS:
        if icase:
            return ch.casefold() == chr(av).casefold()
        return code == av
    if op in _NOT_LITERAL_OPS:
        if icase:
            return ch.casefold() != chr(av).casefold()
        return code != av
    if op == _CATEGORY_OP:
        return _match_category(av, ch)
    if op == _IN_OP:
        negated = bool(av and av[0][0] == _NEGATE_OP)
        body = av[1:] if negated else av
        matched = False
        for item_op, item_av in body:
            if item_op in _LITERAL_OPS:
                if (ch.casefold() == chr(item_av).casefold()) if icase else (code == item_av):
                    matched = True
                    break
            elif item_op == _RANGE_OP:
                lo, hi = item_av
                if lo <= code <= hi:
                    matched = True
                    break
                if icase:
                    cf = ch.casefold()
                    if any(chr(c).casefold() == cf for c in range(lo, min(hi, lo + 256) + 1)):
                        matched = True
                        break
            elif item_op == _CATEGORY_OP:
                if _match_category(item_av, ch):
                    matched = True
                    break
            else:
                return True
        return (not matched) if negated else matched
    return True


def _single_char_atom_from_repeat(sub_items: Sequence[Any], flags: int) -> Optional[Tuple[Any, Any, int]]:
    cur_items = list(sub_items)
    cur_flags = flags
    while len(cur_items) == 1 and cur_items[0][0] == _SUBPATTERN_OP:
        _, add_f, del_f, inner = cur_items[0][1]
        cur_flags = (cur_flags | add_f) & ~del_f
        cur_items = list(inner)
    if len(cur_items) != 1:
        return None
    op, av = cur_items[0]
    if op in (_ANY_OP, _IN_OP, _CATEGORY_OP) or op in _LITERAL_OPS or op in _NOT_LITERAL_OPS:
        return op, av, cur_flags
    return None


def _items_can_overlap(
    atom_a: Optional[Tuple[Any, Any, int]],
    atom_b: Optional[Tuple[Any, Any, int]],
) -> bool:
    if atom_a is None or atom_b is None:
        return True
    op_a, av_a, flags_a = atom_a
    op_b, av_b, flags_b = atom_b
    if op_a == _ANY_OP or op_b == _ANY_OP:
        return True
    sample_codes = list(range(128))
    for op_x, av_x in ((op_a, av_a), (op_b, av_b)):
        if (op_x in _LITERAL_OPS or op_x in _NOT_LITERAL_OPS) and av_x >= 128:
            sample_codes.append(av_x)
    return any(
        _atom_matches_char(op_a, av_a, chr(c), flags_a)
        and _atom_matches_char(op_b, av_b, chr(c), flags_b)
        for c in sample_codes
    )


def _flatten_sequence_with_flags(
    items: Sequence[Any],
    flags: int,
) -> List[Tuple[Any, Any, int]]:
    flat: List[Tuple[Any, Any, int]] = []
    for op, av in items:
        if op == _SUBPATTERN_OP:
            _, add_f, del_f, sub = av
            sub_flags = (flags | add_f) & ~del_f
            # Flatten linear subpatterns; keep branches isolated at branch boundaries
            if not any(s_op == _BRANCH_OP for s_op, _ in sub):
                flat.extend(_flatten_sequence_with_flags(sub, sub_flags))
                continue
        flat.append((op, av, flags))
    return flat


def _validate_sequence_unbounded_repeats(
    items: Sequence[Any],
    effective_flags: int,
) -> None:
    flat = _flatten_sequence_with_flags(items, effective_flags)
    unbounded_positions: List[Tuple[int, Optional[Tuple[Any, Any, int]]]] = []

    for idx, (op, av, item_flags) in enumerate(flat):
        if op in _REPEAT_OPS and av[1] == _MAXREPEAT:
            unbounded_positions.append((idx, _single_char_atom_from_repeat(av[2], item_flags)))

    if len(unbounded_positions) > 2:
        raise ValueError(
            "Too many sequential unbounded repeats (> 2) are disallowed for ReDoS safety."
        )

    for pair_idx in range(len(unbounded_positions) - 1):
        prev_pos, prev_atom = unbounded_positions[pair_idx]
        curr_pos, curr_atom = unbounded_positions[pair_idx + 1]
        if not _items_can_overlap(prev_atom, curr_atom):
            continue

        # Check whether any mandatory non-overlapping literal/atom separates prev and curr
        has_non_overlapping_barrier = False
        for mid_op, mid_av, mid_flags in flat[prev_pos + 1 : curr_pos]:
            if mid_op == _AT_OP:
                continue
            if mid_op in _REPEAT_OPS and mid_av[0] == 0:
                continue
            mid_atom = (
                _single_char_atom_from_repeat(mid_av[2], mid_flags)
                if mid_op in _REPEAT_OPS
                else (
                    (mid_op, mid_av, mid_flags)
                    if (
                        mid_op in (_ANY_OP, _IN_OP, _CATEGORY_OP)
                        or mid_op in _LITERAL_OPS
                        or mid_op in _NOT_LITERAL_OPS
                    )
                    else None
                )
            )
            if mid_atom is not None and not _items_can_overlap(prev_atom, mid_atom):
                has_non_overlapping_barrier = True
                break
            # First consuming mandatory token overlaps prev_atom -> barrier compromised
            break

        if not has_non_overlapping_barrier:
            raise ValueError(
                "Adjacent or non-anchored overlapping unbounded repeats are disallowed for ReDoS safety."
            )


def _validate_ast_sequence(
    items: Sequence[Any],
    effective_flags: int,
    in_repeat: bool,
) -> None:
    _validate_sequence_unbounded_repeats(items, effective_flags)

    for op, av in items:
        if op in _BACKREF_OPS:
            raise ValueError("Backreferences are disallowed in custom rules for ReDoS safety.")

        if op in _LOOKAROUND_OPS:
            if in_repeat:
                raise ValueError("Quantified lookarounds are disallowed for ReDoS safety.")
            if _has_repeat_in_items(av[1]):
                raise ValueError(
                    "Lookarounds containing quantifiers are disallowed for ReDoS safety."
                )
            _validate_ast_sequence(av[1], effective_flags, in_repeat=False)
            continue

        if op in _REPEAT_OPS:
            if in_repeat:
                raise ValueError("Nested quantifiers are disallowed for ReDoS safety.")
            _validate_ast_sequence(av[2], effective_flags, in_repeat=True)
            continue

        if op == _BRANCH_OP:
            _, branches = av
            if in_repeat and _has_overlapping_ast_branches(branches, effective_flags):
                raise ValueError(
                    "Overlapping quantified alternations are disallowed for ReDoS safety."
                )
            for arm in branches:
                _validate_ast_sequence(arm, effective_flags, in_repeat=in_repeat)
            continue

        if op == _SUBPATTERN_OP:
            _, add_flags, del_flags, sub = av
            sub_flags = (effective_flags | add_flags) & ~del_flags
            _validate_ast_sequence(sub, sub_flags, in_repeat=in_repeat)
            continue

        if _ATOMIC_GROUP_OP is not None and op == _ATOMIC_GROUP_OP:
            _validate_ast_sequence(av, effective_flags, in_repeat=in_repeat)


def validate_custom_rule_regex(pattern: str) -> re.Pattern[str]:
    """
    Validates a custom security rule regex against ReDoS and syntax hazards using
    Python's regex AST parser (`re._parser` / `sre_parse`).
    """
    if not isinstance(pattern, str) or not pattern or not pattern.strip():
        raise ValueError("Custom rule regex pattern must be a non-empty string.")
    if len(pattern) > _MAX_REGEX_LENGTH:
        raise ValueError(
            f"Custom rule regex exceeds maximum length of {_MAX_REGEX_LENGTH} characters."
        )
    if any((ord(ch) < 32 and ch != "\t") or ord(ch) == 127 for ch in pattern):
        raise ValueError("Custom rule regex contains forbidden control characters.")

    try:
        compiled = re.compile(pattern)
        parsed = _re_parser.parse(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid custom rule regex syntax: {exc}") from exc

    effective_flags = int(getattr(getattr(parsed, "state", None), "flags", 0))
    _validate_ast_sequence(parsed, effective_flags, in_repeat=False)
    return compiled


# ---------------------------------------------------------------------------
# Workspace Validation & Language Matching Helpers
# ---------------------------------------------------------------------------
def _validate_confined_repo_dir(
    project_path: str,
    workspace_confinement_fn: Optional[Callable[[str], str]] = None,
) -> str:
    if not isinstance(project_path, str) or not project_path.strip():
        raise HostileRepoError("project_path must be a non-empty directory path.")
    if any(ch in project_path for ch in ("\r", "\n", "\x00")):
        raise HostileRepoError("project_path contains forbidden control characters.")
    cleaned = project_path.strip()
    if cleaned.startswith("-"):
        raise HostileRepoError("project_path cannot start with '-'.")
    if "://" in cleaned:
        raise HostileRepoError("Remote URLs are not supported; supply a local directory path.")
    parts = [p for p in re.split(r"[\\/]+", cleaned) if p]
    if any(p == ".." for p in parts):
        raise HostileRepoError("Path traversal '..' is forbidden in project_path.")

    abs_candidate = os.path.abspath(cleaned)
    if workspace_confinement_fn is not None:
        confined = workspace_confinement_fn(cleaned)
        real_repo = os.path.realpath(confined)
    else:
        if is_link_or_junction(abs_candidate):
            raise HostileRepoError(f"Refusing symlink/junction project_path: {project_path}")
        real_repo = os.path.realpath(abs_candidate)

    if not os.path.isdir(real_repo):
        raise ValueError(f"Workspace path does not exist or is not a directory: {project_path}")
    return real_repo


def _rule_matches_language(rule_languages: Sequence[str], file_language: str) -> bool:
    if not rule_languages:
        return True
    file_lang_norm = (file_language or "").strip().lower()
    if not file_lang_norm:
        return False
    allowed: Set[str] = set()
    for raw_lang in rule_languages:
        key = str(raw_lang or "").strip().lower()
        if not key:
            continue
        allowed.update(_LANGUAGE_ALIASES.get(key, (key,)))
    return file_lang_norm in allowed


def _scan_lines_for_rule(
    *,
    filepath: str,
    lines: Sequence[str],
    compiled_pattern: re.Pattern[str],
    compiled_anti: Optional[re.Pattern[str]],
    max_matches_remaining: int,
    warnings: List[str],
) -> Tuple[List[CustomRuleMatchItem], int, int]:
    matches: List[CustomRuleMatchItem] = []
    unsuppressed_count = 0
    suppressed_count = 0

    if len(lines) > _MAX_SCAN_LINES_PER_FILE:
        warnings.append(
            f"File '{filepath}' truncated at {_MAX_SCAN_LINES_PER_FILE} lines during custom rule scan."
        )
    bounded_lines = lines[:_MAX_SCAN_LINES_PER_FILE]

    for idx, raw_line in enumerate(bounded_lines):
        if len(matches) >= max_matches_remaining:
            break
        line_slice = raw_line[:_MAX_SCAN_CHARS_PER_LINE]
        if len(raw_line) > _MAX_SCAN_CHARS_PER_LINE and len(warnings) < 10:
            warnings.append(
                f"Line {idx + 1} in '{filepath}' truncated at {_MAX_SCAN_CHARS_PER_LINE} chars."
            )
        if not compiled_pattern.search(line_slice):
            continue

        suppressed = False
        if compiled_anti is not None:
            ctx_lo = max(0, idx - 1)
            ctx_hi = min(len(bounded_lines), idx + 2)
            for ctx_idx in range(ctx_lo, ctx_hi):
                if compiled_anti.search(bounded_lines[ctx_idx][:_MAX_SCAN_CHARS_PER_LINE]):
                    suppressed = True
                    break

        scrubbed_excerpt = scrub_raw_secrets_text(line_slice.strip())[:300]
        matches.append(
            CustomRuleMatchItem(
                filepath=filepath,
                line=idx + 1,
                matched_excerpt=scrubbed_excerpt,
                suppressed_by_anti_pattern=suppressed,
            )
        )
        if suppressed:
            suppressed_count += 1
        else:
            unsuppressed_count += 1

    return matches, unsuppressed_count, suppressed_count


# ---------------------------------------------------------------------------
# Custom Rule Studio Engine (Atomic Vault Persistence + Sandbox + Workspace Eval)
# ---------------------------------------------------------------------------
class CustomRuleEngine:
    """
    Manages persisted custom security rules inside `<vault_dir>/custom_rules.json`
    with atomic writes, `0o700`/`0o600` permissions, ReDoS validation, live sandbox
    testing, and confined workspace rule evaluation.
    """

    def __init__(self, vault_dir: str) -> None:
        if not isinstance(vault_dir, str) or not vault_dir.strip():
            raise ValueError("vault_dir must be a non-empty directory path.")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in vault_dir):
            raise HostileRepoError("vault_dir contains forbidden control characters.")
        self.vault_dir = vault_dir.strip()
        self._lock = threading.RLock()

    def _validate_rule_id(self, rule_id: str) -> str:
        if not isinstance(rule_id, str) or not _RULE_ID_RE.match(rule_id):
            raise ValueError(
                "rule_id must be 2-64 chars matching ^[A-Za-z0-9._-]{2,64}$."
            )
        return rule_id

    def _validate_rule_payload(self, rule: CustomSecurityRule) -> CustomSecurityRule:
        self._validate_rule_id(rule.rule_id)
        validate_custom_rule_regex(rule.pattern)
        clean_anti = rule.anti_pattern if rule.anti_pattern else None
        if clean_anti is not None:
            validate_custom_rule_regex(clean_anti)
        return rule.model_copy(update={"anti_pattern": clean_anti}, deep=True)

    def _resolve_vault_file(self, create_dir: bool) -> Tuple[str, str]:
        abs_vault = os.path.abspath(self.vault_dir)
        if os.path.lexists(abs_vault) and is_link_or_junction(abs_vault):
            raise HostileRepoError("Refusing symlink/junction custom rule vault directory.")
        if create_dir:
            os.makedirs(abs_vault, mode=0o700, exist_ok=True)
            try:
                os.chmod(abs_vault, 0o700)
            except OSError:
                pass
        vault_real = os.path.realpath(abs_vault)
        target_cand = os.path.join(vault_real, _CUSTOM_RULES_FILENAME)
        if os.path.lexists(target_cand) and is_link_or_junction(target_cand):
            raise HostileRepoError("Refusing symlink/junction custom_rules.json target.")
        target_real = os.path.realpath(target_cand)
        if os.path.commonpath([vault_real, target_real]) != vault_real:
            raise HostileRepoError("Custom rule vault path confinement violation.")
        return vault_real, target_real

    def _load_rules_locked(self) -> List[CustomSecurityRule]:
        vault_real, target_real = self._resolve_vault_file(create_dir=False)
        if os.path.commonpath([vault_real, target_real]) != vault_real:
            return []
        if not os.path.isfile(target_real):
            return []
        try:
            with open(target_real, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception as exc:
            safe_msg = str(exc).replace("\r", " ").replace("\n", " ")[:160]
            logger.warning("Failed to load custom rules vault: %s", safe_msg)
            return []

        raw_rules = payload.get("rules") if isinstance(payload, dict) else payload
        if not isinstance(raw_rules, list):
            return []

        loaded: List[CustomSecurityRule] = []
        for item in raw_rules:
            if not isinstance(item, dict):
                continue
            try:
                loaded.append(CustomSecurityRule.model_validate(item))
            except Exception as exc:
                safe_msg = str(exc).replace("\r", " ").replace("\n", " ")[:120]
                logger.warning("Skipping invalid persisted custom rule: %s", safe_msg)
        return loaded

    def _save_rules_locked(self, rules: Sequence[CustomSecurityRule]) -> None:
        vault_real, target_real = self._resolve_vault_file(create_dir=True)
        tmp_name = f"{_CUSTOM_RULES_FILENAME}.tmp.{os.getpid()}.{threading.get_ident()}"
        tmp_cand = os.path.join(vault_real, tmp_name)
        if os.path.lexists(tmp_cand) and is_link_or_junction(tmp_cand):
            raise HostileRepoError("Refusing symlink/junction temporary custom rule vault file.")
        tmp_real = os.path.realpath(tmp_cand)
        if os.path.commonpath([vault_real, tmp_real]) != vault_real:
            raise HostileRepoError("Custom rule vault temporary path confinement violation.")

        payload = {
            "version": 1,
            "rules": [r.model_dump() for r in rules],
        }
        serialized = json.dumps(payload, indent=2, sort_keys=True)
        fd = -1
        try:
            fd = os.open(tmp_real, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.chmod(tmp_real, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fd = -1
                fh.write(serialized)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            os.replace(tmp_real, target_real)
            try:
                os.chmod(target_real, 0o600)
            except OSError:
                pass
        except Exception:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if os.path.lexists(tmp_real) and not is_link_or_junction(tmp_real):
                try:
                    os.unlink(tmp_real)
                except OSError:
                    pass
            raise

    def list_rules(self) -> List[CustomSecurityRule]:
        with self._lock:
            return [r.model_copy(deep=True) for r in self._load_rules_locked()]

    def get_rule(self, rule_id: str) -> Optional[CustomSecurityRule]:
        self._validate_rule_id(rule_id)
        with self._lock:
            for rule in self._load_rules_locked():
                if rule.rule_id == rule_id:
                    return rule.model_copy(deep=True)
        return None

    def create_rule(self, rule: CustomSecurityRule) -> CustomSecurityRule:
        clean_rule = self._validate_rule_payload(rule)
        now = _utc_iso_now()
        with self._lock:
            existing = self._load_rules_locked()
            if any(r.rule_id == clean_rule.rule_id for r in existing):
                raise ValueError(f"Custom rule '{clean_rule.rule_id}' already exists.")
            stored = clean_rule.model_copy(update={"created_at": now, "updated_at": now}, deep=True)
            existing.append(stored)
            self._save_rules_locked(existing)
            return stored.model_copy(deep=True)

    def update_rule(self, rule_id: str, rule: CustomSecurityRule) -> CustomSecurityRule:
        self._validate_rule_id(rule_id)
        clean_rule = self._validate_rule_payload(
            rule.model_copy(update={"rule_id": rule_id}, deep=True)
        )
        now = _utc_iso_now()
        with self._lock:
            existing = self._load_rules_locked()
            for idx, current in enumerate(existing):
                if current.rule_id == rule_id:
                    updated = clean_rule.model_copy(
                        update={
                            "created_at": current.created_at or now,
                            "updated_at": now,
                        },
                        deep=True,
                    )
                    existing[idx] = updated
                    self._save_rules_locked(existing)
                    return updated.model_copy(deep=True)
            raise KeyError(f"Custom rule '{rule_id}' not found.")

    def delete_rule(self, rule_id: str) -> bool:
        self._validate_rule_id(rule_id)
        with self._lock:
            existing = self._load_rules_locked()
            remaining = [r for r in existing if r.rule_id != rule_id]
            if len(remaining) == len(existing):
                return False
            self._save_rules_locked(remaining)
            return True

    def test_rule(
        self,
        req: CustomRuleTestRequest,
        workspace_confinement_fn: Optional[Callable[[str], str]] = None,
    ) -> CustomRuleTestResponse:
        compiled_pattern = validate_custom_rule_regex(req.rule.pattern)
        compiled_anti: Optional[re.Pattern[str]] = None
        if req.rule.anti_pattern:
            compiled_anti = validate_custom_rule_regex(req.rule.anti_pattern)

        warnings: List[str] = []
        all_matches: List[CustomRuleMatchItem] = []
        matches_count = 0
        suppressed_count = 0

        if req.sample_code is not None:
            lang_key = (req.sample_language or "python").strip().lower()
            ext = _LANGUAGE_TO_SAMPLE_EXT.get(lang_key, "txt")
            sample_fp = f"sample.{ext}"
            sample_lines = str(req.sample_code).splitlines()
            file_matches, unsup, sup = _scan_lines_for_rule(
                filepath=sample_fp,
                lines=sample_lines,
                compiled_pattern=compiled_pattern,
                compiled_anti=compiled_anti,
                max_matches_remaining=_MAX_TEST_MATCHES,
                warnings=warnings,
            )
            all_matches.extend(file_matches)
            matches_count += unsup
            suppressed_count += sup
        elif req.project_path is not None:
            real_repo = _validate_confined_repo_dir(
                req.project_path,
                workspace_confinement_fn=workspace_confinement_fn,
            )
            scanned_files, _telemetry = scan_directory_with_telemetry(real_repo, exclude_tests=False)
            for sf in scanned_files:
                if len(all_matches) >= _MAX_TEST_MATCHES:
                    warnings.append(f"Match output capped at {_MAX_TEST_MATCHES} matches.")
                    break
                if not _rule_matches_language(req.rule.languages, sf.language):
                    continue
                text = sf.content_bytes.decode("utf-8", errors="replace")
                file_matches, unsup, sup = _scan_lines_for_rule(
                    filepath=sf.filepath,
                    lines=text.splitlines(),
                    compiled_pattern=compiled_pattern,
                    compiled_anti=compiled_anti,
                    max_matches_remaining=_MAX_TEST_MATCHES - len(all_matches),
                    warnings=warnings,
                )
                all_matches.extend(file_matches)
                matches_count += unsup
                suppressed_count += sup
        else:
            raise ValueError("Provide either sample_code or project_path to test a custom rule.")

        if len(all_matches) >= _MAX_TEST_MATCHES and not any("capped at" in w for w in warnings):
            warnings.append(f"Match output capped at {_MAX_TEST_MATCHES} matches.")

        return CustomRuleTestResponse(
            rule_id=scrub_raw_secrets_text(req.rule.rule_id),
            regex_safe=True,
            matches_count=matches_count,
            suppressed_count=suppressed_count,
            matches=all_matches,
            warnings=warnings,
        )

    def evaluate_enabled_rules_on_workspace(
        self,
        repo_path: str,
        workspace_confinement_fn: Optional[Callable[[str], str]] = None,
    ) -> List[Finding]:
        real_repo = _validate_confined_repo_dir(
            repo_path,
            workspace_confinement_fn=workspace_confinement_fn,
        )
        enabled_rules = [r for r in self.list_rules() if r.enabled]
        if not enabled_rules:
            return []

        compiled_entries: List[Tuple[CustomSecurityRule, re.Pattern[str], Optional[re.Pattern[str]]]] = []
        for rule in enabled_rules:
            try:
                c_pat = validate_custom_rule_regex(rule.pattern)
                c_anti = validate_custom_rule_regex(rule.anti_pattern) if rule.anti_pattern else None
                compiled_entries.append((rule, c_pat, c_anti))
            except ValueError as exc:
                logger.warning("Skipping unsafe persisted custom rule %s: %s", rule.rule_id, str(exc)[:120])

        if not compiled_entries:
            return []

        scanned_files, _telemetry = scan_directory_with_telemetry(real_repo, exclude_tests=False)
        findings: List[Finding] = []
        file_lines_cache: Dict[str, List[str]] = {}

        for sf in scanned_files:
            lines = file_lines_cache.get(sf.filepath)
            if lines is None:
                lines = sf.content_bytes.decode("utf-8", errors="replace").splitlines()
                file_lines_cache[sf.filepath] = lines

            for rule, c_pat, c_anti in compiled_entries:
                if not _rule_matches_language(rule.languages, sf.language):
                    continue
                warnings: List[str] = []
                matches, _unsup, _sup = _scan_lines_for_rule(
                    filepath=sf.filepath,
                    lines=lines,
                    compiled_pattern=c_pat,
                    compiled_anti=c_anti,
                    max_matches_remaining=_MAX_TEST_MATCHES,
                    warnings=warnings,
                )
                for m in matches:
                    if m.suppressed_by_anti_pattern:
                        continue
                    findings.append(_build_finding_from_custom_match(rule, sf, m))

        return findings


def _build_finding_from_custom_match(
    rule: CustomSecurityRule,
    sf: ScannedFile,
    match: CustomRuleMatchItem,
) -> Finding:
    digest = hashlib.sha256(
        f"{rule.rule_id}:{sf.filepath}:{match.line}".encode("utf-8")
    ).hexdigest()[:12]
    fid = f"CUST-{digest}"
    node_id = f"custom-{digest}"
    lang_spec = LANGUAGE_SPECS.get(sf.language)
    display_lang = (
        lang_spec.display_name
        if lang_spec is not None
        else infer_language_from_filepath(sf.filepath, rule.rule_id)
    )
    safe_excerpt = scrub_raw_secrets_text(match.matched_excerpt)
    safe_desc = scrub_raw_secrets_text(
        rule.description or f"Custom rule '{rule.name}' matched at {sf.filepath}:{match.line}."
    )
    safe_rem = scrub_raw_secrets_text(rule.remediation) if rule.remediation else None

    return Finding(
        id=fid,
        rule_id=rule.rule_id,
        severity=rule.severity,
        title=scrub_raw_secrets_text(rule.name),
        description=safe_desc,
        cwe_id=rule.cwe_id,
        remediation=safe_rem,
        scan_engine="SAST",
        source_engine="ALASTOR_CUSTOM_RULE",
        corroborated_by=["ALASTOR_CUSTOM_RULE"],
        language=display_lang,
        path_nodes=[
            {
                "id": node_id,
                "label": "Call",
                "ast_type": "custom_pattern_match",
                "name": rule.rule_id,
                "code": safe_excerpt,
                "filepath": sf.filepath,
                "start_line": match.line,
                "end_line": match.line,
                "start_col": 0,
                "end_col": len(safe_excerpt),
                "scope_id": "module",
                "language": sf.language,
                "is_bfl": True,
            }
        ],
        path_edges=[],
        best_fix_location=BestFixLocation(
            node_id=node_id,
            filepath=sf.filepath,
            line=match.line,
            column=0,
            code_snippet=safe_excerpt,
            explanation=safe_desc,
            recommended_fix=safe_rem or "",
        ),
    )
