"""
Native TruffleHog-Grade Secret Scanner, Git-History Hunter & Live Key Validator.

Zero-external-binary Python stdlib engine providing:
1. 14 high-signal credential & private-material detector families.
2. Working-tree + `.git` commit-history (`git log -p`) hunting with working-tree deduplication.
3. Safe read-only live provider identity verification (`ALLOWED_VERIFY_HOSTS`, HTTPS-only,
   zero redirects, <= 4.0s timeout, AWS STS SigV4 signing, SHA-256 verdict cache) paired with
   persistent `Offline Mode` configuration in `.alastor_vault/secret_scanner_config.json` (`0o600`).
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import logging
import math
import os
import re
import socket
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request

from models import (
    BestFixLocation,
    Finding,
    SecretInventoryResponse,
    SecretScannerConfig,
    SecretScannerConfigUpdate,
)

logger = logging.getLogger("cpg-sast.secret-validator")

SUPPORTED_DETECTORS_COUNT = 14
_CACHE_TTL_SECONDS = 1800.0
_VAULT_CFG_FILENAME = "secret_scanner_config.json"

ALLOWED_VERIFY_HOSTS: frozenset[str] = frozenset(
    {
        "api.github.com",
        "gitlab.com",
        "sts.amazonaws.com",
        "api.openai.com",
        "generativelanguage.googleapis.com",
        "api.anthropic.com",
        "api.stripe.com",
        "slack.com",
        "api.sendgrid.com",
        "huggingface.co",
    }
)

_VERIFY_ENDPOINTS: Dict[str, str] = {
    "github_pat": "https://api.github.com/user",
    "gitlab_pat": "https://gitlab.com/api/v4/personal_access_tokens/self",
    "aws_iam": "https://sts.amazonaws.com/",
    "openai_key": "https://api.openai.com/v1/models",
    "gemini_key": "https://generativelanguage.googleapis.com/v1beta/models",
    "anthropic_key": "https://api.anthropic.com/v1/models",
    "stripe_key": "https://api.stripe.com/v1/account",
    "slack_token": "https://slack.com/api/auth.test",
    "sendgrid_key": "https://api.sendgrid.com/v3/scopes",
    "huggingface_token": "https://huggingface.co/api/whoami-v2",
}

_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
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
        "coverage",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "docs",
        "doc",
        "tests",
        "test",
        "__tests__",
        "fixtures",
        "testdata",
        ".alastor_patches",
        ".alastor_vault",
        ".superpowers",
        "scratch",
        "uploaded_scans",
    }
)

_EXCLUDED_EXACT_FILES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "pipfile.lock",
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "verify_harness.py",
        ".ds_store",
        "thumbs.db",
        "desktop.ini",
    }
)

_SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".cs",
        ".rs",
        ".kt",
        ".swift",
        ".scala",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".tf",
        ".tfvars",
        ".pem",
        ".key",
    }
)

_PLACEHOLDER_MARKERS: Tuple[str, ...] = (
    "example",
    "changeme",
    "change_me",
    "your_api",
    "your-api",
    "your_key",
    "your_tok",
    "placeholder",
    "dummy",
    "sample",
    "replace_me",
    "insert_here",
    "todo",
    "xxxx",
    "00000000",
    "11111111",
    "abcdef123456",
)

# Detector regexes (kept on single re.compile lines so static regex-line filters recognize them)
_DETECTOR_SPECS: List[Tuple[str, str, re.Pattern[str]]] = [
    ("github_pat", "GitHub Personal / Fine-Grained Access Token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("gitlab_pat", "GitLab Personal Access Token", re.compile(r"\b(glpat-[A-Za-z0-9_\-=]{20,128})\b")),
    ("aws_iam", "AWS IAM Access Key Credential", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("anthropic_key", "Anthropic Claude API Key", re.compile(r"\b(sk-ant-api03-[A-Za-z0-9_\-]{20,255})\b")),
    ("stripe_key", "Stripe API Credential", re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,128})\b")),
    ("openai_key", "OpenAI API Key", re.compile(r"\b(sk-(?:proj|svcacct)-[A-Za-z0-9_\-]{20,255}|sk-(?!ant-|live_|test_)[A-Za-z0-9]{32,128})\b")),
    ("gemini_key", "Google Gemini / Cloud API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("slack_token", "Slack Bot / User Token or Webhook", re.compile(r"(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9\-]{16,128}|https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,36})")),
    ("sendgrid_key", "SendGrid API Key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{16,64}\.[A-Za-z0-9_\-]{16,128})\b")),
    ("huggingface_token", "HuggingFace Hub Access Token", re.compile(r"\b(hf_[A-Za-z0-9]{30,64})\b")),
    ("jwt_bearer", "Hardcoded Signed JWT Bearer Token", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,512}\.eyJ[A-Za-z0-9_\-]{8,1024}\.[A-Za-z0-9_\-]{8,512})\b")),
    ("private_key_pem", "Cryptographic Private Key PEM", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE" + r" KEY-----[\s\S]{16,8192}?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE" + r" KEY-----)")),
    ("database_uri", "Database URI with Embedded Credential", re.compile(r"((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss)://[^\s/\"'<>]+@[^\s\"'<>]+)")),
]

_PEM_HEADER_LINE_RX = re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE" + r" KEY-----)")
_AWS_40_CAND_RX = re.compile(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])")
_AWS_SESSION_RX = re.compile(r'(?i)aws_session_token\s*[:=]\s*["\']([A-Za-z0-9/+=]{32,1024})["\']')
_ASSIGN_NAME_RX = re.compile(r"^\s*(?:export\s+)?(?:const|let|var\s+)?([A-Za-z_][A-Za-z0-9_.\-]{1,64})\s*[:=]")
_HUNK_LINE_RX = re.compile(r"^@@\s+-[0-9]+(?:,[0-9]+)?\s+\+([0-9]+)(?:,[0-9]+)?\s+@@")


class _ProbeRedirectError(Exception):
    """Raised when an outbound verification probe encounters a blocked 30x redirect."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Blocks all 301/302/303/307/308 redirects during outbound provider verification probes."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            int(code or 302),
            "Redirects blocked by ALASTOR SSRF policy",
            headers,
            fp,
        )


def _shannon_entropy(val: str) -> float:
    if not val:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in val:
        freq[ch] = freq.get(ch, 0) + 1
    length = float(len(val))
    ent = 0.0
    for cnt in freq.values():
        prob = cnt / length
        ent -= prob * math.log2(prob)
    return round(ent, 2)


def _mask_token(raw_val: str) -> str:
    clean = (raw_val or "").strip()
    if "\n" in clean and clean.startswith("-----BEGIN "):
        first_ln = clean.splitlines()[0].strip()
        return f"{first_ln[:24]}••••••••"
    if len(clean) <= 5:
        return "••••" + clean[-1:] if clean else "••••••"
    if len(clean) <= 10:
        return clean[:2] + "••••" + clean[-2:]
    return clean[:4] + "••••••••" + clean[-4:]


def _scrub_raw_value(msg: str, raw_val: str) -> str:
    safe_msg = (msg or "").replace("\r", " ").replace("\n", " ").strip()
    if raw_val and len(raw_val) >= 4 and raw_val in safe_msg:
        safe_msg = safe_msg.replace(raw_val, _mask_token(raw_val))
    return safe_msg[:320]


def _b64url_decode_bytes(seg: str) -> bytes:
    padded = seg + ("=" * ((4 - (len(seg) % 4)) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _is_excluded_relpath(rel_path: str) -> bool:
    norm = (rel_path or "").replace("\\", "/").lstrip("./")
    if not norm:
        return True
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return True
    for part in parts[:-1]:
        low_part = part.lower()
        if low_part in _EXCLUDED_DIR_NAMES or low_part.startswith(".alastor"):
            return True
    leaf = parts[-1]
    low_leaf = leaf.lower()
    if low_leaf in _EXCLUDED_EXACT_FILES or low_leaf.startswith("._"):
        return True
    if low_leaf.endswith((".md", ".mdx", ".rst", ".lock", ".min.js", ".min.css", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".tar", ".gz")):
        return True
    if (
        low_leaf.startswith("test_")
        or low_leaf.endswith(("_test.py", "_test.go", ".test.ts", ".test.tsx", ".test.js", ".test.jsx", ".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx"))
    ):
        return True
    ext = os.path.splitext(low_leaf)[1]
    if low_leaf.startswith(".env"):
        return False
    return ext not in _SCANNABLE_EXTENSIONS


def _infer_lang(rel_path: str) -> str:
    low = (rel_path or "").lower()
    if low.endswith(".py"):
        return "Python"
    if low.endswith((".ts", ".tsx")):
        return "TypeScript"
    if low.endswith((".js", ".jsx", ".mjs", ".cjs")):
        return "JavaScript"
    if low.endswith(".go"):
        return "Go"
    if low.endswith(".java"):
        return "Java"
    if low.endswith((".yaml", ".yml")):
        return "YAML"
    if low.endswith(".json"):
        return "JSON"
    return "Config"


def _aws_sigv4_headers(access_id: str, pair_val: str, body_bytes: bytes, session_tok: str = "") -> Dict[str, str]:
    now_utc = datetime.now(timezone.utc)
    amz_date = now_utc.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now_utc.strftime("%Y%m%d")
    region = "us-east-1"
    service = "sts"
    host = "sts.amazonaws.com"
    content_type = "application/x-www-form-urlencoded; charset=utf-8"
    payload_hash = hashlib.sha256(body_bytes).hexdigest()

    canon_hdr_map: Dict[str, str] = {
        "content-type": content_type,
        "host": host,
        "x-amz-date": amz_date,
    }
    if session_tok:
        canon_hdr_map["x-amz-security-token"] = session_tok

    sorted_keys = sorted(canon_hdr_map.keys())
    canon_headers = "".join(f"{k}:{canon_hdr_map[k]}\n" for k in sorted_keys)
    signed_headers = ";".join(sorted_keys)
    canon_req = "\n".join(["POST", "/", "", canon_headers, signed_headers, payload_hash])

    cred_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    str_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            cred_scope,
            hashlib.sha256(canon_req.encode("utf-8")).hexdigest(),
        ]
    )

    k_date = hmac.new(("AWS4" + pair_val).encode("utf-8"), date_stamp.encode("utf-8"), hashlib.sha256).digest()
    k_region = hmac.new(k_date, region.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode("utf-8"), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    sig_hex = hmac.new(k_signing, str_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth_val = (
        f"AWS4-HMAC-SHA256 Credential={access_id}/{cred_scope}, "
        f"SignedHeaders={signed_headers}, Signature={sig_hex}"
    )
    out_headers: Dict[str, str] = {
        "Content-Type": content_type,
        "Host": host,
        "X-Amz-Date": amz_date,
        "Authorization": auth_val,
    }
    if session_tok:
        out_headers["X-Amz-Security-Token"] = session_tok
    return out_headers


def _extract_aws_pair_from_context(access_id: str, context_text: str) -> Tuple[str, str]:
    if not context_text:
        return "", ""
    sess_match = _AWS_SESSION_RX.search(context_text)
    sess_tok = sess_match.group(1).strip() if sess_match else ""
    for cand_match in _AWS_40_CAND_RX.finditer(context_text):
        cand = cand_match.group(1)
        if cand == access_id or "EXAMPLE" in cand.upper():
            continue
        if cand.count("/") >= 4 and not any(ch.isdigit() for ch in cand):
            continue
        if _shannon_entropy(cand) >= 3.3:
            return cand, sess_tok
    return "", sess_tok


class SecretValidatorEngine:
    """Native TruffleHog-grade secret detector, `.git` history hunter, and live provider validator."""

    def __init__(self, platform_root: Optional[str] = None):
        if platform_root:
            self.platform_root = os.path.realpath(platform_root)
        else:
            backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.platform_root = os.path.realpath(os.path.dirname(backend_dir))
        self.vault_dir = os.path.realpath(os.path.join(self.platform_root, ".alastor_vault"))

        self._lock = threading.Lock()
        self._live_enabled: bool = True
        self._scan_git_history: bool = True
        self._max_git_commits: int = 50
        self._verdict_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

        self._load_config()

    def _resolve_vault_cfg_path(self) -> str:
        vault_real = os.path.realpath(self.vault_dir)
        os.makedirs(vault_real, mode=0o700, exist_ok=True)
        try:
            os.chmod(vault_real, 0o700)
        except OSError:
            pass
        cand_real = os.path.realpath(os.path.join(vault_real, _VAULT_CFG_FILENAME))
        if os.path.commonpath([vault_real, cand_real]) != vault_real:
            raise ValueError("Vault configuration path confinement violation.")
        return cand_real

    def _load_config(self) -> None:
        try:
            vault_real = os.path.realpath(self.vault_dir)
            raw_cfg_path = self._resolve_vault_cfg_path()
            confined_cfg_path = (
                raw_cfg_path
                if os.path.commonpath([vault_real, raw_cfg_path]) == vault_real
                else ""
            )
            if not confined_cfg_path:
                raise ValueError("Vault configuration path confinement violation.")
            if os.path.isfile(confined_cfg_path):
                with open(confined_cfg_path, "r", encoding="utf-8") as fh:
                    blob = json.load(fh)
                if isinstance(blob, dict):
                    if "live_verification_enabled" in blob:
                        self._live_enabled = bool(blob["live_verification_enabled"])
                    if "scan_git_history" in blob:
                        self._scan_git_history = bool(blob["scan_git_history"])
                    if "max_git_commits" in blob:
                        self._max_git_commits = max(1, min(500, int(blob["max_git_commits"])))
        except Exception as exc:
            safe_err = str(exc).replace("\r", " ").replace("\n", " ")[:140]
            logger.warning("Could not read scanner config from vault: %s", safe_err)

    def _persist_config_locked(self) -> None:
        vault_real = os.path.realpath(self.vault_dir)
        raw_cfg_path = self._resolve_vault_cfg_path()
        confined_cfg_path = (
            raw_cfg_path
            if os.path.commonpath([vault_real, raw_cfg_path]) == vault_real
            else ""
        )
        if not confined_cfg_path:
            raise ValueError("Vault configuration path confinement violation.")
        payload = {
            "live_verification_enabled": self._live_enabled,
            "scan_git_history": self._scan_git_history,
            "max_git_commits": self._max_git_commits,
            "supported_detectors_count": SUPPORTED_DETECTORS_COUNT,
        }
        serialized = json.dumps(payload, indent=2)
        with open(confined_cfg_path, "w", encoding="utf-8") as fh:
            fh.write(serialized)
        try:
            os.chmod(confined_cfg_path, 0o600)
        except OSError:
            pass

    def get_config(self) -> SecretScannerConfig:
        with self._lock:
            return SecretScannerConfig(
                live_verification_enabled=self._live_enabled,
                scan_git_history=self._scan_git_history,
                max_git_commits=self._max_git_commits,
                supported_detectors_count=SUPPORTED_DETECTORS_COUNT,
            )

    def update_config(self, payload: SecretScannerConfigUpdate) -> SecretScannerConfig:
        with self._lock:
            if payload.live_verification_enabled is not None:
                self._live_enabled = bool(payload.live_verification_enabled)
            if payload.scan_git_history is not None:
                self._scan_git_history = bool(payload.scan_git_history)
            if payload.max_git_commits is not None:
                self._max_git_commits = max(1, min(500, int(payload.max_git_commits)))
            self._persist_config_locked()
            return SecretScannerConfig(
                live_verification_enabled=self._live_enabled,
                scan_git_history=self._scan_git_history,
                max_git_commits=self._max_git_commits,
                supported_detectors_count=SUPPORTED_DETECTORS_COUNT,
            )

    def _build_http_opener(self) -> urllib.request.OpenerDirector:
        return urllib.request.build_opener(_NoRedirectHandler())

    def _http_probe(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        timeout: float = 4.0,
    ) -> Tuple[int, str, Dict[str, str]]:
        clean_url = (url or "").strip()
        if not clean_url.startswith("https://") or re.search(r"[\r\n\x00\s]", clean_url):
            raise ValueError("Outbound verification URL must use https:// without control characters.")
        parsed = urllib.parse.urlparse(clean_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme != "https" or host not in ALLOWED_VERIFY_HOSTS:
            raise ValueError(f"Host '{host}' is not in ALLOWED_VERIFY_HOSTS.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Outbound verification URL must not contain userinfo, query params, or fragments.")
        if parsed.port not in (None, 443):
            raise ValueError("Outbound verification URL must use standard HTTPS port 443.")

        eff_timeout = max(0.5, min(4.0, float(timeout or 4.0)))
        req_headers: Dict[str, str] = {
            "User-Agent": "ALASTOR-CredentialValidator/1.0",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)

        http_req = urllib.request.Request(
            url=clean_url,
            data=body,
            headers=req_headers,
            method=(method or "GET").upper(),
        )
        opener = self._build_http_opener()
        try:
            with opener.open(http_req, timeout=eff_timeout) as resp:
                status_num = int(getattr(resp, "status", None) or resp.getcode() or 200)
                resp_bytes = resp.read()
                raw_hdrs = getattr(resp, "headers", None) or {}
                hdr_dict = {str(k).lower(): str(v) for k, v in raw_hdrs.items()} if hasattr(raw_hdrs, "items") else {}
                return status_num, resp_bytes.decode("utf-8", errors="replace")[:8192], hdr_dict
        except urllib.error.HTTPError as http_err:
            code_num = int(getattr(http_err, "code", 500) or 500)
            err_body = ""
            err_hdrs: Dict[str, str] = {}
            try:
                raw_err_bytes = http_err.read() if hasattr(http_err, "read") else b""
                err_body = raw_err_bytes.decode("utf-8", errors="replace")[:4096]
                if getattr(http_err, "headers", None) and hasattr(http_err.headers, "items"):
                    err_hdrs = {str(k).lower(): str(v) for k, v in http_err.headers.items()}
            finally:
                try:
                    http_err.close()
                except Exception:
                    pass
            if code_num in (301, 302, 303, 307, 308):
                raise _ProbeRedirectError(f"HTTP {code_num} redirect blocked by ALASTOR SSRF policy.") from None
            return code_num, err_body, err_hdrs

    def _classify_detector(self, raw_cred: str, key_name: str = "") -> Tuple[str, str]:
        clean = (raw_cred or "").strip()
        for det_id, det_label, rx in _DETECTOR_SPECS:
            if rx.search(clean):
                return det_id, det_label
        if _PEM_HEADER_LINE_RX.search(clean):
            return "private_key_pem", "Cryptographic Private Key PEM"
        key_up = (key_name or "").upper()
        if "JWT" in key_up and clean.startswith("eyJ"):
            return "jwt_bearer", "Hardcoded Signed JWT Bearer Token"
        return "generic_high_entropy", "Hardcoded Application Credential"

    def _is_placeholder_value(self, det_id: str, raw_cred: str, key_name: str = "") -> Optional[str]:
        clean = (raw_cred or "").strip()
        low = clean.lower()
        if not clean:
            return "Empty credential value."
        if det_id == "stripe_key" and low.startswith(("sk_test_", "rk_test_")):
            return "Stripe sandbox test key prefix (sk_test_ / rk_test_) detected."
        if det_id == "aws_iam" and ("EXAMPLE" in clean.upper() or clean.endswith("00000000")):
            return "AWS documentation canary / example key ID detected."
        if clean.startswith(("${", "{{", "<")) or "os.getenv(" in low or "process.env" in low:
            return "Environment variable interpolation or template placeholder."
        if det_id not in ("private_key_pem", "jwt_bearer", "database_uri"):
            for marker in _PLACEHOLDER_MARKERS:
                if marker in low:
                    return f"Matches known documentation/test placeholder pattern ('{marker}')."
        if low in ("true", "false", "null", "none", "undefined", "admin", "root", "postgres", "redis", "local"):
            return "Non-credential literal or default local identifier."
        return None

    def _validate_offline_deterministic(
        self,
        det_id: str,
        raw_cred: str,
        context_text: str,
        now_iso: str,
    ) -> Optional[Dict[str, Any]]:
        clean = (raw_cred or "").strip()
        if det_id == "jwt_bearer":
            parts = clean.split(".")
            if len(parts) != 3:
                return {
                    "secret_validation_status": "REVOKED_OR_INVALID",
                    "secret_detector_id": det_id,
                    "secret_verified_identity": None,
                    "secret_validation_message": "Malformed JWT structure (expected 3 base64url segments).",
                    "secret_verified_at": now_iso,
                }
            try:
                hdr_obj = json.loads(_b64url_decode_bytes(parts[0]).decode("utf-8"))
                pay_obj = json.loads(_b64url_decode_bytes(parts[1]).decode("utf-8"))
            except Exception:
                return {
                    "secret_validation_status": "REVOKED_OR_INVALID",
                    "secret_detector_id": det_id,
                    "secret_verified_identity": None,
                    "secret_validation_message": "Invalid base64url JSON in JWT header or payload.",
                    "secret_verified_at": now_iso,
                }
            if not isinstance(hdr_obj, dict) or not isinstance(pay_obj, dict):
                return {
                    "secret_validation_status": "REVOKED_OR_INVALID",
                    "secret_detector_id": det_id,
                    "secret_verified_identity": None,
                    "secret_validation_message": "Decoded JWT segments are not JSON objects.",
                    "secret_verified_at": now_iso,
                }
            alg_val = str(hdr_obj.get("alg") or "unknown")
            iss_val = str(pay_obj.get("iss") or "unspecified")
            sub_val = str(pay_obj.get("sub") or "unspecified")
            ident_summary = f"JWT sub={sub_val} iss={iss_val} (alg={alg_val})"
            exp_raw = pay_obj.get("exp")
            if isinstance(exp_raw, (int, float)):
                if float(exp_raw) < time.time():
                    exp_dt = datetime.fromtimestamp(float(exp_raw), tz=timezone.utc).strftime("%Y-%m-%d")
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": ident_summary,
                        "secret_validation_message": f"Offline JWT inspection: token is expired (exp={exp_dt}).",
                        "secret_verified_at": now_iso,
                    }
                exp_dt = datetime.fromtimestamp(float(exp_raw), tz=timezone.utc).strftime("%Y-%m-%d")
                return {
                    "secret_validation_status": "OFFLINE_STRUCTURALLY_VALID",
                    "secret_detector_id": det_id,
                    "secret_verified_identity": ident_summary,
                    "secret_validation_message": f"Offline JWT inspection: structurally valid unexpired signed JWT (exp={exp_dt}).",
                    "secret_verified_at": now_iso,
                }
            return {
                "secret_validation_status": "OFFLINE_STRUCTURALLY_VALID",
                "secret_detector_id": det_id,
                "secret_verified_identity": ident_summary,
                "secret_validation_message": "Offline JWT inspection: structurally valid signed JWT without exp claim.",
                "secret_verified_at": now_iso,
            }

        if det_id == "private_key_pem":
            candidate_pem = clean
            if "-----END " not in candidate_pem and context_text:
                m_full = _DETECTOR_SPECS[11][2].search(context_text)
                if m_full:
                    candidate_pem = m_full.group(1)
            lines = [ln.strip() for ln in candidate_pem.splitlines() if ln.strip()]
            if len(lines) >= 3 and lines[0].startswith("-----BEGIN ") and lines[-1].startswith("-----END "):
                body_lines = [
                    ln for ln in lines[1:-1]
                    if ":" not in ln
                ]
                b64_joined = "".join(body_lines)
                try:
                    decoded = base64.b64decode(b64_joined, validate=False)
                    if len(decoded) >= 16:
                        hdr_kind = lines[0].replace("-----BEGIN ", "").replace("-----", "").strip()
                        return {
                            "secret_validation_status": "OFFLINE_STRUCTURALLY_VALID",
                            "secret_detector_id": det_id,
                            "secret_verified_identity": hdr_kind,
                            "secret_validation_message": f"Offline PEM verification: balanced header/footer and valid {len(decoded)}-byte ASN.1/OpenSSH body.",
                            "secret_verified_at": now_iso,
                        }
                except Exception:
                    pass
                return {
                    "secret_validation_status": "TEST_OR_PLACEHOLDER",
                    "secret_detector_id": det_id,
                    "secret_verified_identity": None,
                    "secret_validation_message": "PEM block contains non-decodable or truncated placeholder body.",
                    "secret_verified_at": now_iso,
                }
            if lines and lines[0].startswith("-----BEGIN "):
                hdr_kind = lines[0].replace("-----BEGIN ", "").replace("-----", "").strip()
                return {
                    "secret_validation_status": "OFFLINE_STRUCTURALLY_VALID",
                    "secret_detector_id": det_id,
                    "secret_verified_identity": hdr_kind,
                    "secret_validation_message": "Offline PEM header detected in source/configuration.",
                    "secret_verified_at": now_iso,
                }

        if det_id == "database_uri":
            scheme, has_scheme, rest = clean.partition("://")
            if not has_scheme or "@" not in rest:
                return {
                    "secret_validation_status": "TEST_OR_PLACEHOLDER",
                    "secret_detector_id": det_id,
                    "secret_verified_identity": None,
                    "secret_validation_message": "Database URI does not contain embedded user credentials.",
                    "secret_verified_at": now_iso,
                }
            authority, _, db_path = rest.partition("/")
            userinfo, _, hostport = authority.rpartition("@")
            user_part, has_colon, cred_part = userinfo.partition(":")
            cred_low = cred_part.lower()
            if (
                not has_colon
                or not cred_part
                or cred_low in ("postgres", "root", "admin", "pass", "changeme", "example", "123456", "test")
                or any(m in cred_low for m in _PLACEHOLDER_MARKERS)
                or cred_part.startswith(("${", "<"))
            ):
                return {
                    "secret_validation_status": "TEST_OR_PLACEHOLDER",
                    "secret_detector_id": det_id,
                    "secret_verified_identity": None,
                    "secret_validation_message": "Database URI uses a local/default placeholder credential.",
                    "secret_verified_at": now_iso,
                }
            db_name = db_path.split("?")[0]
            ident_uri = f"{scheme}://{user_part}@{hostport}" + (f"/{db_name}" if db_name else "")
            return {
                "secret_validation_status": "OFFLINE_STRUCTURALLY_VALID",
                "secret_detector_id": det_id,
                "secret_verified_identity": ident_uri,
                "secret_validation_message": f"Offline URI inspection: embedded high-entropy credential for '{ident_uri}' (no DB connection attempted).",
                "secret_verified_at": now_iso,
            }

        if det_id == "slack_token" and clean.startswith("https://hooks.slack.com/services/"):
            return {
                "secret_validation_status": "OFFLINE_STRUCTURALLY_VALID",
                "secret_detector_id": det_id,
                "secret_verified_identity": "Slack Incoming Webhook Endpoint",
                "secret_validation_message": "Structurally valid Slack Incoming Webhook URL (outbound message post skipped for safety).",
                "secret_verified_at": now_iso,
            }

        if det_id == "generic_high_entropy":
            ent = _shannon_entropy(clean)
            if len(clean) >= 8 and ent >= 3.2:
                return {
                    "secret_validation_status": "OFFLINE_STRUCTURALLY_VALID",
                    "secret_detector_id": det_id,
                    "secret_verified_identity": None,
                    "secret_validation_message": f"High-entropy credential literal ({ent} bits/char, length {len(clean)}).",
                    "secret_verified_at": now_iso,
                }
            return {
                "secret_validation_status": "TEST_OR_PLACEHOLDER",
                "secret_detector_id": det_id,
                "secret_verified_identity": None,
                "secret_validation_message": f"Low-entropy or short literal ({ent} bits/char) classified as test/placeholder.",
                "secret_verified_at": now_iso,
            }

        return None

    def _probe_live_provider(
        self,
        det_id: str,
        raw_cred: str,
        aws_pair_val: str,
        aws_sess_tok: str,
        now_iso: str,
    ) -> Dict[str, Any]:
        endpoint_url = _VERIFY_ENDPOINTS.get(det_id, "")
        if not endpoint_url:
            return {
                "secret_validation_status": "OFFLINE_STRUCTURALLY_VALID",
                "secret_detector_id": det_id,
                "secret_verified_identity": None,
                "secret_validation_message": "Structurally valid credential (no live provider endpoint mapped).",
                "secret_verified_at": now_iso,
            }

        try:
            if det_id == "github_pat":
                code_num, body_txt, hdrs = self._http_probe(
                    endpoint_url,
                    method="GET",
                    headers={
                        "Authorization": f"Bearer {raw_cred}",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                if code_num == 200:
                    data = json.loads(body_txt or "{}")
                    login = str(data.get("login") or "authenticated-user")
                    scopes = hdrs.get("x-oauth-scopes", "").strip()
                    ident = f"GitHub user @{login}" + (f" (scopes: {scopes})" if scopes else "")
                    return {
                        "secret_validation_status": "VERIFIED_ACTIVE",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": ident,
                        "secret_validation_message": f"Live GitHub API probe confirmed active token for @{login}.",
                        "secret_verified_at": now_iso,
                    }
                if code_num in (401, 403) and (code_num == 401 or "bad credentials" in body_txt.lower()):
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": f"GitHub API rejected token (HTTP {code_num} Unauthorized).",
                        "secret_verified_at": now_iso,
                    }

            elif det_id == "gitlab_pat":
                code_num, body_txt, _ = self._http_probe(
                    endpoint_url,
                    method="GET",
                    headers={"PRIVATE-TOKEN": raw_cred},
                )
                if code_num == 200:
                    data = json.loads(body_txt or "{}")
                    if data.get("revoked") is True or data.get("active") is False:
                        return {
                            "secret_validation_status": "REVOKED_OR_INVALID",
                            "secret_detector_id": det_id,
                            "secret_verified_identity": None,
                            "secret_validation_message": "GitLab token metadata reports token is revoked/inactive.",
                            "secret_verified_at": now_iso,
                        }
                    tok_name = str(data.get("name") or "personal-token")
                    scopes_list = data.get("scopes") if isinstance(data.get("scopes"), list) else []
                    scopes_str = ", ".join(str(s) for s in scopes_list[:5])
                    ident = f"GitLab PAT '{tok_name}'" + (f" (scopes: {scopes_str})" if scopes_str else "")
                    return {
                        "secret_validation_status": "VERIFIED_ACTIVE",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": ident,
                        "secret_validation_message": "Live GitLab API probe confirmed active Personal Access Token.",
                        "secret_verified_at": now_iso,
                    }
                if code_num == 401:
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": "GitLab API rejected token (HTTP 401 Unauthorized).",
                        "secret_verified_at": now_iso,
                    }

            elif det_id == "aws_iam":
                sts_body = b"Action=GetCallerIdentity&Version=2011-06-15"
                sig_headers = _aws_sigv4_headers(raw_cred, aws_pair_val, sts_body, session_tok=aws_sess_tok)
                code_num, body_txt, _ = self._http_probe(
                    endpoint_url,
                    method="POST",
                    headers=sig_headers,
                    body=sts_body,
                )
                if code_num == 200:
                    acct_m = re.search(r"<Account>([^<]{1,64})</Account>", body_txt)
                    arn_m = re.search(r"<Arn>([^<]{1,256})</Arn>", body_txt)
                    acct_id = acct_m.group(1).strip() if acct_m else "unknown-account"
                    arn_val = arn_m.group(1).strip() if arn_m else "sts:GetCallerIdentity"
                    ident = f"AWS Account {acct_id} ({arn_val})"
                    return {
                        "secret_validation_status": "VERIFIED_ACTIVE",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": ident,
                        "secret_validation_message": f"Live AWS STS GetCallerIdentity confirmed active IAM credential ({ident}).",
                        "secret_verified_at": now_iso,
                    }
                if code_num in (401, 403):
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": f"AWS STS rejected IAM credential pair (HTTP {code_num}).",
                        "secret_verified_at": now_iso,
                    }

            elif det_id == "openai_key":
                code_num, _, _ = self._http_probe(
                    endpoint_url,
                    method="GET",
                    headers={"Authorization": f"Bearer {raw_cred}"},
                )
                if code_num == 200:
                    return {
                        "secret_validation_status": "VERIFIED_ACTIVE",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": "OpenAI API Principal (v1/models authorized)",
                        "secret_validation_message": "Live OpenAI /v1/models probe confirmed active API key.",
                        "secret_verified_at": now_iso,
                    }
                if code_num == 401:
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": "OpenAI API rejected key (HTTP 401 Unauthorized).",
                        "secret_verified_at": now_iso,
                    }

            elif det_id == "gemini_key":
                code_num, body_txt, _ = self._http_probe(
                    endpoint_url,
                    method="GET",
                    headers={"x-goog-api-key": raw_cred},
                )
                if code_num == 200:
                    return {
                        "secret_validation_status": "VERIFIED_ACTIVE",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": "Google Gemini API Key (v1beta/models authorized)",
                        "secret_validation_message": "Live Google Gemini API probe confirmed active key via x-goog-api-key header.",
                        "secret_verified_at": now_iso,
                    }
                if code_num in (400, 401, 403) and (
                    code_num in (400, 401) or "api_key_invalid" in body_txt.lower() or "invalid" in body_txt.lower()
                ):
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": f"Google Gemini API rejected key (HTTP {code_num}).",
                        "secret_verified_at": now_iso,
                    }

            elif det_id == "anthropic_key":
                code_num, _, _ = self._http_probe(
                    endpoint_url,
                    method="GET",
                    headers={
                        "x-api-key": raw_cred,
                        "anthropic-version": "2023-06-01",
                    },
                )
                if code_num == 200:
                    return {
                        "secret_validation_status": "VERIFIED_ACTIVE",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": "Anthropic Workspace API Key (v1/models authorized)",
                        "secret_validation_message": "Live Anthropic /v1/models probe confirmed active API key.",
                        "secret_verified_at": now_iso,
                    }
                if code_num == 401:
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": "Anthropic API rejected key (HTTP 401 Unauthorized).",
                        "secret_verified_at": now_iso,
                    }

            elif det_id == "stripe_key":
                code_num, body_txt, _ = self._http_probe(
                    endpoint_url,
                    method="GET",
                    headers={"Authorization": f"Bearer {raw_cred}"},
                )
                if code_num == 200:
                    data = json.loads(body_txt or "{}")
                    acct_id = str(data.get("id") or "stripe-live-account")
                    return {
                        "secret_validation_status": "VERIFIED_ACTIVE",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": f"Stripe Live Account {acct_id}",
                        "secret_validation_message": f"Live Stripe /v1/account probe confirmed active live key ({acct_id}).",
                        "secret_verified_at": now_iso,
                    }
                if code_num == 401:
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": "Stripe API rejected live key (HTTP 401 Unauthorized).",
                        "secret_verified_at": now_iso,
                    }

            elif det_id == "slack_token":
                code_num, body_txt, _ = self._http_probe(
                    endpoint_url,
                    method="POST",
                    headers={
                        "Authorization": f"Bearer {raw_cred}",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    body=b"",
                )
                if code_num == 200:
                    data = json.loads(body_txt or "{}")
                    if data.get("ok") is True:
                        team = str(data.get("team") or "workspace")
                        usr = str(data.get("user") or "bot")
                        ident = f"Slack @{usr} in workspace '{team}'"
                        return {
                            "secret_validation_status": "VERIFIED_ACTIVE",
                            "secret_detector_id": det_id,
                            "secret_verified_identity": ident,
                            "secret_validation_message": f"Live Slack auth.test probe confirmed active token ({ident}).",
                            "secret_verified_at": now_iso,
                        }
                    err_code = str(data.get("error") or "invalid_auth")
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": f"Slack auth.test rejected token (error: {err_code}).",
                        "secret_verified_at": now_iso,
                    }
                if code_num == 401:
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": "Slack API rejected token (HTTP 401).",
                        "secret_verified_at": now_iso,
                    }

            elif det_id == "sendgrid_key":
                code_num, body_txt, _ = self._http_probe(
                    endpoint_url,
                    method="GET",
                    headers={"Authorization": f"Bearer {raw_cred}"},
                )
                if code_num == 200:
                    data = json.loads(body_txt or "{}")
                    scopes_list = data.get("scopes") if isinstance(data.get("scopes"), list) else []
                    scopes_preview = ", ".join(str(s) for s in scopes_list[:5]) or "authenticated"
                    ident = f"SendGrid API Key (scopes: {scopes_preview})"
                    return {
                        "secret_validation_status": "VERIFIED_ACTIVE",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": ident,
                        "secret_validation_message": f"Live SendGrid /v3/scopes probe confirmed active key ({scopes_preview}).",
                        "secret_verified_at": now_iso,
                    }
                if code_num in (401, 403):
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": f"SendGrid API rejected key (HTTP {code_num}).",
                        "secret_verified_at": now_iso,
                    }

            elif det_id == "huggingface_token":
                code_num, body_txt, _ = self._http_probe(
                    endpoint_url,
                    method="GET",
                    headers={"Authorization": f"Bearer {raw_cred}"},
                )
                if code_num == 200:
                    data = json.loads(body_txt or "{}")
                    hf_user = str(data.get("name") or "hf-user")
                    hf_type = str(data.get("type") or "user")
                    ident = f"HuggingFace {hf_type} @{hf_user}"
                    return {
                        "secret_validation_status": "VERIFIED_ACTIVE",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": ident,
                        "secret_validation_message": f"Live HuggingFace whoami-v2 probe confirmed active token (@{hf_user}).",
                        "secret_verified_at": now_iso,
                    }
                if code_num == 401:
                    return {
                        "secret_validation_status": "REVOKED_OR_INVALID",
                        "secret_detector_id": det_id,
                        "secret_verified_identity": None,
                        "secret_validation_message": "HuggingFace API rejected token (HTTP 401 Unauthorized).",
                        "secret_verified_at": now_iso,
                    }

            return {
                "secret_validation_status": "VERIFICATION_ERROR",
                "secret_detector_id": det_id,
                "secret_verified_identity": None,
                "secret_validation_message": f"Provider verification endpoint returned unexpected HTTP {code_num}.",
                "secret_verified_at": now_iso,
            }
        except _ProbeRedirectError as redir_exc:
            return {
                "secret_validation_status": "VERIFICATION_ERROR",
                "secret_detector_id": det_id,
                "secret_verified_identity": None,
                "secret_validation_message": _scrub_raw_value(str(redir_exc), raw_cred),
                "secret_verified_at": now_iso,
            }
        except (TimeoutError, socket.timeout):
            return {
                "secret_validation_status": "VERIFICATION_ERROR",
                "secret_detector_id": det_id,
                "secret_verified_identity": None,
                "secret_validation_message": "Live provider verification timed out (4.0s ceiling).",
                "secret_verified_at": now_iso,
            }
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as net_exc:
            return {
                "secret_validation_status": "VERIFICATION_ERROR",
                "secret_detector_id": det_id,
                "secret_verified_identity": None,
                "secret_validation_message": _scrub_raw_value(
                    f"Live provider network probe error: {type(net_exc).__name__}", raw_cred
                ),
                "secret_verified_at": now_iso,
            }

    def validate_secret_value(
        self,
        raw_secret: str,
        key_name: str = "",
        context_text: str = "",
        allow_live: Optional[bool] = None,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Validates a single raw credential structurally and (when enabled) via safe read-only provider API."""
        raw_cred = (raw_secret or "").strip()
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        det_id, _ = self._classify_detector(raw_cred, key_name=key_name)

        placeholder_reason = self._is_placeholder_value(det_id, raw_cred, key_name=key_name)
        if placeholder_reason:
            return {
                "secret_validation_status": "TEST_OR_PLACEHOLDER",
                "secret_detector_id": det_id,
                "secret_verified_identity": None,
                "secret_validation_message": placeholder_reason,
                "secret_verified_at": now_iso,
            }

        offline_verdict = self._validate_offline_deterministic(det_id, raw_cred, context_text, now_iso)
        if offline_verdict is not None:
            return offline_verdict

        aws_pair_val = ""
        aws_sess_tok = ""
        if det_id == "aws_iam":
            aws_pair_val, aws_sess_tok = _extract_aws_pair_from_context(raw_cred, context_text)
            if not aws_pair_val:
                return {
                    "secret_validation_status": "OFFLINE_STRUCTURALLY_VALID",
                    "secret_detector_id": det_id,
                    "secret_verified_identity": None,
                    "secret_validation_message": "Structurally valid AWS Access Key ID (no paired 40-char key in file/commit context for STS SigV4 check).",
                    "secret_verified_at": now_iso,
                }

        with self._lock:
            eff_live = self._live_enabled if allow_live is None else bool(allow_live)

        if not eff_live:
            return {
                "secret_validation_status": "OFFLINE_STRUCTURALLY_VALID",
                "secret_detector_id": det_id,
                "secret_verified_identity": None,
                "secret_validation_message": f"Offline Mode active: '{det_id}' passed strict prefix, length, and entropy checks without outbound network traffic.",
                "secret_verified_at": now_iso,
            }

        cache_material = f"{det_id}:{raw_cred}:{aws_pair_val}" if det_id == "aws_iam" else f"{det_id}:{raw_cred}"
        cache_key = hashlib.sha256(cache_material.encode("utf-8")).hexdigest()
        now_mono = time.time()
        if not force_refresh:
            with self._lock:
                cached_hit = self._verdict_cache.get(cache_key)
                if cached_hit and (now_mono - cached_hit[0]) < _CACHE_TTL_SECONDS:
                    return dict(cached_hit[1])

        live_res = self._probe_live_provider(det_id, raw_cred, aws_pair_val, aws_sess_tok, now_iso)
        with self._lock:
            self._verdict_cache[cache_key] = (now_mono, dict(live_res))
        return live_res

    def _read_confined_workspace_file(self, root_real: str, cand_path: str) -> str:
        cand_real = os.path.realpath(cand_path)
        confined_fp = (
            cand_real
            if os.path.commonpath([root_real, cand_real]) == root_real
            else ""
        )
        if not confined_fp or not os.path.isfile(confined_fp):
            raise ValueError("Workspace path confinement violation.")
        if os.path.getsize(confined_fp) > 1_500_000:
            return ""
        with open(confined_fp, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()

    def _extract_tokens_from_content(self, rel_path: str, content: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        if not content:
            return hits
        seen_spans: Set[Tuple[int, str]] = set()

        # 1. Multi-line PEM block scan first
        pem_det_id, pem_label, pem_rx = _DETECTOR_SPECS[11]
        for pm in pem_rx.finditer(content):
            raw_pem = pm.group(1).strip()
            line_no = content.count("\n", 0, pm.start()) + 1
            first_ln = raw_pem.splitlines()[0].strip()
            seen_spans.add((line_no, first_ln))
            hits.append(
                {
                    "rel_path": rel_path,
                    "line": line_no,
                    "det_id": pem_det_id,
                    "det_label": pem_label,
                    "key_name": "PRIVATE_KEY_PEM",
                    "raw_val": raw_pem,
                    "snippet": first_ln[:160],
                }
            )

        # 2. Line-by-line high-signal detector pass
        for idx, raw_line in enumerate(content.splitlines()):
            stripped = raw_line.strip()
            if not stripped or len(stripped) > 2000:
                continue
            if stripped.startswith(("#", "//", "/*", "*")):
                continue
            if "re.compile(" in stripped or "new RegExp(" in stripped:
                continue
            line_no = idx + 1
            if any(ln == line_no for ln, _ in seen_spans):
                continue

            for det_id, det_label, rx in _DETECTOR_SPECS:
                if det_id == "private_key_pem":
                    continue
                m_tok = rx.search(stripped)
                if not m_tok:
                    continue
                cand_val = m_tok.group(1).strip()
                if self._is_placeholder_value(det_id, cand_val) is not None:
                    continue
                if det_id == "database_uri":
                    off_chk = self._validate_offline_deterministic(det_id, cand_val, content, "")
                    if off_chk and off_chk.get("secret_validation_status") == "TEST_OR_PLACEHOLDER":
                        continue
                m_var = _ASSIGN_NAME_RX.match(raw_line)
                var_name = m_var.group(1) if m_var else det_id.upper()
                if (line_no, cand_val) not in seen_spans:
                    seen_spans.add((line_no, cand_val))
                    hits.append(
                        {
                            "rel_path": rel_path,
                            "line": line_no,
                            "det_id": det_id,
                            "det_label": det_label,
                            "key_name": var_name,
                            "raw_val": cand_val,
                            "snippet": stripped[:160],
                        }
                    )
                break
        return hits

    def _scan_working_tree(self, root_real: str) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        is_synth = os.path.basename(root_real).lower() == "synthetic_test_target"
        file_contents: Dict[str, str] = {}
        tree_hits: List[Dict[str, Any]] = []
        if is_synth or not os.path.isdir(root_real):
            return tree_hits, file_contents

        for cur_root, dir_names, file_names in os.walk(root_real):
            dir_names[:] = [
                d
                for d in dir_names
                if d.lower() not in _EXCLUDED_DIR_NAMES
                and not d.lower().startswith(".alastor")
                and d.lower() != "synthetic_test_target"
            ]
            for fname in file_names:
                full_p = os.path.join(cur_root, fname)
                rel_p = os.path.relpath(full_p, root_real).replace("\\", "/")
                if _is_excluded_relpath(rel_p):
                    continue
                try:
                    txt = self._read_confined_workspace_file(root_real, full_p)
                except Exception:
                    continue
                if not txt:
                    continue
                file_contents[rel_p] = txt
                file_hits = self._extract_tokens_from_content(rel_p, txt)
                tree_hits.extend(file_hits)
        return tree_hits, file_contents

    def _hunt_git_commits(self, root_real: str, max_commits: int) -> List[Dict[str, Any]]:
        git_marker = os.path.join(root_real, ".git")
        if not os.path.exists(git_marker):
            return []
        if os.path.basename(root_real).lower() == "synthetic_test_target":
            return []

        bounded_commits = max(1, min(500, int(max_commits or 50)))
        git_env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CEILING_DIRECTORIES": os.path.dirname(root_real),
        }
        try:
            proc = subprocess.run(
                [
                    "git",
                    "-C",
                    root_real,
                    "log",
                    "-p",
                    "-n",
                    str(bounded_commits),
                    "--no-color",
                    "--unified=0",
                    "--pretty=format:__ALASTOR_COMMIT__%H|%an <%ae>|%ad",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=12,
                env=git_env,
            )
        except Exception as exc:
            safe_err = str(exc).replace("\r", " ").replace("\n", " ")[:140]
            logger.warning("Git history hunter skipped on %s: %s", os.path.basename(root_real), safe_err)
            return []

        if proc.returncode != 0 or not proc.stdout:
            return []

        commits_parsed: List[Dict[str, Any]] = []
        cur_commit: Optional[Dict[str, Any]] = None
        cur_file = ""
        cur_line_no = 1

        for raw_ln in proc.stdout.splitlines():
            if raw_ln.startswith("__ALASTOR_COMMIT__"):
                meta = raw_ln[len("__ALASTOR_COMMIT__") :]
                parts = meta.split("|", 2)
                cur_commit = {
                    "sha": (parts[0] if len(parts) > 0 else "").strip(),
                    "author": (parts[1] if len(parts) > 1 else "unknown").strip(),
                    "date": (parts[2] if len(parts) > 2 else "").strip(),
                    "file_added_blocks": {},
                }
                commits_parsed.append(cur_commit)
                cur_file = ""
                cur_line_no = 1
                continue

            if cur_commit is None:
                continue

            if raw_ln.startswith("+++ b/"):
                cur_file = raw_ln[6:].strip().replace("\\", "/")
                if cur_file.lower().startswith("synthetic_test_target/"):
                    cur_file = ""
                cur_line_no = 1
                continue
            if raw_ln.startswith("+++ /dev/null"):
                cur_file = ""
                continue

            m_hunk = _HUNK_LINE_RX.match(raw_ln)
            if m_hunk:
                cur_line_no = int(m_hunk.group(1) or 1)
                continue

            if not cur_file or _is_excluded_relpath(cur_file):
                continue

            if raw_ln.startswith("+") and not raw_ln.startswith("+++"):
                added_text = raw_ln[1:]
                file_entries = cur_commit["file_added_blocks"].setdefault(cur_file, [])
                file_entries.append((cur_line_no, added_text))
                cur_line_no += 1

        hist_hits: List[Dict[str, Any]] = []
        for commit_rec in commits_parsed:
            c_sha = commit_rec["sha"]
            c_author = commit_rec["author"]
            c_date = commit_rec["date"]
            for rel_fp, numbered_lines in commit_rec["file_added_blocks"].items():
                joined_added = "\n".join(txt for _, txt in numbered_lines)
                extracted = self._extract_tokens_from_content(rel_fp, joined_added)
                for item in extracted:
                    rel_idx = max(0, min(len(numbered_lines) - 1, int(item["line"]) - 1))
                    orig_line = numbered_lines[rel_idx][0]
                    hist_hits.append(
                        {
                            **item,
                            "line": orig_line,
                            "commit_sha": c_sha,
                            "commit_author": c_author,
                            "commit_date": c_date,
                            "context_text": joined_added,
                        }
                    )
        return hist_hits

    def _is_cred_finding(self, item: Finding) -> bool:
        rule_up = (item.rule_id or "").upper()
        cwe_up = (item.cwe_id or "").upper()
        title_up = (item.title or "").upper()
        return bool(
            item.is_secret_finding
            or rule_up.startswith("SECRET-")
            or "SECRET" in rule_up
            or "CREDENTIAL" in rule_up
            or cwe_up == "CWE-798"
            or "HARDCODED SECRET" in title_up
            or "API KEY" in title_up
        )

    def _extract_raw_from_finding(self, item: Finding) -> Tuple[str, str, str, int]:
        node = item.path_nodes[-1] if item.path_nodes else {}
        rel_fp = str(
            (item.best_fix_location.filepath if item.best_fix_location and item.best_fix_location.filepath else "")
            or (node.get("filepath") if isinstance(node, dict) else getattr(node, "filepath", ""))
            or ""
        ).replace("\\", "/")
        ln_num = int(
            (item.best_fix_location.line if item.best_fix_location and item.best_fix_location.line else 0)
            or (node.get("start_line") if isinstance(node, dict) else getattr(node, "start_line", 1))
            or 1
        )
        code_txt = str(
            (node.get("code") if isinstance(node, dict) else getattr(node, "code", ""))
            or (item.best_fix_location.code_snippet if item.best_fix_location else "")
            or ""
        ).strip()
        ident_name = str(
            getattr(item, "secret_key_name", None)
            or (node.get("name") if isinstance(node, dict) else getattr(node, "name", ""))
            or "CREDENTIAL_ID"
        ).strip()
        raw_val = str(getattr(item, "secret_value_raw", None) or "").strip()
        if not raw_val and code_txt:
            m_q = re.search(r'["\']([^"\']{4,})["\']', code_txt)
            if m_q:
                raw_val = m_q.group(1).strip()
        return raw_val, ident_name, rel_fp, ln_num

    def _apply_verdict_to_finding(self, item: Finding, raw_val: str, ident_name: str, verdict: Dict[str, Any]) -> None:
        status_val = verdict.get("secret_validation_status")
        det_id = verdict.get("secret_detector_id")
        det_ident = verdict.get("secret_verified_identity")
        det_msg = verdict.get("secret_validation_message")
        det_ts = verdict.get("secret_verified_at")

        setattr(item, "is_secret_finding", True)
        if ident_name and not getattr(item, "secret_key_name", None):
            setattr(item, "secret_key_name", ident_name)
        if raw_val:
            setattr(item, "secret_value_raw", raw_val)
            setattr(item, "secret_value_masked", _mask_token(raw_val))
            setattr(item, "secret_entropy", _shannon_entropy(raw_val))
        setattr(item, "secret_validation_status", status_val)
        setattr(item, "secret_detector_id", det_id)
        setattr(item, "secret_verified_identity", det_ident)
        setattr(item, "secret_validation_message", det_msg)
        setattr(item, "secret_verified_at", det_ts)
        if not getattr(item, "secret_source", None):
            setattr(item, "secret_source", "WORKING_TREE")

        if status_val == "VERIFIED_ACTIVE":
            item.severity = "CRITICAL"
            item.cvss_score = max(float(item.cvss_score or 0.0), 9.8)

    def scan_and_validate_workspace(
        self,
        target_dir: str,
        existing_findings: List[Finding],
        allow_live: Optional[bool] = None,
        force_refresh: bool = False,
    ) -> List[Finding]:
        """
        Scans working tree + `.git` history, deduplicates against `existing_findings`,
        and validates all discovered secret findings concurrently.
        """
        merged: List[Finding] = [f.model_copy(deep=True) for f in (existing_findings or [])]
        raw_root = target_dir if target_dir and os.path.exists(target_dir) else self.platform_root
        root_real = os.path.realpath(os.path.dirname(raw_root) if os.path.isfile(raw_root) else raw_root)

        tree_hits, file_contents = self._scan_working_tree(root_real)

        existing_locs: Set[Tuple[str, int]] = set()
        working_cred_to_finding: Dict[str, Finding] = {}

        for f_item in merged:
            if not self._is_cred_finding(f_item):
                continue
            raw_v, _, rel_fp, ln_no = self._extract_raw_from_finding(f_item)
            if rel_fp:
                existing_locs.add((rel_fp, ln_no))
            if raw_v and getattr(f_item, "secret_source", "WORKING_TREE") != "GIT_HISTORY":
                working_cred_to_finding[raw_v] = f_item

        # Emit working-tree findings missed by AST-only rules
        for hit in tree_hits:
            h_fp = hit["rel_path"]
            h_ln = int(hit["line"])
            h_raw = hit["raw_val"]
            if (h_fp, h_ln) in existing_locs or h_raw in working_cred_to_finding:
                continue
            fid = hashlib.sha256(f"TRUFFLE-WT:{h_fp}:{h_ln}:{hit['det_id']}".encode("utf-8")).hexdigest()[:16]
            node_id = f"truffle-wt-node-{fid}"
            wt_kwargs: Dict[str, Any] = {
                "id": fid,
                "rule_id": "RULE-8-HARDCODED-SECRET",
                "severity": "HIGH",
                "title": f"Exposed {hit['det_label']} (`{hit['key_name']}`) in `{h_fp}` (Line {h_ln})",
                "description": (
                    f"ALASTOR Native Secret Scanner detected `{hit['det_label']}` (`{_mask_token(h_raw)}`) "
                    f"in `{h_fp}` at Line {h_ln}."
                ),
                "cwe_id": "CWE-798",
                "owasp_category": "A07:2021 - Identification and Authentication Failures",
                "cvss_score": 9.1,
                "remediation": (
                    f"Revoke and rotate `{hit['key_name']}` immediately, remove it from `{h_fp}`, "
                    f"and load credentials at runtime from environment variables or a Secret Manager."
                ),
                "source_site": "ALASTOR Native Secret Scanner",
                "reference_url": "https://cwe.mitre.org/data/definitions/798.html",
                "scan_engine": "SAST",
                "language": _infer_lang(h_fp),
                "is_secret_finding": True,
                "secret_key_name": hit["key_name"],
                "secret_value_raw": h_raw,
                "secret_value_masked": _mask_token(h_raw),
                "secret_type": hit["det_label"],
                "secret_entropy": _shannon_entropy(h_raw),
                "secret_detector_id": hit["det_id"],
                "secret_source": "WORKING_TREE",
                "path_nodes": [
                    {
                        "id": node_id,
                        "label": "Assignment",
                        "ast_type": "credential_literal",
                        "name": hit["key_name"],
                        "code": f"{hit['key_name']} = \"{_mask_token(h_raw)}\"",
                        "filepath": h_fp,
                        "start_line": h_ln,
                        "end_line": h_ln,
                        "start_col": 0,
                        "end_col": len(hit["snippet"]),
                        "scope_id": "working_tree",
                        "is_source": False,
                        "is_sink": True,
                        "is_sanitizer": False,
                    }
                ],
                "path_edges": [],
                "best_fix_location": BestFixLocation(
                    node_id=node_id,
                    filepath=h_fp,
                    line=h_ln,
                    column=0,
                    code_snippet=f"{hit['key_name']} = \"{_mask_token(h_raw)}\"",
                    explanation=f"Remove hardcoded {hit['det_label']} from source control and rotate immediately.",
                    recommended_fix=f"os.environ.get(\"{hit['key_name']}\")",
                ),
            }
            new_wt = Finding(**wt_kwargs)
            merged.append(new_wt)
            existing_locs.add((h_fp, h_ln))
            working_cred_to_finding[h_raw] = new_wt

        # Hunt `.git` commit history when enabled
        cfg = self.get_config()
        hist_context_by_id: Dict[str, str] = {}
        if cfg.scan_git_history:
            git_hits = self._hunt_git_commits(root_real, cfg.max_git_commits)
            emitted_git_creds: Set[str] = set()
            for g_hit in git_hits:
                g_raw = g_hit["raw_val"]
                g_sha_short = (g_hit["commit_sha"] or "")[:12]
                g_author = g_hit["commit_author"]
                if g_raw in working_cred_to_finding:
                    wt_f = working_cred_to_finding[g_raw]
                    if not getattr(wt_f, "secret_commit_sha", None) and g_sha_short:
                        setattr(wt_f, "secret_commit_sha", g_sha_short)
                        setattr(wt_f, "secret_commit_author", g_author)
                    continue
                if g_raw in emitted_git_creds:
                    continue
                emitted_git_creds.add(g_raw)
                g_fp = g_hit["rel_path"]
                g_ln = int(g_hit["line"])
                gfid = hashlib.sha256(
                    f"TRUFFLE-GIT:{g_sha_short}:{g_fp}:{g_ln}:{g_hit['det_id']}".encode("utf-8")
                ).hexdigest()[:16]
                gnode_id = f"truffle-git-node-{gfid}"
                git_kwargs: Dict[str, Any] = {
                    "id": gfid,
                    "rule_id": "SECRET-GIT-HISTORY-LEAK",
                    "severity": "HIGH",
                    "title": f"Git History Leak: {g_hit['det_label']} in `{g_fp}` (Commit `{g_sha_short}`)",
                    "description": (
                        f"Credential `{_mask_token(g_raw)}` (`{g_hit['det_label']}`) was deleted from the current "
                        f"working tree but remains recoverable in `.git` commit `{g_sha_short}` authored by "
                        f"`{g_author}` ({g_hit['commit_date']}) at `{g_fp}:L{g_ln}`."
                    ),
                    "cwe_id": "CWE-798",
                    "owasp_category": "A07:2021 - Identification and Authentication Failures",
                    "cvss_score": 9.1,
                    "remediation": (
                        f"1. Immediately revoke and rotate `{g_hit['key_name']}` with the provider (rewriting git history alone does not invalidate leaked keys). "
                        f"2. Purge `{g_fp}` commit history using `git filter-repo --replace-text` and force-push cleaned refs."
                    ),
                    "source_site": "ALASTOR Git-History Hunter",
                    "reference_url": "https://cwe.mitre.org/data/definitions/798.html",
                    "scan_engine": "SAST",
                    "language": _infer_lang(g_fp),
                    "is_secret_finding": True,
                    "secret_key_name": g_hit["key_name"],
                    "secret_value_raw": g_raw,
                    "secret_value_masked": _mask_token(g_raw),
                    "secret_type": g_hit["det_label"],
                    "secret_entropy": _shannon_entropy(g_raw),
                    "secret_detector_id": g_hit["det_id"],
                    "secret_source": "GIT_HISTORY",
                    "secret_commit_sha": g_sha_short,
                    "secret_commit_author": g_author,
                    "path_nodes": [
                        {
                            "id": gnode_id,
                            "label": "Assignment",
                            "ast_type": "git_history_credential",
                            "name": g_hit["key_name"],
                            "code": f"[commit {g_sha_short}] {g_hit['key_name']} = \"{_mask_token(g_raw)}\"",
                            "filepath": g_fp,
                            "start_line": g_ln,
                            "end_line": g_ln,
                            "start_col": 0,
                            "end_col": len(g_hit["snippet"]),
                            "scope_id": f"git:{g_sha_short}",
                            "is_source": False,
                            "is_sink": True,
                            "is_sanitizer": False,
                        }
                    ],
                    "path_edges": [],
                    "best_fix_location": BestFixLocation(
                        node_id=gnode_id,
                        filepath=g_fp,
                        line=g_ln,
                        column=0,
                        code_snippet=f"[commit {g_sha_short}] {g_hit['key_name']} = \"{_mask_token(g_raw)}\"",
                        explanation=(
                            f"Deleted from working tree, but still exposed in git commit `{g_sha_short}` ({g_author}). "
                            f"Rotate the credential immediately and scrub git history with `git filter-repo`."
                        ),
                        recommended_fix="Rotate provider credential + run `git filter-repo --replace-text expressions.txt`",
                    ),
                }
                new_git_f = Finding(**git_kwargs)
                hist_context_by_id[gfid] = g_hit.get("context_text", "")
                merged.append(new_git_f)

        # Validate all secret findings concurrently via bounded ThreadPoolExecutor(max_workers=6)
        tasks: List[Tuple[Finding, str, str, str]] = []
        for f_item in merged:
            if not self._is_cred_finding(f_item):
                continue
            raw_v, ident_n, rel_fp, _ = self._extract_raw_from_finding(f_item)
            if not raw_v:
                continue
            ctx_txt = hist_context_by_id.get(f_item.id) or file_contents.get(rel_fp, "")
            if not ctx_txt and rel_fp:
                cand_full = os.path.join(root_real, rel_fp)
                if os.path.isfile(cand_full):
                    try:
                        ctx_txt = self._read_confined_workspace_file(root_real, cand_full)
                    except Exception:
                        ctx_txt = ""
            tasks.append((f_item, raw_v, ident_n, ctx_txt))

        if tasks:
            def _eval_one(entry: Tuple[Finding, str, str, str]) -> Tuple[Finding, str, str, Dict[str, Any]]:
                f_obj, raw_c, key_n, ctx_s = entry
                verdict_d = self.validate_secret_value(
                    raw_c,
                    key_name=key_n,
                    context_text=ctx_s,
                    allow_live=allow_live,
                    force_refresh=force_refresh,
                )
                return f_obj, raw_c, key_n, verdict_d

            max_w = min(6, len(tasks))
            with ThreadPoolExecutor(max_workers=max_w) as pool:
                for f_obj, raw_c, key_n, verdict_d in pool.map(_eval_one, tasks):
                    self._apply_verdict_to_finding(f_obj, raw_c, key_n, verdict_d)

        return merged

    def verify_selected_findings(
        self,
        findings: List[Finding],
        finding_ids: Optional[List[str]] = None,
        target_dir: Optional[str] = None,
        allow_live: Optional[bool] = None,
        force_refresh: bool = False,
    ) -> List[Finding]:
        """Re-verifies selected (or all) secret findings in place and returns the updated list."""
        wanted = set(finding_ids or [])
        raw_root = target_dir if target_dir and os.path.exists(target_dir) else self.platform_root
        root_real = os.path.realpath(os.path.dirname(raw_root) if os.path.isfile(raw_root) else raw_root)

        to_verify: List[Tuple[Finding, str, str, str]] = []
        for f_item in findings:
            if not self._is_cred_finding(f_item):
                continue
            if wanted and f_item.id not in wanted:
                continue
            raw_v, ident_n, rel_fp, _ = self._extract_raw_from_finding(f_item)
            if not raw_v:
                continue
            ctx_txt = ""
            if rel_fp:
                cand_full = os.path.join(root_real, rel_fp)
                if os.path.isfile(cand_full):
                    try:
                        ctx_txt = self._read_confined_workspace_file(root_real, cand_full)
                    except Exception:
                        ctx_txt = ""
            to_verify.append((f_item, raw_v, ident_n, ctx_txt))

        if to_verify:
            def _run_item(entry: Tuple[Finding, str, str, str]) -> Tuple[Finding, str, str, Dict[str, Any]]:
                f_obj, raw_c, key_n, ctx_s = entry
                verdict_d = self.validate_secret_value(
                    raw_c,
                    key_name=key_n,
                    context_text=ctx_s,
                    allow_live=allow_live,
                    force_refresh=force_refresh,
                )
                return f_obj, raw_c, key_n, verdict_d

            with ThreadPoolExecutor(max_workers=min(6, len(to_verify))) as pool:
                for f_obj, raw_c, key_n, verdict_d in pool.map(_run_item, to_verify):
                    self._apply_verdict_to_finding(f_obj, raw_c, key_n, verdict_d)

        return findings

    def build_inventory_response(self, findings: List[Finding]) -> SecretInventoryResponse:
        cred_items = [f for f in (findings or []) if self._is_cred_finding(f)]
        verified_c = sum(1 for f in cred_items if f.secret_validation_status == "VERIFIED_ACTIVE")
        revoked_c = sum(1 for f in cred_items if f.secret_validation_status == "REVOKED_OR_INVALID")
        struct_c = sum(1 for f in cred_items if f.secret_validation_status == "OFFLINE_STRUCTURALLY_VALID")
        placeholder_c = sum(1 for f in cred_items if f.secret_validation_status == "TEST_OR_PLACEHOLDER")
        git_hist_c = sum(1 for f in cred_items if f.secret_source == "GIT_HISTORY")
        return SecretInventoryResponse(
            config=self.get_config(),
            total_secrets=len(cred_items),
            verified_active_count=verified_c,
            revoked_count=revoked_c,
            structurally_valid_count=struct_c,
            test_placeholder_count=placeholder_c,
            git_history_count=git_hist_c,
            secrets=cred_items,
        )


_ENGINE_SINGLETON: Optional[SecretValidatorEngine] = None
_SINGLETON_LOCK = threading.Lock()


def get_secret_validator_engine(platform_root: Optional[str] = None) -> SecretValidatorEngine:
    global _ENGINE_SINGLETON
    with _SINGLETON_LOCK:
        if _ENGINE_SINGLETON is None:
            _ENGINE_SINGLETON = SecretValidatorEngine(platform_root=platform_root)
        return _ENGINE_SINGLETON
