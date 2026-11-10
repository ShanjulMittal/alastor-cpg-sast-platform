"""
Token-Efficient Multi-Provider BYOK Frontier AI Engine for ALASTOR v4.0.

Security & Efficiency Invariants:
1. Zero-Leak Vault: Stores configuration and SHA-256 verdict cache strictly inside `.alastor_vault/`
   verified via `os.path.realpath` + `os.path.commonpath` with `0o600` permissions. Raw credentials
   are never returned by `get_public_config()` or written to disk when `persist_key=False`.
2. SSRF-Hardened Outbound Egress: Validates URLs via `urllib.parse.urlparse` and `ipaddress` before
   constructing `urllib.request.Request`, restricting traffic to allowlisted `https://` provider
   endpoints (or explicit loopback `localhost`/`127.0.0.1` for `openai_compatible`).
3. Workspace Path Confinement: Reads source slices strictly through `_locate_enumerated_workspace_file`
   and `os.path.commonpath` containment checks.
4. CPG Micro-Slicing & SHA-256 Caching: Compresses multi-hundred-line files down to enclosing
   signatures + deduplicated +-3 line taint windows (capped at 40 lines) and caches verdicts by SHA-256.
"""
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from engine.remediation_patcher import _locate_enumerated_workspace_file
from models import (
    AiCodeAuditObservation,
    AiCodeAuditRequest,
    AiCodeAuditResponse,
    AiConfigUpdateRequest,
    AiConnectionTestResponse,
    AiFindingVerdict,
    AiGraphExplainRequest,
    AiGraphExplainResponse,
    AiPatchSynthesisRequest,
    AiPatchSynthesisResponse,
    AiProviderType,
    AiPublicConfigResponse,
    AiTokenTelemetry,
    AiValidateFindingsRequest,
    AiValidateFindingsResponse,
    BestFixLocation,
    CPGNode,
    Finding,
)

logger = logging.getLogger("cpg-sast.frontier_ai")

_ALLOWED_VAULT_FILENAMES = frozenset({"ai_config.json", "ai_verdict_cache.json"})
_MAX_VERDICT_CACHE_ENTRIES = 500
_MAX_MICRO_SLICE_LINES = 40

_PROVIDER_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "gemini",
        "label": "Google Gemini",
        "default_model": "gemini-2.5-flash",
        "models": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
        "default_base_url": "https://generativelanguage.googleapis.com",
        "requires_api_key": True,
    },
    {
        "id": "openai",
        "label": "OpenAI",
        "default_model": "gpt-4o-mini",
        "models": ["gpt-4o-mini", "gpt-4o", "o3-mini"],
        "default_base_url": "https://api.openai.com/v1",
        "requires_api_key": True,
    },
    {
        "id": "anthropic",
        "label": "Anthropic Claude",
        "default_model": "claude-3-5-haiku-latest",
        "models": ["claude-3-5-haiku-latest", "claude-3-7-sonnet-latest", "claude-3-5-sonnet-latest"],
        "default_base_url": "https://api.anthropic.com/v1",
        "requires_api_key": True,
    },
    {
        "id": "openai_compatible",
        "label": "OpenAI-Compatible (OpenRouter / Ollama / vLLM)",
        "default_model": "llama3.2",
        "models": ["llama3.2", "qwen2.5-coder:7b", "deepseek-r1"],
        "default_base_url": "http://localhost:11434/v1",
        "requires_api_key": False,
    },
]

_DEFAULT_BASE_URLS: Dict[str, str] = {
    "gemini": "https://generativelanguage.googleapis.com",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "openai_compatible": "http://localhost:11434/v1",
}

_STRICT_PROVIDER_HOSTS: Dict[str, str] = {
    "gemini": "generativelanguage.googleapis.com",
    "openai": "api.openai.com",
    "anthropic": "api.anthropic.com",
}

_BLOCKED_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
    "100.100.100.200",
    "0.0.0.0",
    "::",
    "::1",
    "[::]",
    "[::1]",
})

_HEADER_SIG_RX = re.compile(
    r"^\s*(?:async\s+def\s+|def\s+|class\s+|export\s+(?:default\s+)?(?:async\s+)?(?:function|class)\s+|(?:async\s+)?function\s+)"
)


class _AiDispatchError(Exception):
    """Internal structured exception carrying safe error_code and user_message."""

    def __init__(self, error_code: str, user_message: str):
        super().__init__(user_message)
        self.error_code = error_code
        self.user_message = user_message


def _mask_credential(raw_cred: str) -> str:
    clean = (raw_cred or "").strip()
    if not clean:
        return ""
    if len(clean) <= 4:
        return "••••••••"
    return "••••••••" + clean[-4:]


def _validate_provider_endpoint(
    provider: str,
    base_url: Optional[str],
    verify_dns: bool = False,
) -> str:
    """
    Validates outbound AI provider base URL against SSRF (CWE-918):
    - Fixed providers (`gemini`, `openai`, `anthropic`) MUST use `https://` on their exact official host.
    - `openai_compatible` MUST use either `https://` on a non-private/non-metadata public host OR
      explicit loopback (`localhost` or `127.0.0.1`) over `http`/`https` for local Ollama/vLLM.
    """
    if provider not in _DEFAULT_BASE_URLS:
        raise ValueError(f"Unsupported or unsafe AI provider '{provider}'.")

    raw_candidate = (base_url or "").strip() or _DEFAULT_BASE_URLS[provider]
    if re.search(r"[\r\n\x00\s]", raw_candidate):
        raise ValueError("Unsupported or unsafe characters in AI endpoint URL.")

    parsed = urllib.parse.urlparse(raw_candidate)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    if parsed.username or parsed.password:
        raise ValueError("Unsupported or unsafe embedded credentials in AI endpoint URL.")
    if not scheme or not host:
        raise ValueError("Unsupported or unsafe AI endpoint URL: missing scheme or hostname.")
    if host in _BLOCKED_METADATA_HOSTS or host.endswith(".internal"):
        raise ValueError(f"Unsupported or unsafe cloud metadata or internal host '{host}'.")

    # Validate literal IPv4 / IPv6 addresses
    is_ip_literal = False
    try:
        ip_obj = ipaddress.ip_address(host)
        is_ip_literal = True
    except ValueError:
        ip_obj = None

    if is_ip_literal and ip_obj is not None:
        if provider == "openai_compatible" and host == "127.0.0.1" and scheme in {"http", "https"}:
            return raw_candidate.rstrip("/")
        raise ValueError(f"Unsupported or unsafe IP literal '{host}' for AI provider '{provider}'.")

    if provider in _STRICT_PROVIDER_HOSTS:
        expected_host = _STRICT_PROVIDER_HOSTS[provider]
        if scheme != "https" or host != expected_host:
            raise ValueError(
                f"Unsupported or unsafe endpoint for provider '{provider}'; expected https://{expected_host}."
            )
        return raw_candidate.rstrip("/")

    # provider == "openai_compatible"
    if host == "localhost":
        if scheme not in {"http", "https"}:
            raise ValueError(f"Unsupported or unsafe URL scheme '{scheme}' for localhost AI endpoint.")
        return raw_candidate.rstrip("/")

    if scheme != "https":
        raise ValueError(
            f"Unsupported or unsafe URL scheme '{scheme}'; non-loopback endpoints require https://."
        )

    if verify_dns:
        port = parsed.port or 443
        try:
            addr_infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ValueError(f"Unsupported or unsafe unresolvable host '{host}': {exc}") from exc
        for info in addr_infos:
            resolved_ip = ipaddress.ip_address(info[4][0])
            if (
                resolved_ip.is_private
                or resolved_ip.is_loopback
                or resolved_ip.is_link_local
                or resolved_ip.is_reserved
                or resolved_ip.is_multicast
                or resolved_ip.is_unspecified
            ):
                raise ValueError(
                    f"Unsupported or unsafe non-public resolved IP ({resolved_ip}) for host '{host}'."
                )

    return raw_candidate.rstrip("/")


def _extract_json_object(raw_text: str) -> Dict[str, Any]:
    """Parses JSON object from model response, stripping optional markdown code fences."""
    cleaned = (raw_text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        cleaned = cleaned.strip()
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        start_idx = cleaned.find("{")
        end_idx = cleaned.rfind("}")
        if 0 <= start_idx < end_idx:
            parsed = json.loads(cleaned[start_idx : end_idx + 1])
            if isinstance(parsed, dict):
                return parsed
    raise ValueError("Model response did not contain a valid JSON object.")


def _read_confined_workspace_file(
    raw_filepath: str,
    allowed_roots: List[str],
) -> Optional[Tuple[str, str]]:
    """
    Resolves `raw_filepath` through `_locate_enumerated_workspace_file` and verifies
    `os.path.commonpath` confinement within `allowed_roots` before reading UTF-8 text.
    """
    server_entry = _locate_enumerated_workspace_file(raw_filepath, allowed_roots)
    if not server_entry:
        return None
    server_real = os.path.realpath(server_entry)
    confined_root: Optional[str] = None
    for raw_root in allowed_roots:
        if not raw_root or not os.path.exists(raw_root):
            continue
        root_real = os.path.realpath(os.path.dirname(raw_root) if os.path.isfile(raw_root) else raw_root)
        try:
            if os.path.commonpath([root_real, server_real]) == root_real:
                confined_root = root_real
                break
        except ValueError:
            continue
    if not confined_root:
        return None
    confined_path = (
        server_real
        if os.path.commonpath([confined_root, server_real]) == confined_root
        else ""
    )
    if not confined_path or not os.path.isfile(confined_path):
        return None
    with open(confined_path, "r", encoding="utf-8", errors="replace") as fh:
        return confined_path, fh.read()


def _find_enclosing_signature_line(lines: List[str], anchor_line_1idx: int) -> Optional[int]:
    """Finds the 1-indexed line number of the nearest enclosing `def`/`class`/`function` header."""
    if not lines:
        return None
    idx = max(0, min(len(lines) - 1, anchor_line_1idx - 1))
    anchor_raw = lines[idx]
    anchor_indent = len(anchor_raw) - len(anchor_raw.lstrip()) if anchor_raw.strip() else 999
    if _HEADER_SIG_RX.match(anchor_raw):
        return idx + 1
    for scan_idx in range(idx - 1, -1, -1):
        cand = lines[scan_idx]
        if not cand.strip():
            continue
        cand_indent = len(cand) - len(cand.lstrip())
        if _HEADER_SIG_RX.match(cand) and cand_indent < anchor_indent:
            return scan_idx + 1
    return None


class FrontierAiEngine:
    """Token-efficient multi-provider BYOK Frontier AI engine with 0o600 local vault & SHA-256 slice cache."""

    def __init__(self, vault_dir: Optional[str] = None):
        if vault_dir:
            self.vault_dir = os.path.realpath(vault_dir)
        else:
            backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            platform_root = os.path.dirname(backend_dir)
            self.vault_dir = os.path.realpath(os.path.join(platform_root, ".alastor_vault"))

        self._lock = threading.Lock()
        self._provider: AiProviderType = "gemini"
        self._model: str = "gemini-2.5-flash"
        self._base_url: str = _DEFAULT_BASE_URLS["gemini"]
        self._persist_key: bool = True
        self._active_cred: str = ""
        self._telemetry: Dict[str, int] = {
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_full_file_tokens_est": 0,
            "total_tokens_saved": 0,
            "cache_hits": 0,
            "total_requests": 0,
        }
        self._verdict_cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()

        self._load_vault_state()

    def _resolve_vault_file(self, filename: str) -> str:
        """Resolves a vault file strictly inside `self.vault_dir` via realpath + commonpath."""
        if filename not in _ALLOWED_VAULT_FILENAMES:
            raise ValueError("Unsupported vault filename.")
        vault_real = os.path.realpath(self.vault_dir)
        os.makedirs(vault_real, mode=0o700, exist_ok=True)
        try:
            os.chmod(vault_real, 0o700)
        except OSError:
            pass
        target_real = os.path.realpath(os.path.join(vault_real, filename))
        if os.path.commonpath([vault_real, target_real]) != vault_real:
            raise ValueError("Vault path confinement violation.")
        return target_real

    def _write_vault_json(self, filename: str, payload: Dict[str, Any]) -> None:
        vault_real = os.path.realpath(self.vault_dir)
        raw_target = self._resolve_vault_file(filename)
        confined_vault_path = (
            raw_target
            if os.path.commonpath([vault_real, raw_target]) == vault_real
            else ""
        )
        if not confined_vault_path:
            raise ValueError("Vault path confinement violation.")
        serialized = json.dumps(payload, indent=2)
        with open(confined_vault_path, "w", encoding="utf-8") as fh:
            fh.write(serialized)
        try:
            os.chmod(confined_vault_path, 0o600)
        except OSError:
            pass

    def _load_vault_state(self) -> None:
        try:
            cfg_path = self._resolve_vault_file("ai_config.json")
            if os.path.isfile(cfg_path):
                with open(cfg_path, "r", encoding="utf-8") as fh:
                    blob = json.load(fh)
                if isinstance(blob, dict):
                    prov = str(blob.get("provider") or "gemini")
                    if prov in _DEFAULT_BASE_URLS:
                        self._provider = prov  # type: ignore[assignment]
                    self._model = str(blob.get("model") or _PROVIDER_CATALOG[0]["default_model"])
                    raw_base = str(blob.get("base_url") or _DEFAULT_BASE_URLS[self._provider])
                    try:
                        self._base_url = _validate_provider_endpoint(self._provider, raw_base)
                    except ValueError:
                        self._base_url = _DEFAULT_BASE_URLS[self._provider]
                    self._persist_key = bool(blob.get("persist_key", True))
                    enc_cred = str(blob.get("stored_cred_b64") or "")
                    if enc_cred and self._persist_key:
                        self._active_cred = base64.b64decode(enc_cred.encode("ascii")).decode("utf-8")
                    saved_tel = blob.get("token_telemetry")
                    if isinstance(saved_tel, dict):
                        for k in self._telemetry:
                            if k in saved_tel:
                                self._telemetry[k] = max(0, int(saved_tel[k]))
        except Exception as exc:
            logger.warning("Failed to load Frontier AI config from vault: %s", str(exc)[:120])

        try:
            cache_path = self._resolve_vault_file("ai_verdict_cache.json")
            if os.path.isfile(cache_path):
                with open(cache_path, "r", encoding="utf-8") as fh:
                    cache_blob = json.load(fh)
                entries = cache_blob.get("entries") if isinstance(cache_blob, dict) else None
                if isinstance(entries, dict):
                    for ck, cv in list(entries.items())[-_MAX_VERDICT_CACHE_ENTRIES:]:
                        if isinstance(ck, str) and isinstance(cv, dict):
                            self._verdict_cache[ck] = cv
        except Exception as exc:
            logger.warning("Failed to load Frontier AI verdict cache: %s", str(exc)[:120])

    def _persist_config_locked(self) -> None:
        encoded_cred = ""
        if self._persist_key and self._active_cred:
            encoded_cred = base64.b64encode(self._active_cred.encode("utf-8")).decode("ascii")
        payload: Dict[str, Any] = {
            "version": 1,
            "provider": self._provider,
            "model": self._model,
            "base_url": self._base_url,
            "persist_key": self._persist_key,
            "stored_cred_b64": encoded_cred,
            "token_telemetry": dict(self._telemetry),
        }
        try:
            self._write_vault_json("ai_config.json", payload)
        except Exception as exc:
            logger.warning("Failed to persist Frontier AI config: %s", str(exc)[:120])

    def _persist_cache_locked(self) -> None:
        while len(self._verdict_cache) > _MAX_VERDICT_CACHE_ENTRIES:
            self._verdict_cache.popitem(last=False)
        try:
            self._write_vault_json(
                "ai_verdict_cache.json",
                {"version": 1, "entries": dict(self._verdict_cache)},
            )
        except Exception as exc:
            logger.warning("Failed to persist Frontier AI verdict cache: %s", str(exc)[:120])

    def _compute_overall_savings_pct_locked(self) -> float:
        total_full = self._telemetry["total_full_file_tokens_est"]
        total_saved = self._telemetry["total_tokens_saved"]
        if total_full <= 0:
            return 0.0
        return round((total_saved / max(1, total_full)) * 100.0, 1)

    def _snapshot_public_telemetry_locked(self) -> AiTokenTelemetry:
        overall_pct = self._compute_overall_savings_pct_locked()
        return AiTokenTelemetry(
            prompt_tokens=self._telemetry["total_prompt_tokens"],
            completion_tokens=self._telemetry["total_completion_tokens"],
            full_file_tokens_est=self._telemetry["total_full_file_tokens_est"],
            tokens_saved=self._telemetry["total_tokens_saved"],
            savings_pct=overall_pct,
            total_prompt_tokens=self._telemetry["total_prompt_tokens"],
            total_completion_tokens=self._telemetry["total_completion_tokens"],
            total_full_file_tokens_est=self._telemetry["total_full_file_tokens_est"],
            total_tokens_saved=self._telemetry["total_tokens_saved"],
            overall_savings_pct=overall_pct,
            cache_hits=self._telemetry["cache_hits"],
            total_cache_hits=self._telemetry["cache_hits"],
            total_requests=self._telemetry["total_requests"],
        )

    def _record_call_telemetry(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        full_file_tokens_est: int,
        call_cache_hits: int,
        counted_request: bool = True,
    ) -> AiTokenTelemetry:
        p_tok = max(0, int(prompt_tokens))
        c_tok = max(0, int(completion_tokens))
        f_tok = max(p_tok, int(full_file_tokens_est))
        saved = max(0, f_tok - p_tok)
        call_pct = round((saved / max(1, f_tok)) * 100.0, 1) if f_tok > 0 else 0.0

        with self._lock:
            self._telemetry["total_prompt_tokens"] += p_tok
            self._telemetry["total_completion_tokens"] += c_tok
            self._telemetry["total_full_file_tokens_est"] += f_tok
            self._telemetry["total_tokens_saved"] += saved
            self._telemetry["cache_hits"] += max(0, int(call_cache_hits))
            if counted_request:
                self._telemetry["total_requests"] += 1
            overall_pct = self._compute_overall_savings_pct_locked()
            self._persist_config_locked()
            return AiTokenTelemetry(
                prompt_tokens=p_tok,
                completion_tokens=c_tok,
                full_file_tokens_est=f_tok,
                tokens_saved=saved,
                savings_pct=call_pct,
                total_prompt_tokens=self._telemetry["total_prompt_tokens"],
                total_completion_tokens=self._telemetry["total_completion_tokens"],
                total_full_file_tokens_est=self._telemetry["total_full_file_tokens_est"],
                total_tokens_saved=self._telemetry["total_tokens_saved"],
                overall_savings_pct=overall_pct,
                cache_hits=max(0, int(call_cache_hits)),
                total_cache_hits=self._telemetry["cache_hits"],
                total_requests=self._telemetry["total_requests"],
            )

    def get_public_config(self) -> AiPublicConfigResponse:
        """Returns public provider configuration, masked credential status, and cumulative token telemetry."""
        with self._lock:
            has_cred = bool(self._active_cred)
            masked_cred = _mask_credential(self._active_cred)
            return AiPublicConfigResponse(
                provider=self._provider,
                model=self._model,
                base_url=self._base_url,
                has_api_key=has_cred,
                masked_api_key=masked_cred,
                persist_key=self._persist_key,
                available_providers=[dict(item) for item in _PROVIDER_CATALOG],
                token_telemetry=self._snapshot_public_telemetry_locked(),
            )

    def update_config(self, req: AiConfigUpdateRequest) -> AiPublicConfigResponse:
        """Validates endpoint URL, updates BYOK configuration, and persists to `.alastor_vault` if requested."""
        validated_url = _validate_provider_endpoint(req.provider, req.base_url)
        default_model = next(
            (p["default_model"] for p in _PROVIDER_CATALOG if p["id"] == req.provider),
            "gemini-2.5-flash",
        )
        clean_model = (req.model or "").strip() or str(default_model)
        incoming_cred = (req.api_key or "").strip()

        with self._lock:
            if incoming_cred and "••••" not in incoming_cred:
                eff_cred = incoming_cred
            else:
                eff_cred = self._active_cred

            self._provider = req.provider
            self._model = clean_model
            self._base_url = validated_url
            self._persist_key = bool(req.persist_key)
            self._active_cred = eff_cred
            self._persist_config_locked()

        return self.get_public_config()

    def _has_usable_credentials(self) -> bool:
        with self._lock:
            if self._active_cred:
                return True
            if self._provider == "openai_compatible":
                parsed = urllib.parse.urlparse(self._base_url)
                if (parsed.hostname or "").lower() in {"localhost", "127.0.0.1"}:
                    return True
            return False

    def _build_cache_key(self, workflow: str, material: str) -> str:
        with self._lock:
            prov = self._provider
            mod = self._model
        raw_str = f"{prov}|{mod}|{workflow}|{material}"
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    def _cache_get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            hit = self._verdict_cache.get(cache_key)
            if hit is not None:
                self._verdict_cache.move_to_end(cache_key)
                return dict(hit)
            return None

    def _cache_put(self, cache_key: str, entry: Dict[str, Any]) -> None:
        with self._lock:
            self._verdict_cache[cache_key] = dict(entry)
            self._verdict_cache.move_to_end(cache_key)
            self._persist_cache_locked()

    def _dispatch_provider_call(
        self,
        system_prompt: str,
        user_prompt: str,
        expect_json: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes a multi-provider HTTPS (or loopback Ollama/vLLM) POST call via `urllib.request`
        with strict pre-flight SSRF validation and header-redacted error mapping.
        """
        with self._lock:
            provider = self._provider
            model = self._model
            base_url = self._base_url
            eff_cred = self._active_cred

        verified_base = _validate_provider_endpoint(provider, base_url, verify_dns=True)
        req_headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ALASTOR-FrontierAI/4.0",
        }

        if provider == "gemini":
            if not eff_cred:
                raise _AiDispatchError("MISSING_API_KEY", "No Gemini API key configured.")
            req_headers["x-goog-api-key"] = eff_cred
            model_seg = urllib.parse.quote(model, safe="-._")
            target_raw = f"{verified_base}/v1beta/models/{model_seg}:generateContent"
            gen_cfg: Dict[str, Any] = {"temperature": 0.1}
            if expect_json:
                gen_cfg["responseMimeType"] = "application/json"
            body_obj: Dict[str, Any] = {
                "systemInstruction": {"parts": [{"text": system_prompt}]},
                "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                "generationConfig": gen_cfg,
            }
        elif provider == "anthropic":
            if not eff_cred:
                raise _AiDispatchError("MISSING_API_KEY", "No Anthropic API key configured.")
            req_headers["x-api-key"] = eff_cred
            req_headers["anthropic-version"] = "2023-06-01"
            if verified_base.endswith("/messages"):
                target_raw = verified_base
            elif verified_base.endswith("/v1"):
                target_raw = f"{verified_base}/messages"
            else:
                target_raw = f"{verified_base}/v1/messages"
            body_obj = {
                "model": model,
                "max_tokens": 1536,
                "temperature": 0.1,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            }
        else:
            if provider == "openai" and not eff_cred:
                raise _AiDispatchError("MISSING_API_KEY", "No OpenAI API key configured.")
            if eff_cred:
                req_headers["Authorization"] = f"Bearer {eff_cred}"
            if verified_base.endswith("/chat/completions"):
                target_raw = verified_base
            elif verified_base.endswith(("/v1", "/api/v1")):
                target_raw = f"{verified_base}/chat/completions"
            else:
                target_raw = f"{verified_base}/v1/chat/completions"
            body_obj = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.1,
            }
            if expect_json and provider == "openai":
                body_obj["response_format"] = {"type": "json_object"}

        # Re-validate full target URL and construct sanitized URL before Request/urlopen
        validated_full = _validate_provider_endpoint(provider, target_raw, verify_dns=False)
        parsed_u = urllib.parse.urlparse(validated_full)
        scheme = parsed_u.scheme.lower()
        netloc = parsed_u.netloc
        raw_path = parsed_u.path or "/"
        query_suffix = f"?{parsed_u.query}" if parsed_u.query else ""
        safe_url = f"{scheme}://{netloc}{urllib.parse.quote(raw_path, safe='/:@+-._~')}{query_suffix}"

        payload_bytes = json.dumps(body_obj).encode("utf-8")
        http_req = urllib.request.Request(
            safe_url,
            data=payload_bytes,
            headers=req_headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(http_req, timeout=28) as resp:
                resp_bytes = resp.read()
        except urllib.error.HTTPError as http_err:
            code = int(getattr(http_err, "code", 500) or 500)
            if code in (401, 403):
                raise _AiDispatchError(
                    "AUTH_FAILED",
                    f"Provider '{provider}' rejected credentials (HTTP {code}). Check your API key and permissions.",
                ) from None
            if code == 429:
                raise _AiDispatchError(
                    "RATE_LIMITED",
                    f"Provider '{provider}' rate limit or quota exceeded (HTTP 429). Retry shortly or switch models.",
                ) from None
            if code == 404:
                raise _AiDispatchError(
                    "MODEL_NOT_FOUND",
                    f"Model '{model}' or endpoint was not found on '{provider}' (HTTP 404).",
                ) from None
            raise _AiDispatchError(
                f"HTTP_{code}",
                f"Provider '{provider}' returned HTTP {code}.",
            ) from None
        except (TimeoutError, socket.timeout):
            raise _AiDispatchError(
                "TIMEOUT",
                f"Request to '{provider}' ({model}) timed out after 28 seconds.",
            ) from None
        except urllib.error.URLError:
            raise _AiDispatchError(
                "NETWORK_ERROR",
                f"Unable to reach '{provider}' endpoint. Verify connectivity and endpoint URL.",
            ) from None

        try:
            resp_json = json.loads(resp_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            raise _AiDispatchError(
                "INVALID_MODEL_RESPONSE",
                f"Provider '{provider}' returned a non-JSON HTTP response.",
            ) from None

        est_prompt = max(1, (len(system_prompt) + len(user_prompt)) // 4)
        text_out = ""
        prompt_toks = est_prompt
        comp_toks = 0

        if provider == "gemini":
            candidates = resp_json.get("candidates") or []
            if candidates and isinstance(candidates[0], dict):
                parts = ((candidates[0].get("content") or {}).get("parts")) or []
                text_out = "".join(str(p.get("text") or "") for p in parts if isinstance(p, dict))
            usage = resp_json.get("usageMetadata") or {}
            prompt_toks = int(usage.get("promptTokenCount") or est_prompt)
            comp_toks = int(usage.get("candidatesTokenCount") or max(1, len(text_out) // 4))
        elif provider == "anthropic":
            blocks = resp_json.get("content") or []
            text_out = "".join(str(b.get("text") or "") for b in blocks if isinstance(b, dict))
            usage = resp_json.get("usage") or {}
            prompt_toks = int(usage.get("input_tokens") or est_prompt)
            comp_toks = int(usage.get("output_tokens") or max(1, len(text_out) // 4))
        else:
            choices = resp_json.get("choices") or []
            if choices and isinstance(choices[0], dict):
                msg_obj = choices[0].get("message") or {}
                text_out = str(msg_obj.get("content") or "")
            usage = resp_json.get("usage") or {}
            prompt_toks = int(usage.get("prompt_tokens") or est_prompt)
            comp_toks = int(usage.get("completion_tokens") or max(1, len(text_out) // 4))

        return {
            "text": text_out,
            "prompt_tokens": max(1, prompt_toks),
            "completion_tokens": max(0, comp_toks),
        }

    def test_connection(self) -> AiConnectionTestResponse:
        """Sends a minimal 10-token ping to verify provider reachability, latency, and credentials."""
        with self._lock:
            provider = self._provider
            model = self._model

        if not self._has_usable_credentials():
            return AiConnectionTestResponse(
                ok=False,
                provider=provider,
                model=model,
                latency_ms=0,
                message=f"No API key configured for provider '{provider}'. Add your BYOK key first.",
                error_code="MISSING_API_KEY",
            )

        t0 = time.perf_counter()
        try:
            _res = self._dispatch_provider_call(
                system_prompt='Reply strictly with {"ok": true}.',
                user_prompt="ping",
                expect_json=False,
            )
            elapsed_ms = max(1, int((time.perf_counter() - t0) * 1000))
            return AiConnectionTestResponse(
                ok=True,
                provider=provider,
                model=model,
                latency_ms=elapsed_ms,
                message=f"Verified live connection to {provider} ({model}) in {elapsed_ms} ms.",
                error_code=None,
            )
        except (_AiDispatchError, ValueError) as err:
            elapsed_ms = max(1, int((time.perf_counter() - t0) * 1000))
            code = err.error_code if isinstance(err, _AiDispatchError) else "INVALID_ENDPOINT"
            msg = err.user_message if isinstance(err, _AiDispatchError) else str(err)
            return AiConnectionTestResponse(
                ok=False,
                provider=provider,
                model=model,
                latency_ms=elapsed_ms,
                message=msg,
                error_code=code,
            )

    def build_cpg_micro_slice(
        self,
        finding: Finding,
        allowed_roots: List[str],
    ) -> Dict[str, Any]:
        """
        Extracts a deterministic CPG Micro-Slice for `finding`:
        - Enclosing `def`/`class`/`function` signature line(s)
        - Deduplicated +-3 line windows around `path_nodes` and `best_fix_location` (capped at 40 lines)
        - Compact taint/flow edge chain + rule/CWE metadata
        """
        norm_nodes: List[Dict[str, Any]] = [
            n.model_dump() if isinstance(n, BaseModel) else dict(n)
            for n in (finding.path_nodes or [])
            if isinstance(n, (dict, BaseModel))
        ]
        bfl: Optional[BestFixLocation] = finding.best_fix_location

        primary_fp = ""
        if bfl and bfl.filepath:
            primary_fp = bfl.filepath
        elif norm_nodes:
            primary_fp = str(norm_nodes[-1].get("filepath") or norm_nodes[0].get("filepath") or "")

        edge_summaries: List[str] = []
        node_by_id = {str(n.get("id") or ""): n for n in norm_nodes}
        for edge in finding.path_edges or []:
            e_dict = edge.model_dump() if isinstance(edge, BaseModel) else (edge if isinstance(edge, dict) else {})
            src_id = str(e_dict.get("source") or e_dict.get("source_id") or "")
            tgt_id = str(e_dict.get("target") or e_dict.get("target_id") or "")
            etype = str(e_dict.get("type") or e_dict.get("edge_type") or "FLOW")
            vname = str(e_dict.get("var_name") or "")
            src_ln = node_by_id.get(src_id, {}).get("start_line", "?")
            tgt_ln = node_by_id.get(tgt_id, {}).get("start_line", "?")
            tag = f"{etype}:{vname}" if vname else etype
            edge_summaries.append(f"L{src_ln} --[{tag}]--> L{tgt_ln}")
        edge_chain_str = " ; ".join(edge_summaries) if edge_summaries else "single-node-observation"

        file_pair = _read_confined_workspace_file(primary_fp, allowed_roots) if primary_fp else None
        if file_pair is not None:
            resolved_path, full_text = file_pair
            all_lines = full_text.splitlines()
            total_lines = max(1, len(all_lines))
            full_file_tokens_est = max(1, len(full_text) // 4)

            anchor_lines: List[int] = []
            for n in norm_nodes:
                n_fp = str(n.get("filepath") or "")
                if not n_fp or n_fp == primary_fp or primary_fp.endswith(n_fp) or n_fp.endswith(primary_fp):
                    s_ln = max(1, min(total_lines, int(n.get("start_line") or 1)))
                    e_ln = max(s_ln, min(total_lines, int(n.get("end_line") or s_ln)))
                    for ln in range(s_ln, min(e_ln + 1, s_ln + 4)):
                        anchor_lines.append(ln)
            if bfl and bfl.line:
                anchor_lines.append(max(1, min(total_lines, int(bfl.line))))
            if not anchor_lines:
                anchor_lines = [1]

            sig_lines_set = set()
            for a_ln in anchor_lines:
                sig_ln = _find_enclosing_signature_line(all_lines, a_ln)
                if sig_ln is not None:
                    sig_lines_set.add(sig_ln)

            window_lines_set = set()
            for a_ln in anchor_lines:
                for w_ln in range(max(1, a_ln - 3), min(total_lines, a_ln + 3) + 1):
                    window_lines_set.add(w_ln)

            combined_sorted = sorted(sig_lines_set | window_lines_set)
            if len(combined_sorted) > _MAX_MICRO_SLICE_LINES:
                priority = sorted(sig_lines_set | set(anchor_lines))
                remaining = [ln for ln in combined_sorted if ln not in set(priority)]
                budget = max(0, _MAX_MICRO_SLICE_LINES - len(priority))
                combined_sorted = sorted((priority + remaining[:budget])[:_MAX_MICRO_SLICE_LINES])

            rendered_code_lines: List[str] = []
            prev_ln: Optional[int] = None
            for ln in combined_sorted:
                if prev_ln is not None and ln > prev_ln + 1:
                    rendered_code_lines.append("  ...")
                rendered_code_lines.append(f"L{ln}: {all_lines[ln - 1]}")
                prev_ln = ln

            target_bfl_ln = max(1, min(total_lines, int(bfl.line if bfl and bfl.line else anchor_lines[-1])))
            b_start = max(1, target_bfl_ln - 2)
            b_end = min(total_lines, target_bfl_ln + 2)
            before_snippet = "\n".join(all_lines[b_start - 1 : b_end])
            enclosing_sig = (
                all_lines[min(sig_lines_set) - 1].strip() if sig_lines_set else ""
            )

            slice_header = (
                f"File: {primary_fp} | Rule: {finding.rule_id} ({finding.cwe_id or 'N/A'}) "
                f"| Severity: {finding.severity} | Flow: {edge_chain_str}"
            )
            slice_text = slice_header + "\n" + "\n".join(rendered_code_lines)
            slice_lines_count = len(combined_sorted)
        else:
            resolved_path = None
            fallback_lines = [
                f"L{int(n.get('start_line') or 1)}: {str(n.get('code') or n.get('name') or '').strip()}"
                for n in norm_nodes
            ]
            if bfl and bfl.code_snippet and not fallback_lines:
                fallback_lines.append(f"L{bfl.line}: {bfl.code_snippet}")
            before_snippet = bfl.code_snippet if bfl and bfl.code_snippet else "\n".join(fallback_lines)
            enclosing_sig = ""
            slice_text = (
                f"File: {primary_fp or 'unknown'} | Rule: {finding.rule_id} ({finding.cwe_id or 'N/A'}) "
                f"| Flow: {edge_chain_str}\n" + "\n".join(fallback_lines)
            )
            slice_lines_count = max(1, len(fallback_lines))
            total_lines = slice_lines_count
            full_file_tokens_est = max(1, len(slice_text) // 4)

        slice_tokens_est = max(1, len(slice_text) // 4)
        tokens_saved = max(0, full_file_tokens_est - slice_tokens_est)
        savings_pct = round((tokens_saved / max(1, full_file_tokens_est)) * 100.0, 1)

        return {
            "filepath": primary_fp,
            "resolved_path": resolved_path,
            "slice_text": slice_text,
            "slice_lines_count": slice_lines_count,
            "full_file_lines_count": total_lines,
            "slice_tokens_est": slice_tokens_est,
            "full_file_tokens_est": full_file_tokens_est,
            "tokens_saved": tokens_saved,
            "savings_pct": savings_pct,
            "before_snippet": before_snippet,
            "enclosing_signature": enclosing_sig,
        }

    def validate_findings(
        self,
        findings: List[Finding],
        allowed_roots: List[str],
    ) -> AiValidateFindingsResponse:
        """
        Batch-validates findings using CPG Micro-Slices + SHA-256 slice verdict cache.
        Cached slices cost 0 outbound network calls (`cache_hit=True`).
        """
        if not findings:
            return AiValidateFindingsResponse(
                ok=True,
                verdicts=[],
                token_telemetry=self._record_call_telemetry(0, 0, 0, 0, counted_request=False),
            )

        if not self._has_usable_credentials():
            return AiValidateFindingsResponse(
                ok=False,
                verdicts=[],
                token_telemetry=self.get_public_config().token_telemetry,
                error_code="MISSING_API_KEY",
                user_message="No API key configured. Open the Frontier AI drawer to configure your BYOK provider key.",
            )

        verdicts_by_id: Dict[str, AiFindingVerdict] = {}
        uncached_batch: List[Tuple[Finding, Dict[str, Any], str]] = []
        call_cache_hits = 0
        total_full_est = 0

        for f in findings:
            slice_info = self.build_cpg_micro_slice(f, allowed_roots)
            total_full_est += int(slice_info["full_file_tokens_est"])
            c_key = self._build_cache_key(
                "validate_finding",
                f"{f.rule_id}|{f.cwe_id or ''}|{slice_info['slice_text']}",
            )
            cached_entry = self._cache_get(c_key)
            if cached_entry is not None:
                call_cache_hits += 1
                verdicts_by_id[f.id] = AiFindingVerdict(
                    finding_id=f.id,
                    verdict=cached_entry.get("verdict", "NEEDS_REVIEW"),
                    confidence=float(cached_entry.get("confidence", 0.75)),
                    exploitability_summary=str(cached_entry.get("exploitability_summary") or ""),
                    recommended_action=str(cached_entry.get("recommended_action") or ""),
                    suggested_triage_status=cached_entry.get("suggested_triage_status", "TO_VERIFY"),
                    slice_lines_count=int(slice_info["slice_lines_count"]),
                    cache_hit=True,
                )
            else:
                uncached_batch.append((f, slice_info, c_key))

        prompt_toks = 0
        comp_toks = 0

        if uncached_batch:
            system_prompt = (
                "You are ALASTOR Frontier AppSec Auditor. Evaluate each CPG Micro-Slice finding for "
                "real-world exploitability vs sanitizer/reachability false positives. "
                "Return ONLY JSON matching: "
                '{"verdicts": [{"finding_id": "...", "verdict": "TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_REVIEW", '
                '"confidence": 0.95, "exploitability_summary": "...", "recommended_action": "...", '
                '"suggested_triage_status": "CONFIRMED|PROPOSED_NOT_EXPLOITABLE|TO_VERIFY"}]}'
            )
            digest_blocks = [
                f"### Finding {f.id} ({f.title})\n{s_info['slice_text']}"
                for f, s_info, _ in uncached_batch
            ]
            user_prompt = "\n\n".join(digest_blocks)

            try:
                raw_res = self._dispatch_provider_call(system_prompt, user_prompt, expect_json=True)
                prompt_toks = int(raw_res.get("prompt_tokens") or 0)
                comp_toks = int(raw_res.get("completion_tokens") or 0)
                parsed_obj = _extract_json_object(str(raw_res.get("text") or ""))
            except _AiDispatchError as err:
                return AiValidateFindingsResponse(
                    ok=False,
                    verdicts=list(verdicts_by_id.values()),
                    token_telemetry=self.get_public_config().token_telemetry,
                    error_code=err.error_code,
                    user_message=err.user_message,
                )
            except ValueError:
                return AiValidateFindingsResponse(
                    ok=False,
                    verdicts=list(verdicts_by_id.values()),
                    token_telemetry=self.get_public_config().token_telemetry,
                    error_code="INVALID_MODEL_RESPONSE",
                    user_message="Model response did not match expected JSON verdict schema.",
                )

            raw_verdicts = parsed_obj.get("verdicts")
            raw_list = raw_verdicts if isinstance(raw_verdicts, list) else []
            by_ret_id: Dict[str, Dict[str, Any]] = {
                str(item.get("finding_id") or ""): item
                for item in raw_list
                if isinstance(item, dict)
            }

            for idx, (f, s_info, c_key) in enumerate(uncached_batch):
                matched = by_ret_id.get(f.id)
                if matched is None and idx < len(raw_list) and isinstance(raw_list[idx], dict):
                    matched = raw_list[idx]
                matched = matched or {}

                raw_v = str(matched.get("verdict") or "NEEDS_REVIEW").upper().strip()
                norm_v = raw_v if raw_v in {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"} else "NEEDS_REVIEW"
                try:
                    conf = max(0.0, min(1.0, float(matched.get("confidence", 0.75))))
                except (TypeError, ValueError):
                    conf = 0.75

                default_triage = (
                    "CONFIRMED"
                    if norm_v == "TRUE_POSITIVE"
                    else ("PROPOSED_NOT_EXPLOITABLE" if norm_v == "FALSE_POSITIVE" else "TO_VERIFY")
                )
                raw_triage = str(matched.get("suggested_triage_status") or default_triage).upper().strip()
                norm_triage = (
                    raw_triage
                    if raw_triage in {"CONFIRMED", "PROPOSED_NOT_EXPLOITABLE", "TO_VERIFY"}
                    else default_triage
                )

                verdict_obj = AiFindingVerdict(
                    finding_id=f.id,
                    verdict=norm_v,  # type: ignore[arg-type]
                    confidence=round(conf, 3),
                    exploitability_summary=str(
                        matched.get("exploitability_summary") or "Reviewed CPG taint slice."
                    ),
                    recommended_action=str(
                        matched.get("recommended_action") or (f.remediation or "Apply Best Fix Location guard.")
                    ),
                    suggested_triage_status=norm_triage,  # type: ignore[arg-type]
                    slice_lines_count=int(s_info["slice_lines_count"]),
                    cache_hit=False,
                )
                verdicts_by_id[f.id] = verdict_obj
                self._cache_put(
                    c_key,
                    {
                        "verdict": verdict_obj.verdict,
                        "confidence": verdict_obj.confidence,
                        "exploitability_summary": verdict_obj.exploitability_summary,
                        "recommended_action": verdict_obj.recommended_action,
                        "suggested_triage_status": verdict_obj.suggested_triage_status,
                    },
                )

        ordered = [verdicts_by_id[f.id] for f in findings if f.id in verdicts_by_id]
        tel = self._record_call_telemetry(
            prompt_tokens=prompt_toks,
            completion_tokens=comp_toks,
            full_file_tokens_est=total_full_est,
            call_cache_hits=call_cache_hits,
        )
        return AiValidateFindingsResponse(ok=True, verdicts=ordered, token_telemetry=tel)

    def audit_code_selection(
        self,
        req: AiCodeAuditRequest,
        allowed_roots: List[str],
    ) -> AiCodeAuditResponse:
        """
        Audits a confined line range inside `allowed_roots` for logic, authz, crypto, or injection flaws.
        Blocks path traversal outside `allowed_roots` before any file read or API dispatch.
        """
        file_pair = _read_confined_workspace_file(req.filepath, allowed_roots)
        if file_pair is None:
            return AiCodeAuditResponse(
                ok=False,
                token_telemetry=self.get_public_config().token_telemetry,
                error_code="PATH_CONFINEMENT_BLOCKED",
                user_message=f"File '{req.filepath}' was not found or is outside the authorized scan workspace.",
            )

        if not self._has_usable_credentials():
            return AiCodeAuditResponse(
                ok=False,
                token_telemetry=self.get_public_config().token_telemetry,
                error_code="MISSING_API_KEY",
                user_message="No API key configured. Open the Frontier AI drawer to configure your BYOK provider key.",
            )

        _resolved, full_text = file_pair
        all_lines = full_text.splitlines()
        total_lines = max(1, len(all_lines))
        full_tokens_est = max(1, len(full_text) // 4)

        s_line = max(1, min(total_lines, int(req.start_line or 1)))
        e_line = max(s_line, min(total_lines, min(int(req.end_line or s_line), s_line + 120)))

        sig_ln = _find_enclosing_signature_line(all_lines, s_line)
        snippet_parts: List[str] = []
        if sig_ln is not None and sig_ln < s_line:
            snippet_parts.append(f"L{sig_ln}: {all_lines[sig_ln - 1]}")
            if sig_ln < s_line - 1:
                snippet_parts.append("  ...")
        for ln in range(s_line, e_line + 1):
            snippet_parts.append(f"L{ln}: {all_lines[ln - 1]}")
        selection_slice = "\n".join(snippet_parts)

        focus_str = (req.focus_question or "").strip()
        c_key = self._build_cache_key(
            "audit_selection",
            f"{req.filepath}|{s_line}-{e_line}|{focus_str}|{selection_slice}",
        )
        cached = self._cache_get(c_key)
        if cached is not None:
            tel = self._record_call_telemetry(0, 0, full_tokens_est, 1)
            obs_list = [
                AiCodeAuditObservation(**o)
                for o in (cached.get("observations") or [])
                if isinstance(o, dict)
            ]
            return AiCodeAuditResponse(
                ok=True,
                summary=str(cached.get("summary") or ""),
                risk_level=str(cached.get("risk_level") or "INFO"),
                observations=obs_list,
                secure_snippet=str(cached.get("secure_snippet") or ""),
                token_telemetry=tel,
            )

        system_prompt = (
            "You are ALASTOR Principal Code Security Reviewer. Audit ONLY the provided code selection "
            "for injection, authz/authn bypass, path traversal, SSRF, cryptographic, or logic flaws. "
            "Return ONLY JSON matching: "
            '{"summary": "...", "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|SECURE", '
            '"observations": [{"line_range": "L10-L12", "severity": "HIGH", "title": "...", '
            '"explanation": "...", "remediation": "..."}], "secure_snippet": "..."}'
        )
        user_prompt = (
            f"File: {req.filepath} (Lines {s_line}-{e_line})\n"
            + (f"Focus Question: {focus_str}\n" if focus_str else "")
            + f"Selection:\n{selection_slice}"
        )

        try:
            raw_res = self._dispatch_provider_call(system_prompt, user_prompt, expect_json=True)
            parsed = _extract_json_object(str(raw_res.get("text") or ""))
        except _AiDispatchError as err:
            return AiCodeAuditResponse(
                ok=False,
                token_telemetry=self.get_public_config().token_telemetry,
                error_code=err.error_code,
                user_message=err.user_message,
            )
        except ValueError:
            return AiCodeAuditResponse(
                ok=False,
                token_telemetry=self.get_public_config().token_telemetry,
                error_code="INVALID_MODEL_RESPONSE",
                user_message="Model response did not match expected JSON code-audit schema.",
            )

        obs_items: List[AiCodeAuditObservation] = []
        for raw_obs in parsed.get("observations") or []:
            if isinstance(raw_obs, dict):
                obs_items.append(
                    AiCodeAuditObservation(
                        line_range=str(raw_obs.get("line_range") or f"L{s_line}-L{e_line}"),
                        severity=str(raw_obs.get("severity") or "MEDIUM").upper(),
                        title=str(raw_obs.get("title") or "Security Observation"),
                        explanation=str(raw_obs.get("explanation") or ""),
                        remediation=str(raw_obs.get("remediation") or ""),
                    )
                )

        summary_val = str(parsed.get("summary") or "Completed focused code selection audit.")
        risk_val = str(parsed.get("risk_level") or ("HIGH" if obs_items else "SECURE")).upper()
        sec_snip = str(parsed.get("secure_snippet") or "")

        self._cache_put(
            c_key,
            {
                "summary": summary_val,
                "risk_level": risk_val,
                "observations": [o.model_dump() for o in obs_items],
                "secure_snippet": sec_snip,
            },
        )
        tel = self._record_call_telemetry(
            prompt_tokens=int(raw_res.get("prompt_tokens") or 0),
            completion_tokens=int(raw_res.get("completion_tokens") or 0),
            full_file_tokens_est=full_tokens_est,
            call_cache_hits=0,
        )
        return AiCodeAuditResponse(
            ok=True,
            summary=summary_val,
            risk_level=risk_val,
            observations=obs_items,
            secure_snippet=sec_snip,
            token_telemetry=tel,
        )

    def synthesize_patch(
        self,
        finding: Finding,
        allowed_roots: List[str],
    ) -> AiPatchSynthesisResponse:
        """Synthesizes a minimal context-aware security patch from a finding's CPG Micro-Slice."""
        slice_info = self.build_cpg_micro_slice(finding, allowed_roots)
        filepath = str(slice_info["filepath"] or "")

        if not self._has_usable_credentials():
            return AiPatchSynthesisResponse(
                ok=False,
                finding_id=finding.id,
                filepath=filepath,
                token_telemetry=self.get_public_config().token_telemetry,
                error_code="MISSING_API_KEY",
                user_message="No API key configured. Open the Frontier AI drawer to configure your BYOK provider key.",
            )

        full_text: Optional[str] = None
        if filepath:
            file_pair = _read_confined_workspace_file(filepath, allowed_roots)
            if file_pair is not None:
                full_text = file_pair[1]

        c_key = self._build_cache_key(
            "synthesize_patch",
            f"{finding.rule_id}|{finding.cwe_id or ''}|{slice_info['slice_text']}",
        )
        cached = self._cache_get(c_key)
        if cached is not None:
            before_s = str(cached.get("before_snippet") or slice_info["before_snippet"])
            after_s = str(cached.get("after_snippet") or "")
            patched_full = (
                full_text.replace(before_s, after_s, 1)
                if (full_text and before_s and after_s and before_s in full_text)
                else None
            )
            tel = self._record_call_telemetry(0, 0, int(slice_info["full_file_tokens_est"]), 1)
            return AiPatchSynthesisResponse(
                ok=True,
                finding_id=finding.id,
                filepath=filepath,
                explanation=str(cached.get("explanation") or ""),
                before_snippet=before_s,
                after_snippet=after_s,
                patched_full_content=patched_full,
                token_telemetry=tel,
            )

        system_prompt = (
            "You are ALASTOR Remediation Synthesizer. Produce a minimal drop-in security fix for the "
            "given CPG Micro-Slice where `before_snippet` matches the exact vulnerable source lines "
            "(without `L12:` line-number prefixes) and `after_snippet` is the hardened replacement. "
            "Return ONLY JSON matching: "
            '{"explanation": "...", "before_snippet": "...", "after_snippet": "..."}'
        )
        user_prompt = (
            f"Finding: {finding.id} — {finding.title} ({finding.rule_id} / {finding.cwe_id or 'N/A'})\n"
            f"Candidate Target Block:\n{slice_info['before_snippet']}\n\n"
            f"CPG Micro-Slice:\n{slice_info['slice_text']}"
        )

        try:
            raw_res = self._dispatch_provider_call(system_prompt, user_prompt, expect_json=True)
            parsed = _extract_json_object(str(raw_res.get("text") or ""))
        except _AiDispatchError as err:
            return AiPatchSynthesisResponse(
                ok=False,
                finding_id=finding.id,
                filepath=filepath,
                token_telemetry=self.get_public_config().token_telemetry,
                error_code=err.error_code,
                user_message=err.user_message,
            )
        except ValueError:
            return AiPatchSynthesisResponse(
                ok=False,
                finding_id=finding.id,
                filepath=filepath,
                token_telemetry=self.get_public_config().token_telemetry,
                error_code="INVALID_MODEL_RESPONSE",
                user_message="Model response did not match expected JSON patch schema.",
            )

        explanation = str(parsed.get("explanation") or "Synthesized context-aware remediation patch.")
        before_snip = str(parsed.get("before_snippet") or slice_info["before_snippet"])
        after_snip = str(parsed.get("after_snippet") or "")

        patched_full_content: Optional[str] = None
        if full_text and before_snip and after_snip and before_snip in full_text:
            patched_full_content = full_text.replace(before_snip, after_snip, 1)

        self._cache_put(
            c_key,
            {
                "explanation": explanation,
                "before_snippet": before_snip,
                "after_snippet": after_snip,
            },
        )
        tel = self._record_call_telemetry(
            prompt_tokens=int(raw_res.get("prompt_tokens") or 0),
            completion_tokens=int(raw_res.get("completion_tokens") or 0),
            full_file_tokens_est=int(slice_info["full_file_tokens_est"]),
            call_cache_hits=0,
        )
        return AiPatchSynthesisResponse(
            ok=True,
            finding_id=finding.id,
            filepath=filepath,
            explanation=explanation,
            before_snippet=before_snip,
            after_snippet=after_snip,
            patched_full_content=patched_full_content,
            token_telemetry=tel,
        )

    def explain_graph(self, req: AiGraphExplainRequest) -> AiGraphExplainResponse:
        """Generates a plain-English architectural & attack-flow walkthrough from a compact graph digest."""
        if not self._has_usable_credentials():
            return AiGraphExplainResponse(
                ok=False,
                token_telemetry=self.get_public_config().token_telemetry,
                error_code="MISSING_API_KEY",
                user_message="No API key configured. Open the Frontier AI drawer to configure your BYOK provider key.",
            )

        compact_nodes = [
            {
                "id": str(n.get("id") or "")[:32],
                "label": str(n.get("label") or ""),
                "name": str(n.get("name") or "")[:60],
                "file": str(n.get("filepath") or "")[:80],
                "line": n.get("start_line"),
            }
            for n in (req.nodes_digest or [])[:30]
            if isinstance(n, dict)
        ]
        compact_edges = [
            {
                "src": str(e.get("source") or e.get("source_id") or "")[:32],
                "tgt": str(e.get("target") or e.get("target_id") or "")[:32],
                "type": str(e.get("type") or e.get("edge_type") or ""),
                "label": str(e.get("flow_label") or e.get("var_name") or "")[:40],
            }
            for e in (req.edges_digest or [])[:40]
            if isinstance(e, dict)
        ]
        digest_json = json.dumps(
            {"view_mode": req.view_mode, "finding_id": req.finding_id, "nodes": compact_nodes, "edges": compact_edges},
            separators=(",", ":"),
        )
        full_graph_equiv_tokens = max(
            240,
            len(req.nodes_digest or []) * 65 + len(req.edges_digest or []) * 40,
        )

        c_key = self._build_cache_key("explain_graph", digest_json)
        cached = self._cache_get(c_key)
        if cached is not None:
            tel = self._record_call_telemetry(0, 0, full_graph_equiv_tokens, 1)
            return AiGraphExplainResponse(
                ok=True,
                headline=str(cached.get("headline") or ""),
                plain_english_story=str(cached.get("plain_english_story") or ""),
                step_walkthrough=[str(s) for s in (cached.get("step_walkthrough") or [])],
                security_takeaway=str(cached.get("security_takeaway") or ""),
                token_telemetry=tel,
            )

        system_prompt = (
            "You are ALASTOR Graph Architect. Translate the compact CPG / 360° directional graph digest "
            "into a clear plain-English narrative for both engineers and security leads. "
            "Return ONLY JSON matching: "
            '{"headline": "...", "plain_english_story": "...", '
            '"step_walkthrough": ["Step 1: ...", "Step 2: ..."], "security_takeaway": "..."}'
        )
        user_prompt = f"Graph Digest:\n{digest_json}"

        try:
            raw_res = self._dispatch_provider_call(system_prompt, user_prompt, expect_json=True)
            parsed = _extract_json_object(str(raw_res.get("text") or ""))
        except _AiDispatchError as err:
            return AiGraphExplainResponse(
                ok=False,
                token_telemetry=self.get_public_config().token_telemetry,
                error_code=err.error_code,
                user_message=err.user_message,
            )
        except ValueError:
            return AiGraphExplainResponse(
                ok=False,
                token_telemetry=self.get_public_config().token_telemetry,
                error_code="INVALID_MODEL_RESPONSE",
                user_message="Model response did not match expected JSON graph-explanation schema.",
            )

        headline = str(parsed.get("headline") or f"{req.view_mode} Directional Flow Walkthrough")
        story = str(parsed.get("plain_english_story") or "")
        raw_steps = parsed.get("step_walkthrough")
        steps = [str(s) for s in raw_steps] if isinstance(raw_steps, list) else []
        takeaway = str(parsed.get("security_takeaway") or "")

        self._cache_put(
            c_key,
            {
                "headline": headline,
                "plain_english_story": story,
                "step_walkthrough": steps,
                "security_takeaway": takeaway,
            },
        )
        tel = self._record_call_telemetry(
            prompt_tokens=int(raw_res.get("prompt_tokens") or 0),
            completion_tokens=int(raw_res.get("completion_tokens") or 0),
            full_file_tokens_est=full_graph_equiv_tokens,
            call_cache_hits=0,
        )
        return AiGraphExplainResponse(
            ok=True,
            headline=headline,
            plain_english_story=story,
            step_walkthrough=steps,
            security_takeaway=takeaway,
            token_telemetry=tel,
        )


__all__ = [
    "AiCodeAuditObservation",
    "AiCodeAuditRequest",
    "AiCodeAuditResponse",
    "AiConfigUpdateRequest",
    "AiConnectionTestResponse",
    "AiFindingVerdict",
    "AiGraphExplainRequest",
    "AiGraphExplainResponse",
    "AiPatchSynthesisRequest",
    "AiPatchSynthesisResponse",
    "AiProviderType",
    "AiPublicConfigResponse",
    "AiTokenTelemetry",
    "AiValidateFindingsRequest",
    "AiValidateFindingsResponse",
    "BestFixLocation",
    "CPGNode",
    "Finding",
    "FrontierAiEngine",
]
