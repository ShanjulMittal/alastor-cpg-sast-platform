"""
ALASTOR v5.0 Pillar 5 — Cross-Repo Microservice Attack-Graph Stitcher.

Extracts inbound endpoints (HTTP across FastAPI/Flask/Django/Express/Next.js/Go/Spring,
gRPC `.proto`, and Queue consumers) and outbound service calls across multiple local
microservice repositories using `PolyglotScopeWalker` (`scan_directory_with_telemetry`)
with hostile-repo symlink/junction confinement, stitches cross-service edges, discovers
multi-hop cross-service attack paths (up to 4 hops) ranked by composite risk, scrubs all
narratives via `scrub_raw_secrets_text`, and emits ReactFlow-ready graph topology.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from collections import deque
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from compiler.scanner import (
    IGNORE_DIRS,
    _is_confined,
    _is_gitignored,
    _is_link_or_junction,
    _parse_gitignore_file,
    scan_directory_with_telemetry,
)
from engine.frontier_ai_engine import scrub_raw_secrets_text
from engine.hostile_repo_guard import HostileRepoError, is_link_or_junction
from engine.pr_delta_gate import _normalize_repo_relpath, _run_standalone_deterministic_scan
from engine.scanner_fusion_engine import scrub_finding_secrets
from models import (
    CrossServiceAttackPath,
    Finding,
    MicroserviceCallEdge,
    MicroserviceEndpointItem,
    MicroserviceGraphRequest,
    MicroserviceGraphResponse,
    MicroserviceRepoInput,
)

logger = logging.getLogger("cpg-sast.microservice-stitcher")

_MAX_PROTO_SIZE_BYTES = 1_000_000
_MAX_ATTACK_PATH_HOPS = 4
_MAX_ATTACK_PATHS = 50

_SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

_SCHEME_PREFIX_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_LEADING_BASE_VAR_RE = re.compile(r"^(?:\$\{[A-Za-z0-9_.]+\}|\{[A-Za-z0-9_.]+\})(?=/)")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# File-level URL constant bindings (e.g. BILLING_URL = "http://billing-service:8080")
_URL_CONST_RE = re.compile(
    r"""(?:const|let|var|export\s+const)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:os\.getenv\([^,]+,\s*)?["'`](https?://[^"'`\s]+)["'`]"""
)

# Inbound HTTP route patterns
_PY_DECORATOR_ROUTE_RE = re.compile(
    r"""^\s*@(?:app|router|bp|blueprint|api)\.(get|post|put|delete|patch|options|head)\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_PY_FLASK_ROUTE_RE = re.compile(
    r"""^\s*@(?:app|bp|blueprint)\.route\(\s*["']([^"']+)["'](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?""",
    re.IGNORECASE,
)
_PY_DJANGO_PATH_RE = re.compile(
    r"""\b(?:path|re_path)\(\s*["']([^"']+)["']""",
)
_PY_ROUTER_PREFIX_RE = re.compile(
    r"""(?:APIRouter|Blueprint)\([^)]*(?:prefix|url_prefix)\s*=\s*["']([^"']+)["']"""
)
_JS_EXPRESS_ROUTE_RE = re.compile(
    r"""\b(?:app|router|fastify|server)\.(get|post|put|delete|patch|all)\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)
_NEXT_APP_ROUTE_FILE_RE = re.compile(r"""(?:^|/)app/(api/.+)/route\.(?:ts|tsx|js|jsx|mjs)$""")
_NEXT_PAGES_API_FILE_RE = re.compile(r"""(?:^|/)pages/(api/.+)\.(?:ts|tsx|js|jsx|mjs)$""")
_NEXT_HANDLER_METHOD_RE = re.compile(
    r"""\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b"""
)
_GO_HANDLE_FUNC_RE = re.compile(r"""\b(?:http|mux|r|router)\.Handle(?:Func)?\(\s*"([^"]+)\"""")
_GO_METHOD_ROUTE_RE = re.compile(
    r"""\.(GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch)\(\s*"([^"]+)\""""
)
_JAVA_CLASS_DECL_RE = re.compile(r"""\b(?:public\s+)?class\s+[A-Za-z_][A-Za-z0-9_]*""")
_JAVA_CLASS_MAPPING_RE = re.compile(
    r"""@RequestMapping\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']"""
)
_JAVA_REQUEST_METHOD_RE = re.compile(r"""RequestMethod\.(GET|POST|PUT|DELETE|PATCH)""")
_JAVA_METHOD_MAPPING_RE = re.compile(
    r"""@(Get|Post|Put|Delete|Patch)Mapping(?:\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']*)["'])?"""
)

# Inbound gRPC & Queue patterns
_PROTO_SERVICE_RE = re.compile(r"""^\s*service\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{|$)""")
_PROTO_RPC_RE = re.compile(r"""^\s*rpc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(""")
_QUEUE_DECORATOR_RE = re.compile(
    r"""@(?:kafka_listener|KafkaListener|consumer|subscribe)\(\s*(?:topics?\s*=\s*)?["']([^"']+)["']""",
    re.IGNORECASE,
)
_QUEUE_METHOD_CONSUME_RE = re.compile(
    r"""(?:\.subscribe|\.consume|\bconsume|KafkaConsumer|\.basic_consume|\.receive_messages?)\(\s*(?:\[\s*)?(?:queue\s*=\s*|QueueUrl\s*=\s*)?["']([^"']+)["']"""
)

# Outbound HTTP / Queue / gRPC patterns
_PY_OUTBOUND_METHOD_RE = re.compile(
    r"""\b(?:requests|httpx|http_requests|session|client)\.(get|post|put|delete|patch|head|options)\(\s*f?["'`]([^"'`]+)["'`](\s*\+)?"""
)
_PY_OUTBOUND_REQUEST_RE = re.compile(
    r"""\b(?:requests|httpx|http_requests|session|client)\.request\(\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*f?["'`]([^"'`]+)["'`](\s*\+)?""",
    re.IGNORECASE,
)
_JS_FETCH_RE = re.compile(r"""\bfetch\(\s*["'`]([^"'`]+)["'`](\s*\+)?""")
_JS_FETCH_METHOD_RE = re.compile(r"""method\s*:\s*["'](GET|POST|PUT|DELETE|PATCH)["']""", re.IGNORECASE)
_JS_AXIOS_RE = re.compile(
    r"""\b(?:axios|api|client|http)\.(get|post|put|delete|patch)\(\s*["'`]([^"'`]+)["'`](\s*\+)?""",
    re.IGNORECASE,
)
_GO_HTTP_METHOD_RE = re.compile(r"""\bhttp\.(Get|Post)\(\s*"([^"]+)"(\s*\+)?""")
_GO_NEW_REQUEST_RE = re.compile(
    r"""\bhttp\.NewRequest(?:WithContext\(\s*[^,]+,\s*|\(\s*)(?:"(GET|POST|PUT|DELETE|PATCH)"|http\.Method(Get|Post|Put|Delete|Patch))\s*,\s*"([^"]+)"(\s*\+)?"""
)
_JAVA_REST_RE = re.compile(
    r"""\b(?:restTemplate|webClient)\.(getForObject|getForEntity|postForObject|postForEntity|put|delete)\(\s*"([^"]+)"(\s*\+)?""",
    re.IGNORECASE,
)
_QUEUE_PUBLISH_RE = re.compile(
    r"""(?:\b(?:producer|kafka_producer|publisher|broker|bus|sqs|client)\.(?:send|publish|emit)|\.send_message|\.basic_publish)\(\s*(?:topic\s*=\s*|QueueUrl\s*=\s*|routing_key\s*=\s*)?["']([^"']+)["']"""
)
_GRPC_CHANNEL_RE = re.compile(r"""insecure_channel\(\s*["']([^"']+)["']|grpc\.Dial\(\s*"([^"]+)\"""")
_GRPC_STUB_CALL_RE = re.compile(r"""\bstub\.([A-Z][A-Za-z0-9_]*)\(""")


def normalize_route_template(raw_path: str) -> str:
    """
    Canonicalizes HTTP/REST URLs and route templates so equivalent endpoints match
    across frameworks (`/api/orders/{order_id}`, `/api/orders/${id}`,
    `http://billing-service:8080/api/orders/123` -> `/api/orders/:param`).
    """
    cleaned = str(raw_path or "").strip().strip("'\"`")
    if not cleaned:
        return "/"

    if _SCHEME_PREFIX_RE.match(cleaned):
        parsed = urlsplit(cleaned)
        path_only = parsed.path or "/"
    else:
        stripped = _LEADING_BASE_VAR_RE.sub("", cleaned)
        path_only = stripped.split("?", 1)[0].split("#", 1)[0]

    path_only = re.sub(r"/+", "/", path_only).strip()
    if not path_only.startswith("/"):
        path_only = "/" + path_only

    segments = [seg for seg in path_only.split("/") if seg]
    if not segments:
        return "/"

    norm_segments: List[str] = []
    for seg in segments:
        if (
            (seg.startswith("${") and seg.endswith("}"))
            or (seg.startswith("{") and seg.endswith("}"))
            or (seg.startswith("<") and seg.endswith(">"))
            or (seg.startswith("[") and seg.endswith("]"))
            or (seg.startswith(":") and len(seg) > 1)
            or seg in ("%s", "%d", "%v", "%q")
            or seg.isdigit()
            or bool(_UUID_RE.match(seg))
        ):
            norm_segments.append(":param")
        else:
            norm_segments.append(seg)

    return "/" + "/".join(norm_segments)


def _normalize_queue_topic(raw_topic: str) -> str:
    cleaned = str(raw_topic or "").strip().strip("'\"`")
    if _SCHEME_PREFIX_RE.match(cleaned):
        parsed = urlsplit(cleaned)
        tail = (parsed.path or "").strip("/").rsplit("/", 1)[-1]
        return tail.lower() if tail else cleaned.lower()
    return cleaned.lower()


def _extract_host_hint_from_url(raw_url: str) -> str:
    cleaned = str(raw_url or "").strip().strip("'\"`")
    if not _SCHEME_PREFIX_RE.match(cleaned):
        return ""
    parsed = urlsplit(cleaned)
    host = (parsed.hostname or "").strip().lower()
    if not host or "{" in host or "}" in host or "$" in host:
        return ""
    return host


def _expand_url_constants(raw_url: str, url_constants: Dict[str, str]) -> str:
    expanded = str(raw_url or "")
    for var_name, var_val in url_constants.items():
        expanded = expanded.replace(f"${{{var_name}}}", var_val).replace(f"{{{var_name}}}", var_val)
    return expanded


def _validate_service_repo_dir(
    repo_path: str,
    workspace_confinement_fn: Optional[Callable[[str], str]] = None,
) -> str:
    if not isinstance(repo_path, str) or not repo_path.strip():
        raise HostileRepoError("service.repo_path must be a non-empty directory path.")
    if any(ch in repo_path for ch in ("\r", "\n", "\x00")):
        raise HostileRepoError("service.repo_path contains forbidden control characters.")
    cleaned = repo_path.strip()
    if cleaned.startswith("-"):
        raise HostileRepoError("service.repo_path cannot start with '-'.")
    if "://" in cleaned:
        raise HostileRepoError("Remote URLs are not supported; supply a local repository path.")
    parts = [p for p in re.split(r"[\\/]+", cleaned) if p]
    if any(p == ".." for p in parts):
        raise HostileRepoError("Path traversal '..' is forbidden in service.repo_path.")

    abs_candidate = os.path.abspath(cleaned)
    if workspace_confinement_fn is not None:
        confined = workspace_confinement_fn(cleaned)
        real_repo = os.path.realpath(confined)
    else:
        if is_link_or_junction(abs_candidate):
            raise HostileRepoError(f"Refusing symlink/junction repository path: {repo_path}")
        real_repo = os.path.realpath(abs_candidate)

    if not os.path.isdir(real_repo):
        raise ValueError(f"Microservice repository path does not exist or is not a directory: {repo_path}")
    return real_repo


def _collect_proto_files_confined(real_repo: str) -> List[Tuple[str, str]]:
    """
    Walks `real_repo` for `.proto` service contracts with the same `.gitignore`
    and symlink/junction confinement protections as `PolyglotScopeWalker`.
    """
    proto_files: List[Tuple[str, str]] = []
    rules_by_dir: Dict[str, Any] = {}

    for current_dir, dirnames, filenames in os.walk(real_repo, followlinks=False):
        rel_dir_raw = os.path.relpath(current_dir, real_repo).replace("\\", "/")
        rel_dir = "" if rel_dir_raw == "." else rel_dir_raw

        if ".gitignore" in filenames:
            gi_path = os.path.join(current_dir, ".gitignore")
            if not _is_link_or_junction(gi_path) or _is_confined(real_repo, gi_path):
                rules_by_dir[rel_dir] = _parse_gitignore_file(gi_path, rel_dir)

        parts = [p for p in rel_dir.split("/") if p]
        ancestors = [""]
        acc = ""
        for p in parts:
            acc = f"{acc}/{p}" if acc else p
            ancestors.append(acc)

        kept_dirs: List[str] = []
        for d in sorted(dirnames):
            full_sub = os.path.join(current_dir, d)
            sub_rel = f"{rel_dir}/{d}" if rel_dir else d
            if _is_link_or_junction(full_sub):
                continue
            if d in IGNORE_DIRS or d.startswith(".") or d == "synthetic_test_target":
                continue
            if _is_gitignored(sub_rel, is_dir=True, ancestor_dirs=ancestors, rules_by_dir=rules_by_dir):
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            if not filename.lower().endswith(".proto"):
                continue
            full_path = os.path.join(current_dir, filename)
            rel_path = f"{rel_dir}/{filename}" if rel_dir else filename
            if (_is_link_or_junction(full_path) and not _is_confined(real_repo, full_path)) or not _is_confined(real_repo, full_path):
                continue
            if _is_gitignored(rel_path, is_dir=False, ancestor_dirs=ancestors, rules_by_dir=rules_by_dir):
                continue
            try:
                if os.path.getsize(full_path) > _MAX_PROTO_SIZE_BYTES:
                    continue
                with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                    proto_files.append((rel_path, fh.read()))
            except OSError:
                continue

    return proto_files


def _join_route(prefix: str, route: str) -> str:
    p = (prefix or "").strip()
    r = (route or "").strip()
    if not p:
        return r or "/"
    if not r or r == "/":
        return p
    if r.startswith(p):
        return r
    return f"{p.rstrip('/')}/{r.lstrip('/')}"


def _extract_from_proto_file(
    service_name: str,
    filepath: str,
    text: str,
) -> List[MicroserviceEndpointItem]:
    endpoints: List[MicroserviceEndpointItem] = []
    current_service = "GrpcService"
    for idx, line in enumerate(text.splitlines(), start=1):
        svc_m = _PROTO_SERVICE_RE.match(line)
        if svc_m:
            current_service = svc_m.group(1)
            continue
        rpc_m = _PROTO_RPC_RE.match(line)
        if rpc_m:
            method_name = rpc_m.group(1)
            raw_rpc = f"{current_service}/{method_name}"
            endpoints.append(
                MicroserviceEndpointItem(
                    service_name=service_name,
                    protocol="GRPC",
                    method="RPC",
                    normalized_path=f"/{raw_rpc}",
                    raw_path=raw_rpc,
                    filepath=filepath,
                    line=idx,
                )
            )
    return endpoints


def _extract_file_surface(
    *,
    service_name: str,
    filepath: str,
    language: str,
    text: str,
) -> Tuple[List[MicroserviceEndpointItem], List[Dict[str, Any]]]:
    endpoints: List[MicroserviceEndpointItem] = []
    outbound: List[Dict[str, Any]] = []
    lines = text.splitlines()

    url_constants: Dict[str, str] = {}
    for line in lines:
        const_m = _URL_CONST_RE.search(line)
        if const_m:
            url_constants[const_m.group(1)] = const_m.group(2)

    py_prefix = ""
    java_class_prefix = ""
    java_class_line = len(lines) + 1
    grpc_host_hint = ""
    has_grpc_import = "grpc" in text.lower()

    for line_idx, line in enumerate(lines, start=1):
        if language == "python" and not py_prefix:
            pm = _PY_ROUTER_PREFIX_RE.search(line)
            if pm:
                py_prefix = pm.group(1)
        if language == "java":
            if java_class_line > len(lines) and _JAVA_CLASS_DECL_RE.search(line):
                java_class_line = line_idx
            elif line_idx < java_class_line and not java_class_prefix:
                jm = _JAVA_CLASS_MAPPING_RE.search(line)
                if jm:
                    java_class_prefix = jm.group(1)
        ch_m = _GRPC_CHANNEL_RE.search(line)
        if ch_m and not grpc_host_hint:
            raw_target = ch_m.group(1) or ch_m.group(2) or ""
            grpc_host_hint = raw_target.split(":", 1)[0].strip().lower()

    # Next.js App Router / Pages API file-path convention
    app_m = _NEXT_APP_ROUTE_FILE_RE.search(filepath)
    if app_m:
        next_route = "/" + app_m.group(1)
        for idx, line in enumerate(lines, start=1):
            hm = _NEXT_HANDLER_METHOD_RE.search(line)
            if hm:
                endpoints.append(
                    MicroserviceEndpointItem(
                        service_name=service_name,
                        protocol="HTTP",
                        method=hm.group(1).upper(),
                        normalized_path=normalize_route_template(next_route),
                        raw_path=next_route,
                        filepath=filepath,
                        line=idx,
                    )
                )
    else:
        pages_m = _NEXT_PAGES_API_FILE_RE.search(filepath)
        if pages_m:
            next_route = "/" + pages_m.group(1)
            endpoints.append(
                MicroserviceEndpointItem(
                    service_name=service_name,
                    protocol="HTTP",
                    method="ANY",
                    normalized_path=normalize_route_template(next_route),
                    raw_path=next_route,
                    filepath=filepath,
                    line=1,
                )
            )

    for idx, line in enumerate(lines, start=1):
        # 1. Inbound HTTP endpoints
        if language == "python":
            m_py = _PY_DECORATOR_ROUTE_RE.match(line)
            if m_py:
                raw_r = _join_route(py_prefix, m_py.group(2))
                endpoints.append(
                    MicroserviceEndpointItem(
                        service_name=service_name,
                        protocol="HTTP",
                        method=m_py.group(1).upper(),
                        normalized_path=normalize_route_template(raw_r),
                        raw_path=raw_r,
                        filepath=filepath,
                        line=idx,
                    )
                )
            else:
                m_flask = _PY_FLASK_ROUTE_RE.match(line)
                if m_flask:
                    raw_r = _join_route(py_prefix, m_flask.group(1))
                    methods_raw = m_flask.group(2) or ""
                    methods = re.findall(r"""["'](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)["']""", methods_raw, re.IGNORECASE)
                    for meth in (methods or ["GET"]):
                        endpoints.append(
                            MicroserviceEndpointItem(
                                service_name=service_name,
                                protocol="HTTP",
                                method=meth.upper(),
                                normalized_path=normalize_route_template(raw_r),
                                raw_path=raw_r,
                                filepath=filepath,
                                line=idx,
                            )
                        )
                else:
                    m_dj = _PY_DJANGO_PATH_RE.search(line)
                    if m_dj and ("urlpatterns" in text or "django.urls" in text):
                        raw_r = "/" + m_dj.group(1).lstrip("/")
                        endpoints.append(
                            MicroserviceEndpointItem(
                                service_name=service_name,
                                protocol="HTTP",
                                method="ANY",
                                normalized_path=normalize_route_template(raw_r),
                                raw_path=raw_r,
                                filepath=filepath,
                                line=idx,
                            )
                        )

        elif language in ("javascript", "typescript", "tsx"):
            m_js = _JS_EXPRESS_ROUTE_RE.search(line)
            if m_js:
                meth = m_js.group(1).upper()
                raw_r = m_js.group(2)
                endpoints.append(
                    MicroserviceEndpointItem(
                        service_name=service_name,
                        protocol="HTTP",
                        method="ANY" if meth == "ALL" else meth,
                        normalized_path=normalize_route_template(raw_r),
                        raw_path=raw_r,
                        filepath=filepath,
                        line=idx,
                    )
                )

        elif language == "go":
            m_go_h = _GO_HANDLE_FUNC_RE.search(line)
            if m_go_h:
                raw_r = m_go_h.group(1)
                endpoints.append(
                    MicroserviceEndpointItem(
                        service_name=service_name,
                        protocol="HTTP",
                        method="ANY",
                        normalized_path=normalize_route_template(raw_r),
                        raw_path=raw_r,
                        filepath=filepath,
                        line=idx,
                    )
                )
            m_go_m = _GO_METHOD_ROUTE_RE.search(line)
            if m_go_m:
                raw_r = m_go_m.group(2)
                endpoints.append(
                    MicroserviceEndpointItem(
                        service_name=service_name,
                        protocol="HTTP",
                        method=m_go_m.group(1).upper(),
                        normalized_path=normalize_route_template(raw_r),
                        raw_path=raw_r,
                        filepath=filepath,
                        line=idx,
                    )
                )

        elif language == "java":
            m_java = _JAVA_METHOD_MAPPING_RE.search(line)
            if m_java:
                raw_r = _join_route(java_class_prefix, m_java.group(2) or "")
                endpoints.append(
                    MicroserviceEndpointItem(
                        service_name=service_name,
                        protocol="HTTP",
                        method=m_java.group(1).upper(),
                        normalized_path=normalize_route_template(raw_r),
                        raw_path=raw_r,
                        filepath=filepath,
                        line=idx,
                    )
                )
            elif idx > java_class_line:
                m_req = _JAVA_CLASS_MAPPING_RE.search(line)
                if m_req:
                    raw_r = _join_route(java_class_prefix, m_req.group(1))
                    rm_m = _JAVA_REQUEST_METHOD_RE.search(line)
                    endpoints.append(
                        MicroserviceEndpointItem(
                            service_name=service_name,
                            protocol="HTTP",
                            method=rm_m.group(1).upper() if rm_m else "ANY",
                            normalized_path=normalize_route_template(raw_r),
                            raw_path=raw_r,
                            filepath=filepath,
                            line=idx,
                        )
                    )

        # 2. Inbound Queue consumers
        q_dec = _QUEUE_DECORATOR_RE.search(line)
        q_mth = _QUEUE_METHOD_CONSUME_RE.search(line)
        topic_match = q_dec or q_mth
        if topic_match:
            raw_topic = topic_match.group(1)
            endpoints.append(
                MicroserviceEndpointItem(
                    service_name=service_name,
                    protocol="QUEUE",
                    method="CONSUME",
                    normalized_path=_normalize_queue_topic(raw_topic),
                    raw_path=raw_topic,
                    filepath=filepath,
                    line=idx,
                )
            )

        # 3. Outbound HTTP calls
        out_http_hits: List[Tuple[str, str, bool]] = []
        for om in _PY_OUTBOUND_METHOD_RE.finditer(line):
            out_http_hits.append((om.group(1).upper(), om.group(2), bool(om.group(3))))
        for om in _PY_OUTBOUND_REQUEST_RE.finditer(line):
            out_http_hits.append((om.group(1).upper(), om.group(2), bool(om.group(3))))
        for fm in _JS_FETCH_RE.finditer(line):
            ctx_window = "\n".join(lines[idx - 1 : min(len(lines), idx + 3)])
            meth_m = _JS_FETCH_METHOD_RE.search(ctx_window)
            out_http_hits.append(
                (meth_m.group(1).upper() if meth_m else "GET", fm.group(1), bool(fm.group(2)))
            )
        for am in _JS_AXIOS_RE.finditer(line):
            out_http_hits.append((am.group(1).upper(), am.group(2), bool(am.group(3))))
        for gm in _GO_HTTP_METHOD_RE.finditer(line):
            out_http_hits.append((gm.group(1).upper(), gm.group(2), bool(gm.group(3))))
        for gnm in _GO_NEW_REQUEST_RE.finditer(line):
            g_meth = (gnm.group(1) or gnm.group(2) or "GET").upper()
            out_http_hits.append((g_meth, gnm.group(3), bool(gnm.group(4))))
        for jm in _JAVA_REST_RE.finditer(line):
            jmeth = jm.group(1).lower()
            http_m = "POST" if jmeth.startswith("post") else ("PUT" if jmeth == "put" else ("DELETE" if jmeth == "delete" else "GET"))
            out_http_hits.append((http_m, jm.group(2), bool(jm.group(3))))

        for method, raw_target, has_concat in out_http_hits:
            expanded = _expand_url_constants(raw_target, url_constants)
            if has_concat and expanded.endswith("/"):
                expanded = f"{expanded}:param"
            host_hint = _extract_host_hint_from_url(expanded)
            outbound.append(
                {
                    "service_name": service_name,
                    "protocol": "HTTP",
                    "method": method,
                    "raw_target": scrub_raw_secrets_text(expanded)[:240],
                    "normalized_path": normalize_route_template(expanded),
                    "target_host_hint": host_hint,
                    "filepath": filepath,
                    "line": idx,
                }
            )

        # 4. Outbound Queue publishers
        qp_m = _QUEUE_PUBLISH_RE.search(line)
        if qp_m:
            raw_topic = qp_m.group(1)
            outbound.append(
                {
                    "service_name": service_name,
                    "protocol": "QUEUE",
                    "method": "PUBLISH",
                    "raw_target": scrub_raw_secrets_text(raw_topic)[:240],
                    "normalized_path": _normalize_queue_topic(raw_topic),
                    "target_host_hint": "",
                    "filepath": filepath,
                    "line": idx,
                }
            )

        # 5. Outbound gRPC stub calls
        if has_grpc_import:
            gs_m = _GRPC_STUB_CALL_RE.search(line)
            if gs_m:
                rpc_method = gs_m.group(1)
                outbound.append(
                    {
                        "service_name": service_name,
                        "protocol": "GRPC",
                        "method": "RPC",
                        "raw_target": rpc_method,
                        "normalized_path": f"/{rpc_method}",
                        "target_host_hint": grpc_host_hint,
                        "filepath": filepath,
                        "line": idx,
                    }
                )

    return endpoints, outbound


def extract_service_surface(
    service: MicroserviceRepoInput,
    scan_findings: bool = True,
    workspace_confinement_fn: Optional[Callable[[str], str]] = None,
) -> Tuple[List[MicroserviceEndpointItem], List[Dict[str, Any]], List[Finding]]:
    """
    Discovers inbound endpoints, outbound service calls, and (optionally) deterministic
    offline SAST/SCA/IaC/Secret findings for a single microservice repository.
    """
    real_repo = _validate_service_repo_dir(
        service.repo_path,
        workspace_confinement_fn=workspace_confinement_fn,
    )
    scanned_files, _telemetry = scan_directory_with_telemetry(real_repo, exclude_tests=True)
    proto_files = _collect_proto_files_confined(real_repo)

    inbound_endpoints: List[MicroserviceEndpointItem] = []
    outbound_calls: List[Dict[str, Any]] = []

    for sf in scanned_files:
        text = sf.content_bytes.decode("utf-8", errors="replace")
        eps, calls = _extract_file_surface(
            service_name=service.service_name,
            filepath=sf.filepath,
            language=sf.language,
            text=text,
        )
        inbound_endpoints.extend(eps)
        outbound_calls.extend(calls)

    for proto_fp, proto_text in proto_files:
        inbound_endpoints.extend(_extract_from_proto_file(service.service_name, proto_fp, proto_text))

    findings: List[Finding] = []
    if scan_findings:
        raw_findings, _nodes, _edges = _run_standalone_deterministic_scan(real_repo=real_repo)
        extra_raw = [
            f.secret_value_raw
            for f in raw_findings
            if isinstance(f.secret_value_raw, str) and len(f.secret_value_raw) >= 4
        ]
        for raw_f in raw_findings:
            findings.append(
                scrub_finding_secrets(raw_f, extra_raw_secrets=extra_raw, clear_raw_secret=True)
            )

        findings_by_fp: Dict[str, List[str]] = {}
        for f in findings:
            raw_fp = ""
            if f.best_fix_location and f.best_fix_location.filepath:
                raw_fp = f.best_fix_location.filepath
            elif f.path_nodes:
                last_n = f.path_nodes[-1] if isinstance(f.path_nodes[-1], dict) else {}
                raw_fp = str(last_n.get("filepath") or "")
            norm_fp = _normalize_repo_relpath(raw_fp, real_repo)
            if norm_fp:
                findings_by_fp.setdefault(norm_fp, []).append(f.id)

        for ep in inbound_endpoints:
            ep_fp = _normalize_repo_relpath(ep.filepath, real_repo)
            matched_ids = findings_by_fp.get(ep_fp, [])
            if matched_ids:
                ep.linked_finding_ids = list(dict.fromkeys(matched_ids))

    return inbound_endpoints, outbound_calls, findings


def _service_host_aliases(svc: MicroserviceRepoInput) -> Set[str]:
    name_low = svc.service_name.strip().lower()
    aliases = {
        name_low,
        name_low.replace("_", "-"),
        name_low.replace("-", "_"),
    }
    if svc.base_url_hint:
        hint = svc.base_url_hint.strip()
        if not _SCHEME_PREFIX_RE.match(hint):
            hint = f"http://{hint}"
        parsed = urlsplit(hint)
        if parsed.hostname:
            host_low = parsed.hostname.lower()
            aliases.add(host_low)
            aliases.add(host_low.split(".", 1)[0])
    return {a for a in aliases if a}


def _match_host_affinity(host_hint: str, target_aliases: Set[str]) -> Tuple[bool, float]:
    if not host_hint or "{" in host_hint or "}" in host_hint or "$" in host_hint:
        return True, 0.75
    hint_low = host_hint.strip().lower()
    hint_label = hint_low.split(".", 1)[0]
    if hint_low in target_aliases or hint_label in target_aliases:
        return True, 0.95
    for alias in target_aliases:
        if len(alias) >= 3 and (
            alias in hint_low or (len(hint_label) >= 3 and hint_label in alias)
        ):
            return True, 0.88
    return False, 0.0


def _paths_match(
    protocol: str,
    call_norm: str,
    ep_norm: str,
) -> bool:
    if protocol == "HTTP":
        return call_norm == ep_norm
    if protocol == "QUEUE":
        return call_norm.lower() == ep_norm.lower()
    if protocol == "GRPC":
        c_low = call_norm.lower().lstrip("/")
        e_low = ep_norm.lower().lstrip("/")
        return c_low == e_low or e_low.endswith(f"/{c_low}")
    return False


def _compute_composite_severity(
    path_services: Sequence[str],
    findings_by_service: Dict[str, List[Finding]],
    finding_by_id: Dict[str, Finding],
    path_finding_ids: Sequence[str],
) -> Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    if not path_finding_ids:
        return "LOW"

    max_rank = 1
    has_ev_confirmed = False
    services_with_findings = 0

    for svc in path_services:
        if findings_by_service.get(svc):
            services_with_findings += 1

    for fid in path_finding_ids:
        f = finding_by_id.get(fid)
        if f is None:
            continue
        rank = _SEVERITY_ORDER.get(str(f.severity or "LOW").upper(), 1)
        if rank > max_rank:
            max_rank = rank
        if f.ev_status == "RUNTIME_EXPLOIT_CONFIRMED":
            has_ev_confirmed = True

    if has_ev_confirmed or max_rank >= 4:
        return "CRITICAL"
    if max_rank == 3:
        return "CRITICAL" if services_with_findings >= 2 else "HIGH"
    if max_rank == 2:
        return "HIGH" if services_with_findings >= 2 else "MEDIUM"
    return "LOW"


def _compute_node_columns(
    service_names: Sequence[str],
    edges: Sequence[MicroserviceCallEdge],
) -> Tuple[Dict[str, int], Set[str]]:
    in_degree: Dict[str, int] = {s: 0 for s in service_names}
    adj: Dict[str, List[str]] = {s: [] for s in service_names}
    for e in edges:
        if e.target_service not in adj[e.source_service]:
            adj[e.source_service].append(e.target_service)
            in_degree[e.target_service] = in_degree.get(e.target_service, 0) + 1

    entry_services = {s for s, deg in in_degree.items() if deg == 0}
    if not entry_services and service_names:
        entry_services = {service_names[0]}

    col_by_service: Dict[str, int] = {}
    queue: deque[Tuple[str, int]] = deque((s, 0) for s in service_names if s in entry_services)
    while queue:
        svc, depth = queue.popleft()
        if svc in col_by_service and col_by_service[svc] <= depth:
            continue
        col_by_service[svc] = depth
        for nxt in sorted(adj.get(svc, ())):
            if depth + 1 <= len(service_names):
                queue.append((nxt, depth + 1))

    for s in service_names:
        col_by_service.setdefault(s, 0)

    return col_by_service, entry_services


def stitch_microservice_attack_graph(
    req: MicroserviceGraphRequest,
    workspace_confinement_fn: Optional[Callable[[str], str]] = None,
) -> MicroserviceGraphResponse:
    """
    Stitches inbound/outbound API, gRPC, and Queue surfaces across multiple
    microservice repositories, discovers cross-service attack paths (up to 4 hops),
    and returns ReactFlow-ready graph nodes and edges with zero secret leakage.
    """
    if not req.services:
        raise ValueError("Provide at least one microservice repository to analyze.")

    seen_names: Set[str] = set()
    for svc in req.services:
        clean_name = (svc.service_name or "").strip()
        if not clean_name:
            raise ValueError("Every microservice entry must define a non-empty service_name.")
        if clean_name in seen_names:
            raise ValueError(f"Duplicate service_name '{clean_name}' in MicroserviceGraphRequest.")
        seen_names.add(clean_name)

    warnings: List[str] = []
    if len(req.services) < 2:
        warnings.append(
            "Fewer than 2 services provided; cross-service edge stitching requires at least 2 services."
        )

    all_endpoints: List[MicroserviceEndpointItem] = []
    all_outbound_calls: List[Dict[str, Any]] = []
    endpoints_by_service: Dict[str, List[MicroserviceEndpointItem]] = {}
    findings_by_service: Dict[str, List[Finding]] = {}
    finding_by_id: Dict[str, Finding] = {}
    aliases_by_service: Dict[str, Set[str]] = {}
    extra_raw_secrets: List[str] = []

    for svc in req.services:
        aliases_by_service[svc.service_name] = _service_host_aliases(svc)
        eps, calls, svc_findings = extract_service_surface(
            svc,
            scan_findings=req.scan_findings,
            workspace_confinement_fn=workspace_confinement_fn,
        )
        all_endpoints.extend(eps)
        all_outbound_calls.extend(calls)
        endpoints_by_service[svc.service_name] = eps
        findings_by_service[svc.service_name] = svc_findings
        for f in svc_findings:
            finding_by_id[f.id] = f
            if isinstance(f.secret_value_raw, str) and len(f.secret_value_raw) >= 4:
                extra_raw_secrets.append(f.secret_value_raw)

    # Stitch cross-service edges
    stitched_edges: List[MicroserviceCallEdge] = []
    seen_edge_keys: Set[Tuple[Any, ...]] = set()

    for call in all_outbound_calls:
        src_svc = call["service_name"]
        proto = call["protocol"]
        call_method = call["method"]
        call_norm = call["normalized_path"]
        host_hint = call.get("target_host_hint", "")

        for target_svc in req.services:
            tgt_name = target_svc.service_name
            if tgt_name == src_svc:
                continue

            host_ok, confidence = _match_host_affinity(host_hint, aliases_by_service[tgt_name])
            if not host_ok:
                continue

            for ep in endpoints_by_service.get(tgt_name, ()):
                if ep.protocol != proto:
                    continue
                if proto == "HTTP":
                    if call_method != ep.method and call_method != "ANY" and ep.method != "ANY":
                        continue
                if not _paths_match(proto, call_norm, ep.normalized_path):
                    continue

                dedup_key = (
                    src_svc,
                    tgt_name,
                    proto,
                    call_method if proto == "HTTP" else ep.method,
                    ep.normalized_path,
                    call["filepath"],
                    call["line"],
                    ep.filepath,
                    ep.line,
                )
                if dedup_key in seen_edge_keys:
                    continue
                seen_edge_keys.add(dedup_key)

                edge_digest = hashlib.sha256(
                    "|".join(str(x) for x in dedup_key).encode("utf-8")
                ).hexdigest()[:12]
                stitched_edges.append(
                    MicroserviceCallEdge(
                        edge_id=f"edge-{edge_digest}",
                        source_service=src_svc,
                        target_service=tgt_name,
                        protocol=proto,  # type: ignore[arg-type]
                        method=call_method if proto == "HTTP" else f"{call_method}->{ep.method}",
                        normalized_path=ep.normalized_path,
                        caller_filepath=call["filepath"],
                        caller_line=int(call["line"]),
                        callee_filepath=ep.filepath,
                        callee_line=int(ep.line),
                        confidence=confidence,
                    )
                )

    service_names = [s.service_name for s in req.services]
    col_by_service, entry_services = _compute_node_columns(service_names, stitched_edges)

    # Discover cross-service attack paths up to 4 hops over unique (src, tgt) pairs
    pair_edges: Dict[Tuple[str, str], List[MicroserviceCallEdge]] = {}
    adj_targets: Dict[str, List[str]] = {s: [] for s in service_names}
    for e in stitched_edges:
        pair = (e.source_service, e.target_service)
        if pair not in pair_edges:
            pair_edges[pair] = []
            adj_targets[e.source_service].append(e.target_service)
        pair_edges[pair].append(e)

    discovered_paths: List[Tuple[int, CrossServiceAttackPath, Set[str]]] = []
    seen_path_sigs: Set[Tuple[Tuple[str, ...], Tuple[str, ...]]] = set()
    visited_in_dfs: Set[str] = set()

    def _dfs(
        curr_svc: str,
        svc_chain: List[str],
        pair_chain: List[Tuple[str, str]],
    ) -> None:
        visited_in_dfs.add(curr_svc)
        if pair_chain:
            participating_fids: List[str] = []
            seen_fid: Set[str] = set()
            for svc_item in svc_chain:
                for f in findings_by_service.get(svc_item, ()):
                    if f.id not in seen_fid:
                        seen_fid.add(f.id)
                        participating_fids.append(f.id)

            if participating_fids:
                sig = (tuple(svc_chain), tuple(sorted(participating_fids)))
                if sig not in seen_path_sigs:
                    seen_path_sigs.add(sig)
                    comp_sev = _compute_composite_severity(
                        svc_chain, findings_by_service, finding_by_id, participating_fids
                    )
                    hop_parts: List[str] = []
                    hop_edge_ids: Set[str] = set()
                    for pair in pair_chain:
                        p_edges = pair_edges.get(pair, [])
                        hop_edge_ids.update(pe.edge_id for pe in p_edges)
                        edge_labels = ", ".join(
                            f"{pe.protocol} {pe.method} {pe.normalized_path}"
                            for pe in p_edges[:3]
                        )
                        if len(p_edges) > 3:
                            edge_labels += f" (+{len(p_edges) - 3} more)"
                        hop_parts.append(f"{pair[0]} [{edge_labels}] -> {pair[1]}")
                    hop_desc = " -> ".join(hop_parts)

                    finding_summaries: List[str] = []
                    for fid in participating_fids[:6]:
                        f_obj = finding_by_id.get(fid)
                        if f_obj is not None:
                            finding_summaries.append(
                                f"{f_obj.rule_id} ({f_obj.severity}, {f_obj.cwe_id or 'N/A'})"
                            )
                    raw_narrative = (
                        f"Cross-service attack chain across {len(svc_chain)} services "
                        f"({hop_desc}) impacts {len(participating_fids)} finding(s): "
                        f"{', '.join(finding_summaries)}."
                    )
                    clean_narrative = scrub_raw_secrets_text(
                        raw_narrative, extra_raw_secrets=extra_raw_secrets
                    )
                    clean_title = scrub_raw_secrets_text(
                        f"{' -> '.join(svc_chain)} ({comp_sev} Multi-Service Chain)",
                        extra_raw_secrets=extra_raw_secrets,
                    )
                    path_digest = hashlib.sha256(
                        f"{'->'.join(svc_chain)}|{','.join(sorted(participating_fids))}".encode("utf-8")
                    ).hexdigest()[:12]
                    attack_path = CrossServiceAttackPath(
                        path_id=f"path-{path_digest}",
                        title=clean_title,
                        composite_severity=comp_sev,
                        hop_count=len(pair_chain),
                        services=list(svc_chain),
                        finding_ids=participating_fids,
                        narrative=clean_narrative,
                    )
                    discovered_paths.append(
                        (
                            _SEVERITY_ORDER.get(comp_sev, 1),
                            attack_path,
                            hop_edge_ids,
                        )
                    )

        if len(pair_chain) >= _MAX_ATTACK_PATH_HOPS:
            return

        for nxt_svc in adj_targets.get(curr_svc, ()):
            if nxt_svc in svc_chain:
                continue
            _dfs(
                nxt_svc,
                svc_chain + [nxt_svc],
                pair_chain + [(curr_svc, nxt_svc)],
            )

    for start_svc in service_names:
        if start_svc in entry_services and adj_targets[start_svc]:
            _dfs(start_svc, [start_svc], [])

    for start_svc in service_names:
        if start_svc not in visited_in_dfs and adj_targets[start_svc]:
            _dfs(start_svc, [start_svc], [])

    discovered_paths.sort(
        key=lambda item: (
            -item[0],
            -len(item[1].finding_ids),
            item[1].hop_count,
            item[1].services,
        )
    )
    top_paths = discovered_paths[:_MAX_ATTACK_PATHS]
    attack_paths = [item[1] for item in top_paths]
    attack_edge_ids: Set[str] = set()
    for _rank, _path_obj, e_ids in top_paths:
        attack_edge_ids.update(e_ids)

    # Build deterministic ReactFlow nodes & edges
    rows_per_col: Dict[int, int] = {}
    node_id_by_service: Dict[str, str] = {}
    reactflow_nodes: List[Dict[str, Any]] = []

    for svc_name in service_names:
        col = col_by_service.get(svc_name, 0)
        row = rows_per_col.get(col, 0)
        rows_per_col[col] = row + 1

        svc_findings = findings_by_service.get(svc_name, [])
        highest_sev = "NONE"
        if svc_findings:
            best_f = max(
                svc_findings,
                key=lambda f: _SEVERITY_ORDER.get(str(f.severity or "INFO").upper(), 0),
            )
            highest_sev = str(best_f.severity).upper()

        node_id = f"svc-{svc_name}"
        node_id_by_service[svc_name] = node_id
        reactflow_nodes.append(
            {
                "id": node_id,
                "type": "serviceNode",
                "position": {"x": col * 340, "y": row * 200},
                "data": {
                    "service_name": svc_name,
                    "endpoints_count": len(endpoints_by_service.get(svc_name, [])),
                    "findings_count": len(svc_findings),
                    "highest_severity": highest_sev,
                    "is_entry": svc_name in entry_services,
                },
            }
        )

    reactflow_edges: List[Dict[str, Any]] = []
    for edge in stitched_edges:
        is_atk = edge.edge_id in attack_edge_ids
        reactflow_edges.append(
            {
                "id": edge.edge_id,
                "source": node_id_by_service[edge.source_service],
                "target": node_id_by_service[edge.target_service],
                "label": f"{edge.protocol} {edge.method} {edge.normalized_path}",
                "animated": is_atk,
                "data": {
                    "protocol": edge.protocol,
                    "method": edge.method,
                    "normalized_path": edge.normalized_path,
                    "is_attack_path": is_atk,
                },
            }
        )

    return MicroserviceGraphResponse(
        services_analyzed=len(req.services),
        total_inbound_endpoints=len(all_endpoints),
        total_outbound_calls=len(all_outbound_calls),
        stitched_edges_count=len(stitched_edges),
        cross_service_attack_paths_count=len(attack_paths),
        endpoints=all_endpoints,
        edges=stitched_edges,
        attack_paths=attack_paths,
        reactflow_nodes=reactflow_nodes,
        reactflow_edges=reactflow_edges,
        warnings=warnings,
    )
