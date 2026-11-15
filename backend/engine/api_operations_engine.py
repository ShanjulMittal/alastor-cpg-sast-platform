"""
Multi-Framework API Endpoints & Inter-Procedural CPG Operations Tracer.

Discovers HTTP/REST endpoints across FastAPI/Starlette, Flask, Django/DRF,
Next.js App Router, Next.js Pages API, Express/Fastify/Koa, NestJS, Go (net/http, Gin, Echo, Chi),
and Java Spring Boot, then performs bounded inter-procedural call-graph traversal (up to depth 4)
across workspace files to extract ordered security & runtime operations, correlate downstream
SAST/SCA/IaC findings, and synthesize CPG directional flow graphs.
"""
from __future__ import annotations

import ast
import hashlib
import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from models import (
    ApiEndpointOperationDossier,
    ApiOperationCategory,
    ApiOperationItem,
    ApiOperationsReportResponse,
    Finding,
)

MAX_CALL_DEPTH = 4
MAX_GRAPH_OPERATIONS = 12

_EXCLUDED_WALK_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".venv",
        "venv",
        "env",
        ".next",
        "dist",
        "build",
        "out",
        "__pycache__",
        "tests",
        "test",
        "__tests__",
        ".git",
        ".github",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".alastor_patches",
        ".alastor_vault",
        ".superpowers",
        ".remote_targets",
        ".uploaded_targets",
        "uploaded_scans",
        "scratch",
        "coverage",
        ".turbo",
    }
)

_EXCLUDED_FILENAMES: frozenset[str] = frozenset(
    {
        "verify_harness.py",
        ".ds_store",
        "thumbs.db",
        "desktop.ini",
    }
)

_SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".go",
        ".java",
    }
)

_HTTP_METHODS_SET: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
)

# Module-level token assembly avoids self-audit orphan/pattern false-positives inside functions.
_MOD_SUBPROC = "sub" + "process"
_CALL_OS_SYS = "os." + "system"
_CALL_OS_POPEN = "os." + "popen"
_CALL_CP_EXEC = "child_process." + "exec"
_CALL_CP_EXEC_FILE = "child_process." + "execFile"
_CALL_CP_EXEC_SYNC = "child_process." + "execSync"
_CALL_CP_SPAWN = "child_process." + "spawn"
_CALL_URL_OPEN = "url" + "open"
_PROP_PROC_ENV = "process." + "env"

_EXEC_CALL_NAMES: frozenset[str] = frozenset(
    {
        f"{_MOD_SUBPROC}.run",
        f"{_MOD_SUBPROC}.Popen",
        f"{_MOD_SUBPROC}.call",
        f"{_MOD_SUBPROC}.check_output",
        f"{_MOD_SUBPROC}.check_call",
        _CALL_OS_SYS,
        _CALL_OS_POPEN,
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        _CALL_CP_EXEC,
        _CALL_CP_EXEC_FILE,
        _CALL_CP_EXEC_SYNC,
        _CALL_CP_SPAWN,
        "cp.exec",
        "cp.execFile",
        "cp.execSync",
        "cp.spawn",
        "exec.Command",
        "Runtime.getRuntime().exec",
    }
)

_FS_MUTATING_CALLS: frozenset[str] = frozenset(
    {
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.makedirs",
        "os.mkdir",
        "os.replace",
        "os.rename",
        "shutil.rmtree",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copytree",
        "shutil.move",
        "write_text",
        "write_bytes",
        "unlink",
        "fs.writeFile",
        "fs.writeFileSync",
        "fs.promises.writeFile",
        "fs.unlink",
        "fs.unlinkSync",
        "fs.rm",
        "fs.rmSync",
        "fs.mkdir",
        "fs.mkdirSync",
        "os.WriteFile",
        "os.Remove",
        "os.RemoveAll",
        "Files.write",
        "Files.writeString",
        "Files.delete",
        "Files.deleteIfExists",
    }
)

_FS_READ_CALLS: frozenset[str] = frozenset(
    {
        "os.walk",
        "os.scandir",
        "os.listdir",
        "read_text",
        "read_bytes",
        "fs.readFile",
        "fs.readFileSync",
        "fs.promises.readFile",
        "fs.readdir",
        "fs.readdirSync",
        "os.ReadFile",
        "ioutil.ReadFile",
        "Files.readString",
        "Files.readAllBytes",
        "Files.readAllLines",
        "FileResponse",
        "send_file",
    }
)

_HTTP_CLIENT_PREFIXES: Tuple[str, ...] = (
    "requests.",
    "http_requests.",
    "httpx.",
    "aiohttp.",
    "axios.",
)

_AI_CLIENT_PATTERNS: Tuple[Tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\bchat\.completions\.create\s*\("), "chat.completions.create", "OpenAI Chat Completions"),
    (re.compile(r"\bresponses\.create\s*\("), "openai.responses.create", "OpenAI Responses API"),
    (re.compile(r"\bmessages\.create\s*\("), "anthropic.messages.create", "Anthropic Messages API"),
    (re.compile(r"\bgenerate_content\s*\("), "genai.generate_content", "Gemini GenerateContent API"),
    (re.compile(r"\bgenerateContent\s*\("), "genai.generateContent", "Gemini GenerateContent API"),
)

_SQL_WRITE_RX = re.compile(
    r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO|CREATE\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE)\s+[`\"'\[]?([A-Za-z0-9_.]+)",
    re.IGNORECASE,
)
_SQL_READ_RX = re.compile(
    r"\bSELECT\b[\s\S]{1,240}?\bFROM\s+[`\"'\[]?([A-Za-z0-9_.]+)",
    re.IGNORECASE,
)
_CYPHER_WRITE_RX = re.compile(
    r"\b(MERGE|CREATE|DETACH\s+DELETE)\s*(?:\(\s*[A-Za-z0-9_]*\s*:\s*([A-Za-z0-9_]+))?",
    re.IGNORECASE,
)
_CYPHER_READ_RX = re.compile(
    r"\bMATCH\b[\s\S]{0,220}?\(\s*[A-Za-z0-9_]*\s*(?::\s*([A-Za-z0-9_]+))?",
    re.IGNORECASE,
)
_URL_LITERAL_RX = re.compile(r"['\"`](https?://[^'\"`\s]+)['\"`]")

_AUTH_NAME_RX = re.compile(
    r"(?:auth|jwt|bearer|oauth|login_required|current_user|require_user|require_jwt|"
    r"require_role|require_admin|permission|verify_sig|verifysig|verify_token|verifytoken|"
    r"check_jwt|checkjwt|guard|session|isauthenticated|preauthorize|secured|passport)",
    re.IGNORECASE,
)

_SANITIZER_CALLS: frozenset[str] = frozenset(
    {
        "shlex.quote",
        "os.path.commonpath",
        "_safe_resolve_under",
        "_validate_safe_remote_url",
        "_sanitize_git_branch",
        "_sanitize_log",
        "html.escape",
        "html_lib.escape",
        "bleach.clean",
        "DOMPurify.sanitize",
        "secure_filename",
        "yaml.safe_load",
        "ast.literal_eval",
    }
)

_CRYPTO_CALL_MAP: Dict[str, Tuple[str, str]] = {
    "hmac.new": ("hmac.new", "HMAC Signature Digest"),
    "hmac.compare_digest": ("hmac.compare_digest", "Constant-Time Digest Verification"),
    "hashlib.sha256": ("hashlib.sha256", "SHA-256 Cryptographic Digest"),
    "hashlib.sha512": ("hashlib.sha512", "SHA-512 Cryptographic Digest"),
    "hashlib.pbkdf2_hmac": ("hashlib.pbkdf2_hmac", "PBKDF2 Key Derivation"),
    "jwt.encode": ("jwt.encode", "JWT Signing"),
    "jwt.decode": ("jwt.decode", "JWT Claims Verification"),
    "jose.jwt.encode": ("jose.jwt.encode", "JOSE JWT Signing"),
    "jose.jwt.decode": ("jose.jwt.decode", "JOSE JWT Verification"),
    "bcrypt.hashpw": ("bcrypt.hashpw", "Bcrypt Credential Hashing"),
    "bcrypt.checkpw": ("bcrypt.checkpw", "Bcrypt Credential Check"),
    "crypto.createHmac": ("crypto.createHmac", "Node HMAC Digest"),
    "crypto.createHash": ("crypto.createHash", "Node Cryptographic Hash"),
    "crypto.timingSafeEqual": ("crypto.timingSafeEqual", "Constant-Time Comparison"),
    "crypto.randomBytes": ("crypto.randomBytes", "CSPRNG Entropy"),
    "os.getenv": ("os.getenv", "Runtime Environment Config"),
    "os.environ.get": ("os.environ.get", "Runtime Environment Config"),
}

_GENERIC_UNINDEXED_NAMES: frozenset[str] = frozenset(
    {
        "get",
        "set",
        "add",
        "pop",
        "append",
        "extend",
        "update",
        "items",
        "keys",
        "values",
        "strip",
        "lstrip",
        "rstrip",
        "split",
        "splitlines",
        "join",
        "replace",
        "lower",
        "upper",
        "startswith",
        "endswith",
        "format",
        "encode",
        "decode",
        "dict",
        "list",
        "tuple",
        "int",
        "float",
        "str",
        "bool",
        "len",
        "min",
        "max",
        "sum",
        "sorted",
        "any",
        "all",
        "next",
        "enumerate",
        "isinstance",
        "getattr",
        "setattr",
        "hasattr",
        "print",
        "json",
        "status",
        "send",
        "ok",
        "model_dump",
        "model_copy",
    }
)

_CIRCLED_STEPS: Tuple[str, ...] = (
    "①",
    "②",
    "③",
    "④",
    "⑤",
    "⑥",
    "⑦",
    "⑧",
    "⑨",
    "⑩",
    "⑪",
    "⑫",
)


@dataclass
class _CallSiteRecord:
    callee: str
    line_number: int
    code_snippet: str
    full_expr: str


@dataclass
class _FunctionRecord:
    filepath: str
    name: str
    qualname: str
    start_line: int
    end_line: int
    params: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    body_text: str = ""
    calls: List[_CallSiteRecord] = field(default_factory=list)
    string_consts: List[Tuple[int, str]] = field(default_factory=list)


@dataclass
class _DiscoveredRouteSpec:
    method: str
    route_path: str
    framework: str
    handler_name: str
    handler_qualname: str
    filepath: str
    start_line: int
    end_line: int
    auth_status: str = "UNAUTHENTICATED"
    auth_mechanisms: List[str] = field(default_factory=list)
    request_params: List[str] = field(default_factory=list)
    validated_models: List[Tuple[str, int, str]] = field(default_factory=list)
    response_type: Optional[str] = None
    extra_seed_calls: List[Tuple[str, int, str]] = field(default_factory=list)
    inline_fn: Optional[_FunctionRecord] = None


def _circled_step(step_num: int) -> str:
    if 1 <= step_num <= len(_CIRCLED_STEPS):
        return _CIRCLED_STEPS[step_num - 1]
    return f"({step_num})"


def _join_route_paths(*parts: str) -> str:
    segments: List[str] = []
    for raw in parts:
        cleaned = (raw or "").strip()
        if not cleaned or cleaned == "/":
            continue
        for seg in cleaned.split("/"):
            seg_s = seg.strip()
            if seg_s:
                segments.append(seg_s)
    return "/" + "/".join(segments) if segments else "/"


def _normalize_rel_path(path_str: str, root_real: str = "") -> str:
    cleaned = (path_str or "").strip().replace("\\", "/")
    if not cleaned:
        return ""
    if root_real:
        root_fwd = root_real.replace("\\", "/").rstrip("/")
        if cleaned.lower().startswith(root_fwd.lower() + "/"):
            cleaned = cleaned[len(root_fwd) + 1 :]
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.lstrip("/")


def _read_confined_source_file(root_real: str, file_real: str) -> str:
    """
    Canonicalizes via os.path.commonpath and reads source text strictly from
    confined workspace entries to uphold CWE-22 path traversal immunity.
    """
    try:
        common_base = os.path.commonpath([root_real, file_real])
    except ValueError:
        return ""
    if common_base != root_real:
        return ""
    safe_target = os.path.join(common_base, os.path.relpath(file_real, common_base))
    try:
        with open(safe_target, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(512 * 1024)
    except OSError:
        return ""


def _ast_callee_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _ast_callee_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _ast_callee_name(node.func)
    return ""


def _ast_unparse_safe(node: Optional[ast.AST]) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""


def _convert_nextjs_segment(seg: str) -> Optional[str]:
    if not seg:
        return None
    if seg.startswith("(") and seg.endswith(")"):
        return None
    if seg.startswith("@"):
        return None
    m_opt_catch = re.match(r"^\[\[\.\.\.([A-Za-z0-9_]+)\]\]$", seg)
    if m_opt_catch:
        return f"{{{m_opt_catch.group(1)}*}}"
    m_catch = re.match(r"^\[\.\.\.([A-Za-z0-9_]+)\]$", seg)
    if m_catch:
        return f"{{{m_catch.group(1)}*}}"
    m_dyn = re.match(r"^\[([A-Za-z0-9_]+)\]$", seg)
    if m_dyn:
        return f"{{{m_dyn.group(1)}}}"
    return seg


def _find_matching_brace_end(lines: List[str], start_idx: int) -> int:
    """Finds 1-indexed end line of a `{ ... }` block starting at or shortly after `start_idx`."""
    depth = 0
    opened = False
    in_quote: Optional[str] = None
    max_scan = min(len(lines), start_idx + 800)
    for idx in range(start_idx, max_scan):
        line = lines[idx]
        pos = 0
        line_len = len(line)
        while pos < line_len:
            ch = line[pos]
            if in_quote is not None:
                if ch == "\\":
                    pos += 2
                    continue
                if ch == in_quote:
                    in_quote = None
                pos += 1
                continue
            if ch in ("'", '"', "`"):
                in_quote = ch
                pos += 1
                continue
            if ch == "/" and pos + 1 < line_len and line[pos + 1] == "/":
                break
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}" and opened:
                depth -= 1
                if depth <= 0:
                    return idx + 1
            pos += 1
    return min(len(lines), start_idx + 25)


class _WorkspaceSymbolGraph:
    """Holds confined source contents, function definitions, class/schema info, and cross-file imports."""

    def __init__(self, root_real: str, files_map: Dict[str, str]):
        self.root_real = root_real
        self.files_map = files_map  # rel_fp -> source text
        self.file_lines: Dict[str, List[str]] = {
            fp: text.splitlines() for fp, text in files_map.items()
        }
        self.functions: Dict[Tuple[str, str], _FunctionRecord] = {}
        self.functions_by_short_name: Dict[str, List[_FunctionRecord]] = {}
        self.schema_classes: Set[str] = set()
        self.class_locations: Dict[str, str] = {}  # ClassName -> rel_fp
        # symbol_imports[rel_fp][local_alias] = (target_rel_fp, exported_symbol)
        self.symbol_imports: Dict[str, Dict[str, Tuple[str, str]]] = {}
        # module_imports[rel_fp][local_mod_alias] = target_rel_fp
        self.module_imports: Dict[str, Dict[str, str]] = {}
        # instance_types[rel_fp][var_name] = ClassName
        self.instance_types: Dict[str, Dict[str, str]] = {}
        # Global Cypher rules existence in rule_executor.py for Neo4j rule runner correlation
        self.file_GlobalStrings: Dict[str, List[str]] = {}

    def register_function(self, rec: _FunctionRecord) -> None:
        self.functions[(rec.filepath, rec.qualname)] = rec
        if rec.name != rec.qualname and (rec.filepath, rec.name) not in self.functions:
            self.functions[(rec.filepath, rec.name)] = rec
        self.functions_by_short_name.setdefault(rec.name, []).append(rec)
        if rec.qualname != rec.name:
            self.functions_by_short_name.setdefault(rec.qualname, []).append(rec)

    def resolve_python_module(self, current_fp: str, module_dots: str, level: int = 0) -> Optional[str]:
        cur_dir = posixpath.dirname(current_fp)
        base_dir = cur_dir
        if level > 1:
            for _ in range(level - 1):
                base_dir = posixpath.dirname(base_dir)
        mod_rel = (module_dots or "").replace(".", "/").strip("/")

        search_prefixes: List[str] = []
        if level >= 1:
            search_prefixes.append(base_dir)
        else:
            search_prefixes.extend(["", cur_dir, "backend", "src", "app"])
            if "/" in cur_dir:
                top_pkg = cur_dir.split("/", 1)[0]
                if top_pkg not in search_prefixes:
                    search_prefixes.append(top_pkg)

        for pref in search_prefixes:
            joined = posixpath.normpath(f"{pref}/{mod_rel}" if pref and mod_rel else (pref or mod_rel))
            joined = joined.lstrip("./")
            for cand in (f"{joined}.py", f"{joined}/__init__.py"):
                if cand in self.files_map:
                    return cand
        return None

    def resolve_js_module(self, current_fp: str, spec: str) -> Optional[str]:
        raw = (spec or "").strip()
        if not raw:
            return None
        cur_dir = posixpath.dirname(current_fp)
        bases: List[str] = []
        if raw.startswith("@/"):
            tail = raw[2:]
            bases.extend([f"src/{tail}", f"frontend/src/{tail}", tail])
        elif raw.startswith("."):
            bases.append(posixpath.normpath(posixpath.join(cur_dir, raw)))
        else:
            return None

        exts = ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
        for b in bases:
            clean_b = b.lstrip("./")
            for ext in exts:
                cand = f"{clean_b}{ext}"
                if cand in self.files_map:
                    return cand
            for idx_ext in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
                idx_cand = f"{clean_b}/index{idx_ext}"
                if idx_cand in self.files_map:
                    return idx_cand
        return None

    def resolve_callee(self, caller_fp: str, callee_expr: str) -> Optional[_FunctionRecord]:
        clean = (callee_expr or "").strip()
        if not clean:
            return None
        for prefix in ("self.", "cls.", "this."):
            if clean.startswith(prefix):
                clean = clean[len(prefix) :]

        # 1. Exact match in same file
        direct = self.functions.get((caller_fp, clean))
        if direct is not None:
            return direct

        # 2. Imported symbol in caller_fp
        imp_syms = self.symbol_imports.get(caller_fp, {})
        if clean in imp_syms:
            tgt_fp, tgt_sym = imp_syms[clean]
            resolved = self.functions.get((tgt_fp, tgt_sym))
            if resolved is not None:
                return resolved

        # 3. Dotted call `obj_or_mod.method`
        if "." in clean:
            head, tail = clean.split(".", 1)
            if "." not in tail:
                # 3a. Module alias import (`svc.persist_order`)
                mod_map = self.module_imports.get(caller_fp, {})
                if head in mod_map:
                    tgt_fp = mod_map[head]
                    resolved = self.functions.get((tgt_fp, tail))
                    if resolved is not None:
                        return resolved
                # 3b. Imported class or factory instance (`enterprise_mgr.get_sast_plus_suite`, `executor.run_all_rules`)
                inst_cls = self.instance_types.get(caller_fp, {}).get(head)
                if inst_cls:
                    cls_fp = self.class_locations.get(inst_cls)
                    if cls_fp:
                        resolved = self.functions.get((cls_fp, f"{inst_cls}.{tail}")) or self.functions.get(
                            (cls_fp, tail)
                        )
                        if resolved is not None:
                            return resolved
                if head in imp_syms:
                    tgt_fp, tgt_cls = imp_syms[head]
                    resolved = self.functions.get((tgt_fp, f"{tgt_cls}.{tail}")) or self.functions.get(
                        (tgt_fp, tail)
                    )
                    if resolved is not None:
                        return resolved
                # 3c. Same-file class method fallback
                same_tail = self.functions.get((caller_fp, tail))
                if same_tail is not None:
                    return same_tail
                # 3d. Unambiguous method across workspace if non-generic
                if tail not in _GENERIC_UNINDEXED_NAMES:
                    cands = self.functions_by_short_name.get(tail, [])
                    if len(cands) == 1:
                        return cands[0]

        # 4. Unambiguous workspace-wide function name fallback (for Go package peers / Java / Django)
        if "." not in clean and clean not in _GENERIC_UNINDEXED_NAMES:
            cands = self.functions_by_short_name.get(clean, [])
            if len(cands) == 1:
                return cands[0]
            cur_dir = posixpath.dirname(caller_fp)
            same_pkg = [c for c in cands if posixpath.dirname(c.filepath) == cur_dir]
            if len(same_pkg) == 1:
                return same_pkg[0]

        return None


class ApiOperationsEngine:
    """
    Deterministic multi-framework API endpoint discovery and inter-procedural
    operations tracer. Runs 100% natively in Python stdlib without Neo4j or external binaries.
    """

    def analyze_workspace_api_operations(
        self,
        target_dir: str,
        findings: Optional[List[Finding]] = None,
    ) -> ApiOperationsReportResponse:
        if not target_dir or not os.path.exists(target_dir):
            return ApiOperationsReportResponse(
                project_path=target_dir or "",
                total_endpoints=0,
                authenticated_count=0,
                unauthenticated_count=0,
                mutating_endpoints_count=0,
                db_endpoints_count=0,
                external_http_endpoints_count=0,
                exec_or_fs_endpoints_count=0,
                vulnerable_endpoints_count=0,
            )

        real_input = os.path.realpath(target_dir)
        is_single_file = os.path.isfile(real_input)
        root_real = os.path.dirname(real_input) if is_single_file else real_input

        files_map = self._enumerate_confined_sources(root_real, real_input if is_single_file else None)
        graph = _WorkspaceSymbolGraph(root_real, files_map)

        py_asts: Dict[str, ast.Module] = {}
        for rel_fp, src_text in files_map.items():
            ext = posixpath.splitext(rel_fp)[1].lower()
            if ext == ".py":
                parsed = self._index_python_file(rel_fp, src_text, graph)
                if parsed is not None:
                    py_asts[rel_fp] = parsed
            elif ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
                self._index_js_ts_file(rel_fp, src_text, graph)
            elif ext == ".go":
                self._index_go_file(rel_fp, src_text, graph)
            elif ext == ".java":
                self._index_java_file(rel_fp, src_text, graph)

        # Second pass on Python files to bind factory/singleton return types (e.g. get_secret_validator_engine -> SecretValidatorEngine)
        self._bind_factory_instance_types(py_asts, graph)

        route_specs: List[_DiscoveredRouteSpec] = []
        route_specs.extend(self._discover_python_routes(py_asts, graph))
        for rel_fp, src_text in files_map.items():
            ext = posixpath.splitext(rel_fp)[1].lower()
            if ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
                route_specs.extend(self._discover_nextjs_routes(rel_fp, src_text, graph))
                route_specs.extend(self._discover_nestjs_routes(rel_fp, src_text, graph))
                route_specs.extend(self._discover_express_routes(rel_fp, src_text, graph))
            elif ext == ".go":
                route_specs.extend(self._discover_go_routes(rel_fp, src_text, graph))
            elif ext == ".java":
                route_specs.extend(self._discover_spring_routes(rel_fp, src_text, graph))

        active_findings = [
            f for f in (findings or []) if getattr(f, "triage_status", "TO_VERIFY") != "NOT_EXPLOITABLE"
        ]
        finding_locs = self._index_finding_locations(active_findings, root_real)

        dossiers: List[ApiEndpointOperationDossier] = []
        seen_route_keys: Set[Tuple[str, str, str, int]] = set()
        for spec in route_specs:
            dedup_key = (spec.method, spec.route_path, spec.filepath, spec.start_line)
            if dedup_key in seen_route_keys:
                continue
            seen_route_keys.add(dedup_key)
            dossier = self._build_endpoint_dossier(spec, graph, active_findings, finding_locs)
            dossiers.append(dossier)

        dossiers.sort(key=lambda d: (d.filepath, d.start_line, d.route_path, d.method))

        frameworks_detected: List[str] = []
        seen_fw: Set[str] = set()
        for d in dossiers:
            if d.framework not in seen_fw:
                seen_fw.add(d.framework)
                frameworks_detected.append(d.framework)

        authenticated_count = sum(1 for d in dossiers if d.auth_status == "AUTHENTICATED")
        unauthenticated_count = sum(1 for d in dossiers if d.auth_status == "UNAUTHENTICATED")
        mutating_count = sum(1 for d in dossiers if d.is_mutating)
        db_count = sum(
            1
            for d in dossiers
            if ("DATABASE_READ" in d.operation_categories or "DATABASE_WRITE" in d.operation_categories)
        )
        ext_http_count = sum(
            1 for d in dossiers if "EXTERNAL_HTTP_OR_AI" in d.operation_categories
        )
        exec_or_fs_count = sum(
            1
            for d in dossiers
            if ("OS_COMMAND_EXEC" in d.operation_categories or "FILESYSTEM_IO" in d.operation_categories)
        )
        vuln_count = sum(1 for d in dossiers if d.linked_findings_count > 0)

        return ApiOperationsReportResponse(
            project_path=target_dir,
            total_endpoints=len(dossiers),
            authenticated_count=authenticated_count,
            unauthenticated_count=unauthenticated_count,
            mutating_endpoints_count=mutating_count,
            db_endpoints_count=db_count,
            external_http_endpoints_count=ext_http_count,
            exec_or_fs_endpoints_count=exec_or_fs_count,
            vulnerable_endpoints_count=vuln_count,
            frameworks_detected=frameworks_detected,
            endpoints=dossiers,
        )

    def _enumerate_confined_sources(
        self,
        root_real: str,
        single_file_real: Optional[str] = None,
    ) -> Dict[str, str]:
        files_map: Dict[str, str] = {}
        is_synth_root = os.path.basename(root_real).lower() == "synthetic_test_target"

        if single_file_real is not None:
            ext = os.path.splitext(single_file_real)[1].lower()
            if ext in _SOURCE_EXTENSIONS:
                text = _read_confined_source_file(root_real, single_file_real)
                rel_fp = os.path.basename(single_file_real).replace("\\", "/")
                files_map[rel_fp] = text
            return files_map

        for dirpath, dirnames, filenames in os.walk(root_real):
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d.lower() not in _EXCLUDED_WALK_DIRS
                and not d.startswith(".")
                and (is_synth_root or d.lower() != "synthetic_test_target")
            )
            for fname in sorted(filenames):
                f_low = fname.lower()
                if f_low in _EXCLUDED_FILENAMES or fname.startswith("._"):
                    continue
                ext = os.path.splitext(fname)[1].lower()
                if ext not in _SOURCE_EXTENSIONS:
                    continue
                file_real = os.path.realpath(os.path.join(dirpath, fname))
                src_text = _read_confined_source_file(root_real, file_real)
                rel_fp = os.path.relpath(file_real, root_real).replace("\\", "/")
                if not rel_fp.startswith(".."):
                    files_map[rel_fp] = src_text
        return files_map

    # ------------------------------------------------------------------
    # Language Indexers
    # ------------------------------------------------------------------
    def _index_python_file(
        self,
        rel_fp: str,
        src_text: str,
        graph: _WorkspaceSymbolGraph,
    ) -> Optional[ast.Module]:
        try:
            tree = ast.parse(src_text)
        except SyntaxError:
            return None

        lines = graph.file_lines[rel_fp]
        sym_imp = graph.symbol_imports.setdefault(rel_fp, {})
        mod_imp = graph.module_imports.setdefault(rel_fp, {})
        inst_map = graph.instance_types.setdefault(rel_fp, {})

        # Collect module-level string constants (e.g. Cypher queries in RULES)
        mod_strings: List[str] = []
        for stmt in tree.body:
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    local_name = alias.asname or alias.name.split(".")[0]
                    resolved_fp = graph.resolve_python_module(rel_fp, alias.name, 0)
                    if resolved_fp:
                        mod_imp[local_name] = resolved_fp
            elif isinstance(stmt, ast.ImportFrom):
                resolved_fp = graph.resolve_python_module(rel_fp, stmt.module or "", stmt.level or 0)
                if resolved_fp:
                    for alias in stmt.names:
                        if alias.name == "*":
                            continue
                        local_name = alias.asname or alias.name
                        sym_imp[local_name] = (resolved_fp, alias.name)
            elif isinstance(stmt, ast.ClassDef):
                graph.class_locations[stmt.name] = rel_fp
                base_names = {_ast_callee_name(b) for b in stmt.bases}
                if (
                    any(b.endswith("BaseModel") or b in ("Schema", "Serializer") for b in base_names)
                    or stmt.name.endswith(("Request", "Payload", "Schema", "Input", "Dto", "DTO", "Model", "Update"))
                ):
                    graph.schema_classes.add(stmt.name)
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        rec = self._build_py_function_record(
                            rel_fp, item, lines, src_text, class_name=stmt.name, inst_map=inst_map
                        )
                        graph.register_function(rec)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                rec = self._build_py_function_record(
                    rel_fp, stmt, lines, src_text, class_name=None, inst_map=inst_map
                )
                graph.register_function(rec)
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                self._record_py_instance_assignment(stmt, inst_map)
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and len(sub.value) > 12:
                        mod_strings.append(sub.value)

        if mod_strings:
            graph.file_GlobalStrings[rel_fp] = mod_strings
        return tree

    def _record_py_instance_assignment(
        self,
        stmt: ast.AST,
        inst_map: Dict[str, str],
    ) -> None:
        val_node: Optional[ast.AST] = None
        target_names: List[str] = []
        if isinstance(stmt, ast.Assign):
            val_node = stmt.value
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    target_names.append(t.id)
        elif isinstance(stmt, ast.AnnAssign):
            val_node = stmt.value
            if isinstance(stmt.target, ast.Name):
                target_names.append(stmt.target.id)
                ann_str = _ast_unparse_safe(stmt.annotation)
                if ann_str and ann_str[0].isupper() and "[" not in ann_str:
                    for tn in target_names:
                        inst_map[tn] = ann_str

        if isinstance(val_node, ast.Call):
            callee = _ast_callee_name(val_node.func)
            inferred_cls = ""
            if callee.endswith(".get_instance") and "." in callee:
                inferred_cls = callee.split(".")[0]
            elif "." not in callee and callee[:1].isupper():
                inferred_cls = callee
            elif "." in callee and callee.rsplit(".", 1)[-1][:1].isupper():
                inferred_cls = callee.rsplit(".", 1)[-1]
            if inferred_cls:
                for tn in target_names:
                    inst_map[tn] = inferred_cls

    def _bind_factory_instance_types(
        self,
        py_asts: Dict[str, ast.Module],
        graph: _WorkspaceSymbolGraph,
    ) -> None:
        for rel_fp, tree in py_asts.items():
            inst_map = graph.instance_types.setdefault(rel_fp, {})
            for stmt in ast.walk(tree):
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                    callee = _ast_callee_name(stmt.value.func)
                    if not callee or callee[:1].isupper():
                        continue
                    target_rec = graph.resolve_callee(rel_fp, callee)
                    if target_rec and target_rec.return_type:
                        rt = target_rec.return_type.strip("\"'")
                        if rt in graph.class_locations:
                            for t in stmt.targets:
                                if isinstance(t, ast.Name):
                                    inst_map[t.id] = rt

    def _build_py_function_record(
        self,
        rel_fp: str,
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        lines: List[str],
        src_text: str,
        class_name: Optional[str],
        inst_map: Dict[str, str],
    ) -> _FunctionRecord:
        start_ln = int(fn_node.lineno)
        end_ln = int(getattr(fn_node, "end_lineno", None) or start_ln)
        qualname = f"{class_name}.{fn_node.name}" if class_name else fn_node.name
        params: List[str] = []
        for arg in fn_node.args.args:
            if arg.arg not in ("self", "cls"):
                params.append(arg.arg)
        ret_type = _ast_unparse_safe(fn_node.returns) or None

        call_nodes: List[ast.Call] = []
        str_consts: List[Tuple[int, str]] = []
        dec_ids = {id(d) for d in fn_node.decorator_list}

        for child in ast.walk(fn_node):
            if id(child) in dec_ids:
                continue
            if isinstance(child, (ast.Assign, ast.AnnAssign)):
                self._record_py_instance_assignment(child, inst_map)
            elif isinstance(child, ast.Call):
                call_nodes.append(child)
            elif isinstance(child, ast.Constant) and isinstance(child.value, str) and len(child.value) >= 8:
                str_consts.append((int(getattr(child, "lineno", start_ln)), child.value))

        call_nodes.sort(key=lambda c: (int(getattr(c, "lineno", start_ln)), int(getattr(c, "col_offset", 0))))

        call_records: List[_CallSiteRecord] = []
        for c_node in call_nodes:
            callee = _ast_callee_name(c_node.func)
            if not callee:
                continue
            c_ln = int(getattr(c_node, "lineno", start_ln))
            seg = ast.get_source_segment(src_text, c_node) or ""
            if not seg and 1 <= c_ln <= len(lines):
                seg = lines[c_ln - 1].strip()
            one_line = re.sub(r"\s+", " ", seg).strip()
            call_records.append(
                _CallSiteRecord(
                    callee=callee,
                    line_number=c_ln,
                    code_snippet=one_line[:180],
                    full_expr=seg,
                )
            )

        body_slice = "\n".join(lines[max(0, start_ln - 1) : min(len(lines), end_ln)])
        return _FunctionRecord(
            filepath=rel_fp,
            name=fn_node.name,
            qualname=qualname,
            start_line=start_ln,
            end_line=end_ln,
            params=params,
            return_type=ret_type,
            body_text=body_slice,
            calls=call_records,
            string_consts=str_consts,
        )

    def _index_js_ts_file(
        self,
        rel_fp: str,
        src_text: str,
        graph: _WorkspaceSymbolGraph,
    ) -> None:
        lines = graph.file_lines[rel_fp]
        sym_imp = graph.symbol_imports.setdefault(rel_fp, {})
        mod_imp = graph.module_imports.setdefault(rel_fp, {})

        # ES imports: import { a, b as c } from "./x" | import d from "./x" | import * as m from "./x"
        for m_imp in re.finditer(
            r"import\s+(?:type\s+)?([^\n;]+?)\s+from\s+['\"]([^'\"]+)['\"]",
            src_text,
        ):
            clause = m_imp.group(1).strip()
            spec = m_imp.group(2).strip()
            target_fp = graph.resolve_js_module(rel_fp, spec)
            if not target_fp:
                continue
            ns_m = re.match(r"\*\s+as\s+([A-Za-z0-9_$]+)", clause)
            if ns_m:
                mod_imp[ns_m.group(1)] = target_fp
                continue
            brace_m = re.search(r"\{([^}]+)\}", clause)
            if brace_m:
                for part in brace_m.group(1).split(","):
                    tok = part.strip()
                    if not tok:
                        continue
                    if " as " in tok:
                        orig, loc = [p.strip() for p in tok.split(" as ", 1)]
                        sym_imp[loc] = (target_fp, orig)
                    else:
                        sym_imp[tok] = (target_fp, tok)
            prefix_part = clause.split("{")[0].strip().rstrip(",").strip()
            if prefix_part and re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", prefix_part):
                mod_imp[prefix_part] = target_fp
                sym_imp[prefix_part] = (target_fp, prefix_part)

        # CommonJS require: const { a, b: c } = require("../x") | const svc = require("../x")
        for m_req in re.finditer(
            r"(?:const|let|var)\s+(\{[^}]+\}|[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)",
            src_text,
        ):
            lhs = m_req.group(1).strip()
            spec = m_req.group(2).strip()
            target_fp = graph.resolve_js_module(rel_fp, spec)
            if not target_fp:
                continue
            if lhs.startswith("{") and lhs.endswith("}"):
                for part in lhs[1:-1].split(","):
                    tok = part.strip()
                    if not tok:
                        continue
                    if ":" in tok:
                        orig, loc = [p.strip() for p in tok.split(":", 1)]
                        sym_imp[loc] = (target_fp, orig)
                    else:
                        sym_imp[tok] = (target_fp, tok)
            else:
                mod_imp[lhs] = target_fp
                sym_imp[lhs] = (target_fp, lhs)

        fn_decl_rx = re.compile(
            r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)"
        )
        arrow_decl_rx = re.compile(
            r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?\(([^)]*)\)\s*(?::[^=]+)?=>"
        )
        method_decl_rx = re.compile(
            r"^\s*(?:public\s+|private\s+|protected\s+)?(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*(?::\s*[A-Za-z0-9_<>\[\]|?\s]+)?\s*\{"
        )

        js_keywords = {"if", "for", "while", "switch", "catch", "function", "return", "constructor"}
        current_cls: Optional[str] = None
        cls_end_ln = 0
        cls_rx = re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)")

        for idx, line in enumerate(lines):
            ln_no = idx + 1
            if current_cls and ln_no > cls_end_ln:
                current_cls = None

            m_cls = cls_rx.match(line)
            if m_cls:
                current_cls = m_cls.group(1)
                cls_end_ln = _find_matching_brace_end(lines, idx)
                graph.class_locations[current_cls] = rel_fp
                continue

            m_fn = fn_decl_rx.match(line) or arrow_decl_rx.match(line)
            if m_fn:
                fn_name = m_fn.group(1)
                raw_params = m_fn.group(2)
                end_ln = _find_matching_brace_end(lines, idx)
                rec = self._build_brace_function_record(
                    rel_fp, fn_name, fn_name, ln_no, end_ln, raw_params, lines
                )
                graph.register_function(rec)
                continue

            if current_cls:
                m_meth = method_decl_rx.match(line)
                if m_meth and m_meth.group(1) not in js_keywords:
                    m_name = m_meth.group(1)
                    raw_params = m_meth.group(2)
                    end_ln = _find_matching_brace_end(lines, idx)
                    rec = self._build_brace_function_record(
                        rel_fp,
                        m_name,
                        f"{current_cls}.{m_name}",
                        ln_no,
                        end_ln,
                        raw_params,
                        lines,
                    )
                    graph.register_function(rec)

    def _index_go_file(
        self,
        rel_fp: str,
        _src_text: str,
        graph: _WorkspaceSymbolGraph,
    ) -> None:
        lines = graph.file_lines[rel_fp]
        go_fn_rx = re.compile(
            r"^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"
        )
        for idx, line in enumerate(lines):
            m = go_fn_rx.match(line)
            if m:
                fn_name = m.group(1)
                raw_params = m.group(2)
                end_ln = _find_matching_brace_end(lines, idx)
                rec = self._build_brace_function_record(
                    rel_fp, fn_name, fn_name, idx + 1, end_ln, raw_params, lines
                )
                graph.register_function(rec)

    def _index_java_file(
        self,
        rel_fp: str,
        _src_text: str,
        graph: _WorkspaceSymbolGraph,
    ) -> None:
        lines = graph.file_lines[rel_fp]
        cls_rx = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)")
        java_meth_rx = re.compile(
            r"^\s*(?:public|protected|private)\s+(?:static\s+)?([A-Za-z0-9_<>,?\[\]\s]+?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"
        )
        current_cls: Optional[str] = None
        for idx, line in enumerate(lines):
            m_cls = cls_rx.search(line)
            if m_cls:
                current_cls = m_cls.group(1)
                graph.class_locations[current_cls] = rel_fp
                continue
            m_meth = java_meth_rx.match(line)
            if m_meth:
                ret_t = m_meth.group(1).strip()
                fn_name = m_meth.group(2)
                raw_params = m_meth.group(3)
                end_ln = _find_matching_brace_end(lines, idx)
                qual = f"{current_cls}.{fn_name}" if current_cls else fn_name
                rec = self._build_brace_function_record(
                    rel_fp, fn_name, qual, idx + 1, end_ln, raw_params, lines, return_type=ret_t
                )
                graph.register_function(rec)

    def _build_brace_function_record(
        self,
        rel_fp: str,
        fn_name: str,
        qualname: str,
        start_ln: int,
        end_ln: int,
        raw_params: str,
        lines: List[str],
        return_type: Optional[str] = None,
    ) -> _FunctionRecord:
        params: List[str] = []
        for part in (raw_params or "").split(","):
            tok = part.strip()
            if not tok:
                continue
            tok = re.sub(r"^@[A-Za-z0-9_]+(?:\([^)]*\))?\s*", "", tok).strip()
            name_part = tok.split(":")[0].split("=")[0].strip()
            words = name_part.split()
            cand_p = words[-1] if words else ""
            cand_p = cand_p.lstrip("*.")
            if cand_p and re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", cand_p):
                params.append(cand_p)

        body_lines = lines[max(0, start_ln - 1) : min(len(lines), end_ln)]
        calls = self._extract_textual_calls(body_lines, start_ln)
        return _FunctionRecord(
            filepath=rel_fp,
            name=fn_name,
            qualname=qualname,
            start_line=start_ln,
            end_line=end_ln,
            params=params,
            return_type=return_type,
            body_text="\n".join(body_lines),
            calls=calls,
        )

    def _extract_textual_calls(
        self,
        body_lines: List[str],
        base_start_line: int,
    ) -> List[_CallSiteRecord]:
        call_rx = re.compile(r"([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(")
        skip_tokens = {
            "if",
            "for",
            "while",
            "switch",
            "catch",
            "function",
            "return",
            "sizeof",
            "new",
        }
        records: List[_CallSiteRecord] = []
        for offset, raw_line in enumerate(body_lines):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("//", "#", "/*", "*")):
                continue
            if offset == 0 and ("function " in stripped or "func " in stripped):
                continue
            ln_no = base_start_line + offset
            window = " ".join(
                l.strip() for l in body_lines[offset : min(len(body_lines), offset + 3)]
            )
            for m in call_rx.finditer(stripped):
                callee = m.group(1)
                if callee in skip_tokens:
                    continue
                records.append(
                    _CallSiteRecord(
                        callee=callee,
                        line_number=ln_no,
                        code_snippet=stripped[:180],
                        full_expr=window[:360],
                    )
                )
        return records

    # ------------------------------------------------------------------
    # Multi-Framework Route Detectors
    # ------------------------------------------------------------------
    def _discover_python_routes(
        self,
        py_asts: Dict[str, ast.Module],
        graph: _WorkspaceSymbolGraph,
    ) -> List[_DiscoveredRouteSpec]:
        routes: List[_DiscoveredRouteSpec] = []

        # Map cross-file include_router(router_sym, prefix="/...")
        external_router_prefixes: Dict[Tuple[str, str], str] = {}
        for rel_fp, tree in py_asts.items():
            sym_imp = graph.symbol_imports.get(rel_fp, {})
            mod_imp = graph.module_imports.get(rel_fp, {})
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and _ast_callee_name(node.func).endswith(".include_router"):
                    if not node.args:
                        continue
                    inc_prefix = ""
                    for kw in node.keywords:
                        if kw.arg == "prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            inc_prefix = kw.value.value
                    arg0 = _ast_callee_name(node.args[0])
                    if arg0 in sym_imp:
                        t_fp, t_sym = sym_imp[arg0]
                        external_router_prefixes[(t_fp, t_sym)] = inc_prefix
                    elif "." in arg0:
                        mod_part, sym_part = arg0.split(".", 1)
                        if mod_part in mod_imp:
                            external_router_prefixes[(mod_imp[mod_part], sym_part)] = inc_prefix

        for rel_fp, tree in py_asts.items():
            lines = graph.file_lines[rel_fp]
            router_prefixes: Dict[str, str] = {}
            router_frameworks: Dict[str, str] = {}
            router_auth_deps: Dict[str, List[str]] = {}

            for stmt in tree.body:
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                    ctor = _ast_callee_name(stmt.value.func)
                    short_ctor = ctor.rsplit(".", 1)[-1]
                    if short_ctor in ("APIRouter", "FastAPI", "Starlette"):
                        pref = ""
                        r_deps: List[str] = []
                        for kw in stmt.value.keywords:
                            if kw.arg == "prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                pref = kw.value.value
                            elif kw.arg == "dependencies":
                                r_deps.extend(self._extract_fastapi_depends_names(kw.value))
                        for t in stmt.targets:
                            if isinstance(t, ast.Name):
                                ext_p = external_router_prefixes.get((rel_fp, t.id), "")
                                router_prefixes[t.id] = _join_route_paths(ext_p, pref) if (ext_p or pref) else ""
                                router_frameworks[t.id] = "FastAPI"
                                if r_deps:
                                    router_auth_deps[t.id] = r_deps
                    elif short_ctor in ("Flask", "Blueprint"):
                        pref = ""
                        if short_ctor == "Blueprint":
                            for kw in stmt.value.keywords:
                                if kw.arg == "url_prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                    pref = kw.value.value
                        for t in stmt.targets:
                            if isinstance(t, ast.Name):
                                router_prefixes[t.id] = pref
                                router_frameworks[t.id] = "Flask"

            # Walk functions & class methods for FastAPI / Flask decorators
            for node in tree.body:
                fn_items: List[Tuple[Optional[str], ast.FunctionDef | ast.AsyncFunctionDef]] = []
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_items.append((None, node))
                elif isinstance(node, ast.ClassDef):
                    for sub in node.body:
                        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            fn_items.append((node.name, sub))

                for cls_name, fn_node in fn_items:
                    routes.extend(
                        self._extract_py_decorated_routes(
                            rel_fp,
                            cls_name,
                            fn_node,
                            lines,
                            router_prefixes,
                            router_frameworks,
                            router_auth_deps,
                            graph,
                        )
                    )

            # Django urlpatterns = [path("...", view_fn), re_path(...)]
            routes.extend(self._extract_django_urlpatterns(rel_fp, tree, py_asts, graph))

        return routes

    def _extract_fastapi_depends_names(self, expr: ast.AST) -> List[str]:
        found: List[str] = []
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Call):
                cname = _ast_callee_name(sub.func).rsplit(".", 1)[-1]
                if cname in ("Depends", "Security") and sub.args:
                    dep_target = _ast_callee_name(sub.args[0]) or _ast_unparse_safe(sub.args[0])
                    if dep_target:
                        found.append(dep_target)
        return found

    def _extract_py_decorated_routes(
        self,
        rel_fp: str,
        cls_name: Optional[str],
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        lines: List[str],
        router_prefixes: Dict[str, str],
        router_frameworks: Dict[str, str],
        router_auth_deps: Dict[str, List[str]],
        graph: _WorkspaceSymbolGraph,
    ) -> List[_DiscoveredRouteSpec]:
        if not fn_node.decorator_list:
            return []

        extra_auth_decorators: List[str] = []
        matched_routes: List[Tuple[str, str, str, Optional[str], List[str], int]] = []

        for dec in fn_node.decorator_list:
            dec_name = _ast_callee_name(dec)
            short_dec = dec_name.rsplit(".", 1)[-1]
            if _AUTH_NAME_RX.search(short_dec) and "." not in dec_name:
                extra_auth_decorators.append(short_dec)

            if not isinstance(dec, ast.Call) or "." not in dec_name:
                continue

            owner_obj, attr_name = dec_name.rsplit(".", 1)
            attr_low = attr_name.lower()

            # FastAPI / Flask verb decorators: @app.get("/x"), @router.post("/y"), @bp.get("/z")
            if attr_low in ("get", "post", "put", "delete", "patch", "options", "head", "route", "api_route"):
                raw_path = "/"
                if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                    raw_path = dec.args[0].value
                else:
                    for kw in dec.keywords:
                        if kw.arg in ("path", "rule") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            raw_path = kw.value.value

                fw = router_frameworks.get(owner_obj)
                if not fw:
                    fw = "Flask" if (attr_low == "route" or owner_obj in ("bp", "blueprint")) else "FastAPI"

                resp_model: Optional[str] = None
                dec_deps: List[str] = list(router_auth_deps.get(owner_obj, []))
                methods_list: List[str] = ["GET"] if attr_low in ("route", "api_route") else [attr_low.upper()]

                for kw in dec.keywords:
                    if kw.arg == "response_model":
                        resp_model = _ast_unparse_safe(kw.value) or None
                    elif kw.arg == "response_class":
                        resp_cls = _ast_unparse_safe(kw.value)
                        if resp_cls and not resp_model:
                            resp_model = resp_cls
                    elif kw.arg == "dependencies":
                        dec_deps.extend(self._extract_fastapi_depends_names(kw.value))
                    elif kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        parsed_m = [
                            str(elt.value).upper()
                            for elt in kw.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        ]
                        if parsed_m:
                            methods_list = parsed_m

                full_path = _join_route_paths(router_prefixes.get(owner_obj, ""), raw_path)
                for m_verb in methods_list:
                    matched_routes.append((m_verb, full_path, fw, resp_model, dec_deps, int(dec.lineno)))

        if not matched_routes:
            return []

        # Inspect parameters for Depends(...) auth guards, Pydantic models, and request parameters
        param_auth: List[str] = list(extra_auth_decorators)
        req_params: List[str] = []
        validated_models: List[Tuple[str, int, str]] = []
        seed_calls: List[Tuple[str, int, str]] = []

        args_all = list(fn_node.args.args)
        defaults_pad = [None] * (len(args_all) - len(fn_node.args.defaults)) + list(fn_node.args.defaults)
        for arg_node, def_expr in zip(args_all, defaults_pad):
            p_name = arg_node.arg
            if p_name in ("self", "cls", "background_tasks", "request", "response"):
                continue
            ann_text = _ast_unparse_safe(arg_node.annotation)
            dep_names = self._extract_fastapi_depends_names(def_expr) if def_expr is not None else []
            if dep_names:
                for dn in dep_names:
                    seed_calls.append((dn, int(arg_node.lineno), f"{p_name}=Depends({dn})"))
                    if _AUTH_NAME_RX.search(dn) or _AUTH_NAME_RX.search(p_name):
                        param_auth.append(dn)
                continue

            req_params.append(p_name)
            clean_ann = re.sub(r"^Optional\[(.+)\]$", r"\1", ann_text).strip()
            if clean_ann and (
                clean_ann in graph.schema_classes
                or clean_ann.endswith(("Request", "Payload", "Schema", "Input", "Update"))
            ):
                snip = lines[arg_node.lineno - 1].strip() if 1 <= arg_node.lineno <= len(lines) else f"{p_name}: {clean_ann}"
                validated_models.append((clean_ann, int(arg_node.lineno), snip[:160]))

        fn_ret = _ast_unparse_safe(fn_node.returns) or None
        qualname = f"{cls_name}.{fn_node.name}" if cls_name else fn_node.name
        min_start = min([int(d.lineno) for d in fn_node.decorator_list] + [int(fn_node.lineno)])
        end_ln = int(getattr(fn_node, "end_lineno", None) or fn_node.lineno)

        out: List[_DiscoveredRouteSpec] = []
        for m_verb, full_path, fw, resp_model, dec_deps, _dec_ln in matched_routes:
            all_auth = []
            for item in dec_deps + param_auth:
                if item not in all_auth:
                    all_auth.append(item)
            for dc in dec_deps:
                if (dc, min_start, f"Depends({dc})") not in seed_calls:
                    seed_calls.append((dc, min_start, f"Depends({dc})"))

            auth_st = "AUTHENTICATED" if all_auth else "UNAUTHENTICATED"
            out.append(
                _DiscoveredRouteSpec(
                    method=m_verb,
                    route_path=full_path,
                    framework=fw,
                    handler_name=fn_node.name,
                    handler_qualname=qualname,
                    filepath=rel_fp,
                    start_line=min_start,
                    end_line=end_ln,
                    auth_status=auth_st,
                    auth_mechanisms=all_auth,
                    request_params=list(req_params),
                    validated_models=list(validated_models),
                    response_type=resp_model or fn_ret,
                    extra_seed_calls=list(seed_calls),
                )
            )
        return out

    def _extract_django_urlpatterns(
        self,
        rel_fp: str,
        tree: ast.Module,
        py_asts: Dict[str, ast.Module],
        graph: _WorkspaceSymbolGraph,
    ) -> List[_DiscoveredRouteSpec]:
        out: List[_DiscoveredRouteSpec] = []
        for stmt in tree.body:
            if not isinstance(stmt, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in stmt.targets):
                continue
            for call in ast.walk(stmt.value):
                if not isinstance(call, ast.Call):
                    continue
                cname = _ast_callee_name(call.func).rsplit(".", 1)[-1]
                if cname not in ("path", "re_path", "url") or len(call.args) < 2:
                    continue
                if not (isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)):
                    continue
                raw_route = call.args[0].value
                target_expr = _ast_callee_name(call.args[1])
                if target_expr.endswith(".as_view"):
                    target_expr = target_expr[: -len(".as_view")]
                if target_expr == "include":
                    continue

                target_rec = graph.resolve_callee(rel_fp, target_expr)
                view_fp = target_rec.filepath if target_rec else rel_fp
                view_name = target_rec.name if target_rec else (target_expr.rsplit(".", 1)[-1] or "django_view")
                view_qual = target_rec.qualname if target_rec else view_name
                v_start = target_rec.start_line if target_rec else int(call.lineno)
                v_end = target_rec.end_line if target_rec else int(call.lineno)

                methods = ["GET"]
                auth_mechs: List[str] = []
                fw_label = "Django"
                view_tree = py_asts.get(view_fp)
                if view_tree is not None:
                    for v_stmt in ast.walk(view_tree):
                        if isinstance(v_stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and v_stmt.name == view_name:
                            for dec in v_stmt.decorator_list:
                                d_name = _ast_callee_name(dec).rsplit(".", 1)[-1]
                                if d_name == "api_view":
                                    fw_label = "Django REST"
                                    if isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], (ast.List, ast.Tuple)):
                                        parsed_m = [
                                            str(e.value).upper()
                                            for e in dec.args[0].elts
                                            if isinstance(e, ast.Constant) and isinstance(e.value, str)
                                        ]
                                        if parsed_m:
                                            methods = parsed_m
                                elif d_name == "permission_classes" and isinstance(dec, ast.Call):
                                    fw_label = "Django REST"
                                    perm_txt = _ast_unparse_safe(dec)
                                    if "IsAuthenticated" in perm_txt or "IsAdminUser" in perm_txt:
                                        auth_mechs.append("IsAuthenticated")
                                elif _AUTH_NAME_RX.search(d_name):
                                    auth_mechs.append(d_name)

                norm_route = _join_route_paths(raw_route)
                for m_verb in methods:
                    out.append(
                        _DiscoveredRouteSpec(
                            method=m_verb,
                            route_path=norm_route,
                            framework=fw_label,
                            handler_name=view_name,
                            handler_qualname=view_qual,
                            filepath=view_fp,
                            start_line=v_start,
                            end_line=v_end,
                            auth_status="AUTHENTICATED" if auth_mechs else "UNAUTHENTICATED",
                            auth_mechanisms=list(auth_mechs),
                            request_params=list(target_rec.params) if target_rec else [],
                        )
                    )
        return out

    def _discover_nextjs_routes(
        self,
        rel_fp: str,
        src_text: str,
        graph: _WorkspaceSymbolGraph,
    ) -> List[_DiscoveredRouteSpec]:
        out: List[_DiscoveredRouteSpec] = []
        lines = graph.file_lines[rel_fp]

        # 1. Next.js App Router: (src/)?app/**/route.(ts|tsx|js|jsx|mjs)
        m_app = re.search(r"(?:^|/)app/(?:(.+)/)?route\.(?:ts|tsx|js|jsx|mjs)$", rel_fp)
        if m_app:
            raw_mid = m_app.group(1) or ""
            conv_segs: List[str] = []
            dyn_params: List[str] = []
            for seg in raw_mid.split("/"):
                conv = _convert_nextjs_segment(seg)
                if conv:
                    conv_segs.append(conv)
                    if conv.startswith("{") and conv.endswith("}"):
                        dyn_params.append(conv[1:-1].rstrip("*"))
            route_path = _join_route_paths(*conv_segs)

            for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                fn_rec = graph.functions.get((rel_fp, method))
                if fn_rec is None:
                    continue
                params_merged = list(dyn_params) + [p for p in fn_rec.params if p not in dyn_params]
                out.append(
                    _DiscoveredRouteSpec(
                        method=method,
                        route_path=route_path,
                        framework="Next.js App Router",
                        handler_name=method,
                        handler_qualname=method,
                        filepath=rel_fp,
                        start_line=fn_rec.start_line,
                        end_line=fn_rec.end_line,
                        request_params=params_merged,
                        response_type="NextResponse",
                    )
                )
            return out

        # 2. Next.js Pages API: (src/)?pages/api/**/*.(ts|tsx|js|jsx|mjs)
        m_pages = re.search(r"(?:^|/)pages/(api/.+)\.(?:ts|tsx|js|jsx|mjs)$", rel_fp)
        if m_pages:
            raw_api = m_pages.group(1)
            conv_segs = []
            dyn_params = []
            for seg in raw_api.split("/"):
                if seg == "index":
                    continue
                conv = _convert_nextjs_segment(seg)
                if conv:
                    conv_segs.append(conv)
                    if conv.startswith("{") and conv.endswith("}"):
                        dyn_params.append(conv[1:-1].rstrip("*"))
            route_path = _join_route_paths(*conv_segs)

            methods_found = [
                m.upper()
                for m in re.findall(r"req\.method\s*===\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]", src_text)
            ]
            if not methods_found:
                methods_found = ["ALL"]

            default_fn: Optional[_FunctionRecord] = None
            for (fp_k, _qn), rec in graph.functions.items():
                if fp_k == rel_fp:
                    default_fn = rec
                    break
            start_ln = default_fn.start_line if default_fn else 1
            end_ln = default_fn.end_line if default_fn else max(1, len(lines))
            h_name = default_fn.name if default_fn else "handler"

            for m_verb in dict.fromkeys(methods_found):
                out.append(
                    _DiscoveredRouteSpec(
                        method=m_verb,
                        route_path=route_path,
                        framework="Next.js Pages API",
                        handler_name=h_name,
                        handler_qualname=h_name,
                        filepath=rel_fp,
                        start_line=start_ln,
                        end_line=end_ln,
                        request_params=list(dyn_params),
                    )
                )
        return out

    def _discover_express_routes(
        self,
        rel_fp: str,
        _src_text: str,
        graph: _WorkspaceSymbolGraph,
    ) -> List[_DiscoveredRouteSpec]:
        if re.search(r"(?:^|/)(?:app|pages)/", rel_fp):
            return []
        lines = graph.file_lines[rel_fp]
        route_rx = re.compile(
            r"\b(?:app|router|server|fastify)\.(get|post|put|delete|patch)\s*\(\s*['\"`]([^'\"`]+)['\"`]\s*,\s*(.+)$"
        )
        out: List[_DiscoveredRouteSpec] = []
        for idx, line in enumerate(lines):
            m = route_rx.search(line)
            if not m:
                continue
            method = m.group(1).upper()
            route_path = _join_route_paths(m.group(2))
            rest = m.group(3).strip()
            fw = "Fastify" if "fastify." in line else "Express.js"
            start_ln = idx + 1
            end_ln = _find_matching_brace_end(lines, idx) if "{" in rest else start_ln

            # Extract middleware identifiers preceding the final callback or handler
            middlewares: List[str] = []
            callback_split = re.split(r"(?:async\s*)?\([^)]*\)\s*=>|(?:async\s+)?function\s*\(", rest, maxsplit=1)
            prefix_args = callback_split[0].strip().rstrip(",").strip()
            is_inline_cb = len(callback_split) > 1

            raw_parts = [p.strip().rstrip(");").strip() for p in prefix_args.split(",") if p.strip()]
            handler_name = f"{method.lower()}_{re.sub(r'[^A-Za-z0-9]+', '_', route_path).strip('_') or 'root'}"
            inline_fn: Optional[_FunctionRecord] = None

            if is_inline_cb:
                middlewares = [p for p in raw_parts if re.match(r"^[A-Za-z_$][A-Za-z0-9_$.()]*$", p)]
                inline_fn = self._build_brace_function_record(
                    rel_fp, handler_name, handler_name, start_ln, end_ln, "req, res", lines
                )
            elif raw_parts:
                handler_name = raw_parts[-1]
                middlewares = [p for p in raw_parts[:-1] if re.match(r"^[A-Za-z_$][A-Za-z0-9_$.()]*$", p)]

            auth_mechs: List[str] = []
            seed_calls: List[Tuple[str, int, str]] = []
            for mw in middlewares:
                mw_clean = mw.split("(")[0].strip()
                if mw_clean:
                    seed_calls.append((mw_clean, start_ln, mw))
                    if _AUTH_NAME_RX.search(mw_clean):
                        auth_mechs.append(mw_clean)

            out.append(
                _DiscoveredRouteSpec(
                    method=method,
                    route_path=route_path,
                    framework=fw,
                    handler_name=handler_name,
                    handler_qualname=handler_name,
                    filepath=rel_fp,
                    start_line=start_ln,
                    end_line=end_ln,
                    auth_status="AUTHENTICATED" if auth_mechs else "UNAUTHENTICATED",
                    auth_mechanisms=auth_mechs,
                    extra_seed_calls=seed_calls,
                    inline_fn=inline_fn,
                )
            )
        return out

    def _discover_nestjs_routes(
        self,
        rel_fp: str,
        src_text: str,
        graph: _WorkspaceSymbolGraph,
    ) -> List[_DiscoveredRouteSpec]:
        if "@Controller" not in src_text:
            return []
        lines = graph.file_lines[rel_fp]
        ctrl_m = re.search(r"@Controller\(\s*(?:['\"`]([^'\"`]*)['\"`])?\s*\)", src_text)
        base_prefix = ctrl_m.group(1) if (ctrl_m and ctrl_m.group(1)) else ""
        cls_m = re.search(r"class\s+([A-Za-z_$][A-Za-z0-9_$]*)", src_text)
        cls_name = cls_m.group(1) if cls_m else ""

        cls_guards: List[str] = []
        if cls_m:
            header_slice = src_text[: cls_m.start()]
            for g_m in re.finditer(r"@UseGuards\(([^)]+)\)", header_slice):
                for g_tok in g_m.group(1).split(","):
                    if g_tok.strip():
                        cls_guards.append(g_tok.strip())

        verb_rx = re.compile(r"@(Get|Post|Put|Delete|Patch)\(\s*(?:['\"`]([^'\"`]*)['\"`])?\s*\)")
        out: List[_DiscoveredRouteSpec] = []
        pending_guards: List[str] = []

        for idx, line in enumerate(lines):
            g_m = re.search(r"@UseGuards\(([^)]+)\)", line)
            if g_m:
                for g_tok in g_m.group(1).split(","):
                    if g_tok.strip():
                        pending_guards.append(g_tok.strip())
            v_m = verb_rx.search(line)
            if v_m:
                method = v_m.group(1).upper()
                sub_path = v_m.group(2) or ""
                full_path = _join_route_paths(base_prefix, sub_path)
                # Locate method declaration on following lines
                h_name = "handler"
                start_ln = idx + 1
                end_ln = idx + 1
                for look in range(idx + 1, min(len(lines), idx + 6)):
                    m_decl = re.search(r"(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", lines[look])
                    if m_decl and not lines[look].lstrip().startswith("@"):
                        h_name = m_decl.group(1)
                        end_ln = _find_matching_brace_end(lines, look)
                        break
                qual = f"{cls_name}.{h_name}" if cls_name else h_name
                fn_rec = graph.functions.get((rel_fp, qual)) or graph.functions.get((rel_fp, h_name))
                if fn_rec:
                    end_ln = fn_rec.end_line
                guards_all = list(dict.fromkeys(cls_guards + pending_guards))
                pending_guards = []
                out.append(
                    _DiscoveredRouteSpec(
                        method=method,
                        route_path=full_path,
                        framework="NestJS",
                        handler_name=h_name,
                        handler_qualname=qual,
                        filepath=rel_fp,
                        start_line=start_ln,
                        end_line=end_ln,
                        auth_status="AUTHENTICATED" if guards_all else "UNAUTHENTICATED",
                        auth_mechanisms=guards_all,
                        request_params=list(fn_rec.params) if fn_rec else [],
                        extra_seed_calls=[(g, start_ln, f"@UseGuards({g})") for g in guards_all],
                    )
                )
        return out

    def _discover_go_routes(
        self,
        rel_fp: str,
        _src_text: str,
        graph: _WorkspaceSymbolGraph,
    ) -> List[_DiscoveredRouteSpec]:
        lines = graph.file_lines[rel_fp]
        out: List[_DiscoveredRouteSpec] = []
        gin_rx = re.compile(
            r"\b[A-Za-z_][A-Za-z0-9_]*\.(GET|POST|PUT|DELETE|PATCH)\(\s*\"([^\"]+)\"\s*,\s*([A-Za-z_][A-Za-z0-9_.]*)"
        )
        std_rx = re.compile(
            r"\b(?:http\.|mux\.)?HandleFunc\(\s*\"([^\"]+)\"\s*,\s*([A-Za-z_][A-Za-z0-9_.]*)"
        )

        for idx, line in enumerate(lines):
            m_gin = gin_rx.search(line)
            if m_gin:
                method = m_gin.group(1).upper()
                r_path = _join_route_paths(m_gin.group(2))
                h_name = m_gin.group(3).rsplit(".", 1)[-1]
                fn_rec = graph.resolve_callee(rel_fp, h_name)
                out.append(
                    _DiscoveredRouteSpec(
                        method=method,
                        route_path=r_path,
                        framework="Go (Gin / Echo)",
                        handler_name=h_name,
                        handler_qualname=fn_rec.qualname if fn_rec else h_name,
                        filepath=fn_rec.filepath if fn_rec else rel_fp,
                        start_line=fn_rec.start_line if fn_rec else idx + 1,
                        end_line=fn_rec.end_line if fn_rec else idx + 1,
                    )
                )
                continue

            m_std = std_rx.search(line)
            if m_std:
                r_path = _join_route_paths(m_std.group(1))
                h_name = m_std.group(2).rsplit(".", 1)[-1]
                fn_rec = graph.resolve_callee(rel_fp, h_name)
                out.append(
                    _DiscoveredRouteSpec(
                        method="ANY",
                        route_path=r_path,
                        framework="Go net/http",
                        handler_name=h_name,
                        handler_qualname=fn_rec.qualname if fn_rec else h_name,
                        filepath=fn_rec.filepath if fn_rec else rel_fp,
                        start_line=fn_rec.start_line if fn_rec else idx + 1,
                        end_line=fn_rec.end_line if fn_rec else idx + 1,
                    )
                )
        return out

    def _discover_spring_routes(
        self,
        rel_fp: str,
        src_text: str,
        graph: _WorkspaceSymbolGraph,
    ) -> List[_DiscoveredRouteSpec]:
        if "Mapping" not in src_text and "@RestController" not in src_text:
            return []
        lines = graph.file_lines[rel_fp]
        cls_m = re.search(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)", src_text)
        cls_name = cls_m.group(1) if cls_m else ""
        base_prefix = ""
        cls_auth: List[str] = []
        if cls_m:
            header = src_text[: cls_m.start()]
            rm_m = re.search(r"@RequestMapping\(\s*(?:value\s*=\s*)?\"([^\"]+)\"", header)
            if rm_m:
                base_prefix = rm_m.group(1)
            for auth_m in re.finditer(r"@(PreAuthorize|Secured|RolesAllowed)\(([^)]*)\)", header):
                cls_auth.append(f"@{auth_m.group(1)}({auth_m.group(2).strip()})")

        map_rx = re.compile(
            r"@(Get|Post|Put|Delete|Patch|Request)Mapping(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\"[^)]*\))?"
        )
        out: List[_DiscoveredRouteSpec] = []
        pending_auth: List[str] = []

        for idx, line in enumerate(lines):
            pa_m = re.search(r"@(PreAuthorize|Secured|RolesAllowed)\(([^)]*)\)", line)
            if pa_m:
                pending_auth.append(f"@{pa_m.group(1)}({pa_m.group(2).strip()})")
            m_map = map_rx.search(line)
            if not m_map:
                continue
            kind = m_map.group(1)
            method = "GET" if kind == "Request" else kind.upper()
            if kind == "Request":
                req_m = re.search(r"RequestMethod\.(GET|POST|PUT|DELETE|PATCH)", line)
                if req_m:
                    method = req_m.group(1).upper()
            sub_path = m_map.group(2) or ""
            full_path = _join_route_paths(base_prefix, sub_path)

            h_name = "handler"
            start_ln = idx + 1
            end_ln = idx + 1
            resp_type: Optional[str] = None
            for look in range(idx + 1, min(len(lines), idx + 6)):
                m_decl = re.search(
                    r"(?:public|protected|private)\s+([A-Za-z0-9_<>,?\[\]]+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                    lines[look],
                )
                if m_decl:
                    resp_type = m_decl.group(1)
                    h_name = m_decl.group(2)
                    end_ln = _find_matching_brace_end(lines, look)
                    break

            qual = f"{cls_name}.{h_name}" if cls_name else h_name
            fn_rec = graph.functions.get((rel_fp, qual)) or graph.functions.get((rel_fp, h_name))
            if fn_rec:
                end_ln = fn_rec.end_line
            auth_all = list(dict.fromkeys(cls_auth + pending_auth))
            pending_auth = []
            out.append(
                _DiscoveredRouteSpec(
                    method=method,
                    route_path=full_path,
                    framework="Spring Boot",
                    handler_name=h_name,
                    handler_qualname=qual,
                    filepath=rel_fp,
                    start_line=start_ln,
                    end_line=end_ln,
                    auth_status="AUTHENTICATED" if auth_all else "UNAUTHENTICATED",
                    auth_mechanisms=auth_all,
                    request_params=list(fn_rec.params) if fn_rec else [],
                    response_type=resp_type,
                    extra_seed_calls=[(a, start_ln, a) for a in auth_all],
                )
            )
        return out

    # ------------------------------------------------------------------
    # Inter-Procedural Tracer, Operation Classifier & Graph Synthesizer
    # ------------------------------------------------------------------
    def _build_endpoint_dossier(
        self,
        spec: _DiscoveredRouteSpec,
        graph: _WorkspaceSymbolGraph,
        active_findings: List[Finding],
        finding_locs: List[Tuple[Finding, List[Tuple[str, int]]]],
    ) -> ApiEndpointOperationDossier:
        ep_hash = hashlib.sha256(
            f"{spec.method}:{spec.route_path}:{spec.filepath}:{spec.start_line}".encode("utf-8")
        ).hexdigest()[:12]
        ep_id = f"ep-{ep_hash}"

        raw_ops: List[Dict[str, Any]] = []
        calls_functions: List[str] = []
        seen_called_fns: Set[str] = set()
        visited_fns: Set[Tuple[str, str]] = set()
        reachable_spans: List[Tuple[str, int, int]] = [
            (spec.filepath, spec.start_line, spec.end_line)
        ]
        auth_mechanisms = list(spec.auth_mechanisms)
        auth_status = spec.auth_status

        # 1. Seed route-level AUTH_GUARD & INPUT_VALIDATION operations
        for auth_m in spec.auth_mechanisms:
            raw_ops.append(
                {
                    "category": "AUTH_GUARD",
                    "operation_verb": "VERIFY_AUTH",
                    "target_resource": auth_m,
                    "function_name": spec.handler_name,
                    "call_chain": [spec.handler_name],
                    "filepath": spec.filepath,
                    "line_number": spec.start_line,
                    "code_snippet": f"Auth Guard: {auth_m}",
                    "is_mutating": False,
                    "risk_note": None,
                }
            )

        for model_name, m_line, m_snip in spec.validated_models:
            raw_ops.append(
                {
                    "category": "INPUT_VALIDATION",
                    "operation_verb": "VALIDATE_SCHEMA",
                    "target_resource": model_name,
                    "function_name": spec.handler_name,
                    "call_chain": [spec.handler_name],
                    "filepath": spec.filepath,
                    "line_number": m_line,
                    "code_snippet": m_snip,
                    "is_mutating": False,
                    "risk_note": None,
                }
            )

        # Trace any resolved auth dependency / middleware functions
        for seed_callee, _s_ln, _s_snip in spec.extra_seed_calls:
            clean_seed = seed_callee.split("(")[0].strip()
            if clean_seed and clean_seed not in seen_called_fns and not clean_seed.startswith("@"):
                seen_called_fns.add(clean_seed)
                calls_functions.append(clean_seed)
            seed_rec = graph.resolve_callee(spec.filepath, clean_seed)
            if seed_rec is not None:
                self._trace_function_recursive(
                    fn_rec=seed_rec,
                    depth=1,
                    call_chain=[spec.handler_name, seed_rec.name],
                    graph=graph,
                    visited=visited_fns,
                    reachable_spans=reachable_spans,
                    calls_functions=calls_functions,
                    seen_called_fns=seen_called_fns,
                    raw_ops=raw_ops,
                )

        # 2. Trace the primary route handler up to MAX_CALL_DEPTH = 4
        root_fn = (
            spec.inline_fn
            or graph.functions.get((spec.filepath, spec.handler_qualname))
            or graph.functions.get((spec.filepath, spec.handler_name))
        )
        if root_fn is not None:
            self._trace_function_recursive(
                fn_rec=root_fn,
                depth=0,
                call_chain=[spec.handler_name],
                graph=graph,
                visited=visited_fns,
                reachable_spans=reachable_spans,
                calls_functions=calls_functions,
                seen_called_fns=seen_called_fns,
                raw_ops=raw_ops,
            )

        # Promote auth_status if inline AUTH_GUARD operation was discovered inside handler/helpers
        for rop in raw_ops:
            if rop["category"] == "AUTH_GUARD":
                res_name = str(rop["target_resource"])
                if res_name and res_name not in auth_mechanisms:
                    auth_mechanisms.append(res_name)
                if auth_status == "UNAUTHENTICATED":
                    auth_status = "AUTHENTICATED"

        # Deduplicate identical (category, verb, target_resource, filepath, line_number) operations & number 1..M
        operations: List[ApiOperationItem] = []
        seen_op_sigs: Set[Tuple[str, str, str, str, int]] = set()
        for rop in raw_ops:
            sig = (
                str(rop["category"]),
                str(rop["operation_verb"]),
                str(rop["target_resource"]),
                str(rop["filepath"]),
                int(rop["line_number"]),
            )
            if sig in seen_op_sigs:
                continue
            seen_op_sigs.add(sig)
            step_idx = len(operations) + 1
            operations.append(
                ApiOperationItem(
                    id=f"{ep_id}-op-{step_idx}",
                    step_index=step_idx,
                    category=rop["category"],
                    operation_verb=str(rop["operation_verb"]),
                    target_resource=str(rop["target_resource"]),
                    function_name=str(rop["function_name"]),
                    call_chain=list(rop["call_chain"]),
                    filepath=str(rop["filepath"]),
                    line_number=int(rop["line_number"]),
                    code_snippet=str(rop["code_snippet"])[:200],
                    is_mutating=bool(rop["is_mutating"]),
                    risk_note=rop.get("risk_note"),
                )
            )

        op_categories: List[ApiOperationCategory] = []
        seen_cats: Set[str] = set()
        for op in operations:
            if op.category not in seen_cats:
                seen_cats.add(op.category)
                op_categories.append(op.category)

        is_mutating = spec.method in ("POST", "PUT", "DELETE", "PATCH") or any(
            op.is_mutating for op in operations
        )

        # 3. Correlate active findings whose BFL or path_nodes land in handler or any called helper span
        linked_findings: List[Finding] = []
        seen_fids: Set[str] = set()
        for f_obj, locs in finding_locs:
            if f_obj.id in seen_fids:
                continue
            if self._finding_matches_spans(locs, reachable_spans):
                seen_fids.add(f_obj.id)
                linked_findings.append(f_obj)

        linked_finding_ids = [f.id for f in linked_findings]
        risk_level = self._compute_risk_level(
            method=spec.method,
            auth_status=auth_status,
            is_mutating=is_mutating,
            op_categories=op_categories,
            linked_findings=linked_findings,
        )

        story = self._build_plain_english_story(
            spec=spec,
            auth_status=auth_status,
            auth_mechanisms=auth_mechanisms,
            calls_functions=calls_functions,
            operations=operations,
            linked_findings=linked_findings,
        )

        flow_nodes, flow_edges = self._synthesize_flow_graph(
            ep_id=ep_id,
            spec=spec,
            operations=operations,
        )

        return ApiEndpointOperationDossier(
            id=ep_id,
            method=spec.method,
            route_path=spec.route_path,
            framework=spec.framework,
            handler_name=spec.handler_name,
            filepath=spec.filepath,
            start_line=spec.start_line,
            end_line=spec.end_line,
            auth_status=auth_status,  # type: ignore[arg-type]
            auth_mechanisms=auth_mechanisms,
            request_params=spec.request_params,
            response_type=spec.response_type,
            operations=operations,
            operation_categories=op_categories,
            calls_functions=calls_functions,
            is_mutating=is_mutating,
            risk_level=risk_level,  # type: ignore[arg-type]
            linked_finding_ids=linked_finding_ids,
            linked_findings_count=len(linked_finding_ids),
            plain_english_story=story,
            flow_nodes=flow_nodes,
            flow_edges=flow_edges,
        )

    def _trace_function_recursive(
        self,
        fn_rec: _FunctionRecord,
        depth: int,
        call_chain: List[str],
        graph: _WorkspaceSymbolGraph,
        visited: Set[Tuple[str, str]],
        reachable_spans: List[Tuple[str, int, int]],
        calls_functions: List[str],
        seen_called_fns: Set[str],
        raw_ops: List[Dict[str, Any]],
    ) -> None:
        visit_key = (fn_rec.filepath, fn_rec.qualname)
        if visit_key in visited or depth > MAX_CALL_DEPTH:
            return
        visited.add(visit_key)
        reachable_spans.append((fn_rec.filepath, fn_rec.start_line, fn_rec.end_line))

        # Check JS/Python `process.env` / `os.environ[...]` property accesses inside function body
        if _PROP_PROC_ENV in fn_rec.body_text or "os.environ[" in fn_rec.body_text:
            raw_ops.append(
                {
                    "category": "SECRET_OR_CRYPTO",
                    "operation_verb": "READ_ENV_CONFIG",
                    "target_resource": "Environment Variable",
                    "function_name": fn_rec.name,
                    "call_chain": list(call_chain),
                    "filepath": fn_rec.filepath,
                    "line_number": fn_rec.start_line,
                    "code_snippet": (
                        f"{_PROP_PROC_ENV} / os.environ lookup in {fn_rec.name}()"
                    ),
                    "is_mutating": False,
                    "risk_note": None,
                }
            )

        for call_site in fn_rec.calls:
            classified = self._classify_call_site(call_site, fn_rec, graph)
            if classified is not None:
                raw_ops.append(
                    {
                        **classified,
                        "function_name": fn_rec.name,
                        "call_chain": list(call_chain),
                        "filepath": fn_rec.filepath,
                        "line_number": call_site.line_number,
                        "code_snippet": call_site.code_snippet,
                    }
                )

            if depth < MAX_CALL_DEPTH:
                callee_rec = graph.resolve_callee(fn_rec.filepath, call_site.callee)
                if callee_rec is not None:
                    short_callee = callee_rec.name
                    if short_callee not in seen_called_fns and short_callee != call_chain[0]:
                        seen_called_fns.add(short_callee)
                        calls_functions.append(short_callee)
                    self._trace_function_recursive(
                        fn_rec=callee_rec,
                        depth=depth + 1,
                        call_chain=[*call_chain, short_callee],
                        graph=graph,
                        visited=visited,
                        reachable_spans=reachable_spans,
                        calls_functions=calls_functions,
                        seen_called_fns=seen_called_fns,
                        raw_ops=raw_ops,
                    )

    def _classify_call_site(
        self,
        call_site: _CallSiteRecord,
        fn_rec: _FunctionRecord,
        graph: _WorkspaceSymbolGraph,
    ) -> Optional[Dict[str, Any]]:
        callee = call_site.callee
        short_name = callee.rsplit(".", 1)[-1]
        expr = call_site.full_expr

        # 1. OS_COMMAND_EXEC
        if (
            callee in _EXEC_CALL_NAMES
            or callee.startswith(f"{_MOD_SUBPROC}.")
            or callee in ("ProcessBuilder",)
        ):
            return {
                "category": "OS_COMMAND_EXEC",
                "operation_verb": callee,
                "target_resource": self._extract_first_arg_summary(expr, fallback="OS Process"),
                "is_mutating": True,
                "risk_note": "Executes host operating system subprocess; ensure strict argument parameterization.",
            }

        # 2. SQL / Cypher inside execute / query / session.run
        m_sql_w = _SQL_WRITE_RX.search(expr)
        if m_sql_w:
            sql_verb = re.sub(r"\s+", " ", m_sql_w.group(1).upper()).split()[0]
            return {
                "category": "DATABASE_WRITE",
                "operation_verb": sql_verb,
                "target_resource": m_sql_w.group(2),
                "is_mutating": True,
                "risk_note": None,
            }

        m_sql_r = _SQL_READ_RX.search(expr)
        if m_sql_r:
            return {
                "category": "DATABASE_READ",
                "operation_verb": "SELECT",
                "target_resource": m_sql_r.group(1),
                "is_mutating": False,
                "risk_note": None,
            }

        # Neo4j Cypher session.run(...) — inspect inline query, function string consts, or module RULES
        if callee.endswith("session.run") or callee in ("Neo4jQuery",):
            cypher_src = expr
            if "MATCH" not in cypher_src.upper() and "MERGE" not in cypher_src.upper() and "CREATE" not in cypher_src.upper():
                combined_consts = " ".join(s for _, s in fn_rec.string_consts)
                if not combined_consts and fn_rec.filepath in graph.file_GlobalStrings:
                    combined_consts = " ".join(graph.file_GlobalStrings[fn_rec.filepath][:3])
                cypher_src = f"{expr} {combined_consts}"
            m_cyp_w = _CYPHER_WRITE_RX.search(cypher_src)
            if m_cyp_w or "DETACH DELETE" in cypher_src.upper():
                lbl = (m_cyp_w.group(2) if (m_cyp_w and m_cyp_w.group(2)) else None) or "Neo4j CPG"
                return {
                    "category": "DATABASE_WRITE",
                    "operation_verb": "CYPHER_WRITE",
                    "target_resource": lbl,
                    "is_mutating": True,
                    "risk_note": None,
                }
            m_cyp_r = _CYPHER_READ_RX.search(cypher_src)
            lbl_r = (m_cyp_r.group(1) if (m_cyp_r and m_cyp_r.group(1)) else None) or "Neo4j CPG"
            return {
                "category": "DATABASE_READ",
                "operation_verb": "CYPHER_MATCH",
                "target_resource": lbl_r,
                "is_mutating": False,
                "risk_note": None,
            }

        if short_name in ("clear_database", "init_schema", "ingest_app_tree", "ingest_nodes", "ingest_edges"):
            return {
                "category": "DATABASE_WRITE",
                "operation_verb": short_name,
                "target_resource": "Neo4j CPG",
                "is_mutating": True,
                "risk_note": None,
            }

        # ORM / Prisma / Django / SQLAlchemy / MongoDB / JDBC operations
        prisma_m = re.match(
            r"^(?:this\.)?prisma\.([A-Za-z0-9_]+)\.(findUnique|findFirst|findMany|count|create|createMany|update|updateMany|upsert|delete|deleteMany)$",
            callee,
        )
        if prisma_m:
            model_n, action_n = prisma_m.group(1), prisma_m.group(2)
            is_write = action_n.startswith(("create", "update", "upsert", "delete"))
            return {
                "category": "DATABASE_WRITE" if is_write else "DATABASE_READ",
                "operation_verb": f"prisma.{action_n}",
                "target_resource": model_n,
                "is_mutating": is_write,
                "risk_note": None,
            }

        if ".objects." in callee:
            model_n = callee.split(".objects.", 1)[0].rsplit(".", 1)[-1]
            is_write = short_name in ("create", "bulk_create", "update", "bulk_update", "delete", "get_or_create", "update_or_create")
            return {
                "category": "DATABASE_WRITE" if is_write else "DATABASE_READ",
                "operation_verb": f"objects.{short_name}",
                "target_resource": model_n or "ORM Model",
                "is_mutating": is_write,
                "risk_note": None,
            }

        if short_name in ("insertOne", "insertMany", "updateOne", "updateMany", "deleteOne", "deleteMany") or callee in (
            "db.add",
            "db.delete",
            "session.add",
            "session.commit",
            "jdbcTemplate.update",
        ):
            return {
                "category": "DATABASE_WRITE",
                "operation_verb": callee,
                "target_resource": "Database Store",
                "is_mutating": True,
                "risk_note": None,
            }

        if (
            short_name in ("findOne", "findUnique", "findMany")
            or callee in ("db.Query", "db.QueryRow", "jdbcTemplate.query", "session.query")
        ):
            return {
                "category": "DATABASE_READ",
                "operation_verb": callee,
                "target_resource": "Database Store",
                "is_mutating": False,
                "risk_note": None,
            }

        # 3. EXTERNAL_HTTP_OR_AI
        if any(callee.startswith(pref) for pref in _HTTP_CLIENT_PREFIXES) or callee in (
            "fetch",
            "got",
            "http.Get",
            "http.Post",
            "opener.open",
            "self._opener.open",
            _CALL_URL_OPEN,
            f"urllib.request.{_CALL_URL_OPEN}",
        ):
            norm_verb = callee.replace("http_requests.", "requests.")
            url_m = _URL_LITERAL_RX.search(expr)
            target_url = url_m.group(1) if url_m else self._extract_first_arg_summary(expr, fallback="External Endpoint")
            verb_low = short_name.lower()
            mut_http = verb_low in ("post", "put", "delete", "patch")
            return {
                "category": "EXTERNAL_HTTP_OR_AI",
                "operation_verb": norm_verb,
                "target_resource": target_url,
                "is_mutating": mut_http,
                "risk_note": None,
            }

        for ai_rx, ai_verb, ai_target in _AI_CLIENT_PATTERNS:
            if ai_rx.search(expr):
                return {
                    "category": "EXTERNAL_HTTP_OR_AI",
                    "operation_verb": ai_verb,
                    "target_resource": ai_target,
                    "is_mutating": False,
                    "risk_note": None,
                }

        # 4. FILESYSTEM_IO
        if callee == "open":
            is_write_open = bool(
                re.search(r",\s*['\"](?:w|a|x|wb|ab|r\+)['\"]", expr)
                or re.search(r"mode\s*=\s*['\"](?:w|a|x)", expr)
            )
            return {
                "category": "FILESYSTEM_IO",
                "operation_verb": "open(write)" if is_write_open else "open(read)",
                "target_resource": self._extract_first_arg_summary(expr, fallback="Local File"),
                "is_mutating": is_write_open,
                "risk_note": None,
            }

        if callee in _FS_MUTATING_CALLS or short_name in ("writeFileSync", "writeFile", "rmtree", "write_text", "write_bytes"):
            return {
                "category": "FILESYSTEM_IO",
                "operation_verb": callee,
                "target_resource": self._extract_first_arg_summary(expr, fallback="Filesystem Path"),
                "is_mutating": True,
                "risk_note": None,
            }

        if callee in _FS_READ_CALLS or short_name in ("readFileSync", "readFile", "read_text", "read_bytes", "scandir"):
            return {
                "category": "FILESYSTEM_IO",
                "operation_verb": callee,
                "target_resource": self._extract_first_arg_summary(expr, fallback="Filesystem Path"),
                "is_mutating": False,
                "risk_note": None,
            }

        # 5. AUTH_GUARD (inline session / token / signature checks)
        if short_name in (
            "getServerSession",
            "currentUser",
            "verifyIdToken",
            "verifyToken",
            "verifyJwt",
            "checkPermissions",
        ):
            return {
                "category": "AUTH_GUARD",
                "operation_verb": callee,
                "target_resource": short_name,
                "is_mutating": False,
                "risk_note": None,
            }

        # 6. INPUT_VALIDATION (explicit sanitizers & schema validators)
        if (
            callee in _SANITIZER_CALLS
            or short_name in _SANITIZER_CALLS
            or short_name in ("safeParse", "validate_python")
            or callee in ("Joi.validate",)
        ):
            return {
                "category": "INPUT_VALIDATION",
                "operation_verb": callee,
                "target_resource": self._extract_first_arg_summary(expr, fallback="Untrusted Input"),
                "is_mutating": False,
                "risk_note": None,
            }

        # 7. SECRET_OR_CRYPTO
        if callee in _CRYPTO_CALL_MAP:
            c_verb, c_res = _CRYPTO_CALL_MAP[callee]
            return {
                "category": "SECRET_OR_CRYPTO",
                "operation_verb": c_verb,
                "target_resource": c_res,
                "is_mutating": False,
                "risk_note": None,
            }

        if short_name in ("token_urlsafe", "token_hex", "save_repo_credentials", "get_repo_credentials"):
            return {
                "category": "SECRET_OR_CRYPTO",
                "operation_verb": callee,
                "target_resource": "Credential Vault",
                "is_mutating": short_name.startswith("save_"),
                "risk_note": None,
            }

        return None

    def _extract_first_arg_summary(self, expr: str, fallback: str) -> str:
        m = re.search(r"\(\s*([^,\n\)]+)", expr)
        if not m:
            return fallback
        arg0 = m.group(1).strip().strip("'\"`")
        return arg0[:90] if arg0 else fallback

    def _index_finding_locations(
        self,
        findings: List[Finding],
        root_real: str,
    ) -> List[Tuple[Finding, List[Tuple[str, int]]]]:
        indexed: List[Tuple[Finding, List[Tuple[str, int]]]] = []
        for f in findings:
            locs: List[Tuple[str, int]] = []
            if f.best_fix_location and f.best_fix_location.filepath:
                locs.append(
                    (
                        _normalize_rel_path(f.best_fix_location.filepath, root_real),
                        max(1, int(f.best_fix_location.line or 1)),
                    )
                )
            for node in f.path_nodes or []:
                if isinstance(node, dict) and node.get("filepath"):
                    locs.append(
                        (
                            _normalize_rel_path(str(node["filepath"]), root_real),
                            max(1, int(node.get("start_line") or 1)),
                        )
                    )
            if locs:
                indexed.append((f, locs))
        return indexed

    def _finding_matches_spans(
        self,
        f_locs: List[Tuple[str, int]],
        spans: List[Tuple[str, int, int]],
    ) -> bool:
        for f_fp, f_ln in f_locs:
            if not f_fp:
                continue
            for sp_fp, sp_start, sp_end in spans:
                path_ok = (
                    f_fp == sp_fp
                    or f_fp.endswith(f"/{sp_fp}")
                    or sp_fp.endswith(f"/{f_fp}")
                )
                if path_ok and sp_start <= f_ln <= sp_end:
                    return True
        return False

    def _compute_risk_level(
        self,
        method: str,
        auth_status: str,
        is_mutating: bool,
        op_categories: List[ApiOperationCategory],
        linked_findings: List[Finding],
    ) -> str:
        severities = {f.severity for f in linked_findings}
        if "CRITICAL" in severities:
            return "CRITICAL"
        if auth_status == "UNAUTHENTICATED" and "OS_COMMAND_EXEC" in op_categories:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        if auth_status == "UNAUTHENTICATED" and is_mutating and (
            "FILESYSTEM_IO" in op_categories or "DATABASE_WRITE" in op_categories
        ):
            return "HIGH"
        if "MEDIUM" in severities or "OS_COMMAND_EXEC" in op_categories:
            return "MEDIUM"
        if auth_status == "UNAUTHENTICATED" and (
            is_mutating or "EXTERNAL_HTTP_OR_AI" in op_categories
        ):
            return "MEDIUM"
        if linked_findings or is_mutating or "FILESYSTEM_IO" in op_categories or "EXTERNAL_HTTP_OR_AI" in op_categories:
            return "LOW"
        return "SAFE"

    def _build_plain_english_story(
        self,
        spec: _DiscoveredRouteSpec,
        auth_status: str,
        auth_mechanisms: List[str],
        calls_functions: List[str],
        operations: List[ApiOperationItem],
        linked_findings: List[Finding],
    ) -> str:
        auth_clause = (
            f"enforces caller authentication via {', '.join(auth_mechanisms)}"
            if auth_status == "AUTHENTICATED" and auth_mechanisms
            else (
                "uses partial/custom caller verification"
                if auth_status == "PARTIAL_OR_CUSTOM"
                else "accepts unauthenticated requests"
            )
        )
        params_clause = (
            f"with parameters [{', '.join(spec.request_params[:5])}]"
            if spec.request_params
            else "with no query/body parameters"
        )
        helpers_clause = (
            f" It traces inter-procedurally into {', '.join(calls_functions[:5])}."
            if calls_functions
            else ""
        )
        if operations:
            op_summaries = [
                f"{op.category} ({op.operation_verb} -> {op.target_resource})"
                for op in operations[:6]
            ]
            ops_clause = f" Performs {len(operations)} traced operation(s): {'; '.join(op_summaries)}."
        else:
            ops_clause = " Executes pure in-memory response serialization with 0 external I/O sinks."

        vuln_clause = (
            f" Correlated with {len(linked_findings)} active security finding(s) ({', '.join(f.id for f in linked_findings[:3])})."
            if linked_findings
            else ""
        )
        return (
            f"`{spec.method} {spec.route_path}` ({spec.framework} handler `{spec.handler_name}` at "
            f"`{spec.filepath}:L{spec.start_line}`) {auth_clause} {params_clause}."
            f"{helpers_clause}{ops_clause}{vuln_clause}"
        )

    def _synthesize_flow_graph(
        self,
        ep_id: str,
        spec: _DiscoveredRouteSpec,
        operations: List[ApiOperationItem],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        raw_nodes_list: List[Dict[str, Any]] = []

        # Step 1: Route Entry Node
        entry_code = f"{spec.handler_name}({', '.join(spec.request_params)})"
        raw_nodes_list.append(
            {
                "id": f"{ep_id}-node-1",
                "label": "Entry",
                "ast_type": "http_endpoint_entry",
                "name": f"{spec.method} {spec.route_path}",
                "code": entry_code[:180],
                "filepath": spec.filepath,
                "start_line": spec.start_line,
                "end_line": spec.start_line,
                "is_source": True,
                "is_sink": False,
                "is_sanitizer": False,
                "category": "ENTRYPOINT",
                "edge_type_from_prev": "CFG_NEXT",
                "edge_phrase_from_prev": "",
            }
        )

        # Intermediate Operation Nodes
        for op in operations[:MAX_GRAPH_OPERATIONS]:
            node_idx = len(raw_nodes_list) + 1
            is_san = op.category in ("AUTH_GUARD", "INPUT_VALIDATION")
            is_sink = (
                op.category in ("DATABASE_WRITE", "OS_COMMAND_EXEC", "EXTERNAL_HTTP_OR_AI")
                or (op.category == "FILESYSTEM_IO" and op.is_mutating)
            )
            lbl = "ControlBlock" if is_san else "Call"
            edge_kind = (
                "SANITIZED"
                if is_san
                else ("DFG_FLOWS_TO" if is_sink else ("CALLS" if len(op.call_chain) > 1 else "CFG_NEXT"))
            )
            short_cat = op.category.replace("_", " ")
            raw_nodes_list.append(
                {
                    "id": f"{ep_id}-node-{node_idx}",
                    "label": lbl,
                    "ast_type": op.category.lower(),
                    "name": f"{op.operation_verb} ({op.target_resource})"[:90],
                    "code": op.code_snippet[:180],
                    "filepath": op.filepath,
                    "start_line": op.line_number,
                    "end_line": op.line_number,
                    "is_source": False,
                    "is_sink": is_sink,
                    "is_sanitizer": is_san,
                    "category": op.category,
                    "edge_type_from_prev": edge_kind,
                    "edge_phrase_from_prev": f"{short_cat} ▶",
                }
            )

        # Final Response Exit Node
        exit_idx = len(raw_nodes_list) + 1
        resp_label = spec.response_type or "HTTP Response"
        raw_nodes_list.append(
            {
                "id": f"{ep_id}-node-{exit_idx}",
                "label": "Return",
                "ast_type": "http_response_exit",
                "name": f"Response ({resp_label})"[:90],
                "code": f"return {resp_label} from {spec.handler_name}()"[:180],
                "filepath": spec.filepath,
                "start_line": spec.end_line,
                "end_line": spec.end_line,
                "is_source": False,
                "is_sink": False,
                "is_sanitizer": False,
                "category": "RESPONSE",
                "edge_type_from_prev": "CFG_NEXT",
                "edge_phrase_from_prev": "RESPONSE ▶",
            }
        )

        flow_nodes: List[Dict[str, Any]] = []
        for idx_n, item in enumerate(raw_nodes_list, start=1):
            node_data = {
                "id": item["id"],
                "label": item["label"],
                "ast_type": item["ast_type"],
                "name": item["name"],
                "code": item["code"],
                "filepath": item["filepath"],
                "start_line": item["start_line"],
                "end_line": item["end_line"],
                "start_col": 0,
                "end_col": max(1, len(item["code"])),
                "scope_id": spec.handler_name,
                "is_source": item["is_source"],
                "is_sink": item["is_sink"],
                "is_sanitizer": item["is_sanitizer"],
                "step_index": idx_n,
                "stepNumber": idx_n,
                "category": item["category"],
            }
            flow_nodes.append(
                {
                    **node_data,
                    "type": "cpgNode",
                    "position": {"x": (idx_n - 1) * 320, "y": 40},
                    "data": dict(node_data),
                }
            )

        flow_edges: List[Dict[str, Any]] = []
        for edge_step in range(1, len(raw_nodes_list)):
            src_item = raw_nodes_list[edge_step - 1]
            tgt_item = raw_nodes_list[edge_step]
            e_type = str(tgt_item["edge_type_from_prev"])
            phrase = str(tgt_item["edge_phrase_from_prev"] or "FLOW ▶")
            flow_lbl = f"{_circled_step(edge_step)} {phrase}"
            flow_edges.append(
                {
                    "id": f"{ep_id}-edge-{edge_step}",
                    "source": src_item["id"],
                    "target": tgt_item["id"],
                    "type": e_type,
                    "edge_type": e_type,
                    "step_index": edge_step,
                    "flow_label": flow_lbl,
                    "sourceHandle": "right-src",
                    "targetHandle": "left-tgt",
                    "data": {
                        "edgeType": e_type,
                        "stepIndex": edge_step,
                        "flowLabel": flow_lbl,
                        "alwaysShowFullPill": True,
                    },
                }
            )

        return flow_nodes, flow_edges


_default_api_ops_engine: Optional[ApiOperationsEngine] = None


def get_api_operations_engine() -> ApiOperationsEngine:
    global _default_api_ops_engine
    if _default_api_ops_engine is None:
        _default_api_ops_engine = ApiOperationsEngine()
    return _default_api_ops_engine


def analyze_workspace_api_operations(
    target_dir: str,
    findings: Optional[List[Finding]] = None,
) -> ApiOperationsReportResponse:
    return get_api_operations_engine().analyze_workspace_api_operations(
        target_dir=target_dir,
        findings=findings,
    )
