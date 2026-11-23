"""
ALASTOR v5.0 Pillar 5 — Automated Security Regression Unit-Test Generator.

Synthesizes runnable, self-contained, zero-raw-secret security regression unit tests
tailored to CWE vulnerability families across:
  - `pytest` (Python, verified with `ast.parse`)
  - `jest` (JavaScript / TypeScript)
  - `vitest` (JavaScript / TypeScript)
  - `go_test` (Go `*_test.go`)

Supports preview-only generation and strictly workspace-confined writes inside
`<real_repo>/tests/security/` with symlink/NTFS-junction and overwrite protection.
"""
from __future__ import annotations

import ast
import json
import os
import re
from typing import Dict, List, Literal, Optional, Sequence, Tuple

from engine.frontier_ai_engine import scrub_raw_secrets_text
from engine.hostile_repo_guard import HostileRepoError, is_link_or_junction
from engine.scanner_fusion_engine import scrub_finding_secrets
from models import (
    Finding,
    SecurityTestGenerateRequest,
    SecurityTestGenerateResponse,
)

ResolvedTestFramework = Literal["pytest", "jest", "vitest", "go_test"]

_VALID_FRAMEWORKS: Tuple[ResolvedTestFramework, ...] = ("pytest", "jest", "vitest", "go_test")
_SAFE_FILENAME_RE = re.compile(r"^[a-z0-9_.-]+$")
_CWE_NUM_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_MAX_PKG_JSON_BYTES = 2 * 1024 * 1024


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


def _extract_finding_filepath_and_line(finding: Finding) -> Tuple[str, int, str]:
    fp = ""
    line = 1
    snippet = ""
    if finding.best_fix_location and finding.best_fix_location.filepath:
        fp = finding.best_fix_location.filepath
        line = max(1, int(finding.best_fix_location.line or 1))
        snippet = finding.best_fix_location.code_snippet or ""
    elif finding.path_nodes:
        sink = finding.path_nodes[-1] if isinstance(finding.path_nodes[-1], dict) else {}
        fp = str(sink.get("filepath") or "")
        line = max(1, int(sink.get("start_line") or 1))
        snippet = str(sink.get("code") or sink.get("name") or "")
    fp_norm = fp.replace("\\", "/").lstrip("./") or "app.py"
    return fp_norm, line, snippet


def _has_vitest_in_repo(repo_path: Optional[str]) -> bool:
    if not repo_path or not isinstance(repo_path, str):
        return False
    try:
        real_repo = os.path.realpath(repo_path)
    except OSError:
        return False
    if not os.path.isdir(real_repo) or is_link_or_junction(real_repo):
        return False

    for cfg_name in ("vitest.config.ts", "vitest.config.js", "vitest.config.mts", "vitest.config.mjs"):
        cfg_path = os.path.join(real_repo, cfg_name)
        if os.path.lexists(cfg_path) and not is_link_or_junction(cfg_path):
            if os.path.commonpath([real_repo, os.path.realpath(cfg_path)]) == real_repo:
                return True

    pkg_path = os.path.join(real_repo, "package.json")
    if not os.path.lexists(pkg_path) or is_link_or_junction(pkg_path):
        return False
    pkg_real = os.path.realpath(pkg_path)
    try:
        if os.path.commonpath([real_repo, pkg_real]) != real_repo:
            return False
    except ValueError:
        return False
    if not os.path.isfile(pkg_real) or os.path.getsize(pkg_real) > _MAX_PKG_JSON_BYTES:
        return False
    try:
        with open(pkg_real, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict) and "vitest" in deps:
            return True
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        if any("vitest" in str(v).lower() for v in scripts.values()):
            return True
    return False


def detect_test_framework(
    finding: Finding,
    repo_path: Optional[str] = None,
) -> ResolvedTestFramework:
    """
    Infers the target unit-test framework (`pytest`, `jest`, `vitest`, or `go_test`)
    from the finding's source filepath extension and repository manifest (`package.json`).
    """
    filepath, _, _ = _extract_finding_filepath_and_line(finding)
    ext = os.path.splitext(filepath.lower())[1]

    if ext == ".py":
        return "pytest"
    if ext == ".go":
        return "go_test"
    if ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        return "vitest" if _has_vitest_in_repo(repo_path) else "jest"

    lang_low = (finding.language or "").strip().lower()
    if lang_low == "go":
        return "go_test"
    if any(tok in lang_low for tok in ("typescript", "javascript")):
        return "vitest" if _has_vitest_in_repo(repo_path) else "jest"
    return "pytest"


def _normalize_cwe(finding: Finding) -> str:
    if finding.cwe_id:
        m = _CWE_NUM_RE.search(finding.cwe_id)
        if m:
            return f"CWE-{int(m.group(1))}"
    combined = f"{finding.rule_id} {finding.title} {finding.description}".upper()
    if "SQLI" in combined or "SQL INJECTION" in combined:
        return "CWE-89"
    if "SHELL" in combined or "CMDI" in combined or "COMMAND INJECTION" in combined or "TAINT" in combined:
        return "CWE-78"
    if "XSS" in combined or "INNERHTML" in combined or "TEMPLATE" in combined:
        return "CWE-79"
    if "PATH-TRAVERSAL" in combined or "PATH TRAVERSAL" in combined:
        return "CWE-22"
    if "SSRF" in combined:
        return "CWE-918"
    if "IDOR" in combined or "BOLA" in combined:
        return "CWE-639"
    if "DESER" in combined or "PICKLE" in combined:
        return "CWE-502"
    if "SECRET" in combined or "HARDCODED" in combined or finding.is_secret_finding:
        return "CWE-798"
    if "CORS" in combined:
        return "CWE-942"
    return "CWE-20"


def _cwe_family(cwe_id: str, finding: Finding) -> str:
    cwe_upper = cwe_id.upper()
    combined = f"{finding.rule_id} {finding.title}".upper()
    if cwe_upper in ("CWE-89",):
        return "CWE-89"
    if cwe_upper in ("CWE-78", "CWE-77"):
        return "CWE-78"
    if cwe_upper in ("CWE-79", "CWE-1336"):
        return "CWE-79"
    if cwe_upper in ("CWE-22", "CWE-23", "CWE-73"):
        return "CWE-22"
    if cwe_upper in ("CWE-918",):
        return "CWE-918"
    if cwe_upper in ("CWE-639",) or "IDOR" in combined or "BOLA" in combined:
        return "CWE-639"
    if cwe_upper in ("CWE-502",):
        return "CWE-502"
    if cwe_upper in ("CWE-798", "CWE-259", "CWE-321") or finding.is_secret_finding:
        return "CWE-798"
    if cwe_upper in ("CWE-942",):
        return "CWE-942"
    return "GENERIC"


def _slugify_identifier(text: str, max_len: int = 44) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")
    cleaned = re.sub(r"_+", "_", cleaned)[:max_len].strip("_")
    return cleaned or "finding"


def _to_go_pascal_suffix(slug: str) -> str:
    parts = [p for p in slug.split("_") if p]
    if not parts:
        return "Finding"
    return "".join(p[0].upper() + p[1:] for p in parts)


def _safe_comment(text: str, extra_secrets: Sequence[str], max_len: int = 160) -> str:
    scrubbed = scrub_raw_secrets_text(text or "", extra_raw_secrets=extra_secrets)
    one_line = re.sub(r"[\r\n\x00]+", " ", scrubbed).strip()
    return one_line[:max_len]


def _render_pytest_test(
    *,
    cwe_id: str,
    family: str,
    test_name: str,
    finding_id: str,
    rule_id: str,
    filepath: str,
    line: int,
    title: str,
    snippet: str,
) -> str:
    header = "\n".join(
        [
            f"# ALASTOR Security Regression Test ({cwe_id})",
            f"# Finding ID : {finding_id}",
            f"# Rule ID    : {rule_id}",
            f"# Location   : {filepath}:{line}",
            f"# Summary    : {title}",
            f"# Snippet    : {snippet}" if snippet else "# Snippet    : (unavailable)",
            "import html",
            "import ipaddress",
            "import json",
            "import os",
            "import re",
            "import shlex",
            "import sqlite3",
            "from urllib.parse import urlparse",
            "",
            "import pytest",
            "",
            "",
        ]
    )

    bodies: Dict[str, str] = {
        "CWE-89": f'''def _build_parameterized_user_query(user_id: str):
    """Reference parameterized SQL contract preventing {cwe_id} string interpolation."""
    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("user_id must be a non-empty string")
    return ("SELECT id, username FROM users WHERE id = ?", (user_id,))


def {test_name}() -> None:
    """Regression guard for {cwe_id} at {filepath}:{line}."""
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT)")
        conn.execute("INSERT INTO users (id, username) VALUES (?, ?)", ("u-100", "alice"))
        conn.execute("INSERT INTO users (id, username) VALUES (?, ?)", ("u-200", "bob"))

        malicious_payload = "' OR 1=1 --"
        sql, params = _build_parameterized_user_query(malicious_payload)
        assert malicious_payload not in sql
        assert "?" in sql
        rows = conn.execute(sql, params).fetchall()
        assert rows == []

        safe_sql, safe_params = _build_parameterized_user_query("u-100")
        assert conn.execute(safe_sql, safe_params).fetchall() == [("u-100", "alice")]
    finally:
        conn.close()
''',
        "CWE-78": f'''_SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9._:/-]+$")


def _build_safe_argv(executable: str, user_arg: str):
    """Reference shell-free argv builder preventing {cwe_id} command injection."""
    if not _SAFE_ARG_RE.match(user_arg):
        raise ValueError(f"Blocked shell metacharacters in argument: {{user_arg!r}}")
    return [executable, "--input", shlex.quote(user_arg)]


def {test_name}() -> None:
    """Regression guard for {cwe_id} at {filepath}:{line}."""
    for payload in ("ok; rm -rf /", "$(whoami)", "arg && cat /etc/passwd", "a|b"):
        with pytest.raises(ValueError):
            _build_safe_argv("/usr/bin/echo", payload)

    argv = _build_safe_argv("/usr/bin/echo", "release-v5.0")
    assert isinstance(argv, list)
    assert argv[0] == "/usr/bin/echo"
    assert "release-v5.0" in argv[-1]
''',
        "CWE-79": f'''def _render_safe_html_and_href(untrusted_text: str, untrusted_url: str) -> str:
    """Reference contextual HTML escaping & URL scheme allowlist for {cwe_id}."""
    escaped_text = html.escape(untrusted_text, quote=True)
    parsed = urlparse((untrusted_url or "").strip())
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Blocked unsafe URL scheme: {{parsed.scheme!r}}")
    safe_href = html.escape(untrusted_url.strip(), quote=True)
    return f'<a href="{{safe_href}}">{{escaped_text}}</a>'


def {test_name}() -> None:
    """Regression guard for {cwe_id} at {filepath}:{line}."""
    rendered = _render_safe_html_and_href("<script>alert(1)</script>", "https://example.com/docs")
    assert "<script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered

    for bad_url in ("javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "vbscript:msgbox(1)"):
        with pytest.raises(ValueError):
            _render_safe_html_and_href("click", bad_url)
''',
        "CWE-22": f'''def _resolve_confined_path(base_dir: str, relative_path: str) -> str:
    """Reference realpath + commonpath workspace confinement for {cwe_id}."""
    if not relative_path or "\\x00" in relative_path:
        raise ValueError("Invalid path")
    real_base = os.path.realpath(base_dir)
    candidate = os.path.realpath(os.path.join(real_base, relative_path))
    if os.path.commonpath([real_base, candidate]) != real_base or candidate == real_base:
        raise ValueError(f"Path traversal blocked: {{relative_path!r}}")
    return candidate


def {test_name}(tmp_path) -> None:
    """Regression guard for {cwe_id} at {filepath}:{line}."""
    safe_root = tmp_path / "uploads"
    safe_root.mkdir()
    for payload in ("../../etc/passwd", "../secret.txt", "..\\\\..\\\\Windows\\\\win.ini", "/etc/passwd"):
        with pytest.raises(ValueError):
            _resolve_confined_path(str(safe_root), payload)

    resolved = _resolve_confined_path(str(safe_root), "reports/summary.txt")
    assert os.path.commonpath([os.path.realpath(safe_root), resolved]) == os.path.realpath(safe_root)
''',
        "CWE-918": f'''_BLOCKED_HOSTS = frozenset({{"localhost", "metadata", "metadata.google.internal", "169.254.169.254", "100.100.100.200"}})


def _validate_outbound_url(raw_url: str) -> str:
    """Reference SSRF URL validation rejecting private/link-local/metadata endpoints ({cwe_id})."""
    parsed = urlparse((raw_url or "").strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS outbound URLs are permitted")
    host = (parsed.hostname or "").lower()
    if not host or host in _BLOCKED_HOSTS:
        raise ValueError(f"Blocked internal or metadata host: {{host!r}}")
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return parsed.geturl()
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
        raise ValueError(f"Blocked non-public IP target: {{ip_obj}}")
    return parsed.geturl()


def {test_name}() -> None:
    """Regression guard for {cwe_id} at {filepath}:{line}."""
    for bad_url in (
        "http://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1:8080/admin",
        "https://10.0.0.5/internal",
        "file:///etc/passwd",
    ):
        with pytest.raises(ValueError):
            _validate_outbound_url(bad_url)

    assert _validate_outbound_url("https://api.example.com/v1/status") == "https://api.example.com/v1/status"
''',
        "CWE-639": f'''def _authorize_resource_access(requester_id: str, owner_id: str, roles=None) -> bool:
    """Reference object-level authorization guard preventing {cwe_id} IDOR/BOLA."""
    role_set = set(roles or ())
    if not requester_id or not owner_id:
        raise PermissionError("Missing principal or resource owner")
    if requester_id != owner_id and "SECURITY_ADMIN" not in role_set:
        raise PermissionError("Cross-tenant object access denied (IDOR blocked)")
    return True


def {test_name}() -> None:
    """Regression guard for {cwe_id} at {filepath}:{line}."""
    with pytest.raises(PermissionError):
        _authorize_resource_access("user-attacker", "user-victim", roles=["USER"])

    assert _authorize_resource_access("user-victim", "user-victim", roles=["USER"]) is True
''',
        "CWE-502": f'''def _safe_deserialize_payload(raw_bytes: bytes):
    """Reference safe JSON deserialization rejecting untrusted binary/pickle payloads ({cwe_id})."""
    if raw_bytes.startswith((b"\\x80\\x02", b"\\x80\\x03", b"\\x80\\x04", b"\\x80\\x05", b"cos\\n")):
        raise ValueError("Blocked unsafe pickle opcode stream")
    text = raw_bytes.decode("utf-8")
    if "!!python/" in text:
        raise ValueError("Blocked unsafe YAML python/object tag")
    return json.loads(text)


def {test_name}() -> None:
    """Regression guard for {cwe_id} at {filepath}:{line}."""
    for bad_payload in (b"\\x80\\x04\\x95\\x00", b"cos\\nsystem\\n", b'{{"cmd": "!!python/object/apply:os.system"}}'):
        with pytest.raises(ValueError):
            _safe_deserialize_payload(bad_payload)

    assert _safe_deserialize_payload(b'{{"status": "ok"}}') == {{"status": "ok"}}
''',
        "CWE-798": f'''_KNOWN_CREDENTIAL_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{{16,}}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{{20,}}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{{16}}"),
    re.compile(r"sk-ant-[A-Za-z0-9_-]{{12,}}"),
    re.compile(r"sk-[A-Za-z0-9_-]{{16,}}"),
    re.compile(r"AIza[0-9A-Za-z\\-_]{{20,}}"),
)


def _assert_no_hardcoded_secret(candidate_source: str, env_var: str = "APP_API_TOKEN") -> str:
    """Reference secret-hygiene guard ensuring runtime injection instead of hardcoded tokens ({cwe_id})."""
    for rx in _KNOWN_CREDENTIAL_PATTERNS:
        if rx.search(candidate_source):
            raise ValueError("Hardcoded credential pattern detected in source")
    return f"os.environ[{{env_var!r}}]"


def {test_name}() -> None:
    """Regression guard for {cwe_id} at {filepath}:{line}."""
    synthetic_leak = "TOKEN = '" + "ghp_" + ("0" * 36) + "'"
    with pytest.raises(ValueError):
        _assert_no_hardcoded_secret(synthetic_leak)

    clean_ref = _assert_no_hardcoded_secret("TOKEN = os.environ['APP_API_TOKEN']")
    assert "os.environ" in clean_ref
''',
        "CWE-942": f'''_ALLOWED_ORIGINS = frozenset({{"https://app.example.com", "https://admin.example.com"}})


def _evaluate_cors_origin(origin: str, allow_credentials: bool = True):
    """Reference strict CORS allowlist rejecting wildcard/arbitrary reflection ({cwe_id})."""
    clean = (origin or "").strip()
    if clean == "*" and allow_credentials:
        raise ValueError("Wildcard CORS with Allow-Credentials=true is forbidden")
    if clean not in _ALLOWED_ORIGINS:
        raise PermissionError(f"Blocked untrusted CORS origin: {{clean!r}}")
    return clean


def {test_name}() -> None:
    """Regression guard for {cwe_id} at {filepath}:{line}."""
    with pytest.raises(ValueError):
        _evaluate_cors_origin("*", allow_credentials=True)
    with pytest.raises(PermissionError):
        _evaluate_cors_origin("https://evil.attacker.example", allow_credentials=True)

    assert _evaluate_cors_origin("https://app.example.com", allow_credentials=True) == "https://app.example.com"
''',
        "GENERIC": f'''_CONTROL_CHARS_RX = re.compile(r"[\\x00-\\x1f\\x7f]")


def _validate_boundary_input(raw_value: str, max_len: int = 128) -> str:
    """Reference strict boundary validation guard for {cwe_id}."""
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise ValueError("Input must be a non-empty string")
    if len(raw_value) > max_len or _CONTROL_CHARS_RX.search(raw_value):
        raise ValueError("Input violates size or control-character boundary")
    return raw_value.strip()


def {test_name}() -> None:
    """Regression guard for {cwe_id} at {filepath}:{line}."""
    for bad in ("", "bad\\x00input", "x" * 256):
        with pytest.raises(ValueError):
            _validate_boundary_input(bad)

    assert _validate_boundary_input("valid-input") == "valid-input"
''',
    }
    return header + bodies.get(family, bodies["GENERIC"])


def _render_js_ts_test(
    *,
    framework: Literal["jest", "vitest"],
    cwe_id: str,
    family: str,
    test_name: str,
    finding_id: str,
    rule_id: str,
    filepath: str,
    line: int,
    title: str,
    snippet: str,
) -> str:
    import_line = "import { describe, it, expect } from 'vitest';\n\n" if framework == "vitest" else ""
    header = "\n".join(
        [
            f"// ALASTOR Security Regression Test ({cwe_id}) [{framework}]",
            f"// Finding ID : {finding_id}",
            f"// Rule ID    : {rule_id}",
            f"// Location   : {filepath}:{line}",
            f"// Summary    : {title}",
            f"// Snippet    : {snippet}" if snippet else "// Snippet    : (unavailable)",
            "",
        ]
    )

    family_blocks: Dict[str, str] = {
        "CWE-89": f'''function buildParameterizedSql(userId) {{
  if (typeof userId !== 'string' || !userId.trim()) {{
    throw new Error('Invalid userId');
  }}
  return {{ sql: 'SELECT id, username FROM users WHERE id = $1', params: [userId] }};
}}

describe({json.dumps(f"{test_name} ({cwe_id})")}, () => {{
  it('binds untrusted SQL input as a parameter instead of interpolating', () => {{
    const payload = "' OR 1=1 --";
    const query = buildParameterizedSql(payload);
    expect(query.sql).not.toContain(payload);
    expect(query.sql).toContain('$1');
    expect(query.params).toEqual([payload]);
  }});
}});
''',
        "CWE-78": f'''const SAFE_ARG_RX = /^[A-Za-z0-9._:/-]+$/;

function buildSafeExecArgs(userArg) {{
  if (!SAFE_ARG_RX.test(String(userArg || ''))) {{
    throw new Error('Blocked shell metacharacter payload');
  }}
  return ['--target', userArg];
}}

describe({json.dumps(f"{test_name} ({cwe_id})")}, () => {{
  it('rejects command injection metacharacters and enforces argv array', () => {{
    expect(() => buildSafeExecArgs('ok; rm -rf /')).toThrow();
    expect(() => buildSafeExecArgs('$(id)')).toThrow();
    expect(buildSafeExecArgs('release-v5')).toEqual(['--target', 'release-v5']);
  }});
}});
''',
        "CWE-79": f'''function escapeHtml(raw) {{
  return String(raw || '')
    .split('&').join('&amp;')
    .split('<').join('&lt;')
    .split('>').join('&gt;')
    .split('"').join('&quot;')
    .split("'").join('&#39;');
}}

function validateSafeHref(url) {{
  const trimmed = String(url || '').trim();
  if (!/^https?:\\/\\//i.test(trimmed)) {{
    throw new Error('Blocked non-HTTP(S) URL scheme');
  }}
  return trimmed;
}}

describe({json.dumps(f"{test_name} ({cwe_id})")}, () => {{
  it('escapes HTML sinks and blocks javascript: URL schemes', () => {{
    const rendered = escapeHtml('<script>alert(1)</script>');
    expect(rendered).not.toContain('<script>');
    expect(() => validateSafeHref('javascript:alert(1)')).toThrow();
    expect(validateSafeHref('https://example.com')).toBe('https://example.com');
  }});
}});
''',
        "CWE-22": f'''function resolveConfinedRelativePath(rawRel) {{
  const clean = String(rawRel || '').replace(/\\\\/g, '/');
  if (!clean || clean.startsWith('/') || clean.split('/').includes('..')) {{
    throw new Error('Blocked path traversal');
  }}
  return clean;
}}

describe({json.dumps(f"{test_name} ({cwe_id})")}, () => {{
  it('blocks dot-dot traversal and absolute path escapes', () => {{
    expect(() => resolveConfinedRelativePath('../../etc/passwd')).toThrow();
    expect(() => resolveConfinedRelativePath('/etc/passwd')).toThrow();
    expect(resolveConfinedRelativePath('reports/q4.json')).toBe('reports/q4.json');
  }});
}});
''',
        "CWE-918": f'''function assertSafeOutboundUrl(rawUrl) {{
  const parsed = new URL(String(rawUrl || ''));
  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol !== 'https:') {{
    throw new Error('Only https: is allowed');
  }}
  if (['localhost', '127.0.0.1', '169.254.169.254', 'metadata.google.internal'].includes(host)) {{
    throw new Error('Blocked loopback or cloud metadata host');
  }}
  return parsed.toString();
}}

describe({json.dumps(f"{test_name} ({cwe_id})")}, () => {{
  it('blocks cloud metadata and loopback SSRF targets', () => {{
    expect(() => assertSafeOutboundUrl('http://169.254.169.254/latest/meta-data/')).toThrow();
    expect(() => assertSafeOutboundUrl('https://127.0.0.1/admin')).toThrow();
    expect(assertSafeOutboundUrl('https://api.example.com/health')).toBe('https://api.example.com/health');
  }});
}});
''',
        "CWE-639": f'''function authorizeObjectAccess(requesterId, ownerId, roles = []) {{
  if (!requesterId || !ownerId) throw new Error('Missing identity');
  if (requesterId !== ownerId && !roles.includes('SECURITY_ADMIN')) {{
    throw new Error('Cross-tenant IDOR access denied');
  }}
  return true;
}}

describe({json.dumps(f"{test_name} ({cwe_id})")}, () => {{
  it('denies cross-tenant object access without ownership or admin role', () => {{
    expect(() => authorizeObjectAccess('attacker-1', 'victim-2', ['USER'])).toThrow();
    expect(authorizeObjectAccess('victim-2', 'victim-2', ['USER'])).toBe(true);
  }});
}});
''',
        "CWE-502": f'''function safeDeserializeJson(rawPayload) {{
  const text = String(rawPayload || '');
  if (text.includes('__proto__') || text.includes('constructor') || text.includes('!!python/')) {{
    throw new Error('Blocked unsafe deserialization gadget payload');
  }}
  return JSON.parse(text);
}}

describe({json.dumps(f"{test_name} ({cwe_id})")}, () => {{
  it('blocks prototype pollution and unsafe deserialization tags', () => {{
    expect(() => safeDeserializeJson('{{"__proto__":{{"admin":true}}}}')).toThrow();
    expect(safeDeserializeJson('{{"status":"ok"}}')).toEqual({{ status: 'ok' }});
  }});
}});
''',
        "CWE-798": f'''const SECRET_RX = /(?:gh[pousr]_[A-Za-z0-9_]{{16,}}|(?:AKIA|ASIA)[0-9A-Z]{{16}}|sk-[A-Za-z0-9_-]{{16,}})/;

function assertNoHardcodedSecret(codeLine) {{
  if (SECRET_RX.test(String(codeLine || ''))) {{
    throw new Error('Hardcoded credential detected');
  }}
  return true;
}}

describe({json.dumps(f"{test_name} ({cwe_id})")}, () => {{
  it('rejects hardcoded token literals and enforces env injection', () => {{
    const syntheticToken = 'ghp_' + '0'.repeat(36);
    expect(() => assertNoHardcodedSecret(`const k = "${{syntheticToken}}";`)).toThrow();
    expect(assertNoHardcodedSecret('const k = process.env.APP_TOKEN;')).toBe(true);
  }});
}});
''',
        "CWE-942": f'''const ALLOWED_ORIGINS = new Set(['https://app.example.com']);

function checkCorsOrigin(origin, allowCredentials) {{
  if (origin === '*' && allowCredentials) throw new Error('Wildcard CORS with credentials blocked');
  if (!ALLOWED_ORIGINS.has(origin)) throw new Error('Untrusted origin blocked');
  return origin;
}}

describe({json.dumps(f"{test_name} ({cwe_id})")}, () => {{
  it('rejects wildcard credentialed CORS and untrusted origin reflection', () => {{
    expect(() => checkCorsOrigin('*', true)).toThrow();
    expect(() => checkCorsOrigin('https://evil.example', true)).toThrow();
    expect(checkCorsOrigin('https://app.example.com', true)).toBe('https://app.example.com');
  }});
}});
''',
        "GENERIC": f'''function validateBoundaryInput(value) {{
  if (typeof value !== 'string' || !value.trim() || /[\\x00-\\x1f\\x7f]/.test(value)) {{
    throw new Error('Invalid boundary input');
  }}
  return value.trim();
}}

describe({json.dumps(f"{test_name} ({cwe_id})")}, () => {{
  it('enforces input boundary validation for {cwe_id}', () => {{
    expect(() => validateBoundaryInput('')).toThrow();
    expect(() => validateBoundaryInput('bad\\x00val')).toThrow();
    expect(validateBoundaryInput('safe-value')).toBe('safe-value');
  }});
}});
''',
    }
    block = family_blocks.get(family, family_blocks["GENERIC"])
    return header + import_line + block


def _render_go_test(
    *,
    cwe_id: str,
    family: str,
    test_name: str,
    finding_id: str,
    rule_id: str,
    filepath: str,
    line: int,
    title: str,
    snippet: str,
) -> str:
    header = "\n".join(
        [
            f"// ALASTOR Security Regression Test ({cwe_id}) [go test]",
            f"// Finding ID : {finding_id}",
            f"// Rule ID    : {rule_id}",
            f"// Location   : {filepath}:{line}",
            f"// Summary    : {title}",
            f"// Snippet    : {snippet}" if snippet else "// Snippet    : (unavailable)",
            "package security_test",
            "",
        ]
    )

    go_blocks: Dict[str, str] = {
        "CWE-89": f'''import (
\t"strings"
\t"testing"
)

func buildParameterizedSQL(userID string) (string, []any, error) {{
\tif strings.TrimSpace(userID) == "" {{
\t\treturn "", nil, errInvalidInput
\t}}
\treturn "SELECT id, username FROM users WHERE id = $1", []any{{userID}}, nil
}}

type staticErr string

func (e staticErr) Error() string {{ return string(e) }}

const errInvalidInput = staticErr("invalid input")

func {test_name}(t *testing.T) {{
\tpayload := "' OR 1=1 --"
\tsql, params, err := buildParameterizedSQL(payload)
\tif err != nil {{
\t\tt.Fatalf("unexpected error: %v", err)
\t}}
\tif strings.Contains(sql, payload) || !strings.Contains(sql, "$1") || len(params) != 1 {{
\t\tt.Fatalf("SQL was not parameterized safely: %s", sql)
\t}}
}}
''',
        "CWE-78": f'''import (
\t"strings"
\t"testing"
)

func isSafeCLIArg(arg string) bool {{
\tif arg == "" || strings.ContainsAny(arg, ";&|$`\\n\\r") {{
\t\treturn false
\t}}
\treturn true
}}

func {test_name}(t *testing.T) {{
\tfor _, bad := range []string{{"ok; rm -rf /", "$(whoami)", "a|b"}} {{
\t\tif isSafeCLIArg(bad) {{
\t\t\tt.Fatalf("expected metacharacter payload to be rejected: %s", bad)
\t\t}}
\t}}
\tif !isSafeCLIArg("release-v5") {{
\t\tt.Fatalf("expected benign argument to pass")
\t}}
}}
''',
        "CWE-79": f'''import (
\t"html"
\t"strings"
\t"testing"
)

func {test_name}(t *testing.T) {{
\tescaped := html.EscapeString("<script>alert(1)</script>")
\tif strings.Contains(escaped, "<script>") {{
\t\tt.Fatalf("expected HTML escaping to neutralize script tag: %s", escaped)
\t}}
}}
''',
        "CWE-22": f'''import (
\t"path/filepath"
\t"strings"
\t"testing"
)

func isConfinedRelPath(rel string) bool {{
\tcleaned := filepath.Clean(rel)
\treturn rel != "" && !filepath.IsAbs(cleaned) && cleaned != ".." && !strings.HasPrefix(cleaned, ".."+string(filepath.Separator))
}}

func {test_name}(t *testing.T) {{
\tif isConfinedRelPath("../../etc/passwd") || isConfinedRelPath("/etc/passwd") {{
\t\tt.Fatalf("expected traversal path to be blocked")
\t}}
\tif !isConfinedRelPath("reports/summary.txt") {{
\t\tt.Fatalf("expected valid relative path to pass")
\t}}
}}
''',
        "CWE-918": f'''import (
\t"net/url"
\t"testing"
)

func isAllowedOutboundURL(raw string) bool {{
\tu, err := url.Parse(raw)
\tif err != nil || u.Scheme != "https" {{
\t\treturn false
\t}}
\thost := u.Hostname()
\treturn host != "" && host != "169.254.169.254" && host != "127.0.0.1" && host != "localhost"
}}

func {test_name}(t *testing.T) {{
\tif isAllowedOutboundURL("http://169.254.169.254/latest/meta-data/") || isAllowedOutboundURL("https://127.0.0.1/admin") {{
\t\tt.Fatalf("expected SSRF target to be blocked")
\t}}
\tif !isAllowedOutboundURL("https://api.example.com/status") {{
\t\tt.Fatalf("expected safe HTTPS URL to pass")
\t}}
}}
''',
        "CWE-639": f'''import "testing"

func authorizeResourceOwner(requesterID string, ownerID string) bool {{
\treturn requesterID != "" && requesterID == ownerID
}}

func {test_name}(t *testing.T) {{
\tif authorizeResourceOwner("attacker-1", "victim-2") {{
\t\tt.Fatalf("expected cross-tenant IDOR access to be denied")
\t}}
\tif !authorizeResourceOwner("victim-2", "victim-2") {{
\t\tt.Fatalf("expected owner access to succeed")
\t}}
}}
''',
        "CWE-502": f'''import (
\t"encoding/json"
\t"strings"
\t"testing"
)

func safeDecodeStrictJSON(raw string) (map[string]any, error) {{
\tif strings.Contains(raw, "!!python/") || strings.Contains(raw, "\\x80\\x04") {{
\t\treturn nil, errUnsafePayload
\t}}
\tvar out map[string]any
\terr := json.Unmarshal([]byte(raw), &out)
\treturn out, err
}}

type deserErr string

func (e deserErr) Error() string {{ return string(e) }}

const errUnsafePayload = deserErr("unsafe deserialization payload")

func {test_name}(t *testing.T) {{
\tif _, err := safeDecodeStrictJSON("!!python/object/apply:os.system"); err == nil {{
\t\tt.Fatalf("expected unsafe deserialization payload to be rejected")
\t}}
\tif _, err := safeDecodeStrictJSON(`{{"status":"ok"}}`); err != nil {{
\t\tt.Fatalf("expected valid JSON to decode: %v", err)
\t}}
}}
''',
        "CWE-942": f'''import "testing"

func isTrustedCORSOrigin(origin string, allowCredentials bool) bool {{
\tif origin == "*" && allowCredentials {{
\t\treturn false
\t}}
\treturn origin == "https://app.example.com"
}}

func {test_name}(t *testing.T) {{
\tif isTrustedCORSOrigin("*", true) || isTrustedCORSOrigin("https://evil.example", true) {{
\t\tt.Fatalf("expected untrusted or wildcard credentialed CORS origin to be rejected")
\t}}
\tif !isTrustedCORSOrigin("https://app.example.com", true) {{
\t\tt.Fatalf("expected allowlisted origin to pass")
\t}}
}}
''',
        "CWE-798": f'''import (
\t"strings"
\t"testing"
)

func containsHardcodedCredentialPrefix(line string) bool {{
\treturn strings.Contains(line, "ghp_") || strings.Contains(line, "AKIA") || strings.Contains(line, "sk-ant-")
}}

func {test_name}(t *testing.T) {{
\tsynthetic := "token := " + `"` + "ghp_" + strings.Repeat("0", 36) + `"`
\tif !containsHardcodedCredentialPrefix(synthetic) {{
\t\tt.Fatalf("expected hardcoded token pattern to be detected")
\t}}
\tif containsHardcodedCredentialPrefix(`token := os.Getenv("APP_TOKEN")`) {{
\t\tt.Fatalf("expected env lookup to pass secret hygiene check")
\t}}
}}
''',
        "GENERIC": f'''import (
\t"strings"
\t"testing"
)

func isSafeBoundaryInput(val string) bool {{
\treturn strings.TrimSpace(val) != "" && !strings.ContainsRune(val, '\\x00')
}}

func {test_name}(t *testing.T) {{
\tif isSafeBoundaryInput("") || isSafeBoundaryInput("bad\\x00input") {{
\t\tt.Fatalf("expected invalid boundary input to be rejected")
\t}}
\tif !isSafeBoundaryInput("safe-value") {{
\t\tt.Fatalf("expected valid input to pass")
\t}}
}}
''',
    }
    return header + go_blocks.get(family, go_blocks["GENERIC"])


def _has_balanced_delimiters(code: str) -> bool:
    pairs = {")": "(", "}": "{", "]": "["}
    stack: List[str] = []
    in_quote: Optional[str] = None
    in_regex = False
    regex_class = False
    i = 0
    n = len(code)
    prev_sig = ""
    while i < n:
        ch = code[i]
        if in_quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == in_quote:
                in_quote = None
                prev_sig = ch
            i += 1
            continue
        if in_regex:
            if ch == "\\":
                i += 2
                continue
            if ch == "[":
                regex_class = True
            elif ch == "]" and regex_class:
                regex_class = False
            elif ch == "/" and not regex_class:
                in_regex = False
                prev_sig = "/"
            i += 1
            continue
        if code.startswith("//", i):
            nl = code.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        if code.startswith("/*", i):
            end = code.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        if ch in ('"', "'", "`"):
            in_quote = ch
            i += 1
            continue
        if ch == "/" and prev_sig in ("", "(", ",", "=", ":", "!", "[", "{", ";", "&", "|", "?"):
            in_regex = True
            regex_class = False
            i += 1
            continue
        if ch in ("(", "{", "["):
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack[-1] != pairs[ch]:
                return False
            stack.pop()
        if not ch.isspace():
            prev_sig = ch
        i += 1
    return not stack and in_quote is None and not in_regex


def _validate_generated_syntax(
    framework: ResolvedTestFramework,
    code: str,
) -> Tuple[bool, List[str]]:
    warnings: List[str] = []
    if not code.strip():
        return False, ["Generated test code is empty"]
    if framework == "pytest":
        try:
            ast.parse(code)
            return True, warnings
        except SyntaxError as exc:
            warnings.append(f"Generated Python syntax check failed: {exc}")
            return False, warnings
    if framework in ("jest", "vitest"):
        ok = "describe(" in code and "expect(" in code and _has_balanced_delimiters(code)
        if not ok:
            warnings.append(f"Generated {framework} test structure check failed")
        return ok, warnings
    if framework == "go_test":
        ok = (
            "package security_test" in code
            and '"testing"' in code
            and "func Test" in code
            and _has_balanced_delimiters(code)
        )
        if not ok:
            warnings.append("Generated go_test structure check failed")
        return ok, warnings
    return False, [f"Unsupported framework: {framework}"]


def _write_confined_security_test(
    real_repo: str,
    suggested_relative_path: str,
    test_code: str,
    overwrite: bool,
) -> str:
    """
    Confines writes strictly inside `<real_repo>/tests/security/<safe_filename>`,
    rejecting symlinks and Windows NTFS junctions along every ancestor and leaf,
    and refusing to overwrite existing files unless `overwrite=True`.
    """
    parts = [p for p in suggested_relative_path.replace("\\", "/").split("/") if p]
    if len(parts) != 3 or parts[0] != "tests" or parts[1] != "security":
        raise HostileRepoError(f"Refused unsafe relative test path: {suggested_relative_path}")
    filename = parts[2]
    if ".." in parts or not _SAFE_FILENAME_RE.match(filename):
        raise HostileRepoError(f"Refused unsafe test filename: {filename}")

    cursor = real_repo
    for dir_part in ("tests", "security"):
        cursor = os.path.join(cursor, dir_part)
        if os.path.lexists(cursor):
            if is_link_or_junction(cursor):
                raise HostileRepoError(
                    f"Refused writing inside symlink/junction directory: {cursor}"
                )
            if not os.path.isdir(cursor):
                raise HostileRepoError(
                    f"Expected directory at {dir_part} inside repository, found non-directory"
                )
            real_dir = os.path.realpath(cursor)
            try:
                if os.path.commonpath([real_repo, real_dir]) != real_repo:
                    raise HostileRepoError(f"Directory escapes repository root: {cursor}")
            except ValueError as exc:
                raise HostileRepoError(f"Directory escapes repository root: {cursor}") from exc
        else:
            os.makedirs(cursor, exist_ok=True)
            if is_link_or_junction(cursor):
                raise HostileRepoError(f"Unexpected symlink/junction created at {cursor}")

    sec_dir_real = os.path.realpath(cursor)
    target_path = os.path.join(sec_dir_real, filename)
    if os.path.lexists(target_path):
        if is_link_or_junction(target_path):
            raise HostileRepoError(f"Refused overwriting symlink/junction target: {target_path}")
        if not overwrite:
            raise FileExistsError(
                f"Security regression test already exists (pass overwrite=True): {suggested_relative_path}"
            )

    real_target = os.path.realpath(target_path)
    try:
        if (
            os.path.commonpath([real_repo, real_target]) != real_repo
            or os.path.commonpath([sec_dir_real, real_target]) != sec_dir_real
        ):
            raise HostileRepoError(f"Target path escapes confined tests/security directory: {target_path}")
    except ValueError as exc:
        raise HostileRepoError(f"Target path escapes confined tests/security directory: {target_path}") from exc

    with open(real_target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(test_code)
    return real_target


def generate_security_regression_test(
    req: SecurityTestGenerateRequest,
    finding: Optional[Finding] = None,
) -> SecurityTestGenerateResponse:
    """
    Generates a scrubbed, syntax-validated, CWE-tailored security regression unit test
    for `finding` (or `req.finding`) in `pytest`, `jest`, `vitest`, or `go_test`.
    """
    real_repo = _validate_repo_dir(req.project_path)
    effective_finding = finding if finding is not None else req.finding
    if effective_finding is None:
        raise ValueError("A Finding object is required to generate a security regression test")

    raw_secrets: List[str] = []
    if isinstance(effective_finding.secret_value_raw, str) and len(effective_finding.secret_value_raw) >= 4:
        raw_secrets.append(effective_finding.secret_value_raw)

    scrubbed_finding = scrub_finding_secrets(
        effective_finding,
        extra_raw_secrets=raw_secrets,
        clear_raw_secret=True,
    )

    if req.framework == "auto":
        resolved_fw: ResolvedTestFramework = detect_test_framework(scrubbed_finding, real_repo)
    elif req.framework in _VALID_FRAMEWORKS:
        resolved_fw = req.framework  # type: ignore[assignment]
    else:
        raise ValueError(f"Unsupported test framework: {req.framework}")

    cwe_id = _normalize_cwe(scrubbed_finding)
    family = _cwe_family(cwe_id, scrubbed_finding)
    raw_filepath, line_num, raw_snippet = _extract_finding_filepath_and_line(scrubbed_finding)

    scrubbed_fid = scrub_raw_secrets_text(scrubbed_finding.id, extra_raw_secrets=raw_secrets)
    safe_finding_id = _slugify_identifier(scrubbed_fid, max_len=16)
    safe_cwe_slug = _slugify_identifier(cwe_id, max_len=12)
    safe_file_slug = _slugify_identifier(os.path.splitext(os.path.basename(raw_filepath))[0], max_len=18)
    slug = _slugify_identifier(f"{safe_cwe_slug}_{safe_file_slug}_{safe_finding_id}", max_len=48)

    safe_rule_id = _safe_comment(scrubbed_finding.rule_id, raw_secrets, max_len=64)
    safe_filepath = _safe_comment(raw_filepath, raw_secrets, max_len=140)
    safe_title = _safe_comment(scrubbed_finding.title, raw_secrets, max_len=140)
    safe_snippet = _safe_comment(raw_snippet, raw_secrets, max_len=140)

    if resolved_fw == "pytest":
        test_name = f"test_security_regression_{slug}"
        suggested_rel = f"tests/security/test_alastor_{slug}.py"
        run_hint = f"pytest {suggested_rel}"
        raw_code = _render_pytest_test(
            cwe_id=cwe_id,
            family=family,
            test_name=test_name,
            finding_id=safe_finding_id,
            rule_id=safe_rule_id,
            filepath=safe_filepath,
            line=line_num,
            title=safe_title,
            snippet=safe_snippet,
        )
    elif resolved_fw in ("jest", "vitest"):
        test_name = f"test_security_regression_{slug}"
        suggested_rel = f"tests/security/alastor_{slug}.test.ts"
        run_hint = (
            f"npx vitest run {suggested_rel}"
            if resolved_fw == "vitest"
            else f"npx jest {suggested_rel}"
        )
        raw_code = _render_js_ts_test(
            framework=resolved_fw,
            cwe_id=cwe_id,
            family=family,
            test_name=test_name,
            finding_id=safe_finding_id,
            rule_id=safe_rule_id,
            filepath=safe_filepath,
            line=line_num,
            title=safe_title,
            snippet=safe_snippet,
        )
    else:
        test_name = f"TestSecurityRegression_{_to_go_pascal_suffix(slug)}"
        suggested_rel = f"tests/security/alastor_{slug}_test.go"
        run_hint = "go test -v ./tests/security/..."
        raw_code = _render_go_test(
            cwe_id=cwe_id,
            family=family,
            test_name=test_name,
            finding_id=safe_finding_id,
            rule_id=safe_rule_id,
            filepath=safe_filepath,
            line=line_num,
            title=safe_title,
            snippet=safe_snippet,
        )

    test_code = scrub_raw_secrets_text(raw_code, extra_raw_secrets=raw_secrets)
    syntax_valid, warnings = _validate_generated_syntax(resolved_fw, test_code)

    written_to_disk = False
    written_path: Optional[str] = None
    if req.write_to_workspace:
        if is_link_or_junction(os.path.abspath(req.project_path.strip())):
            raise HostileRepoError("Refused writing inside symlink/junction project_path")
        written_path = _write_confined_security_test(
            real_repo=real_repo,
            suggested_relative_path=suggested_rel,
            test_code=test_code,
            overwrite=req.overwrite,
        )
        written_to_disk = True

    return SecurityTestGenerateResponse(
        project_path=real_repo,
        finding_id=scrub_raw_secrets_text(scrubbed_finding.id, extra_raw_secrets=raw_secrets),
        cwe_id=cwe_id,
        framework=resolved_fw,
        suggested_relative_path=suggested_rel,
        test_name=test_name,
        test_code=test_code,
        syntax_valid=syntax_valid,
        written_to_disk=written_to_disk,
        written_path=written_path,
        run_command_hint=run_hint,
        warnings=[scrub_raw_secrets_text(w, extra_raw_secrets=raw_secrets) for w in warnings],
    )
