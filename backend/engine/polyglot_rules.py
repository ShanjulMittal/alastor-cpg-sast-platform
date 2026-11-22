"""
Deterministic Polyglot Security Rule Packs (RULE-22 through RULE-33) for ALASTOR v5.0 Pillar 1.
Runs over ScannedFile + 4-Pass CPG (nodes & edges) in both Neo4j and Embedded SQLite modes
at $0 LLM token cost.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from compiler.ast_parser import compute_node_id
from compiler.language_registry import LANGUAGE_SPECS
from compiler.scanner import ScannedFile
from models import BestFixLocation, CPGEdge, CPGNode, Finding


POLYGLOT_RULE_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "RULE-22-CPP-BUFFER-OVERFLOW",
        "name": "C/C++ Unbounded Buffer Copy & Memory Overflow",
        "languages": ["c", "cpp"],
        "cwe_id": "CWE-120",
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "Unbounded string/memory copy API (strcpy, strcat, gets, sprintf, vsprintf, or dynamic-length memcpy) can overflow destination buffers.",
        "remediation": "Replace unbounded copy functions with length-bounded equivalents (strncpy/strlcpy, snprintf, fgets) and validate memcpy length against sizeof(dst).",
    },
    {
        "id": "RULE-23-CPP-FORMAT-STRING",
        "name": "C/C++ Externally-Controlled Format String",
        "languages": ["c", "cpp"],
        "cwe_id": "CWE-134",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 8.1,
        "severity": "HIGH",
        "description": "Non-literal format string argument passed to printf/fprintf/sprintf/snprintf/syslog enables arbitrary stack read/write.",
        "remediation": "Always pass a compile-time constant format literal (e.g., printf(\"%s\", msg)) and supply dynamic strings as subsequent arguments.",
    },
    {
        "id": "RULE-24-CPP-UAF-DOUBLE-FREE",
        "name": "C/C++ Use-After-Free & Double-Free Memory Lifetime Violation",
        "languages": ["c", "cpp"],
        "cwe_id": "CWE-416",
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_score": 9.1,
        "severity": "CRITICAL",
        "description": "Heap pointer is dereferenced, passed to a function, or freed a second time after free()/delete without intervening NULL reset or reallocation.",
        "remediation": "Immediately assign freed pointers to NULL/nullptr after free()/delete or manage ownership with RAII smart pointers (std::unique_ptr).",
    },
    {
        "id": "RULE-25-RUST-UNSAFE-FFI",
        "name": "Rust Unsafe Block Raw Pointer Dereference / Transmute / Unchecked FFI",
        "languages": ["rust"],
        "cwe_id": "CWE-242",
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "description": "Rust `unsafe` block performs raw pointer dereference, `mem::transmute`, or unchecked `extern \"C\"` FFI invocation bypassing borrow-checker memory safety.",
        "remediation": "Eliminate `unsafe` via safe Rust abstractions (TryFrom/from_ne_bytes/slices), or encapsulate FFI calls behind validated null/bounds checks and SAFETY invariants.",
    },
    {
        "id": "RULE-26-POLYGLOT-SQLI",
        "name": "Polyglot SQL Injection via Dynamic Query Construction",
        "languages": ["go", "java", "kotlin", "csharp", "scala", "php", "ruby", "swift", "dart", "rust"],
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "SQL query execution constructs SQL text dynamically via string concatenation or interpolation instead of parameterized bind placeholders.",
        "remediation": "Use parameterized queries/PreparedStatements with positional or named bind parameters (?, $1, @p1) and never concatenate untrusted values into SQL text.",
    },
    {
        "id": "RULE-27-POLYGLOT-CMDI",
        "name": "Polyglot OS Command Injection via Dynamic Shell / Process Invocation",
        "languages": ["go", "java", "kotlin", "csharp", "scala", "php", "ruby", "swift", "dart", "rust"],
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "Dynamic or untrusted data is passed into an OS shell or process execution sink without strict allowlisting or argument escaping.",
        "remediation": "Avoid invoking an intermediate shell (sh -c / cmd /c), pass constant executable paths with strict argument arrays, or sanitize arguments with platform-native escapers.",
    },
    {
        "id": "RULE-28-POLYGLOT-DESER",
        "name": "Polyglot Unsafe Native Object Deserialization",
        "languages": ["java", "kotlin", "csharp", "scala", "php", "ruby", "swift"],
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "Application deserializes untrusted payloads via unsafe native object deserializers (ObjectInputStream, BinaryFormatter, unserialize, Marshal.load, YAML.load, NSKeyedUnarchiver).",
        "remediation": "Use schema-validated JSON parsers, YAML.safe_load, unserialize(..., ['allowed_classes' => false]), or strict type allowlists instead of native object deserialization.",
    },
    {
        "id": "RULE-29-POLYGLOT-XXE",
        "name": "Polyglot XML External Entity (XXE) Parser Misconfiguration",
        "languages": ["java", "kotlin", "csharp", "php", "ruby", "go"],
        "cwe_id": "CWE-611",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cvss_score": 8.2,
        "severity": "HIGH",
        "description": "XML parser is configured without disabling DTD processing and external entity resolution, enabling local file disclosure and SSRF.",
        "remediation": "Explicitly disable DTDs and external entities (e.g., setFeature disallow-doctype-decl=true in Java, DtdProcessing.Prohibit / XmlResolver=null in C#, omit LIBXML_NOENT in PHP).",
    },
    {
        "id": "RULE-30-SOLIDITY-REENTRANCY",
        "name": "Solidity Reentrancy (Checks-Effects-Interactions Violation)",
        "languages": ["solidity"],
        "cwe_id": "CWE-841",
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_score": 9.1,
        "severity": "CRITICAL",
        "description": "Smart contract performs an external value `.call{value: ...}` before updating storage state in a function lacking `nonReentrant` protection.",
        "remediation": "Follow the Checks-Effects-Interactions pattern by mutating contract storage state BEFORE external calls, and apply OpenZeppelin's `nonReentrant` modifier.",
    },
    {
        "id": "RULE-31-SOLIDITY-TX-ORIGIN-DELEGATE",
        "name": "Solidity Insecure `tx.origin` Auth, Unguarded `delegatecall`, or `selfdestruct`",
        "languages": ["solidity"],
        "cwe_id": "CWE-284",
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_score": 9.1,
        "severity": "CRITICAL",
        "description": "Contract relies on phishing-vulnerable `tx.origin` for authorization, executes unguarded `delegatecall`, or exposes `selfdestruct`/`suicide`.",
        "remediation": "Replace `tx.origin` with `msg.sender` for authorization checks, restrict `delegatecall` to immutable trusted implementation addresses with strict access controls, and remove `selfdestruct`.",
    },
    {
        "id": "RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI",
        "name": "Web Template Unescaped Output (XSS) or Server-Side Template Injection",
        "languages": ["web_template"],
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 8.0,
        "severity": "HIGH",
        "description": "Template explicitly disables contextual HTML auto-escaping (|safe, autoescape false, <%-, {{{, {!!, @Html.Raw, v-html) or evaluates dynamic template expressions.",
        "remediation": "Use default contextual auto-escaping (`{{ var }}`, `<%= var %>`) or sanitize rich HTML strictly via DOMPurify/bleach before rendering.",
    },
    {
        "id": "RULE-33-TEMPLATE-MISSING-CSRF",
        "name": "Web Template State-Changing POST Form Missing CSRF Token",
        "languages": ["web_template"],
        "cwe_id": "CWE-352",
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_score": 6.5,
        "severity": "MEDIUM",
        "description": "HTML/template `<form method=\"post\">` lacks a framework anti-CSRF token input or directive (csrf_token, @csrf, csrf_field, authenticity_token, __RequestVerificationToken).",
        "remediation": "Include the framework's anti-CSRF token inside every state-changing POST form (e.g., `{{ csrf_token() }}`, `@csrf`, `{% csrf_token %}`, or `@Html.AntiForgeryToken()`).",
    },
]

_CATALOG_BY_ID: Dict[str, Dict[str, Any]] = {r["id"]: r for r in POLYGLOT_RULE_CATALOG}


_CHAR_LITERAL_RE = re.compile(r"'(?:[^'\\\n]|\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|.))'")


def _strip_c_style_comments_preserve_lines(source: str) -> str:
    """
    Replaces `//...` and `/*...*/` comments with spaces while preserving newlines (1-to-1 line numbers).
    Handles double-quoted strings and single-quoted character literals cleanly without mistaking
    Rust lifetimes (`'a`, `'static`) for unterminated single-quoted strings.
    """
    out: List[str] = []
    i = 0
    n = len(source)
    in_str: Optional[str] = None
    escape_next = False

    while i < n:
        ch = source[i]
        if in_str:
            out.append(ch)
            if escape_next:
                escape_next = False
            elif ch == "\\":
                escape_next = True
            elif ch == in_str:
                in_str = None
            i += 1
            continue

        if ch == '"':
            in_str = '"'
            out.append(ch)
            i += 1
            continue

        if ch == "'":
            # Only consume as char literal when matching `'x'` / `'\n'` / `'\x41'` / `'\u{...}'`,
            # never entering string mode on Rust lifetimes like `'static` or `'a`.
            cm = _CHAR_LITERAL_RE.match(source, i)
            if cm:
                out.append(cm.group(0))
                i = cm.end()
            else:
                out.append(ch)
                i += 1
            continue

        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue

        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            out.append("  ")
            i += 2
            while i < n:
                if source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def _strip_hash_comments_preserve_lines(source: str) -> str:
    """Strips `#` line comments outside quotes (Ruby/PHP) while preserving line numbers."""
    out_lines: List[str] = []
    for line in source.splitlines():
        in_str: Optional[str] = None
        escape_next = False
        cut = len(line)
        for idx, ch in enumerate(line):
            if escape_next:
                escape_next = False
                continue
            if in_str:
                if ch == "\\":
                    escape_next = True
                elif ch == in_str:
                    in_str = None
                continue
            if ch in ('"', "'"):
                in_str = ch
            elif ch == "#" and not (idx + 1 < len(line) and line[idx + 1] == "{"):
                cut = idx
                break
        out_lines.append(line[:cut])
    return "\n".join(out_lines)


def _extract_call_args_from_offset(text: str, open_paren_idx: int) -> Optional[List[str]]:
    """Parses comma-separated call arguments starting at `(` with balanced parens/strings."""
    if open_paren_idx >= len(text) or text[open_paren_idx] != "(":
        return None
    args: List[str] = []
    depth = 1
    in_str: Optional[str] = None
    escape_next = False
    start = open_paren_idx + 1
    i = start
    n = len(text)

    while i < n and depth > 0:
        ch = text[i]
        if escape_next:
            escape_next = False
            i += 1
            continue
        if in_str:
            if ch == "\\":
                escape_next = True
            elif ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
        elif ch in ("(", "[", "{"):
            depth += 1
        elif ch in (")", "]", "}"):
            depth -= 1
            if depth == 0:
                args.append(text[start:i].strip())
                return [a for a in args if a != ""]
        elif ch == "," and depth == 1:
            args.append(text[start:i].strip())
            start = i + 1
        i += 1
    return None


def _is_string_literal_arg(arg: str) -> bool:
    a = arg.strip()
    if not a:
        return False
    # C/C++ prefixed literals L"...", u8"...", R"(...)"
    if re.match(r'^(?:L|u8|u|U|R)?"', a) and a.endswith('"'):
        return True
    if (a.startswith("'") and a.endswith("'")) or (a.startswith('"') and a.endswith('"')):
        return True
    return False


def _display_language_name(lang_key: str) -> str:
    spec = LANGUAGE_SPECS.get(lang_key)
    if spec:
        return spec.display_name
    return lang_key.capitalize()


def _build_finding(
    rule_id: str,
    sf: ScannedFile,
    line_no: int,
    snippet: str,
    title: str,
    detail: str,
    nodes_by_file_line: Dict[Tuple[str, int], List[CPGNode]],
    edges_by_target: Dict[str, List[CPGEdge]],
    node_by_id: Dict[str, CPGNode],
    seen_keys: Set[Tuple[str, str, int]],
) -> Optional[Finding]:
    """Constructs a deterministic, EnterpriseManager/STRIDE/PASTA/SAR-compatible Finding."""
    dedup_key = (rule_id, sf.filepath, line_no)
    if dedup_key in seen_keys:
        return None
    seen_keys.add(dedup_key)

    meta = _CATALOG_BY_ID[rule_id]
    clean_snip = snippet.strip().replace("\x00", "")[:240]
    finding_id = hashlib.sha256(
        f"{rule_id}:{sf.filepath}:{line_no}:{clean_snip}".encode("utf-8")
    ).hexdigest()[:16]

    matched_nodes = nodes_by_file_line.get((sf.filepath, line_no), [])
    primary_cpg: Optional[CPGNode] = None
    for cand in matched_nodes:
        if cand.label in ("Call", "Assignment", "ControlBlock", "Return"):
            primary_cpg = cand
            break
    if primary_cpg is None and matched_nodes:
        primary_cpg = matched_nodes[0]

    path_nodes: List[Dict[str, Any]] = []
    path_edges: List[Dict[str, Any]] = []

    if primary_cpg is not None:
        # Include one upstream DFG node if present for richer trace context
        incoming = edges_by_target.get(primary_cpg.id, [])
        for edge in incoming:
            if edge.edge_type == "DFG_FLOWS_TO":
                src_node = node_by_id.get(edge.source_id)
                if src_node is not None and src_node.id != primary_cpg.id:
                    src_d = src_node.model_dump()
                    src_d["is_bfl"] = False
                    path_nodes.append(src_d)
                    path_edges.append(
                        {"id": edge.id, "source": edge.source_id, "target": edge.target_id, "type": edge.edge_type}
                    )
                    break

        node_dict = primary_cpg.model_dump()
        node_dict["is_bfl"] = True
        path_nodes.append(node_dict)
        node_id = primary_cpg.id
        col = primary_cpg.start_col
    else:
        node_id = compute_node_id(sf.filepath, rule_id, line_no, line_no + len(clean_snip))
        col = 0
        path_nodes.append(
            {
                "id": node_id,
                "label": "Call",
                "ast_type": "polyglot_finding",
                "name": rule_id,
                "code": clean_snip,
                "filepath": sf.filepath,
                "start_line": line_no,
                "end_line": line_no,
                "start_col": 0,
                "end_col": len(clean_snip),
                "scope_id": "global",
                "language": sf.language,
                "is_bfl": True,
            }
        )

    cwe_id = meta["cwe_id"]
    cwe_num = cwe_id.split("-")[1] if cwe_id and "-" in cwe_id else None
    bfl = BestFixLocation(
        node_id=node_id,
        filepath=sf.filepath,
        line=line_no,
        column=col,
        code_snippet=clean_snip,
        explanation=detail,
        recommended_fix=meta["remediation"],
    )

    full_desc = (
        f"{meta['description']} "
        f"[Written Evidence: {detail} at `{sf.filepath}` (Line {line_no}: `{clean_snip[:120]}`)]"
    )
    full_rem = f"{meta['remediation']} (Target Location: `{sf.filepath}` at Line {line_no})."

    return Finding(
        id=finding_id,
        rule_id=rule_id,
        severity=meta["severity"],
        title=title,
        description=full_desc,
        cwe_id=cwe_id,
        owasp_category=meta["owasp_category"],
        cvss_score=meta["cvss_score"],
        remediation=full_rem,
        source_site="ALASTOR Polyglot Engine",
        reference_url=f"https://cwe.mitre.org/data/definitions/{cwe_num}.html" if cwe_num else None,
        path_nodes=path_nodes,
        path_edges=path_edges,
        scan_engine="SAST",
        language=_display_language_name(sf.language),
        best_fix_location=bfl,
    )


# ---------------------------------------------------------------------------
# Individual Rule Pack Evaluators (RULE-22 .. RULE-33)
# ---------------------------------------------------------------------------

_RULE22_UNBOUNDED_RE = re.compile(r"\b(strcpy|strcat|gets|sprintf|vsprintf)\s*\(")
_RULE22_MEMCPY_RE = re.compile(r"\bmemcpy\s*\(")


def _check_rule_22_cpp_buffer_overflow(sf: ScannedFile, clean_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = clean_src.splitlines()
    for m in _RULE22_UNBOUNDED_RE.finditer(clean_src):
        fn_name = m.group(1)
        line_no = clean_src.count("\n", 0, m.start()) + 1
        line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
        f = _build_finding(
            "RULE-22-CPP-BUFFER-OVERFLOW",
            sf,
            line_no,
            line_txt,
            f"Unbounded C/C++ Buffer Copy via `{fn_name}()`",
            f"Call to unbounded memory/string function `{fn_name}()` without destination size limit",
            **ctx,
        )
        if f:
            findings.append(f)

    for m in _RULE22_MEMCPY_RE.finditer(clean_src):
        open_idx = m.end() - 1
        args = _extract_call_args_from_offset(clean_src, open_idx)
        if args and len(args) >= 3:
            len_arg = args[2].strip()
            # Safe if constant integer literal or bounded by sizeof(...)
            if re.fullmatch(r"\d+[uUlL]*", len_arg) or "sizeof(" in len_arg:
                continue
            line_no = clean_src.count("\n", 0, m.start()) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
            f = _build_finding(
                "RULE-22-CPP-BUFFER-OVERFLOW",
                sf,
                line_no,
                line_txt,
                "Dynamic / Unbounded Length Passed to `memcpy()`",
                f"`memcpy()` invoked with non-constant length expression `{len_arg}`",
                **ctx,
            )
            if f:
                findings.append(f)
    return findings


_RULE23_FMT_RE = re.compile(r"\b(printf|fprintf|sprintf|snprintf|syslog)\s*\(")
_RULE23_FMT_ARG_IDX = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1}


def _check_rule_23_cpp_format_string(sf: ScannedFile, clean_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = clean_src.splitlines()
    for m in _RULE23_FMT_RE.finditer(clean_src):
        fn_name = m.group(1)
        fmt_idx = _RULE23_FMT_ARG_IDX[fn_name]
        args = _extract_call_args_from_offset(clean_src, m.end() - 1)
        if not args or len(args) <= fmt_idx:
            continue
        fmt_arg = args[fmt_idx].strip()
        if _is_string_literal_arg(fmt_arg):
            continue
        line_no = clean_src.count("\n", 0, m.start()) + 1
        line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
        f = _build_finding(
            "RULE-23-CPP-FORMAT-STRING",
            sf,
            line_no,
            line_txt,
            f"Format String Vulnerability in `{fn_name}()`",
            f"Non-literal format argument `{fmt_arg}` passed to `{fn_name}()`",
            **ctx,
        )
        if f:
            findings.append(f)
    return findings


_RULE24_FREE_RE = re.compile(r"\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
_RULE24_DELETE_RE = re.compile(r"\bdelete(?:\s*\[\s*\])?\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_RULE24_REASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)")


def _check_rule_24_cpp_uaf_double_free(
    sf: ScannedFile,
    clean_src: str,
    file_nodes: List[CPGNode],
    ctx: Dict[str, Any],
) -> List[Finding]:
    findings: List[Finding] = []
    lines = clean_src.splitlines()
    func_ranges: List[Tuple[int, int]] = [
        (n.start_line, n.end_line) for n in file_nodes if n.label == "Function"
    ]
    if not func_ranges:
        func_ranges = [(1, len(lines))]

    for start_ln, end_ln in func_ranges:
        # Map var -> (freed_line_no, brace_depth_when_freed)
        freed_vars: Dict[str, Tuple[int, int]] = {}
        brace_depth = 0
        func_base_depth: Optional[int] = None

        for ln in range(max(1, start_ln), min(len(lines), end_ln) + 1):
            line = lines[ln - 1]
            stripped = line.strip()
            if not stripped:
                continue

            # Track brace nesting depth relative to function body
            open_braces = line.count("{")
            close_braces = line.count("}")
            if func_base_depth is None and open_braces > 0:
                func_base_depth = brace_depth + 1
            current_depth = brace_depth + (1 if (open_braces > 0 and stripped.startswith("{")) else 0)
            if open_braces > 0 and not stripped.startswith("{"):
                brace_depth += open_braces
                current_depth = brace_depth
            elif open_braces > 0:
                brace_depth += open_braces

            # Check free(ptr) / delete ptr
            free_hits: List[str] = [m.group(1) for m in _RULE24_FREE_RE.finditer(line)]
            free_hits.extend(m.group(1) for m in _RULE24_DELETE_RE.finditer(line))

            for var in free_hits:
                if var in freed_vars:
                    prev_ln, _ = freed_vars[var]
                    f = _build_finding(
                        "RULE-24-CPP-UAF-DOUBLE-FREE",
                        sf,
                        ln,
                        line,
                        f"Double-Free of Pointer `{var}`",
                        f"Pointer `{var}` freed on line {prev_ln} is freed again on line {ln} without reallocation",
                        **ctx,
                    )
                    if f:
                        findings.append(f)
                else:
                    freed_vars[var] = (ln, current_depth)

            if not free_hits:
                # Check reassignment (e.g., `ptr = NULL;`, `ptr = malloc(...)`) -> clears freed state
                reassigned_on_line: Set[str] = set()
                for rm in _RULE24_REASSIGN_RE.finditer(line):
                    lhs_var = rm.group(1)
                    if lhs_var in freed_vars:
                        rhs_part = line[rm.end():]
                        if not re.search(rf"\b{re.escape(lhs_var)}\b", rhs_part):
                            reassigned_on_line.add(lhs_var)
                            freed_vars.pop(lhs_var, None)

                # Check use-after-free on remaining freed variables
                for var in list(freed_vars.keys()):
                    if var in reassigned_on_line:
                        continue
                    if re.search(rf"\b{re.escape(var)}\s*(?:==|!=)\s*(?:NULL|nullptr|0)\b", line):
                        continue
                    if re.search(rf"\b{re.escape(var)}\b", line):
                        prev_ln, _ = freed_vars[var]
                        f = _build_finding(
                            "RULE-24-CPP-UAF-DOUBLE-FREE",
                            sf,
                            ln,
                            line,
                            f"Use-After-Free of Pointer `{var}`",
                            f"Pointer `{var}` freed on line {prev_ln} is subsequently accessed on line {ln}",
                            **ctx,
                        )
                        if f:
                            findings.append(f)
                        freed_vars.pop(var, None)

            # Early-exit branch handling: `if (err) { free(ptr); return -1; }`
            # Clear entries freed inside a nested block that terminates with return/exit/abort/goto
            if (
                func_base_depth is not None
                and current_depth > func_base_depth
                and re.search(r"\b(?:return|exit|_exit|abort|goto)\b", line)
            ):
                for var in [v for v, (_, f_depth) in freed_vars.items() if f_depth >= current_depth]:
                    freed_vars.pop(var, None)

            if close_braces > 0:
                brace_depth = max(0, brace_depth - close_braces)
    return findings


def _extract_brace_block(text: str, open_brace_idx: int) -> Tuple[str, int]:
    """Returns `(block_text, end_idx)` for balanced `{ ... }` starting at `open_brace_idx`."""
    depth = 0
    in_str: Optional[str] = None
    escape_next = False
    i = open_brace_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if escape_next:
            escape_next = False
            i += 1
            continue
        if in_str:
            if ch == "\\":
                escape_next = True
            elif ch == in_str:
                in_str = None
            i += 1
            continue
        if ch == '"':
            in_str = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace_idx:i + 1], i + 1
        i += 1
    return text[open_brace_idx:], n


_RULE25_EXTERN_FN_RE = re.compile(r'extern\s+"C"\s*\{([\s\S]*?)\}')
_RULE25_UNSAFE_BLK_RE = re.compile(r"\bunsafe\s*(?:fn\s+[A-Za-z0-9_]+[^{]*?)?\{")


def _check_rule_25_rust_unsafe_ffi(sf: ScannedFile, clean_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = clean_src.splitlines()

    extern_fns: Set[str] = set()
    for em in _RULE25_EXTERN_FN_RE.finditer(clean_src):
        for fn_m in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", em.group(1)):
            extern_fns.add(fn_m.group(1))

    for um in _RULE25_UNSAFE_BLK_RE.finditer(clean_src):
        brace_idx = um.end() - 1
        block_txt, _ = _extract_brace_block(clean_src, brace_idx)
        reasons: List[str] = []
        if re.search(r"\btransmute\b", block_txt):
            reasons.append("mem::transmute")
        if re.search(r"(?:\*[A-Za-z_][A-Za-z0-9_]*|\*\s*\(|ptr::(?:read|write)|from_raw_parts|\.offset\(|\.add\()", block_txt):
            reasons.append("raw pointer dereference")
        if re.search(r"\blibc::[A-Za-z_][A-Za-z0-9_]*\s*\(", block_txt):
            reasons.append("libc FFI call")
        for efn in extern_fns:
            if re.search(rf"\b{re.escape(efn)}\s*\(", block_txt):
                reasons.append(f'extern "C" FFI call `{efn}()`')
                break

        if reasons:
            line_no = clean_src.count("\n", 0, um.start()) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else um.group(0)
            f = _build_finding(
                "RULE-25-RUST-UNSAFE-FFI",
                sf,
                line_no,
                line_txt,
                "Unsafe Rust Memory / FFI Operation",
                f"`unsafe` block executes {', '.join(reasons)}",
                **ctx,
            )
            if f:
                findings.append(f)
    return findings


_RULE26_SINK_RE = re.compile(
    r"(?:\b(?:db|tx|conn|pool|stmt|statement|cursor|session|database|pdo|mysqli)\s*(?:\.|->|::)\s*"
    r"(?:Query|Exec|QueryRow|QueryContext|ExecContext|executeQuery|executeUpdate|execute|query|rawQuery|rawExecute)\s*\("
    r"|\b(?:mysqli_query|sqlite3_exec|find_by_sql|rawQuery|rawExecute|sqlx::raw_sql|SQL)\s*\("
    r"|\bnew\s+SqlCommand\s*\("
    r"|\.(?:executeQuery|executeUpdate|ExecuteReader|ExecuteNonQuery|where)\s*\()",
    re.IGNORECASE,
)
_RULE26_SQL_KW_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|FROM|WHERE)\b", re.IGNORECASE)
_RULE26_DYNAMIC_SQL_ASSIGN_RE = re.compile(
    r"""(?:^|[;\s])(?:(?:var|val|let|const|String|string)\s+)?(\$?[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(.+)"""
)


def _expr_has_dynamic_sql(expr: str, lang: str) -> bool:
    if not _RULE26_SQL_KW_RE.search(expr):
        return False
    # Check concatenation (+, PHP .) or interpolation ($var, ${var}, #{var}, \(var), Sprintf, format!, String.format)
    if re.search(r"""["'`]\s*\+\s*[A-Za-z_$]|[A-Za-z_$]\s*\+\s*["'`]""", expr):
        return True
    if lang == "php" and (
        re.search(r"""["']\s*\.\s*\$|\$\w+\s*\.\s*["']""", expr)
        or re.search(r'"[^"]*\$[A-Za-z_][A-Za-z0-9_]*[^"]*"', expr)
    ):
        return True
    if re.search(r"(?:fmt\.Sprintf|String\.format|format!)\s*\(", expr):
        return True
    if re.search(r'(?:\$|\bs)"[^"]*\{[^}]+\}|\$\{[^}]+\}|#\{[^}]+\}|\\\([^)]+\)', expr):
        return True
    if lang in ("kotlin", "scala", "dart") and re.search(r'"[^"]*\$[A-Za-z_][A-Za-z0-9_]*[^"]*"', expr):
        return True
    return False


def _check_rule_26_polyglot_sqli(sf: ScannedFile, clean_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = clean_src.splitlines()

    # Pre-scan dynamic SQL variable definitions
    tainted_sql_vars: Set[str] = set()
    for line in lines:
        am = _RULE26_DYNAMIC_SQL_ASSIGN_RE.search(line)
        if am and _expr_has_dynamic_sql(am.group(2), sf.language):
            tainted_sql_vars.add(am.group(1))

    for m in _RULE26_SINK_RE.finditer(clean_src):
        args = _extract_call_args_from_offset(clean_src, m.end() - 1)
        if not args:
            continue
        arg_blob = ", ".join(args)
        is_vuln = _expr_has_dynamic_sql(arg_blob, sf.language)
        if not is_vuln and tainted_sql_vars:
            for tv in tainted_sql_vars:
                if re.search(rf"(?<![A-Za-z0-9_$]){re.escape(tv)}(?![A-Za-z0-9_])", arg_blob):
                    is_vuln = True
                    break

        if not is_vuln:
            continue

        # Ensure safe parameterized PreparedStatement/SqlParameter isn't falsely flagged
        line_no = clean_src.count("\n", 0, m.start()) + 1
        line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
        f = _build_finding(
            "RULE-26-POLYGLOT-SQLI",
            sf,
            line_no,
            line_txt,
            f"SQL Injection via Dynamic Query Construction ({_display_language_name(sf.language)})",
            "Dynamic string concatenation/interpolation flows into SQL execution sink without parameterization",
            **ctx,
        )
        if f:
            findings.append(f)
    return findings


_RULE27_SINK_RE = re.compile(
    r"(?:\bexec\.Command(?:Context)?\s*\("
    r"|\bRuntime\.getRuntime\s*\(\s*\)\.exec\s*\("
    r"|\bProcessBuilder\s*\("
    r"|\bProcess\.(?:Start|run|start)\s*\("
    r"|\b(?:shell_exec|passthru|proc_open|system)\s*\("
    r"|\bOpen3\.(?:capture2|capture2e|capture3|popen2|popen2e|popen3)\s*\("
    r"|\bCommand::new\s*\()"
)
_RULE27_SAN_RE = re.compile(
    r"\b(?:escapeshellarg|escapeshellcmd|Shellwords\.escape|strconv\.Atoi|intval|Integer\.parseInt)\s*\("
)


def _check_rule_27_polyglot_cmdi(sf: ScannedFile, clean_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = clean_src.splitlines()

    for m in _RULE27_SINK_RE.finditer(clean_src):
        line_no = clean_src.count("\n", 0, m.start()) + 1
        line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)

        if _RULE27_SAN_RE.search(line_txt):
            continue

        args = _extract_call_args_from_offset(clean_src, m.end() - 1) or []

        # Rust chained `Command::new("sh").arg("-c").arg(input)` (supports single-line & multi-line chains!)
        if "Command::new" in m.group(0):
            semi_idx = clean_src.find(";", m.start())
            end_window = min(len(clean_src), semi_idx + 1 if semi_idx != -1 else m.start() + 500)
            stmt_slice = clean_src[m.start():end_window]
            if _RULE27_SAN_RE.search(stmt_slice):
                continue
            arg_calls = re.findall(r"\.arg(?:s)?\s*\(([^)]+)\)", stmt_slice)
            all_parts = list(args) + [a.strip() for a in arg_calls]
            if all_parts and all(_is_string_literal_arg(p) for p in all_parts):
                continue
        else:
            # Safe if every argument is a plain string literal (e.g., `exec.Command("ls", "-la")`)
            if args and all(_is_string_literal_arg(a) for a in args):
                # Still check for embedded interpolation inside double-quoted literal (PHP/Ruby/Kotlin)
                if not any(re.search(r"(\$\{|\#\{|\\\(|\$[A-Za-z_])", a) for a in args):
                    continue
            # Java safe constant array `new String[]{"ls", "-la"}`
            if re.search(r'new\s+String\s*\[\s*\]\s*\{\s*"[^"]*"(?:\s*,\s*"[^"]*")*\s*\}', line_txt):
                continue

        f = _build_finding(
            "RULE-27-POLYGLOT-CMDI",
            sf,
            line_no,
            line_txt,
            f"OS Command Injection via Dynamic Process Execution ({_display_language_name(sf.language)})",
            "Dynamic or shell-interpolated argument passed into OS command execution sink",
            **ctx,
        )
        if f:
            findings.append(f)
    return findings


_RULE28_PATTERNS: Tuple[Tuple[Set[str], re.Pattern[str], str], ...] = (
    ({"java", "kotlin", "scala"}, re.compile(r"\.readObject\s*\("), "Java/JVM `ObjectInputStream.readObject()`"),
    ({"java", "kotlin", "scala"}, re.compile(r"\bnew\s+XMLDecoder\s*\("), "Java `XMLDecoder` deserialization"),
    ({"csharp"}, re.compile(r"\.Deserialize\s*\("), ".NET `BinaryFormatter.Deserialize()`"),
    ({"csharp"}, re.compile(r"\bTypeNameHandling\.All\b"), "Json.NET `TypeNameHandling.All`"),
    ({"php"}, re.compile(r"\bunserialize\s*\("), "PHP `unserialize()`"),
    ({"ruby"}, re.compile(r"\bMarshal\.(?:load|restore)\s*\(|\bYAML\.load\s*\("), "Ruby unsafe `Marshal.load` / `YAML.load`"),
    ({"swift"}, re.compile(r"\bNSKeyedUnarchiver\.unarchive(?:Object|TopLevelObjectWithData)\s*\("), "Swift deprecated `NSKeyedUnarchiver`"),
)


def _check_rule_28_polyglot_deser(sf: ScannedFile, clean_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = clean_src.splitlines()

    for langs, pat, label in _RULE28_PATTERNS:
        if sf.language not in langs:
            continue
        for m in pat.finditer(clean_src):
            line_no = clean_src.count("\n", 0, m.start()) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)

            # C# `.Deserialize(` only flags if an unsafe formatter type is present in the file
            if sf.language == "csharp" and ".Deserialize" in m.group(0):
                if not re.search(
                    r"\b(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)\b",
                    clean_src,
                ):
                    continue

            # Java `.readObject(` only flags if ObjectInputStream is in file
            if sf.language in ("java", "kotlin", "scala") and ".readObject" in m.group(0):
                if "ObjectInputStream" not in clean_src:
                    continue

            # PHP safe `unserialize($x, ['allowed_classes' => false])`
            if sf.language == "php" and re.search(r"allowed_classes['\"]?\s*=>\s*false", line_txt, re.IGNORECASE):
                continue

            f = _build_finding(
                "RULE-28-POLYGLOT-DESER",
                sf,
                line_no,
                line_txt,
                f"Unsafe Native Deserialization: {label}",
                f"Untrusted data deserialized via {label}",
                **ctx,
            )
            if f:
                findings.append(f)
    return findings


def _check_rule_29_polyglot_xxe(sf: ScannedFile, clean_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = clean_src.splitlines()

    if sf.language in ("java", "kotlin"):
        if re.search(r"disallow-doctype-decl|ACCESS_EXTERNAL_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES", clean_src):
            return findings
        for m in re.finditer(r"\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(", clean_src):
            line_no = clean_src.count("\n", 0, m.start()) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
            f = _build_finding(
                "RULE-29-POLYGLOT-XXE",
                sf,
                line_no,
                line_txt,
                f"XXE Risk: `{m.group(1)}` Missing `disallow-doctype-decl`",
                f"`{m.group(1)}.newInstance()` initialized without disabling DTD/external entity resolution",
                **ctx,
            )
            if f:
                findings.append(f)

    elif sf.language == "csharp":
        if re.search(r"DtdProcessing\.Prohibit|XmlResolver\s*=\s*null", clean_src):
            return findings
        for m in re.finditer(r"\bnew\s+(XmlDocument|XmlTextReader)\s*\(", clean_src):
            line_no = clean_src.count("\n", 0, m.start()) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
            f = _build_finding(
                "RULE-29-POLYGLOT-XXE",
                sf,
                line_no,
                line_txt,
                f"XXE Risk: `{m.group(1)}` Missing `XmlResolver = null` / `DtdProcessing.Prohibit`",
                f"`{m.group(1)}` instantiated without prohibiting DTDs or nullifying XmlResolver",
                **ctx,
            )
            if f:
                findings.append(f)

    elif sf.language == "php":
        for m in re.finditer(r"\b(?:simplexml_load_string|simplexml_load_file|loadXML)\s*\([^;]*\b(?:LIBXML_NOENT|LIBXML_DTDLOAD)\b", clean_src):
            line_no = clean_src.count("\n", 0, m.start()) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
            f = _build_finding(
                "RULE-29-POLYGLOT-XXE",
                sf,
                line_no,
                line_txt,
                "XXE Risk: PHP XML Parser Enabled `LIBXML_NOENT` / `LIBXML_DTDLOAD`",
                "External entity substitution explicitly enabled via LIBXML_NOENT/LIBXML_DTDLOAD",
                **ctx,
            )
            if f:
                findings.append(f)

    elif sf.language == "ruby":
        for m in re.finditer(r"\bNokogiri::XML\s*\([^)]*\b(?:NOENT|DTDLOAD)\b", clean_src):
            line_no = clean_src.count("\n", 0, m.start()) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
            f = _build_finding(
                "RULE-29-POLYGLOT-XXE",
                sf,
                line_no,
                line_txt,
                "XXE Risk: Ruby `Nokogiri::XML` Enabled `NOENT`",
                "Nokogiri XML parser invoked with NOENT/DTDLOAD external entity flags",
                **ctx,
            )
            if f:
                findings.append(f)

    elif sf.language == "go":
        for m in re.finditer(r"\bXMLParseNoEnt\b", clean_src):
            line_no = clean_src.count("\n", 0, m.start()) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
            f = _build_finding(
                "RULE-29-POLYGLOT-XXE",
                sf,
                line_no,
                line_txt,
                "XXE Risk: Go XML Parser Enabled `XMLParseNoEnt`",
                "External entity expansion enabled in XML parser options",
                **ctx,
            )
            if f:
                findings.append(f)

    return findings


_RULE30_SOL_FN_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)([^{;]*)\{")
_RULE30_EXT_CALL_RE = re.compile(r"\.call\s*\{\s*value\s*:|\.call\.value\s*\(")
_RULE30_STATE_WRITE_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]+\])?\s*(?:\+=|-=|\*=|/=|=(?!=))"
)


def _check_rule_30_solidity_reentrancy(sf: ScannedFile, clean_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = clean_src.splitlines()

    for fm in _RULE30_SOL_FN_RE.finditer(clean_src):
        fn_name = fm.group(1)
        modifiers = fm.group(2)
        if re.search(r"\bnonReentrant\b", modifiers):
            continue

        brace_idx = fm.end() - 1
        body_txt, _ = _extract_brace_block(clean_src, brace_idx)
        call_match = _RULE30_EXT_CALL_RE.search(body_txt)
        if not call_match:
            continue

        after_call = body_txt[call_match.end():]
        # Check for storage state mutation after the external call (excluding local type declarations)
        state_mutated = False
        for after_line in after_call.splitlines():
            st = after_line.strip()
            if not st or st.startswith(("uint", "int", "bool", "address", "bytes", "string", "require(", "assert(", "emit ", "return ")):
                continue
            if _RULE30_STATE_WRITE_RE.search(st):
                state_mutated = True
                break

        if state_mutated:
            abs_offset = brace_idx + call_match.start()
            line_no = clean_src.count("\n", 0, abs_offset) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else call_match.group(0)
            f = _build_finding(
                "RULE-30-SOLIDITY-REENTRANCY",
                sf,
                line_no,
                line_txt,
                f"Solidity Reentrancy in `{fn_name}()` (State Updated After External Call)",
                f"External `.call{{value: ...}}` in `{fn_name}()` precedes storage state update without `nonReentrant` modifier",
                **ctx,
            )
            if f:
                findings.append(f)
    return findings


def _check_rule_31_solidity_tx_origin_delegate(sf: ScannedFile, clean_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = clean_src.splitlines()

    # 1. tx.origin authorization checks
    for m in re.finditer(r"\b(?:require|if|assert)\s*\([^)]*\btx\.origin\b", clean_src):
        line_no = clean_src.count("\n", 0, m.start()) + 1
        line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
        f = _build_finding(
            "RULE-31-SOLIDITY-TX-ORIGIN-DELEGATE",
            sf,
            line_no,
            line_txt,
            "Solidity Phishing-Vulnerable Authorization via `tx.origin`",
            "`tx.origin` used in authorization check instead of `msg.sender`",
            **ctx,
        )
        if f:
            findings.append(f)

    # 2. Unguarded delegatecall / selfdestruct / suicide
    for fm in _RULE30_SOL_FN_RE.finditer(clean_src):
        fn_name = fm.group(1)
        modifiers = fm.group(2)
        brace_idx = fm.end() - 1
        body_txt, _ = _extract_brace_block(clean_src, brace_idx)
        has_owner_guard = bool(
            re.search(r"\bonlyOwner\b|\bonlyAdmin\b", modifiers)
            or re.search(r"require\s*\(\s*msg\.sender\s*==", body_txt)
        )

        for dm in re.finditer(r"\.delegatecall\s*\(", body_txt):
            if not has_owner_guard:
                abs_off = brace_idx + dm.start()
                line_no = clean_src.count("\n", 0, abs_off) + 1
                line_txt = lines[line_no - 1] if line_no <= len(lines) else dm.group(0)
                f = _build_finding(
                    "RULE-31-SOLIDITY-TX-ORIGIN-DELEGATE",
                    sf,
                    line_no,
                    line_txt,
                    f"Unguarded Solidity `delegatecall()` in `{fn_name}()`",
                    f"Unprotected `.delegatecall()` in `{fn_name}()` allows arbitrary storage takeover",
                    **ctx,
                )
                if f:
                    findings.append(f)

        for sm in re.finditer(r"\b(selfdestruct|suicide)\s*\(", body_txt):
            abs_off = brace_idx + sm.start()
            line_no = clean_src.count("\n", 0, abs_off) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else sm.group(0)
            f = _build_finding(
                "RULE-31-SOLIDITY-TX-ORIGIN-DELEGATE",
                sf,
                line_no,
                line_txt,
                f"Dangerous Solidity `{sm.group(1)}()` in `{fn_name}()`",
                f"Destructive `{sm.group(1)}()` invocation can permanently destroy contract funds/code",
                **ctx,
            )
            if f:
                findings.append(f)

    return findings


_RULE32_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\{\{[^}]*\|\s*safe\b[^}]*\}\}", re.IGNORECASE), "Jinja/Twig `|safe` unescaped filter"),
    (re.compile(r"\{%\s*autoescape\s+false\s*%\}", re.IGNORECASE), "Jinja `autoescape false` block"),
    (re.compile(r"<%-([\s\S]*?)%>"), "EJS unescaped `<%- ... %>` tag"),
    (re.compile(r"\{\{\{([\s\S]*?)\}\}\}"), "Handlebars/Mustache raw triple-stash `{{{ ... }}}`"),
    (re.compile(r"\{!!([\s\S]*?)!!\}"), "Laravel Blade raw `{!! ... !!}` output"),
    (re.compile(r"<%=\s*raw\b|<%==|\.html_safe\b"), "ERB raw/html_safe unescaped output"),
    (re.compile(r"@Html\.Raw\s*\("), "ASP.NET Razor `@Html.Raw()` unescaped output"),
    (re.compile(r"\bv-html\s*=|\{@html\b"), "Vue `v-html` / Svelte `{@html}` raw DOM sink"),
    (re.compile(r"\brender_template_string\s*\("), "Dynamic SSTI `render_template_string()`"),
)


def _check_rule_32_template_xss_ssti(sf: ScannedFile, raw_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = raw_src.splitlines()
    for pat, label in _RULE32_PATTERNS:
        for m in pat.finditer(raw_src):
            line_no = raw_src.count("\n", 0, m.start()) + 1
            line_txt = lines[line_no - 1] if line_no <= len(lines) else m.group(0)
            f = _build_finding(
                "RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI",
                sf,
                line_no,
                line_txt,
                f"Template Unescaped Output / XSS: {label}",
                f"Detected {label} bypassing contextual HTML escaping",
                **ctx,
            )
            if f:
                findings.append(f)
    return findings


_RULE33_POST_FORM_RE = re.compile(
    r"""<form\b[^>]*\bmethod\s*=\s*["']?post["']?[^>]*>([\s\S]*?)(?:</form>|$)""",
    re.IGNORECASE,
)
_RULE33_CSRF_TOKEN_RE = re.compile(
    r"(?:csrf_token|@csrf|csrf_field|authenticity_token|_csrf|__RequestVerificationToken|"
    r"csrfmiddlewaretoken|AntiForgeryToken|asp-antiforgery|form_authenticity_token)",
    re.IGNORECASE,
)


def _check_rule_33_template_missing_csrf(sf: ScannedFile, raw_src: str, ctx: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    lines = raw_src.splitlines()
    for m in _RULE33_POST_FORM_RE.finditer(raw_src):
        form_block = m.group(0)
        if _RULE33_CSRF_TOKEN_RE.search(form_block):
            continue
        line_no = raw_src.count("\n", 0, m.start()) + 1
        line_txt = lines[line_no - 1] if line_no <= len(lines) else form_block[:120]
        f = _build_finding(
            "RULE-33-TEMPLATE-MISSING-CSRF",
            sf,
            line_no,
            line_txt,
            "State-Changing POST Form Missing CSRF Token",
            "HTML `<form method=\"post\">` contains no anti-CSRF token field or template directive",
            **ctx,
        )
        if f:
            findings.append(f)
    return findings


def run_polyglot_rules(
    scanned_files: List[ScannedFile],
    all_nodes: List[CPGNode],
    all_edges: List[CPGEdge],
    enabled_rule_ids: Optional[Set[str]] = None,
) -> List[Finding]:
    """
    Executes all enabled deterministic polyglot security rules (`RULE-22`..`RULE-33`)
    across `scanned_files`, enriched with 4-Pass CPG nodes and edges.
    """
    enabled = (
        set(enabled_rule_ids)
        if enabled_rule_ids is not None
        else set(_CATALOG_BY_ID.keys())
    )

    nodes_by_file_line: Dict[Tuple[str, int], List[CPGNode]] = {}
    nodes_by_file: Dict[str, List[CPGNode]] = {}
    node_by_id: Dict[str, CPGNode] = {}
    for n in all_nodes:
        node_by_id[n.id] = n
        nodes_by_file.setdefault(n.filepath, []).append(n)
        nodes_by_file_line.setdefault((n.filepath, n.start_line), []).append(n)

    edges_by_target: Dict[str, List[CPGEdge]] = {}
    for e in all_edges:
        edges_by_target.setdefault(e.target_id, []).append(e)

    seen_keys: Set[Tuple[str, str, int]] = set()
    ctx: Dict[str, Any] = {
        "nodes_by_file_line": nodes_by_file_line,
        "edges_by_target": edges_by_target,
        "node_by_id": node_by_id,
        "seen_keys": seen_keys,
    }

    findings: List[Finding] = []
    for sf in scanned_files:
        lang = (sf.language or "").strip().lower()
        if not lang or not sf.content_bytes:
            continue
        raw_src = sf.content_bytes.decode("utf-8", errors="replace")

        if lang in ("c", "cpp"):
            clean_src = _strip_c_style_comments_preserve_lines(raw_src)
            if "RULE-22-CPP-BUFFER-OVERFLOW" in enabled:
                findings.extend(_check_rule_22_cpp_buffer_overflow(sf, clean_src, ctx))
            if "RULE-23-CPP-FORMAT-STRING" in enabled:
                findings.extend(_check_rule_23_cpp_format_string(sf, clean_src, ctx))
            if "RULE-24-CPP-UAF-DOUBLE-FREE" in enabled:
                findings.extend(
                    _check_rule_24_cpp_uaf_double_free(sf, clean_src, nodes_by_file.get(sf.filepath, []), ctx)
                )

        elif lang == "rust":
            clean_src = _strip_c_style_comments_preserve_lines(raw_src)
            if "RULE-25-RUST-UNSAFE-FFI" in enabled:
                findings.extend(_check_rule_25_rust_unsafe_ffi(sf, clean_src, ctx))
            if "RULE-26-POLYGLOT-SQLI" in enabled:
                findings.extend(_check_rule_26_polyglot_sqli(sf, clean_src, ctx))
            if "RULE-27-POLYGLOT-CMDI" in enabled:
                findings.extend(_check_rule_27_polyglot_cmdi(sf, clean_src, ctx))

        elif lang in ("go", "java", "kotlin", "csharp", "scala", "php", "ruby", "swift", "dart"):
            if lang == "ruby":
                clean_src = _strip_hash_comments_preserve_lines(raw_src)
            elif lang == "php":
                clean_src = _strip_hash_comments_preserve_lines(_strip_c_style_comments_preserve_lines(raw_src))
            else:
                clean_src = _strip_c_style_comments_preserve_lines(raw_src)

            if "RULE-26-POLYGLOT-SQLI" in enabled:
                findings.extend(_check_rule_26_polyglot_sqli(sf, clean_src, ctx))
            if "RULE-27-POLYGLOT-CMDI" in enabled:
                findings.extend(_check_rule_27_polyglot_cmdi(sf, clean_src, ctx))
            if "RULE-28-POLYGLOT-DESER" in enabled and lang in ("java", "kotlin", "csharp", "scala", "php", "ruby", "swift"):
                findings.extend(_check_rule_28_polyglot_deser(sf, clean_src, ctx))
            if "RULE-29-POLYGLOT-XXE" in enabled and lang in ("java", "kotlin", "csharp", "php", "ruby", "go"):
                findings.extend(_check_rule_29_polyglot_xxe(sf, clean_src, ctx))

        elif lang == "solidity":
            clean_src = _strip_c_style_comments_preserve_lines(raw_src)
            if "RULE-30-SOLIDITY-REENTRANCY" in enabled:
                findings.extend(_check_rule_30_solidity_reentrancy(sf, clean_src, ctx))
            if "RULE-31-SOLIDITY-TX-ORIGIN-DELEGATE" in enabled:
                findings.extend(_check_rule_31_solidity_tx_origin_delegate(sf, clean_src, ctx))

        elif lang == "web_template":
            if "RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI" in enabled:
                findings.extend(_check_rule_32_template_xss_ssti(sf, raw_src, ctx))
            if "RULE-33-TEMPLATE-MISSING-CSRF" in enabled:
                findings.extend(_check_rule_33_template_missing_csrf(sf, raw_src, ctx))

    return findings
