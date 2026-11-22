"""
Pass 1: Unified 18-Language Tree-Sitter AST Normalization and Domain-Aware Taint Classification.
Normalizes AST into deterministic CPGNodes and AST_CHILD edges using the declarative LanguageSpec registry.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter
import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Parser

from compiler.language_registry import LANGUAGE_SPECS, LanguageSpec, get_parser_for_language
from compiler.scanner import ScannedFile
from models import CPGEdge, CPGNode, NodeLabel

logger = logging.getLogger("cpg-sast.compiler.ast")

# Preserve backward-compatible bundled Tree-sitter language & parser exports
PY_LANGUAGE = Language(tree_sitter_python.language())
JS_LANGUAGE = Language(tree_sitter_javascript.language())
TS_LANGUAGE = Language(tree_sitter_typescript.language_typescript())
TSX_LANGUAGE = Language(tree_sitter_typescript.language_tsx())

py_parser = Parser(PY_LANGUAGE)
js_parser = Parser(JS_LANGUAGE)
ts_parser = Parser(TS_LANGUAGE)
tsx_parser = Parser(TSX_LANGUAGE)

_BUNDLED_PARSERS: Dict[str, Parser] = {
    "python": py_parser,
    "javascript": js_parser,
    "typescript": ts_parser,
    "tsx": tsx_parser,
}

# Secondary PATH/URL sinks in Python/JS/TS/TSX: queried explicitly by RULE-10 / RULE-11 by name,
# so they receive `sink_domain` metadata without setting primary execution `is_sink=True`
# (which would otherwise cause RULE-1 CWE-78 / RULE-2 orphan false positives on benign file/HTTP helpers).
_SECONDARY_NON_PRIMARY_SINKS: Dict[str, Set[str]] = {
    "python": {"open", "requests.get", "urllib.request.urlopen"},
    "javascript": {"fetch", "axios.get", "axios.post", "fs.readFile", "fs.readFileSync"},
    "typescript": {"fetch", "axios.get", "axios.post", "fs.readFile", "fs.readFileSync"},
    "tsx": {"fetch", "axios.get", "axios.post", "fs.readFile", "fs.readFileSync"},
}

# Backward-compatible taint catalog exports
SOURCE_PATTERNS = {
    "request.args", "request.form", "request.json", "request.values", "request.cookies",
    "request.GET", "request.POST", "req.query", "req.body", "req.params",
    "request.nextUrl.searchParams", "sys.argv", "input",
    "fastapi.Query", "fastapi.Body",
}

SINK_PATTERNS = {
    "cursor.execute", "session.execute",
    "os.system", "subprocess.Popen", "subprocess.run", "subprocess.call",
    "eval", "exec", "pickle.loads", "yaml.load", "render_template_string",
    "document.write", "document.writeln", ".innerHTML", ".outerHTML", "dangerouslySetInnerHTML",
}

SANITIZER_PATTERNS = {
    "int", "float", "bool", "shlex.quote", "html.escape", "bleach.clean", "urllib.parse.quote",
    "DOMPurify.sanitize", "encodeURIComponent", "esc", "escapeHtml",
    "os.path.commonpath", "os.path.basename", "path.basename", "secure_filename",
    "yaml.safe_load", "uuid.uuid4", "ast.literal_eval",
    "defusedxml.ElementTree.fromstring", "secrets.token_urlsafe", "secrets.token_hex",
}

HTTP_ROUTE_DECORATOR_TOKENS = (
    "@app.get", "@app.post", "@app.put", "@app.delete", "@app.patch", "@app.route",
    "@router.get", "@router.post", "@router.put", "@router.delete", "@router.patch", "@router.route",
    "@blueprint.route", "@bp.route",
)

SAFE_PRIMITIVE_PARAM_TYPES = {
    "int", "float", "bool", "Optional[int]", "Optional[float]", "Optional[bool]",
}

DI_EXCLUDED_PARAM_NAMES = {
    "self", "cls", "db", "session", "background_tasks", "current_user", "response",
}

# Inline sanitizer token -> sanitizer domains
INLINE_SANITIZER_DOMAIN_MAP: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("shlex.quote(", ("SHELL",)),
    ("os.path.basename(", ("PATH",)),
    ("path.basename(", ("PATH",)),
    ("os.path.commonpath(", ("PATH",)),
    ("secure_filename(", ("PATH",)),
    ("filepath.Clean(", ("PATH",)),
    ("filepath.Base(", ("PATH",)),
    ("Path.GetFileName(", ("PATH",)),
    ("ast.literal_eval(", ("CODE",)),
    ("yaml.safe_load(", ("DESER",)),
    ("YAML.safe_load(", ("DESER",)),
    ("DOMPurify.sanitize(", ("HTML",)),
    ("html.escape(", ("HTML",)),
    ("bleach.clean(", ("HTML",)),
    ("html.EscapeString(", ("HTML",)),
    ("HtmlUtils.htmlEscape(", ("HTML",)),
    ("HtmlEncoder.Default.Encode(", ("HTML",)),
    ("htmlspecialchars(", ("HTML",)),
    ("htmlentities(", ("HTML",)),
    ("escapeshellarg(", ("SHELL",)),
    ("Shellwords.escape(", ("SHELL",)),
    ("urllib.parse.quote(", ("URL",)),
    ("encodeURIComponent(", ("URL",)),
    ("encodeURI(", ("URL",)),
    ("url.QueryEscape(", ("URL",)),
    ("secrets.token_urlsafe(", ("UNIVERSAL",)),
    ("secrets.token_hex(", ("UNIVERSAL",)),
    ("uuid.uuid4(", ("UNIVERSAL",)),
    ("strconv.Atoi(", ("UNIVERSAL",)),
    ("strconv.ParseInt(", ("UNIVERSAL",)),
    ("Integer.parseInt(", ("UNIVERSAL",)),
    ("int.Parse(", ("UNIVERSAL",)),
    ("int.TryParse(", ("UNIVERSAL",)),
    ("intval(", ("UNIVERSAL",)),
    ("defusedxml.", ("XML",)),
    ('.replace("\\r"', ("LOG",)),
    (".replace('\\r'", ("LOG",)),
    ('filter="data"', ("PATH",)),
    ("filter='data'", ("PATH",)),
)

# HTML/URL/UNIVERSAL sanitizer prefixes recognized inside template expressions
_HTML_SAFE_CALL_PREFIXES = (
    "esc(",
    "escape(",
    "escapeHtml(",
    "DOMPurify.sanitize(",
    "encodeURIComponent(",
    "encodeURI(",
    "Number(",
    "parseInt(",
    "parseFloat(",
    "Boolean(",
    "Math.",
)

# URL attribute interpolation bypass detector (href/src/action/formaction starting directly with ${...})
_UNSAFE_URI_ATTR_RE = re.compile(
    r"""(?i)\b(?:href|src|action|formaction)\s*=\s*["']\s*\$\{([^}]+)\}"""
)
_URL_VALIDATOR_PREFIXES = ("safeUrl(", "sanitizeUrl(", "validateUrl(", "allowlistedUrl(")

# Non-semantic / trivia AST node types skipped across languages
_GLOBAL_SKIP_TYPES: Set[str] = {
    "interface_declaration",
    "type_alias_declaration",
    "type_annotation",
    "type_arguments",
    "type_parameters",
    "import_statement",
    "import_from_statement",
    "comment",
    "line_comment",
    "block_comment",
    "multiline_comment",
    "documentation_comment",
    "jsx_text",
    "jsx_closing_element",
    "string_content",
    "string_start",
    "string_end",
    "string_fragment",
    "escape_sequence",
    "package_clause",
    "package_declaration",
    "package_header",
    "pragma_directive",
    "doctype",
}

# Wrapper/expression AST types that are traversed through rather than emitted as primary CPGNodes
_TRANSPARENT_NODE_TYPES: Set[str] = {
    "string_content", "string_start", "string_end", "string_fragment", "escape_sequence",
    "string", "integer", "float", "number", "true", "false", "none", "null", "boolean",
    "string_literal", "interpreted_string_literal", "raw_string_literal", "line_string_literal",
    "int_literal", "integer_literal", "decimal_integer_literal", "float_literal", "number_literal",
    "boolean_literal", "null_literal", "nil", "nullptr", "char_literal",
    "template_string", "template_substitution", "interpolation",
    "binary_expression", "boolean_operator", "comparison_operator", "not_operator",
    "unary_expression", "conditional_expression", "ternary_expression", "await_expression",
    "spread_element", "as_expression", "satisfies_expression", "non_null_expression",
    "comment", "line_comment", "block_comment", "multiline_comment", "documentation_comment",
    "jsx_element", "jsx_opening_element", "jsx_closing_element", "jsx_self_closing_element",
    "jsx_attribute", "jsx_expression", "jsx_text",
    "type", "type_annotation", "type_identifier", "predefined_type", "primitive_type",
    "type_arguments", "type_parameters", "interface_declaration", "type_alias_declaration",
    "property_signature", "user_type", "reference_type", "void_type", "type_qualifier",
    "import_statement", "import_from_statement", "import_specifier", "import_clause",
    "named_imports", "dotted_name", "import_declaration", "import_header", "using_directive",
    "use_declaration", "preproc_include", "namespace_use_declaration", "import_directive",
    "argument_list", "arguments", "pair", "keyword_argument", "value_arguments", "value_argument",
    "call_suffix", "argument_part", "argument",
    "dictionary", "list", "tuple", "set", "object", "array",
    "parenthesized_expression", "expression_statement",
    "lexical_declaration", "variable_declaration", "local_variable_declaration",
    "local_declaration_statement", "declaration", "decorator",
    "statement_list", "statements", "expression_list",
    "php_tag", "php_end_tag", "text_interpolation", "visibility", "return_type_definition",
    "type_name", "start_tag", "end_tag", "raw_text",
}

# Short patterns requiring strict call/identifier boundary matching to prevent false positives
_STRICT_BOUNDARY_PATTERNS: Set[str] = {
    "input", "eval", "exec", "Function", "open", "free", "delete", "gets", "read",
    "args", "argv", "cin", "stdin", "send", "system", "include", "require", "unsafe",
    "int", "float", "bool", "esc", "escape", "prepare", "basename", "normalize",
    "toInt", "toLong", "to_i", "to_f", "intval", "floatval", "atoi", "strtol",
    "Number", "parseInt", "parseFloat", "Boolean",
}

# Template expression scanner for web_template files
_WEB_TEMPLATE_EXPR_RE = re.compile(
    r"(\{\{\{[\s\S]*?\}\}\}|\{\{[\s\S]*?\}\}|\{%[\s\S]*?%\}|<%-[\s\S]*?%>|<%=[\s\S]*?%>|\{!![\s\S]*?!!\}|@Html\.Raw\s*\([^)]*\)|<form\b[^>]*>)",
    re.IGNORECASE,
)


def compute_node_id(filepath: str, node_type: str, start_byte: int, end_byte: int) -> str:
    """Deterministic SHA256 ID truncated to 24 hex characters."""
    token = f"{filepath}:{node_type}:{start_byte}:{end_byte}"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


def compute_edge_id(source_id: str, target_id: str, edge_type: str) -> str:
    """Deterministic SHA256 Edge ID."""
    token = f"{source_id}:{target_id}:{edge_type}"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


def has_unsafe_uri_interpolation(text: str) -> bool:
    """
    Detects HTML-entity-only or raw interpolation directly at the start of a URI attribute
    (e.g., `<a href="${esc(url)}">`, `<img src="${escapeHtml(u)}">`, `<form action="${url}">`).
    HTML entity escaping does NOT block `javascript:` or `data:` URI scheme execution.
    """
    if not text:
        return False
    for match in _UNSAFE_URI_ATTR_RE.finditer(text):
        expr = match.group(1).strip()
        if any(expr.startswith(prefix) for prefix in _URL_VALIDATOR_PREFIXES):
            continue
        return True
    return False


def _split_top_level(expr: str, sep: str) -> List[str]:
    """Splits an expression by a separator at paren/bracket/quote nesting depth 0."""
    parts: List[str] = []
    depth_paren = 0
    depth_bracket = 0
    depth_brace = 0
    in_quote: Optional[str] = None
    escape_next = False
    start = 0
    i = 0
    sep_len = len(sep)
    n = len(expr)

    while i < n:
        ch = expr[i]
        if escape_next:
            escape_next = False
            i += 1
            continue
        if in_quote:
            if ch == "\\":
                escape_next = True
            elif ch == in_quote:
                in_quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            in_quote = ch
        elif ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif ch == "[":
            depth_bracket += 1
        elif ch == "]":
            depth_bracket = max(0, depth_bracket - 1)
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace = max(0, depth_brace - 1)
        elif (
            depth_paren == 0
            and depth_bracket == 0
            and depth_brace == 0
            and expr[i:i + sep_len] == sep
        ):
            # Guard against splitting '===' on '==' or '||' on '|'
            if sep == "+" and ((i > 0 and expr[i - 1] == "+") or (i + 1 < n and expr[i + 1] == "+")):
                i += 1
                continue
            parts.append(expr[start:i])
            i += sep_len
            start = i
            continue
        i += 1

    parts.append(expr[start:])
    return parts


def _split_top_level_ternary(expr: str) -> Optional[Tuple[str, str, str]]:
    """Splits `cond ? true_branch : false_branch` at top level, returning None if not a ternary."""
    depth_paren = 0
    depth_bracket = 0
    depth_brace = 0
    in_quote: Optional[str] = None
    escape_next = False
    q_idx = -1
    ternary_depth = 0

    for i, ch in enumerate(expr):
        if escape_next:
            escape_next = False
            continue
        if in_quote:
            if ch == "\\":
                escape_next = True
            elif ch == in_quote:
                in_quote = None
            continue
        if ch in ("'", '"', "`"):
            in_quote = ch
        elif ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif ch == "[":
            depth_bracket += 1
        elif ch == "]":
            depth_bracket = max(0, depth_bracket - 1)
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace = max(0, depth_brace - 1)
        elif depth_paren == 0 and depth_bracket == 0 and depth_brace == 0:
            if ch == "?":
                # Ignore optional chaining '?.' and nullish coalescing '??'
                next_ch = expr[i + 1] if i + 1 < len(expr) else ""
                prev_ch = expr[i - 1] if i > 0 else ""
                if next_ch in (".", "?") or prev_ch == "?":
                    continue
                if q_idx == -1:
                    q_idx = i
                ternary_depth += 1
            elif ch == ":" and q_idx != -1:
                ternary_depth -= 1
                if ternary_depth == 0:
                    return expr[:q_idx].strip(), expr[q_idx + 1:i].strip(), expr[i + 1:].strip()
    return None


def _is_balanced_single_call(expr: str) -> bool:
    """Checks whether `expr` is a single function call `fn(...)` spanning the entire string."""
    open_idx = expr.find("(")
    if open_idx <= 0 or not expr.endswith(")"):
        return False
    depth = 0
    in_quote: Optional[str] = None
    escape_next = False
    for i in range(open_idx, len(expr)):
        ch = expr[i]
        if escape_next:
            escape_next = False
            continue
        if in_quote:
            if ch == "\\":
                escape_next = True
            elif ch == in_quote:
                in_quote = None
            continue
        if ch in ("'", '"', "`"):
            in_quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and i != len(expr) - 1:
                return False
    return depth == 0


def _is_structurally_safe_html_expr(expr: str) -> bool:
    """
    Purely structural (non-app-specific) predicate determining whether an interpolated JS/TS
    expression cannot inject raw HTML markup:
    - String / numeric / boolean / null literals
    - Uppercase constants (e.g. MAX_ITEMS)
    - HTML / URL / numeric sanitizer calls (esc, escape, escapeHtml, DOMPurify.sanitize,
      encodeURIComponent, encodeURI, Number, parseInt, parseFloat, Boolean, Math.*)
    - Pure `.length` property access or pure comparison (`===`, `!==`, `>`, `<`, `>=`, `<=`)
    - Ternaries / concatenations / fallbacks whose result branches are all structurally safe.
    """
    e = (expr or "").strip()
    if not e:
        return True

    # Unwrap outer balanced parentheses
    while e.startswith("(") and e.endswith(")"):
        depth = 0
        wraps_all = True
        for i, ch in enumerate(e):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(e) - 1:
                    wraps_all = False
                    break
        if wraps_all and depth == 0:
            e = e[1:-1].strip()
        else:
            break

    # 1. Pure literals (quoted strings, non-interpolated template literals, numbers, booleans)
    if (e.startswith("'") and e.endswith("'") and "'" not in e[1:-1].replace("\\'", "")) or (
        e.startswith('"') and e.endswith('"') and '"' not in e[1:-1].replace('\\"', "")
    ):
        return True
    if e.startswith("`") and e.endswith("`") and "${" not in e:
        return True
    if re.fullmatch(r"-?\d+(?:\.\d+)?", e) or e in ("true", "false", "null", "undefined"):
        return True

    # 2. Uppercase constants (e.g., MAX_RETRIES, STATUS_OK)
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", e):
        return True

    # 3. Ternary: both result branches must be structurally safe
    ternary = _split_top_level_ternary(e)
    if ternary is not None:
        _, true_br, false_br = ternary
        return _is_structurally_safe_html_expr(true_br) and _is_structurally_safe_html_expr(false_br)

    # 4. Top-level binary concatenation / fallback operators (+, ||, ??)
    for op in ("??", "||", "+"):
        parts = _split_top_level(e, op)
        if len(parts) > 1:
            return all(_is_structurally_safe_html_expr(p) for p in parts)

    # 5. Pure `.length` access or numeric/sanitizer calls spanning the whole expression
    if re.fullmatch(r"[A-Za-z_$][\w$.?\]]*\.length", e):
        return True
    if any(e.startswith(prefix) for prefix in _HTML_SAFE_CALL_PREFIXES) and _is_balanced_single_call(e):
        return True

    # 6. Pure comparison returning boolean (`a === b`, `n > 1`, `x !== 0`)
    if any(cmp_op in e for cmp_op in ("===", "!==", ">=", "<=", "==", "!=", ">", "<")):
        if not any(ch in e for ch in ("?", "`")):
            return True

    # 7. Nested template literal whose every `${...}` is structurally safe (and no unsafe href=)
    if e.startswith("`") and e.endswith("`") and "${" in e:
        if has_unsafe_uri_interpolation(e):
            return False
        interps = _extract_template_interpolations(e)
        return bool(interps) and all(_is_structurally_safe_html_expr(sub) for sub in interps)

    return False


def _extract_template_interpolations(template_text: str) -> List[str]:
    """Extracts `${ ... }` expression strings from a JS/TS template literal handling nested braces."""
    results: List[str] = []
    i = 0
    n = len(template_text)
    while i < n - 1:
        if template_text[i] == "$" and template_text[i + 1] == "{":
            start = i + 2
            depth = 1
            j = start
            in_quote: Optional[str] = None
            escape_next = False
            while j < n and depth > 0:
                ch = template_text[j]
                if escape_next:
                    escape_next = False
                elif in_quote:
                    if ch == "\\":
                        escape_next = True
                    elif ch == in_quote:
                        in_quote = None
                else:
                    if ch in ("'", '"', "`"):
                        in_quote = ch
                    elif ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                j += 1
            if depth == 0:
                results.append(template_text[start:j - 1])
            i = j
        else:
            i += 1
    return results


def _analyze_html_assignment(raw_text: str) -> Tuple[bool, Optional[str]]:
    """
    Sound structural analyzer for `.innerHTML` / `.outerHTML` / `dangerouslySetInnerHTML` assignments.
    Returns `(is_unsafe, sink_domain)` where `sink_domain` is:
      - `"URL"` when a URI attribute (`href=`/`src=`/`action=`) interpolates an HTML-only escaper or raw value
      - `"HTML"` for all other dynamic HTML assignments (resolved in Pass 3 by DFGBuilder if sanitized)
      - `None` when statically proven safe in Pass 1.
    """
    if "=" not in raw_text:
        return False, None
    rhs = raw_text.split("=", 1)[1].strip().rstrip(";").strip()
    if not rhs:
        return False, None

    # Rule 1: Pure static string literal or non-interpolated template literal -> safe
    if (rhs.startswith("'") and rhs.endswith("'") and "+" not in rhs) or (
        rhs.startswith('"') and rhs.endswith('"') and "+" not in rhs
    ):
        return False, None
    if rhs.startswith("`") and rhs.endswith("`") and "${" not in rhs:
        return False, None

    # Rule 2: <a href="${esc(...)}"> / src= / action= URI scheme injection -> ALWAYS UNSAFE with sink_domain="URL"
    if has_unsafe_uri_interpolation(rhs):
        return True, "URL"

    # Rule 3: Structurally safe expression (direct HTML sanitizer call, numeric/boolean, or safe template literal)
    if _is_structurally_safe_html_expr(rhs):
        return False, None

    # Rule 3b: `.map(... => `...`).join(...)` where every template interpolation is structurally safe
    if "`" in rhs and "${" in rhs and ".map(" in rhs:
        interps = _extract_template_interpolations(rhs)
        if interps and all(_is_structurally_safe_html_expr(expr) for expr in interps):
            return False, None

    # Rule 4: All other dynamic assignments (including variable RHS like `el.innerHTML = safeCard`)
    # are initially tagged `is_sink=True, sink_domain="HTML"` and cleared in Pass 3 if proven sanitized.
    return True, "HTML"


def _is_unsafe_html_assignment(raw_text: str) -> bool:
    """Backward-compatible boolean wrapper over `_analyze_html_assignment`."""
    is_unsafe, _ = _analyze_html_assignment(raw_text)
    return is_unsafe


def _matches_pattern(pattern: str, clean_code: str, clean_raw: str) -> bool:
    """Matches a taint pattern cleanly with word/call boundary awareness for short identifiers."""
    if pattern in _STRICT_BOUNDARY_PATTERNS:
        if (
            clean_code == pattern
            or clean_raw == pattern
            or clean_code.startswith(f"{pattern}(")
            or clean_raw.startswith(f"{pattern}(")
            or clean_code.startswith(f"{pattern}[")
            or clean_raw.startswith(f"{pattern}[")
        ):
            return True
        if pattern in ("toInt", "toLong", "to_i", "to_f", "normalize", "prepare"):
            if f".{pattern}(" in clean_raw or clean_raw.endswith(f".{pattern}"):
                return True
        if pattern in ("delete", "unsafe", "cin"):
            return bool(re.search(rf"\b{re.escape(pattern)}\b", clean_raw))
        return False
    return pattern in clean_code or pattern in clean_raw


def classify_taint_with_domains(
    code_snippet: str,
    node_type: str,
    raw_text: str,
    language: str = "python",
) -> Tuple[bool, bool, bool, Optional[str], List[str]]:
    """
    Classifies an AST node into `(is_source, is_sink, is_sanitizer, sink_domain, sanitizer_domains)`
    using the declarative `LanguageSpec` for `language`.
    """
    clean_code = code_snippet.strip()
    clean_raw = raw_text.strip()

    lang_key = (language or "python").strip().lower()
    spec = LANGUAGE_SPECS.get(lang_key)

    is_source = False
    is_sink = False
    is_sanitizer = False
    sink_domain: Optional[str] = None
    sanitizer_domains: List[str] = []

    source_patterns = spec.source_patterns if spec else tuple(SOURCE_PATTERNS)
    sink_domain_map = spec.sink_domain_map if spec else {p: "CODE" for p in SINK_PATTERNS}
    sanitizer_domain_map = (
        spec.sanitizer_domain_map if spec else {p: ("UNIVERSAL",) for p in SANITIZER_PATTERNS}
    )

    source_allowed_types = {
        "subscript", "subscript_expression", "attribute", "member_expression",
        "call", "call_expression", "method_invocation", "invocation_expression",
        "function_call_expression", "member_call_expression", "scoped_call_expression",
        "identifier", "simple_identifier", "variable_name", "field_identifier",
        "parameter", "formal_parameter", "parameter_declaration", "simple_parameter",
        "element", "template_expression",
    }
    call_or_member_types = {
        "call", "call_expression", "new_expression", "method_invocation",
        "object_creation_expression", "invocation_expression",
        "function_call_expression", "member_call_expression", "scoped_call_expression",
        "macro_invocation", "selector", "attribute", "member_expression",
        "delete_expression", "unsafe_block", "element", "template_expression",
    }
    assign_types = {
        "assignment", "assignment_expression", "augmented_assignment",
        "augmented_assignment_expression", "variable_declarator",
        "short_var_declaration", "let_declaration", "init_declarator",
        "property_declaration", "val_definition", "var_definition",
        "initialized_variable_definition", "variable_declaration_statement",
        "assignment_statement", "var_spec", "operator_assignment",
    }

    # 1. Sources
    for sp in source_patterns:
        if node_type in source_allowed_types and _matches_pattern(sp, clean_code, clean_raw):
            is_source = True
            break

    # 2. Sinks & sink_domain
    is_html_dom_assign = False
    for sp, domain in sink_domain_map.items():
        if sp in (".innerHTML", ".outerHTML", "dangerouslySetInnerHTML"):
            if node_type in assign_types:
                left_part = clean_code.split("=", 1)[0].strip()
                if (
                    left_part.endswith(".innerHTML")
                    or left_part.endswith(".outerHTML")
                    or left_part == "dangerouslySetInnerHTML"
                ):
                    is_html_dom_assign = True
                    unsafe_html, html_domain = _analyze_html_assignment(clean_raw)
                    if unsafe_html:
                        is_sink = True
                        sink_domain = html_domain or "HTML"
                    break
        elif sp in ("eval", "exec", "Function"):
            if node_type in call_or_member_types and (
                clean_code == sp
                or clean_code.startswith(f"{sp}(")
                or clean_raw == sp
                or clean_raw.startswith(f"{sp}(")
                or (sp == "Function" and clean_raw.startswith("new Function("))
            ):
                is_sink = True
                sink_domain = domain
                break
        elif sp in ("subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_output"):
            if node_type in call_or_member_types and (sp in clean_code or sp in clean_raw):
                if "shell=False" in clean_raw and "shell=True" not in clean_raw and (
                    "shlex.quote(" in clean_raw or "shlex.split(" in clean_raw or "[" in clean_raw
                ):
                    is_sanitizer = True
                    sanitizer_domains = ["SHELL"]
                else:
                    is_sink = True
                    sink_domain = domain
                break
        elif sp in ("cursor.execute", "session.execute"):
            if node_type in call_or_member_types and (sp in clean_code or sp in clean_raw):
                if (
                    ("?" in clean_raw or "%s" in clean_raw)
                    and 'f"' not in clean_raw
                    and "f'" not in clean_raw
                    and ".format(" not in clean_raw
                    and " + " not in clean_raw
                ):
                    is_sanitizer = True
                    sanitizer_domains = ["SQL"]
                else:
                    is_sink = True
                    sink_domain = domain
                break
        elif node_type in call_or_member_types and _matches_pattern(sp, clean_code, clean_raw):
            # Sound structural exemption for URL/SSRF sinks with a constant literal URL first argument
            # (e.g., `requests.get("https://api.example.com/v1", params={"q": user_q})` cannot redirect host/origin)
            if domain == "URL" and re.search(
                r"""\(\s*(?:"https?://[^"$`{}+]*"|'https?://[^'$`{}+]*')\s*(?:,|\))""",
                clean_raw,
            ):
                is_sanitizer = True
                if "URL" not in sanitizer_domains:
                    sanitizer_domains.append("URL")
                break
            sink_domain = domain
            if sp not in _SECONDARY_NON_PRIMARY_SINKS.get(lang_key, set()):
                is_sink = True
            break

    # 3. Sanitizers & sanitizer_domains
    # Never mark a flagged unsafe HTML/URL DOM assignment or any expression with unsafe URI
    # attribute interpolation (`href="${esc(...)}"`) as a sanitizer!
    # For variable assignments containing JS/TS template interpolations (`${...}`), defer
    # sanitization classification to Pass 3 (DFGBuilder) so partial escaping cannot mask
    # unescaped sibling interpolations or unsafe href attributes.
    is_unsafe_uri_expr = has_unsafe_uri_interpolation(clean_raw)
    is_template_assignment = (node_type in assign_types) and ("${" in clean_raw)
    if not (is_html_dom_assign and is_sink) and not is_unsafe_uri_expr and not is_template_assignment:
        for san, domains in sanitizer_domain_map.items():
            if _matches_pattern(san, clean_code, clean_raw):
                # Avoid falsely marking a whole function/block as sanitizer just because it contains a sanitizer
                if node_type in call_or_member_types or node_type in assign_types or node_type in (
                    "identifier", "simple_identifier", "attribute", "template_expression",
                ):
                    is_sanitizer = True
                    for d in domains:
                        if d not in sanitizer_domains:
                            sanitizer_domains.append(d)
                    break

        if not is_sanitizer and (node_type in call_or_member_types or node_type in assign_types):
            for inline_san, domains in INLINE_SANITIZER_DOMAIN_MAP:
                if inline_san in clean_raw:
                    is_sanitizer = True
                    for d in domains:
                        if d not in sanitizer_domains:
                            sanitizer_domains.append(d)
                    break

    if is_sanitizer:
        is_sink = False
        is_source = False
        sink_domain = None

    return is_source, is_sink, is_sanitizer, sink_domain, sanitizer_domains


def classify_taint(
    code_snippet: str,
    node_type: str,
    raw_text: str,
    language: str = "python",
) -> Tuple[bool, bool, bool]:
    """Backward-compatible taint classifier returning `(is_source, is_sink, is_sanitizer)`."""
    is_source, is_sink, is_sanitizer, _, _ = classify_taint_with_domains(
        code_snippet, node_type, raw_text, language=language
    )
    return is_source, is_sink, is_sanitizer


def map_node_label(
    node_type: str,
    parent_type: Optional[str] = None,
    spec: Optional[LanguageSpec] = None,
) -> NodeLabel:
    """Maps a Tree-sitter AST node type to a canonical CPG NodeLabel."""
    if spec is not None:
        if node_type in spec.module_node_types:
            return "Module"
        if node_type in spec.class_node_types:
            return "Class"
        if node_type in spec.function_node_types:
            return "Function"
        if node_type in spec.parameter_node_types:
            return "Parameter"
        if node_type in spec.assignment_node_types:
            return "Assignment"
        if node_type in spec.call_node_types:
            return "Call"
        if node_type in spec.control_node_types:
            return "ControlBlock"
        if node_type in spec.loop_node_types:
            return "LoopBlock"
        if node_type in spec.return_node_types:
            return "Return"
        if node_type in spec.identifier_node_types:
            if parent_type and parent_type in spec.parameter_node_types:
                return "Parameter"
            return "Variable"
        if node_type in spec.literal_node_types:
            return "Literal"

    # Default fallback mapping (backward compatible for spec=None)
    if node_type in ("module", "program", "source_file", "compilation_unit", "translation_unit", "document"):
        return "Module"
    if node_type in ("class_definition", "class_declaration", "contract_declaration", "struct_item", "object_definition"):
        return "Class"
    if node_type in (
        "function_definition", "method_definition", "function_declaration", "method_declaration",
        "arrow_function", "function_expression", "generator_function_declaration", "generator_function",
        "function_item", "method", "function_signature", "constructor_declaration",
    ):
        return "Function"
    if node_type in (
        "parameters", "parameter", "formal_parameters", "typed_parameter", "default_parameter",
        "parameter_declaration", "formal_parameter", "simple_parameter", "normal_formal_parameter",
    ):
        return "Parameter"
    if node_type in (
        "assignment", "augmented_assignment", "variable_declarator",
        "assignment_expression", "augmented_assignment_expression",
        "short_var_declaration", "let_declaration", "init_declarator",
        "property_declaration", "val_definition", "var_definition",
        "initialized_variable_definition", "variable_declaration_statement",
        "assignment_statement",
    ):
        return "Assignment"
    if node_type in (
        "call", "call_expression", "method_invocation", "invocation_expression",
        "function_call_expression", "member_call_expression", "scoped_call_expression",
        "macro_invocation", "new_expression", "object_creation_expression",
    ):
        return "Call"
    if node_type in ("if_statement", "elif_clause", "else_clause", "switch_statement", "if_expression", "if"):
        return "ControlBlock"
    if node_type in ("while_statement", "for_statement", "for_in_statement", "do_statement", "while_expression", "for_expression", "while"):
        return "LoopBlock"
    if node_type in ("return_statement", "return_expression", "return", "jump_expression", "control_transfer_statement"):
        return "Return"
    if node_type in ("identifier", "variable_name", "property_identifier", "simple_identifier", "field_identifier", "name"):
        if parent_type in ("parameters", "formal_parameters", "default_parameter", "typed_parameter", "parameter", "formal_parameter", "parameter_declaration"):
            return "Parameter"
        return "Variable"
    if node_type in ("integer", "float", "number", "string", "true", "false", "none", "null", "boolean"):
        return "Literal"
    return "Variable"


def _unwrap_c_declarator_name(ts_node: Optional[tree_sitter.Node]) -> Optional[str]:
    """Unwraps C/C++ declarators (function_declarator, pointer_declarator, reference_declarator) to the identifier."""
    curr = ts_node
    depth = 0
    while curr is not None and depth < 8:
        depth += 1
        if curr.type in ("identifier", "field_identifier", "qualified_identifier", "destructor_name"):
            return curr.text.decode("utf-8", errors="replace").strip()
        inner = curr.child_by_field_name("declarator")
        if inner is not None:
            curr = inner
            continue
        found = None
        for ch in curr.children:
            if ch.type in ("identifier", "field_identifier", "function_declarator", "pointer_declarator"):
                found = ch
                break
        if found is None:
            break
        curr = found
    return None


def _extract_first_identifier(ts_node: tree_sitter.Node) -> Optional[str]:
    """Extracts the first identifier-like token from a subtree."""
    if ts_node.type in ("identifier", "simple_identifier", "variable_name", "name", "field_identifier", "property_identifier"):
        return ts_node.text.decode("utf-8", errors="replace").strip()
    for ch in ts_node.children:
        if ch.type in ("identifier", "simple_identifier", "variable_name", "name", "field_identifier", "property_identifier"):
            return ch.text.decode("utf-8", errors="replace").strip()
    for ch in ts_node.children:
        res = _extract_first_identifier(ch)
        if res:
            return res
    return None


def _extract_symbol_name(
    ts_node: tree_sitter.Node,
    label: NodeLabel,
    node_type: str,
    raw_text: str,
    language: str,
) -> str:
    """Extracts a clean symbol name for a CPGNode across all 18 languages."""
    if label == "Parameter":
        # C/C++ parameter_declaration uses declarator
        decl = ts_node.child_by_field_name("declarator")
        if decl is not None:
            cname = _unwrap_c_declarator_name(decl)
            if cname:
                return cname
        # Rust parameter uses pattern
        pat = ts_node.child_by_field_name("pattern")
        if pat is not None:
            return pat.text.decode("utf-8", errors="replace").strip()
        name_ch = ts_node.child_by_field_name("name")
        if name_ch is not None:
            return name_ch.text.decode("utf-8", errors="replace").strip()
        if node_type in ("parameter", "formal_parameter", "parameter_declaration", "simple_parameter", "normal_formal_parameter"):
            ident = _extract_first_identifier(ts_node)
            if ident:
                return ident
        if ":" in raw_text:
            return raw_text.split(":", 1)[0].strip()
        if "=" in raw_text:
            return raw_text.split("=", 1)[0].strip()
        return raw_text.strip()

    if label == "Variable":
        return raw_text.strip()

    if label == "Function":
        name_child = ts_node.child_by_field_name("name")
        if name_child is not None:
            return name_child.text.decode("utf-8", errors="replace").strip()
        # C / C++ function_definition -> declarator
        decl = ts_node.child_by_field_name("declarator")
        if decl is not None:
            cname = _unwrap_c_declarator_name(decl)
            if cname:
                return cname
        # Kotlin function_declaration -> first simple_identifier child
        for ch in ts_node.children:
            if ch.type in ("simple_identifier", "identifier", "name"):
                return ch.text.decode("utf-8", errors="replace").strip()
        return "anonymous_func"

    if label == "Class":
        name_child = ts_node.child_by_field_name("name")
        if name_child is not None:
            return name_child.text.decode("utf-8", errors="replace").strip()
        for ch in ts_node.children:
            if ch.type in ("identifier", "simple_identifier", "type_identifier", "constant", "name"):
                return ch.text.decode("utf-8", errors="replace").strip()
        return "anonymous_class"

    if label == "Call":
        # Dart selector call: callee is preceding named sibling identifier
        if language == "dart" and node_type == "selector":
            prev = ts_node.prev_named_sibling
            if prev is not None:
                return prev.text.decode("utf-8", errors="replace").strip()
        # Java method_invocation: object.name or name
        if node_type == "method_invocation":
            obj_ch = ts_node.child_by_field_name("object")
            m_name = ts_node.child_by_field_name("name")
            if obj_ch is not None and m_name is not None:
                return f"{obj_ch.text.decode('utf-8', errors='replace').strip()}.{m_name.text.decode('utf-8', errors='replace').strip()}"
            if m_name is not None:
                return m_name.text.decode("utf-8", errors="replace").strip()
        # PHP member_call_expression / scoped_call_expression
        if node_type in ("member_call_expression", "scoped_call_expression"):
            obj_ch = ts_node.child_by_field_name("object") or ts_node.child_by_field_name("scope")
            m_name = ts_node.child_by_field_name("name")
            sep = "::" if node_type == "scoped_call_expression" else "->"
            if obj_ch is not None and m_name is not None:
                return f"{obj_ch.text.decode('utf-8', errors='replace').strip()}{sep}{m_name.text.decode('utf-8', errors='replace').strip()}"
            if m_name is not None:
                return m_name.text.decode("utf-8", errors="replace").strip()
        # Standard function / method / macro fields
        func_child = (
            ts_node.child_by_field_name("function")
            or ts_node.child_by_field_name("method")
            or ts_node.child_by_field_name("macro")
            or ts_node.child_by_field_name("type")
        )
        if func_child is not None:
            return func_child.text.decode("utf-8", errors="replace").strip()
        # Swift / Kotlin / Ruby call_expression -> first named child
        for ch in ts_node.children:
            if ch.is_named and ch.type in (
                "simple_identifier", "identifier", "navigation_expression", "member_expression", "scoped_identifier",
            ):
                return ch.text.decode("utf-8", errors="replace").strip()
        if node_type == "element":
            for ch in ts_node.children:
                if ch.type == "start_tag":
                    for sc in ch.children:
                        if sc.type == "tag_name":
                            return sc.text.decode("utf-8", errors="replace").strip()
        return raw_text.split("(", 1)[0].strip()

    if label == "Assignment":
        left_child = (
            ts_node.child_by_field_name("left")
            or ts_node.child_by_field_name("name")
            or ts_node.child_by_field_name("pattern")
        )
        if left_child is not None:
            return left_child.text.decode("utf-8", errors="replace").strip()
        decl = ts_node.child_by_field_name("declarator")
        if decl is not None:
            cname = _unwrap_c_declarator_name(decl)
            if cname:
                return cname
        # Kotlin property_declaration / Solidity variable_declaration_statement
        for ch in ts_node.children:
            if ch.type in ("variable_declaration", "identifier", "simple_identifier", "variable_name"):
                ident = _extract_first_identifier(ch)
                if ident:
                    return ident
        return raw_text.split("=", 1)[0].strip() if "=" in raw_text else "="

    if label == "LoopBlock":
        return "while" if "while" in node_type else "for"
    if label == "ControlBlock":
        return "if"
    if label == "Return":
        return "return"
    if label == "Literal":
        return raw_text.strip()
    return node_type


class ASTNormalizer:
    def __init__(self, scanned_file: ScannedFile):
        self.file = scanned_file
        self.language = (scanned_file.language or "python").strip().lower()
        self.spec: Optional[LanguageSpec] = LANGUAGE_SPECS.get(self.language)
        self.nodes: List[CPGNode] = []
        self.edges: List[CPGEdge] = []
        self.node_map: Dict[str, CPGNode] = {}
        self.scope_stack: List[str] = []
        self._route_func_byte_ranges: List[Tuple[int, int]] = []
        self._skip_types: Set[str] = set(_GLOBAL_SKIP_TYPES)
        if self.spec:
            self._skip_types.update(self.spec.skip_node_types)
            self._skip_types.update(self.spec.import_node_types)

    def parse(self) -> Tuple[List[CPGNode], List[CPGEdge]]:
        """Public alias for `normalize()` — returns `(nodes, edges)` for all 18 languages."""
        return self.normalize()

    def normalize(self) -> Tuple[List[CPGNode], List[CPGEdge]]:
        content_bytes = self.file.content_bytes or b""
        line_count = max(1, content_bytes.count(b"\n") + 1)

        file_node_id = compute_node_id(self.file.filepath, "File", 0, len(content_bytes))
        file_cpg = CPGNode(
            id=file_node_id,
            label="File",
            ast_type="file",
            name=self.file.filepath,
            code=self.file.filepath,
            filepath=self.file.filepath,
            start_line=1,
            end_line=line_count,
            start_col=0,
            end_col=0,
            scope_id="global",
            language=self.language,
        )
        self.nodes.append(file_cpg)
        self.node_map[file_cpg.id] = file_cpg
        self.scope_stack.append(file_cpg.id)

        parser = get_parser_for_language(self.language) or _BUNDLED_PARSERS.get(self.language)
        if parser is not None:
            try:
                tree = parser.parse(content_bytes)
                root_node = tree.root_node
                file_cpg.end_line = max(1, root_node.end_point[0] + 1)
                file_cpg.end_col = root_node.end_point[1]
                self._traverse(root_node, parent_cpg=file_cpg)
            except Exception as exc:
                logger.warning(f"AST parse degraded for {self.file.filepath} ({self.language}): {exc}")

        if self.language == "web_template":
            self._emit_web_template_expressions(file_cpg, content_bytes)

        return self.nodes, self.edges

    def _emit_web_template_expressions(self, file_cpg: CPGNode, content_bytes: bytes) -> None:
        """
        Emits deterministic CPGNodes for template expressions (`{{ ... }}`, `<%- ... %>`,
        `{!! ... !!}`, `@Html.Raw(...)`, `<form ...>`) inside `web_template` files so
        AST/CFG/DFG/CALLS passes operate over template constructs in addition to HTML elements.
        """
        try:
            text = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            return

        for match in _WEB_TEMPLATE_EXPR_RE.finditer(text):
            raw_expr = match.group(0).strip()
            start_char = match.start()
            end_char = match.end()
            start_byte = len(text[:start_char].encode("utf-8", errors="replace"))
            end_byte = len(text[:end_char].encode("utf-8", errors="replace"))
            start_line = text.count("\n", 0, start_char) + 1
            end_line = text.count("\n", 0, end_char) + 1
            last_nl = text.rfind("\n", 0, start_char)
            start_col = start_char - last_nl - 1 if last_nl != -1 else start_char

            node_id = compute_node_id(self.file.filepath, "template_expression", start_byte, end_byte)
            if node_id in self.node_map:
                continue

            is_source, is_sink, is_sanitizer, sink_domain, sanitizer_domains = classify_taint_with_domains(
                raw_expr[:1200], "template_expression", raw_expr, language="web_template"
            )
            tpl_node = CPGNode(
                id=node_id,
                label="Call",
                ast_type="template_expression",
                name=raw_expr[:250],
                code=raw_expr[:1200],
                filepath=self.file.filepath,
                start_line=start_line,
                end_line=end_line,
                start_col=start_col,
                end_col=start_col + len(raw_expr),
                scope_id=file_cpg.id,
                is_source=is_source,
                is_sink=is_sink,
                is_sanitizer=is_sanitizer,
                sink_domain=sink_domain,
                sanitizer_domains=sanitizer_domains,
                language="web_template",
            )
            self.nodes.append(tpl_node)
            self.node_map[tpl_node.id] = tpl_node
            self.edges.append(
                CPGEdge(
                    id=compute_edge_id(file_cpg.id, tpl_node.id, "AST_CHILD"),
                    source_id=file_cpg.id,
                    target_id=tpl_node.id,
                    edge_type="AST_CHILD",
                )
            )

    def _is_structural_node(self, ts_node: tree_sitter.Node) -> bool:
        """Determines whether a Tree-sitter node should become a primary CPGNode."""
        node_type = ts_node.type
        if node_type in self._skip_types:
            return False

        # For Dart `selector`, only treat it as a structural Call if it represents an invocation `(...)`
        if self.language == "dart" and node_type == "selector":
            return any(ch.type == "argument_part" for ch in ts_node.children)

        # Explicitly retain all category node types declared in the language's LanguageSpec
        if self.spec is not None:
            if (
                node_type in self.spec.module_node_types
                or node_type in self.spec.class_node_types
                or node_type in self.spec.function_node_types
                or node_type in self.spec.parameter_node_types
                or node_type in self.spec.assignment_node_types
                or node_type in self.spec.call_node_types
                or node_type in self.spec.control_node_types
                or node_type in self.spec.loop_node_types
                or node_type in self.spec.return_node_types
                or node_type in self.spec.identifier_node_types
            ):
                return True

        return (
            (
                ts_node.is_named
                or node_type in ("assignment", "call", "subscript", "attribute", "identifier")
            )
            and node_type not in _TRANSPARENT_NODE_TYPES
        )

    def _traverse(self, ts_node: tree_sitter.Node, parent_cpg: Optional[CPGNode] = None) -> Optional[CPGNode]:
        node_type = ts_node.type

        if node_type in self._skip_types:
            return None

        # Skip static JSX attribute names and static JSX string attributes (e.g., className="...")
        if (
            ts_node.parent is not None
            and ts_node.parent.type == "jsx_attribute"
            and node_type in ("property_identifier", "string")
        ):
            return None

        # Track Python @app.get/post/... and @router.get/post/... route definitions
        if self.language == "python" and node_type == "decorated_definition":
            dec_texts = [
                self.file.content_bytes[ch.start_byte:ch.end_byte].decode("utf-8", errors="replace").strip()
                for ch in ts_node.children
                if ch.type == "decorator"
            ]
            if any(any(dt.startswith(tok) for tok in HTTP_ROUTE_DECORATOR_TOKENS) for dt in dec_texts):
                for ch in ts_node.children:
                    if ch.type == "function_definition":
                        self._route_func_byte_ranges.append((ch.start_byte, ch.end_byte))

        is_structural = self._is_structural_node(ts_node)
        cpg_node: Optional[CPGNode] = None
        scope_pushed = False

        if is_structural:
            node_id = compute_node_id(self.file.filepath, node_type, ts_node.start_byte, ts_node.end_byte)
            raw_text = self.file.content_bytes[ts_node.start_byte:ts_node.end_byte].decode("utf-8", errors="replace")
            code_snippet = raw_text[:1200]

            parent_type = ts_node.parent.type if ts_node.parent is not None else None
            label = map_node_label(node_type, parent_type, spec=self.spec)
            name = _extract_symbol_name(ts_node, label, node_type, raw_text, self.language)[:250]

            is_source, is_sink, is_sanitizer, sink_domain, sanitizer_domains = classify_taint_with_domains(
                code_snippet, node_type, raw_text, language=self.language
            )

            # Promote untrusted HTTP route formal parameters (FastAPI / Flask) to CPG taint sources
            if (
                self.language == "python"
                and not is_source
                and label == "Parameter"
                and node_type not in ("parameters", "formal_parameters")
                and name not in DI_EXCLUDED_PARAM_NAMES
                and not name.startswith("(")
                and self._route_func_byte_ranges
            ):
                in_route_params = False
                p_curr = ts_node.parent
                while p_curr is not None:
                    if p_curr.type in ("parameters", "formal_parameters") and p_curr.parent is not None:
                        fn_parent = p_curr.parent
                        if any(
                            r_start == fn_parent.start_byte and r_end == fn_parent.end_byte
                            for r_start, r_end in self._route_func_byte_ranges
                        ):
                            in_route_params = True
                        break
                    p_curr = p_curr.parent

                if in_route_params:
                    type_part = ""
                    if ":" in raw_text:
                        type_part = raw_text.split(":", 1)[1].split("=", 1)[0].strip()
                    if type_part not in SAFE_PRIMITIVE_PARAM_TYPES:
                        is_source = True

            if node_id not in self.node_map:
                cpg_node = CPGNode(
                    id=node_id,
                    label=label,
                    ast_type=node_type,
                    name=name,
                    code=code_snippet,
                    filepath=self.file.filepath,
                    start_line=ts_node.start_point[0] + 1,
                    end_line=ts_node.end_point[0] + 1,
                    start_col=ts_node.start_point[1],
                    end_col=ts_node.end_point[1],
                    scope_id=self.scope_stack[-1] if self.scope_stack else "global",
                    is_source=is_source,
                    is_sink=is_sink,
                    is_sanitizer=is_sanitizer,
                    sink_domain=sink_domain,
                    sanitizer_domains=sanitizer_domains,
                    language=self.language,
                )
                self.nodes.append(cpg_node)
                self.node_map[cpg_node.id] = cpg_node

                if parent_cpg and parent_cpg.id != cpg_node.id:
                    edge_id = compute_edge_id(parent_cpg.id, cpg_node.id, "AST_CHILD")
                    self.edges.append(
                        CPGEdge(
                            id=edge_id,
                            source_id=parent_cpg.id,
                            target_id=cpg_node.id,
                            edge_type="AST_CHILD",
                        )
                    )

                # Push scope for modules, classes, and functions
                if label in ("Module", "Class", "Function"):
                    self.scope_stack.append(cpg_node.id)
                    scope_pushed = True

                # Generate synthetic Entry and Exit nodes for Functions
                if label == "Function":
                    entry_id = compute_node_id(self.file.filepath, "Entry", ts_node.start_byte, ts_node.start_byte)
                    exit_id = compute_node_id(self.file.filepath, "Exit", ts_node.end_byte, ts_node.end_byte)

                    entry_node = CPGNode(
                        id=entry_id,
                        label="Entry",
                        ast_type="entry",
                        name=f"{name}_entry",
                        code=f"entry {name}",
                        filepath=self.file.filepath,
                        start_line=cpg_node.start_line,
                        end_line=cpg_node.start_line,
                        start_col=cpg_node.start_col,
                        end_col=cpg_node.start_col,
                        scope_id=cpg_node.id,
                        language=self.language,
                    )
                    exit_node = CPGNode(
                        id=exit_id,
                        label="Exit",
                        ast_type="exit",
                        name=f"{name}_exit",
                        code=f"exit {name}",
                        filepath=self.file.filepath,
                        start_line=cpg_node.end_line,
                        end_line=cpg_node.end_line,
                        start_col=cpg_node.end_col,
                        end_col=cpg_node.end_col,
                        scope_id=cpg_node.id,
                        language=self.language,
                    )
                    self.nodes.extend([entry_node, exit_node])
                    self.node_map[entry_node.id] = entry_node
                    self.node_map[exit_node.id] = exit_node

                    self.edges.append(
                        CPGEdge(
                            id=compute_edge_id(cpg_node.id, entry_node.id, "AST_CHILD"),
                            source_id=cpg_node.id,
                            target_id=entry_node.id,
                            edge_type="AST_CHILD",
                        )
                    )
                    self.edges.append(
                        CPGEdge(
                            id=compute_edge_id(cpg_node.id, exit_node.id, "AST_CHILD"),
                            source_id=cpg_node.id,
                            target_id=exit_node.id,
                            edge_type="AST_CHILD",
                        )
                    )
            else:
                cpg_node = self.node_map[node_id]

        # Recurse children
        next_parent = cpg_node if cpg_node else parent_cpg
        for child in ts_node.children:
            self._traverse(child, parent_cpg=next_parent)

        if scope_pushed:
            self.scope_stack.pop()

        return cpg_node
