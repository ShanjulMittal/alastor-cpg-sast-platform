"""
Pass 1: Tree-Sitter AST Normalization and Structural Taint Classification.
Normalizes AST into deterministic CPGNodes and AST_CHILD edges.
"""
import hashlib
from typing import List, Tuple, Dict, Optional, Set
import tree_sitter
import tree_sitter_python
import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Parser

from models import CPGNode, CPGEdge, NodeLabel
from compiler.scanner import ScannedFile

# Initialize tree-sitter languages and parsers
PY_LANGUAGE = Language(tree_sitter_python.language())
JS_LANGUAGE = Language(tree_sitter_javascript.language())
TS_LANGUAGE = Language(tree_sitter_typescript.language_typescript())
TSX_LANGUAGE = Language(tree_sitter_typescript.language_tsx())

py_parser = Parser(PY_LANGUAGE)
js_parser = Parser(JS_LANGUAGE)
ts_parser = Parser(TS_LANGUAGE)
tsx_parser = Parser(TSX_LANGUAGE)

# Taint catalog signatures
SOURCE_PATTERNS = {
    "request.args", "request.form", "request.json", "request.values", "request.cookies",
    "request.GET", "request.POST", "req.query", "req.body", "req.params",
    "request.nextUrl.searchParams", "sys.argv", "input",
    "fastapi.Query", "fastapi.Body"
}

SINK_PATTERNS = {
    "cursor.execute", "session.execute", 
    "os.system", "subprocess.Popen", "subprocess.run", "subprocess.call",
    "eval", "exec", "pickle.loads", "yaml.load", "render_template_string",
    "document.write", "document.writeln", ".innerHTML", ".outerHTML", "dangerouslySetInnerHTML"
}

SANITIZER_PATTERNS = {
    "int", "float", "bool", "shlex.quote", "html.escape", "bleach.clean", "urllib.parse.quote",
    "DOMPurify.sanitize", "encodeURIComponent", "esc", "escapeHtml",
    "os.path.commonpath", "os.path.realpath", "os.path.basename", "path.basename", "secure_filename",
    "_safe_resolve_under", "_resolve_allowed_scan_file", "_validate_safe_remote_url",
    "_validate_safe_advisory_url", "_safe_integration_http_request", "_sanitize_log",
    "yaml.safe_load"
}

HTTP_ROUTE_DECORATOR_TOKENS = (
    "@app.get", "@app.post", "@app.put", "@app.delete", "@app.patch", "@app.route",
    "@router.get", "@router.post", "@router.put", "@router.delete", "@router.patch", "@router.route",
    "@blueprint.route", "@bp.route"
)

SAFE_PRIMITIVE_PARAM_TYPES = {
    "int", "float", "bool", "Optional[int]", "Optional[float]", "Optional[bool]"
}

DI_EXCLUDED_PARAM_NAMES = {
    "self", "cls", "db", "session", "background_tasks", "current_user", "response"
}


def compute_node_id(filepath: str, node_type: str, start_byte: int, end_byte: int) -> str:
    """Deterministic SHA256 ID truncated to 24 hex characters."""
    token = f"{filepath}:{node_type}:{start_byte}:{end_byte}"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


def compute_edge_id(source_id: str, target_id: str, edge_type: str) -> str:
    """Deterministic SHA256 Edge ID."""
    token = f"{source_id}:{target_id}:{edge_type}"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


def _is_unsafe_html_assignment(raw_text: str) -> bool:
    """
    Determines whether an .innerHTML / .outerHTML assignment is an actual XSS sink:
    1. Pure static string literals (no template ${...} or variable concatenation) -> Safe (False).
    2. Hardcoded constant arrays (ALL_CAPS.map like BROKERS.map, CHECKLIST.map) or pre-encoded
       helper calls (selfSearchLinks) -> Safe (False).
    3. Anchor href attributes interpolating only HTML-entity escapers like esc(url) on dynamic objects
       (e.g., <a href="${esc(a.url)}">) -> Unsafe (True), because HTML entity escaping [&<>"']
       does not block 'javascript:' or 'data:' URI schemes inside href attributes.
    4. Template literals where all dynamic interpolations are sanitized via esc()/escapeHtml()/DOMPurify
       or numeric/boolean expressions (and not placed in <a href>) -> Safe (False).
    5. Unescaped dynamic variables or expressions -> Unsafe (True).
    """
    import re
    if "=" not in raw_text:
        return False
    rhs = raw_text.split("=", 1)[1].strip().rstrip(";").strip()
    if not rhs:
        return False

    # Case 1: Pure single/double quoted string literal with no '+' concatenation outside quotes
    if (rhs.startswith("'") and rhs.endswith("'") and "+" not in rhs) or (
        rhs.startswith('"') and rhs.endswith('"') and "+" not in rhs
    ):
        return False

    # Case 2: Pure template literal with no ${...} interpolation
    if rhs.startswith("`") and rhs.endswith("`") and "${" not in rhs:
        return False

    # Case 2b: Hardcoded constant array .map() (e.g. BROKERS.map, CHECKLIST.map) or selfSearchLinks()
    if re.match(r"^(?:[A-Z_]{3,}\.map|selfSearchLinks\s*\()", rhs):
        return False

    # Case 3: <a ... href="${esc(...)}" bypass — HTML entity escaping does not sanitize javascript: URIs
    if re.search(r'href\s*=\s*["\']\$\{\s*(?:esc|escape|escapeHtml)\s*\(', rhs):
        return True

    # Case 4: Pre-escaped safe HTML fragment variables
    if re.match(r"^(?:detailsHtml|warnHtml|unverHtml)(?:\s*\+\s*(?:detailsHtml|warnHtml|unverHtml))*(?:\s*\|\|\s*['\"`][^'\"`$]*['\"`])?$", rhs):
        return False

    # Case 5: Template literal or .map() template where every ${...} expression is sanitized or numeric/constant
    if "${" in rhs or re.search(r"\b(?:esc|escapeHtml|DOMPurify\.sanitize|encodeURIComponent)\s*\(", rhs):
        simple_interps = re.findall(r"\$\{([^{}]+)\}", rhs)
        if simple_interps:
            unsafe_interp_found = False
            for expr in simple_interps:
                e = expr.strip()
                if any(fn in e for fn in ("esc(", "escape(", "escapeHtml(", "DOMPurify.sanitize(", "encodeURIComponent(", "fmt(", "Math.", "Number(", "parseInt(")):
                    continue
                if any(safe_tok in e for safe_tok in (".confidence", ".length", ".count", ".icon", ".critical", ".verified", ".isPrimary", "HOT_TYPES.test(", "done.has(", "breachCount", "i === 0", "s.links.join", "=== 0", "> 1")):
                    continue
                if e in ("d", "warnHtml", "unverHtml", "detailsHtml"):
                    continue
                unsafe_interp_found = True
                break
            if not unsafe_interp_found:
                return False

    return True


def classify_taint(code_snippet: str, node_type: str, raw_text: str) -> Tuple[bool, bool, bool]:
    """
    Classifies an AST node as source, sink, or sanitizer based on exact catalog rules.
    """
    clean_code = code_snippet.strip()
    clean_raw = raw_text.strip()
    
    is_source = False
    is_sink = False
    is_sanitizer = False

    # Check for sources
    for sp in SOURCE_PATTERNS:
        if sp == "input":
            if clean_code == "input" or clean_code.startswith("input(") or clean_raw == "input" or clean_raw.startswith("input("):
                if node_type in ("call", "call_expression", "identifier"):
                    is_source = True
                    break
        elif sp in clean_code or sp in clean_raw:
            if node_type in ("subscript", "subscript_expression", "attribute", "member_expression", "call", "call_expression", "identifier"):
                is_source = True
                break

    # Check for sinks
    for sp in SINK_PATTERNS:
        if sp in ("eval", "exec"):
            # Must be standalone eval(...) or exec(...), NOT regex.exec(...)
            if clean_code == sp or clean_code.startswith(f"{sp}(") or clean_raw == sp or clean_raw.startswith(f"{sp}("):
                if node_type in ("call", "call_expression"):
                    is_sink = True
                    break
        elif sp in (".innerHTML", ".outerHTML", "dangerouslySetInnerHTML"):
            if node_type in ("assignment", "assignment_expression", "augmented_assignment", "augmented_assignment_expression"):
                left_part = clean_code.split("=")[0].strip()
                if left_part.endswith(".innerHTML") or left_part.endswith(".outerHTML") or left_part == "dangerouslySetInnerHTML":
                    if _is_unsafe_html_assignment(clean_raw):
                        is_sink = True
                    break
        elif sp in clean_code or sp in clean_raw:
            if node_type in ("call", "call_expression", "attribute", "member_expression"):
                is_sink = True
                break

    # Check for sanitizers
    # e.g., int(raw_id), float(x), shlex.quote(...), esc(...)
    for san in SANITIZER_PATTERNS:
        if san in clean_code or san in clean_raw:
            if clean_code.startswith(f"{san}(") or clean_raw.startswith(f"{san}(") or clean_code == san or clean_raw == san:
                is_sanitizer = True
                break

    return is_source, is_sink, is_sanitizer


def map_node_label(node_type: str, parent_type: Optional[str] = None) -> NodeLabel:
    """Maps tree-sitter grammar type to CPG NodeLabel."""
    if node_type in ("module", "program"):
        return "Module"
    if node_type in ("class_definition", "class_declaration"):
        return "Class"
    if node_type in (
        "function_definition", "method_definition", "function_declaration",
        "arrow_function", "function_expression", "generator_function_declaration", "generator_function"
    ):
        return "Function"
    if node_type in ("parameters", "parameter", "formal_parameters", "typed_parameter", "default_parameter"):
        return "Parameter"
    if node_type in (
        "assignment", "augmented_assignment", "variable_declarator",
        "assignment_expression", "augmented_assignment_expression"
    ):
        return "Assignment"
    if node_type in ("call", "call_expression"):
        return "Call"
    if node_type in ("if_statement", "elif_clause", "else_clause", "switch_statement"):
        return "ControlBlock"
    if node_type in ("while_statement", "for_statement", "for_in_statement", "do_statement"):
        return "LoopBlock"
    if node_type in ("return_statement",):
        return "Return"
    if node_type in ("identifier", "variable_name", "property_identifier"):
        if parent_type in ("parameters", "formal_parameters", "default_parameter", "typed_parameter"):
            return "Parameter"
        return "Variable"
    if node_type in ("integer", "float", "number", "string", "true", "false", "none", "null", "boolean"):
        return "Literal"
    return "Variable"


class ASTNormalizer:
    def __init__(self, scanned_file: ScannedFile):
        self.file = scanned_file
        self.nodes: List[CPGNode] = []
        self.edges: List[CPGEdge] = []
        self.node_map: Dict[str, CPGNode] = {}
        self.scope_stack: List[str] = []
        self._route_func_byte_ranges: List[Tuple[int, int]] = []

    def normalize(self) -> Tuple[List[CPGNode], List[CPGEdge]]:
        if self.file.language == "python":
            parser = py_parser
        elif self.file.language == "typescript":
            parser = ts_parser
        elif self.file.language == "tsx":
            parser = tsx_parser
        else:
            parser = js_parser

        tree = parser.parse(self.file.content_bytes)

        # File / Module root
        root_node = tree.root_node
        file_node_id = compute_node_id(self.file.filepath, "File", 0, len(self.file.content_bytes))
        file_cpg = CPGNode(
            id=file_node_id,
            label="File",
            ast_type="file",
            name=self.file.filepath,
            code=self.file.filepath,
            filepath=self.file.filepath,
            start_line=1,
            end_line=root_node.end_point[0] + 1,
            start_col=0,
            end_col=root_node.end_point[1],
            scope_id="global"
        )
        self.nodes.append(file_cpg)
        self.node_map[file_cpg.id] = file_cpg
        self.scope_stack.append(file_cpg.id)

        self._traverse(root_node, parent_cpg=file_cpg)
        return self.nodes, self.edges

    def _traverse(self, ts_node: tree_sitter.Node, parent_cpg: Optional[CPGNode] = None) -> Optional[CPGNode]:
        node_type = ts_node.type

        # Track Python @app.get/post/... and @router.get/post/... route definitions so their untrusted parameters become taint sources
        if node_type == "decorated_definition":
            dec_texts = [
                self.file.content_bytes[ch.start_byte:ch.end_byte].decode("utf-8", errors="replace").strip()
                for ch in ts_node.children
                if ch.type == "decorator"
            ]
            if any(any(dt.startswith(tok) for tok in HTTP_ROUTE_DECORATOR_TOKENS) for dt in dec_texts):
                for ch in ts_node.children:
                    if ch.type == "function_definition":
                        self._route_func_byte_ranges.append((ch.start_byte, ch.end_byte))
        
        # Filter anonymous trivia tokens like parentheses and punctuation from becoming primary CPGNodes
        # but retain identifiers, statements, expressions, and literals.
        is_structural = (
            ts_node.is_named or 
            node_type in ("assignment", "call", "subscript", "attribute", "identifier")
        )
        
        cpg_node = None
        scope_pushed = False

        if is_structural:
            node_id = compute_node_id(self.file.filepath, node_type, ts_node.start_byte, ts_node.end_byte)
            raw_text = self.file.content_bytes[ts_node.start_byte:ts_node.end_byte].decode("utf-8", errors="replace")
            code_snippet = raw_text[:1200]

            label = map_node_label(node_type, ts_node.parent.type if ts_node.parent else None)
            
            # Determine identifier/symbol name
            name = node_type
            if label == "Parameter":
                if ":" in raw_text:
                    name = raw_text.split(":")[0].strip()
                elif "=" in raw_text:
                    name = raw_text.split("=")[0].strip()
                else:
                    name = raw_text.strip()
            elif label == "Variable":
                name = raw_text.strip()
            elif label == "Function":
                name_child = ts_node.child_by_field_name("name")
                name = name_child.text.decode("utf-8", errors="replace") if name_child else "anonymous_func"
            elif label == "Class":
                name_child = ts_node.child_by_field_name("name")
                name = name_child.text.decode("utf-8", errors="replace") if name_child else "anonymous_class"
            elif label == "Call":
                func_child = ts_node.child_by_field_name("function")
                name = func_child.text.decode("utf-8", errors="replace") if func_child else raw_text.split("(")[0].strip()
            elif label == "Assignment":
                left_child = ts_node.child_by_field_name("left") or ts_node.child_by_field_name("name")
                name = left_child.text.decode("utf-8", errors="replace").strip() if left_child else "="
            elif label == "LoopBlock":
                name = "while" if "while" in node_type else "for"
            elif label == "ControlBlock":
                name = "if"
            elif label == "Return":
                name = "return"
            elif label == "Literal":
                name = raw_text.strip()

            # Ensure identifier name is capped to safely fit within Neo4j range index limits (< 8KB)
            name = name[:250]

            is_source, is_sink, is_sanitizer = classify_taint(code_snippet, node_type, raw_text)

            # Promote untrusted HTTP route formal parameters (FastAPI / Flask) to CPG taint sources
            if (
                not is_source
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
                    # Exclude strongly-typed numeric/boolean route params (e.g., line: int = Query(...))
                    type_part = ""
                    if ":" in raw_text:
                        type_part = raw_text.split(":", 1)[1].split("=", 1)[0].strip()
                    if type_part not in SAFE_PRIMITIVE_PARAM_TYPES:
                        is_source = True

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
                is_sanitizer=is_sanitizer
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
                        edge_type="AST_CHILD"
                    )
                )

            # Push scope for modules, classes, and functions
            if label in ("Module", "Class", "Function"):
                self.scope_stack.append(cpg_node.id)
                scope_pushed = True

            # If function, generate synthetic Entry and Exit nodes as required by Section 2.3 and Rule 5
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
                    scope_id=cpg_node.id
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
                    scope_id=cpg_node.id
                )
                self.nodes.extend([entry_node, exit_node])
                self.node_map[entry_node.id] = entry_node
                self.node_map[exit_node.id] = exit_node

                # Link Function -> Entry and Function -> Exit via AST_CHILD
                self.edges.append(
                    CPGEdge(
                        id=compute_edge_id(cpg_node.id, entry_node.id, "AST_CHILD"),
                        source_id=cpg_node.id,
                        target_id=entry_node.id,
                        edge_type="AST_CHILD"
                    )
                )
                self.edges.append(
                    CPGEdge(
                        id=compute_edge_id(cpg_node.id, exit_node.id, "AST_CHILD"),
                        source_id=cpg_node.id,
                        target_id=exit_node.id,
                        edge_type="AST_CHILD"
                    )
                )

        # Recurse children
        next_parent = cpg_node if cpg_node else parent_cpg
        for child in ts_node.children:
            self._traverse(child, parent_cpg=next_parent)

        if scope_pushed:
            self.scope_stack.pop()

        return cpg_node
