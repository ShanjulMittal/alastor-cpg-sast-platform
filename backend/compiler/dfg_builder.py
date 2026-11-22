"""
Pass 3: Unified 18-Language Data Flow Graph (DFG) & Domain-Aware Sanitizer Propagation Builder.
Implements Reaching Definitions analysis, inter-procedural DFG propagation,
structural helper-function sanitizer inference, and domain-scoped sanitizer tracking.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter

from compiler.ast_parser import (
    _is_structurally_safe_html_expr,
    _unwrap_c_declarator_name,
    compute_edge_id,
    compute_node_id,
    has_unsafe_uri_interpolation,
    js_parser,
    py_parser,
    ts_parser,
    tsx_parser,
)
from compiler.language_registry import LANGUAGE_SPECS, LanguageSpec, get_parser_for_language
from models import CPGEdge, CPGNode

logger = logging.getLogger("cpg-sast.compiler.dfg")

_AUGMENTED_ASSIGN_TYPES: Set[str] = {
    "augmented_assignment",
    "augmented_assignment_expression",
    "compound_assignment_expr",
    "operator_assignment",
}

_PURE_LITERAL_TYPES: Set[str] = {
    "integer", "float", "number", "true", "false", "none", "null", "undefined", "boolean",
    "int_literal", "integer_literal", "decimal_integer_literal", "float_literal",
    "number_literal", "boolean_literal", "null_literal", "nil", "nullptr", "char_literal",
    "real_literal",
}

_STRING_LITERAL_TYPES: Set[str] = {
    "string", "string_literal", "interpreted_string_literal", "raw_string_literal",
    "line_string_literal", "encapsed_string",
}

_BLOCK_TYPES: Set[str] = {
    "block", "statement_block", "compound_statement", "function_body", "body_statement",
    "statements", "statement_list", "control_structure_body", "then", "do",
}

_SAFE_NUMERIC_CALL_NAMES: Set[str] = {
    "int", "float", "bool", "len", "Number", "parseInt", "parseFloat", "Boolean",
    "Math.floor", "Math.ceil", "Math.round", "Math.abs", "Math.max", "Math.min",
    "strconv.Atoi", "strconv.ParseInt", "strconv.ParseUint",
    "Integer.parseInt", "Long.parseLong", "int.Parse", "int.TryParse",
    "intval", "floatval", "atoi", "strtol", "std::stoi",
}

_HTML_SANITIZER_NAMES: Set[str] = {
    "esc", "escape", "escapeHtml", "DOMPurify.sanitize",
    "html.escape", "bleach.clean", "html.EscapeString",
    "HtmlUtils.htmlEscape", "ESAPI.encoder", "HtmlEncoder.Default.Encode",
    "htmlspecialchars", "htmlentities", "ERB::Util.html_escape", "CGI.escapeHTML",
}

_URL_SANITIZER_NAMES: Set[str] = {
    "encodeURIComponent", "encodeURI", "urllib.parse.quote", "url.QueryEscape",
    "safeUrl", "sanitizeUrl", "validateUrl",
}


def _combine_domains(d1: Set[str], d2: Set[str]) -> Set[str]:
    """
    Combines two sanitizer domain sets for concatenation / ternary / multi-return expressions.
    `"UNIVERSAL"` acts as identity (compatible with any specific domain).
    If either side is empty (unsanitized), the combined result is empty.
    """
    if not d1 or not d2:
        return set()
    if "UNIVERSAL" in d1 and "UNIVERSAL" in d2:
        return {"UNIVERSAL"}
    if "UNIVERSAL" in d1:
        return set(d2)
    if "UNIVERSAL" in d2:
        return set(d1)
    return d1 & d2


class DFGBuilder:
    def __init__(
        self,
        filepath: str,
        content_bytes: bytes,
        language: str,
        nodes: List[CPGNode],
        node_map: Dict[str, CPGNode],
        function_params_map: Dict[str, List[CPGNode]],
        function_returns_map: Dict[str, List[CPGNode]],
    ):
        self.filepath = filepath
        self.content_bytes = content_bytes
        self.language = (language or "python").strip().lower()
        self.spec: Optional[LanguageSpec] = LANGUAGE_SPECS.get(self.language)
        self.nodes = nodes
        self.node_map = node_map
        self.function_params_map = function_params_map
        self.function_returns_map = function_returns_map
        self.dfg_edges: List[CPGEdge] = []
        self._seen_edge_ids: Set[str] = set()

        # Symbol Table per scope: defs[scope_id][var_name] -> List[node_id]
        self.defs: Dict[str, Dict[str, List[str]]] = {}
        # Domain-aware sanitized variables: scope_id -> var_name -> Set[domain]
        self.sanitized_vars: Dict[str, Dict[str, Set[str]]] = {}
        # Structurally verified sanitizer helper functions: func_name -> Set[domain]
        self.sanitizer_helpers: Dict[str, Set[str]] = {}

        self.func_types: Set[str] = set(self.spec.function_node_types) if self.spec else {
            "function_definition", "method_definition", "function_declaration",
            "function_expression", "arrow_function", "generator_function_declaration", "generator_function",
        }
        self.assign_types: Set[str] = (
            set(self.spec.assignment_node_types) if self.spec else set()
        ) | {
            "assignment", "augmented_assignment", "variable_declarator",
            "assignment_expression", "augmented_assignment_expression",
            "short_var_declaration", "let_declaration", "init_declarator",
            "property_declaration", "state_variable_declaration",
            "val_definition", "var_definition", "initialized_variable_definition",
            "variable_declaration_statement", "assignment_statement", "var_spec",
            "operator_assignment", "compound_assignment_expr",
        }
        self.call_types: Set[str] = (
            set(self.spec.call_node_types) if self.spec else set()
        ) | {
            "call", "call_expression", "new_expression", "method_invocation",
            "object_creation_expression", "invocation_expression",
            "function_call_expression", "member_call_expression", "scoped_call_expression",
            "macro_invocation",
        }
        self.loop_types: Set[str] = set(self.spec.loop_node_types) if self.spec else {
            "for_statement", "for_in_statement", "while_statement", "do_statement",
        }
        self.ident_types: Set[str] = (
            set(self.spec.identifier_node_types) if self.spec else set()
        ) | {"identifier", "simple_identifier", "variable_name", "field_identifier", "property_identifier", "name"}
        self.return_types: Set[str] = (
            set(self.spec.return_node_types) if self.spec else set()
        ) | {"return_statement", "return_expression", "return", "jump_expression", "control_transfer_statement"}

        self.sanitizer_domain_map: Dict[str, Tuple[str, ...]] = (
            self.spec.sanitizer_domain_map if self.spec else {}
        )

        self.vars_by_name_and_line: Dict[Tuple[str, int], CPGNode] = {
            (n.name, n.start_line): n for n in nodes
        }

    def emit_dfg_edge(self, source_id: str, target_id: str, var_name: Optional[str] = None) -> None:
        """Emits a deterministic, deduplicated DFG_FLOWS_TO edge."""
        if not source_id or not target_id or source_id == target_id:
            return
        edge_id = compute_edge_id(source_id, target_id, "DFG_FLOWS_TO")
        if edge_id in self._seen_edge_ids:
            return
        self._seen_edge_ids.add(edge_id)
        self.dfg_edges.append(
            CPGEdge(
                id=edge_id,
                source_id=source_id,
                target_id=target_id,
                edge_type="DFG_FLOWS_TO",
                var_name=var_name,
            )
        )

    def find_cpg_node(self, ts_node: Optional[tree_sitter.Node]) -> Optional[CPGNode]:
        """Finds matching CPGNode for an AST node."""
        if ts_node is None:
            return None
        node_id = compute_node_id(self.filepath, ts_node.type, ts_node.start_byte, ts_node.end_byte)
        return self.node_map.get(node_id)

    def find_source_node_in_tree(self, ts_node: tree_sitter.Node) -> Optional[CPGNode]:
        """Finds if any descendant or self is tagged as is_source."""
        cpg = self.find_cpg_node(ts_node)
        if cpg and cpg.is_source:
            return cpg
        for ch in ts_node.children:
            res = self.find_source_node_in_tree(ch)
            if res:
                return res
        return None

    def build(self) -> List[CPGEdge]:
        """Runs reaching definitions and domain-aware sanitizer propagation, emitting DFG_FLOWS_TO edges."""
        parser = get_parser_for_language(self.language)
        if parser is None:
            return self.dfg_edges

        try:
            tree = parser.parse(self.content_bytes or b"")
            root = tree.root_node
        except Exception as exc:
            logger.warning(f"DFG parse degraded for {self.filepath} ({self.language}): {exc}")
            return self.dfg_edges

        if self.language == "web_template":
            self._build_web_template_dfg()
            return self.dfg_edges

        # 1. Pre-scan helper functions to infer structurally verified sanitizer helpers
        self._infer_sanitizer_helpers(root)

        # 2. Initialize formal parameters in symbol tables for each function
        self._initialize_function_parameters()

        # 3. Traverse AST and process definitions, uses, sanitizer propagation, and inter-procedural calls
        self._traverse_for_dataflow(root, current_scope="global")

        return self.dfg_edges

    def _build_web_template_dfg(self) -> None:
        """Emits DFG_FLOWS_TO edges connecting template expressions / HTML inputs sharing variable tokens."""
        var_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{1,40})\b")
        last_seen: Dict[str, CPGNode] = {}
        tpl_nodes = sorted(
            [n for n in self.nodes if n.filepath == self.filepath and n.ast_type in ("template_expression", "attribute")],
            key=lambda n: (n.start_line, n.start_col, n.id),
        )
        for node in tpl_nodes:
            for tok in var_re.findall(node.code):
                if tok.lower() in {"name", "value", "type", "method", "post", "get", "form", "input", "div", "safe", "html", "raw"}:
                    continue
                prev = last_seen.get(tok)
                if prev and prev.id != node.id:
                    self.emit_dfg_edge(prev.id, node.id, var_name=tok)
                last_seen[tok] = node

    # ------------------------------------------------------------------
    # Generalized Domain-Aware Sanitizer Inference & Propagation
    # ------------------------------------------------------------------
    def _infer_sanitizer_helpers(self, root: tree_sitter.Node) -> None:
        """
        Pre-scans function definitions in the file (up to 3 fixed-point iterations) to identify
        helper functions whose return expressions are structurally sanitized for a specific domain D
        (e.g., HTML, SHELL, URL, UNIVERSAL) without unsafe URI attribute interpolation.
        """
        func_nodes: List[Tuple[str, tree_sitter.Node]] = []
        self._collect_named_functions(root, func_nodes)
        if not func_nodes:
            return

        for _ in range(3):
            changed = False
            for fn_name, fn_ts in func_nodes:
                if fn_name in self.sanitizer_helpers:
                    continue
                domains = self._analyze_helper_function_domains(fn_ts)
                if domains:
                    self.sanitizer_helpers[fn_name] = domains
                    changed = True
            if not changed:
                break

    def _collect_named_functions(self, ts_node: tree_sitter.Node, out: List[Tuple[str, tree_sitter.Node]]) -> None:
        if ts_node.type in self.func_types:
            cpg = self.find_cpg_node(ts_node)
            if cpg and cpg.name and cpg.name != "anonymous_func":
                out.append((cpg.name, ts_node))
        # Also detect `const fnName = (...) => ...`
        if ts_node.type == "variable_declarator":
            lhs = ts_node.child_by_field_name("name")
            rhs = ts_node.child_by_field_name("value")
            if lhs is not None and rhs is not None and rhs.type in ("arrow_function", "function_expression"):
                fn_name = lhs.text.decode("utf-8", errors="replace").strip()
                if fn_name:
                    out.append((fn_name, rhs))
        for ch in ts_node.children:
            self._collect_named_functions(ch, out)

    def _analyze_helper_function_domains(self, fn_ts: tree_sitter.Node) -> Set[str]:
        """Checks if every return expression of `fn_ts` is structurally sanitized for a domain."""
        body = fn_ts.child_by_field_name("body")
        if body is None and self.language == "dart" and fn_ts.type in ("function_signature", "method_signature"):
            sib = fn_ts.next_named_sibling
            if sib is not None and sib.type == "function_body":
                body = sib
        if body is None:
            for ch in fn_ts.children:
                if ch.type in _BLOCK_TYPES:
                    body = ch
                    break
        if body is None:
            return set()

        # Concise arrow function body without braces: `(x) => \`<span>${esc(x)}</span>\``
        if body.type not in _BLOCK_TYPES:
            return self._infer_expr_sanitizer_domains(body, scope_id="__helper_tmp__", local_override={})

        # Track local sanitized variables inside helper body before evaluating returns
        local_san: Dict[str, Set[str]] = {}
        return_exprs: List[tree_sitter.Node] = []
        self._walk_helper_body(body, local_san, return_exprs)

        if not return_exprs:
            return set()

        combined: Optional[Set[str]] = None
        for ret_expr in return_exprs:
            ret_domains = self._infer_expr_sanitizer_domains(
                ret_expr, scope_id="__helper_tmp__", local_override=local_san
            )
            if not ret_domains:
                return set()
            combined = set(ret_domains) if combined is None else _combine_domains(combined, ret_domains)
            if not combined:
                return set()
        return combined or set()

    def _walk_helper_body(
        self,
        ts_node: tree_sitter.Node,
        local_san: Dict[str, Set[str]],
        return_exprs: List[tree_sitter.Node],
    ) -> None:
        if ts_node.type in self.func_types:
            return  # Do not descend into nested inner functions

        if ts_node.type in self.assign_types:
            lhs, rhs = self._extract_assignment_sides(ts_node)
            if lhs is not None and rhs is not None:
                var_name = self._extract_lhs_var_name(lhs)
                if var_name:
                    doms = self._infer_expr_sanitizer_domains(
                        rhs, scope_id="__helper_tmp__", local_override=local_san
                    )
                    if ts_node.type in _AUGMENTED_ASSIGN_TYPES:
                        prior = local_san.get(var_name, set())
                        merged = _combine_domains(prior, doms) if prior else doms
                        if merged:
                            local_san[var_name] = merged
                        else:
                            local_san.pop(var_name, None)
                    else:
                        if doms:
                            local_san[var_name] = doms
                        else:
                            local_san.pop(var_name, None)
            return

        if ts_node.type in self.return_types:
            named = [ch for ch in ts_node.children if ch.is_named]
            if named:
                return_exprs.append(named[0])
            return

        for ch in ts_node.children:
            self._walk_helper_body(ch, local_san, return_exprs)

    def _lookup_sanitized_var(
        self,
        var_name: str,
        scope_id: str,
        local_override: Optional[Dict[str, Set[str]]] = None,
    ) -> Set[str]:
        if local_override is not None:
            if var_name in local_override:
                return set(local_override[var_name])
        scoped = self.sanitized_vars.get(scope_id, {}).get(var_name)
        if scoped:
            return set(scoped)
        glob = self.sanitized_vars.get("global", {}).get(var_name)
        if glob:
            return set(glob)
        return set()

    def _infer_call_sanitizer_domains(
        self,
        call_ts: tree_sitter.Node,
        scope_id: str,
        local_override: Optional[Dict[str, Set[str]]] = None,
    ) -> Set[str]:
        """Infers sanitizer domains produced by a call expression."""
        raw = call_ts.text.decode("utf-8", errors="replace").strip()
        if has_unsafe_uri_interpolation(raw):
            return set()

        call_cpg = self.find_cpg_node(call_ts)
        if call_cpg and call_cpg.is_sanitizer:
            return set(call_cpg.sanitizer_domains) or {"UNIVERSAL"}

        func_name, short_name = self._extract_call_names(call_ts)

        # Direct registered sanitizer function
        if func_name in _SAFE_NUMERIC_CALL_NAMES or short_name in _SAFE_NUMERIC_CALL_NAMES:
            return {"UNIVERSAL"}
        if func_name in _HTML_SANITIZER_NAMES or short_name in _HTML_SANITIZER_NAMES:
            return {"HTML"}
        if func_name in _URL_SANITIZER_NAMES or short_name in _URL_SANITIZER_NAMES:
            return {"URL"}

        if func_name in self.sanitizer_domain_map:
            return set(self.sanitizer_domain_map[func_name])
        if short_name in self.sanitizer_domain_map:
            return set(self.sanitizer_domain_map[short_name])

        # Structurally verified helper function in this file
        if func_name in self.sanitizer_helpers:
            return set(self.sanitizer_helpers[func_name])
        if short_name in self.sanitizer_helpers:
            return set(self.sanitizer_helpers[short_name])

        # Chained `.join(...)` on a sanitized `.map(...)` or sanitized array variable
        if short_name == "join":
            func_node = call_ts.child_by_field_name("function")
            if func_node is not None and func_node.type in ("member_expression", "attribute"):
                obj = func_node.child_by_field_name("object")
                if obj is not None:
                    return self._infer_expr_sanitizer_domains(obj, scope_id, local_override)

        # `.map(item => ...)` callback returning sanitized HTML
        if short_name == "map":
            args_node = call_ts.child_by_field_name("arguments")
            if args_node is not None:
                for ch in args_node.children:
                    if ch.type in ("arrow_function", "function_expression"):
                        cb_domains = self._analyze_helper_function_domains(ch)
                        if cb_domains:
                            return cb_domains
                    elif ch.type in self.ident_types:
                        cb_name = ch.text.decode("utf-8", errors="replace").strip()
                        if cb_name in self.sanitizer_helpers:
                            return set(self.sanitizer_helpers[cb_name])

        # Safe string-preserving transforms on an already-sanitized receiver (`.trim()`, `.toLowerCase()`, etc.)
        if short_name in ("trim", "toLowerCase", "toUpperCase", "slice", "substring", "strip"):
            func_node = call_ts.child_by_field_name("function")
            if func_node is not None and func_node.type in ("member_expression", "attribute"):
                obj = func_node.child_by_field_name("object")
                if obj is not None:
                    return self._infer_expr_sanitizer_domains(obj, scope_id, local_override)

        return set()

    def _infer_expr_sanitizer_domains(
        self,
        expr_ts: Optional[tree_sitter.Node],
        scope_id: str,
        local_override: Optional[Dict[str, Set[str]]] = None,
    ) -> Set[str]:
        """
        Recursively determines which security domains an RHS expression is proven sanitized for.
        Returns `set()` if the expression is tainted/unsanitized or contains an unsafe URI attribute interpolation.
        """
        if expr_ts is None:
            return set()

        raw = expr_ts.text.decode("utf-8", errors="replace").strip()
        if not raw:
            return set()

        # Hard guard: NEVER mark an expression containing `<a href="${esc(...)}">` / `src="${...}"` as sanitized!
        if has_unsafe_uri_interpolation(raw):
            return set()

        etype = expr_ts.type

        # Unwrap parenthesized / expression_list / equals_value_clause wrappers
        if etype in ("parenthesized_expression", "expression_list", "equals_value_clause"):
            named = [ch for ch in expr_ts.children if ch.is_named]
            if len(named) == 1:
                return self._infer_expr_sanitizer_domains(named[0], scope_id, local_override)

        # 1. Pure non-string literals (numbers, booleans, null) -> UNIVERSAL
        if etype in _PURE_LITERAL_TYPES:
            return {"UNIVERSAL"}

        # 2. Pure string literals without interpolation -> UNIVERSAL
        if etype in _STRING_LITERAL_TYPES:
            # Guard against Python f-strings (`f"..."`), PHP `"$var"`, Ruby `"#{var}"`
            if raw.startswith(("f'", 'f"', "F'", 'F"', "rf'", 'rf"', "fr'", 'fr"')) and "{" in raw:
                return set()
            if self.language in ("php", "ruby", "kotlin", "swift", "dart", "scala") and (
                "$" in raw or "#{" in raw or "\\(" in raw
            ):
                return set()
            return {"UNIVERSAL"}

        # 3. Template strings (`...${...}...`)
        if etype == "template_string":
            subs = [ch for ch in expr_ts.children if ch.type == "template_substitution"]
            if not subs:
                return {"UNIVERSAL"}
            for sub in subs:
                sub_named = [c for c in sub.children if c.is_named]
                if not sub_named:
                    continue
                sub_expr = sub_named[0]
                sub_doms = self._infer_expr_sanitizer_domains(sub_expr, scope_id, local_override)
                if not sub_doms:
                    # Fallback to structural HTML safety check (e.g. `.length`, comparisons, constants)
                    sub_txt = sub_expr.text.decode("utf-8", errors="replace").strip()
                    if _is_structurally_safe_html_expr(sub_txt):
                        sub_doms = {"HTML"}
                if not ("HTML" in sub_doms or "UNIVERSAL" in sub_doms):
                    return set()
            return {"HTML"}

        # 4. Call expressions (sanitizer calls or verified sanitizer helpers)
        if etype in self.call_types or etype in ("call", "call_expression"):
            return self._infer_call_sanitizer_domains(expr_ts, scope_id, local_override)

        # 5. Identifiers -> look up in sanitized_vars (or uppercase constant)
        if etype in self.ident_types:
            if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", raw):
                return {"UNIVERSAL"}
            return self._lookup_sanitized_var(raw, scope_id, local_override)

        # 6. Member expressions (`arr.length`)
        if etype in ("member_expression", "attribute"):
            if raw.endswith(".length"):
                return {"UNIVERSAL"}
            return set()

        # 7. Binary expressions (`a + b`, `a || ""`, `a ?? ""`, comparisons `a === b`)
        if etype in ("binary_expression", "boolean_operator", "comparison_operator"):
            left_ch = expr_ts.child_by_field_name("left")
            right_ch = expr_ts.child_by_field_name("right")
            op_ch = expr_ts.child_by_field_name("operator")
            op_txt = op_ch.text.decode("utf-8", errors="replace").strip() if op_ch else ""
            if op_txt in ("===", "!==", "==", "!=", "<", ">", "<=", ">=", "&&"):
                return {"UNIVERSAL"}
            if left_ch is not None and right_ch is not None:
                l_doms = self._infer_expr_sanitizer_domains(left_ch, scope_id, local_override)
                r_doms = self._infer_expr_sanitizer_domains(right_ch, scope_id, local_override)
                return _combine_domains(l_doms, r_doms)

        # 8. Ternary / conditional expressions (`cond ? a : b`)
        if etype in ("ternary_expression", "conditional_expression"):
            conseq = expr_ts.child_by_field_name("consequence")
            alt = expr_ts.child_by_field_name("alternative")
            if conseq is not None and alt is not None:
                c_doms = self._infer_expr_sanitizer_domains(conseq, scope_id, local_override)
                a_doms = self._infer_expr_sanitizer_domains(alt, scope_id, local_override)
                return _combine_domains(c_doms, a_doms)

        # 9. Unary expressions (`!x`, `-n`, `typeof x`)
        if etype in ("unary_expression", "not_operator"):
            return {"UNIVERSAL"}

        # Check if the node itself was pre-classified as a sanitizer in Pass 1
        cpg = self.find_cpg_node(expr_ts)
        if cpg and cpg.is_sanitizer:
            return set(cpg.sanitizer_domains) or {"UNIVERSAL"}

        return set()

    # ------------------------------------------------------------------
    # Standard DFG Construction Across All 18 Languages
    # ------------------------------------------------------------------
    def _initialize_function_parameters(self) -> None:
        """Registers formal parameters into each function's local symbol table."""
        param_container_types = {
            "parameters", "formal_parameters", "parameter_list",
            "function_value_parameters", "method_parameters", "block_parameters",
            "formal_parameter_list",
        }
        params_by_scope: Dict[str, List[CPGNode]] = {}
        seen_by_scope: Dict[str, Set[str]] = {}
        for n in self.nodes:
            if (
                n.label == "Parameter"
                and n.ast_type not in param_container_types
                and not n.name.startswith("(")
            ):
                seen = seen_by_scope.setdefault(n.scope_id, set())
                if n.name not in seen:
                    seen.add(n.name)
                    params_by_scope.setdefault(n.scope_id, []).append(n)

        for node in self.nodes:
            if node.label == "Function" and node.filepath == self.filepath:
                func_id = node.id
                self.defs.setdefault(func_id, {})
                params = params_by_scope.get(func_id) or self.function_params_map.get(node.name, [])
                for p in params:
                    self.defs[func_id][p.name] = [p.id]

    def _traverse_for_dataflow(self, ts_node: tree_sitter.Node, current_scope: str) -> None:
        """Traverses AST nodes and builds def-use chains across all 18 languages."""
        node_type = ts_node.type

        # Dart special case: pair `function_signature` with its sibling `function_body` under the same scope
        if self.language == "dart" and node_type in ("program", "class_body", "block"):
            children = ts_node.children
            idx = 0
            while idx < len(children):
                ch = children[idx]
                if ch.type in ("function_signature", "method_signature"):
                    fn_cpg = self.find_cpg_node(ch)
                    fn_scope = fn_cpg.id if fn_cpg else current_scope
                    self.defs.setdefault(fn_scope, {})
                    if idx + 1 < len(children) and children[idx + 1].type == "function_body":
                        self._traverse_for_dataflow(children[idx + 1], fn_scope)
                        idx += 2
                        continue
                self._traverse_for_dataflow(ch, current_scope)
                idx += 1
            return

        # Function scope changes
        if node_type in self.func_types:
            func_cpg = self.find_cpg_node(ts_node)
            new_scope = func_cpg.id if func_cpg else current_scope
            self.defs.setdefault(new_scope, {})
            for child in ts_node.children:
                self._traverse_for_dataflow(child, new_scope)
            return

        # 1. Assignments
        if node_type in self.assign_types:
            self._process_assignment(ts_node, current_scope)
            _, right = self._extract_assignment_sides(ts_node)
            if right is not None:
                if right.type in self.call_types or (
                    self.language == "dart" and right.type == "selector"
                ):
                    self._process_call(right, current_scope)
                for ch in right.children:
                    self._traverse_for_dataflow(ch, current_scope)
            return

        # 2. For-loop iterator flow
        if node_type in self.loop_types:
            left_iter = ts_node.child_by_field_name("left") or ts_node.child_by_field_name("pattern")
            right_iter = ts_node.child_by_field_name("right") or ts_node.child_by_field_name("value")
            if left_iter is not None and right_iter is not None:
                iter_target = self.find_cpg_node(left_iter)
                if iter_target:
                    for use_cpg in self._extract_variable_uses(right_iter):
                        self._link_reaching_definitions(use_cpg, current_scope)
                        self.emit_dfg_edge(use_cpg.id, iter_target.id, var_name=iter_target.name)
                    self.defs.setdefault(current_scope, {})[iter_target.name] = [iter_target.id]
            for child in ts_node.children:
                self._traverse_for_dataflow(child, current_scope)
            return

        # 3. Return statements: link uses in return expression to reaching definitions & Return node
        if node_type in self.return_types:
            ret_cpg = self.find_cpg_node(ts_node)
            for use_cpg in self._extract_variable_uses(ts_node):
                self._link_reaching_definitions(use_cpg, current_scope)
                if ret_cpg and ret_cpg.id != use_cpg.id:
                    self.emit_dfg_edge(use_cpg.id, ret_cpg.id, var_name=use_cpg.name)
            for child in ts_node.children:
                self._traverse_for_dataflow(child, current_scope)
            return

        # 4. Calls (all 18 languages, including Dart `selector` invocations)
        if node_type in self.call_types or (
            self.language == "dart"
            and node_type == "selector"
            and any(ch.type == "argument_part" for ch in ts_node.children)
        ):
            self._process_call(ts_node, current_scope)
            for ch in ts_node.children:
                self._traverse_for_dataflow(ch, current_scope)
            return

        for child in ts_node.children:
            self._traverse_for_dataflow(child, current_scope)

    def _extract_assignment_sides(
        self, assign_ts: tree_sitter.Node
    ) -> Tuple[Optional[tree_sitter.Node], Optional[tree_sitter.Node]]:
        """Extracts `(lhs_node, rhs_node)` from any assignment/declaration AST shape across 18 languages."""
        left = (
            assign_ts.child_by_field_name("left")
            or assign_ts.child_by_field_name("name")
            or assign_ts.child_by_field_name("pattern")
            or assign_ts.child_by_field_name("declarator")
        )
        right = (
            assign_ts.child_by_field_name("right")
            or assign_ts.child_by_field_name("value")
            or assign_ts.child_by_field_name("initializer")
        )

        # Unwrap Go expression_list (`y := x`)
        if left is not None and left.type == "expression_list" and left.named_children:
            left = left.named_children[0]
        if right is not None and right.type == "expression_list" and right.named_children:
            right = right.named_children[0]

        # C# variable_declarator (`var y = x;` -> children `[identifier, equals_value_clause]`)
        if right is None:
            for ch in assign_ts.children:
                if ch.type == "equals_value_clause" and ch.named_children:
                    right = ch.named_children[0]
                    break

        # Kotlin `property_declaration` / Solidity `variable_declaration_statement`
        if left is None or right is None:
            named = [ch for ch in assign_ts.children if ch.is_named]
            if left is None and named:
                for ch in named:
                    if ch.type in ("variable_declaration", "identifier", "simple_identifier", "variable_name", "pattern"):
                        left = ch
                        break
            if right is None and len(named) >= 2:
                # Take the last expression child that isn't the LHS or a type annotation
                for ch in reversed(named):
                    if ch != left and ch.type not in ("type", "user_type", "type_identifier", "type_name", "binding_pattern_kind"):
                        right = ch
                        break

        return left, right

    def _extract_lhs_var_name(self, left: tree_sitter.Node) -> str:
        """Extracts a clean variable name from an LHS AST node."""
        if left.type in ("pointer_declarator", "reference_declarator", "array_declarator"):
            cname = _unwrap_c_declarator_name(left)
            if cname:
                return cname
        if left.type == "variable_declaration":
            for ch in left.children:
                if ch.type in self.ident_types:
                    return ch.text.decode("utf-8", errors="replace").strip()
        return left.text.decode("utf-8", errors="replace").strip()

    def _find_lhs_cpg_node(self, left: tree_sitter.Node, assign_cpg: Optional[CPGNode]) -> Optional[CPGNode]:
        """Finds the target CPGNode for an assignment LHS across all 18 languages."""
        target = self.find_cpg_node(left)
        if target is not None:
            return target
        # Unwrap C/C++ pointer_declarator or Kotlin/Solidity variable_declaration to inner identifier
        for ch in left.children:
            if ch.type in self.ident_types:
                inner = self.find_cpg_node(ch)
                if inner is not None:
                    return inner
        var_name = self._extract_lhs_var_name(left)
        target = self.vars_by_name_and_line.get((var_name, left.start_point[0] + 1))
        if target is not None:
            return target
        return assign_cpg

    def _process_assignment(self, assign_ts: tree_sitter.Node, scope_id: str) -> None:
        """
        Handles assignment def-use flow AND domain-aware sanitizer propagation:
        - Uses in RHS propagate to target in LHS
        - Reaching definitions propagate to uses in RHS
        - Propagates domain-scoped sanitizers into `self.sanitized_vars` and LHS `CPGNode`
        - Clears `.innerHTML`/`.outerHTML` `is_sink` ONLY when `sink_domain` is satisfied!
        """
        left, right = self._extract_assignment_sides(assign_ts)
        if left is None or right is None:
            return

        assign_cpg = self.find_cpg_node(assign_ts)
        target_cpg = self._find_lhs_cpg_node(left, assign_cpg)
        if target_cpg is None:
            return

        target_var_name = self._extract_lhs_var_name(left) or target_cpg.name
        uses = self._extract_variable_uses(right)
        right_cpg = self.find_cpg_node(right)
        source_cpg = self.find_source_node_in_tree(right)

        # Compute domain-aware sanitizer status of RHS
        rhs_domains = self._infer_expr_sanitizer_domains(right, scope_id)

        # Merge Pass-1 sanitizer classification if right_cpg or assign_cpg is already tagged as sanitizer
        if right_cpg and right_cpg.is_sanitizer:
            rhs_domains = rhs_domains | (set(right_cpg.sanitizer_domains) or {"UNIVERSAL"})
        if assign_cpg and assign_cpg.is_sanitizer:
            rhs_domains = rhs_domains | (set(assign_cpg.sanitizer_domains) or {"UNIVERSAL"})

        # Check DOM HTML sink resolution BEFORE updating symbol table
        is_dom_html_sink = bool(
            assign_cpg
            and assign_cpg.is_sink
            and (
                assign_cpg.name.endswith(".innerHTML")
                or assign_cpg.name.endswith(".outerHTML")
                or assign_cpg.name == "dangerouslySetInnerHTML"
            )
        )
        if is_dom_html_sink and assign_cpg is not None:
            if assign_cpg.sink_domain == "URL":
                # NEVER allow HTML-only sanitizer to clear URL scheme sink!
                if "URL" in rhs_domains or "UNIVERSAL" in rhs_domains:
                    assign_cpg.is_sink = False
            elif assign_cpg.sink_domain in ("HTML", None):
                if "HTML" in rhs_domains or "UNIVERSAL" in rhs_domains:
                    assign_cpg.is_sink = False

        # Propagate or kill sanitized_vars for normal variable LHS (not DOM property sinks)
        if not is_dom_html_sink:
            scope_san = self.sanitized_vars.setdefault(scope_id, {})
            if assign_ts.type in _AUGMENTED_ASSIGN_TYPES:
                prior = scope_san.get(target_var_name, set())
                effective_domains = _combine_domains(prior, rhs_domains) if prior else rhs_domains
            else:
                effective_domains = rhs_domains

            if effective_domains:
                scope_san[target_var_name] = set(effective_domains)
                target_cpg.is_sanitizer = True
                merged_doms = sorted(set(target_cpg.sanitizer_domains) | effective_domains)
                target_cpg.sanitizer_domains = merged_doms
            else:
                scope_san.pop(target_var_name, None)

        # Emit DFG edges
        if (right_cpg and right_cpg.is_sanitizer) or (assign_cpg and assign_cpg.is_sanitizer):
            target_cpg.is_sanitizer = True
            if source_cpg and right_cpg and source_cpg.id != right_cpg.id:
                self.emit_dfg_edge(source_cpg.id, right_cpg.id, var_name=target_var_name)
            for use_cpg in uses:
                self._link_reaching_definitions(use_cpg, scope_id)
                if right_cpg:
                    self.emit_dfg_edge(use_cpg.id, right_cpg.id, var_name=use_cpg.name)
            if right_cpg:
                self.emit_dfg_edge(right_cpg.id, target_cpg.id, var_name=target_var_name)
        elif (
            right_cpg
            and right_cpg.label == "Call"
            and not (
                scope_id == "global"
                and target_var_name.isupper()
                and right_cpg.name in ("dict", "set", "list", "tuple", "frozenset")
            )
        ):
            if source_cpg:
                self.emit_dfg_edge(source_cpg.id, target_cpg.id, var_name=target_var_name)
            for use_cpg in uses:
                self._link_reaching_definitions(use_cpg, scope_id)
                self.emit_dfg_edge(use_cpg.id, right_cpg.id, var_name=use_cpg.name)
            self.emit_dfg_edge(right_cpg.id, target_cpg.id, var_name=target_var_name)
        else:
            if source_cpg:
                self.emit_dfg_edge(source_cpg.id, target_cpg.id, var_name=target_var_name)
            for use_cpg in uses:
                self._link_reaching_definitions(use_cpg, scope_id)
                self.emit_dfg_edge(use_cpg.id, target_cpg.id, var_name=target_var_name)

        # If assignment itself remains a DOM sink, link RHS uses into the Assignment CPGNode
        if assign_cpg and assign_cpg.is_sink:
            for use_cpg in uses:
                self.emit_dfg_edge(use_cpg.id, assign_cpg.id, var_name=use_cpg.name)

        # Update symbol table with this definition
        self.defs.setdefault(scope_id, {})[target_var_name] = [target_cpg.id]

    def _extract_call_names(self, call_ts: tree_sitter.Node) -> Tuple[str, str]:
        """Extracts `(full_callee_name, short_callee_name)` across all 18 language call shapes."""
        if self.language == "dart" and call_ts.type == "selector":
            prev = call_ts.prev_named_sibling
            if prev is not None:
                fname = prev.text.decode("utf-8", errors="replace").strip()
                return fname, re.split(r"(?:\.|->|::)", fname)[-1]

        if call_ts.type == "method_invocation":
            obj = call_ts.child_by_field_name("object")
            name = call_ts.child_by_field_name("name")
            short = name.text.decode("utf-8", errors="replace").strip() if name else ""
            full = f"{obj.text.decode('utf-8', errors='replace').strip()}.{short}" if (obj and short) else short
            return full, short

        if call_ts.type in ("member_call_expression", "scoped_call_expression"):
            obj = call_ts.child_by_field_name("object") or call_ts.child_by_field_name("scope")
            name = call_ts.child_by_field_name("name")
            short = name.text.decode("utf-8", errors="replace").strip() if name else ""
            sep = "::" if call_ts.type == "scoped_call_expression" else "->"
            full = f"{obj.text.decode('utf-8', errors='replace').strip()}{sep}{short}" if (obj and short) else short
            return full, short

        func_node = (
            call_ts.child_by_field_name("function")
            or call_ts.child_by_field_name("method")
            or call_ts.child_by_field_name("macro")
        )
        if func_node is not None:
            full = func_node.text.decode("utf-8", errors="replace").strip()
        else:
            full = ""
            for ch in call_ts.children:
                if ch.is_named and ch.type in (
                    "simple_identifier", "identifier", "navigation_expression", "member_expression", "scoped_identifier"
                ):
                    full = ch.text.decode("utf-8", errors="replace").strip()
                    break

        short = re.split(r"(?:\.|->|::)", full)[-1] if full else ""
        return full, short

    def _extract_call_args_node(self, call_ts: tree_sitter.Node) -> Optional[tree_sitter.Node]:
        """Finds the arguments container node for a call across all 18 grammars."""
        args_node = call_ts.child_by_field_name("arguments")
        if args_node is not None:
            return args_node
        for ch in call_ts.children:
            if ch.type in ("arguments", "argument_list", "value_arguments", "call_suffix", "argument_part"):
                return ch
        return None

    def _process_call(self, call_ts: tree_sitter.Node, scope_id: str) -> None:
        """
        Handles Call nodes:
        - Links reaching definitions to arguments
        - Tags calls to structurally verified sanitizer helpers
        - Links argument uses to called function's formal parameters (Inter-procedural DFG)
        - Links argument uses into sink Call nodes
        """
        call_cpg = self.find_cpg_node(call_ts)
        func_name, short_name = self._extract_call_names(call_ts)
        args_node = self._extract_call_args_node(call_ts)

        # Tag call site if it invokes a structurally verified sanitizer helper
        if call_cpg is not None:
            helper_doms = self.sanitizer_helpers.get(func_name) or self.sanitizer_helpers.get(short_name)
            if helper_doms:
                call_cpg.is_sanitizer = True
                call_cpg.sanitizer_domains = sorted(set(call_cpg.sanitizer_domains) | helper_doms)

        arg_uses: List[CPGNode] = []

        # Link variable uses in the function / object expression
        func_node = call_ts.child_by_field_name("function") or call_ts.child_by_field_name("object")
        if func_node is not None:
            for fv in self._extract_variable_uses(func_node):
                self._link_reaching_definitions(fv, scope_id)
                if call_cpg:
                    self.emit_dfg_edge(fv.id, call_cpg.id, var_name=fv.name)

        if args_node is not None:
            for child in args_node.children:
                if child.is_named:
                    for av in self._extract_variable_uses(child):
                        self._link_reaching_definitions(av, scope_id)
                        arg_uses.append(av)

        # 1. Inter-procedural flow: Argument -> Call Site -> Formal Parameter
        target_params = self.function_params_map.get(short_name) or self.function_params_map.get(func_name)
        if target_params and arg_uses:
            for i, arg_u in enumerate(arg_uses):
                if i < len(target_params):
                    param_cpg = target_params[i]
                    if call_cpg:
                        self.emit_dfg_edge(arg_u.id, call_cpg.id, var_name=arg_u.name)
                        self.emit_dfg_edge(call_cpg.id, param_cpg.id, var_name=param_cpg.name)
                    else:
                        self.emit_dfg_edge(arg_u.id, param_cpg.id, var_name=param_cpg.name)

        # 2. Sink flow: arguments flow into sink or secondary security sink
        is_secondary_security_sink = (
            short_name in {
                "open", "rmtree", "remove", "unlink", "send_file", "FileResponse",
                "readFile", "readFileSync", "writeFile", "writeFileSync", "rmSync",
                "urlopen", "urlretrieve",
                "loads", "load", "md5", "sha1", "decode", "encode", "driver", "connect",
                "println", "print", "puts", "printf", "WriteLine",
            }
            or func_name in {
                "requests.get", "requests.post", "requests.put", "requests.delete", "requests.request",
                "http_requests.get", "http_requests.post", "http_requests.request",
                "httpx.get", "httpx.post", "axios.get", "axios.post",
                "logger.info", "logger.warning", "logger.error", "logger.critical",
                "logging.info", "logging.warning", "logging.error",
                "GraphDatabase.driver", "psycopg2.connect", "mysql.connector.connect",
            }
        )
        if call_cpg and (call_cpg.is_sink or is_secondary_security_sink or func_name.endswith(".setAttribute")):
            for arg_u in arg_uses:
                self.emit_dfg_edge(arg_u.id, call_cpg.id, var_name=arg_u.name)

    def _link_reaching_definitions(self, use_cpg: CPGNode, scope_id: str) -> None:
        """Looks up reaching definitions for variable use and emits DFG_FLOWS_TO."""
        var_name = use_cpg.name
        reaching_ids = self.defs.get(scope_id, {}).get(var_name)
        if not reaching_ids and "global" in self.defs:
            reaching_ids = self.defs["global"].get(var_name)

        if reaching_ids:
            for r_id in reaching_ids:
                if r_id != use_cpg.id:
                    self.emit_dfg_edge(r_id, use_cpg.id, var_name=var_name)

    def _extract_variable_uses(self, ts_node: tree_sitter.Node) -> List[CPGNode]:
        """Extracts variable identifier uses from an expression across all 18 languages."""
        results: List[CPGNode] = []

        if ts_node.type in self.ident_types:
            cpg = self.find_cpg_node(ts_node)
            if cpg and cpg.label in ("Variable", "Parameter"):
                results.append(cpg)
            return results

        if ts_node.type in ("attribute", "member_expression", "field_expression", "selector_expression", "navigation_expression"):
            obj_child = ts_node.child_by_field_name("object") or ts_node.child_by_field_name("operand") or ts_node.child_by_field_name("argument")
            if obj_child is not None:
                results.extend(self._extract_variable_uses(obj_child))
                return results

        if ts_node.type in self.call_types:
            func_child = ts_node.child_by_field_name("function") or ts_node.child_by_field_name("object")
            args_child = self._extract_call_args_node(ts_node)
            if func_child is not None:
                results.extend(self._extract_variable_uses(func_child))
            if args_child is not None:
                results.extend(self._extract_variable_uses(args_child))
            return results

        for child in ts_node.children:
            results.extend(self._extract_variable_uses(child))

        return results
