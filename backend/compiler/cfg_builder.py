"""
Pass 2: Unified 18-Language Deterministic Control Flow Graph (CFG) State Machine.
Builds basic-block/statement-level CFG with explicit branching, cycles, and jump semantics
using the declarative LanguageSpec registry.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter

from compiler.ast_parser import (
    compute_edge_id,
    compute_node_id,
    js_parser,
    py_parser,
    ts_parser,
    tsx_parser,
)
from compiler.language_registry import LANGUAGE_SPECS, LanguageSpec, get_parser_for_language
from models import CPGEdge, CPGNode

logger = logging.getLogger("cpg-sast.compiler.cfg")

_BLOCK_CONTAINER_TYPES: Set[str] = {
    "block",
    "statement_block",
    "compound_statement",
    "function_body",
    "body_statement",
    "statements",
    "statement_list",
    "control_structure_body",
    "then",
    "do",
    "else_clause",
}

_WRAPPER_STMT_TYPES: Set[str] = {
    "expression_statement",
    "lexical_declaration",
    "variable_declaration",
    "local_variable_declaration",
    "local_declaration_statement",
    "declaration",
    "export_statement",
}

_NEUTRAL_TERMINATOR_TYPES: Set[str] = {
    "break_statement",
    "continue_statement",
    "throw_statement",
    "raise_statement",
    "panic",
    "return_statement",
    "return_expression",
    "break_expression",
    "jump_expression",
    "control_transfer_statement",
    "return",
}

_HARD_EXIT_TERMINATOR_TYPES: Set[str] = {
    "return_statement",
    "return_expression",
    "return",
    "raise_statement",
    "throw_statement",
    "panic",
    "jump_expression",
    "control_transfer_statement",
}

_BREAK_TYPES: Set[str] = {
    "break_statement",
    "break_expression",
    "break",
}

_IF_CONTROL_TYPES: Set[str] = {
    "if_statement",
    "if_expression",
    "if",
    "unless",
    "guard_statement",
}


def is_truthy_literal(condition_node: tree_sitter.Node) -> bool:
    """Checks if the loop condition is a constant truthy literal (True, 1, non-empty string)."""
    text = condition_node.text.decode("utf-8", errors="replace").strip().strip("()")
    if text in ("True", "1", "true"):
        return True
    if text.startswith(('"', "'")) and len(text) > 2:
        return True
    return False


def body_has_terminator(
    node: tree_sitter.Node,
    loop_types: Optional[Set[str]] = None,
    func_types: Optional[Set[str]] = None,
) -> bool:
    """Recursively checks whether a loop body contains any break, return, raise, throw, or panic."""
    if node.type in _NEUTRAL_TERMINATOR_TYPES:
        # `continue` does not exit a loop
        if node.type == "continue_statement":
            return False
        if node.type in ("jump_expression", "control_transfer_statement"):
            txt = node.text.decode("utf-8", errors="replace").strip()
            if txt.startswith("continue"):
                return False
        return True

    skip_nested = (loop_types or {
        "while_statement", "for_statement", "for_in_statement", "do_statement",
        "while_expression", "for_expression", "loop_expression", "while", "until", "for",
    }) | (func_types or {
        "function_definition", "function_declaration", "function_expression",
        "arrow_function", "method_definition", "method_declaration", "function_item", "method",
    })

    for child in node.children:
        if child.type in skip_nested:
            continue
        if body_has_terminator(child, loop_types=loop_types, func_types=func_types):
            return True
    return False


class CFGBuilder:
    def __init__(
        self,
        filepath: str,
        content_bytes: bytes,
        language: str,
        nodes: List[CPGNode],
        node_map: Dict[str, CPGNode],
    ):
        self.filepath = filepath
        self.content_bytes = content_bytes
        self.language = (language or "python").strip().lower()
        self.spec: Optional[LanguageSpec] = LANGUAGE_SPECS.get(self.language)
        self.nodes = nodes
        self.node_map = node_map
        self.cfg_edges: List[CPGEdge] = []
        self._seen_edge_ids: Set[str] = set()
        self.ts_by_cpg_id: Dict[str, tree_sitter.Node] = {}

        self.func_types: Set[str] = set(self.spec.function_node_types) if self.spec else {
            "function_definition", "function_declaration", "function_expression",
            "arrow_function", "method_definition",
        }
        self.class_types: Set[str] = set(self.spec.class_node_types) if self.spec else {
            "class_definition", "class_declaration",
        }
        self.control_types: Set[str] = set(self.spec.control_node_types) if self.spec else {
            "if_statement", "elif_clause", "else_clause", "switch_statement",
        }
        self.loop_types: Set[str] = set(self.spec.loop_node_types) if self.spec else {
            "while_statement", "for_statement", "for_in_statement", "do_statement",
        }
        self.return_types: Set[str] = (
            (set(self.spec.return_node_types) if self.spec else set()) | _HARD_EXIT_TERMINATOR_TYPES
        )
        self.skip_types: Set[str] = (
            (set(self.spec.skip_node_types) if self.spec else set())
            | {"comment", "line_comment", "block_comment", "multiline_comment", "documentation_comment"}
        )

        # Fast lookup by start_col, end_col, and ast_type
        self.cpg_by_span: Dict[Tuple[int, int, str], CPGNode] = {
            (n.start_col, n.end_col, n.ast_type): n for n in nodes
        }

    def _index_ts_nodes(self, ts_node: tree_sitter.Node) -> None:
        """Indexes all Tree-Sitter nodes by their deterministic CPG ID in O(N) time."""
        cid = compute_node_id(self.filepath, ts_node.type, ts_node.start_byte, ts_node.end_byte)
        self.ts_by_cpg_id[cid] = ts_node
        for ch in ts_node.children:
            self._index_ts_nodes(ch)

    def _extract_block_statements(self, container: Optional[tree_sitter.Node]) -> List[tree_sitter.Node]:
        """Flattens nested block/statement_list/statements containers into executable child statements."""
        if container is None:
            return []
        if container.type in _BLOCK_CONTAINER_TYPES:
            out: List[tree_sitter.Node] = []
            for ch in container.children:
                if not ch.is_named or ch.type in self.skip_types:
                    continue
                if ch.type in ("statement_list", "statements", "block") and container.type in (
                    "block", "function_body", "control_structure_body", "else_clause"
                ):
                    out.extend(self._extract_block_statements(ch))
                else:
                    out.append(ch)
            return out
        return [container]

    def find_cpg_node(self, ts_node: Optional[tree_sitter.Node]) -> Optional[CPGNode]:
        """Finds the corresponding CPGNode for a tree-sitter node (unwrapping statement wrappers)."""
        if ts_node is None:
            return None

        # Dart expression_statement calling a function: `identifier` followed by `selector(argument_part)`
        if self.language == "dart" and ts_node.type == "expression_statement":
            for ch in ts_node.children:
                if ch.type == "selector" and any(sc.type == "argument_part" for sc in ch.children):
                    found = self.find_cpg_node(ch)
                    if found:
                        return found

        if ts_node.type in _WRAPPER_STMT_TYPES and ts_node.children:
            for ch in ts_node.children:
                if ch.is_named:
                    found = self.find_cpg_node(ch)
                    if found:
                        return found

        node_id = compute_node_id(self.filepath, ts_node.type, ts_node.start_byte, ts_node.end_byte)
        return self.node_map.get(node_id)

    def emit_cfg_edge(self, source_id: str, target_id: str, edge_type: str) -> None:
        """Emits a deterministic, deduplicated CFG edge."""
        if not source_id or not target_id or source_id == target_id:
            return
        edge_id = compute_edge_id(source_id, target_id, edge_type)
        if edge_id in self._seen_edge_ids:
            return
        self._seen_edge_ids.add(edge_id)
        self.cfg_edges.append(
            CPGEdge(
                id=edge_id,
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
            )
        )

    def build(self) -> List[CPGEdge]:
        parser = get_parser_for_language(self.language)
        if parser is None:
            return self.cfg_edges

        try:
            tree = parser.parse(self.content_bytes or b"")
            root = tree.root_node
        except Exception as exc:
            logger.warning(f"CFG parse degraded for {self.filepath} ({self.language}): {exc}")
            return self.cfg_edges

        # Build O(1) lookup index from CPG ID -> Tree-Sitter node
        self._index_ts_nodes(root)

        # Special sequential CFG for web_template nodes (elements + template expressions)
        if self.language == "web_template":
            self._build_web_template_cfg()
            return self.cfg_edges

        # Build CFG for each function across all 18 languages
        self._process_functions(root)

        # Build CFG for top-level module statements
        decl_skip = self.func_types | self.class_types | self.skip_types | {"function_body"}
        top_stmts = [
            c for c in root.children
            if c.is_named and c.type not in decl_skip
        ]
        self._link_statement_sequence(top_stmts, post_node=None, exit_node=None)

        return self.cfg_edges

    def _build_web_template_cfg(self) -> None:
        """Links sequential HTML/template expression nodes in source order via CFG_NEXT."""
        ordered = sorted(
            [
                n for n in self.nodes
                if n.filepath == self.filepath
                and n.label in ("Call", "Assignment")
                and n.ast_type in ("template_expression", "element")
            ],
            key=lambda n: (n.start_line, n.start_col, n.id),
        )
        for idx in range(len(ordered) - 1):
            self.emit_cfg_edge(ordered[idx].id, ordered[idx + 1].id, "CFG_NEXT")

    def _find_function_body(self, func_ts: tree_sitter.Node) -> Optional[tree_sitter.Node]:
        """Finds the body AST node for a function across all 18 language grammars."""
        body_node = func_ts.child_by_field_name("body")
        if body_node is not None:
            return body_node

        # Dart: `function_signature` / `method_signature` has sibling `function_body`
        if self.language == "dart" and func_ts.type in ("function_signature", "method_signature"):
            sib = func_ts.next_named_sibling
            if sib is not None and sib.type == "function_body":
                return sib

        # Kotlin / Swift / Ruby fallback: look for direct child block/function_body
        for ch in func_ts.children:
            if ch.type in _BLOCK_CONTAINER_TYPES:
                return ch
        return None

    def _process_functions(self, root: tree_sitter.Node) -> None:
        """Finds all function definitions/declarations/expressions and builds statement CFG with Entry and Exit nodes."""
        entry_nodes = {n.scope_id: n for n in self.nodes if n.label == "Entry"}
        exit_nodes = {n.scope_id: n for n in self.nodes if n.label == "Exit"}

        for cpg in self.nodes:
            if cpg.label == "Function" and cpg.filepath == self.filepath:
                entry_cpg = entry_nodes.get(cpg.id)
                exit_cpg = exit_nodes.get(cpg.id)

                func_ts = self.ts_by_cpg_id.get(cpg.id)
                if not func_ts:
                    continue

                body_node = self._find_function_body(func_ts)
                if not body_node:
                    if entry_cpg and exit_cpg:
                        self.emit_cfg_edge(entry_cpg.id, exit_cpg.id, "CFG_NEXT")
                    continue

                stmts = self._extract_block_statements(body_node)
                hoisted_skip = {"function_declaration", "class_declaration", "function_signature", "function_body"}
                exec_stmts = [s for s in stmts if s.type not in hoisted_skip and s.type not in self.skip_types]

                if not exec_stmts:
                    if entry_cpg and exit_cpg:
                        self.emit_cfg_edge(entry_cpg.id, exit_cpg.id, "CFG_NEXT")
                    continue

                first_cpg = self.find_cpg_node(exec_stmts[0])
                if entry_cpg and first_cpg:
                    self.emit_cfg_edge(entry_cpg.id, first_cpg.id, "CFG_NEXT")

                self._link_statement_sequence(exec_stmts, post_node=exit_cpg, exit_node=exit_cpg)

    def _is_hard_terminator(self, stmt: tree_sitter.Node) -> bool:
        """Checks whether a statement unconditionally transfers control out of the current sequence."""
        if stmt.type in self.return_types:
            if stmt.type in ("jump_expression", "control_transfer_statement"):
                txt = stmt.text.decode("utf-8", errors="replace").strip()
                return txt.startswith(("return", "throw", "break"))
            return True
        return False

    def _link_statement_sequence(
        self,
        stmts: List[tree_sitter.Node],
        post_node: Optional[CPGNode],
        exit_node: Optional[CPGNode],
    ) -> None:
        """
        Sequentially links statements with CFG_NEXT, handling jumps, loops, and branches.
        Crucial: Return/Raise/Throw do NOT emit CFG_NEXT to subsequent siblings (enabling unreachable code detection).
        """
        skip_set = {"function_declaration", "class_declaration"} | self.skip_types

        for i, stmt in enumerate(stmts):
            if stmt.type in skip_set:
                continue

            current_cpg = self.find_cpg_node(stmt)
            if not current_cpg:
                continue

            next_stmt = None
            for cand in stmts[i + 1:]:
                if cand.type not in skip_set:
                    next_stmt = cand
                    break
            next_cpg = self.find_cpg_node(next_stmt) if next_stmt else post_node

            self._link_inner_expressions(stmt, current_cpg)

            # Unwrap expression_statement for control/loop/return expressions (e.g., Rust if_expression/while_expression)
            effective_stmt = stmt
            if stmt.type == "expression_statement" and len(stmt.named_children) == 1:
                inner = stmt.named_children[0]
                if inner.type in self.control_types or inner.type in self.loop_types or self._is_hard_terminator(inner):
                    effective_stmt = inner

            # Handle Return / Raise / Throw / Panic jumps
            if self._is_hard_terminator(effective_stmt):
                if exit_node:
                    self.emit_cfg_edge(current_cpg.id, exit_node.id, "CFG_NEXT")
                # CRITICAL: Do NOT emit CFG_NEXT to next_cpg!
                break

            # Handle If / Conditional Branching
            elif effective_stmt.type in _IF_CONTROL_TYPES or (
                effective_stmt.type in self.control_types and "if" in effective_stmt.type
            ):
                self._process_if_statement(effective_stmt, current_cpg, next_cpg, exit_node)

            # Handle While / For / Do / Loop Statements
            elif effective_stmt.type in self.loop_types:
                self._process_loop_statement(effective_stmt, current_cpg, next_cpg, exit_node)

            # Sequential Statement (Assignment, Call, Try, Switch, Match, etc.)
            else:
                if next_cpg:
                    self.emit_cfg_edge(current_cpg.id, next_cpg.id, "CFG_NEXT")

    def _link_inner_expressions(self, parent_stmt_ts: tree_sitter.Node, parent_cpg: CPGNode) -> None:
        """Connects inner executable expressions (sub-calls, nested assignments) into the statement's CFG path."""
        for child in parent_stmt_ts.children:
            if child.type in self.func_types or child.type in self.class_types:
                continue
            ch_cpg = self.find_cpg_node(child)
            if ch_cpg and ch_cpg.id != parent_cpg.id and ch_cpg.label in ("Call", "Assignment"):
                self.emit_cfg_edge(parent_cpg.id, ch_cpg.id, "CFG_NEXT")
            self._link_inner_expressions(child, parent_cpg)

    def _process_if_statement(
        self,
        if_ts: tree_sitter.Node,
        if_cpg: CPGNode,
        merge_cpg: Optional[CPGNode],
        exit_node: Optional[CPGNode],
    ) -> None:
        """Processes if-elif-else branching CFG edges across all 18 grammars."""
        consequence = if_ts.child_by_field_name("consequence") or if_ts.child_by_field_name("body")
        alternative = if_ts.child_by_field_name("alternative")

        # Fallback for grammars without `consequence`/`alternative` fields (e.g., Swift, Dart)
        if consequence is None:
            block_children = [ch for ch in if_ts.children if ch.type in _BLOCK_CONTAINER_TYPES]
            if block_children:
                consequence = block_children[0]
                if len(block_children) > 1 and alternative is None:
                    alternative = block_children[1]
            else:
                # Swift puts statements directly inside if_statement after condition
                cond = if_ts.child_by_field_name("condition")
                direct_stmts = [
                    ch for ch in if_ts.children
                    if ch.is_named and ch != cond and ch.type not in self.skip_types
                ]
                if direct_stmts:
                    first_true_cpg = self.find_cpg_node(direct_stmts[0])
                    if first_true_cpg:
                        self.emit_cfg_edge(if_cpg.id, first_true_cpg.id, "CFG_TRUE")
                    self._link_statement_sequence(direct_stmts, post_node=merge_cpg, exit_node=exit_node)
                    if merge_cpg:
                        self.emit_cfg_edge(if_cpg.id, merge_cpg.id, "CFG_FALSE")
                    return

        # True branch
        if consequence:
            conseq_stmts = self._extract_block_statements(consequence)
            if conseq_stmts:
                first_true_cpg = self.find_cpg_node(conseq_stmts[0])
                if first_true_cpg:
                    self.emit_cfg_edge(if_cpg.id, first_true_cpg.id, "CFG_TRUE")
                self._link_statement_sequence(conseq_stmts, post_node=merge_cpg, exit_node=exit_node)
            elif merge_cpg:
                self.emit_cfg_edge(if_cpg.id, merge_cpg.id, "CFG_TRUE")

        # False branch
        if alternative:
            alt_stmts = self._extract_block_statements(alternative)
            if alt_stmts:
                first_false_cpg = self.find_cpg_node(alt_stmts[0])
                if first_false_cpg:
                    self.emit_cfg_edge(if_cpg.id, first_false_cpg.id, "CFG_FALSE")
                self._link_statement_sequence(alt_stmts, post_node=merge_cpg, exit_node=exit_node)
            elif merge_cpg:
                self.emit_cfg_edge(if_cpg.id, merge_cpg.id, "CFG_FALSE")
        else:
            if merge_cpg:
                self.emit_cfg_edge(if_cpg.id, merge_cpg.id, "CFG_FALSE")

    def _process_loop_statement(
        self,
        loop_ts: tree_sitter.Node,
        loop_cpg: CPGNode,
        post_cpg: Optional[CPGNode],
        exit_node: Optional[CPGNode],
    ) -> None:
        """
        Processes loop CFG edges (`CFG_TRUE`, `CFG_LOOP_BACK`, `CFG_FALSE`, `CFG_BREAK`).
        Crucial for Rule 4: If constant truthy condition and no break/return/raise,
        omit `CFG_FALSE` and omit `CFG_BREAK`.
        """
        body = loop_ts.child_by_field_name("body")
        condition = loop_ts.child_by_field_name("condition")

        if body is None:
            for ch in reversed(loop_ts.children):
                if ch.type in _BLOCK_CONTAINER_TYPES:
                    body = ch
                    break

        is_infinite = False
        if ("while" in loop_ts.type or loop_ts.type == "loop_expression") and (
            loop_ts.type == "loop_expression" or (condition is not None and is_truthy_literal(condition))
        ):
            if not body or not body_has_terminator(body, loop_types=self.loop_types, func_types=self.func_types):
                is_infinite = True

        body_stmts: List[tree_sitter.Node] = []
        if body is not None:
            body_stmts = self._extract_block_statements(body)
        else:
            # Swift while_statement / for_statement without explicit block child
            body_stmts = [
                ch for ch in loop_ts.children
                if ch.is_named and ch != condition and ch.type not in self.skip_types
            ]

        if body_stmts:
            first_body_cpg = self.find_cpg_node(body_stmts[0])
            if first_body_cpg:
                self.emit_cfg_edge(loop_cpg.id, first_body_cpg.id, "CFG_TRUE")

            target_exit = post_cpg or exit_node
            for b_stmt in body_stmts:
                if b_stmt.type in _BREAK_TYPES and target_exit:
                    b_cpg = self.find_cpg_node(b_stmt)
                    if b_cpg:
                        self.emit_cfg_edge(b_cpg.id, target_exit.id, "CFG_BREAK")

            last_stmt = body_stmts[-1]
            last_cpg = self.find_cpg_node(last_stmt)
            if last_cpg and not self._is_hard_terminator(last_stmt) and last_stmt.type not in _BREAK_TYPES:
                self.emit_cfg_edge(last_cpg.id, loop_cpg.id, "CFG_LOOP_BACK")

            self._link_statement_sequence(body_stmts[:-1], post_node=last_cpg, exit_node=exit_node)

        target_exit = post_cpg or exit_node
        if not is_infinite and target_exit:
            self.emit_cfg_edge(loop_cpg.id, target_exit.id, "CFG_FALSE")
