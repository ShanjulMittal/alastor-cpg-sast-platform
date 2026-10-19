"""
Pass 2: Deterministic Control Flow Graph (CFG) State Machine.
Builds basic-block/statement-level CFG with explicit branching, cycles, and jump semantics.
"""
from typing import List, Dict, Optional, Tuple
import tree_sitter
from models import CPGNode, CPGEdge
from compiler.ast_parser import compute_edge_id, compute_node_id, py_parser, js_parser, ts_parser, tsx_parser


def is_truthy_literal(condition_node: tree_sitter.Node) -> bool:
    """Checks if the loop condition is a constant truthy literal (True, 1, non-empty string)."""
    text = condition_node.text.decode("utf-8", errors="replace").strip()
    if text in ("True", "1", "true"):
        return True
    if text.startswith(('"', "'")) and len(text) > 2:
        return True
    return False


def body_has_terminator(node: tree_sitter.Node) -> bool:
    """Recursively checks whether a loop body contains any break, return, raise, or throw statements."""
    if node.type in ("break_statement", "return_statement", "raise_statement", "throw_statement"):
        return True
    for child in node.children:
        # Don't recurse into nested loops or functions when checking this loop's direct terminators
        if child.type in (
            "while_statement", "for_statement", "for_in_statement", "do_statement",
            "function_definition", "function_declaration", "function_expression", "arrow_function", "method_definition"
        ):
            continue
        if body_has_terminator(child):
            return True
    return False


class CFGBuilder:
    def __init__(self, filepath: str, content_bytes: bytes, language: str, 
                 nodes: List[CPGNode], node_map: Dict[str, CPGNode]):
        self.filepath = filepath
        self.content_bytes = content_bytes
        self.language = language
        self.nodes = nodes
        self.node_map = node_map
        self.cfg_edges: List[CPGEdge] = []
        self.ts_by_cpg_id: Dict[str, tree_sitter.Node] = {}
        
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

    def find_cpg_node(self, ts_node: Optional[tree_sitter.Node]) -> Optional[CPGNode]:
        """Finds the corresponding CPGNode for a tree-sitter node."""
        if ts_node is None:
            return None
        # Check direct children if this is a statement wrapper (expression_statement, lexical_declaration, variable_declaration)
        if ts_node.type in ("expression_statement", "lexical_declaration", "variable_declaration", "export_statement") and ts_node.children:
            for ch in ts_node.children:
                if ch.is_named:
                    found = self.find_cpg_node(ch)
                    if found:
                        return found

        node_id = compute_node_id(self.filepath, ts_node.type, ts_node.start_byte, ts_node.end_byte)
        return self.node_map.get(node_id)

    def emit_cfg_edge(self, source_id: str, target_id: str, edge_type: str) -> None:
        """Emits a deterministic CFG edge."""
        edge_id = compute_edge_id(source_id, target_id, edge_type)
        self.cfg_edges.append(
            CPGEdge(
                id=edge_id,
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type
            )
        )

    def build(self) -> List[CPGEdge]:
        if self.language == "python":
            parser = py_parser
        elif self.language == "typescript":
            parser = ts_parser
        elif self.language == "tsx":
            parser = tsx_parser
        else:
            parser = js_parser
        tree = parser.parse(self.content_bytes)
        root = tree.root_node

        # Build O(1) lookup index from CPG ID -> Tree-Sitter node
        self._index_ts_nodes(root)

        # Build CFG for each function (Python, JS, TS)
        self._process_functions(root)

        # Build CFG for top-level module statements
        top_stmts = [
            c for c in root.children
            if c.is_named and c.type not in ("function_definition", "function_declaration", "class_definition", "class_declaration")
        ]
        self._link_statement_sequence(top_stmts, post_node=None, exit_node=None)

        return self.cfg_edges

    def _process_functions(self, root: tree_sitter.Node) -> None:
        """Finds all function definitions/declarations/expressions and builds statement CFG with Entry and Exit nodes."""
        entry_nodes = {n.scope_id: n for n in self.nodes if n.label == "Entry"}
        exit_nodes = {n.scope_id: n for n in self.nodes if n.label == "Exit"}

        for cpg in self.nodes:
            if cpg.label == "Function" and cpg.filepath == self.filepath:
                entry_cpg = entry_nodes.get(cpg.id)
                exit_cpg = exit_nodes.get(cpg.id)
                
                # O(1) lookup of exact tree-sitter node by CPG ID
                func_ts = self.ts_by_cpg_id.get(cpg.id)
                if not func_ts:
                    continue

                body_node = func_ts.child_by_field_name("body")
                if not body_node:
                    continue

                if body_node.type in ("block", "statement_block"):
                    stmts = [c for c in body_node.children if c.is_named and c.type != "comment"]
                else:
                    # Concise arrow function body: (x) => x + 1
                    stmts = [body_node]

                # Separate hoisted JS function declarations so they don't block sequential flow
                exec_stmts = [s for s in stmts if s.type not in ("function_declaration", "class_declaration")]
                if not exec_stmts:
                    if entry_cpg and exit_cpg:
                        self.emit_cfg_edge(entry_cpg.id, exit_cpg.id, "CFG_NEXT")
                    continue

                # Connect Entry to the first executable statement
                first_cpg = self.find_cpg_node(exec_stmts[0])
                if entry_cpg and first_cpg:
                    self.emit_cfg_edge(entry_cpg.id, first_cpg.id, "CFG_NEXT")

                # Link statement sequence
                self._link_statement_sequence(exec_stmts, post_node=exit_cpg, exit_node=exit_cpg)

    def _link_statement_sequence(self, stmts: List[tree_sitter.Node], 
                                  post_node: Optional[CPGNode], 
                                  exit_node: Optional[CPGNode]) -> None:
        """
        Sequentially links statements with CFG_NEXT, handling jumps, loops, and branches.
        Crucial: Return/Raise/Throw do NOT emit CFG_NEXT to subsequent siblings.
        """
        for i, stmt in enumerate(stmts):
            if stmt.type in ("function_declaration", "class_declaration", "comment"):
                continue

            current_cpg = self.find_cpg_node(stmt)
            if not current_cpg:
                continue

            next_stmt = None
            for cand in stmts[i + 1:]:
                if cand.type not in ("function_declaration", "class_declaration", "comment"):
                    next_stmt = cand
                    break
            next_cpg = self.find_cpg_node(next_stmt) if next_stmt else post_node

            # Link inner expressions evaluated within this statement (e.g. sub-calls in assignments/returns)
            self._link_inner_expressions(stmt, current_cpg)

            # Handle Return / Raise / Throw jumps
            if stmt.type in ("return_statement", "raise_statement", "throw_statement"):
                if exit_node:
                    self.emit_cfg_edge(current_cpg.id, exit_node.id, "CFG_NEXT")
                # CRITICAL: Do NOT emit CFG_NEXT to next_cpg!
                # Subsequent executable statements in this block will have no incoming CFG edges (Unreachable Code)
                break

            # Handle If Statement
            elif stmt.type == "if_statement":
                self._process_if_statement(stmt, current_cpg, next_cpg, exit_node)

            # Handle While / For / Do Loops
            elif stmt.type in ("while_statement", "for_statement", "for_in_statement", "do_statement"):
                self._process_loop_statement(stmt, current_cpg, next_cpg, exit_node)

            # Sequential Statement (Assignment, Call, Try, Switch, Labeled, etc.)
            else:
                if next_cpg:
                    self.emit_cfg_edge(current_cpg.id, next_cpg.id, "CFG_NEXT")

    def _link_inner_expressions(self, parent_stmt_ts: tree_sitter.Node, parent_cpg: CPGNode) -> None:
        """Connects inner executable expressions (sub-calls, nested assignments) into the statement's CFG path."""
        for child in parent_stmt_ts.children:
            if child.type in ("function_definition", "function_declaration", "function_expression", "arrow_function", "method_definition"):
                continue
            ch_cpg = self.find_cpg_node(child)
            if ch_cpg and ch_cpg.id != parent_cpg.id and ch_cpg.label in ("Call", "Assignment"):
                self.emit_cfg_edge(parent_cpg.id, ch_cpg.id, "CFG_NEXT")
            self._link_inner_expressions(child, parent_cpg)

    def _process_if_statement(self, if_ts: tree_sitter.Node, if_cpg: CPGNode, 
                              merge_cpg: Optional[CPGNode], exit_node: Optional[CPGNode]) -> None:
        """Processes if-elif-else branching CFG edges."""
        consequence = if_ts.child_by_field_name("consequence")
        alternative = if_ts.child_by_field_name("alternative")

        # True branch
        if consequence:
            if consequence.type in ("block", "statement_block"):
                conseq_stmts = [c for c in consequence.children if c.is_named and c.type != "comment"]
            else:
                conseq_stmts = [consequence]
            if conseq_stmts:
                first_true_cpg = self.find_cpg_node(conseq_stmts[0])
                if first_true_cpg:
                    self.emit_cfg_edge(if_cpg.id, first_true_cpg.id, "CFG_TRUE")
                self._link_statement_sequence(conseq_stmts, post_node=merge_cpg, exit_node=exit_node)
            elif merge_cpg:
                self.emit_cfg_edge(if_cpg.id, merge_cpg.id, "CFG_TRUE")

        # False branch
        if alternative:
            if alternative.type in ("block", "statement_block", "else_clause"):
                alt_stmts = [c for c in alternative.children if c.is_named and c.type != "comment"]
            else:
                alt_stmts = [alternative]
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

    def _process_loop_statement(self, loop_ts: tree_sitter.Node, loop_cpg: CPGNode, 
                                post_cpg: Optional[CPGNode], exit_node: Optional[CPGNode]) -> None:
        """
        Processes loop CFG edges (CFG_TRUE, CFG_LOOP_BACK, CFG_FALSE, CFG_BREAK).
        Crucial for Rule 4: If constant truthy condition and no break/return/raise,
        omit CFG_FALSE and omit CFG_BREAK.
        """
        body = loop_ts.child_by_field_name("body")
        condition = loop_ts.child_by_field_name("condition")

        is_infinite = False
        if loop_ts.type == "while_statement" and condition:
            if is_truthy_literal(condition) and (not body or not body_has_terminator(body)):
                is_infinite = True

        if body:
            if body.type in ("block", "statement_block"):
                body_stmts = [c for c in body.children if c.is_named and c.type != "comment"]
            else:
                body_stmts = [body]
            if body_stmts:
                first_body_cpg = self.find_cpg_node(body_stmts[0])
                if first_body_cpg:
                    self.emit_cfg_edge(loop_cpg.id, first_body_cpg.id, "CFG_TRUE")

                # Handle breaks
                target_exit = post_cpg or exit_node
                for b_stmt in body_stmts:
                    if b_stmt.type == "break_statement" and target_exit:
                        b_cpg = self.find_cpg_node(b_stmt)
                        if b_cpg:
                            self.emit_cfg_edge(b_cpg.id, target_exit.id, "CFG_BREAK")

                # Link body statements; the tail connects back to loop header via CFG_LOOP_BACK
                last_stmt = body_stmts[-1]
                last_cpg = self.find_cpg_node(last_stmt)
                if last_cpg and last_stmt.type not in ("return_statement", "raise_statement", "throw_statement", "break_statement"):
                    self.emit_cfg_edge(last_cpg.id, loop_cpg.id, "CFG_LOOP_BACK")

                # Internal sequence
                self._link_statement_sequence(body_stmts[:-1], post_node=last_cpg, exit_node=exit_node)

        # Connect loop exit via CFG_FALSE unless it is an infinite loop
        target_exit = post_cpg or exit_node
        if not is_infinite and target_exit:
            self.emit_cfg_edge(loop_cpg.id, target_exit.id, "CFG_FALSE")
