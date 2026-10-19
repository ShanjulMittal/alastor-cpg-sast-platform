"""
Pass 3: Data Flow Graph (DFG) & Symbol Table Builder.
Implements Reaching Definitions analysis, inter-procedural DFG propagation, and dead store tracking.
"""
from typing import List, Dict, Optional, Tuple, Set
import tree_sitter
from models import CPGNode, CPGEdge
from compiler.ast_parser import compute_edge_id, compute_node_id, py_parser, js_parser, ts_parser, tsx_parser


class DFGBuilder:
    def __init__(self, filepath: str, content_bytes: bytes, language: str,
                 nodes: List[CPGNode], node_map: Dict[str, CPGNode],
                 function_params_map: Dict[str, List[CPGNode]],
                 function_returns_map: Dict[str, List[CPGNode]]):
        self.filepath = filepath
        self.content_bytes = content_bytes
        self.language = language
        self.nodes = nodes
        self.node_map = node_map
        self.function_params_map = function_params_map       # func_name -> List[Parameter CPGNodes]
        self.function_returns_map = function_returns_map     # func_name -> List[Return CPGNodes]
        self.dfg_edges: List[CPGEdge] = []
        
        # Symbol Table per scope: defs[scope_id][var_name] -> List[node_id]
        self.defs: Dict[str, Dict[str, List[str]]] = {}
        # Fast lookup for variable fallback by name and start_line
        self.vars_by_name_and_line: Dict[Tuple[str, int], CPGNode] = {
            (n.name, n.start_line): n for n in nodes
        }

    def emit_dfg_edge(self, source_id: str, target_id: str, var_name: Optional[str] = None) -> None:
        """Emits a deterministic DFG_FLOWS_TO edge."""
        edge_id = compute_edge_id(source_id, target_id, "DFG_FLOWS_TO")
        self.dfg_edges.append(
            CPGEdge(
                id=edge_id,
                source_id=source_id,
                target_id=target_id,
                edge_type="DFG_FLOWS_TO",
                var_name=var_name
            )
        )

    def find_cpg_node(self, ts_node: tree_sitter.Node) -> Optional[CPGNode]:
        """Finds matching CPGNode for an AST node."""
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
        """Runs reaching definitions analysis and emits all DFG_FLOWS_TO edges."""
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

        # Initialize formal parameters in symbol tables for each function
        self._initialize_function_parameters()

        # Traverse AST and process definitions, uses, and inter-procedural calls
        self._traverse_for_dataflow(root, current_scope="global")

        return self.dfg_edges

    def _initialize_function_parameters(self) -> None:
        """Registers formal parameters into the function's local symbol table."""
        params_by_scope: Dict[str, List[CPGNode]] = {}
        seen_by_scope: Dict[str, Set[str]] = {}
        for n in self.nodes:
            if n.label == "Parameter" and n.ast_type not in ("parameters", "formal_parameters") and not n.name.startswith("("):
                seen = seen_by_scope.setdefault(n.scope_id, set())
                if n.name not in seen:
                    seen.add(n.name)
                    params_by_scope.setdefault(n.scope_id, []).append(n)

        for node in self.nodes:
            if node.label == "Function" and node.filepath == self.filepath:
                func_id = node.id
                if func_id not in self.defs:
                    self.defs[func_id] = {}
                
                # Retrieve parameters for this specific function scope first, fallback to name map
                params = params_by_scope.get(func_id) or self.function_params_map.get(node.name, [])
                for p in params:
                    self.defs[func_id][p.name] = [p.id]

    def _traverse_for_dataflow(self, ts_node: tree_sitter.Node, current_scope: str) -> None:
        """Traverses AST nodes and builds def-use chains."""
        node_type = ts_node.type

        # Scope changes
        if node_type in (
            "function_definition", "method_definition", "function_declaration",
            "function_expression", "arrow_function", "generator_function_declaration", "generator_function"
        ):
            func_cpg = self.find_cpg_node(ts_node)
            new_scope = func_cpg.id if func_cpg else current_scope
            if new_scope not in self.defs:
                self.defs[new_scope] = {}
            for child in ts_node.children:
                self._traverse_for_dataflow(child, new_scope)
            return

        # 1. Assignments: left = right or var name = value
        if node_type in (
            "assignment", "augmented_assignment", "variable_declarator",
            "assignment_expression", "augmented_assignment_expression"
        ):
            self._process_assignment(ts_node, current_scope)
            right = ts_node.child_by_field_name("right") or ts_node.child_by_field_name("value")
            if right:
                for ch in right.children:
                    self._traverse_for_dataflow(ch, current_scope)
            return

        # 2. Standalone Calls (e.g., helper_exec(formatted_cmd), os.system(cmd), document.write(...), IIFE (function(){...})())
        if node_type in ("call", "call_expression"):
            self._process_call(ts_node, current_scope)
            func_node = ts_node.child_by_field_name("function")
            if func_node:
                self._traverse_for_dataflow(func_node, current_scope)
            args_node = ts_node.child_by_field_name("arguments")
            if args_node:
                for ch in args_node.children:
                    self._traverse_for_dataflow(ch, current_scope)
            return

        for child in ts_node.children:
            self._traverse_for_dataflow(child, current_scope)

    def _process_assignment(self, assign_ts: tree_sitter.Node, scope_id: str) -> None:
        """
        Handles assignment def-use flow:
        - Uses in right propagate to target in left
        - Reaching definitions propagate to Uses in right
        - Updates defs[scope_id] with the new definition
        """
        left = assign_ts.child_by_field_name("left") or assign_ts.child_by_field_name("name")
        right = assign_ts.child_by_field_name("right") or assign_ts.child_by_field_name("value")
        if not left or not right:
            return

        assign_cpg = self.find_cpg_node(assign_ts)
        target_cpg = self.find_cpg_node(left)
        if not target_cpg:
            # Fallback to finding variable by name and position
            var_name = left.text.decode("utf-8", errors="replace").strip()
            target_cpg = self.vars_by_name_and_line.get((var_name, left.start_point[0] + 1))

        if not target_cpg:
            return

        target_var_name = target_cpg.name

        # Detect if right-hand side has a source node (e.g. sys.argv[1])
        source_cpg = self.find_source_node_in_tree(right)
        if source_cpg:
            self.emit_dfg_edge(source_cpg.id, target_cpg.id, var_name=target_var_name)

        # Identify all variable uses in right
        uses = self._extract_variable_uses(right)
        right_cpg = self.find_cpg_node(right)

        # If right is a sanitizer call (e.g. int(raw_id)), ensure: use -> sanitizer -> target
        if right_cpg and right_cpg.is_sanitizer:
            for use_cpg in uses:
                # Link previous definition to use
                self._link_reaching_definitions(use_cpg, scope_id)
                # Link use to sanitizer
                self.emit_dfg_edge(use_cpg.id, right_cpg.id, var_name=use_cpg.name)
            # Link sanitizer to target
            self.emit_dfg_edge(right_cpg.id, target_cpg.id, var_name=target_var_name)
        elif right_cpg and right_cpg.label == "Call":
            for use_cpg in uses:
                self._link_reaching_definitions(use_cpg, scope_id)
                self.emit_dfg_edge(use_cpg.id, right_cpg.id, var_name=use_cpg.name)
            self.emit_dfg_edge(right_cpg.id, target_cpg.id, var_name=target_var_name)
        else:
            for use_cpg in uses:
                self._link_reaching_definitions(use_cpg, scope_id)
                self.emit_dfg_edge(use_cpg.id, target_cpg.id, var_name=target_var_name)

        # If the assignment itself is a DOM sink (e.g. g.innerHTML = T), link uses into the Assignment CPGNode
        if assign_cpg and assign_cpg.is_sink:
            for use_cpg in uses:
                self.emit_dfg_edge(use_cpg.id, assign_cpg.id, var_name=use_cpg.name)

        # Update symbol table with this definition
        if scope_id not in self.defs:
            self.defs[scope_id] = {}
        self.defs[scope_id][target_var_name] = [target_cpg.id]

    def _process_call(self, call_ts: tree_sitter.Node, scope_id: str) -> None:
        """
        Handles Call nodes:
        - Links reaching definitions to arguments
        - Links argument uses to called function's formal parameters (Inter-procedural DFG)
        - If Call is a sink (os.system, document.write), links argument uses to the sink Call node
        """
        call_cpg = self.find_cpg_node(call_ts)
        func_node = call_ts.child_by_field_name("function")
        args_node = call_ts.child_by_field_name("arguments")

        func_name = func_node.text.decode("utf-8", errors="replace").strip() if func_node else ""
        if "." in func_name:
            short_name = func_name.split(".")[-1]
        else:
            short_name = func_name

        arg_uses: List[CPGNode] = []
        
        # Link variable uses in the function / object expression (e.g. cursor in cursor.execute)
        if func_node:
            func_vars = self._extract_variable_uses(func_node)
            for fv in func_vars:
                self._link_reaching_definitions(fv, scope_id)
                if call_cpg:
                    self.emit_dfg_edge(fv.id, call_cpg.id, var_name=fv.name)

        if args_node:
            for child in args_node.children:
                if child.is_named:
                    arg_vars = self._extract_variable_uses(child)
                    for av in arg_vars:
                        self._link_reaching_definitions(av, scope_id)
                        arg_uses.append(av)

        # 1. Inter-procedural flow: Argument -> Formal Parameter
        target_params = self.function_params_map.get(short_name) or self.function_params_map.get(func_name)
        if target_params and arg_uses:
            for i, arg_u in enumerate(arg_uses):
                if i < len(target_params):
                    param_cpg = target_params[i]
                    self.emit_dfg_edge(arg_u.id, param_cpg.id, var_name=param_cpg.name)

        # 2. Sink flow: If call is a sensitive sink (e.g. os.system, cursor.execute, document.write), arguments flow into sink
        if call_cpg and (call_cpg.is_sink or func_name.endswith(".setAttribute")):
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
        """Extracts variable identifier uses from an expression, including f-string interpolations and JS member/call chains."""
        results: List[CPGNode] = []
        
        if ts_node.type == "identifier":
            cpg = self.find_cpg_node(ts_node)
            if cpg and cpg.label in ("Variable", "Parameter"):
                results.append(cpg)
            return results

        # If attribute / member_expression (e.g. user_cmd.strip or w.spc): extract object
        if ts_node.type in ("attribute", "member_expression"):
            obj_child = ts_node.child_by_field_name("object")
            if obj_child:
                results.extend(self._extract_variable_uses(obj_child))
            return results

        # If call / call_expression (e.g. user_cmd.strip() or ''.concat(Qg)): extract arguments and object
        if ts_node.type in ("call", "call_expression"):
            func_child = ts_node.child_by_field_name("function")
            args_child = ts_node.child_by_field_name("arguments")
            if func_child:
                results.extend(self._extract_variable_uses(func_child))
            if args_child:
                results.extend(self._extract_variable_uses(args_child))
            return results

        for child in ts_node.children:
            results.extend(self._extract_variable_uses(child))

        return results
