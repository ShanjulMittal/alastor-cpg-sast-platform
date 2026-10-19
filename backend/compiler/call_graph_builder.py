"""
Pass 4: Cross-File Call Graph Resolution.
Builds project-wide export tables, resolves imports, and emits CALLS edges.
"""
from typing import List, Dict, Optional, Tuple
from models import CPGNode, CPGEdge
from compiler.ast_parser import compute_edge_id


class CallGraphBuilder:
    def __init__(self, all_nodes: List[CPGNode]):
        self.all_nodes = all_nodes
        self.call_edges: List[CPGEdge] = []
        
        # Export table: (filepath, function_name) -> List[Function CPGNode]
        self.export_table: Dict[Tuple[str, str], List[CPGNode]] = {}
        # By function name: name -> List[Function CPGNode]
        self.func_by_name: Dict[str, List[CPGNode]] = {}

        self._build_symbol_tables()

    def _build_symbol_tables(self) -> None:
        """Indexes all functions defined across the repository."""
        for node in self.all_nodes:
            if node.label == "Function" and node.name and node.name != "anonymous_func":
                self.export_table.setdefault((node.filepath, node.name), []).append(node)
                self.func_by_name.setdefault(node.name, []).append(node)

    def resolve_calls(self) -> List[CPGEdge]:
        """Resolves all Call CPGNodes to their target Function CPGNodes."""
        for node in self.all_nodes:
            if node.label == "Call":
                target_funcs = self._resolve_call_targets(node)
                for target_func in target_funcs:
                    edge_id = compute_edge_id(node.id, target_func.id, "CALLS")
                    self.call_edges.append(
                        CPGEdge(
                            id=edge_id,
                            source_id=node.id,
                            target_id=target_func.id,
                            edge_type="CALLS"
                        )
                    )
        return self.call_edges

    def _resolve_call_targets(self, call_node: CPGNode) -> List[CPGNode]:
        """Resolves a call's target functions across local and global scopes."""
        call_name = call_node.name.strip()
        if "." in call_name:
            simple_name = call_name.split(".")[-1]
        else:
            simple_name = call_name

        # 1. Local scope check (same file)
        local_targets = self.export_table.get((call_node.filepath, simple_name))
        if local_targets:
            return local_targets

        # 2. Repository-wide check by function name
        global_candidates = self.func_by_name.get(simple_name, [])
        if global_candidates:
            return [global_candidates[0]]

        return []
