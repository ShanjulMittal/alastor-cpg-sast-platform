"""
Pass 4: Polyglot Cross-File Call Graph Resolution.
Normalizes polyglot call targets (`.`, `->`, `::`) and resolves `CALLS` edges in strict priority:
  1. Same file
  2. Same language in same directory/package
  3. Same language anywhere in repository
  4. Repo-wide fallback
"""
from __future__ import annotations

import os
import re
from typing import Dict, List, Set, Tuple

from compiler.ast_parser import compute_edge_id
from models import CPGEdge, CPGNode

_GENERIC_ARGS_RE = re.compile(r"(?:::)?<[^<>]*>$")
_POLYGLOT_SEP_RE = re.compile(r"(?:\.|->|::)")


def _normalize_call_target(raw_name: str) -> str:
    """Extracts the normalized terminal callee identifier from polyglot call expressions."""
    cleaned = (raw_name or "").strip()
    if not cleaned:
        return ""
    # Strip trailing call parentheses or generic type args (e.g. `Utils::clean<String>`)
    if "(" in cleaned:
        cleaned = cleaned.split("(", 1)[0].strip()
    cleaned = _GENERIC_ARGS_RE.sub("", cleaned).strip()
    cleaned = cleaned.lstrip("*&!")
    if not cleaned:
        return ""
    parts = [p.strip() for p in _POLYGLOT_SEP_RE.split(cleaned) if p.strip()]
    if not parts:
        return ""
    terminal = _GENERIC_ARGS_RE.sub("", parts[-1]).strip()
    return terminal


def _normalized_dir(filepath: str) -> str:
    return os.path.dirname((filepath or "").replace("\\", "/")).strip("/")


class CallGraphBuilder:
    def __init__(self, all_nodes: List[CPGNode]):
        self.all_nodes = all_nodes
        self.call_edges: List[CPGEdge] = []
        self._seen_edge_ids: Set[str] = set()

        # Priority lookup tables:
        # 1. (filepath, function_name) -> List[Function CPGNode]
        self.export_table: Dict[Tuple[str, str], List[CPGNode]] = {}
        # 2. (language, dir_path, function_name) -> List[Function CPGNode]
        self.same_lang_dir_table: Dict[Tuple[str, str, str], List[CPGNode]] = {}
        # 3. (language, function_name) -> List[Function CPGNode]
        self.same_lang_table: Dict[Tuple[str, str], List[CPGNode]] = {}
        # 4. function_name -> List[Function CPGNode]
        self.func_by_name: Dict[str, List[CPGNode]] = {}

        self._build_symbol_tables()

    def _build_symbol_tables(self) -> None:
        """Indexes all functions defined across the repository."""
        for node in self.all_nodes:
            if node.label == "Function" and node.name and node.name != "anonymous_func":
                simple = _normalize_call_target(node.name) or node.name
                lang = (node.language or "python").strip().lower()
                dir_path = _normalized_dir(node.filepath)

                self.export_table.setdefault((node.filepath, simple), []).append(node)
                self.same_lang_dir_table.setdefault((lang, dir_path, simple), []).append(node)
                self.same_lang_table.setdefault((lang, simple), []).append(node)
                self.func_by_name.setdefault(simple, []).append(node)

    def resolve_calls(self) -> List[CPGEdge]:
        """Resolves all Call CPGNodes to their target Function CPGNodes."""
        for node in self.all_nodes:
            if node.label == "Call":
                target_funcs = self._resolve_call_targets(node)
                for target_func in target_funcs:
                    if target_func.id == node.id:
                        continue
                    edge_id = compute_edge_id(node.id, target_func.id, "CALLS")
                    if edge_id in self._seen_edge_ids:
                        continue
                    self._seen_edge_ids.add(edge_id)
                    self.call_edges.append(
                        CPGEdge(
                            id=edge_id,
                            source_id=node.id,
                            target_id=target_func.id,
                            edge_type="CALLS",
                        )
                    )
        return self.call_edges

    def _resolve_call_targets(self, call_node: CPGNode) -> List[CPGNode]:
        """Resolves a call's target functions in priority order."""
        simple_name = _normalize_call_target(call_node.name)
        if not simple_name:
            return []

        lang = (call_node.language or "python").strip().lower()
        dir_path = _normalized_dir(call_node.filepath)

        # 1. Same file
        local_targets = self.export_table.get((call_node.filepath, simple_name))
        if local_targets:
            return local_targets

        # 2. Same language in same directory/package
        same_dir_targets = self.same_lang_dir_table.get((lang, dir_path, simple_name))
        if same_dir_targets:
            return [same_dir_targets[0]]

        # 3. Same language anywhere in repository
        same_lang_targets = self.same_lang_table.get((lang, simple_name))
        if same_lang_targets:
            return [same_lang_targets[0]]

        # 4. Repo-wide fallback
        global_candidates = self.func_by_name.get(simple_name, [])
        if global_candidates:
            return [global_candidates[0]]

        return []
