"""
Deterministic Pure-Python Leiden/Modularity Community Detector for ALASTOR v5.0 Pillar 1.

Clusters repository files into logical architectural security communities using weighted
CALLS, DFG_FLOWS_TO, IMPORTS, and directory-locality signals with connected-component
refinement and cross-language polyglot trust-crossing bridge detection.
Zero C/JVM dependencies; 100% deterministic across runs regardless of input order.
"""
from __future__ import annotations

import hashlib
import os
import re
from collections import Counter, defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

from compiler.language_registry import LANGUAGE_SPECS, resolve_language_for_filename
from models import (
    AppTreeSummary,
    CPGEdge,
    CPGNode,
    CommunityBridgeEdge,
    CommunityMapResponse,
    Finding,
    GraphCommunityItem,
    GraphEngineMode,
)

_EDGE_WEIGHTS: Dict[str, float] = {
    "CALLS": 3.0,
    "DFG_FLOWS_TO": 2.5,
    "IMPORTS": 1.5,
}
_SAME_DIR_WEIGHT: float = 0.5
_MAX_MODULARITY_PASSES: int = 12
_GENERIC_SEGMENTS: Set[str] = {
    "",
    ".",
    "src",
    "lib",
    "app",
    "pkg",
    "internal",
    "cmd",
    "backend",
    "frontend",
    "packages",
    "modules",
    "code",
}
_ROUTE_HINTS: Tuple[str, ...] = (
    "@app.",
    "@router.",
    "@GetMapping",
    "@PostMapping",
    "@PutMapping",
    "@DeleteMapping",
    "@RequestMapping",
    "app.get(",
    "app.post(",
    "router.get(",
    "router.post(",
    "http.HandleFunc",
    "export async function GET",
    "export async function POST",
)


def _norm_path(filepath: str) -> str:
    return (filepath or "").replace("\\", "/").lstrip("/").strip()


def _canonical_language(raw_lang: Optional[str], filepath: str) -> str:
    if raw_lang:
        low = raw_lang.strip().lower()
        if low in LANGUAGE_SPECS:
            return low
        for key, spec in LANGUAGE_SPECS.items():
            if spec.display_name.lower() == low:
                return key
    resolved = resolve_language_for_filename(filepath)
    if resolved:
        return resolved
    return (raw_lang or "unknown").strip().lower() or "unknown"


def _display_language(lang_key: str) -> str:
    spec = LANGUAGE_SPECS.get(lang_key)
    if spec:
        return spec.display_name
    return lang_key.replace("_", " ").title() if lang_key else "Unknown"


def _is_entrypoint_node(node: CPGNode) -> bool:
    if node.is_source:
        return True
    if node.label == "Function":
        code = node.code or ""
        return any(hint in code for hint in _ROUTE_HINTS)
    return False


def _humanize_segment(segment: str) -> str:
    tokens = [tok for tok in re.split(r"[^A-Za-z0-9]+", segment) if tok]
    if not tokens:
        return "Core Module"
    return " ".join(tok.capitalize() for tok in tokens[:3])


def _derive_community_label(filepaths: List[str], primary_language: str) -> str:
    segment_counts: Counter[str] = Counter()
    fallback_counts: Counter[str] = Counter()

    for fp in filepaths:
        parts = [p for p in fp.split("/") if p]
        dirs = parts[:-1]
        meaningful = [d for d in dirs if d.lower() not in _GENERIC_SEGMENTS]
        if meaningful:
            # Prefer the most specific meaningful directory segment
            segment_counts[meaningful[-1]] += 1
        elif dirs:
            fallback_counts[dirs[-1]] += 1
        elif parts:
            stem = os.path.splitext(parts[-1])[0]
            fallback_counts[stem] += 1

    if segment_counts:
        top_seg = sorted(segment_counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    elif fallback_counts:
        top_seg = sorted(fallback_counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    else:
        top_seg = "core"

    return f"{_humanize_segment(top_seg)} ({_display_language(primary_language)})"


def _compute_risk_tier(
    crit_count: int,
    high_count: int,
    med_count: int,
    sink_count: int,
    entrypoint_count: int,
) -> str:
    if crit_count >= 1 or high_count >= 3:
        return "CRITICAL"
    if high_count >= 1 or (sink_count + entrypoint_count) >= 2:
        return "HIGH"
    if med_count >= 1 or sink_count >= 1:
        return "MEDIUM"
    return "LOW"


def _run_deterministic_leiden(
    sorted_files: List[str],
    adj: Dict[str, Dict[str, float]],
) -> List[List[str]]:
    """
    Runs deterministic modularity optimization (local-move phase up to 12 iterations)
    followed by connected-component refinement so disconnected subgraphs are never merged.
    """
    if not sorted_files:
        return []

    # Precompute weighted degrees and total edge weight (2m)
    degree: Dict[str, float] = {}
    two_m = 0.0
    for u in sorted_files:
        d = sum(adj.get(u, {}).values())
        degree[u] = d
        two_m += d

    # Initial singleton communities keyed by canonical sorted index
    comm_of: Dict[str, str] = {u: u for u in sorted_files}
    comm_tot: Dict[str, float] = {u: degree[u] for u in sorted_files}

    if two_m > 0.0:
        for _ in range(_MAX_MODULARITY_PASSES):
            moved_any = False
            for u in sorted_files:
                u_neighbors = adj.get(u)
                if not u_neighbors:
                    continue
                k_u = degree[u]
                cur_c = comm_of[u]

                # Temporarily remove u from its current community
                comm_tot[cur_c] -= k_u

                # Accumulate edge weight from u to each neighboring community
                weights_to_comm: Dict[str, float] = defaultdict(float)
                weights_to_comm[cur_c] = 0.0
                for v, w in u_neighbors.items():
                    weights_to_comm[comm_of[v]] += w

                # Evaluate modularity gain deterministically over sorted candidate communities
                best_c = cur_c
                best_gain = weights_to_comm[cur_c] - (k_u * comm_tot[cur_c]) / two_m

                for cand_c in sorted(weights_to_comm.keys()):
                    gain = weights_to_comm[cand_c] - (k_u * comm_tot[cand_c]) / two_m
                    if gain > best_gain + 1e-9:
                        best_gain = gain
                        best_c = cand_c

                comm_of[u] = best_c
                comm_tot[best_c] += k_u
                if best_c != cur_c:
                    moved_any = True

            if not moved_any:
                break

    # Group files by provisional community
    grouped: Dict[str, List[str]] = defaultdict(list)
    for u in sorted_files:
        grouped[comm_of[u]].append(u)

    # Leiden refinement: split any community whose induced subgraph is disconnected
    refined_clusters: List[List[str]] = []
    for members in grouped.values():
        member_set = set(members)
        visited: Set[str] = set()
        for start in sorted(members):
            if start in visited:
                continue
            comp: List[str] = []
            queue: deque[str] = deque([start])
            visited.add(start)
            while queue:
                curr = queue.popleft()
                comp.append(curr)
                for nb in sorted(adj.get(curr, {}).keys()):
                    if nb in member_set and nb not in visited and adj[curr][nb] > 0.0:
                        visited.add(nb)
                        queue.append(nb)
            refined_clusters.append(sorted(comp))

    # Deterministic final cluster ordering
    refined_clusters.sort(key=lambda files: (files[0], len(files)))
    return refined_clusters


def detect_code_communities(
    nodes: List[CPGNode],
    edges: List[CPGEdge],
    app_tree: Optional[AppTreeSummary] = None,
    findings: Optional[List[Finding]] = None,
    graph_engine_mode: GraphEngineMode = "NEO4J_APOC",
) -> CommunityMapResponse:
    """
    Detects deterministic architectural security communities and cross-language polyglot
    trust bridges across repository files.
    """
    all_files: Set[str] = set()
    node_to_file: Dict[str, str] = {}
    file_lang_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    file_entrypoints: Counter[str] = Counter()
    file_sinks: Counter[str] = Counter()

    for n in nodes:
        fp = _norm_path(n.filepath)
        if not fp:
            continue
        all_files.add(fp)
        node_to_file[n.id] = fp
        lang = _canonical_language(n.language, fp)
        file_lang_counts[fp][lang] += 1
        if _is_entrypoint_node(n):
            file_entrypoints[fp] += 1
        if n.is_sink:
            file_sinks[fp] += 1

    if app_tree is not None:
        for ff in app_tree.flat_files:
            fp = _norm_path(ff.filepath)
            if not fp:
                continue
            all_files.add(fp)
            if not file_lang_counts[fp]:
                file_lang_counts[fp][_canonical_language(ff.language, fp)] += 1

    if not all_files:
        return CommunityMapResponse(
            graph_engine_mode=graph_engine_mode,
            total_communities=0,
            polyglot_bridges_count=0,
            communities=[],
            cross_community_edges=[],
        )

    # Undirected weighted adjacency map + directed cross-file edge log
    adj: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
    directed_cross_edges: List[Tuple[str, str, str]] = []

    def _add_undirected_weight(f1: str, f2: str, w: float) -> None:
        if f1 == f2 or w <= 0.0:
            return
        adj[f1][f2] += w
        adj[f2][f1] += w

    for e in edges:
        src_fp = node_to_file.get(e.source_id)
        tgt_fp = node_to_file.get(e.target_id)
        if not src_fp or not tgt_fp or src_fp == tgt_fp:
            continue
        w = _EDGE_WEIGHTS.get(e.edge_type)
        if w is not None:
            _add_undirected_weight(src_fp, tgt_fp, w)
            directed_cross_edges.append((src_fp, tgt_fp, e.edge_type))

    if app_tree is not None and app_tree.cross_file_edges:
        for ce in app_tree.cross_file_edges:
            src_fp = _norm_path(ce.source_filepath)
            tgt_fp = _norm_path(ce.target_filepath)
            if not src_fp or not tgt_fp or src_fp == tgt_fp:
                continue
            all_files.add(src_fp)
            all_files.add(tgt_fp)
            _add_undirected_weight(src_fp, tgt_fp, _EDGE_WEIGHTS["IMPORTS"])
            directed_cross_edges.append((src_fp, tgt_fp, ce.edge_type or "IMPORTS"))

    sorted_files = sorted(all_files)

    # Same parent directory locality (+0.5)
    files_by_dir: Dict[str, List[str]] = defaultdict(list)
    for fp in sorted_files:
        parent_dir = os.path.dirname(fp)
        files_by_dir[parent_dir].append(fp)

    for dir_files in files_by_dir.values():
        count = len(dir_files)
        if count <= 1:
            continue
        if count <= 50:
            for i in range(count):
                for j in range(i + 1, count):
                    _add_undirected_weight(dir_files[i], dir_files[j], _SAME_DIR_WEIGHT)
        else:
            # Bounded deterministic locality window for very large flat directories
            for i in range(count):
                for j in range(i + 1, min(count, i + 11)):
                    _add_undirected_weight(dir_files[i], dir_files[j], _SAME_DIR_WEIGHT)

    # Run deterministic modularity optimization + connected-component refinement
    clusters = _run_deterministic_leiden(sorted_files, adj)

    # Map findings to files for risk tier calculation
    file_to_findings: Dict[str, List[Finding]] = defaultdict(list)
    for finding in findings or []:
        touched_files: Set[str] = set()
        if finding.best_fix_location and finding.best_fix_location.filepath:
            touched_files.add(_norm_path(finding.best_fix_location.filepath))
        for pn in finding.path_nodes or []:
            pn_fp = _norm_path(str(pn.get("filepath") or ""))
            if pn_fp:
                touched_files.add(pn_fp)
        for tf in touched_files:
            file_to_findings[tf].append(finding)

    # Build deterministic GraphCommunityItem list
    communities: List[GraphCommunityItem] = []
    file_to_comm: Dict[str, GraphCommunityItem] = {}
    used_labels: Counter[str] = Counter()

    for idx, member_files in enumerate(clusters, start=1):
        digest = hashlib.sha256("\n".join(member_files).encode("utf-8")).hexdigest()[:8]
        comm_id = f"comm-{idx:02d}-{digest}"

        lang_freq: Counter[str] = Counter()
        ep_total = 0
        sink_total = 0
        comm_findings: Dict[str, Finding] = {}

        for fp in member_files:
            per_file_langs = file_lang_counts.get(fp)
            if per_file_langs:
                dominant_file_lang = sorted(per_file_langs.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            else:
                dominant_file_lang = _canonical_language(None, fp)
            lang_freq[dominant_file_lang] += 1
            ep_total += file_entrypoints.get(fp, 0)
            sink_total += file_sinks.get(fp, 0)
            for fl in file_to_findings.get(fp, []):
                comm_findings[fl.id] = fl

        primary_lang = sorted(lang_freq.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        unique_langs = sorted(lang_freq.keys())

        crit_c = sum(1 for fl in comm_findings.values() if fl.severity == "CRITICAL")
        high_c = sum(1 for fl in comm_findings.values() if fl.severity == "HIGH")
        med_c = sum(1 for fl in comm_findings.values() if fl.severity == "MEDIUM")
        risk_tier = _compute_risk_tier(crit_c, high_c, med_c, sink_total, ep_total)

        base_label = _derive_community_label(member_files, primary_lang)
        used_labels[base_label] += 1
        final_label = base_label if used_labels[base_label] == 1 else f"{base_label} #{used_labels[base_label]}"

        item = GraphCommunityItem(
            id=comm_id,
            label=final_label,
            primary_language=primary_lang,
            languages=unique_langs,
            filepaths=member_files,
            file_count=len(member_files),
            entrypoint_count=ep_total,
            sink_count=sink_total,
            finding_count=len(comm_findings),
            risk_tier=risk_tier,  # type: ignore[arg-type]
        )
        communities.append(item)
        for fp in member_files:
            file_to_comm[fp] = item

    # Aggregate directed cross-community edges
    bridge_acc: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for src_fp, tgt_fp, etype in directed_cross_edges:
        src_comm = file_to_comm.get(src_fp)
        tgt_comm = file_to_comm.get(tgt_fp)
        if src_comm is None or tgt_comm is None or src_comm.id == tgt_comm.id:
            continue
        pair_key = (src_comm.id, tgt_comm.id)
        entry = bridge_acc.get(pair_key)
        if entry is None:
            entry = {
                "src_comm": src_comm,
                "tgt_comm": tgt_comm,
                "edge_count": 0,
                "edge_types": set(),
                "sample_files": set(),
            }
            bridge_acc[pair_key] = entry
        entry["edge_count"] += 1
        entry["edge_types"].add(etype)
        entry["sample_files"].add(src_fp)
        entry["sample_files"].add(tgt_fp)

    cross_edges: List[CommunityBridgeEdge] = []
    polyglot_bridges = 0
    for (src_id, tgt_id) in sorted(bridge_acc.keys()):
        entry = bridge_acc[(src_id, tgt_id)]
        src_comm = entry["src_comm"]
        tgt_comm = entry["tgt_comm"]
        is_polyglot = src_comm.primary_language != tgt_comm.primary_language
        if is_polyglot:
            polyglot_bridges += 1
        edge_id = f"bridge-{hashlib.sha256(f'{src_id}->{tgt_id}'.encode('utf-8')).hexdigest()[:12]}"
        cross_edges.append(
            CommunityBridgeEdge(
                id=edge_id,
                source_community_id=src_id,
                target_community_id=tgt_id,
                edge_count=entry["edge_count"],
                edge_types=sorted(entry["edge_types"]),
                is_polyglot_bridge=is_polyglot,
                sample_files=sorted(entry["sample_files"])[:6],
            )
        )

    return CommunityMapResponse(
        graph_engine_mode=graph_engine_mode,
        total_communities=len(communities),
        polyglot_bridges_count=polyglot_bridges,
        communities=communities,
        cross_community_edges=cross_edges,
    )


def build_community_graph_view(community_map: CommunityMapResponse) -> Dict[str, Any]:
    """Converts a CommunityMapResponse into a ReactFlow-ready COMMUNITY_MAP graph payload."""
    nodes_payload: List[Dict[str, Any]] = []
    for c in community_map.communities:
        nodes_payload.append(
            {
                "id": c.id,
                "label": "CommunityCluster",
                "name": c.label,
                "filepath": c.filepaths[0] if c.filepaths else "",
                "start_line": 1,
                "end_line": 1,
                "ast_type": "community_cluster",
                "code": f"{c.file_count} files • {', '.join(c.languages)} • {c.finding_count} findings",
                "language": c.primary_language,
                "risk_tier": c.risk_tier,
                "file_count": c.file_count,
                "finding_count": c.finding_count,
                "entrypoint_count": c.entrypoint_count,
                "sink_count": c.sink_count,
                "filepaths": c.filepaths,
                "languages": c.languages,
                "is_source": c.entrypoint_count > 0,
                "is_sink": c.sink_count > 0,
                "is_sanitizer": False,
            }
        )

    edges_payload: List[Dict[str, Any]] = []
    for e in community_map.cross_community_edges:
        edge_type_str = "/".join(e.edge_types[:2]) if e.edge_types else "LINK"
        edges_payload.append(
            {
                "id": e.id,
                "source": e.source_community_id,
                "target": e.target_community_id,
                "type": "POLYGLOT_BRIDGE" if e.is_polyglot_bridge else "COMMUNITY_LINK",
                "label": f"{e.edge_count}× {edge_type_str}" + (" (Polyglot)" if e.is_polyglot_bridge else ""),
                "is_polyglot_bridge": e.is_polyglot_bridge,
                "edge_count": e.edge_count,
            }
        )

    return {
        "view_mode": "COMMUNITY_MAP",
        "nodes": nodes_payload,
        "edges": edges_payload,
        "summary": {
            "total_communities": community_map.total_communities,
            "polyglot_bridges_count": community_map.polyglot_bridges_count,
            "graph_engine_mode": community_map.graph_engine_mode,
        },
    }
