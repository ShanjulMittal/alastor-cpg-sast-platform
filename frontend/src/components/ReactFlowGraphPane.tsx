"use client";

import React, { useEffect, useState, useMemo, useCallback, useRef } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  MarkerType,
} from "reactflow";
import "reactflow/dist/style.css";
import dagre from "@dagrejs/dagre";

import { useAuditStore } from "@/store/useAuditStore";
import { fetchGraphData } from "@/lib/api";
import { CustomGraphNode, NodeBlastRole } from "./CustomGraphNode";
import {
  DirectionalFlowEdge,
  DirectionalFlowEdgeData,
  EdgeBlastState,
  formatCircledStep,
  resolveDirectionalEdgeMeta,
} from "./DirectionalFlowEdge";
import {
  CPGNode,
  CrossFileEdge,
  Finding,
  GraphEdgeItem,
  GraphViewMode,
  DirectoryTreeNode,
  FilePurposeInfo,
  DiscoveredElement,
} from "@/types/cpg";
import {
  Layers,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Minimize2,
  Compass,
  Crosshair,
  Search,
  Copy,
  Check,
  GitBranch,
  Flame,
  FolderTree,
  Radar,
  Code2,
  X,
  Sparkles,
  Play,
  Pause,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Download,
  Info,
  ArrowRight,
  ArrowDown,
  Monitor,
  Map as MapIcon,
  ShieldCheck,
  RotateCcw,
  Loader2,
} from "lucide-react";

const NODE_WIDTH = 264;
const NODE_HEIGHT = 132;

const nodeTypes = {
  cpgNode: CustomGraphNode,
};

const edgeTypes = {
  directionalFlow: DirectionalFlowEdge,
};

type AppTreeLayoutStyle = "SPIDER_WEB" | "MIND_MAP" | "HIERARCHY";

interface EdgeLayerFilterState {
  dfg: boolean;
  cfg: boolean;
  calls: boolean;
  ast: boolean;
}

function getNodeDimensions(node: Node): { w: number; h: number } {
  const lbl = node.data?.label;
  if (lbl === "SpiderHub") return { w: 208, h: 208 };
  if (lbl === "AppElement") return { w: 192, h: 36 };
  if (lbl === "AppDirectory") return { w: node.data?.isSpiderMode ? 208 : 256, h: 112 };
  if (lbl === "AppFile") return { w: node.data?.isSpiderMode ? 224 : 256, h: 132 };
  return { w: NODE_WIDTH, h: NODE_HEIGHT };
}

/**
 * Computes outer-perimeter sourceHandle & targetHandle pairs so 100% of arrowheads
 * dock cleanly outside node card borders in LR, TB, Mind-Map, and 360° Spider layouts.
 */
function computePerimeterHandles(
  layoutMode: "LR" | "TB" | "SPIDER_360",
  sourceNode?: Node,
  targetNode?: Node,
  isCrossFileInTree = false
): { sourceHandle: string; targetHandle: string } {
  if (layoutMode === "SPIDER_360" && sourceNode && targetNode) {
    const sDim = getNodeDimensions(sourceNode);
    const tDim = getNodeDimensions(targetNode);
    const sx = sourceNode.position.x + sDim.w / 2;
    const sy = sourceNode.position.y + sDim.h / 2;
    const tx = targetNode.position.x + tDim.w / 2;
    const ty = targetNode.position.y + tDim.h / 2;
    const dx = tx - sx;
    const dy = ty - sy;

    if (Math.abs(dx) >= Math.abs(dy)) {
      return dx >= 0
        ? { sourceHandle: "right-src", targetHandle: "left-tgt" }
        : { sourceHandle: "left-src", targetHandle: "right-tgt" };
    }
    return dy >= 0
      ? { sourceHandle: "bottom-src", targetHandle: "top-tgt" }
      : { sourceHandle: "top-src", targetHandle: "bottom-tgt" };
  }

  if (isCrossFileInTree && sourceNode && targetNode) {
    const dx = targetNode.position.x - sourceNode.position.x;
    const dy = targetNode.position.y - sourceNode.position.y;
    if (Math.abs(dx) < 30 && Math.abs(dy) > 20) {
      return dy >= 0
        ? { sourceHandle: "bottom-src", targetHandle: "top-tgt" }
        : { sourceHandle: "top-src", targetHandle: "bottom-tgt" };
    }
    if (layoutMode === "LR" && dx < -30) {
      return { sourceHandle: "left-src", targetHandle: "right-tgt" };
    }
  }

  if (layoutMode === "LR") {
    return { sourceHandle: "right-src", targetHandle: "left-tgt" };
  }
  return { sourceHandle: "bottom-src", targetHandle: "top-tgt" };
}

function computeDagreLayout(
  nodes: Node[],
  edges: Edge[],
  rankdir: "TB" | "LR" = "LR"
): { nodes: Node[]; edges: Edge[] } {
  const safeNodes = nodes.length > 180 ? nodes.slice(0, 180) : nodes;
  const safeNodeIds = new Set(safeNodes.map((n) => n.id));
  const safeEdges = edges.filter(
    (e) => safeNodeIds.has(e.source) && safeNodeIds.has(e.target)
  );

  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({
    rankdir,
    nodesep: rankdir === "LR" ? 64 : 84,
    ranksep: rankdir === "LR" ? 165 : 118,
  });

  safeNodes.forEach((node) => {
    const dim = getNodeDimensions(node);
    dagreGraph.setNode(node.id, { width: dim.w, height: dim.h });
  });

  safeEdges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const posMap = new Map<string, Node>();
  const layoutedNodes = safeNodes.map((node) => {
    const dim = getNodeDimensions(node);
    const nodeWithPosition = dagreGraph.node(node.id);
    const positioned: Node = {
      ...node,
      position: {
        x: nodeWithPosition ? nodeWithPosition.x - dim.w / 2 : 0,
        y: nodeWithPosition ? nodeWithPosition.y - dim.h / 2 : 0,
      },
    };
    posMap.set(positioned.id, positioned);
    return positioned;
  });

  const handlesMode = rankdir === "LR" ? "LR" : "TB";
  const routedEdges = safeEdges.map((edge) => {
    const sNode = posMap.get(edge.source);
    const tNode = posMap.get(edge.target);
    const handles = computePerimeterHandles(handlesMode, sNode, tNode);
    return {
      ...edge,
      sourceHandle: handles.sourceHandle,
      targetHandle: handles.targetHandle,
    };
  });

  return { nodes: layoutedNodes, edges: routedEdges };
}

/**
 * Counts visible weight of a DirectoryTreeNode for proportional angular sector allocation in Spider mode.
 */
function countSubtreeWeight(
  dir: DirectoryTreeNode,
  collapsedDirs: Record<string, boolean>
): number {
  if (dir.path && collapsedDirs[dir.path]) {
    return 1;
  }
  let weight = Math.max(1, dir.files.length);
  for (const sub of dir.subdirectories) {
    weight += countSubtreeWeight(sub, collapsedDirs);
  }
  return Math.max(1, weight);
}

function basenameOf(fp?: string | null): string {
  if (!fp) return "workspace";
  const norm = fp.replace(/\\/g, "/");
  const parts = norm.split("/").filter(Boolean);
  return parts[parts.length - 1] || fp;
}

/**
 * Client-side 3-step context synthesis for single-node or edgeless findings so
 * NO finding ever renders as an isolated single card without directional flow.
 */
function buildClientFindingFlowGraph(finding: Finding): {
  nodes: CPGNode[];
  edges: GraphEdgeItem[];
} {
  const rawNodes = finding.path_nodes || [];
  const rawEdges = finding.path_edges || [];
  const bfl = finding.best_fix_location;
  const findingId = finding.id || "finding";
  const ruleId = finding.rule_id || "";
  const ruleUp = ruleId.toUpperCase();
  const engineUp = (finding.scan_engine || "SAST").toUpperCase();
  const cweId = finding.cwe_id || "CWE-703";
  const severity = finding.severity || "HIGH";
  const title = finding.title || "Security Vulnerability";
  const isSecret =
    Boolean(finding.is_secret_finding) ||
    ruleUp.includes("SECRET") ||
    ruleUp.includes("RULE-8") ||
    cweId.toUpperCase() === "CWE-798";

  if (rawNodes.length >= 2 && rawEdges.length >= 1) {
    const bflNodeId = bfl?.node_id || "";
    const bflFp = (bfl?.filepath || "").replace(/\\/g, "/").replace(/^\/+/, "");
    const bflLine = bfl?.line || 0;

    let matchedBfl = false;
    const enrichedNodes: CPGNode[] = rawNodes.map((n) => {
      const nFp = (n.filepath || "").replace(/\\/g, "/").replace(/^\/+/, "");
      const isMatch = Boolean(
        (bflNodeId && n.id === bflNodeId) ||
          (bflFp &&
            bflLine > 0 &&
            n.start_line === bflLine &&
            (nFp === bflFp ||
              nFp.endsWith(`/${bflFp}`) ||
              bflFp.endsWith(`/${nFp}`)))
      );
      if (isMatch) matchedBfl = true;
      return {
        ...n,
        is_bfl: Boolean(n.is_bfl || isMatch),
        is_synthesized_context: Boolean(n.is_synthesized_context),
      };
    });

    if (!matchedBfl && enrichedNodes.length > 0) {
      const fallbackIdx =
        enrichedNodes.length >= 3
          ? enrichedNodes.length - 2
          : enrichedNodes.length - 1;
      enrichedNodes[fallbackIdx] = {
        ...enrichedNodes[fallbackIdx],
        is_bfl: true,
      };
    }

    const sinkIds = new Set(
      enrichedNodes.filter((n) => n.is_sink).map((n) => String(n.id))
    );

    const enrichedEdges: GraphEdgeItem[] = rawEdges.map((e, idx) => {
      const stepIdx = e.step_index ?? idx + 1;
      const eType = e.type || "DFG_FLOWS_TO";
      const meta = resolveDirectionalEdgeMeta(eType, {
        varName: e.var_name,
        flowLabel: e.flow_label,
        stepIndex: stepIdx,
        isSinkTarget: sinkIds.has(String(e.target)),
      });
      return {
        id: String(e.id || `edge-${findingId}-${idx}`),
        source: String(e.source),
        target: String(e.target),
        type: eType,
        var_name: e.var_name ?? null,
        step_index: stepIdx,
        flow_label: meta.flowLabel,
      };
    });

    return { nodes: enrichedNodes, edges: enrichedEdges };
  }

  // Synthesize 3-node directional chain: ① Origin ──▶ ② BFL Chokepoint ──▶ ③ Security Impact
  let chokepoint: CPGNode;
  if (rawNodes.length >= 1) {
    const first = rawNodes[0];
    chokepoint = {
      ...first,
      id: String(first.id || `bfl:${findingId}`),
      is_bfl: true,
      is_source: false,
      is_sink: false,
      is_synthesized_context: false,
    };
  } else {
    const fpFallback = bfl?.filepath || "workspace";
    const lnFallback = Math.max(1, bfl?.line || 1);
    const colFallback = Math.max(0, bfl?.column || 0);
    const snipFallback = bfl?.code_snippet || title;
    chokepoint = {
      id: bfl?.node_id || `bfl:${findingId}`,
      label: "Call",
      ast_type: "bfl_chokepoint",
      name: `${basenameOf(fpFallback)}:L${lnFallback}`,
      code: snipFallback,
      filepath: fpFallback,
      start_line: lnFallback,
      end_line: lnFallback,
      start_col: colFallback,
      end_col: colFallback + Math.max(1, snipFallback.length),
      scope_id: fpFallback,
      is_source: false,
      is_sink: false,
      is_sanitizer: false,
      is_bfl: true,
      is_synthesized_context: false,
    };
  }

  const chokeFp = chokepoint.filepath || bfl?.filepath || "workspace";
  const chokeLine = Math.max(1, chokepoint.start_line || 1);
  const chokeScope = chokepoint.scope_id || chokeFp;
  const shortFile = basenameOf(chokeFp);

  let originName = `Application Caller (${basenameOf(chokeScope)})`;
  let originCode = `Execution reaches ${shortFile}:L${chokeLine}`;
  let originAst = "application_caller";
  let edge1Label = "① REACHES BFL ▶";
  let edge2Label = "② EXPOSES SINK ▶";

  if (engineUp === "SCA" || ruleUp.startsWith("SCA-")) {
    originName = `Dependency Manifest (${shortFile})`;
    originCode = `Supply-chain dependency resolution in ${chokeFp}`;
    originAst = "dependency_manifest";
    edge1Label = "① LOADS PKG ▶";
    edge2Label = "② RUNTIME IMPACT ▶";
  } else if (engineUp === "IAC" || ruleUp.startsWith("IAC-")) {
    originName = `Deployment / Runtime Config (${shortFile})`;
    originCode = `Infrastructure & container policy in ${chokeFp}`;
    originAst = "iac_config";
    edge1Label = "① CONFIGURES ▶";
    edge2Label = "② EXPOSES SINK ▶";
  } else if (isSecret) {
    originName = `Secret / Credential Exposure (${shortFile})`;
    originCode = `Embedded credential material in ${shortFile}:L${chokeLine}`;
    originAst = "secret_origin";
    edge1Label = "① EMBEDS SECRET ▶";
    edge2Label = "② CREDENTIAL COMPROMISE ▶";
  }

  const originNode: CPGNode = {
    id: `ctx-origin:${findingId}`,
    label: "Entry",
    ast_type: originAst,
    name: originName,
    code: originCode,
    filepath: chokeFp,
    start_line: chokeLine,
    end_line: chokeLine,
    start_col: 0,
    end_col: 20,
    scope_id: chokeScope,
    is_source: true,
    is_sink: false,
    is_sanitizer: false,
    is_bfl: false,
    is_synthesized_context: true,
  };

  const impactNode: CPGNode = {
    id: `ctx-impact:${findingId}`,
    label: "Exit",
    ast_type: "security_impact",
    name: `Security Impact (${cweId})`,
    code: `[${severity}] ${cweId}: ${title}`.slice(0, 220),
    filepath: chokeFp,
    start_line: chokeLine,
    end_line: chokeLine,
    start_col: 0,
    end_col: 20,
    scope_id: chokeScope,
    is_source: false,
    is_sink: true,
    is_sanitizer: false,
    is_bfl: false,
    is_synthesized_context: true,
  };

  const edges: GraphEdgeItem[] = [
    {
      id: `ctx-edge-1:${findingId}`,
      source: originNode.id,
      target: chokepoint.id,
      type: "DFG_FLOWS_TO",
      var_name: ruleId || "context",
      step_index: 1,
      flow_label: edge1Label,
    },
    {
      id: `ctx-edge-2:${findingId}`,
      source: chokepoint.id,
      target: impactNode.id,
      type: "DFG_FLOWS_TO",
      var_name: cweId,
      step_index: 2,
      flow_label: edge2Label,
    },
  ];

  return {
    nodes: [originNode, chokepoint, impactNode],
    edges,
  };
}

function edgeMatchesLayerFilter(
  edgeTypeRaw: string | undefined,
  layers: EdgeLayerFilterState
): boolean {
  const et = (edgeTypeRaw || "").toUpperCase();
  if (et === "DFG_FLOWS_TO" || et === "UNGUARDED" || et === "SANITIZED") {
    return layers.dfg;
  }
  if (et.startsWith("CFG_")) {
    return layers.cfg;
  }
  if (et === "CALLS" || et === "IMPORTS" || et === "CONFIGURES") {
    return layers.calls;
  }
  return layers.ast;
}

export function ReactFlowGraphPane() {
  const projectPath = useAuditStore((s) => s.projectPath);
  const selectedFinding = useAuditStore((s) => s.selectedFinding);
  const findings = useAuditStore((s) => s.findings);
  const appTree = useAuditStore((s) => s.appTree);
  const activeFilepath = useAuditStore((s) => s.activeFilepath);
  const selectedGraphNodeId = useAuditStore((s) => s.selectedGraphNodeId);
  const graphViewMode = useAuditStore((s) => s.graphViewMode);
  const setGraphViewMode = useAuditStore((s) => s.setGraphViewMode);
  const setReactFlowInstance = useAuditStore((s) => s.setReactFlowInstance);
  const reactFlowInstance = useAuditStore((s) => s.reactFlowInstance);
  const isGraphFullscreen = useAuditStore((s) => s.isGraphFullscreen);
  const setGraphFullscreen = useAuditStore((s) => s.setGraphFullscreen);
  const selectFinding = useAuditStore((s) => s.selectFinding);
  const selectGraphNode = useAuditStore((s) => s.selectGraphNode);
  const lastAppliedPatch = useAuditStore((s) => s.lastAppliedPatch);
  const isApplyingPatch = useAuditStore((s) => s.isApplyingPatch);
  const undoLastRemediationPatch = useAuditStore(
    (s) => s.undoLastRemediationPatch
  );
  const setAiDrawerOpen = useAuditStore((s) => s.setAiDrawerOpen);
  const explainCurrentGraphWithAi = useAuditStore(
    (s) => s.explainCurrentGraphWithAi
  );
  const aiIsBusy = useAuditStore((s) => s.aiIsBusy);

  const isCurrentFindingSevered = Boolean(
    lastAppliedPatch?.verifiedSevered &&
      (lastAppliedPatch.findingId === selectedFinding?.id ||
        !selectedFinding ||
        (activeFilepath &&
          lastAppliedPatch.filepath &&
          (activeFilepath === lastAppliedPatch.filepath ||
            activeFilepath.endsWith(lastAppliedPatch.filepath) ||
            lastAppliedPatch.filepath.endsWith(activeFilepath))))
  );

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  // Layout, Cross-File Flow & Layer Controls
  const [treeLayoutStyle, setTreeLayoutStyle] =
    useState<AppTreeLayoutStyle>("SPIDER_WEB");
  const [spiderDeclutterMode, setSpiderDeclutterMode] = useState<
    "SMART_SIMPLIFIED" | "VULNERABLE_ONLY" | "FULL_EXPANDED"
  >("SMART_SIMPLIFIED");
  const [callGraphScope, setCallGraphScope] = useState<
    "WHOLE_APP" | "CURRENT_FILE"
  >("WHOLE_APP");
  const [cpgLayoutDirection, setCpgLayoutDirection] = useState<"TB" | "LR">("LR");
  const [showCrossFileFlows, setShowCrossFileFlows] = useState<boolean>(true);
  const [edgeLayers, setEdgeLayers] = useState<EdgeLayerFilterState>({
    dfg: true,
    cfg: true,
    calls: true,
    ast: true,
  });

  // Blast-Radius Upstream / Downstream Highlighting State
  const [isBlastRadiusEnabled, setIsBlastRadiusEnabled] = useState<boolean>(true);
  const [lockedBlastNodeId, setLockedBlastNodeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [hoveredEdgeId, setHoveredEdgeId] = useState<string | null>(null);

  // Overlays & Popovers
  const [showLayersPopover, setShowLayersPopover] = useState<boolean>(false);
  const [collapsedDirs, setCollapsedDirs] = useState<Record<string, boolean>>({});
  const [expandedFileElements, setExpandedFileElements] = useState<
    Record<string, boolean>
  >({});
  const [spiderSearch, setSpiderSearch] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [showRadarChart, setShowRadarChart] = useState<boolean>(false);
  const [showLegend, setShowLegend] = useState<boolean>(false);
  const [showMiniMap, setShowMiniMap] = useState<boolean>(true);
  const [inspectedNodeData, setInspectedNodeData] = useState<any | null>(null);
  const [copiedRefText, setCopiedRefText] = useState<string | null>(null);

  // Full-Screen Presentation Walkthrough Tour State
  const [activeTourStepIdx, setActiveTourStepIdx] = useState<number>(0);
  const [isAutoPlayingTour, setIsAutoPlayingTour] = useState<boolean>(false);
  const [isNativeFullscreen, setIsNativeFullscreen] = useState<boolean>(false);

  const popoverRef = useRef<HTMLDivElement | null>(null);

  // Close Layers & Layout popover on outside click
  useEffect(() => {
    if (!showLayersPopover) return;
    const onDocClick = (ev: MouseEvent) => {
      if (
        popoverRef.current &&
        !popoverRef.current.contains(ev.target as globalThis.Node)
      ) {
        setShowLayersPopover(false);
      }
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [showLayersPopover]);

  // Synthesized 3+ step finding flow graph (guarantees >= 3 steps even on single-node findings)
  const activeFindingFlow = useMemo(() => {
    if (!selectedFinding) return null;
    return buildClientFindingFlowGraph(selectedFinding);
  }, [selectedFinding]);

  // Extract cross-file IMPORTS/CALLS edges from appTree (with fallback to imports_files)
  const allCrossFileEdges = useMemo<CrossFileEdge[]>(() => {
    if (!appTree) return [];
    if (appTree.cross_file_edges && appTree.cross_file_edges.length > 0) {
      return appTree.cross_file_edges;
    }
    const derived: CrossFileEdge[] = [];
    const seen = new Set<string>();
    for (const f of appTree.flat_files || []) {
      for (const imp of f.imports_files || []) {
        const key = `${f.filepath}->${imp}`;
        if (!seen.has(key) && f.filepath !== imp) {
          seen.add(key);
          derived.push({
            source_filepath: f.filepath,
            target_filepath: imp,
            edge_type: "IMPORTS",
            symbols: [],
            flow_label: "IMPORTS ▶",
          });
        }
      }
    }
    return derived;
  }, [appTree]);

  const handleToggleCollapseDir = useCallback((dirPath: string) => {
    setCollapsedDirs((prev) => ({ ...prev, [dirPath]: !prev[dirPath] }));
  }, []);

  const handleToggleFileElements = useCallback((filepath: string) => {
    setExpandedFileElements((prev) => ({
      ...prev,
      [filepath]: !prev[filepath],
    }));
  }, []);

  const handleCopyReference = (text: string, label: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedRefText(label);
      setTimeout(() => setCopiedRefText(null), 1800);
    }
  };

  // Clear blast focus & tour index on context switch
  useEffect(() => {
    setActiveTourStepIdx(0);
    setIsAutoPlayingTour(false);
    setLockedBlastNodeId(null);
    setHoveredNodeId(null);
  }, [selectedFinding?.id, graphViewMode]);

  // Auto-fit view when toggling Full-Screen Presentation Mode
  useEffect(() => {
    const timer = setTimeout(() => {
      if (reactFlowInstance) {
        reactFlowInstance.fitView({
          padding: isGraphFullscreen ? 0.18 : 0.22,
          duration: 420,
        });
      }
    }, 120);
    return () => clearTimeout(timer);
  }, [isGraphFullscreen, reactFlowInstance]);

  // Escape key clears Blast-Radius Focus, popovers, or Fullscreen
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (lockedBlastNodeId || hoveredNodeId) {
          setLockedBlastNodeId(null);
          setHoveredNodeId(null);
          return;
        }
        if (showLayersPopover) {
          setShowLayersPopover(false);
          return;
        }
        if (showLegend) {
          setShowLegend(false);
          return;
        }
        if (isGraphFullscreen) {
          setGraphFullscreen(false);
          setIsAutoPlayingTour(false);
        }
      }
    };
    const onFsChange = () => {
      setIsNativeFullscreen(Boolean(document.fullscreenElement));
    };
    window.addEventListener("keydown", onKeyDown);
    document.addEventListener("fullscreenchange", onFsChange);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("fullscreenchange", onFsChange);
    };
  }, [
    lockedBlastNodeId,
    hoveredNodeId,
    showLayersPopover,
    showLegend,
    isGraphFullscreen,
    setGraphFullscreen,
  ]);

  const handleToggleBrowserFullscreen = async () => {
    try {
      if (!document.fullscreenElement) {
        await document.documentElement.requestFullscreen();
        setGraphFullscreen(true);
      } else {
        await document.exitFullscreen();
      }
    } catch {
      setGraphFullscreen(!isGraphFullscreen);
    }
  };

  const handleExportGraphSnapshot = () => {
    const payload = {
      exported_at: new Date().toISOString(),
      project_path: projectPath,
      active_filepath: activeFilepath,
      graph_view_mode: graphViewMode,
      selected_finding: selectedFinding
        ? {
            id: selectedFinding.id,
            rule_id: selectedFinding.rule_id,
            title: selectedFinding.title,
            severity: selectedFinding.severity,
            cwe_id: selectedFinding.cwe_id,
          }
        : null,
      total_nodes: nodes.length,
      total_edges: edges.length,
      nodes: nodes.map((n) => ({
        id: n.id,
        position: n.position,
        data: n.data,
      })),
      edges: edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.data?.flowLabel || e.label,
      })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `alastor-graph-${graphViewMode.toLowerCase()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Auto-keep inspectedNodeData synced with selected file in APP_TREE mode
  useEffect(() => {
    if (graphViewMode === "APP_TREE" && activeFilepath && appTree) {
      const matchedFile = appTree.flat_files.find(
        (f) =>
          f.filepath === activeFilepath ||
          activeFilepath.endsWith(f.filepath) ||
          f.filepath.endsWith(activeFilepath)
      );
      if (matchedFile) {
        setInspectedNodeData({
          ...matchedFile,
          id: `file:${matchedFile.filepath}`,
          label: "AppFile",
        });
      }
    }
  }, [activeFilepath, appTree, graphViewMode]);

  // Compute 6-axis Spider Radar Polygon metrics from appTree & findings
  const radarMetrics = useMemo(() => {
    const cats = appTree?.category_counts || {};
    const logicCount = cats["BUSINESS_LOGIC"] || 0;
    const apiCount = cats["API_ROUTER"] || 0;
    const uiCount = cats["FRONTEND_VIEW"] || 0;
    const infraCount =
      (cats["INFRASTRUCTURE"] || 0) +
      (cats["CONFIGURATION"] || 0) +
      (cats["BUILD_TOOLING"] || 0);
    const depCount = cats["DEPENDENCY_MANIFEST"] || 0;
    const flawCount = findings.length;

    const maxVal = Math.max(
      4,
      logicCount,
      apiCount,
      uiCount,
      infraCount,
      depCount,
      flawCount
    );

    return [
      {
        axis: "Logic",
        categoryKey: "BUSINESS_LOGIC",
        raw: logicCount,
        ratio: Math.min(1, Math.max(0.18, logicCount / maxVal)),
      },
      {
        axis: "API",
        categoryKey: "API_ROUTER",
        raw: apiCount,
        ratio: Math.min(1, Math.max(0.18, apiCount / maxVal)),
      },
      {
        axis: "UI Views",
        categoryKey: "FRONTEND_VIEW",
        raw: uiCount,
        ratio: Math.min(1, Math.max(0.18, uiCount / maxVal)),
      },
      {
        axis: "Infra/Cfg",
        categoryKey: "INFRASTRUCTURE",
        raw: infraCount,
        ratio: Math.min(1, Math.max(0.18, infraCount / maxVal)),
      },
      {
        axis: "Manifests",
        categoryKey: "DEPENDENCY_MANIFEST",
        raw: depCount,
        ratio: Math.min(1, Math.max(0.18, depCount / maxVal)),
      },
      {
        axis: "Flaws",
        categoryKey: "VULN_FILES",
        raw: flawCount,
        ratio: Math.min(1, Math.max(0.18, flawCount / maxVal)),
      },
    ];
  }, [appTree, findings]);

  // Primary Graph Builder Effect (APP_TREE + FINDING_PATH + CPG Backend Views)
  useEffect(() => {
    let isCancelled = false;

    async function loadGraph() {
      // CASE 1: Interactive 360° Spider-Web / Mind-Map / Hierarchy App Tree
      if (graphViewMode === "APP_TREE" && appTree) {
        const spiderNodes: Node[] = [];
        const spiderTreeEdges: Edge[] = [];
        const isSpider = treeLayoutStyle === "SPIDER_WEB";
        const queryLower = spiderSearch.trim().toLowerCase();

        // Count cross-file links per file for card badges & declutter priority
        const crossCountByFile = new Map<string, number>();
        for (const ce of allCrossFileEdges) {
          crossCountByFile.set(
            ce.source_filepath,
            (crossCountByFile.get(ce.source_filepath) || 0) + 1
          );
          crossCountByFile.set(
            ce.target_filepath,
            (crossCountByFile.get(ce.target_filepath) || 0) + 1
          );
        }

        const getFlawCountForFile = (fp: string) =>
          findings.filter((f) =>
            (f.path_nodes || []).some(
              (n) =>
                n.filepath === fp ||
                fp.endsWith(n.filepath || "") ||
                (n.filepath || "").endsWith(fp)
            )
          ).length;

        const matchesFilter = (
          name: string,
          purpose: string,
          category?: string,
          flawCount = 0,
          elements: DiscoveredElement[] = []
        ) => {
          if (categoryFilter !== "ALL") {
            if (categoryFilter === "VULN_FILES") {
              if (flawCount === 0) return false;
            } else if (categoryFilter === "INFRASTRUCTURE") {
              if (
                !["INFRASTRUCTURE", "CONFIGURATION", "BUILD_TOOLING"].includes(
                  category || ""
                )
              ) {
                return false;
              }
            } else if (category !== categoryFilter) {
              return false;
            }
          }
          if (!queryLower) return true;
          return (
            name.toLowerCase().includes(queryLower) ||
            purpose.toLowerCase().includes(queryLower) ||
            (category || "").toLowerCase().includes(queryLower) ||
            elements.some(
              (el) =>
                el.name.toLowerCase().includes(queryLower) ||
                el.signature.toLowerCase().includes(queryLower)
            )
          );
        };

        // Central Workspace Root Hub
        const rootId = "dir:root";
        const rootName = appTree.tree.name || "Workspace Root";
        spiderNodes.push({
          id: rootId,
          type: "cpgNode",
          position: { x: -104, y: -104 },
          data: {
            id: rootId,
            label: isSpider ? "SpiderHub" : "AppDirectory",
            name: rootName,
            path: "",
            purpose:
              appTree.tree.purpose ||
              "Application Architecture & CPG Root Hub",
            totalFiles: appTree.total_files,
            totalLines: appTree.total_lines,
            isSpiderMode: isSpider,
            onSelectInspect: setInspectedNodeData,
          },
        });

        const RING_STEP = appTree.total_files > 40 ? 450 : 390;
        const isLargeApp = appTree.total_files > 18;

        const getSubtreeFlawCount = (d: DirectoryTreeNode): number => {
          let total = (d.files || []).reduce(
            (acc, f) => acc + getFlawCountForFile(f.filepath),
            0
          );
          for (const sub of d.subdirectories || []) {
            total += getSubtreeFlawCount(sub);
          }
          return total;
        };

        const getSubtreeCrossCount = (d: DirectoryTreeNode): number => {
          let total = (d.files || []).reduce(
            (acc, f) => acc + (crossCountByFile.get(f.filepath) || 0),
            0
          );
          for (const sub of d.subdirectories || []) {
            total += getSubtreeCrossCount(sub);
          }
          return total;
        };

        const layoutRadialChildren = (
          parentNodeId: string,
          dirNode: DirectoryTreeNode,
          depth: number,
          startAngle: number,
          endAngle: number
        ) => {
          const rawSubDirs = dirNode.subdirectories || [];
          const rawFiles = dirNode.files || [];

          const subDirs =
            spiderDeclutterMode === "VULNERABLE_ONLY"
              ? rawSubDirs.filter((d) => getSubtreeFlawCount(d) > 0)
              : rawSubDirs;

          let files =
            spiderDeclutterMode === "VULNERABLE_ONLY"
              ? rawFiles.filter(
                  (f) =>
                    getFlawCountForFile(f.filepath) > 0 ||
                    f.filepath === activeFilepath
                )
              : rawFiles;

          const maxCleanFilesPerFolder = isLargeApp ? 6 : 16;
          if (
            spiderDeclutterMode === "SMART_SIMPLIFIED" &&
            files.length > maxCleanFilesPerFolder + 2
          ) {
            const priorityFiles = files.filter(
              (f) =>
                getFlawCountForFile(f.filepath) > 0 ||
                f.filepath === activeFilepath ||
                (crossCountByFile.get(f.filepath) || 0) > 0
            );
            const cleanRest = files.filter(
              (f) =>
                getFlawCountForFile(f.filepath) === 0 &&
                f.filepath !== activeFilepath &&
                (crossCountByFile.get(f.filepath) || 0) === 0
            );
            files = [
              ...priorityFiles.slice(0, maxCleanFilesPerFolder + 6),
              ...cleanRest.slice(
                0,
                Math.max(2, maxCleanFilesPerFolder - priorityFiles.length)
              ),
            ];
          }

          const items: Array<
            | { kind: "dir"; dir: DirectoryTreeNode; weight: number }
            | { kind: "file"; file: FilePurposeInfo; weight: number }
          > = [
            ...subDirs.map((d) => ({
              kind: "dir" as const,
              dir: d,
              weight:
                spiderDeclutterMode === "SMART_SIMPLIFIED" && isLargeApp
                  ? Math.min(4, countSubtreeWeight(d, collapsedDirs))
                  : countSubtreeWeight(d, collapsedDirs),
            })),
            ...files.map((f) => ({
              kind: "file" as const,
              file: f,
              weight: 1,
            })),
          ];

          if (items.length === 0) return;

          const totalWeight = items.reduce((acc, it) => acc + it.weight, 0);
          let currentAngle = startAngle;
          const sectorSpan = Math.max(0.35, endAngle - startAngle);
          const minRadiusForNoOverlap = (items.length * 240) / sectorSpan;
          const radius = Math.max(
            depth * RING_STEP,
            Math.min(depth * RING_STEP + 980, minRadiusForNoOverlap)
          );

          items.forEach((item, idx) => {
            const angleSpan =
              ((endAngle - startAngle) * item.weight) / Math.max(1, totalWeight);
            const midAngle = currentAngle + angleSpan / 2;
            currentAngle += angleSpan;

            const stagger = items.length > 5 ? (idx % 3) * 95 : 0;
            const r = radius + stagger;
            const cx = Math.cos(midAngle) * r;
            const cy = Math.sin(midAngle) * r;

            if (item.kind === "dir") {
              const d = item.dir;
              const dId = `dir:${d.path}`;
              const dirFlaws = getSubtreeFlawCount(d);
              const dirCross = getSubtreeCrossCount(d);
              const autoCollapseDeepClean =
                spiderDeclutterMode === "SMART_SIMPLIFIED" &&
                isLargeApp &&
                depth >= 2 &&
                dirFlaws === 0 &&
                dirCross === 0 &&
                collapsedDirs[d.path] === undefined;
              const isCollapsed = autoCollapseDeepClean
                ? true
                : Boolean(collapsedDirs[d.path]);
              const isMatch =
                spiderSearch === "" && categoryFilter === "ALL"
                  ? true
                  : matchesFilter(d.name, d.purpose);

              spiderNodes.push({
                id: dId,
                type: "cpgNode",
                position: { x: cx - 104, y: cy - 56 },
                data: {
                  id: dId,
                  label: "AppDirectory",
                  name: d.name,
                  path: d.path,
                  purpose: d.purpose,
                  childCount: d.files.length + d.subdirectories.length,
                  isCollapsed,
                  isSpiderMode: isSpider,
                  isDimmed:
                    (spiderSearch !== "" || categoryFilter !== "ALL") && !isMatch,
                  onToggleCollapse: handleToggleCollapseDir,
                  onSelectInspect: setInspectedNodeData,
                },
              });

              const containsMeta = resolveDirectionalEdgeMeta("CONTAINS", {
                isSpider,
              });
              spiderTreeEdges.push({
                id: `edge:${parentNodeId}->${dId}`,
                source: parentNodeId,
                target: dId,
                type: "directionalFlow",
                markerEnd: {
                  type: MarkerType.ArrowClosed,
                  color: containsMeta.strokeColor,
                  width: 16,
                  height: 16,
                },
                data: {
                  edgeType: "CONTAINS",
                  flowLabel: "CONTAINS ▶",
                  pathShape: isSpider ? "straight" : "smoothstep",
                  isSpider,
                  strokeColor: containsMeta.strokeColor,
                  badgeTone: containsMeta.badgeTone,
                  isAnimatedPulse: false,
                } satisfies DirectionalFlowEdgeData,
              });

              if (!isCollapsed) {
                layoutRadialChildren(
                  dId,
                  d,
                  depth + 1,
                  midAngle - angleSpan / 2,
                  midAngle + angleSpan / 2
                );
              }
            } else {
              const f = item.file;
              const fId = `file:${f.filepath}`;
              const flawCount = getFlawCountForFile(f.filepath);
              const crossEdgeCount = crossCountByFile.get(f.filepath) || 0;
              const isMatch = matchesFilter(
                f.filename,
                f.purpose,
                f.category,
                flawCount,
                f.elements
              );
              const isExpandedElements =
                expandedFileElements[f.filepath] ??
                (activeFilepath === f.filepath ||
                  (appTree.total_files <= 6 && f.elements.length > 0));

              spiderNodes.push({
                id: fId,
                type: "cpgNode",
                position: { x: cx - 112, y: cy - 66 },
                data: {
                  ...f,
                  id: fId,
                  label: "AppFile",
                  name: f.filename,
                  code: f.purpose,
                  start_line: 1,
                  end_line: f.line_count,
                  flawCount,
                  crossEdgeCount,
                  isSpiderMode: isSpider,
                  isExpandedElements,
                  isDimmed:
                    (spiderSearch !== "" || categoryFilter !== "ALL") && !isMatch,
                  onToggleElements: handleToggleFileElements,
                  onSelectInspect: setInspectedNodeData,
                },
              });

              const containsMeta = resolveDirectionalEdgeMeta("CONTAINS", {
                isSpider,
              });
              spiderTreeEdges.push({
                id: `edge:${parentNodeId}->${fId}`,
                source: parentNodeId,
                target: fId,
                type: "directionalFlow",
                markerEnd: {
                  type: MarkerType.ArrowClosed,
                  color: containsMeta.strokeColor,
                  width: 16,
                  height: 16,
                },
                data: {
                  edgeType: "CONTAINS",
                  flowLabel: "CONTAINS ▶",
                  pathShape: isSpider ? "straight" : "smoothstep",
                  isSpider,
                  strokeColor: containsMeta.strokeColor,
                  badgeTone: containsMeta.badgeTone,
                  isAnimatedPulse: false,
                } satisfies DirectionalFlowEdgeData,
              });

              // Satellite Reference Nodes
              if (isExpandedElements && f.elements && f.elements.length > 0) {
                const maxSatellites = f.elements.slice(0, 10);
                const satSpread = Math.min(
                  Math.PI * 0.75,
                  Math.max(0.45, angleSpan * 0.9)
                );
                const satStart = midAngle - satSpread / 2;
                const satRadius = r + 290;

                maxSatellites.forEach((elem, sIdx) => {
                  const satAngle =
                    maxSatellites.length === 1
                      ? midAngle
                      : satStart +
                        (satSpread * sIdx) / (maxSatellites.length - 1);
                  const sx = Math.cos(satAngle) * satRadius;
                  const sy = Math.sin(satAngle) * satRadius;
                  const elemId = `elem:${f.filepath}:${elem.name}:${elem.line_number}:${sIdx}`;

                  spiderNodes.push({
                    id: elemId,
                    type: "cpgNode",
                    position: { x: sx - 96, y: sy - 18 },
                    data: {
                      ...elem,
                      id: elemId,
                      label: "AppElement",
                      filepath: f.filepath,
                      code: elem.signature || elem.name,
                      start_line: elem.line_number || 1,
                      end_line: elem.line_number || 1,
                      isSpiderMode: isSpider,
                      onSelectInspect: setInspectedNodeData,
                    },
                  });

                  spiderTreeEdges.push({
                    id: `edge:${fId}->${elemId}`,
                    source: fId,
                    target: elemId,
                    type: "directionalFlow",
                    markerEnd: {
                      type: MarkerType.ArrowClosed,
                      color: "#b45309",
                      width: 15,
                      height: 15,
                    },
                    data: {
                      edgeType: "DECLARES",
                      flowLabel: "DECLARES ▶",
                      pathShape: isSpider ? "straight" : "smoothstep",
                      isSpider,
                      strokeColor: "#b45309",
                      badgeTone: "AMBER",
                      isAnimatedPulse: false,
                    } satisfies DirectionalFlowEdgeData,
                  });
                });
              }
            }
          });
        };

        layoutRadialChildren(
          rootId,
          appTree.tree,
          1,
          -Math.PI / 2,
          (3 * Math.PI) / 2
        );

        let positionedNodes = spiderNodes;
        let positionedEdges = spiderTreeEdges;

        if (!isSpider) {
          const rankdir = treeLayoutStyle === "MIND_MAP" ? "LR" : "TB";
          const layouted = computeDagreLayout(
            spiderNodes,
            spiderTreeEdges,
            rankdir
          );
          positionedNodes = layouted.nodes;
          positionedEdges = layouted.edges;
        }

        const nodeById = new Map<string, Node>(
          positionedNodes.map((n) => [n.id, n])
        );

        // Route Spider radial tree edges with exact atan2/quadrant perimeter handles
        if (isSpider) {
          positionedEdges = positionedEdges.map((ed) => {
            const sN = nodeById.get(ed.source);
            const tN = nodeById.get(ed.target);
            const handles = computePerimeterHandles("SPIDER_360", sN, tN);
            return {
              ...ed,
              sourceHandle: handles.sourceHandle,
              targetHandle: handles.targetHandle,
            };
          });
        }

        // Overlay Cross-File IMPORTS / CALLS edges in distinct violet (#6d28d9)
        const crossEdgesToRender: Edge[] = [];
        if (showCrossFileFlows && allCrossFileEdges.length > 0) {
          const handleMode: "LR" | "TB" | "SPIDER_360" = isSpider
            ? "SPIDER_360"
            : treeLayoutStyle === "MIND_MAP"
            ? "LR"
            : "TB";

          allCrossFileEdges.forEach((ce, idx) => {
            const srcId = `file:${ce.source_filepath}`;
            const tgtId = `file:${ce.target_filepath}`;
            const sN = nodeById.get(srcId);
            const tN = nodeById.get(tgtId);
            if (!sN || !tN || srcId === tgtId) return;

            const handles = computePerimeterHandles(handleMode, sN, tN, true);
            const symList = (ce.symbols || []).slice(0, 2).join(", ");
            const rawLbl = (ce.flow_label || "").trim();
            const finalFlowLabel = rawLbl
              ? rawLbl.includes("▶")
                ? rawLbl
                : `${rawLbl} ▶`
              : symList
              ? `IMPORTS (${symList}) ▶`
              : "IMPORTS ▶";

            crossEdgesToRender.push({
              id: `xfile:${ce.source_filepath}->${ce.target_filepath}:${idx}`,
              source: srcId,
              target: tgtId,
              sourceHandle: handles.sourceHandle,
              targetHandle: handles.targetHandle,
              type: "directionalFlow",
              markerEnd: {
                type: MarkerType.ArrowClosed,
                color: "#6d28d9",
                width: 18,
                height: 18,
              },
              data: {
                edgeType: ce.edge_type || "IMPORTS",
                flowLabel: finalFlowLabel,
                varName: symList || null,
                pathShape: "bezier",
                isSpider,
                isAnimatedPulse: true,
                strokeColor: "#6d28d9",
                badgeTone: "VIOLET",
              } satisfies DirectionalFlowEdgeData,
            });
          });
        }

        const combinedEdges = [...positionedEdges, ...crossEdgesToRender];
        const isDense = combinedEdges.length > 45;
        const densityTaggedEdges = combinedEdges.map((ed) => ({
          ...ed,
          data: {
            ...ed.data,
            isDenseGraph: isDense,
          },
        }));

        if (!isCancelled) {
          setNodes(positionedNodes);
          setEdges(densityTaggedEdges);
          setTimeout(() => {
            if (reactFlowInstance) {
              reactFlowInstance.fitView({ padding: 0.22, duration: 450 });
            }
          }, 60);
        }
        return;
      }

      // CASE 2: Standard CPG Views (FINDING_PATH, FULL_CPG, DFG_ONLY, CFG_ONLY, CALL_GRAPH, ENTRYPOINT_GRAPH)
      let rawNodes: CPGNode[] = [];
      let rawEdges: GraphEdgeItem[] = [];

      if (graphViewMode === "FINDING_PATH") {
        if (activeFindingFlow) {
          rawNodes = activeFindingFlow.nodes;
          rawEdges = activeFindingFlow.edges;
        } else {
          if (!isCancelled) {
            setNodes([]);
            setEdges([]);
          }
          return;
        }
      } else {
        try {
          const shouldPassFilepath =
            Boolean(activeFilepath) &&
            graphViewMode !== "APP_TREE" &&
            graphViewMode !== "ENTRYPOINT_GRAPH" &&
            !(graphViewMode === "CALL_GRAPH" && callGraphScope === "WHOLE_APP");
          const data = await fetchGraphData({
            view_mode: graphViewMode,
            filepath: shouldPassFilepath ? activeFilepath : null,
          });
          if (!isCancelled) {
            rawNodes = data.nodes || [];
            rawEdges = data.edges || [];
          }
        } catch (err) {
          console.error("Failed to load graph view:", err);
        }
      }

      if (isCancelled) return;

      const clampedRawNodes =
        rawNodes.length > 150 ? rawNodes.slice(0, 150) : rawNodes;
      const validNodeIds = new Set(clampedRawNodes.map((n) => String(n.id)));
      const clampedRawEdges = rawEdges.filter(
        (e) =>
          validNodeIds.has(String(e.source)) &&
          validNodeIds.has(String(e.target))
      );

      const applySeveredStyle =
        graphViewMode === "FINDING_PATH" && isCurrentFindingSevered;

      const sinkNodeIdSet = new Set(
        clampedRawNodes.filter((n) => n.is_sink).map((n) => String(n.id))
      );

      const flowNodes: Node[] = clampedRawNodes.map((n, idx) => ({
        id: String(n.id),
        type: "cpgNode",
        position: { x: 0, y: 0 },
        data: {
          ...n,
          stepNumber: graphViewMode === "FINDING_PATH" ? idx + 1 : undefined,
          isSevered: applySeveredStyle,
          onSelectInspect: setInspectedNodeData,
        },
      }));

      const isDenseCpg =
        graphViewMode === "FULL_CPG" && clampedRawEdges.length > 45;

      const flowEdges: Edge[] = clampedRawEdges.map((e, idx) => {
        const stepIdx =
          graphViewMode === "FINDING_PATH" ? e.step_index ?? idx + 1 : undefined;
        const meta = resolveDirectionalEdgeMeta(e.type, {
          isSevered: applySeveredStyle,
          varName: e.var_name,
          flowLabel: e.flow_label,
          stepIndex: stepIdx,
          isSinkTarget: sinkNodeIdSet.has(String(e.target)),
        });

        return {
          id: String(e.id || `cpg-edge-${idx}`),
          source: String(e.source),
          target: String(e.target),
          type: "directionalFlow",
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: meta.strokeColor,
            width: 18,
            height: 18,
          },
          data: {
            edgeType: e.type,
            flowLabel: meta.flowLabel,
            stepIndex: stepIdx,
            varName: e.var_name ?? null,
            pathShape: e.type === "CFG_LOOP_BACK" ? "bezier" : "smoothstep",
            isSevered: applySeveredStyle,
            isDenseGraph: isDenseCpg,
            isAnimatedPulse: meta.isAnimatedPulse,
            alwaysShowFullPill: graphViewMode === "FINDING_PATH",
            strokeColor: meta.strokeColor,
            badgeTone: meta.badgeTone,
          } satisfies DirectionalFlowEdgeData,
        };
      });

      if (flowNodes.length > 0) {
        const layouted = computeDagreLayout(
          flowNodes,
          flowEdges,
          cpgLayoutDirection
        );
        setNodes(layouted.nodes);
        setEdges(layouted.edges);

        setTimeout(() => {
          if (reactFlowInstance) {
            reactFlowInstance.fitView({
              padding: isGraphFullscreen ? 0.18 : 0.24,
              duration: 400,
            });
          }
        }, 50);
      } else {
        setNodes([]);
        setEdges([]);
      }
    }

    void loadGraph();

    return () => {
      isCancelled = true;
    };
  }, [
    activeFindingFlow,
    graphViewMode,
    activeFilepath,
    appTree,
    allCrossFileEdges,
    showCrossFileFlows,
    findings,
    treeLayoutStyle,
    spiderDeclutterMode,
    callGraphScope,
    cpgLayoutDirection,
    collapsedDirs,
    expandedFileElements,
    spiderSearch,
    categoryFilter,
    isGraphFullscreen,
    isCurrentFindingSevered,
    handleToggleCollapseDir,
    handleToggleFileElements,
    reactFlowInstance,
    setNodes,
    setEdges,
  ]);

  // Filter edges by active Edge Layers (except FINDING_PATH keeps full path intact unless dfg toggled)
  const layerFilteredEdges = useMemo(() => {
    if (graphViewMode === "APP_TREE") {
      return edges.filter((e) => {
        const et = String(e.data?.edgeType || "").toUpperCase();
        if (et === "IMPORTS" || et === "CALLS") {
          return showCrossFileFlows && edgeLayers.calls;
        }
        return edgeLayers.ast;
      });
    }
    return edges.filter((e) =>
      edgeMatchesLayerFilter(e.data?.edgeType, edgeLayers)
    );
  }, [edges, edgeLayers, graphViewMode, showCrossFileFlows]);

  // Transitive Upstream Predecessors & Downstream Reachable Blast-Radius Computation
  const blastComputation = useMemo(() => {
    const rawOriginId = isBlastRadiusEnabled
      ? lockedBlastNodeId || hoveredNodeId
      : null;
    if (!rawOriginId || !nodes.some((n) => n.id === rawOriginId)) {
      return {
        isActive: false,
        originId: null as string | null,
        originName: "",
        upstreamNodes: new Set<string>(),
        downstreamNodes: new Set<string>(),
        upstreamEdges: new Set<string>(),
        downstreamEdges: new Set<string>(),
      };
    }

    const fwdAdj = new Map<string, Array<{ target: string; edgeId: string }>>();
    const revAdj = new Map<string, Array<{ source: string; edgeId: string }>>();

    for (const e of layerFilteredEdges) {
      if (!fwdAdj.has(e.source)) fwdAdj.set(e.source, []);
      fwdAdj.get(e.source)!.push({ target: e.target, edgeId: e.id });

      if (!revAdj.has(e.target)) revAdj.set(e.target, []);
      revAdj.get(e.target)!.push({ source: e.source, edgeId: e.id });
    }

    const upstreamNodes = new Set<string>();
    const upstreamEdges = new Set<string>();
    const upQueue: string[] = [rawOriginId];
    const visitedUp = new Set<string>([rawOriginId]);

    while (upQueue.length > 0) {
      const cur = upQueue.shift()!;
      for (const prev of revAdj.get(cur) || []) {
        upstreamEdges.add(prev.edgeId);
        if (!visitedUp.has(prev.source)) {
          visitedUp.add(prev.source);
          if (prev.source !== rawOriginId) {
            upstreamNodes.add(prev.source);
          }
          upQueue.push(prev.source);
        }
      }
    }

    const downstreamNodes = new Set<string>();
    const downstreamEdges = new Set<string>();
    const downQueue: string[] = [rawOriginId];
    const visitedDown = new Set<string>([rawOriginId]);

    while (downQueue.length > 0) {
      const cur = downQueue.shift()!;
      for (const nxt of fwdAdj.get(cur) || []) {
        downstreamEdges.add(nxt.edgeId);
        if (!visitedDown.has(nxt.target)) {
          visitedDown.add(nxt.target);
          if (nxt.target !== rawOriginId) {
            downstreamNodes.add(nxt.target);
          }
          downQueue.push(nxt.target);
        }
      }
    }

    const originNode = nodes.find((n) => n.id === rawOriginId);
    const originName =
      originNode?.data?.filename ||
      originNode?.data?.name ||
      originNode?.data?.filepath ||
      rawOriginId;

    return {
      isActive: true,
      originId: rawOriginId,
      originName: String(originName),
      upstreamNodes,
      downstreamNodes,
      upstreamEdges,
      downstreamEdges,
    };
  }, [isBlastRadiusEnabled, lockedBlastNodeId, hoveredNodeId, nodes, layerFilteredEdges]);

  // Decorate nodes & edges with Blast-Radius roles & hover highlights without mutating base layout positions
  const displayNodes = useMemo<Node[]>(() => {
    if (!blastComputation.isActive) return nodes;
    return nodes.map((n) => {
      let blastRole: NodeBlastRole = "DIMMED";
      if (n.id === blastComputation.originId) {
        blastRole = "FOCUSED";
      } else if (blastComputation.upstreamNodes.has(n.id)) {
        blastRole = "UPSTREAM";
      } else if (blastComputation.downstreamNodes.has(n.id)) {
        blastRole = "DOWNSTREAM";
      }
      return {
        ...n,
        data: {
          ...n.data,
          blastRole,
        },
      };
    });
  }, [nodes, blastComputation]);

  const displayEdges = useMemo<Edge[]>(() => {
    return layerFilteredEdges.map((e) => {
      let blastState: EdgeBlastState = "NONE";
      if (blastComputation.isActive) {
        if (blastComputation.upstreamEdges.has(e.id)) {
          blastState = "UPSTREAM";
        } else if (blastComputation.downstreamEdges.has(e.id)) {
          blastState = "DOWNSTREAM";
        } else {
          blastState = "DIMMED";
        }
      }
      return {
        ...e,
        data: {
          ...e.data,
          blastState,
          isHovered: hoveredEdgeId === e.id,
        },
      };
    });
  }, [layerFilteredEdges, blastComputation, hoveredEdgeId]);

  const fitViewOnLoad = useCallback(
    (instance: any) => {
      setReactFlowInstance(instance);
      setTimeout(() => {
        instance.fitView({ padding: 0.2, duration: 500 });
      }, 100);
    },
    [setReactFlowInstance]
  );

  // Camera Helpers
  const handleZoomIn = () => reactFlowInstance?.zoomIn({ duration: 220 });
  const handleZoomOut = () => reactFlowInstance?.zoomOut({ duration: 220 });
  const handleFitAll = () => {
    reactFlowInstance?.fitView({
      padding: isGraphFullscreen ? 0.16 : 0.2,
      duration: 420,
    });
  };

  const handleCenterRoot = () => {
    if (!reactFlowInstance) return;
    const rootNode = nodes.find((n) => n.id === "dir:root");
    if (rootNode) {
      reactFlowInstance.setCenter(
        rootNode.position.x + 104,
        rootNode.position.y + 104,
        { zoom: 0.9, duration: 480 }
      );
    } else {
      handleFitAll();
    }
  };

  const handleFocusSelected = () => {
    if (!reactFlowInstance) return;
    const targetId =
      lockedBlastNodeId ||
      selectedGraphNodeId ||
      (activeFilepath ? `file:${activeFilepath}` : null);
    const matchNode = nodes.find((n) => n.id === targetId);
    if (matchNode) {
      reactFlowInstance.setCenter(
        matchNode.position.x + 115,
        matchNode.position.y + 62,
        { zoom: 1.3, duration: 450 }
      );
    } else {
      handleFitAll();
    }
  };

  // Focus camera on a specific step in the finding flow (works on both multi-node and synthesized 3-step flows)
  const focusTourStep = useCallback(
    (stepIndex: number) => {
      const flowSteps = activeFindingFlow?.nodes || [];
      if (flowSteps.length === 0) return;
      const clampedIdx = Math.max(0, Math.min(stepIndex, flowSteps.length - 1));
      setActiveTourStepIdx(clampedIdx);
      const stepNode = flowSteps[clampedIdx];
      if (!stepNode) return;
      selectGraphNode(stepNode);
      if (reactFlowInstance) {
        const rfNode = nodes.find((n) => String(n.id) === String(stepNode.id));
        if (rfNode) {
          reactFlowInstance.setCenter(
            rfNode.position.x + NODE_WIDTH / 2,
            rfNode.position.y + NODE_HEIGHT / 2,
            { zoom: 1.28, duration: 480 }
          );
        }
      }
    },
    [activeFindingFlow, nodes, reactFlowInstance, selectGraphNode]
  );

  // Auto-play presentation tour interval
  useEffect(() => {
    const total = activeFindingFlow?.nodes?.length || 0;
    if (!isAutoPlayingTour || total === 0) return;
    const interval = setInterval(() => {
      setActiveTourStepIdx((prev) => {
        const nextIdx = (prev + 1) % total;
        focusTourStep(nextIdx);
        return nextIdx;
      });
    }, 2500);
    return () => clearInterval(interval);
  }, [isAutoPlayingTour, activeFindingFlow, focusTourStep]);

  const handleCycleFinding = (delta: number) => {
    if (findings.length === 0) return;
    const curIdx = findings.findIndex((f) => f.id === selectedFinding?.id);
    const nextIdx =
      curIdx === -1
        ? 0
        : (curIdx + delta + findings.length) % findings.length;
    setGraphViewMode("FINDING_PATH");
    selectFinding(findings[nextIdx]);
  };

  const handleExpandOrCollapseAll = () => {
    if (!appTree) return;
    const anyCollapsed = Object.values(collapsedDirs).some(Boolean);
    if (anyCollapsed) {
      setCollapsedDirs({});
    } else {
      const next: Record<string, boolean> = {};
      const walk = (d: DirectoryTreeNode) => {
        if (d.path) next[d.path] = true;
        d.subdirectories.forEach(walk);
      };
      walk(appTree.tree);
      setCollapsedDirs(next);
    }
  };

  const handleTriggerAiExplain = () => {
    setAiDrawerOpen(true, "GRAPH");
    void explainCurrentGraphWithAi({
      view_mode: graphViewMode,
      finding_id: selectedFinding?.id ?? null,
    });
  };

  // Plain-English Flow Story Generator
  const plainEnglishStory = useMemo(() => {
    if (graphViewMode === "FINDING_PATH") {
      if (!selectedFinding || !activeFindingFlow) {
        return "Attack Path View: Select any finding in the left explorer to trace its source-to-sink data flow and BFL fix chokepoint.";
      }
      if (isCurrentFindingSevered) {
        return `Verified Severed Flow (${selectedFinding.cwe_id || selectedFinding.rule_id}): Surgical BFL patch neutralized reachability in ${basenameOf(lastAppliedPatch?.filepath)} — 0 active exploit paths remain.`;
      }
      const fNodes = activeFindingFlow.nodes;
      const srcN = fNodes[0];
      const bflN = fNodes.find((n) => n.is_bfl) || fNodes[Math.floor(fNodes.length / 2)] || srcN;
      const sinkN = fNodes[fNodes.length - 1] || bflN;
      const srcLoc = `${basenameOf(srcN?.filepath)}:${srcN?.start_line || 1}`;
      const bflLoc = `${basenameOf(bflN?.filepath)}:${bflN?.start_line || 1}`;
      const sinkName = sinkN?.name || selectedFinding.rule_id;
      const cweTag = selectedFinding.cwe_id ? ` (${selectedFinding.cwe_id})` : "";
      return `Attack Flow (${fNodes.length} steps): Input/context enters at ${srcLoc}, passes through BFL fix chokepoint ${bflLoc}, and reaches ${sinkName}${cweTag}.`;
    }

    if (graphViewMode === "APP_TREE") {
      const totalFiles = appTree?.total_files ?? nodes.length;
      const totalDirs = appTree?.total_directories ?? 1;
      const xCount = allCrossFileEdges.length;
      return `360° Architecture Map: ${totalFiles} files across ${totalDirs} folders with ${xCount} cross-file import/call dependencies. Click or hover any node to trace its upstream & downstream blast radius.`;
    }

    if (graphViewMode === "CALL_GRAPH") {
      return `Inter-Procedural Call Graph: ${nodes.length} caller/callee symbols linked by ${displayEdges.length} directional CALLS ▶ edges (${callGraphScope === "WHOLE_APP" ? "Whole Repository" : basenameOf(activeFilepath)}).`;
    }

    if (graphViewMode === "ENTRYPOINT_GRAPH") {
      return `Attack Surface Entrypoints: Traces exposed routes & handlers across ${nodes.length} nodes and ${displayEdges.length} directional hops into downstream execution sinks.`;
    }

    if (graphViewMode === "DFG_ONLY") {
      return `Data-Flow Graph (DFG): ${displayEdges.length} variable & taint propagation links (TAINT ▶) across ${nodes.length} statements${activeFilepath ? ` in ${basenameOf(activeFilepath)}` : ""}.`;
    }

    if (graphViewMode === "CFG_ONLY") {
      return `Control-Flow Graph (CFG): ${displayEdges.length} execution & branch transitions (TRUE ▶, FALSE ▶, LOOP ↺) across ${nodes.length} statements${activeFilepath ? ` in ${basenameOf(activeFilepath)}` : ""}.`;
    }

    return `Full Code Property Graph (CPG): Unified syntax (AST), control flow (CFG), and data flow (DFG) across ${nodes.length} nodes and ${displayEdges.length} directional edges.`;
  }, [
    graphViewMode,
    selectedFinding,
    activeFindingFlow,
    isCurrentFindingSevered,
    lastAppliedPatch,
    appTree,
    nodes.length,
    displayEdges.length,
    allCrossFileEdges.length,
    callGraphScope,
    activeFilepath,
  ]);

  // Compute SVG Spider Radar Chart Polygon Points
  const radarSize = 166;
  const radarCenter = radarSize / 2;
  const radarRadius = 56;
  const radarPolygonPoints = useMemo(() => {
    return radarMetrics
      .map((m, idx) => {
        const angle = -Math.PI / 2 + (idx * 2 * Math.PI) / radarMetrics.length;
        const r = m.ratio * radarRadius;
        const x = radarCenter + Math.cos(angle) * r;
        const y = radarCenter + Math.sin(angle) * r;
        return `${x},${y}`;
      })
      .join(" ");
  }, [radarMetrics, radarCenter, radarRadius]);

  // Associated findings for the currently inspected file
  const inspectedFileFindings = useMemo(() => {
    const fp = inspectedNodeData?.filepath;
    if (!fp) return [];
    return findings.filter((f) =>
      (f.path_nodes || []).some(
        (n) =>
          n.filepath === fp ||
          fp.endsWith(n.filepath || "") ||
          (n.filepath || "").endsWith(fp)
      )
    );
  }, [inspectedNodeData, findings]);

  const currentFindingIndex = useMemo(() => {
    if (!selectedFinding) return -1;
    return findings.findIndex((f) => f.id === selectedFinding.id);
  }, [findings, selectedFinding]);

  const activeTourNode = useMemo(() => {
    const pNodes = activeFindingFlow?.nodes || [];
    if (pNodes.length === 0) return null;
    return pNodes[Math.min(activeTourStepIdx, pNodes.length - 1)] || pNodes[0];
  }, [activeFindingFlow, activeTourStepIdx]);

  return (
    <div
      className={
        isGraphFullscreen
          ? "fixed inset-0 z-[100] w-screen h-screen bg-[#f8fafc] text-slate-900 flex flex-col select-none"
          : "flex flex-col h-full bg-[#f8fafc] text-slate-900 border-l border-slate-200"
      }
    >
      {/* EXECUTIVE FULL-SCREEN PRESENTATION HEADER BANNER (Light Mode) */}
      {isGraphFullscreen && (
        <div className="h-12 bg-white border-b border-slate-200 px-4 flex items-center justify-between gap-3 shrink-0 shadow-sm">
          <div className="flex items-center gap-3 min-w-0">
            <span className="px-2.5 py-1 rounded-md bg-cyan-700 text-white border border-cyan-800 font-mono text-[10px] font-extrabold uppercase tracking-wider flex items-center gap-1.5 shrink-0">
              <span className="w-2 h-2 rounded-full bg-white animate-pulse" />
              Full-Screen Presentation
            </span>
            <div className="flex items-center gap-2 text-xs font-mono truncate">
              <span className="text-slate-600">Target:</span>
              <span className="text-slate-900 font-bold truncate max-w-[260px]">
                {activeFilepath ||
                  projectPath.split(/[\\/]/).pop() ||
                  projectPath ||
                  "Workspace"}
              </span>
              <span className="text-slate-300">•</span>
              <span className="text-cyan-800 font-bold">
                {displayNodes.length} Nodes / {displayEdges.length} Flows
              </span>
            </div>
          </div>

          {findings.length > 0 && (
            <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200 rounded-lg px-2 py-1">
              <button
                type="button"
                onClick={() => handleCycleFinding(-1)}
                title="Previous Vulnerability Finding"
                className="p-1 rounded hover:bg-slate-200 text-slate-700 transition-colors"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <select
                value={selectedFinding?.id || ""}
                onChange={(e) => {
                  const found = findings.find((f) => f.id === e.target.value);
                  if (found) {
                    setGraphViewMode("FINDING_PATH");
                    selectFinding(found);
                  }
                }}
                className="bg-white text-slate-900 text-[11px] font-mono px-2 py-0.5 rounded border border-slate-300 max-w-[340px] focus:outline-none focus:border-cyan-600"
              >
                {findings.map((f, idx) => {
                  const sinkLn =
                    f.path_nodes?.[f.path_nodes.length - 1]?.start_line ||
                    f.best_fix_location?.line ||
                    1;
                  return (
                    <option key={f.id} value={f.id}>
                      #{idx + 1}/{findings.length} [{f.severity}] {f.title} (L
                      {sinkLn})
                    </option>
                  );
                })}
              </select>
              <button
                type="button"
                onClick={() => handleCycleFinding(1)}
                title="Next Vulnerability Finding"
                className="p-1 rounded hover:bg-slate-200 text-slate-700 transition-colors"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleExportGraphSnapshot}
              title="Download Current Graph Topology as JSON Snapshot"
              className="px-2.5 py-1 rounded-md bg-white hover:bg-slate-100 text-slate-800 border border-slate-300 text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-cyan-700" />
              <span>Export JSON</span>
            </button>
            <button
              type="button"
              onClick={handleToggleBrowserFullscreen}
              title="Toggle Native OS / Browser Fullscreen"
              className={`px-2.5 py-1 rounded-md border text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors ${
                isNativeFullscreen
                  ? "bg-cyan-700 text-white border-cyan-800"
                  : "bg-white hover:bg-slate-100 text-slate-800 border-slate-300"
              }`}
            >
              <Monitor className="w-3.5 h-3.5" />
              <span>{isNativeFullscreen ? "Exit OS Full" : "OS Fullscreen"}</span>
            </button>
            <button
              type="button"
              onClick={() => {
                if (document.fullscreenElement) {
                  document.exitFullscreen().catch(() => {});
                }
                setGraphFullscreen(false);
                setIsAutoPlayingTour(false);
              }}
              title="Exit Full-Screen Presentation Mode (Esc)"
              className="px-3 py-1 rounded-md bg-rose-700 hover:bg-rose-800 text-white border border-rose-800 text-xs font-bold flex items-center gap-1.5 transition-colors shadow-sm"
            >
              <Minimize2 className="w-3.5 h-3.5 text-white" />
              <span>Exit Full Screen (Esc)</span>
            </button>
          </div>
        </div>
      )}

      {/* CONSOLIDATED SINGLE-ROW GRAPH TOOLBAR + LAYERS & LAYOUT POPOVER */}
      <div className="bg-white border-b border-slate-200 px-2.5 py-1.5 flex items-center justify-between gap-2 flex-wrap text-xs shrink-0">
        {/* Left: All 7 Graph View Mode Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto">
          <div className="flex items-center gap-0.5 bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-[10.5px]">
            {(
              [
                {
                  mode: "FINDING_PATH",
                  label: "Attack Path",
                  tip: "Step-by-step directional source -> BFL chokepoint -> sink flow",
                },
                {
                  mode: "APP_TREE",
                  label: "360° App Map",
                  tip: "Interactive 360° spider & mind-map architecture with cross-file flows",
                },
                {
                  mode: "CALL_GRAPH",
                  label: "Call Graph",
                  tip: "Inter-procedural caller -> callee invocations (:CALLS)",
                },
                {
                  mode: "ENTRYPOINT_GRAPH",
                  label: "Entrypoints",
                  tip: "Exposed HTTP/CLI entrypoints -> handlers -> downstream sinks",
                },
                {
                  mode: "DFG_ONLY",
                  label: "Data Flow (DFG)",
                  tip: "Variable and taint propagation edges (:DFG_FLOWS_TO)",
                },
                {
                  mode: "CFG_ONLY",
                  label: "Control Flow (CFG)",
                  tip: "Execution order, True/False branches & loop back-edges",
                },
                {
                  mode: "FULL_CPG",
                  label: "Full CPG",
                  tip: "Combined AST + CFG + DFG Code Property Graph",
                },
              ] as { mode: GraphViewMode; label: string; tip: string }[]
            ).map((item) => {
              const active = graphViewMode === item.mode;
              return (
                <button
                  key={item.mode}
                  type="button"
                  onClick={() => setGraphViewMode(item.mode)}
                  title={item.tip}
                  className={`px-2 py-1 rounded-md font-mono whitespace-nowrap transition-all ${
                    active
                      ? "bg-cyan-700 text-white border border-cyan-800 font-bold shadow-sm"
                      : "text-slate-700 hover:text-slate-900 hover:bg-white"
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Center/Right: Contextual Quick Chips + Layers & Layout Popover + Camera Controls */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {graphViewMode === "APP_TREE" ? (
            <>
              {/* Quick Layout Pill (360° Spider / Mind-Map / Hierarchy) */}
              <div className="flex items-center gap-0.5 bg-slate-100 p-0.5 rounded-lg border border-slate-200 font-mono text-[10px]">
                {(
                  [
                    { id: "SPIDER_WEB", label: "360° Spider" },
                    { id: "MIND_MAP", label: "Mind-Map" },
                    { id: "HIERARCHY", label: "TB" },
                  ] as { id: AppTreeLayoutStyle; label: string }[]
                ).map((ly) => (
                  <button
                    key={ly.id}
                    type="button"
                    onClick={() => setTreeLayoutStyle(ly.id)}
                    className={`px-2 py-0.5 rounded transition-all ${
                      treeLayoutStyle === ly.id
                        ? "bg-sky-700 text-white font-bold"
                        : "text-slate-700 hover:text-slate-900"
                    }`}
                  >
                    {ly.label}
                  </button>
                ))}
              </div>

              {/* Cross-File Flows Toggle Chip (Enabled by Default) */}
              <button
                type="button"
                onClick={() => setShowCrossFileFlows((prev) => !prev)}
                title="Toggle cross-file IMPORTS / CALLS dependency arcs across repository files"
                className={`px-2.5 py-1 rounded-lg border font-mono text-[10px] font-extrabold flex items-center gap-1 transition-all ${
                  showCrossFileFlows
                    ? "bg-violet-700 text-white border-violet-800 shadow-sm"
                    : "bg-white text-slate-700 border-slate-300 hover:bg-slate-50"
                }`}
              >
                <GitBranch className="w-3 h-3" />
                <span>Cross-File Flows ({allCrossFileEdges.length})</span>
              </button>

              {/* Compact Spotlight Search */}
              <div className="relative w-36 sm:w-44">
                <Search className="w-3 h-3 absolute left-2 top-1.5 text-slate-500" />
                <input
                  type="text"
                  value={spiderSearch}
                  onChange={(e) => setSpiderSearch(e.target.value)}
                  placeholder="Filter file/symbol..."
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg pl-6 pr-5 py-0.5 text-[11px] text-slate-900 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-600 focus:bg-white"
                />
                {spiderSearch && (
                  <button
                    type="button"
                    onClick={() => setSpiderSearch("")}
                    className="absolute right-1.5 top-1 text-slate-500 hover:text-slate-800"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
            </>
          ) : (
            <>
              {/* Quick LR / TB Orientation Toggle */}
              <div className="flex items-center gap-0.5 bg-slate-100 p-0.5 rounded-lg border border-slate-200 font-mono text-[10px]">
                <button
                  type="button"
                  onClick={() => setCpgLayoutDirection("LR")}
                  title="Left-to-Right Horizontal Flow"
                  className={`px-2 py-0.5 rounded flex items-center gap-0.5 transition-all ${
                    cpgLayoutDirection === "LR"
                      ? "bg-sky-700 text-white font-bold"
                      : "text-slate-700 hover:text-slate-900"
                  }`}
                >
                  <ArrowRight className="w-3 h-3" />
                  <span>LR</span>
                </button>
                <button
                  type="button"
                  onClick={() => setCpgLayoutDirection("TB")}
                  title="Top-to-Bottom Vertical Flow"
                  className={`px-2 py-0.5 rounded flex items-center gap-0.5 transition-all ${
                    cpgLayoutDirection === "TB"
                      ? "bg-sky-700 text-white font-bold"
                      : "text-slate-700 hover:text-slate-900"
                  }`}
                >
                  <ArrowDown className="w-3 h-3" />
                  <span>TB</span>
                </button>
              </div>

              {graphViewMode === "CALL_GRAPH" && (
                <button
                  type="button"
                  onClick={() =>
                    setCallGraphScope((s) =>
                      s === "WHOLE_APP" ? "CURRENT_FILE" : "WHOLE_APP"
                    )
                  }
                  title="Switch Call Graph scope between whole application and active file"
                  className="px-2 py-1 rounded-lg border border-slate-300 bg-slate-50 hover:bg-slate-100 text-slate-800 font-mono text-[10px] font-bold"
                >
                  {callGraphScope === "WHOLE_APP"
                    ? "Scope: Whole App"
                    : `Scope: ${basenameOf(activeFilepath)}`}
                </button>
              )}
            </>
          )}

          {/* Consolidated Layers & Layout ▾ Popover */}
          <div className="relative" ref={popoverRef}>
            <button
              type="button"
              onClick={() => setShowLayersPopover((p) => !p)}
              className={`px-2.5 py-1 rounded-lg border font-mono text-[10px] font-bold flex items-center gap-1 transition-colors ${
                showLayersPopover
                  ? "bg-slate-200 text-slate-900 border-slate-400"
                  : "bg-white hover:bg-slate-50 text-slate-800 border-slate-300"
              }`}
            >
              <Layers className="w-3 h-3 text-cyan-700" />
              <span>Layers &amp; Layout</span>
              <ChevronDown className="w-3 h-3 text-slate-600" />
            </button>

            {showLayersPopover && (
              <div className="absolute right-0 mt-1.5 w-72 rounded-xl border border-slate-300 bg-white shadow-xl p-3 z-50 space-y-3 text-[11px] select-none">
                <div className="flex items-center justify-between border-b border-slate-200 pb-1.5">
                  <span className="font-mono font-extrabold text-slate-900 uppercase text-[10px] tracking-wider">
                    Graph Layers &amp; Layout Controls
                  </span>
                  <button
                    type="button"
                    onClick={() => setShowLayersPopover(false)}
                    className="text-slate-500 hover:text-slate-800"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* Layout Section */}
                {graphViewMode === "APP_TREE" ? (
                  <div className="space-y-2">
                    <div className="text-[10px] font-mono font-bold text-slate-600 uppercase">
                      360° Ring Declutter Mode
                    </div>
                    <div className="grid grid-cols-3 gap-1 font-mono text-[10px]">
                      {(
                        [
                          { id: "SMART_SIMPLIFIED", label: "Smart" },
                          { id: "VULNERABLE_ONLY", label: "Flaws Only" },
                          { id: "FULL_EXPANDED", label: "All Files" },
                        ] as const
                      ).map((dm) => (
                        <button
                          key={dm.id}
                          type="button"
                          onClick={() => setSpiderDeclutterMode(dm.id)}
                          className={`px-1.5 py-1 rounded border font-bold ${
                            spiderDeclutterMode === dm.id
                              ? "bg-amber-700 text-white border-amber-800"
                              : "bg-slate-50 text-slate-700 border-slate-300 hover:bg-slate-100"
                          }`}
                        >
                          {dm.label}
                        </button>
                      ))}
                    </div>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={handleExpandOrCollapseAll}
                        className="flex-1 px-2 py-1 rounded border border-slate-300 bg-slate-50 hover:bg-slate-100 text-slate-800 font-mono text-[10px] font-bold flex items-center justify-center gap-1"
                      >
                        <FolderTree className="w-3 h-3 text-cyan-700" />
                        <span>Fold / Unfold Folders</span>
                      </button>
                      <button
                        type="button"
                        onClick={handleCenterRoot}
                        className="px-2 py-1 rounded border border-slate-300 bg-slate-50 hover:bg-slate-100 text-slate-800 font-mono text-[10px] font-bold flex items-center gap-1"
                      >
                        <Compass className="w-3 h-3 text-emerald-700" />
                        <span>Hub</span>
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    <div className="text-[10px] font-mono font-bold text-slate-600 uppercase">
                      Flow Orientation
                    </div>
                    <div className="grid grid-cols-2 gap-1.5 font-mono text-[10px]">
                      <button
                        type="button"
                        onClick={() => setCpgLayoutDirection("LR")}
                        className={`px-2 py-1 rounded border font-bold flex items-center justify-center gap-1 ${
                          cpgLayoutDirection === "LR"
                            ? "bg-cyan-700 text-white border-cyan-800"
                            : "bg-slate-50 text-slate-700 border-slate-300"
                        }`}
                      >
                        <ArrowRight className="w-3 h-3" /> Left-Right (LR)
                      </button>
                      <button
                        type="button"
                        onClick={() => setCpgLayoutDirection("TB")}
                        className={`px-2 py-1 rounded border font-bold flex items-center justify-center gap-1 ${
                          cpgLayoutDirection === "TB"
                            ? "bg-cyan-700 text-white border-cyan-800"
                            : "bg-slate-50 text-slate-700 border-slate-300"
                        }`}
                      >
                        <ArrowDown className="w-3 h-3" /> Top-Down (TB)
                      </button>
                    </div>
                  </div>
                )}

                {/* Edge Layer Visibility Toggles */}
                <div className="space-y-1.5 pt-2 border-t border-slate-200">
                  <div className="text-[10px] font-mono font-bold text-slate-600 uppercase">
                    Directional Edge Layers
                  </div>
                  <div className="grid grid-cols-2 gap-1.5 text-[10.5px] font-mono">
                    {(
                      [
                        { key: "dfg", label: "Data / Taint ▶", dot: "bg-rose-600" },
                        { key: "cfg", label: "Control / CFG ▶", dot: "bg-cyan-600" },
                        { key: "calls", label: "Calls & Imports ▶", dot: "bg-violet-600" },
                        { key: "ast", label: "Tree / AST ▶", dot: "bg-emerald-600" },
                      ] as const
                    ).map((ly) => {
                      const on = edgeLayers[ly.key];
                      return (
                        <button
                          key={ly.key}
                          type="button"
                          onClick={() =>
                            setEdgeLayers((prev) => ({
                              ...prev,
                              [ly.key]: !prev[ly.key],
                            }))
                          }
                          className={`px-2 py-1 rounded border text-left flex items-center gap-1.5 transition-colors ${
                            on
                              ? "bg-slate-100 text-slate-900 border-slate-400 font-bold"
                              : "bg-white text-slate-500 border-slate-200 line-through"
                          }`}
                        >
                          <span className={`w-2 h-2 rounded-full ${ly.dot} shrink-0`} />
                          <span className="truncate">{ly.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Interactive Overlays */}
                <div className="space-y-1.5 pt-2 border-t border-slate-200">
                  <div className="text-[10px] font-mono font-bold text-slate-600 uppercase">
                    Interactive Overlays
                  </div>
                  <div className="flex flex-wrap gap-1.5 font-mono text-[10px]">
                    <button
                      type="button"
                      onClick={() => setIsBlastRadiusEnabled((p) => !p)}
                      className={`px-2 py-1 rounded border font-bold ${
                        isBlastRadiusEnabled
                          ? "bg-indigo-700 text-white border-indigo-800"
                          : "bg-slate-50 text-slate-700 border-slate-300"
                      }`}
                    >
                      🎯 Blast Radius: {isBlastRadiusEnabled ? "ON" : "OFF"}
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowMiniMap((p) => !p)}
                      className={`px-2 py-1 rounded border font-bold flex items-center gap-1 ${
                        showMiniMap
                          ? "bg-sky-700 text-white border-sky-800"
                          : "bg-slate-50 text-slate-700 border-slate-300"
                      }`}
                    >
                      <MapIcon className="w-3 h-3" /> MiniMap
                    </button>
                    {graphViewMode === "APP_TREE" && (
                      <button
                        type="button"
                        onClick={() => setShowRadarChart((p) => !p)}
                        className={`px-2 py-1 rounded border font-bold flex items-center gap-1 ${
                          showRadarChart
                            ? "bg-cyan-700 text-white border-cyan-800"
                            : "bg-slate-50 text-slate-700 border-slate-300"
                        }`}
                      >
                        <Radar className="w-3 h-3" /> Radar
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={handleExportGraphSnapshot}
                      className="px-2 py-1 rounded border border-slate-300 bg-slate-50 hover:bg-slate-100 text-slate-800 font-bold flex items-center gap-1"
                    >
                      <Download className="w-3 h-3 text-cyan-700" /> Export JSON
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Camera Zoom / Fit / Focus / Fullscreen Cluster */}
          <div className="flex items-center gap-0.5 bg-slate-100 p-0.5 rounded-lg border border-slate-200 font-mono text-[10px]">
            <button
              type="button"
              onClick={handleZoomIn}
              title="Zoom In (+)"
              className="p-1 rounded hover:bg-white text-slate-700 hover:text-slate-900"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleZoomOut}
              title="Zoom Out (-)"
              className="p-1 rounded hover:bg-white text-slate-700 hover:text-slate-900"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleFitAll}
              title="Fit Entire Graph in Viewport"
              className="px-1.5 py-0.5 rounded hover:bg-white text-slate-800 font-bold"
            >
              Fit
            </button>
            <button
              type="button"
              onClick={handleFocusSelected}
              title="Zoom Camera to Active Node"
              className="p-1 rounded hover:bg-white text-amber-800"
            >
              <Crosshair className="w-3.5 h-3.5" />
            </button>
          </div>

          <button
            type="button"
            onClick={() => setGraphFullscreen(!isGraphFullscreen)}
            title={
              isGraphFullscreen
                ? "Exit Full-Screen Presentation View (Esc)"
                : "Expand Graph to Full-Screen Presentation View"
            }
            className={`px-2 py-1 rounded-lg font-mono text-[10px] font-bold flex items-center gap-1 border shrink-0 transition-all ${
              isGraphFullscreen
                ? "bg-amber-700 text-white border-amber-800"
                : "bg-white hover:bg-slate-50 text-slate-800 border-slate-300"
            }`}
          >
            {isGraphFullscreen ? (
              <>
                <Minimize2 className="w-3 h-3" />
                <span>Split</span>
              </>
            ) : (
              <>
                <Maximize2 className="w-3 h-3 text-cyan-700" />
                <span>Full</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* PLAIN-ENGLISH FLOW STORY BAR + STEP CHIPS + BLAST RADIUS PILL + AI EXPLAIN FLOW */}
      <div className="bg-slate-50 border-b border-slate-200 px-3 py-1.5 flex items-center justify-between gap-2 flex-wrap text-xs shrink-0">
        <div className="flex items-center gap-2 min-w-0 flex-1 flex-wrap">
          <span className="px-1.5 py-0.5 rounded bg-cyan-50 text-cyan-900 border border-cyan-300 font-mono text-[9.5px] font-extrabold uppercase tracking-wider shrink-0">
            Flow Story
          </span>
          <p className="text-[11.5px] text-slate-800 font-medium leading-snug">
            {plainEnglishStory}
          </p>

          {/* Clickable Step Chips (① → ② → ③) in FINDING_PATH mode */}
          {graphViewMode === "FINDING_PATH" &&
            activeFindingFlow &&
            activeFindingFlow.nodes.length > 0 && (
              <div className="flex items-center gap-1 flex-wrap ml-1">
                {activeFindingFlow.nodes.map((stepNode, idx) => {
                  const total = activeFindingFlow.nodes.length;
                  const roleShort =
                    idx === 0
                      ? "Origin"
                      : stepNode.is_bfl
                      ? "BFL"
                      : idx === total - 1
                      ? "Impact"
                      : `Step ${idx + 1}`;
                  const isActive = idx === activeTourStepIdx;
                  return (
                    <React.Fragment key={`${stepNode.id}-${idx}`}>
                      {idx > 0 && (
                        <span className="text-slate-400 font-mono text-[10px]">
                          →
                        </span>
                      )}
                      <button
                        type="button"
                        onClick={() => focusTourStep(idx)}
                        title={`${stepNode.name} (${stepNode.filepath}:L${stepNode.start_line})`}
                        className={`px-2 py-0.5 rounded-full font-mono text-[10px] font-extrabold border transition-all ${
                          isActive
                            ? stepNode.is_bfl
                              ? "bg-amber-700 text-white border-amber-800 shadow-sm"
                              : stepNode.is_sink
                              ? "bg-rose-700 text-white border-rose-800 shadow-sm"
                              : "bg-cyan-700 text-white border-cyan-800 shadow-sm"
                            : "bg-white text-slate-800 border-slate-300 hover:border-slate-500"
                        }`}
                      >
                        {formatCircledStep(idx + 1)} {roleShort}
                      </button>
                    </React.Fragment>
                  );
                })}
                <button
                  type="button"
                  onClick={() => setIsAutoPlayingTour((p) => !p)}
                  title="Auto-step camera through each flow node"
                  className={`ml-1 px-2 py-0.5 rounded-full border font-mono text-[10px] font-bold flex items-center gap-1 ${
                    isAutoPlayingTour
                      ? "bg-amber-700 text-white border-amber-800"
                      : "bg-white hover:bg-slate-100 text-slate-800 border-slate-300"
                  }`}
                >
                  {isAutoPlayingTour ? (
                    <>
                      <Pause className="w-2.5 h-2.5" /> Pause
                    </>
                  ) : (
                    <>
                      <Play className="w-2.5 h-2.5 fill-current" /> Tour
                    </>
                  )}
                </button>
              </div>
            )}
        </div>

        {/* Right: Blast-Radius Status & Clear Focus + Legend + ✨ AI Explain Flow */}
        <div className="flex items-center gap-1.5 shrink-0 flex-wrap">
          {blastComputation.isActive && (
            <div className="flex items-center gap-1.5 bg-white border border-indigo-300 rounded-full px-2.5 py-0.5 text-[10px] font-mono shadow-sm">
              <span className="font-extrabold text-indigo-900 truncate max-w-[120px]">
                🎯 {blastComputation.originName}
              </span>
              <span className="text-sky-800 font-bold">
                ⬆{blastComputation.upstreamNodes.size} Up
              </span>
              <span className="text-rose-800 font-bold">
                ⬇{blastComputation.downstreamNodes.size} Down
              </span>
              <button
                type="button"
                onClick={() => {
                  setLockedBlastNodeId(null);
                  setHoveredNodeId(null);
                }}
                className="ml-0.5 px-1.5 py-0.2 rounded-full bg-rose-700 hover:bg-rose-800 text-white font-extrabold flex items-center gap-0.5"
                title="Clear Blast-Radius Focus (Esc)"
              >
                <X className="w-2.5 h-2.5 text-white" />
                <span>Clear Focus</span>
              </button>
            </div>
          )}

          <button
            type="button"
            onClick={() => setShowLegend((prev) => !prev)}
            title="Toggle Visual Color & Directional Edge Legend"
            className={`px-2 py-1 rounded-lg border font-mono text-[10px] font-bold flex items-center gap-1 transition-colors ${
              showLegend
                ? "bg-cyan-700 text-white border-cyan-800"
                : "bg-white hover:bg-slate-100 text-slate-800 border-slate-300"
            }`}
          >
            <Info className="w-3 h-3" />
            <span>Legend</span>
          </button>

          <button
            type="button"
            onClick={handleTriggerAiExplain}
            disabled={displayNodes.length === 0}
            title="Generate a Plain-English AI Walkthrough of the current graph flow"
            className="px-2.5 py-1 rounded-lg bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white border border-indigo-800 font-mono text-[10.5px] font-extrabold flex items-center gap-1 shadow-sm transition-colors"
          >
            {aiIsBusy ? (
              <Loader2 className="w-3 h-3 text-white animate-spin" />
            ) : (
              <Sparkles className="w-3 h-3 text-white" />
            )}
            <span>✨ AI Explain Flow</span>
          </button>
        </div>
      </div>

      {/* ReactFlow Light Daylight Canvas (#f8fafc) */}
      <div className="flex-1 w-full h-full relative overflow-hidden bg-[#f8fafc]">
        {/* FLOATING EMERALD "✓ THREAD SEVERED · 0 REACHABLE PATHS" VERIFICATION SEAL */}
        {lastAppliedPatch && lastAppliedPatch.verifiedSevered && (
          <div className="absolute top-3 left-1/2 -translate-x-1/2 z-30 max-w-[92%] rounded-xl border-[1.5px] border-emerald-500 bg-emerald-50/95 backdrop-blur-md px-3.5 py-2 shadow-lg flex items-center justify-between gap-3 text-xs transition-all duration-300 select-none">
            <div className="flex items-center gap-2 min-w-0 flex-wrap">
              <span className="px-2 py-0.5 rounded bg-emerald-700 text-white border border-emerald-800 font-mono text-[10px] font-extrabold tracking-wider flex items-center gap-1 shrink-0">
                <ShieldCheck className="w-3.5 h-3.5 text-white" />
                ✓ THREAD SEVERED · 0 REACHABLE PATHS
              </span>
              <span className="font-mono text-[11px] text-emerald-950 truncate">
                CPG Verified Neutralized in{" "}
                <strong className="font-extrabold">
                  {lastAppliedPatch.filepath}
                </strong>
              </span>
              <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-white border border-emerald-300 text-emerald-900 font-bold">
                patch:{lastAppliedPatch.patchId}
              </span>
            </div>

            <button
              type="button"
              disabled={isApplyingPatch}
              onClick={() => undoLastRemediationPatch()}
              title="Restore exact pre-patch file bytes and re-verify CPG"
              className="px-2.5 py-1 rounded-lg bg-white hover:bg-emerald-100 disabled:opacity-50 text-emerald-900 border border-emerald-500 font-mono text-[10px] font-extrabold flex items-center gap-1 shrink-0 transition-colors"
            >
              <RotateCcw className="w-3 h-3 text-emerald-700" />
              <span>{isApplyingPatch ? "Restoring..." : "Undo Patch"}</span>
            </button>
          </div>
        )}

        {displayNodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none z-10 text-slate-600">
            {lastAppliedPatch && lastAppliedPatch.verifiedSevered ? (
              <>
                <ShieldCheck className="w-11 h-11 mb-3 text-emerald-700" />
                <p className="text-sm font-extrabold text-emerald-900 font-mono">
                  ✓ THREAD SEVERED · 0 REACHABLE PATHS IN CPG
                </p>
                <p className="text-xs text-slate-600 mt-1 max-w-md text-center">
                  The surgical BFL chokepoint patch in{" "}
                  <span className="font-mono font-bold text-emerald-800">
                    {lastAppliedPatch.filepath}
                  </span>{" "}
                  eliminated all source-to-sink attack paths.
                </p>
              </>
            ) : (
              <>
                <Layers className="w-10 h-10 mb-3 text-slate-400" />
                <p className="text-sm font-bold text-slate-700">
                  {graphViewMode === "FINDING_PATH"
                    ? "Select a vulnerability from the sidebar to inspect its directional flow"
                    : "No graph nodes available for this view"}
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  {graphViewMode === "FINDING_PATH"
                    ? "Source -> BFL Chokepoint -> Sink AST/DFG nodes will render here with perimeter arrowheads"
                    : "Switch view mode or select a scanned file to inspect its CPG topology"}
                </p>
              </>
            )}
          </div>
        )}

        {/* FLOATING 6-AXIS SPIDER RADAR CHART WIDGET (Light Mode) */}
        {graphViewMode === "APP_TREE" && showRadarChart && appTree && (
          <div className="absolute top-3 left-3 z-20 w-56 rounded-xl border border-slate-300 bg-white/95 backdrop-blur-md p-2.5 shadow-lg select-none">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-cyan-800 flex items-center gap-1">
                <Radar className="w-3 h-3 text-cyan-700" />
                Spider Radar Profile
              </span>
              {categoryFilter !== "ALL" && (
                <button
                  type="button"
                  onClick={() => setCategoryFilter("ALL")}
                  className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded bg-cyan-50 text-cyan-900 border border-cyan-300 hover:bg-cyan-100"
                >
                  Reset
                </button>
              )}
            </div>

            <div className="flex items-center justify-center">
              <svg width={radarSize} height={radarSize} className="overflow-visible">
                {[0.33, 0.66, 1.0].map((level) => {
                  const ringPts = radarMetrics
                    .map((_, idx) => {
                      const angle =
                        -Math.PI / 2 + (idx * 2 * Math.PI) / radarMetrics.length;
                      const r = level * radarRadius;
                      return `${radarCenter + Math.cos(angle) * r},${
                        radarCenter + Math.sin(angle) * r
                      }`;
                    })
                    .join(" ");
                  return (
                    <polygon
                      key={level}
                      points={ringPts}
                      fill="none"
                      stroke="#cbd5e1"
                      strokeWidth="1"
                      strokeDasharray={level < 1 ? "2 2" : undefined}
                    />
                  );
                })}

                {radarMetrics.map((m, idx) => {
                  const angle =
                    -Math.PI / 2 + (idx * 2 * Math.PI) / radarMetrics.length;
                  const x2 = radarCenter + Math.cos(angle) * radarRadius;
                  const y2 = radarCenter + Math.sin(angle) * radarRadius;
                  const lx = radarCenter + Math.cos(angle) * (radarRadius + 20);
                  const ly = radarCenter + Math.sin(angle) * (radarRadius + 16);
                  const isActiveAxis = categoryFilter === m.categoryKey;

                  return (
                    <g
                      key={m.axis}
                      onClick={() =>
                        setCategoryFilter((prev) =>
                          prev === m.categoryKey ? "ALL" : m.categoryKey
                        )
                      }
                      className="cursor-pointer group"
                    >
                      <line
                        x1={radarCenter}
                        y1={radarCenter}
                        x2={x2}
                        y2={y2}
                        stroke={isActiveAxis ? "#0e7490" : "#94a3b8"}
                        strokeWidth={isActiveAxis ? "1.8" : "1"}
                      />
                      <text
                        x={lx}
                        y={ly}
                        textAnchor="middle"
                        dominantBaseline="middle"
                        className={`text-[8.5px] font-mono fill-current transition-colors ${
                          isActiveAxis
                            ? "text-cyan-900 font-extrabold"
                            : "text-slate-700 group-hover:text-cyan-800"
                        }`}
                      >
                        {m.axis} ({m.raw})
                      </text>
                    </g>
                  );
                })}

                <polygon
                  points={radarPolygonPoints}
                  fill="rgba(14, 116, 144, 0.16)"
                  stroke="#0e7490"
                  strokeWidth="2"
                />

                {radarMetrics.map((m, idx) => {
                  const angle =
                    -Math.PI / 2 + (idx * 2 * Math.PI) / radarMetrics.length;
                  const r = m.ratio * radarRadius;
                  const vx = radarCenter + Math.cos(angle) * r;
                  const vy = radarCenter + Math.sin(angle) * r;
                  return (
                    <circle
                      key={m.axis}
                      cx={vx}
                      cy={vy}
                      r={3.5}
                      fill={
                        m.axis === "Flaws" && m.raw > 0 ? "#be123c" : "#0e7490"
                      }
                      stroke="#ffffff"
                      strokeWidth="1.5"
                      onClick={() =>
                        setCategoryFilter((prev) =>
                          prev === m.categoryKey ? "ALL" : m.categoryKey
                        )
                      }
                      className="cursor-pointer"
                    />
                  );
                })}
              </svg>
            </div>
            <p className="text-[9px] font-mono text-slate-500 text-center">
              Click any axis to spotlight category nodes
            </p>
          </div>
        )}

        {/* FLOATING LIGHT-MODE VISUAL GRAPH & DIRECTIONAL LEGEND OVERLAY */}
        {showLegend && (
          <div className="absolute top-3 right-3 z-20 w-72 rounded-xl border border-slate-300 bg-white/95 backdrop-blur-md p-3 shadow-xl select-none text-[10px] font-mono space-y-2">
            <div className="flex items-center justify-between border-b border-slate-200 pb-1.5">
              <span className="text-slate-900 font-extrabold uppercase tracking-wider flex items-center gap-1">
                <Info className="w-3.5 h-3.5 text-cyan-700" />
                Directional Graph Legend
              </span>
              <button
                type="button"
                onClick={() => setShowLegend(false)}
                className="text-slate-500 hover:text-slate-800"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-1">
              <div className="text-[9px] text-slate-500 uppercase font-extrabold">
                Semantic Node Roles
              </div>
              <div className="flex items-center gap-2 text-slate-800">
                <span className="px-1.5 py-0.2 rounded bg-cyan-700 text-white text-[8.5px] font-bold">
                  SOURCE
                </span>
                <span>Untrusted Input / Origin</span>
              </div>
              <div className="flex items-center gap-2 text-slate-800">
                <span className="px-1.5 py-0.2 rounded bg-amber-700 text-white text-[8.5px] font-bold">
                  BFL CHOKEPOINT
                </span>
                <span>Best Single-Point Fix Location</span>
              </div>
              <div className="flex items-center gap-2 text-slate-800">
                <span className="px-1.5 py-0.2 rounded bg-rose-700 text-white text-[8.5px] font-bold">
                  SINK
                </span>
                <span>Vulnerable Execution / Impact</span>
              </div>
              <div className="flex items-center gap-2 text-slate-800">
                <span className="px-1.5 py-0.2 rounded bg-emerald-700 text-white text-[8.5px] font-bold">
                  SANITIZER
                </span>
                <span>Guarded / Verified Severed</span>
              </div>
            </div>

            <div className="space-y-1 pt-1.5 border-t border-slate-200">
              <div className="text-[9px] text-slate-500 uppercase font-extrabold">
                Directional Flow Edges (Source ──▶ Target)
              </div>
              <div className="flex items-center gap-2 text-slate-800">
                <span className="w-5 h-0.5 border-b-2 border-dashed border-rose-600 shrink-0" />
                <span>TAINT / EXEC SINK ▶ (Animated DFG)</span>
              </div>
              <div className="flex items-center gap-2 text-slate-800">
                <span className="w-5 h-0.5 border-b-2 border-dashed border-violet-700 shrink-0" />
                <span>IMPORTS ▶ (Cross-File Dependency)</span>
              </div>
              <div className="flex items-center gap-2 text-slate-800">
                <span className="w-5 h-0.5 bg-amber-700 shrink-0" />
                <span>CALLS ▶ (Function Invocation)</span>
              </div>
              <div className="flex items-center gap-2 text-slate-800">
                <span className="w-5 h-0.5 bg-sky-700 shrink-0" />
                <span>⬆ Upstream / ⬇ Downstream Blast</span>
              </div>
            </div>
          </div>
        )}

        {/* FLOATING REFERENCE & SYMBOL INSPECTOR DRAWER (Light Mode in APP_TREE) */}
        {graphViewMode === "APP_TREE" && inspectedNodeData && (
          <div className="absolute bottom-3 right-3 z-20 w-80 max-h-[65%] flex flex-col rounded-xl border border-slate-300 bg-white/95 backdrop-blur-md shadow-xl overflow-hidden select-none">
            <div className="px-3 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 truncate">
                <GitBranch className="w-3.5 h-3.5 text-cyan-700 shrink-0" />
                <span className="text-xs font-mono font-extrabold text-slate-900 truncate">
                  {inspectedNodeData.filename ||
                    inspectedNodeData.name ||
                    inspectedNodeData.filepath ||
                    "Node Reference"}
                </span>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  type="button"
                  onClick={() => {
                    const refStr = inspectedNodeData.filepath
                      ? `${inspectedNodeData.filepath}:L${
                          inspectedNodeData.line_number ||
                          inspectedNodeData.start_line ||
                          1
                        } (${
                          inspectedNodeData.signature ||
                          inspectedNodeData.category ||
                          "FILE"
                        })`
                      : `${inspectedNodeData.path || "root"} (${
                          inspectedNodeData.purpose || "Directory"
                        })`;
                    handleCopyReference(refStr, "main-ref");
                  }}
                  className="px-1.5 py-0.5 rounded bg-cyan-50 hover:bg-cyan-100 text-cyan-900 border border-cyan-300 text-[10px] font-mono font-bold flex items-center gap-1"
                  title="Copy full file/symbol reference string"
                >
                  {copiedRefText === "main-ref" ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-700" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Get Ref</span>
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => setInspectedNodeData(null)}
                  className="p-0.5 text-slate-500 hover:text-slate-800"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            <div className="p-3 overflow-y-auto space-y-2.5 text-xs">
              <div className="space-y-1">
                {inspectedNodeData.filepath && (
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-700 bg-slate-100 px-2 py-1 rounded border border-slate-200">
                    <span className="truncate" title={inspectedNodeData.filepath}>
                      {inspectedNodeData.filepath}
                    </span>
                    {inspectedNodeData.line_count && (
                      <span className="text-cyan-800 font-bold shrink-0 ml-2">
                        {inspectedNodeData.line_count} LOC
                      </span>
                    )}
                  </div>
                )}
                <p className="text-[11px] text-slate-700 leading-relaxed">
                  {inspectedNodeData.purpose ||
                    inspectedNodeData.details ||
                    inspectedNodeData.signature}
                </p>
              </div>

              {inspectedNodeData.elements &&
                inspectedNodeData.elements.length > 0 && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-600 font-bold">
                      <span>
                        DECLARED SYMBOLS ({inspectedNodeData.elements.length})
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          handleToggleFileElements(inspectedNodeData.filepath)
                        }
                        className="text-amber-800 hover:underline"
                      >
                        {expandedFileElements[inspectedNodeData.filepath]
                          ? "Hide on Map"
                          : "Pin to Map"}
                      </button>
                    </div>
                    <div className="space-y-1 max-h-40 overflow-y-auto pr-1">
                      {inspectedNodeData.elements.map(
                        (el: DiscoveredElement, i: number) => (
                          <div
                            key={`${el.name}-${i}`}
                            onClick={() => {
                              if (inspectedNodeData.filepath) {
                                useAuditStore.setState({
                                  activeFilepath: inspectedNodeData.filepath,
                                  activeStartLine: el.line_number || 1,
                                  activeEndLine: el.line_number || 1,
                                });
                                void useAuditStore
                                  .getState()
                                  .selectCodeLine(
                                    inspectedNodeData.filepath,
                                    el.line_number || 1
                                  );
                              }
                            }}
                            className="group flex items-center justify-between gap-1.5 px-2 py-1 rounded bg-slate-50 hover:bg-cyan-50 border border-slate-200 hover:border-cyan-400 cursor-pointer font-mono text-[10px]"
                          >
                            <div className="flex items-center gap-1.5 truncate">
                              <span className="px-1 py-0.2 rounded bg-amber-50 text-amber-900 border border-amber-300 text-[8.5px] font-extrabold">
                                {el.element_type.slice(0, 5)}
                              </span>
                              <span className="text-slate-900 font-semibold truncate">
                                {el.name}
                              </span>
                            </div>
                            <div className="flex items-center gap-1.5 shrink-0">
                              <span className="text-cyan-800 font-bold">
                                :L{el.line_number}
                              </span>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleCopyReference(
                                    `${inspectedNodeData.filepath}:L${el.line_number} -> ${
                                      el.signature || el.name
                                    }`,
                                    `ref-${i}`
                                  );
                                }}
                                title="Copy symbol reference"
                                className="text-slate-500 hover:text-cyan-800"
                              >
                                {copiedRefText === `ref-${i}` ? (
                                  <Check className="w-3 h-3 text-emerald-700" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                              </button>
                            </div>
                          </div>
                        )
                      )}
                    </div>
                  </div>
                )}

              {inspectedFileFindings.length > 0 && (
                <div className="space-y-1 pt-1 border-t border-slate-200">
                  <span className="text-[10px] font-mono text-rose-800 font-extrabold flex items-center gap-1">
                    <Flame className="w-3 h-3 text-rose-700" />
                    VULNERABILITIES IN FILE ({inspectedFileFindings.length})
                  </span>
                  <div className="space-y-1 max-h-28 overflow-y-auto">
                    {inspectedFileFindings.map((f) => {
                      const firstN = f.path_nodes?.[0];
                      return (
                        <div
                          key={f.id}
                          onClick={() => selectFinding(f)}
                          className="p-1.5 rounded bg-rose-50 hover:bg-rose-100 border border-rose-300 cursor-pointer flex items-center justify-between gap-2 text-[10px] font-mono"
                        >
                          <span className="text-rose-900 font-semibold truncate">
                            {f.title}
                          </span>
                          <span className="text-rose-800 font-extrabold shrink-0">
                            L{firstN?.start_line || f.best_fix_location?.line || 1}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* FULL-SCREEN PRESENTATION ATTACK WALKTHROUGH & LIVE CODE DOCK (Light Mode) */}
        {isGraphFullscreen &&
          graphViewMode === "FINDING_PATH" &&
          selectedFinding &&
          activeFindingFlow && (
            <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-30 w-[92%] max-w-5xl rounded-2xl border border-slate-300 bg-white/95 backdrop-blur-md shadow-2xl p-3.5 space-y-2.5 select-none">
              <div className="flex items-center justify-between gap-3 flex-wrap border-b border-slate-200 pb-2">
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase border shrink-0 ${
                      selectedFinding.severity === "CRITICAL"
                        ? "bg-rose-700 text-white border-rose-800"
                        : selectedFinding.severity === "HIGH"
                        ? "bg-amber-700 text-white border-amber-800"
                        : "bg-sky-700 text-white border-sky-800"
                    }`}
                  >
                    {selectedFinding.severity}
                  </span>
                  {selectedFinding.cwe_id && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-800 border border-slate-300 shrink-0">
                      {selectedFinding.cwe_id}
                    </span>
                  )}
                  <span className="text-xs font-extrabold text-slate-900 truncate">
                    {currentFindingIndex >= 0
                      ? `Finding #${currentFindingIndex + 1}/${findings.length}: `
                      : ""}
                    {selectedFinding.title}
                  </span>
                </div>

                <div className="flex items-center gap-1.5 flex-wrap">
                  <button
                    type="button"
                    onClick={() => focusTourStep(activeTourStepIdx - 1)}
                    disabled={activeTourStepIdx <= 0}
                    className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 disabled:opacity-40 text-slate-800 border border-slate-300 text-[10px] font-mono font-bold flex items-center gap-1"
                  >
                    <ChevronLeft className="w-3 h-3" />
                    <span>Prev</span>
                  </button>

                  {activeFindingFlow.nodes.map((n, idx) => {
                    const total = activeFindingFlow.nodes.length;
                    const role =
                      idx === 0
                        ? "ORIGIN"
                        : n.is_bfl
                        ? "BFL"
                        : idx === total - 1
                        ? "IMPACT"
                        : `STEP ${idx + 1}`;
                    const isActive = idx === activeTourStepIdx;
                    return (
                      <button
                        key={`${n.id}-${idx}`}
                        type="button"
                        onClick={() => focusTourStep(idx)}
                        className={`px-2.5 py-1 rounded text-[10px] font-mono font-extrabold border transition-all ${
                          isActive
                            ? n.is_sink
                              ? "bg-rose-700 text-white border-rose-800"
                              : n.is_bfl
                              ? "bg-amber-700 text-white border-amber-800"
                              : "bg-cyan-700 text-white border-cyan-800"
                            : "bg-white text-slate-700 border-slate-300 hover:bg-slate-50"
                        }`}
                      >
                        {formatCircledStep(idx + 1)} {role} (L{n.start_line})
                      </button>
                    );
                  })}

                  <button
                    type="button"
                    onClick={() => focusTourStep(activeTourStepIdx + 1)}
                    disabled={
                      activeTourStepIdx >= activeFindingFlow.nodes.length - 1
                    }
                    className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 disabled:opacity-40 text-slate-800 border border-slate-300 text-[10px] font-mono font-bold flex items-center gap-1"
                  >
                    <span>Next</span>
                    <ChevronRight className="w-3 h-3" />
                  </button>
                </div>
              </div>

              {activeTourNode && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div className="bg-slate-50 border border-slate-200 rounded-xl p-2.5 space-y-1.5">
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-600">
                      <span className="text-cyan-900 font-bold truncate">
                        Step {activeTourStepIdx + 1} • {activeTourNode.filepath}:
                        {activeTourNode.start_line}
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          selectGraphNode(activeTourNode);
                          setGraphFullscreen(false);
                        }}
                        className="px-2 py-0.5 rounded bg-cyan-700 hover:bg-cyan-800 text-white border border-cyan-800 text-[10px] font-mono font-bold flex items-center gap-1 shrink-0"
                      >
                        <Code2 className="w-3 h-3 text-white" />
                        <span>Inspect in Code Editor</span>
                      </button>
                    </div>
                    <pre className="text-[11px] font-mono text-slate-800 bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 overflow-x-auto whitespace-pre-wrap break-all max-h-20">
                      {activeTourNode.code || activeTourNode.name}
                    </pre>
                  </div>

                  <div className="bg-slate-50 border border-slate-200 rounded-xl p-2.5 flex flex-col justify-between space-y-1">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-emerald-800 font-extrabold">
                      Vulnerability Story &amp; Recommended Fix
                    </div>
                    <p className="text-[11px] text-slate-700 leading-relaxed line-clamp-2">
                      {selectedFinding.description}
                    </p>
                    {selectedFinding.remediation && (
                      <p className="text-[11px] text-emerald-900 font-mono leading-snug line-clamp-2 font-medium">
                        Fix: {selectedFinding.remediation}
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

        <ReactFlow
          nodes={displayNodes}
          edges={displayEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onInit={fitViewOnLoad}
          onNodeMouseEnter={(_, node) => {
            if (isBlastRadiusEnabled) setHoveredNodeId(node.id);
          }}
          onNodeMouseLeave={() => {
            setHoveredNodeId(null);
          }}
          onNodeClick={(_, node) => {
            if (isBlastRadiusEnabled) {
              setLockedBlastNodeId((prev) =>
                prev === node.id ? null : node.id
              );
            }
          }}
          onEdgeMouseEnter={(_, edge) => setHoveredEdgeId(edge.id)}
          onEdgeMouseLeave={() => setHoveredEdgeId(null)}
          onPaneClick={() => {
            setLockedBlastNodeId(null);
            setHoveredNodeId(null);
          }}
          minZoom={0.08}
          maxZoom={3.0}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#cbd5e1" gap={22} size={1.35} />
          <Controls className="!bg-white !border-slate-300 !text-slate-800 !shadow-md rounded-lg overflow-hidden" />
          {showMiniMap && (
            <MiniMap
              nodeColor={(n) => {
                if (n.data?.label === "SpiderHub") return "#0e7490";
                if (n.data?.label === "AppDirectory") return "#0284c7";
                if (n.data?.label === "AppElement") return "#d97706";
                if (n.data?.flawCount > 0 || n.data?.is_sink) return "#be123c";
                if (n.data?.is_bfl) return "#b45309";
                if (n.data?.is_source) return "#0e7490";
                return "#047857";
              }}
              maskColor="rgba(241, 245, 249, 0.76)"
              className="!bg-white !border-slate-300 !shadow-md rounded-lg overflow-hidden"
            />
          )}
        </ReactFlow>
      </div>
    </div>
  );
}
