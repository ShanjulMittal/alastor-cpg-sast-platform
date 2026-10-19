"use client";

import React, { useEffect, useState, useMemo, useCallback } from "react";
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
import { CustomGraphNode } from "./CustomGraphNode";
import { isLightAppTheme } from "./AlastorBranding";
import {
  CPGNode,
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
  ExternalLink,
  Play,
  Pause,
  ChevronLeft,
  ChevronRight,
  Download,
  Info,
  ArrowRight,
  ArrowDown,
  Monitor,
  Map as MapIcon,
} from "lucide-react";

const NODE_WIDTH = 260;
const NODE_HEIGHT = 120;

const nodeTypes = {
  cpgNode: CustomGraphNode,
};

type AppTreeLayoutStyle = "SPIDER_WEB" | "MIND_MAP" | "HIERARCHY";

function getEdgeStyle(edgeType: string, isSpider = false) {
  switch (edgeType) {
    case "DFG_FLOWS_TO":
      return {
        stroke: "#ef4444",
        strokeWidth: 2.2,
        strokeDasharray: "5 5",
        animated: true,
      };
    case "CFG_NEXT":
    case "CFG_TRUE":
    case "CFG_FALSE":
    case "CFG_LOOP_BACK":
    case "CFG_BREAK":
      return {
        stroke: "#06b6d4",
        strokeWidth: 1.8,
        animated: false,
      };
    case "CALLS":
      return {
        stroke: "#a855f7",
        strokeWidth: 2,
        animated: false,
      };
    case "CONTAINS":
      return {
        stroke: isSpider ? "#22d3ee" : "#10b981",
        strokeWidth: isSpider ? 2 : 2,
        animated: false,
      };
    case "DECLARES":
      return {
        stroke: "#f59e0b",
        strokeWidth: 1.6,
        strokeDasharray: "4 4",
        animated: true,
      };
    case "AST_CHILD":
    default:
      return {
        stroke: "#64748b",
        strokeWidth: 1.2,
        strokeDasharray: "2 2",
        animated: false,
      };
  }
}

function computeDagreLayout(
  nodes: Node[],
  edges: Edge[],
  rankdir: "TB" | "LR" = "TB"
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
    nodesep: rankdir === "LR" ? 55 : 80,
    ranksep: rankdir === "LR" ? 140 : 100,
  });

  safeNodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  });

  safeEdges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = safeNodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition ? nodeWithPosition.x - NODE_WIDTH / 2 : 0,
        y: nodeWithPosition ? nodeWithPosition.y - NODE_HEIGHT / 2 : 0,
      },
    };
  });

  return { nodes: layoutedNodes, edges: safeEdges };
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
  const selectTreeFile = useAuditStore((s) => s.selectTreeFile);
  const selectFinding = useAuditStore((s) => s.selectFinding);
  const selectGraphNode = useAuditStore((s) => s.selectGraphNode);
  const appTheme = useAuditStore((s) => s.appTheme);
  const isLightTheme = isLightAppTheme(appTheme);

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  // Spider App Tree & CPG Presentation interactive controls state
  const [treeLayoutStyle, setTreeLayoutStyle] =
    useState<AppTreeLayoutStyle>("SPIDER_WEB");
  const [cpgLayoutDirection, setCpgLayoutDirection] = useState<"TB" | "LR">("TB");
  const [collapsedDirs, setCollapsedDirs] = useState<Record<string, boolean>>({});
  const [expandedFileElements, setExpandedFileElements] = useState<
    Record<string, boolean>
  >({});
  const [spiderSearch, setSpiderSearch] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [showRadarChart, setShowRadarChart] = useState<boolean>(true);
  const [showLegend, setShowLegend] = useState<boolean>(false);
  const [showMiniMap, setShowMiniMap] = useState<boolean>(true);
  const [inspectedNodeData, setInspectedNodeData] = useState<any | null>(null);
  const [copiedRefText, setCopiedRefText] = useState<string | null>(null);

  // Full-Screen Presentation Walkthrough Tour State
  const [activeTourStepIdx, setActiveTourStepIdx] = useState<number>(0);
  const [isAutoPlayingTour, setIsAutoPlayingTour] = useState<boolean>(false);
  const [isNativeFullscreen, setIsNativeFullscreen] = useState<boolean>(false);

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

  // Reset tour step when selectedFinding changes
  useEffect(() => {
    setActiveTourStepIdx(0);
    setIsAutoPlayingTour(false);
  }, [selectedFinding?.id]);

  // Auto-enable legend and fit view when toggling Full-Screen Presentation Mode
  useEffect(() => {
    if (isGraphFullscreen) {
      setShowLegend(true);
    }
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

  // Keyboard shortcuts for Full-Screen Presentation Mode (Escape to exit)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isGraphFullscreen) {
        setGraphFullscreen(false);
        setIsAutoPlayingTour(false);
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
  }, [isGraphFullscreen, setGraphFullscreen]);

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
        label: e.label,
      })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `argon-graph-${graphViewMode.toLowerCase()}.json`;
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

  // Build Concentric 360° Spider-Web / Mind-Map / Hierarchy Graph for APP_TREE
  useEffect(() => {
    let isCancelled = false;

    async function loadGraph() {
      // CASE 1: Interactive Spider-Web / Mind-Map App Tree built directly from rich AppTreeSummary
      if (graphViewMode === "APP_TREE" && appTree) {
        const spiderNodes: Node[] = [];
        const spiderEdges: Edge[] = [];
        const isSpider = treeLayoutStyle === "SPIDER_WEB";
        const queryLower = spiderSearch.trim().toLowerCase();

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
          label: string,
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
          const matchText =
            name.toLowerCase().includes(queryLower) ||
            purpose.toLowerCase().includes(queryLower) ||
            (category || "").toLowerCase().includes(queryLower) ||
            elements.some(
              (el) =>
                el.name.toLowerCase().includes(queryLower) ||
                el.signature.toLowerCase().includes(queryLower)
            );
          return matchText;
        };

        // Create Central Spider Root Hub at (0, 0)
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

        // Recursive radial sector layout for Spider-Web mode
        const RING_STEP = 380;

        const layoutRadialChildren = (
          parentNodeId: string,
          dirNode: DirectoryTreeNode,
          depth: number,
          startAngle: number,
          endAngle: number
        ) => {
          const subDirs = dirNode.subdirectories || [];
          const files = dirNode.files || [];

          const items: Array<
            | { kind: "dir"; dir: DirectoryTreeNode; weight: number }
            | { kind: "file"; file: FilePurposeInfo; weight: number }
          > = [
            ...subDirs.map((d) => ({
              kind: "dir" as const,
              dir: d,
              weight: countSubtreeWeight(d, collapsedDirs),
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
          const radius = depth * RING_STEP;

          items.forEach((item, idx) => {
            const angleSpan =
              ((endAngle - startAngle) * item.weight) / Math.max(1, totalWeight);
            const midAngle = currentAngle + angleSpan / 2;
            currentAngle += angleSpan;

            // Slight radial stagger on dense rings so adjacent cards never collide
            const stagger = items.length > 6 && idx % 2 === 1 ? 85 : 0;
            const r = radius + stagger;
            const cx = Math.cos(midAngle) * r;
            const cy = Math.sin(midAngle) * r;

            if (item.kind === "dir") {
              const d = item.dir;
              const dId = `dir:${d.path}`;
              const isCollapsed = Boolean(collapsedDirs[d.path]);
              const isMatch =
                spiderSearch === "" && categoryFilter === "ALL"
                  ? true
                  : matchesFilter("AppDirectory", d.name, d.purpose);

              spiderNodes.push({
                id: dId,
                type: "cpgNode",
                position: { x: cx - 104, y: cy - 55 },
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

              spiderEdges.push({
                id: `edge:${parentNodeId}->${dId}`,
                source: parentNodeId,
                target: dId,
                type: isSpider ? "straight" : "smoothstep",
                style: getEdgeStyle("CONTAINS", isSpider),
                markerEnd: {
                  type: MarkerType.ArrowClosed,
                  color: isSpider ? "#22d3ee" : "#10b981",
                  width: 14,
                  height: 14,
                },
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
              const isMatch = matchesFilter(
                "AppFile",
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
                position: { x: cx - 112, y: cy - 64 },
                data: {
                  ...f,
                  id: fId,
                  label: "AppFile",
                  name: f.filename,
                  code: f.purpose,
                  start_line: 1,
                  end_line: f.line_count,
                  flawCount,
                  isSpiderMode: isSpider,
                  isExpandedElements,
                  isDimmed:
                    (spiderSearch !== "" || categoryFilter !== "ALL") && !isMatch,
                  onToggleElements: handleToggleFileElements,
                  onSelectInspect: setInspectedNodeData,
                },
              });

              spiderEdges.push({
                id: `edge:${parentNodeId}->${fId}`,
                source: parentNodeId,
                target: fId,
                type: isSpider ? "straight" : "smoothstep",
                style: getEdgeStyle("CONTAINS", isSpider),
                markerEnd: {
                  type: MarkerType.ArrowClosed,
                  color: isSpider ? "#22d3ee" : "#10b981",
                  width: 14,
                  height: 14,
                },
              });

              // Satellite Reference Nodes (Functions, Routes, Classes, Dependencies)
              if (isExpandedElements && f.elements && f.elements.length > 0) {
                const maxSatellites = f.elements.slice(0, 10);
                const satSpread = Math.min(Math.PI * 0.75, Math.max(0.45, angleSpan * 0.9));
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

                  spiderEdges.push({
                    id: `edge:${fId}->${elemId}`,
                    source: fId,
                    target: elemId,
                    type: isSpider ? "straight" : "smoothstep",
                    style: getEdgeStyle("DECLARES", isSpider),
                    animated: true,
                    markerEnd: {
                      type: MarkerType.ArrowClosed,
                      color: "#f59e0b",
                      width: 12,
                      height: 12,
                    },
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

        if (isSpider) {
          setNodes(spiderNodes);
          setEdges(spiderEdges);
        } else {
          const rankdir = treeLayoutStyle === "MIND_MAP" ? "LR" : "TB";
          const layouted = computeDagreLayout(spiderNodes, spiderEdges, rankdir);
          setNodes(layouted.nodes);
          setEdges(layouted.edges);
        }

        setTimeout(() => {
          if (reactFlowInstance) {
            reactFlowInstance.fitView({ padding: 0.22, duration: 450 });
          }
        }, 60);
        return;
      }

      // CASE 2: Standard CPG Views (FINDING_PATH, FULL_CPG, DFG_ONLY, CFG_ONLY, CALL_GRAPH)
      let rawNodes: CPGNode[] = [];
      let rawEdges: any[] = [];

      if (graphViewMode === "FINDING_PATH") {
        if (selectedFinding) {
          rawNodes = selectedFinding.path_nodes || [];
          rawEdges = selectedFinding.path_edges || [];
        } else {
          if (!isCancelled) {
            setNodes([]);
            setEdges([]);
          }
          return;
        }
      } else {
        try {
          const url =
            activeFilepath && graphViewMode !== "APP_TREE"
              ? `http://localhost:8000/api/graph?view_mode=${graphViewMode}&filepath=${encodeURIComponent(
                  activeFilepath
                )}`
              : `http://localhost:8000/api/graph?view_mode=${graphViewMode}`;
          const res = await fetch(url);
          if (res.ok && !isCancelled) {
            const data = await res.json();
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
      const validNodeIds = new Set(clampedRawNodes.map((n) => n.id));
      const clampedRawEdges = rawEdges.filter(
        (e) => validNodeIds.has(e.source) && validNodeIds.has(e.target)
      );

      const flowNodes: Node[] = clampedRawNodes.map((n) => ({
        id: String(n.id),
        type: "cpgNode",
        position: { x: 0, y: 0 },
        data: n,
      }));

      const flowEdges: Edge[] = clampedRawEdges.map((e) => ({
        id: String(e.id),
        source: String(e.source),
        target: String(e.target),
        type: "smoothstep",
        label: e.var_name ? `(${e.var_name})` : undefined,
        style: getEdgeStyle(e.type),
        animated: e.type === "DFG_FLOWS_TO",
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: getEdgeStyle(e.type).stroke,
          width: 14,
          height: 14,
        },
      }));

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
              padding: isGraphFullscreen ? 0.18 : 0.25,
              duration: 400,
            });
          }
        }, 50);
      } else {
        setNodes([]);
        setEdges([]);
      }
    }

    loadGraph();

    return () => {
      isCancelled = true;
    };
  }, [
    selectedFinding,
    graphViewMode,
    activeFilepath,
    appTree,
    findings,
    treeLayoutStyle,
    cpgLayoutDirection,
    collapsedDirs,
    expandedFileElements,
    spiderSearch,
    categoryFilter,
    isGraphFullscreen,
    handleToggleCollapseDir,
    handleToggleFileElements,
    reactFlowInstance,
    setNodes,
    setEdges,
  ]);

  const fitViewOnLoad = useCallback(
    (instance: any) => {
      setReactFlowInstance(instance);
      setTimeout(() => {
        instance.fitView({ padding: 0.2, duration: 600 });
      }, 100);
    },
    [setReactFlowInstance]
  );

  // Interactive Zoom & Camera Helpers
  const handleZoomIn = () => {
    reactFlowInstance?.zoomIn({ duration: 250 });
  };

  const handleZoomOut = () => {
    reactFlowInstance?.zoomOut({ duration: 250 });
  };

  const handleFitAll = () => {
    reactFlowInstance?.fitView({
      padding: isGraphFullscreen ? 0.16 : 0.2,
      duration: 450,
    });
  };

  const handleCenterRoot = () => {
    if (!reactFlowInstance) return;
    const rootNode = nodes.find((n) => n.id === "dir:root");
    if (rootNode) {
      reactFlowInstance.setCenter(
        rootNode.position.x + 104,
        rootNode.position.y + 104,
        { zoom: 0.9, duration: 500 }
      );
    } else {
      reactFlowInstance.fitView({ padding: 0.2, duration: 450 });
    }
  };

  const handleFocusSelected = () => {
    if (!reactFlowInstance) return;
    const targetId =
      selectedGraphNodeId ||
      (activeFilepath ? `file:${activeFilepath}` : null);
    const matchNode = nodes.find((n) => n.id === targetId);
    if (matchNode) {
      reactFlowInstance.setCenter(
        matchNode.position.x + 110,
        matchNode.position.y + 60,
        { zoom: 1.35, duration: 500 }
      );
    } else {
      handleFitAll();
    }
  };

  // Focus camera on a specific step in the finding path during Full-Screen Presentation Tour
  const focusTourStep = useCallback(
    (stepIndex: number) => {
      const pathNodes = selectedFinding?.path_nodes || [];
      if (pathNodes.length === 0) return;
      const clampedIdx = Math.max(0, Math.min(stepIndex, pathNodes.length - 1));
      setActiveTourStepIdx(clampedIdx);
      const stepNode = pathNodes[clampedIdx];
      if (!stepNode) return;
      selectGraphNode(stepNode);
      if (reactFlowInstance) {
        const rfNode = nodes.find((n) => String(n.id) === String(stepNode.id));
        if (rfNode) {
          reactFlowInstance.setCenter(
            rfNode.position.x + NODE_WIDTH / 2,
            rfNode.position.y + NODE_HEIGHT / 2,
            { zoom: 1.35, duration: 520 }
          );
        }
      }
    },
    [selectedFinding, nodes, reactFlowInstance, selectGraphNode]
  );

  // Auto-play presentation tour interval
  useEffect(() => {
    if (!isAutoPlayingTour || !selectedFinding?.path_nodes?.length) return;
    const total = selectedFinding.path_nodes.length;
    const interval = setInterval(() => {
      setActiveTourStepIdx((prev) => {
        const nextIdx = (prev + 1) % total;
        focusTourStep(nextIdx);
        return nextIdx;
      });
    }, 2600);
    return () => clearInterval(interval);
  }, [isAutoPlayingTour, selectedFinding, focusTourStep]);

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
    const pNodes = selectedFinding?.path_nodes || [];
    if (pNodes.length === 0) return null;
    return pNodes[Math.min(activeTourStepIdx, pNodes.length - 1)] || pNodes[0];
  }, [selectedFinding, activeTourStepIdx]);

  return (
    <div
      className={
        isGraphFullscreen
          ? "fixed inset-0 z-[100] w-screen h-screen bg-zinc-950/90 flex flex-col select-none"
          : "flex flex-col h-full bg-zinc-950/60 border-l border-zinc-800"
      }
    >
      {/* EXECUTIVE FULL-SCREEN PRESENTATION HEADER BANNER */}
      {isGraphFullscreen && (
        <div className="h-12 bg-gradient-to-r from-zinc-950 via-cyan-950/35 to-zinc-950 border-b border-cyan-800/70 px-4 flex items-center justify-between gap-3 shrink-0 shadow-lg">
          {/* Left: Live Presentation Badge & Target Context */}
          <div className="flex items-center gap-3 min-w-0">
            <span className="px-2.5 py-1 rounded-md bg-cyan-500/15 border border-cyan-500/60 text-cyan-300 font-mono text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 shrink-0">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              Full-Screen Presentation View
            </span>
            <div className="flex items-center gap-2 text-xs font-mono truncate">
              <span className="text-zinc-400">Target:</span>
              <span className="text-zinc-100 font-semibold truncate max-w-[260px]">
                {activeFilepath ||
                  projectPath.split(/[\\/]/).pop() ||
                  projectPath}
              </span>
              <span className="text-zinc-600">•</span>
              <span className="text-cyan-400">
                {nodes.length} Nodes / {edges.length} Edges
              </span>
            </div>
          </div>

          {/* Center: Interactive Finding Switcher in Presentation Mode */}
          {findings.length > 0 && (
            <div className="flex items-center gap-1.5 bg-zinc-900/90 border border-zinc-800 rounded-lg px-2 py-1">
              <button
                type="button"
                onClick={() => handleCycleFinding(-1)}
                title="Previous Vulnerability Finding"
                className="p-1 rounded hover:bg-zinc-800 text-zinc-300 hover:text-cyan-300 transition-colors"
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
                className="bg-zinc-950 text-zinc-100 text-[11px] font-mono px-2 py-0.5 rounded border border-zinc-800 max-w-[340px] focus:outline-none focus:border-cyan-500"
              >
                {findings.map((f, idx) => {
                  const sinkLn =
                    f.path_nodes?.[f.path_nodes.length - 1]?.start_line || 1;
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
                className="p-1 rounded hover:bg-zinc-800 text-zinc-300 hover:text-cyan-300 transition-colors"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {/* Right: Snapshot Download, Native Browser Fullscreen & Exit Full Screen */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleExportGraphSnapshot}
              title="Download Current Graph Topology as JSON Snapshot"
              className="px-2.5 py-1 rounded-md bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-700 text-xs font-mono flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export Graph</span>
            </button>
            <button
              type="button"
              onClick={handleToggleBrowserFullscreen}
              title="Toggle Native OS / Browser Fullscreen (F11)"
              className={`px-2.5 py-1 rounded-md border text-xs font-mono flex items-center gap-1.5 transition-colors ${
                isNativeFullscreen
                  ? "bg-cyan-950 text-cyan-300 border-cyan-700"
                  : "bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border-zinc-700"
              }`}
            >
              <Monitor className="w-3.5 h-3.5 text-cyan-400" />
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
              className="px-3 py-1 rounded-md bg-red-950/80 hover:bg-red-900 text-red-200 border border-red-700/80 text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
            >
              <Minimize2 className="w-3.5 h-3.5 text-red-400" />
              <span>Exit Full Screen (Esc)</span>
            </button>
          </div>
        </div>
      )}

      {/* Canvas Top Bar with Self-Explanatory View Modes & Full-Screen Toggle */}
      <div className="h-10 bg-zinc-900/90 border-b border-zinc-800 px-3 flex items-center justify-between text-xs text-zinc-300 gap-2 shrink-0">
        <div className="flex items-center gap-2 truncate">
          <Layers className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="font-semibold text-zinc-200 truncate">
            {graphViewMode === "APP_TREE"
              ? "360° Spider App Map"
              : graphViewMode === "FINDING_PATH"
              ? "Attack Story Graph"
              : "Interactive Code Graph"}
          </span>
          <span className="text-[11px] text-zinc-500 font-mono shrink-0">
            ({nodes.length} nodes, {edges.length} links)
          </span>
        </div>

        <div className="flex items-center gap-2 overflow-x-auto">
          {/* Self-Explanatory View Mode Tabs */}
          <div className="flex items-center gap-1 bg-zinc-950 p-0.5 rounded-md border border-zinc-800 text-[10px]">
            {(
              [
                {
                  mode: "FINDING_PATH",
                  label: "1. Attack Path",
                  tip: "Traces the exact step-by-step path from input source to vulnerable line for the selected finding",
                },
                {
                  mode: "APP_TREE",
                  label: "2. 360° Spider Map",
                  tip: "Interactive 360° spider-web of all folders, files, functions, and references",
                },
                {
                  mode: "DFG_ONLY",
                  label: "3. Data Flow",
                  tip: "Shows how variables and user data move between statements",
                },
                {
                  mode: "CFG_ONLY",
                  label: "4. Control Flow",
                  tip: "Shows if/else branches, loops, and execution order",
                },
                {
                  mode: "CALL_GRAPH",
                  label: "5. Function Calls",
                  tip: "Shows which functions call other functions across files",
                },
                {
                  mode: "FULL_CPG",
                  label: "6. Full Graph",
                  tip: "Complete compiler graph combining syntax, control flow, and data flow",
                },
              ] as { mode: GraphViewMode; label: string; tip: string }[]
            ).map((item) => (
              <button
                key={item.mode}
                onClick={() => setGraphViewMode(item.mode)}
                title={item.tip}
                className={`px-2 py-0.5 rounded font-mono whitespace-nowrap transition-colors ${
                  graphViewMode === item.mode
                    ? "bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>

          {/* Prominent Full-Screen Toggle Button in Graph Header */}
          <button
            type="button"
            onClick={() => setGraphFullscreen(!isGraphFullscreen)}
            title={
              isGraphFullscreen
                ? "Exit Full-Screen Presentation View (Esc)"
                : "Expand Graph to Full-Screen Presentable View"
            }
            className={`px-2.5 py-1 rounded-md font-mono text-[10px] font-bold flex items-center gap-1 border shrink-0 transition-all ${
              isGraphFullscreen
                ? "bg-amber-950/90 text-amber-300 border-amber-700 hover:bg-amber-900"
                : "bg-cyan-950/90 text-cyan-300 border-cyan-700 hover:bg-cyan-900 shadow-sm shadow-cyan-950"
            }`}
          >
            {isGraphFullscreen ? (
              <>
                <Minimize2 className="w-3 h-3" />
                <span>Split View</span>
              </>
            ) : (
              <>
                <Maximize2 className="w-3 h-3" />
                <span>Full Screen</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Plain-English Active View Explanation Strip */}
      <div className="bg-zinc-900/50 border-b border-zinc-800/80 px-3 py-1 text-[11px] text-zinc-400 flex items-center justify-between gap-2 shrink-0">
        <span className="truncate">
          {graphViewMode === "FINDING_PATH" &&
            "Attack Story Path: Shows how untrusted input (Cyan) travels along data/control links to trigger the vulnerable sink (Red). Click any node to highlight its code."}
          {graphViewMode === "APP_TREE" &&
            "360° Spider Architecture Map: Central hub connects to folders, files, and outer symbol satellites. Click any file to inspect references or jump to code."}
          {graphViewMode === "DFG_ONLY" &&
            "Data Flow View (DFG): Red dashed arrows trace how variable values and inputs flow from definitions to usages across the current file."}
          {graphViewMode === "CFG_ONLY" &&
            "Control Flow View (CFG): Cyan arrows trace sequential execution steps, conditional branches (True/False), and loop back-edges."}
          {graphViewMode === "CALL_GRAPH" &&
            "Function Call Map: Purple arrows connect caller functions to the target functions they invoke."}
          {graphViewMode === "FULL_CPG" &&
            "Complete Code Property Graph: Displays combined syntax (AST), execution order (CFG), and variable flow (DFG) for deep inspection."}
        </span>
      </div>

      {/* UNIVERSAL INTERACTIVE CAMERA, LAYOUT & PRESENTATION TOOLBAR (Available Across All 6 Graph Modes) */}
      <div className="bg-zinc-900/75 border-b border-zinc-800/90 px-3 py-1.5 flex items-center justify-between gap-2 flex-wrap text-[11px] shrink-0">
        {/* Left Controls: Spider Layout Mode OR CPG Orientation Toggle (TB vs LR) */}
        {graphViewMode === "APP_TREE" ? (
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex items-center gap-1 bg-zinc-950 p-0.5 rounded-md border border-zinc-800 font-mono text-[10px]">
              {(
                [
                  { id: "SPIDER_WEB", label: "360° Spider Web" },
                  { id: "MIND_MAP", label: "Mind-Map (LR)" },
                  { id: "HIERARCHY", label: "Hierarchy (TB)" },
                ] as { id: AppTreeLayoutStyle; label: string }[]
              ).map((ly) => (
                <button
                  key={ly.id}
                  type="button"
                  onClick={() => setTreeLayoutStyle(ly.id)}
                  className={`px-2 py-0.5 rounded transition-all ${
                    treeLayoutStyle === ly.id
                      ? "bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  {ly.label}
                </button>
              ))}
            </div>

            {/* Search Filter for Spider Nodes & Symbols */}
            <div className="relative min-w-[140px] max-w-[220px]">
              <Search className="w-3 h-3 absolute left-2 top-2 text-zinc-500" />
              <input
                type="text"
                value={spiderSearch}
                onChange={(e) => setSpiderSearch(e.target.value)}
                placeholder="Spotlight file or ref..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded pl-6 pr-5 py-0.5 text-[11px] text-zinc-200 placeholder-zinc-500 font-mono focus:outline-none focus:border-cyan-500"
              />
              {spiderSearch && (
                <button
                  type="button"
                  onClick={() => setSpiderSearch("")}
                  className="absolute right-1.5 top-1.5 text-zinc-500 hover:text-zinc-300"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex items-center gap-1 bg-zinc-950 p-0.5 rounded-md border border-zinc-800 font-mono text-[10px]">
              <button
                type="button"
                onClick={() => setCpgLayoutDirection("TB")}
                title="Vertical Top-Down Flow Layout"
                className={`px-2 py-0.5 rounded flex items-center gap-1 transition-all ${
                  cpgLayoutDirection === "TB"
                    ? "bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <ArrowDown className="w-3 h-3" />
                <span>Top-Down (TB)</span>
              </button>
              <button
                type="button"
                onClick={() => setCpgLayoutDirection("LR")}
                title="Horizontal Left-to-Right Widescreen Flow Layout (Ideal for Full-Screen Presentations)"
                className={`px-2 py-0.5 rounded flex items-center gap-1 transition-all ${
                  cpgLayoutDirection === "LR"
                    ? "bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <ArrowRight className="w-3 h-3" />
                <span>Left-Right (LR)</span>
              </button>
            </div>

            {graphViewMode === "FINDING_PATH" && selectedFinding && (
              <button
                type="button"
                onClick={() => setIsAutoPlayingTour((p) => !p)}
                title="Auto-step camera through each node from Source to Sink"
                className={`px-2.5 py-0.5 rounded border font-mono text-[10px] font-bold flex items-center gap-1 transition-colors ${
                  isAutoPlayingTour
                    ? "bg-amber-950 text-amber-300 border-amber-700"
                    : "bg-zinc-950 hover:bg-zinc-800 text-cyan-300 border-zinc-800"
                }`}
              >
                {isAutoPlayingTour ? (
                  <>
                    <Pause className="w-3 h-3 text-amber-400" />
                    <span>Pause Tour</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3 h-3 text-cyan-400 fill-current" />
                    <span>Play Step Tour</span>
                  </>
                )}
              </button>
            )}
          </div>
        )}

        {/* Right Controls: Universal Camera Zoom, Fit, Focus, Legend, Radar & MiniMap */}
        <div className="flex items-center gap-1 font-mono text-[10px] flex-wrap">
          <button
            type="button"
            onClick={handleZoomIn}
            title="Zoom In (+)"
            className="p-1 rounded bg-zinc-950 hover:bg-zinc-800 text-cyan-400 border border-zinc-800 flex items-center gap-0.5"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={handleZoomOut}
            title="Zoom Out (-)"
            className="p-1 rounded bg-zinc-950 hover:bg-zinc-800 text-cyan-400 border border-zinc-800 flex items-center gap-0.5"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={handleFitAll}
            title="Fit Entire Graph in Viewport"
            className="px-2 py-1 rounded bg-zinc-950 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 flex items-center gap-1"
          >
            <Maximize2 className="w-3 h-3 text-cyan-400" />
            <span>Fit View</span>
          </button>
          {graphViewMode === "APP_TREE" && (
            <button
              type="button"
              onClick={handleCenterRoot}
              title="Center Camera on Spider Core Hub"
              className="px-2 py-1 rounded bg-zinc-950 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 flex items-center gap-1"
            >
              <Compass className="w-3 h-3 text-emerald-400" />
              <span>Core</span>
            </button>
          )}
          <button
            type="button"
            onClick={handleFocusSelected}
            title="Zoom Camera to Active Node"
            className="px-2 py-1 rounded bg-zinc-950 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 flex items-center gap-1"
          >
            <Crosshair className="w-3 h-3 text-amber-400" />
            <span>Focus</span>
          </button>
          {graphViewMode === "APP_TREE" && (
            <>
              <button
                type="button"
                onClick={handleExpandOrCollapseAll}
                title="Toggle Expand / Collapse All Directories"
                className="px-2 py-1 rounded bg-zinc-950 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 flex items-center gap-1"
              >
                <FolderTree className="w-3 h-3 text-cyan-400" />
                <span>Fold/Unfold</span>
              </button>
              <button
                type="button"
                onClick={() => setShowRadarChart((prev) => !prev)}
                title="Toggle 6-Axis Architecture Spider Radar Overlay"
                className={`px-2 py-1 rounded border flex items-center gap-1 ${
                  showRadarChart
                    ? "bg-cyan-950 text-cyan-300 border-cyan-700"
                    : "bg-zinc-950 text-zinc-400 border-zinc-800"
                }`}
              >
                <Radar className="w-3 h-3" />
                <span>Radar</span>
              </button>
            </>
          )}
          <button
            type="button"
            onClick={() => setShowLegend((prev) => !prev)}
            title="Toggle Visual Color & Edge Legend Overlay"
            className={`px-2 py-1 rounded border flex items-center gap-1 ${
              showLegend
                ? "bg-cyan-950 text-cyan-300 border-cyan-700"
                : "bg-zinc-950 text-zinc-400 border-zinc-800"
            }`}
          >
            <Info className="w-3 h-3" />
            <span>Legend</span>
          </button>
          <button
            type="button"
            onClick={() => setShowMiniMap((prev) => !prev)}
            title="Toggle Overview MiniMap"
            className={`px-2 py-1 rounded border flex items-center gap-1 ${
              showMiniMap
                ? "bg-cyan-950 text-cyan-300 border-cyan-700"
                : "bg-zinc-950 text-zinc-400 border-zinc-800"
            }`}
          >
            <MapIcon className="w-3 h-3" />
            <span>MiniMap</span>
          </button>
        </div>
      </div>

      {/* ReactFlow Canvas */}
      <div className="flex-1 w-full h-full relative overflow-hidden">
        {nodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none z-10 text-zinc-500">
            <Layers className="w-10 h-10 mb-3 opacity-30 text-zinc-400" />
            <p className="text-sm font-medium text-zinc-400">
              {graphViewMode === "FINDING_PATH"
                ? "Select a vulnerability from the sidebar to inspect its taint path"
                : "No graph nodes available for this view"}
            </p>
            <p className="text-xs text-zinc-600 mt-1">
              {graphViewMode === "FINDING_PATH"
                ? "Interactive CPG flow and source-to-sink AST nodes will be visualized here"
                : "Switch view mode or select a file to view graph structure"}
            </p>
          </div>
        )}

        {/* FLOATING 6-AXIS SPIDER RADAR CHART WIDGET (Top-Left in APP_TREE mode) */}
        {graphViewMode === "APP_TREE" && showRadarChart && appTree && (
          <div className="absolute top-3 left-3 z-20 w-56 rounded-xl border border-cyan-900/70 bg-zinc-950/90 backdrop-blur-md p-2.5 shadow-2xl select-none">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1">
                <Radar className="w-3 h-3" />
                Spider Radar Profile
              </span>
              {categoryFilter !== "ALL" && (
                <button
                  type="button"
                  onClick={() => setCategoryFilter("ALL")}
                  className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900"
                >
                  Reset ({categoryFilter})
                </button>
              )}
            </div>

            <div className="flex items-center justify-center">
              <svg width={radarSize} height={radarSize} className="overflow-visible">
                {/* Concentric hexagonal spider web rings */}
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
                      stroke="#1e293b"
                      strokeWidth="1"
                      strokeDasharray={level < 1 ? "2 2" : undefined}
                    />
                  );
                })}

                {/* Radial spokes */}
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
                        stroke={isActiveAxis ? "#22d3ee" : "#334155"}
                        strokeWidth={isActiveAxis ? "1.8" : "1"}
                      />
                      <text
                        x={lx}
                        y={ly}
                        textAnchor="middle"
                        dominantBaseline="middle"
                        className={`text-[8.5px] font-mono fill-current transition-colors ${
                          isActiveAxis
                            ? "text-cyan-300 font-bold"
                            : "text-zinc-400 group-hover:text-cyan-300"
                        }`}
                      >
                        {m.axis} ({m.raw})
                      </text>
                    </g>
                  );
                })}

                {/* Filled Spider Radar Polygon */}
                <polygon
                  points={radarPolygonPoints}
                  fill="rgba(6, 182, 212, 0.25)"
                  stroke="#06b6d4"
                  strokeWidth="2"
                />

                {/* Interactive Vertex Dots */}
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
                      fill={m.axis === "Flaws" && m.raw > 0 ? "#ef4444" : "#22d3ee"}
                      stroke="#09090b"
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
            <p className="text-[9px] font-mono text-zinc-500 text-center">
              Click any axis to spotlight category nodes
            </p>
          </div>
        )}

        {/* FLOATING VISUAL GRAPH LEGEND OVERLAY (Top-Right or Bottom-Left) */}
        {showLegend && (
          <div className="absolute top-3 right-3 z-20 w-64 rounded-xl border border-zinc-800 bg-zinc-950/90 backdrop-blur-md p-3 shadow-2xl select-none text-[10px] font-mono space-y-2">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-1.5">
              <span className="text-cyan-400 font-bold uppercase tracking-wider flex items-center gap-1">
                <Info className="w-3 h-3" />
                Graph Visual Legend
              </span>
              <button
                type="button"
                onClick={() => setShowLegend(false)}
                className="text-zinc-500 hover:text-zinc-200"
              >
                <X className="w-3 h-3" />
              </button>
            </div>

            <div className="space-y-1">
              <div className="text-[9px] text-zinc-500 uppercase font-bold">
                Node Roles
              </div>
              <div className="flex items-center gap-2 text-zinc-300">
                <span className="w-2.5 h-2.5 rounded-sm bg-cyan-500/30 border border-cyan-400 shrink-0" />
                <span>Entry / Source / Spider Hub</span>
              </div>
              <div className="flex items-center gap-2 text-zinc-300">
                <span className="w-2.5 h-2.5 rounded-sm bg-blue-500/30 border border-blue-400 shrink-0" />
                <span>Data Propagation / Statement</span>
              </div>
              <div className="flex items-center gap-2 text-zinc-300">
                <span className="w-2.5 h-2.5 rounded-sm bg-red-500/30 border border-red-500 shrink-0" />
                <span>Vulnerable Sink / Flaw File</span>
              </div>
              <div className="flex items-center gap-2 text-zinc-300">
                <span className="w-2.5 h-2.5 rounded-sm bg-amber-500/30 border border-amber-400 shrink-0" />
                <span>Symbol / Function Reference</span>
              </div>
            </div>

            <div className="space-y-1 pt-1 border-t border-zinc-800/80">
              <div className="text-[9px] text-zinc-500 uppercase font-bold">
                Relationship Links
              </div>
              <div className="flex items-center gap-2 text-zinc-300">
                <span className="w-5 h-0.5 border-b-2 border-dashed border-red-500 shrink-0" />
                <span>DFG_FLOWS_TO (Data/Taint Flow)</span>
              </div>
              <div className="flex items-center gap-2 text-zinc-300">
                <span className="w-5 h-0.5 bg-cyan-400 shrink-0" />
                <span>CFG_NEXT / CONTAINS (Control)</span>
              </div>
              <div className="flex items-center gap-2 text-zinc-300">
                <span className="w-5 h-0.5 bg-purple-400 shrink-0" />
                <span>CALLS (Function Invocation)</span>
              </div>
              <div className="flex items-center gap-2 text-zinc-300">
                <span className="w-5 h-0.5 border-b border-dashed border-slate-400 shrink-0" />
                <span>AST_CHILD (Syntax Structure)</span>
              </div>
            </div>
          </div>
        )}

        {/* FLOATING REFERENCE & SYMBOL INSPECTOR DRAWER (Bottom-Right in APP_TREE mode) */}
        {graphViewMode === "APP_TREE" && inspectedNodeData && (
          <div className="absolute bottom-3 right-3 z-20 w-80 max-h-[68%] flex flex-col rounded-xl border border-cyan-800/80 bg-zinc-950/95 backdrop-blur-md shadow-2xl overflow-hidden select-none">
            {/* Drawer Header */}
            <div className="px-3 py-2 bg-zinc-900/90 border-b border-zinc-800 flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 truncate">
                <GitBranch className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="text-xs font-mono font-bold text-zinc-100 truncate">
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
                  className="px-1.5 py-0.5 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700 text-[10px] font-mono flex items-center gap-1"
                  title="Copy full file/symbol reference string"
                >
                  {copiedRefText === "main-ref" ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
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
                  className="p-0.5 text-zinc-500 hover:text-zinc-200"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Drawer Body */}
            <div className="p-3 overflow-y-auto space-y-2.5 text-xs">
              {/* Path & Category Metadata */}
              <div className="space-y-1">
                {inspectedNodeData.filepath && (
                  <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400 bg-zinc-900 px-2 py-1 rounded border border-zinc-800">
                    <span className="truncate" title={inspectedNodeData.filepath}>
                      {inspectedNodeData.filepath}
                    </span>
                    {inspectedNodeData.line_count && (
                      <span className="text-cyan-400 shrink-0 ml-2">
                        {inspectedNodeData.line_count} LOC
                      </span>
                    )}
                  </div>
                )}
                <p className="text-[11px] text-zinc-300 leading-relaxed">
                  {inspectedNodeData.purpose ||
                    inspectedNodeData.details ||
                    inspectedNodeData.signature}
                </p>
              </div>

              {/* Declared Symbols / Code References inside this File */}
              {inspectedNodeData.elements &&
                inspectedNodeData.elements.length > 0 && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400">
                      <span>
                        DECLARED REFERENCES ({inspectedNodeData.elements.length})
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          handleToggleFileElements(inspectedNodeData.filepath)
                        }
                        className="text-amber-400 hover:underline"
                      >
                        {expandedFileElements[inspectedNodeData.filepath]
                          ? "Hide on Web"
                          : "Pin to Web"}
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
                                useAuditStore
                                  .getState()
                                  .selectCodeLine(
                                    inspectedNodeData.filepath,
                                    el.line_number || 1
                                  );
                              }
                            }}
                            className="group flex items-center justify-between gap-1.5 px-2 py-1 rounded bg-zinc-900/90 hover:bg-zinc-800 border border-zinc-800 hover:border-cyan-700 cursor-pointer font-mono text-[10px]"
                          >
                            <div className="flex items-center gap-1.5 truncate">
                              <span className="px-1 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[8px] font-bold">
                                {el.element_type.slice(0, 5)}
                              </span>
                              <span className="text-zinc-200 group-hover:text-cyan-300 truncate">
                                {el.name}
                              </span>
                            </div>
                            <div className="flex items-center gap-1.5 shrink-0">
                              <span className="text-cyan-400">:L{el.line_number}</span>
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
                                className="text-zinc-500 hover:text-cyan-300"
                              >
                                {copiedRefText === `ref-${i}` ? (
                                  <Check className="w-3 h-3 text-emerald-400" />
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

              {/* Associated Security Findings in this File */}
              {inspectedFileFindings.length > 0 && (
                <div className="space-y-1 pt-1 border-t border-zinc-800">
                  <span className="text-[10px] font-mono text-red-400 font-bold flex items-center gap-1">
                    <Flame className="w-3 h-3" />
                    VULNERABILITY REFERENCES ({inspectedFileFindings.length})
                  </span>
                  <div className="space-y-1 max-h-28 overflow-y-auto">
                    {inspectedFileFindings.map((f) => {
                      const firstN = f.path_nodes?.[0];
                      return (
                        <div
                          key={f.id}
                          onClick={() => {
                            selectFinding(f);
                          }}
                          className="p-1.5 rounded bg-red-950/30 hover:bg-red-950/60 border border-red-900/60 cursor-pointer flex items-center justify-between gap-2 text-[10px] font-mono"
                        >
                          <span className="text-red-200 truncate">{f.title}</span>
                          <span className="text-red-400 shrink-0">
                            L{firstN?.start_line || 1}
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

        {/* FULL-SCREEN PRESENTATION ATTACK WALKTHROUGH & LIVE CODE DOCK */}
        {isGraphFullscreen &&
          graphViewMode === "FINDING_PATH" &&
          selectedFinding && (
            <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-30 w-[92%] max-w-5xl rounded-2xl border border-cyan-800/80 bg-zinc-950/95 backdrop-blur-md shadow-2xl p-3.5 space-y-2.5 select-none">
              {/* Top Row: Finding Metadata & Step-by-Step Camera Navigator */}
              <div className="flex items-center justify-between gap-3 flex-wrap border-b border-zinc-800/90 pb-2">
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border shrink-0 ${
                      selectedFinding.severity === "CRITICAL"
                        ? "bg-red-950 text-red-300 border-red-700"
                        : selectedFinding.severity === "HIGH"
                        ? "bg-amber-950 text-amber-300 border-amber-700"
                        : "bg-yellow-950 text-yellow-300 border-yellow-700"
                    }`}
                  >
                    {selectedFinding.severity}
                  </span>
                  {selectedFinding.cwe_id && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-900 text-cyan-300 border border-zinc-700 shrink-0">
                      {selectedFinding.cwe_id}
                    </span>
                  )}
                  <span className="text-xs font-bold text-zinc-100 truncate">
                    {currentFindingIndex >= 0
                      ? `Finding #${currentFindingIndex + 1}/${findings.length}: `
                      : ""}
                    {selectedFinding.title}
                  </span>
                </div>

                {/* Step-by-Step Camera Tour Buttons */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  <button
                    type="button"
                    onClick={() => focusTourStep(activeTourStepIdx - 1)}
                    disabled={activeTourStepIdx <= 0}
                    className="px-2 py-1 rounded bg-zinc-900 hover:bg-zinc-800 disabled:opacity-40 text-zinc-200 border border-zinc-700 text-[10px] font-mono flex items-center gap-1"
                  >
                    <ChevronLeft className="w-3 h-3" />
                    <span>Prev Step</span>
                  </button>

                  {(selectedFinding.path_nodes || []).map((n, idx) => {
                    const total = selectedFinding.path_nodes.length;
                    const role =
                      total === 1
                        ? "TRIGGER"
                        : idx === 0
                        ? "SOURCE"
                        : idx === total - 1
                        ? "SINK"
                        : `STEP ${idx + 1}`;
                    const isActive = idx === activeTourStepIdx;
                    return (
                      <button
                        key={`${n.id}-${idx}`}
                        type="button"
                        onClick={() => focusTourStep(idx)}
                        className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold border transition-all ${
                          isActive
                            ? role === "SINK" || role === "TRIGGER"
                              ? "bg-red-950 text-red-200 border-red-500 shadow-sm shadow-red-950"
                              : "bg-cyan-950 text-cyan-200 border-cyan-500 shadow-sm shadow-cyan-950"
                            : "bg-zinc-900 text-zinc-400 border-zinc-800 hover:text-zinc-200"
                        }`}
                      >
                        {idx + 1}. {role} (L{n.start_line})
                      </button>
                    );
                  })}

                  <button
                    type="button"
                    onClick={() => focusTourStep(activeTourStepIdx + 1)}
                    disabled={
                      activeTourStepIdx >=
                      (selectedFinding.path_nodes?.length || 1) - 1
                    }
                    className="px-2 py-1 rounded bg-zinc-900 hover:bg-zinc-800 disabled:opacity-40 text-zinc-200 border border-zinc-700 text-[10px] font-mono flex items-center gap-1"
                  >
                    <span>Next Step</span>
                    <ChevronRight className="w-3 h-3" />
                  </button>
                </div>
              </div>

              {/* Bottom Row: Active Step Code Callout & Remediation Summary */}
              {activeTourNode && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-2.5 space-y-1.5">
                    <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400">
                      <span className="text-cyan-300 font-semibold truncate">
                        Step {activeTourStepIdx + 1} Code •{" "}
                        {activeTourNode.filepath}:{activeTourNode.start_line}
                        {typeof activeTourNode.start_col === "number"
                          ? `:col ${activeTourNode.start_col + 1}`
                          : ""}
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          selectGraphNode(activeTourNode);
                          setGraphFullscreen(false);
                        }}
                        className="px-2 py-0.5 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-[10px] font-mono flex items-center gap-1 shrink-0"
                      >
                        <Code2 className="w-3 h-3" />
                        <span>Inspect in Code Editor</span>
                      </button>
                    </div>
                    <pre className="text-[11px] font-mono text-amber-200 bg-zinc-950 border border-zinc-800/80 rounded-lg px-2.5 py-1.5 overflow-x-auto whitespace-pre-wrap break-all max-h-20">
                      {activeTourNode.code || activeTourNode.name}
                    </pre>
                  </div>

                  <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-2.5 flex flex-col justify-between space-y-1">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-bold">
                      Story &amp; Recommended Security Fix
                    </div>
                    <p className="text-[11px] text-zinc-300 leading-relaxed line-clamp-2">
                      {selectedFinding.description}
                    </p>
                    {selectedFinding.remediation && (
                      <p className="text-[11px] text-emerald-300/90 font-mono leading-snug line-clamp-2">
                        Fix: {selectedFinding.remediation}
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          onInit={fitViewOnLoad}
          minZoom={0.08}
          maxZoom={3.0}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background
            color={
              isLightTheme
                ? "#94a3b8"
                : graphViewMode === "APP_TREE"
                ? "#164e63"
                : "#3f1d2b"
            }
            gap={24}
            size={1.2}
          />
          <Controls className="!bg-zinc-900 !border-zinc-800 !text-zinc-200" />
          {showMiniMap && (
            <MiniMap
              nodeColor={(n) => {
                if (n.data?.label === "SpiderHub") return "#06b6d4";
                if (n.data?.label === "AppDirectory") return "#0891b2";
                if (n.data?.label === "AppElement") return "#f59e0b";
                if (n.data?.flawCount > 0 || n.data?.is_sink) return "#ef4444";
                if (n.data?.is_source) return "#22d3ee";
                return "#10b981";
              }}
              maskColor={
                isLightTheme
                  ? "rgba(241, 245, 249, 0.72)"
                  : "rgba(9, 9, 11, 0.75)"
              }
              className="!bg-zinc-950 !border-zinc-800 rounded-lg overflow-hidden"
            />
          )}
        </ReactFlow>
      </div>
    </div>
  );
}
