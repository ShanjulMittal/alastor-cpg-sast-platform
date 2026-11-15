"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  Edge,
  MarkerType,
  Node,
  ReactFlowProvider,
} from "reactflow";
import "reactflow/dist/style.css";

import { useAuditStore } from "@/store/useAuditStore";
import {
  ApiEndpointOperationDossier,
  ApiOperationCategory,
  ApiOperationItem,
  Finding,
} from "@/types/cpg";
import { CustomGraphNode } from "./CustomGraphNode";
import {
  DirectionalFlowEdge,
  DirectionalFlowEdgeData,
  formatCircledStep,
  resolveDirectionalEdgeMeta,
} from "./DirectionalFlowEdge";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Code2,
  Compass,
  Crosshair,
  Database,
  Download,
  FileCode2,
  FileSpreadsheet,
  Globe,
  KeyRound,
  Layers,
  Loader2,
  Lock,
  Maximize2,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  X,
} from "lucide-react";

const endpointNodeTypes = {
  cpgNode: CustomGraphNode,
};

const endpointEdgeTypes = {
  directionalFlow: DirectionalFlowEdge,
};

type HttpMethodFilter = "ALL" | "GET" | "POST" | "PUT" | "DELETE" | "PATCH";

type CategoryFilterKey =
  | "ALL"
  | "DATABASE_WRITE"
  | "DATABASE_READ"
  | "EXTERNAL_HTTP_OR_AI"
  | "FILESYSTEM_IO"
  | "OS_COMMAND_EXEC"
  | "SECRET_OR_CRYPTO"
  | "UNAUTHENTICATED"
  | "VULNERABLE";

const METHOD_FILTERS: HttpMethodFilter[] = [
  "ALL",
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
];

const CATEGORY_FILTERS: Array<{ id: CategoryFilterKey; label: string }> = [
  { id: "ALL", label: "ALL" },
  { id: "DATABASE_WRITE", label: "DATABASE_WRITE" },
  { id: "DATABASE_READ", label: "DATABASE_READ" },
  { id: "EXTERNAL_HTTP_OR_AI", label: "EXTERNAL_HTTP_OR_AI" },
  { id: "FILESYSTEM_IO", label: "FILESYSTEM_IO" },
  { id: "OS_COMMAND_EXEC", label: "OS_COMMAND_EXEC" },
  { id: "SECRET_OR_CRYPTO", label: "SECRET_OR_CRYPTO" },
  { id: "UNAUTHENTICATED", label: "UNAUTHENTICATED" },
  { id: "VULNERABLE", label: "VULNERABLE" },
];

function getMethodBadgeClasses(method: string): string {
  switch ((method || "").toUpperCase()) {
    case "GET":
      return "bg-sky-100 text-sky-900 border-sky-300";
    case "POST":
      return "bg-emerald-100 text-emerald-900 border-emerald-300";
    case "PUT":
    case "PATCH":
      return "bg-amber-100 text-amber-950 border-amber-400";
    case "DELETE":
      return "bg-rose-100 text-rose-900 border-rose-300";
    default:
      return "bg-slate-100 text-slate-800 border-slate-300";
  }
}

function getAuthBadgeMeta(
  authStatus: ApiEndpointOperationDossier["auth_status"],
  isMutating: boolean
): { label: string; className: string } {
  if (authStatus === "AUTHENTICATED") {
    return {
      label: "AUTHENTICATED",
      className: "bg-emerald-50 text-emerald-900 border-emerald-300",
    };
  }
  if (authStatus === "PARTIAL_OR_CUSTOM") {
    return {
      label: "CUSTOM / PARTIAL AUTH",
      className: "bg-amber-50 text-amber-950 border-amber-300",
    };
  }
  if (isMutating) {
    return {
      label: "UNAUTHENTICATED",
      className: "bg-rose-100 text-rose-900 border-rose-400",
    };
  }
  return {
    label: "UNAUTHENTICATED",
    className: "bg-amber-50 text-amber-950 border-amber-300",
  };
}

function getRiskBadgeClasses(
  risk: ApiEndpointOperationDossier["risk_level"]
): string {
  switch (risk) {
    case "CRITICAL":
      return "bg-rose-700 text-white border-rose-800";
    case "HIGH":
      return "bg-amber-800 text-white border-amber-900";
    case "MEDIUM":
      return "bg-amber-100 text-amber-950 border-amber-400";
    case "LOW":
      return "bg-sky-100 text-sky-900 border-sky-300";
    default:
      return "bg-emerald-50 text-emerald-900 border-emerald-300";
  }
}

function getCategoryChipMeta(category: ApiOperationCategory | string): {
  shortLabel: string;
  className: string;
} {
  switch (category) {
    case "AUTH_GUARD":
      return {
        shortLabel: "AUTH GUARD",
        className: "bg-emerald-50 text-emerald-900 border-emerald-300",
      };
    case "INPUT_VALIDATION":
      return {
        shortLabel: "INPUT VALIDATION",
        className: "bg-teal-50 text-teal-900 border-teal-300",
      };
    case "DATABASE_READ":
      return {
        shortLabel: "DB READ",
        className: "bg-sky-50 text-sky-900 border-sky-300",
      };
    case "DATABASE_WRITE":
      return {
        shortLabel: "DB WRITE",
        className: "bg-amber-100 text-amber-950 border-amber-400",
      };
    case "EXTERNAL_HTTP_OR_AI":
      return {
        shortLabel: "HTTP / AI",
        className: "bg-indigo-50 text-indigo-900 border-indigo-300",
      };
    case "FILESYSTEM_IO":
      return {
        shortLabel: "FILE I/O",
        className: "bg-purple-50 text-purple-900 border-purple-300",
      };
    case "OS_COMMAND_EXEC":
      return {
        shortLabel: "OS EXEC",
        className: "bg-rose-100 text-rose-900 border-rose-400",
      };
    case "SECRET_OR_CRYPTO":
      return {
        shortLabel: "SECRET / CRYPTO",
        className: "bg-cyan-50 text-cyan-900 border-cyan-300",
      };
    default:
      return {
        shortLabel: String(category).replace(/_/g, " "),
        className: "bg-slate-100 text-slate-800 border-slate-300",
      };
  }
}

function formatCallChain(chain: string[]): string {
  if (!Array.isArray(chain) || chain.length === 0) return "handler()";
  return chain
    .map((fn) => {
      const trimmed = (fn || "").trim();
      if (!trimmed) return "fn()";
      return trimmed.endsWith(")") ? trimmed : `${trimmed}()`;
    })
    .join(" -> ");
}

function escapeCsvCell(val: unknown): string {
  const s = String(val ?? "").replace(/\r?\n/g, " ");
  if (s.includes(",") || s.includes('"') || s.includes("\n")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function downloadBlob(content: BlobPart, mimeType: string, filename: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export function buildEndpointFlowDigest(ep: ApiEndpointOperationDossier): {
  nodesDigest: Array<Record<string, any>>;
  edgesDigest: Array<Record<string, any>>;
} {
  const nodesDigest = (ep.flow_nodes || []).slice(0, 40).map((raw, idx) => {
    const d = raw.data && typeof raw.data === "object" ? raw.data : raw;
    return {
      id: String(raw.id || d.id || `${ep.id}-node-${idx + 1}`),
      label: String(d.name || d.label || `${ep.method} ${ep.route_path}`),
      type: String(d.category || d.label || "OPERATION"),
      code: String(d.code || ""),
      filepath: String(d.filepath || ep.filepath),
      start_line: Number(d.start_line || ep.start_line || 1),
    };
  });

  const edgesDigest = (ep.flow_edges || []).slice(0, 60).map((rawEdge) => {
    const d =
      rawEdge.data && typeof rawEdge.data === "object" ? rawEdge.data : {};
    return {
      source: String(rawEdge.source || ""),
      target: String(rawEdge.target || ""),
      type: String(
        d.flowLabel ||
          rawEdge.flow_label ||
          d.edgeType ||
          rawEdge.edge_type ||
          rawEdge.type ||
          "FLOW"
      ),
    };
  });

  if (nodesDigest.length === 0) {
    nodesDigest.push({
      id: `${ep.id}-entry`,
      label: `${ep.method} ${ep.route_path}`,
      type: "ENTRYPOINT",
      code: `${ep.handler_name}(${ep.request_params.join(", ")})`,
      filepath: ep.filepath,
      start_line: ep.start_line,
    });
  }

  return { nodesDigest, edgesDigest };
}

interface EndpointFlowCanvasProps {
  endpoint: ApiEndpointOperationDossier;
  embedded?: boolean;
  onJumpToIde: (filepath?: string, line?: number, findingId?: string) => void;
}

const EndpointFlowCanvasInner: React.FC<EndpointFlowCanvasProps> = ({
  endpoint,
  embedded = false,
  onJumpToIde,
}) => {
  const setStoreReactFlowInstance = useAuditStore(
    (s) => s.setReactFlowInstance
  );
  const [rfInstance, setRfInstance] = useState<any | null>(null);

  const primaryFindingId = endpoint.linked_finding_ids?.[0];

  const { flowNodes, flowEdges } = useMemo(() => {
    const rawNodes = Array.isArray(endpoint.flow_nodes)
      ? endpoint.flow_nodes
      : [];
    const rawEdges = Array.isArray(endpoint.flow_edges)
      ? endpoint.flow_edges
      : [];

    const nodesOut: Node[] = [];
    const edgesOut: Edge[] = [];

    if (rawNodes.length > 0) {
      rawNodes.forEach((raw, idx) => {
        const d =
          raw.data && typeof raw.data === "object" ? raw.data : (raw as any);
        const stepNum = Number(d.stepNumber || d.step_index || idx + 1);
        const cat = String(d.category || "").toUpperCase();
        const isSan = Boolean(
          d.is_sanitizer ||
            cat === "AUTH_GUARD" ||
            cat === "INPUT_VALIDATION"
        );
        const isSink = Boolean(
          d.is_sink ||
            cat === "OS_COMMAND_EXEC" ||
            cat === "DATABASE_WRITE"
        );
        const trustZoneTone =
          cat === "ENTRYPOINT"
            ? "SKY"
            : isSan
            ? "EMERALD"
            : isSink
            ? "CRIMSON"
            : cat === "EXTERNAL_HTTP_OR_AI" ||
              cat === "FILESYSTEM_IO" ||
              cat === "SECRET_OR_CRYPTO"
            ? "AMBER"
            : "SKY";
        const trustZoneLabel =
          cat === "ENTRYPOINT"
            ? `ENTRYPOINT · ${endpoint.method}`
            : cat === "RESPONSE"
            ? "HTTP RESPONSE"
            : cat
            ? cat.replace(/_/g, " ")
            : "OPERATION";

        const nodeId = String(raw.id || d.id || `${endpoint.id}-node-${idx + 1}`);
        const fp = String(d.filepath || endpoint.filepath || "workspace");
        const ln = Number(d.start_line || endpoint.start_line || 1);

        nodesOut.push({
          id: nodeId,
          type: "cpgNode",
          position: { x: 24 + idx * 320, y: 36 },
          data: {
            ...d,
            id: nodeId,
            label: d.label || (idx === 0 ? "Entry" : "Call"),
            name: d.name || `${endpoint.method} ${endpoint.route_path}`,
            code: d.code || `${endpoint.handler_name}()`,
            filepath: fp,
            start_line: ln,
            end_line: Number(d.end_line || ln),
            is_source: Boolean(d.is_source ?? idx === 0),
            is_sink: isSink,
            is_sanitizer: isSan,
            stepNumber: stepNum,
            trustZoneLabel,
            trustZoneTone,
            trustZoneActionHint: "Click -> IDE",
            onNodeCardClick: (nd: any) => {
              onJumpToIde(
                nd?.filepath || fp,
                Number(nd?.start_line || ln),
                primaryFindingId
              );
            },
          },
        });
      });

      rawEdges.forEach((rawEdge, idx) => {
        const d =
          rawEdge.data && typeof rawEdge.data === "object"
            ? rawEdge.data
            : ({} as Record<string, any>);
        const eType = String(
          d.edgeType || rawEdge.edge_type || rawEdge.type || "CFG_NEXT"
        );
        const stepIdx = Number(d.stepIndex || rawEdge.step_index || idx + 1);
        const rawLbl = String(d.flowLabel || rawEdge.flow_label || "");
        const resolved = resolveDirectionalEdgeMeta(eType, {
          flowLabel: rawLbl || undefined,
          stepIndex: stepIdx,
        });

        edgesOut.push({
          id: String(rawEdge.id || `${endpoint.id}-edge-${idx + 1}`),
          source: String(rawEdge.source),
          target: String(rawEdge.target),
          sourceHandle: String(rawEdge.sourceHandle || "right-src"),
          targetHandle: String(rawEdge.targetHandle || "left-tgt"),
          type: "directionalFlow",
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: resolved.strokeColor,
            width: 18,
            height: 18,
          },
          data: {
            edgeType: eType,
            stepIndex: stepIdx,
            flowLabel: resolved.flowLabel,
            pathShape: "smoothstep",
            isAnimatedPulse: resolved.isAnimatedPulse,
            alwaysShowFullPill: true,
            strokeColor: resolved.strokeColor,
            badgeTone: resolved.badgeTone,
          } satisfies DirectionalFlowEdgeData,
        });
      });
    } else {
      // Fallback LR entry -> exit topology when flow_nodes is empty
      const entryId = `${endpoint.id}-fallback-entry`;
      const exitId = `${endpoint.id}-fallback-exit`;
      nodesOut.push(
        {
          id: entryId,
          type: "cpgNode",
          position: { x: 24, y: 36 },
          data: {
            id: entryId,
            label: "Entry",
            name: `${endpoint.method} ${endpoint.route_path}`,
            code: `${endpoint.handler_name}(${endpoint.request_params.join(", ")})`,
            filepath: endpoint.filepath,
            start_line: endpoint.start_line,
            end_line: endpoint.start_line,
            is_source: true,
            is_sink: false,
            is_sanitizer: false,
            stepNumber: 1,
            trustZoneLabel: `ENTRYPOINT · ${endpoint.method}`,
            trustZoneTone: "SKY",
            trustZoneActionHint: "Click -> IDE",
            onNodeCardClick: () =>
              onJumpToIde(
                endpoint.filepath,
                endpoint.start_line,
                primaryFindingId
              ),
          },
        },
        {
          id: exitId,
          type: "cpgNode",
          position: { x: 344, y: 36 },
          data: {
            id: exitId,
            label: "Return",
            name: `Response (${endpoint.response_type || "HTTP Response"})`,
            code: `return from ${endpoint.handler_name}()`,
            filepath: endpoint.filepath,
            start_line: endpoint.end_line || endpoint.start_line,
            end_line: endpoint.end_line || endpoint.start_line,
            is_source: false,
            is_sink: false,
            is_sanitizer: false,
            stepNumber: 2,
            trustZoneLabel: "HTTP RESPONSE",
            trustZoneTone: "SKY",
            trustZoneActionHint: "Click -> IDE",
            onNodeCardClick: () =>
              onJumpToIde(
                endpoint.filepath,
                endpoint.end_line || endpoint.start_line,
                primaryFindingId
              ),
          },
        }
      );
      edgesOut.push({
        id: `${endpoint.id}-fallback-edge-1`,
        source: entryId,
        target: exitId,
        sourceHandle: "right-src",
        targetHandle: "left-tgt",
        type: "directionalFlow",
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: "#0e7490",
          width: 18,
          height: 18,
        },
        data: {
          edgeType: "CFG_NEXT",
          stepIndex: 1,
          flowLabel: "① RESPONSE ▶",
          pathShape: "smoothstep",
          isAnimatedPulse: false,
          alwaysShowFullPill: true,
          strokeColor: "#0e7490",
          badgeTone: "CYAN",
        } satisfies DirectionalFlowEdgeData,
      });
    }

    return { flowNodes: nodesOut, flowEdges: edgesOut };
  }, [endpoint, onJumpToIde, primaryFindingId]);

  const handleFitFlow = useCallback(() => {
    if (rfInstance && typeof rfInstance.fitView === "function") {
      rfInstance.fitView({ padding: 0.18, duration: 260 });
    }
  }, [rfInstance]);

  useEffect(() => {
    if (!rfInstance || typeof rfInstance.fitView !== "function") return;
    const raf = window.requestAnimationFrame(() => {
      try {
        rfInstance.fitView({ padding: 0.18, duration: 220 });
      } catch {}
    });
    return () => window.cancelAnimationFrame(raf);
  }, [endpoint.id, flowNodes.length, rfInstance]);

  return (
    <div className="rounded-2xl bg-white border border-slate-300 shadow-sm overflow-hidden">
      <div className="px-3.5 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-sky-700" />
            <span>Interactive CPG Endpoint Execution Flow (LR)</span>
          </span>
          <span className="px-2 py-0.5 rounded-full bg-white border border-slate-300 text-[10px] font-mono font-bold text-slate-700">
            {flowNodes.length} Nodes • {flowEdges.length} Directional Hops
          </span>
          <span className="text-[11px] text-slate-600 hidden sm:inline">
            Click any node card to open its exact handler or call site in Stage 2 IDE
          </span>
        </div>

        <button
          type="button"
          onClick={handleFitFlow}
          className="px-2.5 py-1 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 text-xs font-bold flex items-center gap-1.5 transition-colors"
        >
          <Maximize2 className="w-3.5 h-3.5 text-sky-700" />
          <span>Fit Flow</span>
        </button>
      </div>

      <div style={{ height: 300 }} className="w-full bg-slate-50 relative">
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          nodeTypes={endpointNodeTypes}
          edgeTypes={endpointEdgeTypes}
          onInit={(inst) => {
            setRfInstance(inst);
            if (!embedded) {
              setStoreReactFlowInstance(inst);
            }
            try {
              inst.fitView({ padding: 0.18, duration: 0 });
            } catch {}
          }}
          onNodeClick={(_evt, node) => {
            onJumpToIde(
              node.data?.filepath || endpoint.filepath,
              Number(node.data?.start_line || endpoint.start_line || 1),
              primaryFindingId
            );
          }}
          fitView
          fitViewOptions={{ padding: 0.18 }}
          minZoom={0.25}
          maxZoom={1.85}
          nodesDraggable={false}
          nodesConnectable={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#cbd5e1" gap={18} size={1.2} />
          <Controls
            showInteractive={false}
            className="!bg-white !border-slate-300 !shadow-sm"
          />
        </ReactFlow>
      </div>
    </div>
  );
};

export interface ApiOperationsExplorerViewProps {
  embedded?: boolean;
}

export function ApiOperationsExplorerView({
  embedded = false,
}: ApiOperationsExplorerViewProps) {
  const apiOperationsReport = useAuditStore((s) => s.apiOperationsReport);
  const isLoadingApiOperations = useAuditStore((s) => s.isLoadingApiOperations);
  const fetchApiOperationsState = useAuditStore(
    (s) => s.fetchApiOperationsState
  );
  const projectPath = useAuditStore((s) => s.projectPath);
  const findings = useAuditStore((s) => s.findings);
  const selectFinding = useAuditStore((s) => s.selectFinding);
  const jumpToBestFixLocation = useAuditStore((s) => s.jumpToBestFixLocation);
  const openCodeLocationInIde = useAuditStore((s) => s.openCodeLocationInIde);
  const setAiDrawerOpen = useAuditStore((s) => s.setAiDrawerOpen);
  const explainCurrentGraphWithAi = useAuditStore(
    (s) => s.explainCurrentGraphWithAi
  );
  const aiIsBusy = useAuditStore((s) => s.aiIsBusy);

  const [isMounted, setIsMounted] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [methodFilter, setMethodFilter] = useState<HttpMethodFilter>("ALL");
  const [categoryFilter, setCategoryFilter] =
    useState<CategoryFilterKey>("ALL");
  const [selectedEndpointId, setSelectedEndpointId] = useState<string | null>(
    null
  );

  useEffect(() => {
    setIsMounted(true);
  }, []);

  useEffect(() => {
    if (!apiOperationsReport && !isLoadingApiOperations) {
      void fetchApiOperationsState(projectPath || undefined);
    }
  }, [
    apiOperationsReport,
    isLoadingApiOperations,
    fetchApiOperationsState,
    projectPath,
  ]);

  const endpoints = useMemo(
    () => apiOperationsReport?.endpoints || [],
    [apiOperationsReport]
  );

  const unauthenticatedMutatingCount = useMemo(
    () =>
      endpoints.filter(
        (ep) => ep.is_mutating && ep.auth_status === "UNAUTHENTICATED"
      ).length,
    [endpoints]
  );

  const findingsById = useMemo(() => {
    const map = new Map<string, Finding>();
    for (const f of findings) {
      if (f && f.id) {
        map.set(f.id, f);
      }
    }
    return map;
  }, [findings]);

  const filteredEndpoints = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return endpoints.filter((ep) => {
      if (
        methodFilter !== "ALL" &&
        ep.method.toUpperCase() !== methodFilter
      ) {
        return false;
      }

      if (categoryFilter === "UNAUTHENTICATED") {
        if (ep.auth_status !== "UNAUTHENTICATED") return false;
      } else if (categoryFilter === "VULNERABLE") {
        if (
          ep.linked_findings_count <= 0 &&
          ep.linked_finding_ids.length === 0
        ) {
          return false;
        }
      } else if (categoryFilter !== "ALL") {
        const hasCat =
          ep.operation_categories.includes(categoryFilter) ||
          ep.operations.some((op) => op.category === categoryFilter);
        if (!hasCat) return false;
      }

      if (!q) return true;

      if (
        ep.route_path.toLowerCase().includes(q) ||
        ep.handler_name.toLowerCase().includes(q) ||
        ep.filepath.toLowerCase().includes(q) ||
        ep.framework.toLowerCase().includes(q)
      ) {
        return true;
      }

      return ep.operations.some(
        (op) =>
          op.target_resource.toLowerCase().includes(q) ||
          op.operation_verb.toLowerCase().includes(q) ||
          op.function_name.toLowerCase().includes(q)
      );
    });
  }, [endpoints, methodFilter, categoryFilter, searchQuery]);

  useEffect(() => {
    if (filteredEndpoints.length === 0) {
      return;
    }
    if (
      !selectedEndpointId ||
      !filteredEndpoints.some((ep) => ep.id === selectedEndpointId)
    ) {
      setSelectedEndpointId(filteredEndpoints[0].id);
    }
  }, [filteredEndpoints, selectedEndpointId]);

  const selectedEndpoint = useMemo<ApiEndpointOperationDossier | null>(() => {
    if (filteredEndpoints.length === 0) return null;
    return (
      filteredEndpoints.find((ep) => ep.id === selectedEndpointId) ||
      filteredEndpoints[0]
    );
  }, [filteredEndpoints, selectedEndpointId]);

  const linkedFindingsForSelected = useMemo<Finding[]>(() => {
    if (!selectedEndpoint) return [];
    const resolved: Finding[] = [];
    for (const fid of selectedEndpoint.linked_finding_ids || []) {
      const f = findingsById.get(fid);
      if (f) resolved.push(f);
    }
    return resolved;
  }, [selectedEndpoint, findingsById]);

  const handleRefreshTrace = () => {
    void fetchApiOperationsState(projectPath || undefined);
  };

  const handleExportJson = () => {
    const payload = apiOperationsReport || {
      project_path: projectPath || "",
      total_endpoints: 0,
      endpoints: [],
    };
    downloadBlob(
      JSON.stringify(payload, null, 2),
      "application/json",
      "alastor-api-operations-report.json"
    );
  };

  const handleExportCsv = () => {
    const headers = [
      "Method",
      "Route Path",
      "Framework",
      "Handler",
      "Filepath",
      "Start Line",
      "Auth Status",
      "Auth Mechanisms",
      "Is Mutating",
      "Risk Level",
      "Operation Categories",
      "Operations Performed",
      "Linked Findings Count",
      "Plain English Story",
    ];
    const rows = endpoints.map((ep) => {
      const opsSummary = ep.operations
        .map(
          (op) =>
            `[${op.step_index}] ${op.category}: ${op.operation_verb} -> ${op.target_resource} (${op.filepath}:L${op.line_number})`
        )
        .join(" | ");
      return [
        ep.method,
        ep.route_path,
        ep.framework,
        ep.handler_name,
        ep.filepath,
        ep.start_line,
        ep.auth_status,
        ep.auth_mechanisms.join("; "),
        ep.is_mutating ? "TRUE" : "FALSE",
        ep.risk_level,
        ep.operation_categories.join("; "),
        opsSummary,
        ep.linked_findings_count,
        ep.plain_english_story,
      ]
        .map(escapeCsvCell)
        .join(",");
    });

    downloadBlob(
      [headers.join(","), ...rows].join("\n"),
      "text/csv;charset=utf-8",
      "alastor-api-operations-report.csv"
    );
  };

  const handleExplainEndpointAi = (ep: ApiEndpointOperationDossier) => {
    const { nodesDigest, edgesDigest } = buildEndpointFlowDigest(ep);
    setAiDrawerOpen(true, "GRAPH");
    void explainCurrentGraphWithAi({
      view_mode: "API_ENDPOINT_FLOW",
      finding_id: ep.linked_finding_ids?.[0] ?? null,
      nodes_digest: nodesDigest,
      edges_digest: edgesDigest,
    });
  };

  const containerCls = embedded
    ? "flex flex-col gap-4 text-slate-900 select-text"
    : "flex-1 flex flex-col min-w-0 min-h-0 h-full overflow-hidden bg-slate-50 p-4 gap-3.5 text-slate-900 select-text";

  return (
    <div className={containerCls}>
      {/* ================================================================= */}
      {/* TOP KPI & EXPORT STRIP                                            */}
      {/* ================================================================= */}
      <div className="rounded-2xl bg-white border border-slate-300 p-3.5 shadow-sm space-y-3 shrink-0">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2.5 flex-wrap">
            <div className="p-2 rounded-xl bg-sky-50 border border-sky-200 text-sky-800">
              <Compass className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-sm font-extrabold text-slate-900">
                  API Endpoints &amp; Inter-Procedural Operations Explorer
                </h2>
                {(apiOperationsReport?.frameworks_detected || []).map((fw) => (
                  <span
                    key={fw}
                    className="px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-900 border border-indigo-300 text-[10px] font-mono font-bold"
                  >
                    {fw}
                  </span>
                ))}
              </div>
              <p className="text-xs text-slate-700">
                Deterministic multi-framework HTTP route discovery with depth-4
                inter-procedural CPG call-chain tracing across DB, HTTP/AI, File
                I/O, OS Exec, Auth Guards &amp; active vulnerabilities.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              type="button"
              onClick={handleRefreshTrace}
              disabled={isLoadingApiOperations}
              className="px-3 py-1.5 rounded-xl bg-sky-700 hover:bg-sky-800 disabled:opacity-60 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm transition-colors"
            >
              {isLoadingApiOperations ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <RefreshCw className="w-3.5 h-3.5" />
              )}
              <span>Refresh Trace</span>
            </button>

            <button
              type="button"
              onClick={handleExportJson}
              className="px-3 py-1.5 rounded-xl bg-white hover:bg-slate-100 border border-slate-300 text-slate-900 text-xs font-bold flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-sky-700" />
              <span>Export JSON</span>
            </button>

            <button
              type="button"
              onClick={handleExportCsv}
              className="px-3 py-1.5 rounded-xl bg-white hover:bg-slate-100 border border-slate-300 text-slate-900 text-xs font-bold flex items-center gap-1.5 transition-colors"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-700" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* 6 KPI Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-2.5">
          <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
            <div className="text-[10px] font-mono font-bold uppercase text-slate-700 flex items-center justify-between">
              <span>Total API Endpoints</span>
              <Server className="w-3.5 h-3.5 text-sky-700" />
            </div>
            <div className="text-lg font-mono font-extrabold text-slate-900 mt-0.5">
              {apiOperationsReport?.total_endpoints ?? 0}
            </div>
            <div className="text-[10px] font-mono text-slate-600">
              {apiOperationsReport?.authenticated_count ?? 0} Auth •{" "}
              {apiOperationsReport?.unauthenticated_count ?? 0} Unauth
            </div>
          </div>

          <div className="p-2.5 rounded-xl bg-sky-50/70 border border-sky-200">
            <div className="text-[10px] font-mono font-bold uppercase text-sky-900 flex items-center justify-between">
              <span>DB Read / Write Routes</span>
              <Database className="w-3.5 h-3.5 text-sky-700" />
            </div>
            <div className="text-lg font-mono font-extrabold text-sky-950 mt-0.5">
              {apiOperationsReport?.db_endpoints_count ?? 0}
            </div>
            <div className="text-[10px] font-mono text-sky-900">
              SQL / ORM / Neo4j Cypher
            </div>
          </div>

          <div className="p-2.5 rounded-xl bg-indigo-50/70 border border-indigo-200">
            <div className="text-[10px] font-mono font-bold uppercase text-indigo-900 flex items-center justify-between">
              <span>Outbound HTTP / AI Routes</span>
              <Globe className="w-3.5 h-3.5 text-indigo-700" />
            </div>
            <div className="text-lg font-mono font-extrabold text-indigo-950 mt-0.5">
              {apiOperationsReport?.external_http_endpoints_count ?? 0}
            </div>
            <div className="text-[10px] font-mono text-indigo-900">
              REST / Webhook / LLM SDKs
            </div>
          </div>

          <div className="p-2.5 rounded-xl bg-purple-50/70 border border-purple-200">
            <div className="text-[10px] font-mono font-bold uppercase text-purple-900 flex items-center justify-between">
              <span>File I/O &amp; OS Exec Routes</span>
              <Terminal className="w-3.5 h-3.5 text-purple-700" />
            </div>
            <div className="text-lg font-mono font-extrabold text-purple-950 mt-0.5">
              {apiOperationsReport?.exec_or_fs_endpoints_count ?? 0}
            </div>
            <div className="text-[10px] font-mono text-purple-900">
              Filesystem &amp; Subprocess
            </div>
          </div>

          <div className="p-2.5 rounded-xl bg-amber-50/80 border border-amber-300">
            <div className="text-[10px] font-mono font-bold uppercase text-amber-950 flex items-center justify-between">
              <span>Unauthenticated Mutating</span>
              <AlertTriangle className="w-3.5 h-3.5 text-amber-800" />
            </div>
            <div className="text-lg font-mono font-extrabold text-amber-950 mt-0.5">
              {unauthenticatedMutatingCount}
            </div>
            <div className="text-[10px] font-mono text-amber-900">
              {apiOperationsReport?.mutating_endpoints_count ?? 0} Total
              Mutating
            </div>
          </div>

          <div className="p-2.5 rounded-xl bg-rose-50/80 border border-rose-300">
            <div className="text-[10px] font-mono font-bold uppercase text-rose-900 flex items-center justify-between">
              <span>Endpoints with Active Flaws</span>
              <ShieldAlert className="w-3.5 h-3.5 text-rose-700" />
            </div>
            <div className="text-lg font-mono font-extrabold text-rose-950 mt-0.5">
              {apiOperationsReport?.vulnerable_endpoints_count ?? 0}
            </div>
            <div className="text-[10px] font-mono text-rose-900">
              Correlated SAST / SCA / IaC
            </div>
          </div>
        </div>
      </div>

      {/* ================================================================= */}
      {/* SPLIT MASTER-DETAIL EXPLORER                                      */}
      {/* ================================================================= */}
      <div
        className={`grid grid-cols-1 lg:grid-cols-12 gap-3.5 ${
          embedded ? "min-h-[760px]" : "flex-1 min-h-0 overflow-hidden"
        }`}
      >
        {/* --------------------------------------------------------------- */}
        {/* LEFT MASTER INVENTORY                                           */}
        {/* --------------------------------------------------------------- */}
        <div
          className={`lg:col-span-4 xl:col-span-4 rounded-2xl bg-white border border-slate-300 shadow-sm flex flex-col overflow-hidden ${
            embedded ? "max-h-[920px]" : "min-h-0 h-full"
          }`}
        >
          {/* Search & Filter Controls */}
          <div className="p-3 bg-slate-50 border-b border-slate-200 space-y-2.5 shrink-0">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-600 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search route, handler, file, framework, or resource..."
                className="w-full h-8 bg-white border border-slate-300 rounded-lg pl-8 pr-7 text-xs font-mono text-slate-900 placeholder:text-slate-500 focus:outline-none focus:border-sky-700"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-900"
                  title="Clear search"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* HTTP Method Filter Pills */}
            <div className="flex items-center gap-1 flex-wrap">
              {METHOD_FILTERS.map((m) => {
                const active = methodFilter === m;
                return (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setMethodFilter(m)}
                    className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-extrabold border transition-colors ${
                      active
                        ? "bg-sky-700 text-white border-sky-800 shadow-sm"
                        : "bg-white text-slate-800 border-slate-300 hover:bg-slate-100"
                    }`}
                  >
                    {m}
                  </button>
                );
              })}
              <span className="ml-auto text-[10px] font-mono font-bold text-slate-700">
                {filteredEndpoints.length} / {endpoints.length}
              </span>
            </div>

            {/* Operation Category Filter Pills */}
            <div className="flex items-center gap-1 flex-wrap">
              {CATEGORY_FILTERS.map((cat) => {
                const active = categoryFilter === cat.id;
                return (
                  <button
                    key={cat.id}
                    type="button"
                    onClick={() => setCategoryFilter(cat.id)}
                    className={`px-2 py-0.5 rounded-md text-[9.5px] font-mono font-bold border transition-colors ${
                      active
                        ? "bg-indigo-700 text-white border-indigo-800 shadow-sm"
                        : "bg-white text-slate-700 border-slate-300 hover:bg-slate-100 hover:text-slate-950"
                    }`}
                  >
                    {cat.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Endpoint Cards List */}
          <div className="flex-1 overflow-y-auto p-2.5 space-y-2">
            {isLoadingApiOperations && endpoints.length === 0 ? (
              <div className="py-14 flex flex-col items-center justify-center gap-2 text-slate-700 font-mono text-xs">
                <Loader2 className="w-5 h-5 animate-spin text-sky-700" />
                <span>Tracing multi-framework routes &amp; CPG call chains...</span>
              </div>
            ) : filteredEndpoints.length === 0 ? (
              <div className="py-12 px-4 text-center space-y-2">
                <div className="text-xs font-bold text-slate-800">
                  {endpoints.length === 0
                    ? "No HTTP/API endpoints discovered in current target."
                    : "No endpoints match your active search or filters."}
                </div>
                <p className="text-[11px] text-slate-600">
                  {endpoints.length === 0
                    ? "Scan a FastAPI, Flask, Django, Next.js, Express, NestJS, Go, or Spring Boot repository or click Refresh Trace."
                    : "Reset the HTTP method or operation category filter pills above to inspect all routes."}
                </p>
              </div>
            ) : (
              filteredEndpoints.map((ep) => {
                const isSelected = selectedEndpoint?.id === ep.id;
                const authMeta = getAuthBadgeMeta(
                  ep.auth_status,
                  ep.is_mutating
                );
                return (
                  <button
                    key={ep.id}
                    type="button"
                    onClick={() => setSelectedEndpointId(ep.id)}
                    className={`w-full text-left p-3 rounded-xl border transition-all space-y-2 ${
                      isSelected
                        ? "bg-sky-50/80 border-sky-600 ring-2 ring-sky-500/25 shadow-sm"
                        : "bg-white border-slate-200 hover:border-slate-400 hover:bg-slate-50/70"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1.5 flex-wrap">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[10px] font-extrabold border shrink-0 ${getMethodBadgeClasses(
                            ep.method
                          )}`}
                        >
                          {ep.method}
                        </span>
                        <span className="font-mono text-xs font-extrabold text-slate-900 truncate">
                          {ep.route_path}
                        </span>
                      </div>

                      <span className="px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-900 border border-indigo-200 font-mono text-[9.5px] font-bold shrink-0">
                        {ep.framework}
                      </span>
                    </div>

                    <div className="flex items-center justify-between gap-2 text-[10.5px] font-mono text-slate-700">
                      <span className="truncate">
                        {ep.filepath}:L{ep.start_line}
                      </span>
                      <span className="font-semibold text-slate-800 shrink-0">
                        {ep.handler_name}()
                      </span>
                    </div>

                    <div className="flex items-center justify-between gap-1.5 flex-wrap pt-0.5">
                      <span
                        className={`px-1.5 py-0.5 rounded font-mono text-[9.5px] font-bold border ${authMeta.className}`}
                      >
                        {authMeta.label}
                      </span>

                      {ep.linked_findings_count > 0 ? (
                        <span className="px-2 py-0.5 rounded-full bg-rose-700 text-white border border-rose-800 font-mono text-[9.5px] font-extrabold">
                          {ep.linked_findings_count} Flaw
                          {ep.linked_findings_count === 1 ? "" : "s"}
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-900 border border-emerald-200 font-mono text-[9.5px] font-bold">
                          0 Flaws
                        </span>
                      )}
                    </div>

                    {ep.operation_categories.length > 0 && (
                      <div className="flex items-center gap-1 flex-wrap">
                        {ep.operation_categories.map((cat) => {
                          const chip = getCategoryChipMeta(cat);
                          return (
                            <span
                              key={cat}
                              className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold border ${chip.className}`}
                            >
                              {chip.shortLabel}
                            </span>
                          );
                        })}
                      </div>
                    )}
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* --------------------------------------------------------------- */}
        {/* RIGHT SELECTED ENDPOINT INSPECTOR                               */}
        {/* --------------------------------------------------------------- */}
        <div
          className={`lg:col-span-8 xl:col-span-8 rounded-2xl bg-white border border-slate-300 shadow-sm flex flex-col overflow-hidden ${
            embedded ? "" : "min-h-0 h-full"
          }`}
        >
          {!selectedEndpoint ? (
            <div className="flex-1 py-20 px-6 flex flex-col items-center justify-center text-center gap-2">
              <Compass className="w-8 h-8 text-sky-700" />
              <div className="text-sm font-bold text-slate-900">
                Select an API Endpoint to Inspect Its Traced CPG Operations
              </div>
              <p className="text-xs text-slate-600 max-w-md">
                Choose any discovered HTTP route from the inventory on the left
                to visualize its directional execution flow, ordered operations
                timeline, authentication guards, and correlated security
                findings.
              </p>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {/* 1. Endpoint Header & Plain-English Operation Story */}
              <div className="rounded-2xl bg-slate-50 border border-slate-200 p-4 space-y-3">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`px-2.5 py-0.5 rounded-md font-mono text-xs font-extrabold border ${getMethodBadgeClasses(
                          selectedEndpoint.method
                        )}`}
                      >
                        {selectedEndpoint.method}
                      </span>
                      <h3 className="font-mono text-base font-extrabold text-slate-900 break-all">
                        {selectedEndpoint.route_path}
                      </h3>
                      <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-900 border border-indigo-300 font-mono text-[10px] font-bold">
                        {selectedEndpoint.framework}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[10px] font-extrabold border ${getRiskBadgeClasses(
                          selectedEndpoint.risk_level
                        )}`}
                      >
                        RISK: {selectedEndpoint.risk_level}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${
                          getAuthBadgeMeta(
                            selectedEndpoint.auth_status,
                            selectedEndpoint.is_mutating
                          ).className
                        }`}
                      >
                        {
                          getAuthBadgeMeta(
                            selectedEndpoint.auth_status,
                            selectedEndpoint.is_mutating
                          ).label
                        }
                      </span>
                    </div>

                    <div className="text-xs font-mono text-slate-800 flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-slate-900">
                        Handler:{" "}
                        {selectedEndpoint.handler_name}(
                        {selectedEndpoint.request_params.join(", ")})
                      </span>
                      <span className="text-slate-600">•</span>
                      <span className="text-sky-900 font-semibold">
                        {selectedEndpoint.filepath}:L
                        {selectedEndpoint.start_line}
                        {selectedEndpoint.end_line >
                        selectedEndpoint.start_line
                          ? `–L${selectedEndpoint.end_line}`
                          : ""}
                      </span>
                      {selectedEndpoint.response_type && (
                        <>
                          <span className="text-slate-600">•</span>
                          <span className="text-emerald-900 font-semibold">
                            Returns: {selectedEndpoint.response_type}
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-wrap shrink-0">
                    <button
                      type="button"
                      onClick={() =>
                        openCodeLocationInIde(
                          selectedEndpoint.filepath,
                          selectedEndpoint.start_line,
                          selectedEndpoint.linked_finding_ids?.[0]
                        )
                      }
                      className="px-3 py-1.5 rounded-xl bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm transition-colors"
                    >
                      <Code2 className="w-3.5 h-3.5" />
                      <span>Open Handler in IDE</span>
                    </button>

                    <button
                      type="button"
                      disabled={aiIsBusy}
                      onClick={() => handleExplainEndpointAi(selectedEndpoint)}
                      className="px-3 py-1.5 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-60 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm transition-colors"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Explain Endpoint Flow with AI</span>
                    </button>
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-white border border-slate-200 text-xs text-slate-800 leading-relaxed">
                  <span className="font-mono text-[10px] font-extrabold uppercase tracking-wider text-sky-900 block mb-0.5">
                    Plain-English Operation Story
                  </span>
                  {selectedEndpoint.plain_english_story}
                </div>
              </div>

              {/* 2. Unauthenticated Mutating Warning Banner */}
              {selectedEndpoint.is_mutating &&
                selectedEndpoint.auth_status === "UNAUTHENTICATED" && (
                  <div className="rounded-2xl bg-rose-50 border border-rose-400 p-3.5 flex items-start justify-between gap-3 flex-wrap">
                    <div className="flex items-start gap-2.5 max-w-3xl">
                      <AlertTriangle className="w-4 h-4 text-rose-800 shrink-0 mt-0.5" />
                      <div className="space-y-0.5">
                        <div className="text-xs font-extrabold text-rose-950">
                          Unauthenticated State-Mutating Endpoint Detected (
                          {selectedEndpoint.method}{" "}
                          {selectedEndpoint.route_path})
                        </div>
                        <p className="text-xs text-rose-900 leading-relaxed">
                          This route performs state-modifying operations without
                          an explicit authentication or authorization guard
                          detected in its route decorator, middleware chain, or
                          handler dependencies. Verify whether caller identity
                          verification (JWT, session dependency, RBAC guard, or
                          HMAC webhook verification) is required.
                        </p>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        openCodeLocationInIde(
                          selectedEndpoint.filepath,
                          selectedEndpoint.start_line,
                          selectedEndpoint.linked_finding_ids?.[0]
                        )
                      }
                      className="px-2.5 py-1.5 rounded-lg bg-rose-700 hover:bg-rose-800 text-white text-xs font-bold flex items-center gap-1 shrink-0"
                    >
                      <Crosshair className="w-3.5 h-3.5" />
                      <span>Audit Guard in IDE</span>
                    </button>
                  </div>
                )}

              {/* 3. Interactive Directional ReactFlow Canvas (height: 300px) */}
              {isMounted && (
                <ReactFlowProvider>
                  <EndpointFlowCanvasInner
                    endpoint={selectedEndpoint}
                    embedded={embedded}
                    onJumpToIde={openCodeLocationInIde}
                  />
                </ReactFlowProvider>
              )}

              {/* 4. Ordered Operations Performed Table / Timeline */}
              <div className="rounded-2xl bg-white border border-slate-300 overflow-hidden shadow-sm">
                <div className="px-4 py-2.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
                  <div className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5">
                    <ArrowRight className="w-3.5 h-3.5 text-emerald-700" />
                    <span>
                      Ordered Inter-Procedural Operations Performed (
                      {selectedEndpoint.operations.length})
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-700">
                    Bounded depth-4 call-graph trace from{" "}
                    <strong>{selectedEndpoint.handler_name}()</strong>
                  </span>
                </div>

                {selectedEndpoint.operations.length === 0 ? (
                  <div className="p-5 text-xs text-slate-700 font-mono bg-white flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-700 shrink-0" />
                    <span>
                      0 external database, network, filesystem, or OS command
                      sinks traced — handler executes pure in-memory logic and
                      response serialization.
                    </span>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="bg-slate-100 border-b border-slate-200 text-[10px] font-mono font-extrabold uppercase text-slate-800">
                          <th className="py-2.5 px-3">Step</th>
                          <th className="py-2.5 px-3">Category</th>
                          <th className="py-2.5 px-3">
                            Verb &amp; Target Resource
                          </th>
                          <th className="py-2.5 px-3">
                            Inter-Procedural Call Chain
                          </th>
                          <th className="py-2.5 px-3">Location &amp; Snippet</th>
                          <th className="py-2.5 px-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200">
                        {selectedEndpoint.operations.map(
                          (op: ApiOperationItem) => {
                            const catMeta = getCategoryChipMeta(op.category);
                            return (
                              <tr
                                key={op.id}
                                className="hover:bg-slate-50 transition-colors align-top"
                              >
                                <td className="py-2.5 px-3 font-mono font-black text-slate-900 whitespace-nowrap">
                                  {formatCircledStep(op.step_index) ||
                                    `(${op.step_index})`}
                                </td>
                                <td className="py-2.5 px-3 whitespace-nowrap">
                                  <div className="flex flex-col gap-1 items-start">
                                    <span
                                      className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${catMeta.className}`}
                                    >
                                      {op.category}
                                    </span>
                                    {op.is_mutating && (
                                      <span className="px-1.5 py-0.2 rounded bg-amber-100 text-amber-950 border border-amber-300 font-mono text-[9px] font-bold">
                                        MUTATING
                                      </span>
                                    )}
                                  </div>
                                </td>
                                <td className="py-2.5 px-3">
                                  <div className="font-mono font-bold text-slate-900">
                                    {op.operation_verb}
                                  </div>
                                  <div className="text-[11px] font-mono text-slate-700 break-all">
                                    {op.target_resource}
                                  </div>
                                  {op.risk_note && (
                                    <div className="mt-1 text-[10.5px] text-rose-900 bg-rose-50 border border-rose-200 rounded px-1.5 py-0.5">
                                      {op.risk_note}
                                    </div>
                                  )}
                                </td>
                                <td className="py-2.5 px-3 font-mono text-[11px] text-indigo-950">
                                  {formatCallChain(op.call_chain)}
                                </td>
                                <td className="py-2.5 px-3 max-w-xs">
                                  <div className="font-mono text-[11px] font-bold text-sky-900 mb-1">
                                    {op.filepath}:L{op.line_number}
                                  </div>
                                  <div className="px-2 py-1 rounded bg-slate-100 border border-slate-200 font-mono text-[10.5px] text-slate-900 break-all line-clamp-2">
                                    {op.code_snippet}
                                  </div>
                                </td>
                                <td className="py-2.5 px-3 text-right whitespace-nowrap">
                                  <button
                                    type="button"
                                    onClick={() =>
                                      openCodeLocationInIde(
                                        op.filepath,
                                        op.line_number,
                                        selectedEndpoint.linked_finding_ids?.[0]
                                      )
                                    }
                                    className="px-2.5 py-1 rounded-lg bg-white hover:bg-sky-50 border border-slate-300 hover:border-sky-600 text-slate-900 text-[11px] font-bold inline-flex items-center gap-1 transition-colors"
                                  >
                                    <Crosshair className="w-3 h-3 text-sky-700" />
                                    <span>Inspect</span>
                                  </button>
                                </td>
                              </tr>
                            );
                          }
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* 5. Inputs, Auth Guards & Linked CPG Findings Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
                {/* Column 1: Request Parameters & Input Surface */}
                <div className="rounded-2xl bg-slate-50 border border-slate-200 p-3.5 space-y-2.5">
                  <div className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5">
                    <FileCode2 className="w-3.5 h-3.5 text-sky-700" />
                    <span>
                      Request Inputs &amp; Params (
                      {selectedEndpoint.request_params.length})
                    </span>
                  </div>
                  {selectedEndpoint.request_params.length === 0 ? (
                    <p className="text-xs text-slate-700 font-mono">
                      No query, path, or body parameters declared on handler.
                    </p>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {selectedEndpoint.request_params.map((param) => (
                        <span
                          key={param}
                          className="px-2 py-0.5 rounded-md bg-white border border-slate-300 font-mono text-[11px] font-bold text-slate-900"
                        >
                          {param}
                        </span>
                      ))}
                    </div>
                  )}
                  {selectedEndpoint.response_type && (
                    <div className="pt-2 border-t border-slate-200 text-[11px] font-mono text-slate-700">
                      <strong className="text-slate-900">Response Schema:</strong>{" "}
                      {selectedEndpoint.response_type}
                    </div>
                  )}
                </div>

                {/* Column 2: Auth Guards & Helper Call Graph */}
                <div className="rounded-2xl bg-slate-50 border border-slate-200 p-3.5 space-y-2.5">
                  <div className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-emerald-700" />
                    <span>Auth Guards &amp; Traced Callees</span>
                  </div>

                  <div className="space-y-1.5">
                    <div className="text-[10px] font-mono font-bold uppercase text-slate-700">
                      Auth Mechanisms ({selectedEndpoint.auth_mechanisms.length})
                    </div>
                    {selectedEndpoint.auth_mechanisms.length === 0 ? (
                      <div className="text-xs font-mono text-amber-950 bg-amber-50 border border-amber-300 rounded-lg px-2.5 py-1">
                        None detected ({selectedEndpoint.auth_status})
                      </div>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {selectedEndpoint.auth_mechanisms.map((mech) => (
                          <span
                            key={mech}
                            className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 font-mono text-[10.5px] font-bold text-emerald-900 flex items-center gap-1"
                          >
                            <KeyRound className="w-3 h-3 text-emerald-700" />
                            <span>{mech}</span>
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="space-y-1.5 pt-1 border-t border-slate-200">
                    <div className="text-[10px] font-mono font-bold uppercase text-slate-700">
                      Called Helper Functions (
                      {selectedEndpoint.calls_functions.length})
                    </div>
                    {selectedEndpoint.calls_functions.length === 0 ? (
                      <div className="text-xs font-mono text-slate-600">
                        Direct inline handler execution
                      </div>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {selectedEndpoint.calls_functions.map((fn) => (
                          <span
                            key={fn}
                            className="px-2 py-0.5 rounded bg-white border border-slate-300 font-mono text-[10.5px] text-indigo-950 font-semibold"
                          >
                            {fn.endsWith(")") ? fn : `${fn}()`}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Column 3: Linked CPG Security Findings */}
                <div className="rounded-2xl bg-slate-50 border border-slate-200 p-3.5 space-y-2.5">
                  <div className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-rose-700" />
                    <span>
                      Linked CPG Findings (
                      {selectedEndpoint.linked_findings_count})
                    </span>
                  </div>

                  {selectedEndpoint.linked_findings_count === 0 &&
                  linkedFindingsForSelected.length === 0 ? (
                    <div className="p-2.5 rounded-xl bg-emerald-50 border border-emerald-300 text-xs text-emerald-950 font-semibold flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-700 shrink-0" />
                      <span>
                        0 active SAST, SCA, IaC, or Secret findings correlated
                        to this endpoint or its downstream callees.
                      </span>
                    </div>
                  ) : linkedFindingsForSelected.length > 0 ? (
                    <div className="space-y-2">
                      {linkedFindingsForSelected.map((f) => {
                        const sink =
                          f.path_nodes && f.path_nodes.length > 0
                            ? f.path_nodes[f.path_nodes.length - 1]
                            : null;
                        const locFp =
                          f.best_fix_location?.filepath ||
                          sink?.filepath ||
                          selectedEndpoint.filepath;
                        const locLn =
                          f.best_fix_location?.line ||
                          sink?.start_line ||
                          selectedEndpoint.start_line;
                        return (
                          <button
                            key={f.id}
                            type="button"
                            onClick={() => {
                              if (f.best_fix_location) {
                                jumpToBestFixLocation(f);
                              } else {
                                selectFinding(f);
                              }
                            }}
                            className="w-full text-left p-2.5 rounded-xl bg-white hover:bg-rose-50/70 border border-rose-300 hover:border-rose-500 transition-colors space-y-1 shadow-sm"
                          >
                            <div className="flex items-center justify-between gap-1.5">
                              <span className="px-1.5 py-0.5 rounded bg-rose-700 text-white font-mono text-[9.5px] font-extrabold">
                                {f.severity} {f.cwe_id ? `• ${f.cwe_id}` : ""}
                              </span>
                              <span className="font-mono text-[10px] font-bold text-rose-900">
                                Inspect BFL →
                              </span>
                            </div>
                            <div className="text-xs font-bold text-slate-900 line-clamp-2">
                              {f.title}
                            </div>
                            <div className="text-[10.5px] font-mono text-slate-700 truncate">
                              {locFp}:L{locLn}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      {selectedEndpoint.linked_finding_ids.map((fid) => (
                        <button
                          key={fid}
                          type="button"
                          onClick={() =>
                            openCodeLocationInIde(
                              selectedEndpoint.filepath,
                              selectedEndpoint.start_line,
                              fid
                            )
                          }
                          className="w-full text-left px-2.5 py-1.5 rounded-lg bg-white hover:bg-rose-50 border border-rose-300 font-mono text-[11px] font-bold text-rose-900 flex items-center justify-between"
                        >
                          <span className="truncate">{fid}</span>
                          <span>Open →</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default ApiOperationsExplorerView;
