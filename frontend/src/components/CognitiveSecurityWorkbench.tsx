"use client";

import React, {
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import ReactFlow, {
  Background,
  Controls,
  Edge,
  Handle,
  MarkerType,
  MiniMap,
  Node,
  NodeProps,
  Position,
  ReactFlowInstance,
  ReactFlowProvider,
} from "reactflow";
import "reactflow/dist/style.css";
import dagre from "@dagrejs/dagre";

import { useAuditStore } from "@/store/useAuditStore";
import {
  AdversarialFindingVerdict,
  BaselineDisposition,
  ExploitChainHop,
  ExploitChainHopType,
  ExploitChainItem,
  Finding,
  PlaybookDefinitionItem,
  RepoBaselineItem,
} from "@/types/cpg";
import {
  AlertTriangle,
  ArrowUpRight,
  Brain,
  CheckCircle2,
  Code2,
  Compass,
  Crosshair,
  Filter,
  GitBranch,
  Layers,
  Loader2,
  Maximize2,
  Play,
  RefreshCw,
  Scale,
  Search,
  ShieldAlert,
  Sparkles,
  Wrench,
} from "lucide-react";

const CHAIN_NODE_WIDTH = 256;
const CHAIN_NODE_HEIGHT = 108;

type WorkbenchTab = "HUNTER" | "VERIFIER" | "CHAINS";

interface ExploitChainNodeData {
  stepNumber: number;
  hopType: ExploitChainHopType;
  title: string;
  filepath: string;
  line: number;
  cweOrRule: string;
  communityId?: string | null;
  linkedFindingId?: string | null;
  detail: string;
}

function formatShortPath(filepath?: string | null): string {
  const clean = (filepath || "").replace(/\\/g, "/").trim();
  if (!clean) return "";
  const parts = clean.split("/").filter(Boolean);
  if (parts.length <= 2) return clean;
  return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
}

function getSeverityBadgeClass(severity?: string | null): string {
  switch ((severity || "").toUpperCase()) {
    case "CRITICAL":
      return "bg-rose-700 text-white border-rose-800";
    case "HIGH":
      return "bg-rose-50 text-rose-950 border-rose-300";
    case "MEDIUM":
      return "bg-amber-50 text-amber-950 border-amber-300";
    case "LOW":
    default:
      return "bg-sky-50 text-sky-950 border-sky-300";
  }
}

function getBaselineStatusMeta(status: BaselineDisposition): {
  label: string;
  className: string;
} {
  switch (status) {
    case "COVERED_CLEAN":
      return {
        label: "COVERED CLEAN",
        className: "bg-emerald-50 text-emerald-900 border-emerald-300",
      };
    case "FINDING_DETECTED":
      return {
        label: "FINDING DETECTED",
        className: "bg-rose-50 text-rose-950 border-rose-300",
      };
    case "UNDISPOSED_GAP":
    default:
      return {
        label: "UNDISPOSED GAP",
        className: "bg-amber-50 text-amber-950 border-amber-300",
      };
  }
}

function getHopTypeStyle(hopType: ExploitChainHopType): {
  label: string;
  cardClasses: string;
  pillClasses: string;
  dotClasses: string;
  minimapColor: string;
} {
  switch (hopType) {
    case "ENTRYPOINT":
      return {
        label: "ENTRYPOINT",
        cardClasses: "bg-sky-50 border-sky-400 text-sky-950",
        pillClasses: "bg-sky-700 text-white",
        dotClasses: "!bg-sky-700",
        minimapColor: "#0369a1",
      };
    case "LEAKED_SECRET":
      return {
        label: "LEAKED SECRET",
        cardClasses: "bg-rose-50 border-rose-400 text-rose-950",
        pillClasses: "bg-rose-700 text-white",
        dotClasses: "!bg-rose-700",
        minimapColor: "#be123c",
      };
    case "VULNERABILITY":
      return {
        label: "VULNERABILITY",
        cardClasses: "bg-amber-50 border-amber-400 text-amber-950",
        pillClasses: "bg-amber-700 text-white",
        dotClasses: "!bg-amber-700",
        minimapColor: "#b45309",
      };
    case "COMMUNITY_BRIDGE":
      return {
        label: "COMMUNITY BRIDGE",
        cardClasses: "bg-indigo-50 border-indigo-400 text-indigo-950",
        pillClasses: "bg-indigo-700 text-white",
        dotClasses: "!bg-indigo-700",
        minimapColor: "#4338ca",
      };
    case "CROWN_JEWEL":
    default:
      return {
        label: "CROWN JEWEL",
        cardClasses: "bg-violet-50 border-violet-400 text-violet-950",
        pillClasses: "bg-violet-700 text-white",
        dotClasses: "!bg-violet-700",
        minimapColor: "#6d28d9",
      };
  }
}

const ExploitChainHopCardNode = memo(
  ({ data }: NodeProps<ExploitChainNodeData>) => {
    const style = getHopTypeStyle(data.hopType);
    const hasLoc = Boolean((data.filepath || "").trim());

    return (
      <div
        style={{ width: CHAIN_NODE_WIDTH, minHeight: CHAIN_NODE_HEIGHT }}
        className={`rounded-xl border shadow-sm px-3 py-2 transition-shadow hover:shadow-md ${
          hasLoc ? "cursor-pointer" : "cursor-default"
        } ${style.cardClasses}`}
      >
        <Handle
          type="target"
          position={Position.Left}
          id="left-tgt"
          className={`!w-2.5 !h-2.5 !border-2 !border-white ${style.dotClasses}`}
        />

        <div className="flex items-center justify-between gap-1.5 mb-1">
          <div className="flex items-center gap-1 min-w-0">
            <span className="px-1.5 py-0.5 rounded bg-slate-900 text-white text-[9px] font-mono font-extrabold">
              H{data.stepNumber}
            </span>
            <span
              className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-extrabold uppercase tracking-wide ${style.pillClasses}`}
            >
              {style.label}
            </span>
          </div>
          {data.cweOrRule && (
            <span className="px-1.5 py-0.5 rounded bg-white/95 border border-slate-300 text-slate-900 text-[9px] font-mono font-bold truncate max-w-[92px]">
              {data.cweOrRule}
            </span>
          )}
        </div>

        <div className="text-xs font-extrabold leading-snug text-slate-950 line-clamp-1">
          {data.title}
        </div>
        <div className="text-[10px] leading-snug text-slate-800 line-clamp-2 mt-0.5">
          {data.detail || "Multi-hop exploit chain progression node"}
        </div>

        <div className="mt-1.5 pt-1 border-t border-slate-300/70 flex items-center justify-between gap-1 text-[10px] font-mono text-slate-800">
          <span className="truncate">
            {hasLoc
              ? `${formatShortPath(data.filepath)}:L${data.line || 1}`
              : data.communityId
              ? `Community: ${data.communityId}`
              : "Asset Target"}
          </span>
          {hasLoc && (
            <span className="font-bold text-indigo-900 shrink-0">IDE →</span>
          )}
        </div>

        <Handle
          type="source"
          position={Position.Right}
          id="right-src"
          className={`!w-2.5 !h-2.5 !border-2 !border-white ${style.dotClasses}`}
        />
      </div>
    );
  }
);
ExploitChainHopCardNode.displayName = "ExploitChainHopCardNode";

// Module-scoped nodeTypes prevents ReactFlow node remounting & flicker
const exploitChainNodeTypes = {
  exploitChainHop: ExploitChainHopCardNode,
};

function layoutExploitChain(chain: ExploitChainItem): {
  nodes: Node<ExploitChainNodeData>[];
  edges: Edge[];
} {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: "LR",
    nodesep: 44,
    ranksep: 88,
    marginx: 24,
    marginy: 24,
  });

  const hops: ExploitChainHop[] = chain.hops || [];
  const rawNodes =
    Array.isArray(chain.nodes) && chain.nodes.length > 0
      ? chain.nodes
      : hops.map((h) => ({
          id: `${chain.id}-hop-${h.step_number}`,
          step_number: h.step_number,
          hop_type: h.hop_type,
          title: h.title,
          filepath: h.filepath,
          line: h.line,
          cwe_or_rule: h.cwe_or_rule,
          community_id: h.community_id,
          linked_finding_id: h.linked_finding_id,
          detail: h.detail,
        }));

  const validIds = new Set<string>();
  for (let i = 0; i < rawNodes.length; i++) {
    const rn = rawNodes[i];
    const nid = String(rn.id || `${chain.id}-hop-${i + 1}`);
    validIds.add(nid);
    g.setNode(nid, { width: CHAIN_NODE_WIDTH, height: CHAIN_NODE_HEIGHT });
  }

  const rawEdges =
    Array.isArray(chain.edges) && chain.edges.length > 0
      ? chain.edges
      : rawNodes.slice(0, -1).map((rn, idx) => ({
          id: `${chain.id}-edge-${idx}`,
          source: String(rn.id || `${chain.id}-hop-${idx + 1}`),
          target: String(
            rawNodes[idx + 1].id || `${chain.id}-hop-${idx + 2}`
          ),
          label: "CHAINS TO",
        }));

  const validEdges = rawEdges.filter((e) => {
    const src = String(e.source || "");
    const tgt = String(e.target || "");
    return validIds.has(src) && validIds.has(tgt);
  });

  for (const e of validEdges) {
    g.setEdge(String(e.source), String(e.target));
  }

  if (rawNodes.length > 0) {
    dagre.layout(g);
  }

  const rfNodes: Node<ExploitChainNodeData>[] = rawNodes.map((rn, idx) => {
    const nid = String(rn.id || `${chain.id}-hop-${idx + 1}`);
    const matchingHop = hops[idx];
    const pos = g.node(nid);
    const x =
      pos && Number.isFinite(pos.x)
        ? pos.x - CHAIN_NODE_WIDTH / 2
        : idx * (CHAIN_NODE_WIDTH + 88);
    const y =
      pos && Number.isFinite(pos.y) ? pos.y - CHAIN_NODE_HEIGHT / 2 : 28;
    const hopType = (rn.hop_type ||
      matchingHop?.hop_type ||
      "VULNERABILITY") as ExploitChainHopType;

    return {
      id: nid,
      type: "exploitChainHop",
      position: { x, y },
      width: CHAIN_NODE_WIDTH,
      height: CHAIN_NODE_HEIGHT,
      style: { width: CHAIN_NODE_WIDTH, minHeight: CHAIN_NODE_HEIGHT },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      data: {
        stepNumber: Number(rn.step_number ?? matchingHop?.step_number ?? idx + 1),
        hopType,
        title: String(rn.title || rn.label || matchingHop?.title || `Hop ${idx + 1}`),
        filepath: String(rn.filepath ?? matchingHop?.filepath ?? ""),
        line: Number(rn.line ?? matchingHop?.line ?? 1),
        cweOrRule: String(rn.cwe_or_rule ?? matchingHop?.cwe_or_rule ?? ""),
        communityId: (rn.community_id ?? matchingHop?.community_id ?? null) as
          | string
          | null,
        linkedFindingId: (rn.linked_finding_id ??
          matchingHop?.linked_finding_id ??
          null) as string | null,
        detail: String(rn.detail ?? matchingHop?.detail ?? ""),
      },
    };
  });

  const rfEdges: Edge[] = validEdges.map((e, idx) => {
    const eid = String(e.id || `${chain.id}-edge-${idx}`);
    const stroke = "#be123c";
    return {
      id: eid,
      source: String(e.source),
      target: String(e.target),
      sourceHandle: "right-src",
      targetHandle: "left-tgt",
      type: "smoothstep",
      animated: true,
      label: String(e.label || "CHAINS TO"),
      style: {
        stroke,
        strokeWidth: 2.4,
      },
      labelStyle: {
        fill: "#881337",
        fontWeight: 700,
        fontSize: 10,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      },
      labelBgStyle: {
        fill: "#fff1f2",
        stroke: "#fda4af",
        strokeWidth: 1,
      },
      labelBgPadding: [6, 3] as [number, number],
      labelBgBorderRadius: 6,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: stroke,
        width: 18,
        height: 18,
      },
    };
  });

  return { nodes: rfNodes, edges: rfEdges };
}

interface ExploitChainCanvasInnerProps {
  chain: ExploitChainItem;
  syncedToPasta: boolean;
  aiIsBusy: boolean;
  onJumpToIde: (filepath?: string, line?: number, findingId?: string) => void;
  onExplainChainWithAi: (chain: ExploitChainItem) => void;
}

const ExploitChainCanvasInner: React.FC<ExploitChainCanvasInnerProps> = ({
  chain,
  syncedToPasta,
  aiIsBusy,
  onJumpToIde,
  onExplainChainWithAi,
}) => {
  const [rfInstance, setRfInstance] = useState<ReactFlowInstance | null>(null);

  const { nodes, edges } = useMemo(() => layoutExploitChain(chain), [chain]);

  const handleFitView = useCallback(() => {
    if (rfInstance) {
      try {
        rfInstance.fitView({ padding: 0.2, duration: 240 });
      } catch {}
    }
  }, [rfInstance]);

  useEffect(() => {
    if (!rfInstance) return;
    const rafId = window.requestAnimationFrame(() => {
      try {
        rfInstance.fitView({ padding: 0.2, duration: 0 });
      } catch {}
    });
    const timerId = window.setTimeout(() => {
      try {
        rfInstance.fitView({ padding: 0.2, duration: 220 });
      } catch {}
    }, 100);
    return () => {
      window.cancelAnimationFrame(rafId);
      window.clearTimeout(timerId);
    };
  }, [chain.id, nodes.length, rfInstance]);

  return (
    <div className="rounded-xl bg-white border border-slate-300 overflow-hidden shadow-sm">
      {/* Canvas Header Bar */}
      <div className="px-4 py-2.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap min-w-0">
          <span
            className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold uppercase ${getSeverityBadgeClass(
              chain.severity
            )}`}
          >
            {chain.severity}
          </span>
          <span className="px-2 py-0.5 rounded bg-rose-50 border border-rose-300 text-rose-950 text-[10px] font-mono font-extrabold">
            Chain CVSS {chain.chain_cvss.toFixed(1)}
          </span>
          <span className="px-2 py-0.5 rounded bg-sky-50 border border-sky-300 text-sky-950 text-[10px] font-mono font-bold">
            {chain.hops.length} Hops
          </span>
          {syncedToPasta && (
            <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 text-[10px] font-mono font-bold">
              Synced to PASTA Stage VI &amp; SAR .docx/.pdf
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            disabled={aiIsBusy}
            onClick={() => onExplainChainWithAi(chain)}
            className="px-2.5 py-1.5 rounded-lg bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm transition-colors"
          >
            {aiIsBusy ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Sparkles className="w-3.5 h-3.5" />
            )}
            <span>AI Explain Chain</span>
          </button>
          <button
            type="button"
            onClick={handleFitView}
            className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 text-xs font-bold flex items-center gap-1.5 transition-colors"
          >
            <Maximize2 className="w-3.5 h-3.5 text-sky-700" />
            <span>Fit Chain</span>
          </button>
        </div>
      </div>

      {/* Hop Color Legend Strip */}
      <div className="px-4 py-1.5 bg-white border-b border-slate-200 flex items-center gap-2 flex-wrap text-[10px] font-mono">
        <span className="font-bold text-slate-700">Hop Legend:</span>
        <span className="px-1.5 py-0.5 rounded bg-sky-50 text-sky-950 border border-sky-300 font-bold">
          ENTRYPOINT
        </span>
        <span className="px-1.5 py-0.5 rounded bg-rose-50 text-rose-950 border border-rose-300 font-bold">
          LEAKED SECRET
        </span>
        <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-950 border border-amber-300 font-bold">
          VULNERABILITY
        </span>
        <span className="px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-950 border border-indigo-300 font-bold">
          COMMUNITY BRIDGE
        </span>
        <span className="px-1.5 py-0.5 rounded bg-violet-50 text-violet-950 border border-violet-300 font-bold">
          CROWN JEWEL
        </span>
        <span className="ml-auto text-slate-600">
          Click any hop node with a file path to jump into Monaco IDE
        </span>
      </div>

      {/* ReactFlow Canvas */}
      <div className="w-full h-[360px] bg-[#f8fafc] relative">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={exploitChainNodeTypes}
          onInit={setRfInstance}
          onNodeClick={(_, node) => {
            const d = node.data as ExploitChainNodeData | undefined;
            if (d && (d.filepath || "").trim()) {
              onJumpToIde(
                d.filepath,
                d.line || 1,
                d.linkedFindingId || undefined
              );
            }
          }}
          fitView
          minZoom={0.25}
          maxZoom={2.0}
          nodesDraggable={false}
          nodesConnectable={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#cbd5e1" gap={20} size={1.25} />
          <Controls
            showInteractive={false}
            className="!bg-white !border-slate-300 !text-slate-800 !shadow-md rounded-lg overflow-hidden"
          />
          <MiniMap
            nodeColor={(n) => {
              const d = n.data as ExploitChainNodeData | undefined;
              return getHopTypeStyle(d?.hopType || "VULNERABILITY").minimapColor;
            }}
            maskColor="rgba(241, 245, 249, 0.78)"
            className="!bg-white !border-slate-300 !shadow-md rounded-lg overflow-hidden"
          />
        </ReactFlow>
      </div>

      {/* Bottom Break-the-Chain Priority Remediation & Narrative Card */}
      <div className="p-4 bg-white border-t border-slate-200 space-y-3">
        <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-300 space-y-1">
          <div className="text-[11px] font-mono font-extrabold uppercase text-emerald-900 flex items-center gap-1.5">
            <Wrench className="w-3.5 h-3.5 text-emerald-800" />
            <span>Break-the-Chain Priority Remediation</span>
          </div>
          <p className="text-xs text-slate-900 leading-relaxed font-medium">
            {chain.break_the_chain_fix ||
              "Enforce authentication and parameterized controls at the earliest entry hop to sever downstream propagation."}
          </p>
        </div>

        <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
          <div className="text-[11px] font-mono font-extrabold uppercase text-slate-800">
            Attack Chain Narrative
          </div>
          <p className="text-xs text-slate-800 leading-relaxed">
            {chain.narrative}
          </p>
          {chain.blast_radius_communities.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap pt-1">
              <span className="text-[10px] font-mono font-bold text-slate-700">
                Blast-Radius Communities:
              </span>
              {chain.blast_radius_communities.map((comm) => (
                <span
                  key={comm}
                  className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-300 text-indigo-950 font-mono text-[10px] font-bold"
                >
                  {comm}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export const CognitiveSecurityWorkbench: React.FC = () => {
  const projectPath = useAuditStore((s) => s.projectPath);
  const findings = useAuditStore((s) => s.findings);
  const aiConfig = useAuditStore((s) => s.aiConfig);
  const aiIsBusy = useAuditStore((s) => s.aiIsBusy);

  const cognitivePlaybooks = useAuditStore((s) => s.cognitivePlaybooks);
  const cognitiveHuntResult = useAuditStore((s) => s.cognitiveHuntResult);
  const adversarialVerifyResult = useAuditStore(
    (s) => s.adversarialVerifyResult
  );
  const exploitChainsResult = useAuditStore((s) => s.exploitChainsResult);
  const isLoadingCognitive = useAuditStore((s) => s.isLoadingCognitive);
  const isRunningCognitiveHunt = useAuditStore((s) => s.isRunningCognitiveHunt);
  const isRunningAdversarialVerify = useAuditStore(
    (s) => s.isRunningAdversarialVerify
  );
  const isRunningExploitChains = useAuditStore((s) => s.isRunningExploitChains);
  const cognitiveErrorBanner = useAuditStore((s) => s.cognitiveErrorBanner);

  const fetchCognitivePlaybooksState = useAuditStore(
    (s) => s.fetchCognitivePlaybooksState
  );
  const runCognitiveSemanticHunt = useAuditStore(
    (s) => s.runCognitiveSemanticHunt
  );
  const runAdversarialVerification = useAuditStore(
    (s) => s.runAdversarialVerification
  );
  const fetchExploitChainsState = useAuditStore(
    (s) => s.fetchExploitChainsState
  );
  const openCodeLocationInIde = useAuditStore((s) => s.openCodeLocationInIde);
  const selectFinding = useAuditStore((s) => s.selectFinding);
  const updateFindingTriage = useAuditStore((s) => s.updateFindingTriage);
  const setAiDrawerOpen = useAuditStore((s) => s.setAiDrawerOpen);
  const explainCurrentGraphWithAi = useAuditStore(
    (s) => s.explainCurrentGraphWithAi
  );

  const [activeTab, setActiveTab] = useState<WorkbenchTab>("HUNTER");
  const [selectedPlaybookIds, setSelectedPlaybookIds] = useState<string[]>([]);
  const [useHybridAi, setUseHybridAi] = useState<boolean>(false);
  const [includeSiblingSweep, setIncludeSiblingSweep] = useState<boolean>(true);
  const [playbookKindFilter, setPlaybookKindFilter] = useState<
    "ALL" | "LENS" | "METHOD"
  >("ALL");
  const [baselineFilter, setBaselineFilter] = useState<
    "ALL" | BaselineDisposition
  >("ALL");
  const [verdictFilter, setVerdictFilter] = useState<
    "ALL" | "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_REVIEW"
  >("ALL");
  const [appliedTriageMap, setAppliedTriageMap] = useState<
    Record<string, boolean>
  >({});
  const [selectedChainId, setSelectedChainId] = useState<string | null>(null);

  const lastAutoHydratedKeyRef = useRef<string | null>(null);

  // Auto-hydrate once per active project key (prevents infinite error retry loops)
  useEffect(() => {
    const key = (projectPath || "__active__").trim();
    if (lastAutoHydratedKeyRef.current === key) {
      return;
    }
    lastAutoHydratedKeyRef.current = key;
    setSelectedChainId(null);
    setAppliedTriageMap({});
    void fetchCognitivePlaybooksState();
    void fetchExploitChainsState();
  }, [projectPath, fetchCognitivePlaybooksState, fetchExploitChainsState]);

  const aiReady = Boolean(
    cognitivePlaybooks?.ai_available ||
      aiConfig?.has_api_key ||
      aiConfig?.provider === "openai_compatible"
  );

  useEffect(() => {
    if (!aiReady && useHybridAi) {
      setUseHybridAi(false);
    }
  }, [aiReady, useHybridAi]);

  const playbooks: PlaybookDefinitionItem[] = useMemo(
    () => cognitivePlaybooks?.playbooks || [],
    [cognitivePlaybooks]
  );

  const filteredPlaybooks = useMemo(() => {
    if (playbookKindFilter === "ALL") return playbooks;
    return playbooks.filter((pb) => pb.kind === playbookKindFilter);
  }, [playbooks, playbookKindFilter]);

  const effectiveRepoKinds = useMemo(() => {
    if (
      cognitiveHuntResult?.repo_kinds &&
      cognitiveHuntResult.repo_kinds.length > 0
    ) {
      return cognitiveHuntResult.repo_kinds;
    }
    return cognitivePlaybooks?.repo_kinds || [];
  }, [cognitiveHuntResult, cognitivePlaybooks]);

  const effectiveBaselines: RepoBaselineItem[] = useMemo(() => {
    if (
      cognitiveHuntResult?.baseline_items &&
      cognitiveHuntResult.baseline_items.length > 0
    ) {
      return cognitiveHuntResult.baseline_items;
    }
    return cognitivePlaybooks?.baseline_items || [];
  }, [cognitiveHuntResult, cognitivePlaybooks]);

  const filteredBaselines = useMemo(() => {
    if (baselineFilter === "ALL") return effectiveBaselines;
    return effectiveBaselines.filter((b) => b.status === baselineFilter);
  }, [effectiveBaselines, baselineFilter]);

  const baselineKpis = useMemo(() => {
    const covered = effectiveBaselines.filter(
      (b) => b.status === "COVERED_CLEAN"
    ).length;
    const detected = effectiveBaselines.filter(
      (b) => b.status === "FINDING_DETECTED"
    ).length;
    const gaps = effectiveBaselines.filter(
      (b) => b.status === "UNDISPOSED_GAP"
    ).length;
    return {
      covered:
        effectiveBaselines.length > 0
          ? covered
          : cognitivePlaybooks?.covered_count ?? 0,
      detected:
        effectiveBaselines.length > 0
          ? detected
          : cognitivePlaybooks?.detected_count ?? 0,
      gaps:
        effectiveBaselines.length > 0
          ? gaps
          : cognitivePlaybooks?.undisposed_gap_count ?? 0,
      hostileStripped: cognitiveHuntResult?.hostile_files_stripped ?? 0,
    };
  }, [effectiveBaselines, cognitivePlaybooks, cognitiveHuntResult]);

  const discoveredFindings = useMemo(() => {
    const primary = cognitiveHuntResult?.findings || [];
    const siblings = cognitiveHuntResult?.sibling_findings || [];
    return { primary, siblings, total: primary.length + siblings.length };
  }, [cognitiveHuntResult]);

  const findingsById = useMemo(() => {
    const map = new Map<string, Finding>();
    for (const f of findings) {
      map.set(f.id, f);
    }
    for (const f of discoveredFindings.primary) {
      if (!map.has(f.id)) map.set(f.id, f);
    }
    for (const f of discoveredFindings.siblings) {
      if (!map.has(f.id)) map.set(f.id, f);
    }
    return map;
  }, [findings, discoveredFindings]);

  const filteredVerdicts = useMemo(() => {
    const all = adversarialVerifyResult?.verdicts || [];
    if (verdictFilter === "ALL") return all;
    return all.filter((v) => v.verdict === verdictFilter);
  }, [adversarialVerifyResult, verdictFilter]);

  const chains = useMemo(
    () => exploitChainsResult?.chains || [],
    [exploitChainsResult]
  );

  const selectedChain: ExploitChainItem | null = useMemo(() => {
    if (chains.length === 0) return null;
    if (selectedChainId) {
      const found = chains.find((c) => c.id === selectedChainId);
      if (found) return found;
    }
    return chains[0];
  }, [chains, selectedChainId]);

  const togglePlaybookSelection = (id: string) => {
    setSelectedPlaybookIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleRunHunt = async () => {
    setActiveTab("HUNTER");
    await runCognitiveSemanticHunt({
      playbookIds: selectedPlaybookIds,
      useAi: aiReady && useHybridAi,
      includeSiblingSweep,
    });
  };

  const handleRunVerifier = async () => {
    setActiveTab("VERIFIER");
    await runAdversarialVerification({
      useAi: aiReady && useHybridAi,
    });
  };

  const handleSynthesizeChains = async () => {
    setActiveTab("CHAINS");
    await fetchExploitChainsState({
      useAi: aiReady && useHybridAi,
      forceSynthesize: true,
    });
  };

  const handleJumpToFinding = (finding: Finding) => {
    selectFinding(finding);
    const bfl = finding.best_fix_location;
    const node =
      finding.path_nodes && finding.path_nodes.length > 0
        ? finding.path_nodes[finding.path_nodes.length - 1]
        : null;
    const fp = bfl?.filepath || node?.filepath;
    const ln = bfl?.line || node?.start_line || 1;
    openCodeLocationInIde(fp, ln, finding.id);
  };

  const handleApplyAdversarialTriage = async (v: AdversarialFindingVerdict) => {
    const targetStatus =
      v.verdict === "FALSE_POSITIVE" ? "NOT_EXPLOITABLE" : "CONFIRMED";
    const reason = v.exclusion_rule
      ? `S6 Adversarial Verifier (${v.verdict} • ${v.exclusion_rule})`
      : `S6 Adversarial Verifier (${v.verdict} • CVSS ${v.cvss_score.toFixed(1)})`;
    await updateFindingTriage(v.finding_id, targetStatus, reason, v.rationale);
    setAppliedTriageMap((prev) => ({ ...prev, [v.finding_id]: true }));
  };

  const handleExplainChainWithAi = useCallback(
    (chain: ExploitChainItem) => {
      setAiDrawerOpen(true, "GRAPH");
      void explainCurrentGraphWithAi({
        view_mode: "S8_EXPLOIT_CHAIN",
        finding_id: chain.linked_finding_ids[0] ?? null,
        nodes_digest: chain.hops.map((h) => ({
          id: `${chain.id}-hop-${h.step_number}`,
          label: h.title,
          type: h.hop_type,
          code: h.detail,
          filepath: h.filepath,
          start_line: h.line,
        })),
        edges_digest: chain.edges.map((e) => ({
          source: String(e.source || ""),
          target: String(e.target || ""),
          type: String(e.label || "CHAINS_TO"),
        })),
      });
    },
    [setAiDrawerOpen, explainCurrentGraphWithAi]
  );

  const anyBusy =
    isLoadingCognitive ||
    isRunningCognitiveHunt ||
    isRunningAdversarialVerify ||
    isRunningExploitChains;

  return (
    <div className="space-y-5 text-slate-900">
      {/* Header Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3.5 min-w-0">
            <div className="w-11 h-11 rounded-xl bg-indigo-50 border border-indigo-300 flex items-center justify-center text-indigo-800 shrink-0">
              <Brain className="w-6 h-6" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-base font-extrabold tracking-tight text-slate-900">
                  Cognitive Security Hunter, S6 Adversarial Verifier &amp; S8
                  Exploit Chains
                </h2>
                {aiReady ? (
                  <span className="px-2.5 py-0.5 rounded-full bg-indigo-50 text-indigo-950 border border-indigo-300 text-[10px] font-mono font-extrabold">
                    Hybrid BYOK AI Ready
                  </span>
                ) : (
                  <span className="px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-900 border border-emerald-300 text-[10px] font-mono font-extrabold">
                    $0 Deterministic Offline
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-700 mt-1 leading-relaxed">
                17-Lens semantic discovery (15 security lenses + 2 exploration
                &amp; sibling-sweep methods), Repo-Kind mandatory baselines, S6
                Exclusion Rules A–F with CVSS 3.1 scoring, and S8 multi-hop
                exploit chains auto-synced to PASTA Stage VI &amp; SAR reports.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {aiReady && (
              <label className="px-3 py-1.5 rounded-lg bg-indigo-50 border border-indigo-300 text-indigo-950 text-xs font-bold flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={useHybridAi}
                  onChange={(e) => setUseHybridAi(e.target.checked)}
                  className="accent-indigo-700"
                />
                <span>Hybrid BYOK AI</span>
              </label>
            )}

            <button
              type="button"
              disabled={anyBusy}
              onClick={() => void handleRunHunt()}
              className="px-3.5 py-2 rounded-lg bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white border border-indigo-800 text-xs font-extrabold flex items-center gap-1.5 shadow-sm transition-colors"
            >
              {isRunningCognitiveHunt ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Search className="w-3.5 h-3.5" />
              )}
              <span>Run Semantic Hunt</span>
            </button>

            <button
              type="button"
              disabled={anyBusy}
              onClick={() => void handleRunVerifier()}
              className="px-3.5 py-2 rounded-lg bg-sky-700 hover:bg-sky-800 disabled:opacity-50 text-white border border-sky-800 text-xs font-extrabold flex items-center gap-1.5 shadow-sm transition-colors"
            >
              {isRunningAdversarialVerify ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Scale className="w-3.5 h-3.5" />
              )}
              <span>Run S6 Adversarial Verify</span>
            </button>

            <button
              type="button"
              disabled={anyBusy}
              onClick={() => void handleSynthesizeChains()}
              className="px-3.5 py-2 rounded-lg bg-rose-700 hover:bg-rose-800 disabled:opacity-50 text-white border border-rose-800 text-xs font-extrabold flex items-center gap-1.5 shadow-sm transition-colors"
            >
              {isRunningExploitChains ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <GitBranch className="w-3.5 h-3.5" />
              )}
              <span>Synthesize S8 Exploit Chains</span>
            </button>
          </div>
        </div>

        {/* Accessible Daylight Error Banner */}
        {cognitiveErrorBanner && (
          <div
            role="alert"
            className="px-3.5 py-2.5 rounded-xl bg-rose-50 border border-rose-300 text-rose-950 text-xs font-bold flex items-center justify-between gap-3"
          >
            <div className="flex items-center gap-2 min-w-0">
              <AlertTriangle className="w-4 h-4 text-rose-700 shrink-0" />
              <span className="break-words">{cognitiveErrorBanner}</span>
            </div>
            <button
              type="button"
              onClick={() => {
                void fetchCognitivePlaybooksState();
                void fetchExploitChainsState();
              }}
              className="px-2.5 py-1 rounded-lg bg-white hover:bg-rose-100 border border-rose-300 text-rose-950 text-[11px] font-mono font-bold flex items-center gap-1 shrink-0"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Retry</span>
            </button>
          </div>
        )}

        {/* Sub-navigation Tabs */}
        <div
          role="tablist"
          aria-label="Cognitive Security Workbench Sections"
          className="flex items-center gap-2 flex-wrap pt-2 border-t border-slate-200"
        >
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "HUNTER"}
            onClick={() => setActiveTab("HUNTER")}
            className={`px-3.5 py-2 rounded-lg text-xs font-extrabold flex items-center gap-2 border transition-all ${
              activeTab === "HUNTER"
                ? "bg-indigo-700 text-white border-indigo-800 shadow-sm"
                : "bg-slate-50 text-slate-800 hover:bg-slate-100 border-slate-300"
            }`}
          >
            <Compass className="w-3.5 h-3.5" />
            <span>17-Lens Hunter &amp; Baselines</span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-extrabold border ${
                activeTab === "HUNTER"
                  ? "bg-white text-indigo-950 border-indigo-200"
                  : "bg-indigo-50 text-indigo-950 border-indigo-300"
              }`}
            >
              {playbooks.length || 17}
            </span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "VERIFIER"}
            onClick={() => setActiveTab("VERIFIER")}
            className={`px-3.5 py-2 rounded-lg text-xs font-extrabold flex items-center gap-2 border transition-all ${
              activeTab === "VERIFIER"
                ? "bg-sky-700 text-white border-sky-800 shadow-sm"
                : "bg-slate-50 text-slate-800 hover:bg-slate-100 border-slate-300"
            }`}
          >
            <Scale className="w-3.5 h-3.5" />
            <span>S6 Adversarial Verifier</span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-extrabold border ${
                activeTab === "VERIFIER"
                  ? "bg-white text-sky-950 border-sky-200"
                  : "bg-sky-50 text-sky-950 border-sky-300"
              }`}
            >
              {adversarialVerifyResult
                ? `${adversarialVerifyResult.true_positives} TP / ${adversarialVerifyResult.false_positives} FP`
                : "Rules A–F"}
            </span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "CHAINS"}
            onClick={() => setActiveTab("CHAINS")}
            className={`px-3.5 py-2 rounded-lg text-xs font-extrabold flex items-center gap-2 border transition-all ${
              activeTab === "CHAINS"
                ? "bg-rose-700 text-white border-rose-800 shadow-sm"
                : "bg-slate-50 text-slate-800 hover:bg-slate-100 border-slate-300"
            }`}
          >
            <GitBranch className="w-3.5 h-3.5" />
            <span>S8 Exploit Chains</span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-extrabold border ${
                activeTab === "CHAINS"
                  ? "bg-white text-rose-950 border-rose-200"
                  : "bg-rose-50 text-rose-950 border-rose-300"
              }`}
            >
              {exploitChainsResult?.total_chains ?? 0} Chains
            </span>
          </button>
        </div>
      </div>

      {/* =================================================================== */}
      {/* PANEL A: 17-LENS PLAYBOOKS & REPO-KIND AUTO-BASELINE MATRIX         */}
      {/* =================================================================== */}
      {activeTab === "HUNTER" && (
        <div className="space-y-5">
          {/* Repo Kinds + Baseline KPI Row */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <div className="lg:col-span-4 bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-2.5">
              <div className="text-[11px] font-mono font-extrabold uppercase text-slate-700 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-indigo-700" />
                <span>Auto-Detected Repo Kinds</span>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap">
                {effectiveRepoKinds.length > 0 ? (
                  effectiveRepoKinds.map((rk) => (
                    <span
                      key={rk}
                      className="px-2.5 py-1 rounded-lg bg-sky-50 text-sky-950 border border-sky-300 text-xs font-mono font-extrabold uppercase"
                    >
                      {rk}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-slate-600">
                    {isLoadingCognitive
                      ? "Classifying workspace..."
                      : "Scan a workspace to auto-detect repo kinds."}
                  </span>
                )}
              </div>
              <label className="flex items-center gap-2 pt-1 text-xs text-slate-800 font-semibold cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={includeSiblingSweep}
                  onChange={(e) => setIncludeSiblingSweep(e.target.checked)}
                  className="accent-indigo-700"
                />
                <span>Include automatic CPG Sibling Sweep</span>
              </label>
            </div>

            <div className="lg:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-white border border-emerald-300 rounded-xl p-3.5 shadow-sm">
                <div className="text-[10px] font-mono font-extrabold uppercase text-emerald-900">
                  Covered Clean
                </div>
                <div className="text-2xl font-extrabold text-emerald-900 mt-1">
                  {baselineKpis.covered}
                </div>
                <div className="text-[11px] text-slate-700 mt-0.5">
                  Verified baseline items
                </div>
              </div>

              <div className="bg-white border border-rose-300 rounded-xl p-3.5 shadow-sm">
                <div className="text-[10px] font-mono font-extrabold uppercase text-rose-950">
                  Finding Detected
                </div>
                <div className="text-2xl font-extrabold text-rose-900 mt-1">
                  {baselineKpis.detected}
                </div>
                <div className="text-[11px] text-slate-700 mt-0.5">
                  Confirmed vulnerabilities
                </div>
              </div>

              <div className="bg-white border border-amber-300 rounded-xl p-3.5 shadow-sm">
                <div className="text-[10px] font-mono font-extrabold uppercase text-amber-950">
                  Undisposed Gaps
                </div>
                <div className="text-2xl font-extrabold text-amber-950 mt-1">
                  {baselineKpis.gaps}
                </div>
                <div className="text-[11px] text-slate-700 mt-0.5">
                  Needs lens / manual review
                </div>
              </div>

              <div className="bg-white border border-indigo-300 rounded-xl p-3.5 shadow-sm">
                <div className="text-[10px] font-mono font-extrabold uppercase text-indigo-950">
                  Hostile Files Stripped
                </div>
                <div className="text-2xl font-extrabold text-indigo-950 mt-1">
                  {baselineKpis.hostileStripped}
                </div>
                <div className="text-[11px] text-slate-700 mt-0.5">
                  Prompt-injection defense
                </div>
              </div>
            </div>
          </div>

          {/* Interactive 17-Playbook Grid */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-extrabold text-slate-900">
                  17-Playbook Specialist Catalog (15 Security Lenses + 2
                  Methods)
                </h3>
                <p className="text-xs text-slate-700 mt-0.5">
                  Toggle individual playbooks to scope the hunt, or leave none
                  selected to run all applicable probes (
                  {selectedPlaybookIds.length === 0
                    ? "All 17 Active"
                    : `${selectedPlaybookIds.length} Selected`}
                  ).
                </p>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
                  {(["ALL", "LENS", "METHOD"] as const).map((k) => (
                    <button
                      key={k}
                      type="button"
                      onClick={() => setPlaybookKindFilter(k)}
                      className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-bold transition-colors ${
                        playbookKindFilter === k
                          ? "bg-indigo-700 text-white shadow-sm"
                          : "text-slate-800 hover:bg-white"
                      }`}
                    >
                      {k === "ALL"
                        ? `All (${playbooks.length})`
                        : k === "LENS"
                        ? `Lenses (${playbooks.filter((p) => p.kind === "LENS").length})`
                        : `Methods (${playbooks.filter((p) => p.kind === "METHOD").length})`}
                    </button>
                  ))}
                </div>

                {selectedPlaybookIds.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setSelectedPlaybookIds([])}
                    className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 text-[11px] font-mono font-bold"
                  >
                    Reset to All
                  </button>
                )}
              </div>
            </div>

            {isLoadingCognitive && playbooks.length === 0 ? (
              <div className="py-10 flex items-center justify-center gap-2 text-xs text-slate-700 font-mono">
                <Loader2 className="w-4 h-4 animate-spin text-indigo-700" />
                <span>Loading 17-Lens catalog &amp; Repo-Kind baselines...</span>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                {filteredPlaybooks.map((pb) => {
                  const isSelected = selectedPlaybookIds.includes(pb.id);
                  return (
                    <button
                      key={pb.id}
                      type="button"
                      onClick={() => togglePlaybookSelection(pb.id)}
                      className={`p-3.5 rounded-xl border text-left transition-all space-y-2 ${
                        isSelected
                          ? "bg-indigo-50 border-indigo-500 ring-1 ring-indigo-500/30 shadow-sm"
                          : "bg-[#f8fafc] hover:bg-white border-slate-200 hover:border-slate-300"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="text-xs font-extrabold text-slate-900 truncate">
                            {pb.name}
                          </div>
                          <div className="text-[10px] font-mono text-slate-700">
                            {pb.id}
                          </div>
                        </div>
                        <span
                          className={`px-1.5 py-0.5 rounded border text-[9px] font-mono font-extrabold shrink-0 ${
                            pb.supports_deterministic_probe
                              ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                              : "bg-indigo-50 text-indigo-950 border-indigo-300"
                          }`}
                        >
                          {pb.supports_deterministic_probe
                            ? "DETERMINISTIC PROBE"
                            : "BYOK LENS"}
                        </span>
                      </div>

                      <p className="text-[11px] text-slate-700 leading-snug line-clamp-2">
                        {pb.description}
                      </p>

                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span
                          className={`px-1.5 py-0.5 rounded border text-[9px] font-mono font-bold ${
                            pb.kind === "METHOD"
                              ? "bg-sky-50 text-sky-950 border-sky-300"
                              : "bg-white text-slate-800 border-slate-300"
                          }`}
                        >
                          {pb.kind}
                        </span>
                        {pb.auto_triggered && (
                          <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-950 border border-amber-300 text-[9px] font-mono font-bold">
                            AUTO-TRIGGERED
                          </span>
                        )}
                        {pb.cwe_ids.slice(0, 3).map((cwe) => (
                          <span
                            key={cwe}
                            className="px-1.5 py-0.5 rounded bg-white border border-slate-300 text-slate-800 text-[9px] font-mono font-semibold"
                          >
                            {cwe}
                          </span>
                        ))}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Discovered Semantic & Sibling Findings */}
          {cognitiveHuntResult && (
            <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-700" />
                    <span>
                      Discovered Semantic &amp; CPG Sibling Findings (
                      {discoveredFindings.total})
                    </span>
                  </h3>
                  <p className="text-xs text-slate-700 mt-0.5">
                    {cognitiveHuntResult.summary}
                  </p>
                </div>
                <div className="flex items-center gap-2 font-mono text-[10px]">
                  <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-950 border border-indigo-300 font-bold">
                    Mode: {cognitiveHuntResult.execution_mode}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-800 border border-slate-300 font-bold">
                    Primary: {discoveredFindings.primary.length} • Siblings:{" "}
                    {discoveredFindings.siblings.length}
                  </span>
                </div>
              </div>

              {discoveredFindings.total === 0 ? (
                <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-300 text-emerald-900 text-xs font-semibold flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-800 shrink-0" />
                  <span>
                    No new COG-1..5 semantic or sibling-sweep flaws triggered on
                    this run. Review Repo-Kind Baselines below for coverage
                    status.
                  </span>
                </div>
              ) : (
                <div className="space-y-2">
                  {[
                    ...discoveredFindings.primary.map((f) => ({
                      finding: f,
                      isSibling: false,
                    })),
                    ...discoveredFindings.siblings.map((f) => ({
                      finding: f,
                      isSibling: true,
                    })),
                  ].map(({ finding, isSibling }) => {
                    const bfl = finding.best_fix_location;
                    const pNode =
                      finding.path_nodes && finding.path_nodes.length > 0
                        ? finding.path_nodes[finding.path_nodes.length - 1]
                        : null;
                    const fp = bfl?.filepath || pNode?.filepath || "";
                    const ln = bfl?.line || pNode?.start_line || 1;

                    return (
                      <div
                        key={finding.id}
                        className="p-3.5 rounded-xl bg-[#f8fafc] border border-slate-200 hover:border-indigo-400 transition-colors flex flex-wrap items-start justify-between gap-3"
                      >
                        <div className="space-y-1 min-w-0 flex-1">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span
                              className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${getSeverityBadgeClass(
                                finding.severity
                              )}`}
                            >
                              {finding.severity}
                            </span>
                            <span className="px-2 py-0.5 rounded bg-white border border-slate-300 text-slate-900 text-[10px] font-mono font-bold">
                              {finding.rule_id}
                            </span>
                            {finding.cwe_id && (
                              <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-300 text-amber-950 text-[10px] font-mono font-bold">
                                {finding.cwe_id}
                              </span>
                            )}
                            {isSibling && (
                              <span className="px-2 py-0.5 rounded bg-sky-50 border border-sky-300 text-sky-950 text-[10px] font-mono font-extrabold">
                                CPG SIBLING SWEEP
                              </span>
                            )}
                          </div>
                          <div className="text-xs font-extrabold text-slate-900">
                            {finding.title}
                          </div>
                          <p className="text-[11px] text-slate-700 leading-relaxed">
                            {finding.description}
                          </p>
                          {fp && (
                            <div className="text-[10px] font-mono text-slate-700">
                              Location: {formatShortPath(fp)}:L{ln}
                            </div>
                          )}
                        </div>

                        <button
                          type="button"
                          onClick={() => handleJumpToFinding(finding)}
                          className="px-3 py-1.5 rounded-lg bg-indigo-700 hover:bg-indigo-800 text-white text-xs font-bold flex items-center gap-1.5 shrink-0 shadow-sm"
                        >
                          <Code2 className="w-3.5 h-3.5" />
                          <span>Inspect in IDE</span>
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Repo-Kind Baseline Disposition Table */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-3.5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-extrabold text-slate-900">
                  Repo-Kind Mandatory Baseline Disposition Matrix (
                  {effectiveBaselines.length})
                </h3>
                <p className="text-xs text-slate-700 mt-0.5">
                  Every required OWASP / IaC / Native / Mobile baseline item is
                  explicitly tracked so undisposed gaps never masquerade as
                  clean coverage.
                </p>
              </div>

              <div className="flex items-center gap-1.5 flex-wrap">
                <Filter className="w-3.5 h-3.5 text-slate-600" />
                {(
                  [
                    { id: "ALL", label: "All" },
                    { id: "FINDING_DETECTED", label: "Detected" },
                    { id: "UNDISPOSED_GAP", label: "Gaps" },
                    { id: "COVERED_CLEAN", label: "Covered Clean" },
                  ] as const
                ).map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setBaselineFilter(tab.id)}
                    className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono font-bold transition-colors ${
                      baselineFilter === tab.id
                        ? "bg-slate-900 text-white border-slate-900"
                        : "bg-white text-slate-800 border-slate-300 hover:bg-slate-100"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto rounded-lg border border-slate-200">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-mono uppercase text-slate-700">
                    <th className="py-2.5 px-3">Repo Kind</th>
                    <th className="py-2.5 px-3">Baseline Requirement</th>
                    <th className="py-2.5 px-3">Standard / CWE</th>
                    <th className="py-2.5 px-3">Disposition</th>
                    <th className="py-2.5 px-3">Evidence Rationale</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {filteredBaselines.length === 0 ? (
                    <tr>
                      <td
                        colSpan={5}
                        className="py-6 px-3 text-center text-slate-600"
                      >
                        No baseline rows match this filter.
                      </td>
                    </tr>
                  ) : (
                    filteredBaselines.map((item) => {
                      const meta = getBaselineStatusMeta(item.status);
                      return (
                        <tr
                          key={item.id}
                          className="hover:bg-slate-50/80 transition-colors"
                        >
                          <td className="py-2.5 px-3 align-top">
                            <span className="px-2 py-0.5 rounded bg-sky-50 text-sky-950 border border-sky-300 font-mono text-[10px] font-bold uppercase whitespace-nowrap">
                              {item.repo_kind}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 align-top font-bold text-slate-900">
                            {item.title}
                          </td>
                          <td className="py-2.5 px-3 align-top font-mono text-[11px] text-slate-800 whitespace-nowrap">
                            {item.cwe_or_owasp}
                          </td>
                          <td className="py-2.5 px-3 align-top">
                            <span
                              className={`px-2 py-0.5 rounded border font-mono text-[10px] font-extrabold whitespace-nowrap ${meta.className}`}
                            >
                              {meta.label}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 align-top text-slate-700 leading-relaxed">
                            <div>{item.rationale}</div>
                            {item.linked_finding_ids.length > 0 && (
                              <div className="mt-1 flex items-center gap-1 flex-wrap">
                                {item.linked_finding_ids
                                  .slice(0, 4)
                                  .map((fid) => {
                                    const matched = findingsById.get(fid);
                                    return (
                                      <button
                                        key={fid}
                                        type="button"
                                        onClick={() =>
                                          matched
                                            ? handleJumpToFinding(matched)
                                            : openCodeLocationInIde(
                                                undefined,
                                                1,
                                                fid
                                              )
                                        }
                                        className="px-1.5 py-0.5 rounded bg-rose-50 hover:bg-rose-100 border border-rose-300 text-rose-950 font-mono text-[10px] font-bold flex items-center gap-0.5"
                                      >
                                        <span>
                                          {matched?.rule_id || fid.slice(0, 10)}
                                        </span>
                                        <ArrowUpRight className="w-2.5 h-2.5" />
                                      </button>
                                    );
                                  })}
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* PANEL B: S6 ADVERSARIAL FALSE-POSITIVE VERIFIER                     */}
      {/* =================================================================== */}
      {activeTab === "VERIFIER" && (
        <div className="space-y-5">
          {/* Summary KPI Strip */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
              <div className="text-[10px] font-mono font-extrabold uppercase text-slate-700">
                Verified
              </div>
              <div className="text-2xl font-extrabold text-slate-900 mt-1">
                {adversarialVerifyResult?.total_verified ?? 0}
              </div>
              <div className="text-[11px] text-slate-600 mt-0.5">
                Active findings audited
              </div>
            </div>

            <div className="bg-white border border-rose-300 rounded-xl p-3.5 shadow-sm">
              <div className="text-[10px] font-mono font-extrabold uppercase text-rose-950">
                True Positives
              </div>
              <div className="text-2xl font-extrabold text-rose-900 mt-1">
                {adversarialVerifyResult?.true_positives ?? 0}
              </div>
              <div className="text-[11px] text-slate-700 mt-0.5">
                Exploitable &amp; confirmed
              </div>
            </div>

            <div className="bg-white border border-emerald-300 rounded-xl p-3.5 shadow-sm">
              <div className="text-[10px] font-mono font-extrabold uppercase text-emerald-900">
                False Positives Filtered
              </div>
              <div className="text-2xl font-extrabold text-emerald-900 mt-1">
                {adversarialVerifyResult?.false_positives ?? 0}
              </div>
              <div className="text-[11px] text-slate-700 mt-0.5">
                Excluded by Rules A–F
              </div>
            </div>

            <div className="bg-white border border-amber-300 rounded-xl p-3.5 shadow-sm">
              <div className="text-[10px] font-mono font-extrabold uppercase text-amber-950">
                Needs Review
              </div>
              <div className="text-2xl font-extrabold text-amber-950 mt-1">
                {adversarialVerifyResult?.needs_review ?? 0}
              </div>
              <div className="text-[11px] text-slate-700 mt-0.5">
                Analyst confirmation
              </div>
            </div>

            <div className="bg-white border border-indigo-300 rounded-xl p-3.5 shadow-sm">
              <div className="text-[10px] font-mono font-extrabold uppercase text-indigo-950">
                Execution Mode
              </div>
              <div className="text-sm font-mono font-extrabold text-indigo-950 mt-2 truncate">
                {adversarialVerifyResult?.execution_mode ||
                  (aiReady && useHybridAi ? "HYBRID_AI" : "DETERMINISTIC")}
              </div>
              <div className="text-[11px] text-slate-700 mt-0.5">
                CVSS 3.1 + Rules A–F
              </div>
            </div>
          </div>

          {/* Verdicts Table Card */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-extrabold text-slate-900">
                  S6 Adversarial Verdicts &amp; CVSS 3.1 Scorecards
                </h3>
                <p className="text-xs text-slate-700 mt-0.5">
                  {adversarialVerifyResult?.summary ||
                    "Run S6 Adversarial Verify to challenge every active finding against Out-of-Scope Exclusion Rules A–F and compute deterministic CVSS 3.1 vectors."}
                </p>
              </div>

              <div className="flex items-center gap-1.5 flex-wrap">
                {(
                  [
                    { id: "ALL", label: "All" },
                    { id: "TRUE_POSITIVE", label: "True Positives" },
                    { id: "FALSE_POSITIVE", label: "False Positives" },
                    { id: "NEEDS_REVIEW", label: "Needs Review" },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setVerdictFilter(opt.id)}
                    className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono font-bold transition-colors ${
                      verdictFilter === opt.id
                        ? "bg-sky-700 text-white border-sky-800"
                        : "bg-white text-slate-800 border-slate-300 hover:bg-slate-100"
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {!adversarialVerifyResult ? (
              <div className="py-10 px-4 text-center rounded-xl border border-dashed border-slate-300 bg-[#f8fafc] space-y-3">
                <Scale className="w-8 h-8 mx-auto text-sky-700" />
                <div className="text-sm font-extrabold text-slate-900">
                  Ready to Run S6 Adversarial False-Positive Verification
                </div>
                <p className="text-xs text-slate-700 max-w-xl mx-auto">
                  Validates disk coordinates, CPG reachability, domain-compatible
                  sanitizers, secret validation states, and Exclusion Rules A–F
                  offline ($0) or with Hybrid BYOK AI.
                </p>
                <button
                  type="button"
                  disabled={isRunningAdversarialVerify}
                  onClick={() => void handleRunVerifier()}
                  className="px-4 py-2 rounded-lg bg-sky-700 hover:bg-sky-800 disabled:opacity-50 text-white text-xs font-extrabold inline-flex items-center gap-2 shadow-sm"
                >
                  {isRunningAdversarialVerify ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Play className="w-3.5 h-3.5 fill-current" />
                  )}
                  <span>Run S6 Adversarial Verify Now</span>
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-slate-200">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-mono uppercase text-slate-700">
                      <th className="py-2.5 px-3">Finding</th>
                      <th className="py-2.5 px-3">Verdict</th>
                      <th className="py-2.5 px-3">CVSS 3.1 Score &amp; Vector</th>
                      <th className="py-2.5 px-3">Exclusion Rule</th>
                      <th className="py-2.5 px-3">Conf.</th>
                      <th className="py-2.5 px-3">Adversarial Rationale</th>
                      <th className="py-2.5 px-3 text-right">Triage Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {filteredVerdicts.length === 0 ? (
                      <tr>
                        <td
                          colSpan={7}
                          className="py-6 px-3 text-center text-slate-600"
                        >
                          No verdicts match this filter.
                        </td>
                      </tr>
                    ) : (
                      filteredVerdicts.map((v) => {
                        const matched = findingsById.get(v.finding_id);
                        const verdictClass =
                          v.verdict === "TRUE_POSITIVE"
                            ? "bg-rose-50 text-rose-950 border-rose-300"
                            : v.verdict === "FALSE_POSITIVE"
                            ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                            : "bg-amber-50 text-amber-950 border-amber-300";
                        const targetTriage =
                          v.verdict === "FALSE_POSITIVE"
                            ? "NOT_EXPLOITABLE"
                            : "CONFIRMED";
                        const isApplied =
                          appliedTriageMap[v.finding_id] ||
                          matched?.triage_status === targetTriage;

                        return (
                          <tr
                            key={v.finding_id}
                            className="hover:bg-slate-50/80 transition-colors"
                          >
                            <td className="py-2.5 px-3 align-top max-w-[220px]">
                              <div className="font-bold text-slate-900 line-clamp-2">
                                {matched ? matched.title : v.finding_id}
                              </div>
                              <div className="flex items-center gap-1.5 mt-1">
                                <span className="text-[10px] font-mono text-slate-700 truncate">
                                  {matched?.rule_id || v.finding_id.slice(0, 14)}
                                </span>
                                {matched && (
                                  <button
                                    type="button"
                                    onClick={() => handleJumpToFinding(matched)}
                                    className="text-[10px] font-mono font-bold text-sky-800 hover:underline flex items-center gap-0.5 shrink-0"
                                  >
                                    <span>IDE</span>
                                    <ArrowUpRight className="w-2.5 h-2.5" />
                                  </button>
                                )}
                              </div>
                            </td>

                            <td className="py-2.5 px-3 align-top whitespace-nowrap">
                              <span
                                className={`px-2 py-0.5 rounded border font-mono text-[10px] font-extrabold ${verdictClass}`}
                              >
                                {v.verdict.replace(/_/g, " ")}
                              </span>
                            </td>

                            <td className="py-2.5 px-3 align-top">
                              <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-100 border border-slate-300 font-mono text-[10px] font-extrabold text-slate-900">
                                <span>CVSS {v.cvss_score.toFixed(1)}</span>
                              </div>
                              {v.cvss_vector && (
                                <div className="mt-1 font-mono text-[10px] text-slate-700 break-all max-w-[210px]">
                                  {v.cvss_vector}
                                </div>
                              )}
                            </td>

                            <td className="py-2.5 px-3 align-top whitespace-nowrap">
                              {v.exclusion_rule ? (
                                <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-950 border border-indigo-300 font-mono text-[10px] font-bold">
                                  {v.exclusion_rule}
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-300 font-mono text-[10px] font-semibold">
                                  None (In Scope)
                                </span>
                              )}
                            </td>

                            <td className="py-2.5 px-3 align-top font-mono font-extrabold text-slate-900 whitespace-nowrap">
                              {v.confidence}%
                            </td>

                            <td className="py-2.5 px-3 align-top text-slate-700 leading-relaxed min-w-[220px]">
                              <div>{v.rationale}</div>
                              <div className="mt-1 flex items-center gap-1.5 font-mono text-[9px] text-slate-600">
                                <span>{v.verification_mode}</span>
                                {v.cached && (
                                  <span className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 font-bold">
                                    Cached
                                  </span>
                                )}
                              </div>
                            </td>

                            <td className="py-2.5 px-3 align-top text-right whitespace-nowrap">
                              <button
                                type="button"
                                onClick={() =>
                                  void handleApplyAdversarialTriage(v)
                                }
                                className={`px-2.5 py-1.5 rounded-lg font-mono text-[10px] font-bold inline-flex items-center gap-1 border transition-colors ${
                                  isApplied
                                    ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                                    : "bg-indigo-700 hover:bg-indigo-800 text-white border-indigo-800 shadow-sm"
                                }`}
                              >
                                <CheckCircle2 className="w-3 h-3" />
                                <span>
                                  {isApplied
                                    ? "Applied"
                                    : "Apply to Triage"}
                                </span>
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* PANEL C: S8 MULTI-HOP EXPLOIT CHAIN SIMULATION CANVAS               */}
      {/* =================================================================== */}
      {activeTab === "CHAINS" && (
        <div className="space-y-4">
          {chains.length === 0 ? (
            <div className="bg-white border border-slate-200 rounded-xl p-10 text-center shadow-sm space-y-3">
              <GitBranch className="w-9 h-9 mx-auto text-rose-700" />
              <div className="text-sm font-extrabold text-slate-900">
                {isRunningExploitChains
                  ? "Synthesizing S8 Multi-Hop Exploit Chains..."
                  : "No Multi-Hop Exploit Chains Synthesized Yet"}
              </div>
              <p className="text-xs text-slate-700 max-w-xl mx-auto">
                Click <strong>Synthesize S8 Exploit Chains</strong> to stitch
                exposed API entrypoints, leaked credentials, CPG &amp; cognitive
                findings, Leiden cross-community bridges, and business crown
                jewels into ranked attack graphs.
              </p>
              <button
                type="button"
                disabled={isRunningExploitChains}
                onClick={() => void handleSynthesizeChains()}
                className="px-4 py-2 rounded-lg bg-rose-700 hover:bg-rose-800 disabled:opacity-50 text-white text-xs font-extrabold inline-flex items-center gap-2 shadow-sm"
              >
                {isRunningExploitChains ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Crosshair className="w-4 h-4" />
                )}
                <span>Synthesize S8 Exploit Chains</span>
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
              {/* Left Rail: Ranked Exploit Chain Cards */}
              <div className="xl:col-span-4 space-y-2.5">
                <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm flex items-center justify-between gap-2">
                  <div>
                    <div className="text-xs font-extrabold text-slate-900">
                      Ranked S8 Exploit Chains ({chains.length})
                    </div>
                    <div className="text-[11px] text-slate-700">
                      {exploitChainsResult?.critical_chains ?? 0} Critical •{" "}
                      {exploitChainsResult?.execution_mode || "DETERMINISTIC"}
                    </div>
                  </div>
                  {exploitChainsResult?.synced_to_pasta && (
                    <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 text-[9px] font-mono font-extrabold text-right">
                      PASTA VI + SAR Synced
                    </span>
                  )}
                </div>

                <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                  {chains.map((chain) => {
                    const isSelected = selectedChain?.id === chain.id;
                    return (
                      <button
                        key={chain.id}
                        type="button"
                        onClick={() => setSelectedChainId(chain.id)}
                        className={`w-full text-left p-3.5 rounded-xl border transition-all space-y-2 ${
                          isSelected
                            ? "bg-rose-50/70 border-rose-500 ring-1 ring-rose-500/30 shadow-sm"
                            : "bg-white hover:bg-slate-50 border-slate-200"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1.5 flex-wrap">
                          <span
                            className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${getSeverityBadgeClass(
                              chain.severity
                            )}`}
                          >
                            {chain.severity}
                          </span>
                          <div className="flex items-center gap-1.5 font-mono text-[10px]">
                            <span className="px-1.5 py-0.5 rounded bg-rose-50 border border-rose-300 text-rose-950 font-extrabold">
                              CVSS {chain.chain_cvss.toFixed(1)}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-sky-50 border border-sky-300 text-sky-950 font-bold">
                              {chain.hops.length} Hops
                            </span>
                          </div>
                        </div>

                        <div className="text-xs font-extrabold text-slate-900 leading-snug line-clamp-2">
                          {chain.title}
                        </div>

                        <div className="flex items-center gap-1 flex-wrap">
                          {chain.blast_radius_communities
                            .slice(0, 3)
                            .map((comm) => (
                              <span
                                key={comm}
                                className="px-1.5 py-0.5 rounded bg-indigo-50 border border-indigo-300 text-indigo-950 font-mono text-[9px] font-bold truncate max-w-[140px]"
                              >
                                {comm}
                              </span>
                            ))}
                          {exploitChainsResult?.synced_to_pasta && (
                            <span className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 font-mono text-[9px] font-bold">
                              Synced to PASTA Stage VI &amp; SAR .docx/.pdf
                            </span>
                          )}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Main ReactFlow Canvas wrapped in ReactFlowProvider */}
              <div className="xl:col-span-8">
                {selectedChain && (
                  <ReactFlowProvider>
                    <ExploitChainCanvasInner
                      chain={selectedChain}
                      syncedToPasta={Boolean(
                        exploitChainsResult?.synced_to_pasta
                      )}
                      aiIsBusy={aiIsBusy}
                      onJumpToIde={openCodeLocationInIde}
                      onExplainChainWithAi={handleExplainChainWithAi}
                    />
                  </ReactFlowProvider>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default CognitiveSecurityWorkbench;
