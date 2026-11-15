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
  GoLiveGateStatus,
  GoLiveObservationItem,
  GoLiveSlaWindow,
  GoLiveVerdict,
  PastaAttackTreeNode,
  PastaAttackTreeScenario,
  PastaBusinessPreset,
  PastaCrownJewelItem,
  PastaEvidenceItem,
  PastaStageItem,
} from "@/types/cpg";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ClipboardCheck,
  Code2,
  Crosshair,
  Crown,
  Download,
  FileSpreadsheet,
  FileText,
  GitBranch,
  Layers,
  Loader2,
  Maximize2,
  RefreshCw,
  RotateCcw,
  Scale,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Sparkles,
  Target,
} from "lucide-react";

const ATTACK_NODE_WIDTH = 260;
const ATTACK_NODE_HEIGHT = 96;

type GateMatrixTab =
  | "ALL"
  | "MANDATORY_PRE_GO_LIVE"
  | "POST_GO_LIVE_SLA"
  | "RISK_ACCEPTED_WAIVER"
  | "MAKE_IT_LIVE_RUNBOOK";

interface AttackTreeCardData {
  nodeRole: PastaAttackTreeNode["node_role"];
  title: string;
  subtitle: string;
  severity: PastaAttackTreeNode["severity"];
  filepath: string;
  line: number;
  cweOrCapec: string;
  isSevered: boolean;
  linkedFindingId?: string | null;
}

function formatShortPath(filepath: string): string {
  const clean = (filepath || "").replace(/\\/g, "/").trim();
  if (!clean) return "";
  const parts = clean.split("/").filter(Boolean);
  if (parts.length <= 2) return clean;
  return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
}

function getVerdictBannerMeta(verdict: GoLiveVerdict): {
  badgeClasses: string;
  borderClasses: string;
  surfaceClasses: string;
} {
  switch (verdict) {
    case "APPROVED_FOR_GO_LIVE":
      return {
        badgeClasses: "bg-emerald-700 text-white border-emerald-800",
        borderClasses: "border-emerald-300",
        surfaceClasses: "bg-emerald-50/60",
      };
    case "CONDITIONAL_GO_LIVE":
      return {
        badgeClasses: "bg-amber-700 text-white border-amber-800",
        borderClasses: "border-amber-300",
        surfaceClasses: "bg-amber-50/60",
      };
    case "NO_GO_HOLD_RELEASE":
    default:
      return {
        badgeClasses: "bg-rose-700 text-white border-rose-800",
        borderClasses: "border-rose-300",
        surfaceClasses: "bg-rose-50/60",
      };
  }
}

function getRiskLevelMeta(level: string): {
  badgeClasses: string;
  barClasses: string;
} {
  switch ((level || "").toUpperCase()) {
    case "CRITICAL":
      return {
        badgeClasses: "bg-rose-700 text-white border-rose-800",
        barClasses: "bg-rose-600",
      };
    case "HIGH":
      return {
        badgeClasses: "bg-rose-50 text-rose-900 border-rose-300",
        barClasses: "bg-rose-500",
      };
    case "MEDIUM":
    case "MODERATE":
      return {
        badgeClasses: "bg-amber-50 text-amber-950 border-amber-300",
        barClasses: "bg-amber-500",
      };
    case "LOW":
    case "PASS":
    default:
      return {
        badgeClasses: "bg-emerald-50 text-emerald-900 border-emerald-300",
        barClasses: "bg-emerald-600",
      };
  }
}

function getStageStatusMeta(status: PastaStageItem["status"]): {
  label: string;
  badgeClasses: string;
  accentBar: string;
} {
  switch (status) {
    case "PASS":
      return {
        label: "PASS",
        badgeClasses: "bg-emerald-50 text-emerald-900 border-emerald-300",
        accentBar: "bg-emerald-600",
      };
    case "MONITORED":
      return {
        label: "MONITORED",
        badgeClasses: "bg-amber-50 text-amber-950 border-amber-300",
        accentBar: "bg-amber-500",
      };
    case "ACTION_REQUIRED":
    default:
      return {
        label: "ACTION REQUIRED",
        badgeClasses: "bg-rose-50 text-rose-900 border-rose-300",
        accentBar: "bg-rose-600",
      };
  }
}

function getScenarioStatusMeta(
  status: PastaAttackTreeScenario["status"]
): {
  label: string;
  badgeClasses: string;
} {
  switch (status) {
    case "EXPLOITABLE_PATH":
      return {
        label: "EXPLOITABLE PATH",
        badgeClasses: "bg-rose-50 text-rose-900 border-rose-300",
      };
    case "PARTIALLY_GUARDED":
      return {
        label: "PARTIALLY GUARDED",
        badgeClasses: "bg-amber-50 text-amber-950 border-amber-300",
      };
    case "SEVERED_BY_CONTROLS":
    default:
      return {
        label: "SEVERED BY CONTROLS",
        badgeClasses: "bg-emerald-50 text-emerald-900 border-emerald-300",
      };
  }
}

function getAttackNodeRoleStyle(
  role: PastaAttackTreeNode["node_role"],
  isSevered: boolean
): {
  roleLabel: string;
  cardClasses: string;
  pillClasses: string;
  dotClasses: string;
} {
  switch (role) {
    case "ENTRYPOINT":
      return {
        roleLabel: "ENTRYPOINT",
        cardClasses: "bg-sky-50 border-sky-400 text-sky-950",
        pillClasses: "bg-sky-700 text-white",
        dotClasses: "!bg-sky-700",
      };
    case "CAPEC_VECTOR":
      return {
        roleLabel: "CAPEC VECTOR",
        cardClasses: "bg-purple-50 border-purple-400 text-purple-950",
        pillClasses: "bg-purple-700 text-white",
        dotClasses: "!bg-purple-700",
      };
    case "PROPAGATION":
      return {
        roleLabel: "PROPAGATION",
        cardClasses: "bg-amber-50 border-amber-400 text-amber-950",
        pillClasses: "bg-amber-700 text-white",
        dotClasses: "!bg-amber-700",
      };
    case "VULN_SINK":
      return {
        roleLabel: "VULN SINK",
        cardClasses: "bg-rose-50 border-rose-500 text-rose-950",
        pillClasses: "bg-rose-700 text-white",
        dotClasses: "!bg-rose-700",
      };
    case "BFL_SHIELD":
      return {
        roleLabel: "BFL SHIELD",
        cardClasses:
          "bg-emerald-50 border-2 border-dashed border-emerald-600 text-emerald-950",
        pillClasses: "bg-emerald-700 text-white",
        dotClasses: "!bg-emerald-700",
      };
    case "CROWN_JEWEL":
      return {
        roleLabel: "CROWN JEWEL",
        cardClasses: "bg-indigo-50 border-indigo-400 text-indigo-950",
        pillClasses: "bg-indigo-700 text-white",
        dotClasses: "!bg-indigo-700",
      };
    case "GOAL":
    default:
      if (isSevered) {
        return {
          roleLabel: "GOAL BLOCKED ✓",
          cardClasses: "bg-emerald-50 border-emerald-500 text-emerald-950",
          pillClasses: "bg-emerald-700 text-white",
          dotClasses: "!bg-emerald-700",
        };
      }
      return {
        roleLabel: "ATTACKER GOAL",
        cardClasses: "bg-rose-50 border-rose-500 text-rose-950",
        pillClasses: "bg-rose-700 text-white",
        dotClasses: "!bg-rose-700",
      };
  }
}

const PastaAttackTreeCardNode = memo(
  ({ data }: NodeProps<AttackTreeCardData>) => {
    const styleMeta = getAttackNodeRoleStyle(data.nodeRole, data.isSevered);
    const hasLocation = Boolean((data.filepath || "").trim());

    return (
      <div
        style={{ width: ATTACK_NODE_WIDTH, minHeight: ATTACK_NODE_HEIGHT }}
        className={`rounded-xl border shadow-sm px-3 py-2 transition-shadow hover:shadow-md ${
          hasLocation ? "cursor-pointer" : "cursor-default"
        } ${styleMeta.cardClasses}`}
      >
        <Handle
          type="target"
          position={Position.Left}
          id="left-tgt"
          className={`!w-2.5 !h-2.5 !border-2 !border-white ${styleMeta.dotClasses}`}
        />

        <div className="flex items-center justify-between gap-1.5 mb-1">
          <span
            className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-extrabold tracking-wide uppercase ${styleMeta.pillClasses}`}
          >
            {styleMeta.roleLabel}
          </span>
          <div className="flex items-center gap-1 min-w-0">
            {data.isSevered && data.nodeRole !== "GOAL" && (
              <span className="px-1.5 py-0.5 rounded bg-emerald-700 text-white text-[9px] font-mono font-bold">
                SEVERED ✓
              </span>
            )}
            {data.cweOrCapec && (
              <span className="px-1.5 py-0.5 rounded bg-white/90 border border-slate-300 text-slate-900 text-[9px] font-mono font-bold truncate max-w-[105px]">
                {data.cweOrCapec}
              </span>
            )}
          </div>
        </div>

        <div className="text-xs font-extrabold leading-snug text-slate-950 line-clamp-1">
          {data.title}
        </div>
        <div className="text-[11px] leading-tight text-slate-800 line-clamp-1 mt-0.5">
          {data.subtitle || "Deterministic CPG attack path node"}
        </div>

        <div className="mt-1.5 pt-1 border-t border-slate-300/70 flex items-center justify-between gap-1 text-[10px] font-mono text-slate-800">
          <span className="truncate">
            {hasLocation
              ? `${formatShortPath(data.filepath)}:L${data.line || 1}`
              : `Severity: ${data.severity}`}
          </span>
          {hasLocation && (
            <span className="font-bold text-indigo-900 shrink-0">
              IDE →
            </span>
          )}
        </div>

        <Handle
          type="source"
          position={Position.Right}
          id="right-src"
          className={`!w-2.5 !h-2.5 !border-2 !border-white ${styleMeta.dotClasses}`}
        />
      </div>
    );
  }
);
PastaAttackTreeCardNode.displayName = "PastaAttackTreeCardNode";

const attackTreeNodeTypes = {
  pastaAttackNode: PastaAttackTreeCardNode,
};

function layoutAttackTreeScenario(scenario: PastaAttackTreeScenario): {
  nodes: Node<AttackTreeCardData>[];
  edges: Edge[];
} {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: "LR",
    nodesep: 42,
    ranksep: 84,
    marginx: 24,
    marginy: 24,
  });

  const validIds = new Set<string>();
  for (const n of scenario.nodes) {
    validIds.add(n.id);
    g.setNode(n.id, { width: ATTACK_NODE_WIDTH, height: ATTACK_NODE_HEIGHT });
  }

  const validEdges = scenario.edges.filter(
    (e) => validIds.has(e.source) && validIds.has(e.target)
  );
  for (const e of validEdges) {
    g.setEdge(e.source, e.target);
  }

  if (scenario.nodes.length > 0) {
    dagre.layout(g);
  }

  const rfNodes: Node<AttackTreeCardData>[] = scenario.nodes.map((n, idx) => {
    const pos = g.node(n.id);
    const x =
      pos && Number.isFinite(pos.x)
        ? pos.x - ATTACK_NODE_WIDTH / 2
        : idx * (ATTACK_NODE_WIDTH + 84);
    const y =
      pos && Number.isFinite(pos.y) ? pos.y - ATTACK_NODE_HEIGHT / 2 : 24;

    return {
      id: n.id,
      type: "pastaAttackNode",
      position: { x, y },
      width: ATTACK_NODE_WIDTH,
      height: ATTACK_NODE_HEIGHT,
      style: { width: ATTACK_NODE_WIDTH, minHeight: ATTACK_NODE_HEIGHT },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      data: {
        nodeRole: n.node_role,
        title: n.title,
        subtitle: n.subtitle,
        severity: n.severity,
        filepath: n.filepath,
        line: n.line,
        cweOrCapec: n.cwe_or_capec,
        isSevered: n.is_severed,
        linkedFindingId: n.linked_finding_id,
      },
    };
  });

  const rfEdges: Edge[] = validEdges.map((e) => {
    const blocked = Boolean(e.is_blocked);
    const stroke = blocked ? "#047857" : "#be123c";
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      sourceHandle: "right-src",
      targetHandle: "left-tgt",
      type: "smoothstep",
      animated: !blocked,
      label: e.label || (blocked ? "SEVERED ✓" : "EXPLOIT HOP ▶"),
      style: {
        stroke,
        strokeWidth: blocked ? 2.2 : 2.5,
        ...(blocked ? { strokeDasharray: "6 4" } : {}),
      },
      labelStyle: {
        fill: blocked ? "#065f46" : "#881337",
        fontWeight: 700,
        fontSize: 10,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      },
      labelBgStyle: {
        fill: blocked ? "#ecfdf5" : "#fff1f2",
        stroke: blocked ? "#6ee7b7" : "#fda4af",
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

interface AttackTreeCanvasInnerProps {
  scenario: PastaAttackTreeScenario;
  isAiBusy: boolean;
  onExplainAi: (scenario: PastaAttackTreeScenario) => void;
  onJumpToIde: (filepath?: string, line?: number, findingId?: string) => void;
}

const AttackTreeCanvasInner: React.FC<AttackTreeCanvasInnerProps> = ({
  scenario,
  isAiBusy,
  onExplainAi,
  onJumpToIde,
}) => {
  const [rfInstance, setRfInstance] = useState<ReactFlowInstance | null>(null);

  const { nodes, edges } = useMemo(
    () => layoutAttackTreeScenario(scenario),
    [scenario]
  );

  const handleFitTree = useCallback(() => {
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
    }, 120);
    return () => {
      window.cancelAnimationFrame(rafId);
      window.clearTimeout(timerId);
    };
  }, [scenario.id, nodes.length, rfInstance]);

  const hasPrimarySink = Boolean((scenario.primary_filepath || "").trim());

  return (
    <div className="rounded-xl bg-white border border-slate-300 overflow-hidden shadow-sm">
      {/* Top Canvas Telemetry & Action Bar */}
      <div className="px-4 py-2.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="px-2.5 py-1 rounded-md bg-white border border-slate-300 text-xs font-bold text-slate-900 flex items-center gap-1.5">
            <Target className="w-3.5 h-3.5 text-rose-700" />
            <span>Persona: {scenario.attacker_persona}</span>
          </span>
          {scenario.mitre_capec && (
            <span className="px-2 py-0.5 rounded bg-purple-50 border border-purple-300 text-purple-900 text-[11px] font-mono font-bold">
              {scenario.mitre_capec}
            </span>
          )}
          <span className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-300 text-indigo-900 text-[11px] font-mono font-bold">
            STRIDE: {scenario.stride_letter}
          </span>
          {scenario.target_crown_jewel && (
            <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-300 text-amber-950 text-[11px] font-bold flex items-center gap-1">
              <Crown className="w-3 h-3 text-amber-700" />
              <span>Target: {scenario.target_crown_jewel}</span>
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            disabled={isAiBusy}
            onClick={() => onExplainAi(scenario)}
            className="px-3 py-1.5 rounded-lg bg-indigo-700 hover:bg-indigo-800 disabled:opacity-60 text-white text-xs font-bold flex items-center gap-1.5 transition-colors shadow-sm"
          >
            {isAiBusy ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Sparkles className="w-3.5 h-3.5" />
            )}
            <span>✨ AI Explain Attack Tree</span>
          </button>

          <button
            type="button"
            onClick={handleFitTree}
            className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 text-xs font-bold flex items-center gap-1.5 transition-colors"
          >
            <Maximize2 className="w-3.5 h-3.5 text-sky-700" />
            <span>Fit Tree</span>
          </button>

          <button
            type="button"
            disabled={!hasPrimarySink}
            onClick={() =>
              onJumpToIde(
                scenario.primary_filepath || undefined,
                scenario.primary_line || 1,
                scenario.linked_finding_id || undefined
              )
            }
            className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 disabled:opacity-50 border border-slate-300 text-slate-900 text-xs font-bold flex items-center gap-1.5 transition-colors"
          >
            <Code2 className="w-3.5 h-3.5 text-indigo-700" />
            <span>Inspect Primary Sink in IDE</span>
          </button>
        </div>
      </div>

      {/* Interactive ReactFlow LR Attack Tree Canvas */}
      <div style={{ height: 340 }} className="w-full bg-slate-50 relative">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={attackTreeNodeTypes}
          onInit={(inst) => {
            setRfInstance(inst);
            try {
              inst.fitView({ padding: 0.2, duration: 0 });
            } catch {}
          }}
          onNodeClick={(_evt, node) => {
            const fp = (node.data?.filepath || "").trim();
            if (!fp) return;
            onJumpToIde(
              fp,
              Number(node.data?.line || 1),
              node.data?.linkedFindingId ||
                scenario.linked_finding_id ||
                undefined
            );
          }}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.25}
          maxZoom={1.75}
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

      {/* Narrative + BFL Chokepoint Remediation Footer Strip */}
      <div className="p-4 bg-white border-t border-slate-200 grid grid-cols-1 lg:grid-cols-2 gap-3">
        <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
          <div className="text-[11px] font-mono font-extrabold uppercase tracking-wider text-slate-800 mb-1 flex items-center gap-1.5">
            <GitBranch className="w-3.5 h-3.5 text-rose-700" />
            <span>PASTA Stage VI Attack Path Narrative</span>
          </div>
          <p className="text-xs text-slate-800 leading-relaxed">
            {scenario.narrative}
          </p>
        </div>

        <div className="p-3 rounded-xl bg-emerald-50/70 border border-emerald-300">
          <div className="text-[11px] font-mono font-extrabold uppercase tracking-wider text-emerald-900 mb-1 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-700" />
            <span>
              Best-Fix-Location (BFL) Chokepoint Remediation (-
              {scenario.projected_risk_reduction} Risk Pts)
            </span>
          </div>
          <p className="text-xs text-emerald-950 leading-relaxed font-medium">
            {scenario.bfl_remediation}
          </p>
        </div>
      </div>
    </div>
  );
};

interface ObservationGateCardProps {
  obs: GoLiveObservationItem;
  isSavingPasta: boolean;
  onSaveOverride: (payload: {
    observation_id: string;
    gate_status?: GoLiveGateStatus;
    sla_window?: GoLiveSlaWindow | null;
    compensating_control_note?: string | null;
    reset_override?: boolean;
  }) => Promise<unknown>;
  onJumpToIde: (filepath?: string, line?: number, findingId?: string) => void;
}

function getGateBadgeMeta(
  gate: GoLiveGateStatus,
  slaWindow: GoLiveSlaWindow
): {
  label: string;
  classes: string;
} {
  switch (gate) {
    case "MANDATORY_PRE_GO_LIVE":
      return {
        label: "MANDATORY PRE-GO-LIVE BLOCKER",
        classes: "bg-rose-700 text-white border-rose-800",
      };
    case "RISK_ACCEPTED_WAIVER":
      return {
        label: "RISK-ACCEPTED WAIVER",
        classes: "bg-indigo-50 text-indigo-900 border-indigo-300",
      };
    case "POST_GO_LIVE_SLA":
    default:
      return {
        label: `POST-GO-LIVE ALLOWED • SLA: ${slaWindow}`,
        classes: "bg-amber-50 text-amber-950 border-amber-400",
      };
  }
}

const ObservationGateCard: React.FC<ObservationGateCardProps> = ({
  obs,
  isSavingPasta,
  onSaveOverride,
  onJumpToIde,
}) => {
  const [draftGate, setDraftGate] = useState<GoLiveGateStatus>(obs.gate_status);
  const [draftSla, setDraftSla] = useState<GoLiveSlaWindow>(obs.sla_window);
  const [draftNote, setDraftNote] = useState<string>(
    obs.compensating_control || ""
  );

  useEffect(() => {
    setDraftGate(obs.gate_status);
    setDraftSla(obs.sla_window);
    setDraftNote(obs.compensating_control || "");
  }, [obs.id, obs.gate_status, obs.sla_window, obs.compensating_control]);

  const gateMeta = getGateBadgeMeta(obs.gate_status, obs.sla_window);
  const sevMeta = getRiskLevelMeta(obs.severity);
  const hasFile = Boolean((obs.filepath || "").trim());

  const handleGateSelectChange = (nextGate: GoLiveGateStatus) => {
    setDraftGate(nextGate);
    if (nextGate === "MANDATORY_PRE_GO_LIVE") {
      setDraftSla("PRE_LAUNCH");
    } else if (nextGate === "RISK_ACCEPTED_WAIVER") {
      setDraftSla("WAIVED");
    } else if (draftSla === "PRE_LAUNCH" || draftSla === "WAIVED") {
      setDraftSla("30_DAYS");
    }
  };

  return (
    <div className="rounded-xl bg-white border border-slate-300 shadow-sm overflow-hidden">
      {/* Header Strip */}
      <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-start justify-between gap-3 flex-wrap">
        <div className="space-y-1.5 min-w-0 flex-1">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span
              className={`px-2.5 py-0.5 rounded-md border text-[11px] font-mono font-extrabold tracking-wide ${gateMeta.classes}`}
            >
              {gateMeta.label}
            </span>

            {obs.is_overridden && (
              <span className="px-2 py-0.5 rounded-md bg-purple-50 text-purple-900 border border-purple-300 text-[10px] font-mono font-extrabold">
                OVERRIDDEN (Default: {obs.default_gate_status})
              </span>
            )}

            <span
              className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${sevMeta.badgeClasses}`}
            >
              {obs.severity}
            </span>

            <span className="px-2 py-0.5 rounded bg-white border border-slate-300 text-slate-900 text-[10px] font-mono font-bold">
              {obs.source_type}
            </span>

            {obs.cwe_or_standard && (
              <span className="px-2 py-0.5 rounded bg-sky-50 border border-sky-300 text-sky-900 text-[10px] font-mono font-bold">
                {obs.cwe_or_standard}
              </span>
            )}

            <span className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-300 text-indigo-900 text-[10px] font-mono font-bold">
              PASTA-{obs.pasta_stage}
            </span>

            <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-300 text-slate-800 text-[10px] font-mono font-bold">
              STRIDE-{obs.stride_letter}
            </span>

            <span className="px-2 py-0.5 rounded bg-white border border-slate-300 text-slate-800 text-[10px] font-mono font-bold">
              {obs.reachability_status}
            </span>
          </div>

          <h4 className="text-sm font-extrabold text-slate-950 leading-snug">
            {obs.title}
          </h4>
        </div>

        <div className="flex items-center gap-2 flex-wrap shrink-0">
          <span className="px-2.5 py-1 rounded-lg bg-emerald-50 border border-emerald-300 text-emerald-900 text-xs font-mono font-extrabold">
            -{obs.risk_reduction_points} risk pts
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-white border border-slate-300 text-slate-800 text-xs font-mono font-bold">
            {obs.effort_estimate}
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-slate-100 border border-slate-300 text-slate-900 text-xs font-bold">
            RACI: {obs.raci_owner}
          </span>
        </div>
      </div>

      {/* 4-Column / 2x2 Architectural Rationale Grid */}
      <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
          <div className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-slate-800 mb-1">
            Why This Is an Architectural Issue
          </div>
          <p className="text-xs text-slate-800 leading-relaxed">
            {obs.why_issue}
          </p>
        </div>

        <div className="p-3 rounded-lg bg-amber-50/50 border border-amber-200">
          <div className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-amber-950 mb-1">
            Go-Live Gate Classification Rationale
          </div>
          <p className="text-xs text-slate-900 leading-relaxed">
            {obs.why_gate_classification}
          </p>
        </div>

        <div className="p-3 rounded-lg bg-emerald-50/50 border border-emerald-200">
          <div className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-emerald-900 mb-1">
            Mandatory Fix / Remediation Action
          </div>
          <p className="text-xs text-slate-900 leading-relaxed">
            {obs.mandatory_fix_action}
          </p>
        </div>

        <div className="p-3 rounded-lg bg-indigo-50/50 border border-indigo-200">
          <div className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-indigo-900 mb-1">
            Compensating Control / Waiver Condition
          </div>
          <p className="text-xs text-slate-900 leading-relaxed">
            {obs.compensating_control ||
              "No compensating control recorded yet."}
          </p>
        </div>
      </div>

      {/* Interactive ARB Gate Override Controls Footer */}
      <div className="px-4 py-3 bg-slate-50 border-t border-slate-200 flex items-center justify-between gap-2.5 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap flex-1 min-w-[280px]">
          <label className="flex items-center gap-1.5 text-xs font-bold text-slate-800">
            <span>Gate:</span>
            <select
              aria-label={`Gate status for ${obs.title}`}
              value={draftGate}
              onChange={(e) =>
                handleGateSelectChange(e.target.value as GoLiveGateStatus)
              }
              className="px-2.5 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-900 text-xs font-bold focus:outline-none focus:ring-2 focus:ring-indigo-600"
            >
              <option value="MANDATORY_PRE_GO_LIVE">
                MANDATORY_PRE_GO_LIVE
              </option>
              <option value="POST_GO_LIVE_SLA">POST_GO_LIVE_SLA</option>
              <option value="RISK_ACCEPTED_WAIVER">RISK_ACCEPTED_WAIVER</option>
            </select>
          </label>

          <label className="flex items-center gap-1.5 text-xs font-bold text-slate-800">
            <span>SLA:</span>
            <select
              aria-label={`SLA window for ${obs.title}`}
              value={draftSla}
              onChange={(e) => setDraftSla(e.target.value as GoLiveSlaWindow)}
              className="px-2.5 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-900 text-xs font-mono font-bold focus:outline-none focus:ring-2 focus:ring-indigo-600"
            >
              <option value="PRE_LAUNCH">PRE_LAUNCH</option>
              <option value="7_DAYS">7_DAYS</option>
              <option value="14_DAYS">14_DAYS</option>
              <option value="30_DAYS">30_DAYS</option>
              <option value="90_DAYS">90_DAYS</option>
              <option value="WAIVED">WAIVED</option>
            </select>
          </label>

          <input
            type="text"
            aria-label={`Compensating control or waiver note for ${obs.title}`}
            value={draftNote}
            onChange={(e) => setDraftNote(e.target.value)}
            placeholder="Compensating control / ARB waiver rationale..."
            className="flex-1 min-w-[200px] px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-900 placeholder:text-slate-600 text-xs focus:outline-none focus:ring-2 focus:ring-indigo-600"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            disabled={isSavingPasta}
            onClick={() =>
              void onSaveOverride({
                observation_id: obs.id,
                gate_status: draftGate,
                sla_window: draftSla,
                compensating_control_note: draftNote,
              })
            }
            className="px-3 py-1.5 rounded-lg bg-indigo-700 hover:bg-indigo-800 disabled:opacity-60 text-white text-xs font-bold transition-colors shadow-sm"
          >
            Apply Gate Override
          </button>

          {obs.is_overridden && (
            <button
              type="button"
              disabled={isSavingPasta}
              onClick={() =>
                void onSaveOverride({
                  observation_id: obs.id,
                  reset_override: true,
                })
              }
              className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 disabled:opacity-60 border border-slate-300 text-slate-800 text-xs font-bold flex items-center gap-1 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5 text-slate-700" />
              <span>Reset Default</span>
            </button>
          )}

          <button
            type="button"
            disabled={!hasFile}
            onClick={() =>
              onJumpToIde(
                obs.filepath || undefined,
                obs.line || 1,
                obs.linked_finding_id || undefined
              )
            }
            className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 disabled:opacity-50 border border-slate-300 text-slate-900 text-xs font-mono font-bold flex items-center gap-1.5 transition-colors"
          >
            <Code2 className="w-3.5 h-3.5 text-indigo-700" />
            <span>
              Inspect in IDE ({obs.filepath || "workspace"}:{obs.line || 1})
            </span>
          </button>
        </div>
      </div>
    </div>
  );
};

function classifyRunbookPhase(stepText: string): {
  phaseBadge: string;
  badgeClasses: string;
} {
  const upper = (stepText || "").toUpperCase();
  if (
    upper.includes("PHASE A") ||
    upper.includes("PRE-GO-LIVE") ||
    upper.includes("PRE-LAUNCH") ||
    upper.includes("BLOCKER")
  ) {
    return {
      phaseBadge: "PHASE A • MANDATORY PRE-GO-LIVE",
      badgeClasses: "bg-rose-700 text-white border-rose-800",
    };
  }
  if (
    upper.includes("PHASE B") ||
    upper.includes("POST-GO-LIVE") ||
    upper.includes("SLA")
  ) {
    return {
      phaseBadge: "PHASE B • POST-GO-LIVE SLA",
      badgeClasses: "bg-amber-700 text-white border-amber-800",
    };
  }
  if (
    upper.includes("FINAL") ||
    upper.includes("SIGN-OFF") ||
    upper.includes("VERIF") ||
    upper.includes("RE-SCAN")
  ) {
    return {
      phaseBadge: "FINAL ARB VERIFICATION",
      badgeClasses: "bg-emerald-700 text-white border-emerald-800",
    };
  }
  return {
    phaseBadge: "GO-LIVE EXECUTION STEP",
    badgeClasses: "bg-indigo-700 text-white border-indigo-800",
  };
}

export const PastaThreatWorkbench: React.FC = () => {
  const storePastaAssessment = useAuditStore((s) => s.pastaAssessment);
  const sastPlusSuite = useAuditStore((s) => s.sastPlusSuite);
  const pastaAssessment =
    storePastaAssessment ?? sastPlusSuite?.pasta_assessment ?? null;
  const isLoadingPasta = useAuditStore((s) => s.isLoadingPasta);
  const isSavingPasta = useAuditStore((s) => s.isSavingPasta);
  const exportingSarFormat = useAuditStore((s) => s.exportingSarFormat);
  const fetchPastaState = useAuditStore((s) => s.fetchPastaState);
  const savePastaProfileState = useAuditStore((s) => s.savePastaProfileState);
  const savePastaGateOverride = useAuditStore((s) => s.savePastaGateOverride);
  const downloadSarGoLiveReport = useAuditStore(
    (s) => s.downloadSarGoLiveReport
  );
  const openCodeLocationInIde = useAuditStore((s) => s.openCodeLocationInIde);
  const explainGraphAi = useAuditStore((s) => s.explainGraphAi);
  const setAiDrawerOpen = useAuditStore((s) => s.setAiDrawerOpen);
  const isAiBusy = useAuditStore((s) => s.aiIsBusy);
  const projectPath = useAuditStore((s) => s.projectPath);

  const [selectedStageNumber, setSelectedStageNumber] = useState<number>(1);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>("");
  const [activeGateTab, setActiveGateTab] = useState<GateMatrixTab>("ALL");
  const [isWeightsDrawerOpen, setIsWeightsDrawerOpen] =
    useState<boolean>(false);
  const [weightDrafts, setWeightDrafts] = useState<Record<string, number>>({});
  const [exportFeedback, setExportFeedback] = useState<string | null>(null);
  const lastAutoHydratedKeyRef = useRef<string | null>(null);
  const targetKey = (projectPath || "__active__").trim();

  useEffect(() => {
    if (pastaAssessment) {
      lastAutoHydratedKeyRef.current = targetKey;
      return;
    }
    if (!isLoadingPasta && lastAutoHydratedKeyRef.current !== targetKey) {
      lastAutoHydratedKeyRef.current = targetKey;
      void fetchPastaState();
    }
  }, [pastaAssessment, isLoadingPasta, targetKey, fetchPastaState]);

  useEffect(() => {
    if (!pastaAssessment) return;
    const nextWeights: Record<string, number> = {};
    for (const cj of pastaAssessment.crown_jewels || []) {
      nextWeights[cj.id] = Number(cj.weight_multiplier ?? 1.0);
    }
    setWeightDrafts(nextWeights);
  }, [pastaAssessment]);

  useEffect(() => {
    const trees = pastaAssessment?.attack_trees || [];
    if (trees.length === 0) {
      setSelectedScenarioId("");
      return;
    }
    if (!trees.some((t) => t.id === selectedScenarioId)) {
      setSelectedScenarioId(trees[0].id);
    }
  }, [pastaAssessment?.attack_trees, selectedScenarioId]);

  const handleDownloadSar = useCallback(
    async (format: "docx" | "pdf") => {
      setExportFeedback(null);
      const ok = await downloadSarGoLiveReport(format);
      setExportFeedback(
        ok
          ? `Downloaded SAR Go-Live Architecture Report (.${format}) successfully.`
          : `Failed to export SAR Go-Live Report (.${format}). Verify backend connectivity.`
      );
    },
    [downloadSarGoLiveReport]
  );

  const handleExplainAttackTreeAi = useCallback(
    (sc: PastaAttackTreeScenario) => {
      setAiDrawerOpen(true, "GRAPH");
      void explainGraphAi({
        view_mode: "PASTA_ATTACK_TREE",
        finding_id: sc.linked_finding_id || null,
        nodes_digest: sc.nodes.map((n) => ({
          id: n.id,
          label: n.title,
          type: n.node_role,
          severity: n.severity,
          code: n.subtitle,
          filepath: n.filepath,
          start_line: n.line,
          cwe_or_capec: n.cwe_or_capec,
          is_severed: n.is_severed,
        })),
        edges_digest: sc.edges.map((e) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          type: e.label || (e.is_blocked ? "SEVERED_BY_BFL" : "ATTACK_VECTOR"),
          is_blocked: e.is_blocked,
        })),
      });
    },
    [explainGraphAi, setAiDrawerOpen]
  );

  const selectedStage: PastaStageItem | null = useMemo(() => {
    const stages = pastaAssessment?.stages || [];
    if (stages.length === 0) return null;
    return (
      stages.find((s) => s.stage_number === selectedStageNumber) || stages[0]
    );
  }, [pastaAssessment?.stages, selectedStageNumber]);

  const selectedScenario: PastaAttackTreeScenario | null = useMemo(() => {
    const trees = pastaAssessment?.attack_trees || [];
    if (trees.length === 0) return null;
    return trees.find((t) => t.id === selectedScenarioId) || trees[0];
  }, [pastaAssessment?.attack_trees, selectedScenarioId]);

  const filteredObservations: GoLiveObservationItem[] = useMemo(() => {
    const all = pastaAssessment?.golive_observations || [];
    if (activeGateTab === "ALL" || activeGateTab === "MAKE_IT_LIVE_RUNBOOK") {
      return all;
    }
    return all.filter((o) => o.gate_status === activeGateTab);
  }, [pastaAssessment?.golive_observations, activeGateTab]);

  // First-time Loading Skeleton / Guard Card
  if (!pastaAssessment) {
    return (
      <div className="rounded-2xl bg-white border border-slate-300 shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-50 border border-indigo-300 flex items-center justify-center">
              {isLoadingPasta ? (
                <Loader2 className="w-5 h-5 text-indigo-700 animate-spin" />
              ) : (
                <Scale className="w-5 h-5 text-indigo-700" />
              )}
            </div>
            <div>
              <h2 className="text-base font-extrabold text-slate-950">
                7-Stage PASTA Risk-Centric Threat Modeling & ARB Go-Live Gate
              </h2>
              <p className="text-xs text-slate-700">
                {isLoadingPasta
                  ? "Synthesizing Crown Jewels, 7-Stage PASTA telemetry, CAPEC attack trees, and Go-Live gate verdicts..."
                  : "PASTA threat model awaits initialization for the active repository."}
              </p>
            </div>
          </div>

          <button
            type="button"
            disabled={isLoadingPasta}
            onClick={() => void fetchPastaState()}
            className="px-3.5 py-2 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-60 text-white text-xs font-bold flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${isLoadingPasta ? "animate-spin" : ""}`}
            />
            <span>Refresh PASTA Simulation</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {[1, 2, 3, 4].map((slot) => (
            <div
              key={slot}
              className="h-20 rounded-xl bg-slate-50 border border-slate-200 p-3 animate-pulse flex flex-col justify-between"
            >
              <div className="h-3 w-28 rounded bg-slate-200" />
              <div className="h-5 w-20 rounded bg-slate-200" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  const verdictMeta = getVerdictBannerMeta(pastaAssessment.golive_verdict);
  const inherentMeta = getRiskLevelMeta(pastaAssessment.inherent_risk_level);
  const residualMeta = getRiskLevelMeta(pastaAssessment.residual_risk_level);
  const projectedMeta = getRiskLevelMeta(
    pastaAssessment.projected_golive_risk_level
  );

  const businessPresets: Array<{
    id: PastaBusinessPreset;
    label: string;
  }> = [
    {
      id: "AUTO_INFERRED",
      label: `Auto (${pastaAssessment.effective_business_preset})`,
    },
    { id: "FINTECH_PAYMENTS", label: "FinTech / PCI-DSS" },
    { id: "HEALTHCARE_PHI", label: "Healthcare / HIPAA" },
    { id: "AI_SAAS_PUBLIC", label: "AI SaaS / OWASP-LLM" },
    { id: "ENTERPRISE_INTERNAL", label: "Enterprise / SOC2" },
  ];

  return (
    <div className="space-y-5 bg-slate-50 text-slate-900">
      {/* =====================================================================
          SECTION 2: EXECUTIVE GO-LIVE READINESS & 3-STAGE RISK COMMAND HEADER
         ===================================================================== */}
      <section className="rounded-2xl bg-white border border-slate-300 shadow-sm overflow-hidden">
        <div
          className={`p-5 border-b border-slate-200 ${verdictMeta.surfaceClasses}`}
        >
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="space-y-2 max-w-4xl">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2.5 py-0.5 rounded-md bg-indigo-50 border border-indigo-300 text-indigo-900 text-[11px] font-mono font-extrabold uppercase tracking-wider">
                  PASTA 7-STAGE ARB DOSSIER
                </span>
                <span
                  className={`px-3 py-1 rounded-lg border text-xs font-mono font-extrabold tracking-wide shadow-sm ${verdictMeta.badgeClasses}`}
                >
                  {pastaAssessment.golive_verdict_label ||
                    pastaAssessment.golive_verdict}
                </span>
                <span className="px-2.5 py-0.5 rounded-md bg-white border border-slate-300 text-slate-800 text-[11px] font-mono font-bold">
                  Target: {pastaAssessment.application_name}
                </span>
              </div>

              <h2 className="text-lg font-extrabold text-slate-950 leading-snug">
                Security Architecture Review (SAR) & Production Go-Live Gate
              </h2>
              <p className="text-sm text-slate-800 leading-relaxed">
                {pastaAssessment.golive_executive_summary}
              </p>
            </div>

            <div className="flex items-center gap-2 flex-wrap shrink-0">
              <button
                type="button"
                disabled={isLoadingPasta || isSavingPasta}
                onClick={() => void fetchPastaState()}
                className="px-3 py-2 rounded-xl bg-white hover:bg-slate-100 disabled:opacity-60 border border-slate-300 text-slate-900 text-xs font-bold flex items-center gap-1.5 transition-colors shadow-sm"
              >
                <RefreshCw
                  className={`w-3.5 h-3.5 text-slate-700 ${
                    isLoadingPasta || isSavingPasta ? "animate-spin" : ""
                  }`}
                />
                <span>Refresh PASTA Simulation</span>
              </button>

              <button
                type="button"
                disabled={exportingSarFormat !== null}
                onClick={() => void handleDownloadSar("docx")}
                className="px-3.5 py-2 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-60 text-white text-xs font-bold flex items-center gap-1.5 transition-colors shadow-sm"
              >
                {exportingSarFormat === "docx" ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <FileSpreadsheet className="w-3.5 h-3.5" />
                )}
                <span>Download SAR Word (.docx)</span>
              </button>

              <button
                type="button"
                disabled={exportingSarFormat !== null}
                onClick={() => void handleDownloadSar("pdf")}
                className="px-3.5 py-2 rounded-xl bg-rose-700 hover:bg-rose-800 disabled:opacity-60 text-white text-xs font-bold flex items-center gap-1.5 transition-colors shadow-sm"
              >
                {exportingSarFormat === "pdf" ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <FileText className="w-3.5 h-3.5" />
                )}
                <span>Download SAR PDF (.pdf)</span>
              </button>
            </div>
          </div>

          {exportFeedback && (
            <div className="mt-3 px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-xs font-mono font-bold text-slate-900 inline-flex items-center gap-2">
              <Download className="w-3.5 h-3.5 text-indigo-700" />
              <span>{exportFeedback}</span>
            </div>
          )}
        </div>

        {/* 3-Stage Risk Progression KPI Grid (4 Cards) */}
        <div className="p-4 bg-white grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
          {/* Card 1: Inherent Risk */}
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col justify-between gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-extrabold text-slate-900">
                1. Inherent Risk
              </span>
              <span
                className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${inherentMeta.badgeClasses}`}
              >
                {pastaAssessment.inherent_risk_level}
              </span>
            </div>
            <div className="text-2xl font-mono font-extrabold text-slate-950">
              {pastaAssessment.inherent_risk_score}
              <span className="text-xs font-bold text-slate-700">/100</span>
            </div>
            <div className="w-full h-2 rounded-full bg-slate-200 overflow-hidden">
              <div
                style={{
                  width: `${Math.min(
                    100,
                    Math.max(4, pastaAssessment.inherent_risk_score)
                  )}%`,
                }}
                className={`h-full ${inherentMeta.barClasses}`}
              />
            </div>
            <span className="text-[11px] text-slate-700">
              Raw pre-control exposure
            </span>
          </div>

          {/* Card 2: Current Residual Risk */}
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col justify-between gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-extrabold text-slate-900">
                2. Current Residual Risk
              </span>
              <span
                className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${residualMeta.badgeClasses}`}
              >
                {pastaAssessment.residual_risk_level}
              </span>
            </div>
            <div className="text-2xl font-mono font-extrabold text-slate-950">
              {pastaAssessment.residual_risk_score}
              <span className="text-xs font-bold text-slate-700">/100</span>
            </div>
            <div className="w-full h-2 rounded-full bg-slate-200 overflow-hidden">
              <div
                style={{
                  width: `${Math.min(
                    100,
                    Math.max(4, pastaAssessment.residual_risk_score)
                  )}%`,
                }}
                className={`h-full ${residualMeta.barClasses}`}
              />
            </div>
            <span className="text-[11px] text-slate-700">
              Current posture with active controls
            </span>
          </div>

          {/* Card 3: Final Projected Go-Live Risk */}
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col justify-between gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-extrabold text-slate-900">
                3. Final Projected Go-Live Risk
              </span>
              <span
                className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${projectedMeta.badgeClasses}`}
              >
                {pastaAssessment.projected_golive_risk_level}
              </span>
            </div>
            <div className="text-2xl font-mono font-extrabold text-slate-950">
              {pastaAssessment.projected_golive_risk_score}
              <span className="text-xs font-bold text-slate-700">/100</span>
            </div>
            <div className="w-full h-2 rounded-full bg-slate-200 overflow-hidden">
              <div
                style={{
                  width: `${Math.min(
                    100,
                    Math.max(4, pastaAssessment.projected_golive_risk_score)
                  )}%`,
                }}
                className={`h-full ${projectedMeta.barClasses}`}
              />
            </div>
            <span className="text-[11px] text-slate-700">
              Post-blocker launch risk level
            </span>
          </div>

          {/* Card 4: Release Gate Tally */}
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col justify-between gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-extrabold text-slate-900">
                Release Gate Tally
              </span>
              <ClipboardCheck className="w-4 h-4 text-indigo-700" />
            </div>
            <div className="grid grid-cols-2 gap-1.5 text-[11px] font-mono font-bold">
              <span className="px-2 py-1 rounded bg-rose-50 border border-rose-300 text-rose-900">
                {pastaAssessment.mandatory_pre_golive_count} Mandatory Pre-Go-Live
              </span>
              <span className="px-2 py-1 rounded bg-amber-50 border border-amber-300 text-amber-950">
                {pastaAssessment.post_golive_sla_count} Post-Go-Live SLA
              </span>
              <span className="px-2 py-1 rounded bg-indigo-50 border border-indigo-300 text-indigo-900">
                {pastaAssessment.waived_count} Waived
              </span>
              <span className="px-2 py-1 rounded bg-emerald-50 border border-emerald-300 text-emerald-900">
                {pastaAssessment.passing_controls_count} Passing Controls
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* =====================================================================
          SECTION 3: STAGE I — BUSINESS CRITICALITY PRESET & CROWN JEWELS BAR
         ===================================================================== */}
      <section className="rounded-2xl bg-white border border-slate-300 shadow-sm p-4 space-y-3">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-300 text-indigo-900 text-[11px] font-mono font-extrabold">
              STAGE I
            </span>
            <h3 className="text-sm font-extrabold text-slate-950">
              Business Criticality Preset & Crown Jewel Impact Multipliers
            </h3>
          </div>

          <button
            type="button"
            onClick={() => setIsWeightsDrawerOpen((prev) => !prev)}
            className="px-3 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-300 text-slate-900 text-xs font-bold flex items-center gap-1.5 transition-colors"
          >
            <Sliders className="w-3.5 h-3.5 text-indigo-700" />
            <span>
              Customize Crown Jewel Weights (
              {pastaAssessment.crown_jewels.length})
            </span>
            {isWeightsDrawerOpen ? (
              <ChevronUp className="w-3.5 h-3.5 text-slate-700" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5 text-slate-700" />
            )}
          </button>
        </div>

        {/* Preset Selector Pills */}
        <div className="flex items-center gap-2 flex-wrap">
          {businessPresets.map((preset) => {
            const isActive =
              pastaAssessment.selected_business_preset === preset.id;
            return (
              <button
                key={preset.id}
                type="button"
                disabled={isSavingPasta}
                onClick={() =>
                  void savePastaProfileState({ business_preset: preset.id })
                }
                className={`px-3 py-1.5 rounded-lg border text-xs font-bold transition-colors ${
                  isActive
                    ? "bg-indigo-700 text-white border-indigo-800 shadow-sm"
                    : "bg-white hover:bg-slate-100 text-slate-800 border-slate-300"
                }`}
              >
                {preset.label}
              </button>
            );
          })}
        </div>

        {/* Inferred Reason & Compliance Frameworks */}
        <div className="flex items-center justify-between gap-3 flex-wrap pt-1">
          <p className="text-xs text-slate-800">
            <span className="font-bold text-slate-950">
              Profile Telemetry:{" "}
            </span>
            {pastaAssessment.inferred_business_reason}
          </p>

          <div className="flex items-center gap-1.5 flex-wrap">
            {pastaAssessment.compliance_frameworks.map((fw) => (
              <span
                key={fw}
                className="px-2 py-0.5 rounded-md bg-sky-50 border border-sky-300 text-sky-900 text-[11px] font-mono font-bold"
              >
                {fw}
              </span>
            ))}
          </div>
        </div>

        {/* Collapsible Crown Jewel Multipliers Drawer */}
        {isWeightsDrawerOpen && (
          <div className="pt-3 border-t border-slate-200 space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {pastaAssessment.crown_jewels.map((cj: PastaCrownJewelItem) => {
                const val = Number(
                  weightDrafts[cj.id] ?? cj.weight_multiplier ?? 1.0
                );
                return (
                  <div
                    key={cj.id}
                    className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-2"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="text-xs font-extrabold text-slate-950 flex items-center gap-1.5">
                          <Crown className="w-3.5 h-3.5 text-amber-700 shrink-0" />
                          <span>{cj.name}</span>
                        </div>
                        <div className="text-[11px] font-mono text-slate-700 mt-0.5">
                          {cj.category} • {cj.asset_count} discovered assets
                        </div>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-300 text-amber-950 text-[10px] font-mono font-bold">
                        {cj.sensitivity_label}
                      </span>
                    </div>

                    <p className="text-xs text-slate-800 leading-snug">
                      {cj.rationale}
                    </p>

                    {cj.sample_locations.length > 0 && (
                      <div className="flex items-center gap-1 flex-wrap">
                        {cj.sample_locations.slice(0, 3).map((loc) => (
                          <span
                            key={loc}
                            className="px-1.5 py-0.5 rounded bg-white border border-slate-300 text-slate-800 text-[10px] font-mono"
                          >
                            {formatShortPath(loc)}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="pt-1 flex items-center gap-2">
                      <input
                        type="range"
                        aria-label={`Impact weight multiplier for ${cj.name}`}
                        min={0.8}
                        max={2.0}
                        step={0.1}
                        value={val}
                        onChange={(e) =>
                          setWeightDrafts((prev) => ({
                            ...prev,
                            [cj.id]: parseFloat(e.target.value),
                          }))
                        }
                        className="flex-1 accent-indigo-700 cursor-pointer"
                      />
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-300 text-indigo-900 text-xs font-mono font-extrabold min-w-[48px] text-center">
                        {val.toFixed(1)}x
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="flex items-center justify-end gap-2 flex-wrap">
              <button
                type="button"
                disabled={isSavingPasta}
                onClick={() =>
                  void savePastaProfileState({ reset_defaults: true })
                }
                className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 disabled:opacity-60 border border-slate-300 text-slate-800 text-xs font-bold flex items-center gap-1.5 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5 text-slate-700" />
                <span>Reset to Auto Defaults</span>
              </button>

              <button
                type="button"
                disabled={isSavingPasta}
                onClick={() =>
                  void savePastaProfileState({
                    business_preset: pastaAssessment.selected_business_preset,
                    crown_jewel_weights: weightDrafts,
                  })
                }
                className="px-3.5 py-1.5 rounded-lg bg-indigo-700 hover:bg-indigo-800 disabled:opacity-60 text-white text-xs font-bold transition-colors shadow-sm"
              >
                Apply Weights
              </button>
            </div>
          </div>
        )}
      </section>

      {/* =====================================================================
          SECTION 4: INTERACTIVE 7-STAGE PASTA PIPELINE STEPPER & EVIDENCE PANEL
         ===================================================================== */}
      <section className="rounded-2xl bg-white border border-slate-300 shadow-sm p-4 space-y-4">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo-700" />
            <h3 className="text-sm font-extrabold text-slate-950">
              Interactive 7-Stage PASTA Methodology Pipeline (Stage I → Stage
              VII)
            </h3>
          </div>
          <span className="text-xs text-slate-700 font-medium">
            Select any PASTA stage card to inspect automated CPG evidence,
            STRIDE cross-references, and code locations
          </span>
        </div>

        {/* 7-Stage Stepper Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-7 gap-2.5">
          {pastaAssessment.stages.map((st: PastaStageItem) => {
            const stMeta = getStageStatusMeta(st.status);
            const isSelected =
              selectedStage?.stage_number === st.stage_number;

            return (
              <button
                key={st.stage_number}
                type="button"
                onClick={() => setSelectedStageNumber(st.stage_number)}
                className={`text-left rounded-xl border p-3 transition-all flex flex-col justify-between gap-2 ${
                  isSelected
                    ? "bg-indigo-50/70 border-indigo-600 ring-2 ring-indigo-600/20 shadow-sm"
                    : "bg-slate-50 hover:bg-white border-slate-300"
                }`}
              >
                <div className="space-y-1.5 w-full">
                  <div className="flex items-center justify-between gap-1">
                    <span className="px-1.5 py-0.5 rounded bg-white border border-slate-300 text-slate-900 text-[10px] font-mono font-extrabold">
                      Stage {st.stage_roman}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded border text-[9px] font-mono font-extrabold ${stMeta.badgeClasses}`}
                    >
                      {stMeta.label}
                    </span>
                  </div>
                  <div className="text-xs font-extrabold text-slate-950 leading-snug line-clamp-2">
                    {st.title}
                  </div>
                </div>

                <div className="pt-1.5 border-t border-slate-200 flex items-center justify-between gap-1 text-[11px] font-mono font-bold w-full">
                  <span className="text-emerald-900">✔ {st.ok_count} OK</span>
                  <span
                    className={
                      st.gap_count > 0 ? "text-rose-900" : "text-slate-700"
                    }
                  >
                    ✖ {st.gap_count} Gap
                  </span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Selected PASTA Stage Evidence Panel */}
        {selectedStage && (
          <div className="rounded-xl bg-slate-50 border border-slate-200 p-4 space-y-4">
            <div className="flex items-start justify-between gap-3 flex-wrap">
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="px-2 py-0.5 rounded bg-indigo-700 text-white text-xs font-mono font-extrabold">
                    STAGE {selectedStage.stage_roman}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-white border border-slate-300 text-slate-800 text-[11px] font-mono font-bold">
                    {selectedStage.stage_code}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded border text-[11px] font-mono font-extrabold ${
                      getStageStatusMeta(selectedStage.status).badgeClasses
                    }`}
                  >
                    {selectedStage.status}
                  </span>
                </div>
                <h4 className="text-base font-extrabold text-slate-950">
                  {selectedStage.title}
                </h4>
                <p className="text-xs text-slate-700 font-medium">
                  <span className="font-bold text-slate-900">
                    Methodology Objective:{" "}
                  </span>
                  {selectedStage.methodology_goal}
                </p>
              </div>
            </div>

            <p className="text-xs text-slate-900 bg-white border border-slate-200 rounded-lg p-3 leading-relaxed">
              {selectedStage.summary}
            </p>

            {/* What Passed vs What Failed */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-white border border-emerald-300 space-y-1.5">
                <div className="text-xs font-extrabold text-emerald-900 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                  <span>
                    Verified Controls & What Passed (
                    {selectedStage.what_passed.length})
                  </span>
                </div>
                {selectedStage.what_passed.length > 0 ? (
                  <ul className="space-y-1 text-xs text-slate-800">
                    {selectedStage.what_passed.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-emerald-700 font-bold">✔</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-slate-700">
                    No passing items recorded for this stage.
                  </p>
                )}
              </div>

              <div className="p-3 rounded-xl bg-white border border-rose-300 space-y-1.5">
                <div className="text-xs font-extrabold text-rose-900 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-rose-700" />
                  <span>
                    Identified Stage Gaps ({selectedStage.what_failed.length})
                  </span>
                </div>
                {selectedStage.what_failed.length > 0 ? (
                  <ul className="space-y-1 text-xs text-slate-800">
                    {selectedStage.what_failed.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-rose-700 font-bold">✖</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-emerald-900 font-medium">
                    ✔ Zero architectural gaps identified in Stage{" "}
                    {selectedStage.stage_roman}.
                  </p>
                )}
              </div>
            </div>

            {/* Stage Evidence Items */}
            {selectedStage.evidence_items.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs font-mono font-extrabold uppercase tracking-wider text-slate-800">
                  Stage {selectedStage.stage_roman} Evidence Artifacts (
                  {selectedStage.evidence_items.length})
                </div>
                <div className="space-y-2">
                  {selectedStage.evidence_items.map((ev: PastaEvidenceItem) => {
                    const isGap = ev.verdict === "GAP";
                    const hasEvFile = Boolean((ev.filepath || "").trim());
                    return (
                      <div
                        key={ev.id}
                        className="p-3 rounded-xl bg-white border border-slate-300 flex items-start justify-between gap-3 flex-wrap"
                      >
                        <div className="space-y-1 flex-1 min-w-[240px]">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span
                              className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${
                                isGap
                                  ? "bg-rose-50 text-rose-900 border-rose-300"
                                  : "bg-emerald-50 text-emerald-900 border-emerald-300"
                              }`}
                            >
                              {ev.verdict}
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${
                                getRiskLevelMeta(ev.severity).badgeClasses
                              }`}
                            >
                              {ev.severity}
                            </span>
                            {ev.cwe_or_capec && (
                              <span className="px-2 py-0.5 rounded bg-sky-50 border border-sky-300 text-sky-900 text-[10px] font-mono font-bold">
                                {ev.cwe_or_capec}
                              </span>
                            )}
                            {ev.stride_cross_ref && (
                              <span className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-300 text-indigo-900 text-[10px] font-mono font-bold">
                                STRIDE: {ev.stride_cross_ref}
                              </span>
                            )}
                          </div>
                          <div className="text-xs font-extrabold text-slate-950">
                            {ev.title}
                          </div>
                          <p className="text-xs text-slate-800 leading-relaxed">
                            {ev.detail}
                          </p>
                        </div>

                        {hasEvFile && (
                          <button
                            type="button"
                            onClick={() =>
                              openCodeLocationInIde(
                                ev.filepath,
                                ev.line || 1,
                                ev.linked_finding_id || undefined
                              )
                            }
                            className="px-2.5 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-300 text-slate-900 text-xs font-mono font-bold flex items-center gap-1.5 transition-colors shrink-0"
                          >
                            <Code2 className="w-3.5 h-3.5 text-indigo-700" />
                            <span>
                              Inspect in IDE ({formatShortPath(ev.filepath)}:
                              {ev.line || 1})
                            </span>
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* =====================================================================
          SECTION 5: STAGE VI — INTERACTIVE REACTFLOW ATTACK TREE CANVAS
         ===================================================================== */}
      <section className="rounded-2xl bg-white border border-slate-300 shadow-sm p-4 space-y-3">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="px-2 py-0.5 rounded bg-rose-50 border border-rose-300 text-rose-900 text-[11px] font-mono font-extrabold">
              STAGE VI
            </span>
            <h3 className="text-sm font-extrabold text-slate-950 flex items-center gap-1.5">
              <Crosshair className="w-4 h-4 text-rose-700" />
              <span>
                Probabilistic Attack Tree Simulation & BFL Chokepoint Canvas
              </span>
            </h3>
          </div>
          <span className="text-xs font-mono font-bold text-slate-700">
            {pastaAssessment.attack_trees.length} Synthesized Attack Scenarios
          </span>
        </div>

        {/* Scenario Selector Pills */}
        {pastaAssessment.attack_trees.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            {pastaAssessment.attack_trees.map((sc) => {
              const scMeta = getScenarioStatusMeta(sc.status);
              const isSelected = selectedScenario?.id === sc.id;
              return (
                <button
                  key={sc.id}
                  type="button"
                  onClick={() => setSelectedScenarioId(sc.id)}
                  className={`px-3 py-2 rounded-xl border text-left transition-all flex items-center gap-2 flex-wrap ${
                    isSelected
                      ? "bg-slate-100 border-indigo-600 ring-2 ring-indigo-600/20 shadow-sm"
                      : "bg-white hover:bg-slate-50 border-slate-300"
                  }`}
                >
                  <span className="text-xs font-extrabold text-slate-950">
                    {sc.title}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${scMeta.badgeClasses}`}
                  >
                    {scMeta.label}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 text-[10px] font-mono font-bold">
                    -{sc.projected_risk_reduction} risk pts
                  </span>
                </button>
              );
            })}
          </div>
        )}

        {selectedScenario ? (
          <ReactFlowProvider>
            <AttackTreeCanvasInner
              scenario={selectedScenario}
              isAiBusy={isAiBusy}
              onExplainAi={handleExplainAttackTreeAi}
              onJumpToIde={openCodeLocationInIde}
            />
          </ReactFlowProvider>
        ) : (
          <div className="p-6 rounded-xl bg-slate-50 border border-slate-200 text-center text-xs text-slate-800">
            No attack tree scenarios synthesized for this repository yet.
          </div>
        )}
      </section>

      {/* =====================================================================
          SECTION 6: STAGE VII — GO-LIVE GATE TRIAGE MATRIX & RUNBOOK
         ===================================================================== */}
      <section className="rounded-2xl bg-white border border-slate-300 shadow-sm p-4 space-y-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-300 text-indigo-900 text-[11px] font-mono font-extrabold">
              STAGE VII
            </span>
            <h3 className="text-sm font-extrabold text-slate-950 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-indigo-700" />
              <span>
                ARB Go-Live Gate Triage Matrix (Mandatory Pre-Go-Live vs
                Post-Go-Live SLA) & &ldquo;Make It Live&rdquo; Runbook
              </span>
            </h3>
          </div>
        </div>

        {/* Gate View Filter Tabs */}
        <div className="flex items-center gap-2 flex-wrap border-b border-slate-200 pb-3">
          <button
            type="button"
            onClick={() => setActiveGateTab("ALL")}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-extrabold transition-colors ${
              activeGateTab === "ALL"
                ? "bg-indigo-700 text-white border-indigo-800"
                : "bg-white hover:bg-slate-100 text-slate-800 border-slate-300"
            }`}
          >
            ALL ({pastaAssessment.golive_observations.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveGateTab("MANDATORY_PRE_GO_LIVE")}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-extrabold transition-colors ${
              activeGateTab === "MANDATORY_PRE_GO_LIVE"
                ? "bg-rose-700 text-white border-rose-800"
                : "bg-rose-50 hover:bg-rose-100 text-rose-900 border-rose-300"
            }`}
          >
            MANDATORY PRE-GO-LIVE ({pastaAssessment.mandatory_pre_golive_count})
          </button>

          <button
            type="button"
            onClick={() => setActiveGateTab("POST_GO_LIVE_SLA")}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-extrabold transition-colors ${
              activeGateTab === "POST_GO_LIVE_SLA"
                ? "bg-amber-700 text-white border-amber-800"
                : "bg-amber-50 hover:bg-amber-100 text-amber-950 border-amber-300"
            }`}
          >
            POST-GO-LIVE ALLOWED ({pastaAssessment.post_golive_sla_count})
          </button>

          <button
            type="button"
            onClick={() => setActiveGateTab("RISK_ACCEPTED_WAIVER")}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-extrabold transition-colors ${
              activeGateTab === "RISK_ACCEPTED_WAIVER"
                ? "bg-indigo-700 text-white border-indigo-800"
                : "bg-indigo-50 hover:bg-indigo-100 text-indigo-900 border-indigo-300"
            }`}
          >
            WAIVED ({pastaAssessment.waived_count})
          </button>

          <button
            type="button"
            onClick={() => setActiveGateTab("MAKE_IT_LIVE_RUNBOOK")}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-extrabold transition-colors ${
              activeGateTab === "MAKE_IT_LIVE_RUNBOOK"
                ? "bg-emerald-700 text-white border-emerald-800"
                : "bg-emerald-50 hover:bg-emerald-100 text-emerald-900 border-emerald-300"
            }`}
          >
            MAKE IT LIVE RUNBOOK ({pastaAssessment.make_it_live_checklist.length}
            )
          </button>
        </div>

        {/* Active Tab Body */}
        {activeGateTab === "MAKE_IT_LIVE_RUNBOOK" ? (
          <div className="space-y-2.5">
            {pastaAssessment.make_it_live_checklist.map((step, idx) => {
              const phaseMeta = classifyRunbookPhase(step);
              return (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-slate-50 border border-slate-300 flex items-start gap-3"
                >
                  <span className="w-7 h-7 rounded-lg bg-white border border-slate-300 text-slate-950 text-xs font-mono font-extrabold flex items-center justify-center shrink-0">
                    {idx + 1}
                  </span>
                  <div className="space-y-1 flex-1">
                    <span
                      className={`inline-block px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${phaseMeta.badgeClasses}`}
                    >
                      {phaseMeta.phaseBadge}
                    </span>
                    <p className="text-xs font-medium text-slate-900 leading-relaxed">
                      {step}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        ) : filteredObservations.length > 0 ? (
          <div className="space-y-3">
            {filteredObservations.map((obs) => (
              <ObservationGateCard
                key={obs.id}
                obs={obs}
                isSavingPasta={isSavingPasta}
                onSaveOverride={savePastaGateOverride}
                onJumpToIde={openCodeLocationInIde}
              />
            ))}
          </div>
        ) : (
          <div className="p-6 rounded-xl bg-emerald-50/60 border border-emerald-300 flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-2.5">
              <CheckCircle2 className="w-5 h-5 text-emerald-700 shrink-0" />
              <div>
                <div className="text-sm font-extrabold text-emerald-950">
                  Zero Observations in Selected Go-Live Gate Bucket
                </div>
                <p className="text-xs text-emerald-900">
                  No active observations match this gate classification filter
                  for {pastaAssessment.application_name}.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setActiveGateTab("MAKE_IT_LIVE_RUNBOOK")}
              className="px-3 py-1.5 rounded-lg bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold transition-colors"
            >
              View Make It Live Runbook →
            </button>
          </div>
        )}
      </section>
    </div>
  );
};

export default PastaThreatWorkbench;
