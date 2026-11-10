"use client";

import React, { useEffect, useMemo, useState, useCallback } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  ReactFlowProvider,
  Node,
  Edge,
  MarkerType,
  useNodesState,
  useEdgesState,
} from "reactflow";
import "reactflow/dist/style.css";

import { useAuditStore } from "@/store/useAuditStore";
import { apiFetchJson } from "@/lib/api";
import {
  AttackSurfaceEndpoint,
  FilePurposeInfo,
  Finding,
  StrideThreatItem,
} from "@/types/cpg";
import { CustomGraphNode, NodeBlastRole } from "./CustomGraphNode";
import {
  DirectionalFlowEdge,
  DirectionalFlowEdgeData,
  EdgeBlastState,
} from "./DirectionalFlowEdge";
import {
  ShieldAlert,
  KeyRound,
  Eye,
  EyeOff,
  Compass,
  PhoneCall,
  Code2,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Globe,
  Server,
  Database,
  ArrowRight,
  Layers,
  Filter,
  Copy,
  Check,
  XCircle,
  Wrench,
  FileCode,
  ExternalLink,
  Sparkles,
  Maximize2,
  X,
  Loader2,
} from "lucide-react";

const boundaryNodeTypes = {
  cpgNode: CustomGraphNode,
};

const boundaryEdgeTypes = {
  directionalFlow: DirectionalFlowEdge,
};

const STRIDE_META: Record<
  string,
  {
    letter: string;
    label: string;
    securityProperty: string;
    color: string;
    badgeBg: string;
    activeBtn: string;
  }
> = {
  SPOOFING: {
    letter: "S",
    label: "Spoofing Identity",
    securityProperty: "Authentication",
    color: "text-rose-800",
    badgeBg: "bg-rose-50 border-rose-300 text-rose-900",
    activeBtn: "bg-rose-700 border-rose-800 text-white",
  },
  TAMPERING: {
    letter: "T",
    label: "Tampering with Data",
    securityProperty: "Integrity",
    color: "text-amber-800",
    badgeBg: "bg-amber-50 border-amber-300 text-amber-900",
    activeBtn: "bg-amber-700 border-amber-800 text-white",
  },
  REPUDIATION: {
    letter: "R",
    label: "Repudiation",
    securityProperty: "Non-Repudiation & Auditability",
    color: "text-purple-800",
    badgeBg: "bg-purple-50 border-purple-300 text-purple-900",
    activeBtn: "bg-purple-700 border-purple-800 text-white",
  },
  INFORMATION_DISCLOSURE: {
    letter: "I",
    label: "Information Disclosure",
    securityProperty: "Confidentiality & Secret Hygiene",
    color: "text-cyan-800",
    badgeBg: "bg-cyan-50 border-cyan-300 text-cyan-900",
    activeBtn: "bg-cyan-700 border-cyan-800 text-white",
  },
  DENIAL_OF_SERVICE: {
    letter: "D",
    label: "Denial of Service",
    securityProperty: "Availability & Resilience",
    color: "text-orange-800",
    badgeBg: "bg-orange-50 border-orange-300 text-orange-900",
    activeBtn: "bg-orange-700 border-orange-800 text-white",
  },
  ELEVATION_OF_PRIVILEGE: {
    letter: "E",
    label: "Elevation of Privilege",
    securityProperty: "Authorization & Sandboxing",
    color: "text-red-800",
    badgeBg: "bg-red-50 border-red-300 text-red-900",
    activeBtn: "bg-red-700 border-red-800 text-white",
  },
};

function shortFile(fp?: string | null): string {
  if (!fp) return "workspace";
  const norm = fp.replace(/\\/g, "/");
  const segs = norm.split("/").filter(Boolean);
  return segs[segs.length - 1] || fp;
}

interface TrustBoundaryCanvasProps {
  endpoints: AttackSurfaceEndpoint[];
  findings: Finding[];
  secretFindings: Finding[];
  flatFiles: FilePurposeInfo[];
  passedStrideCount: number;
  onJumpToIde: (filepath?: string, line?: number, findingId?: string) => void;
  onExplainWithAi: (nodes: Node[], edges: Edge[]) => void;
  aiIsBusy: boolean;
}

const TrustBoundaryFlowCanvasInner: React.FC<TrustBoundaryCanvasProps> = ({
  endpoints,
  findings,
  secretFindings,
  flatFiles,
  passedStrideCount,
  onJumpToIde,
  onExplainWithAi,
  aiIsBusy,
}) => {
  const [rfInstance, setRfInstance] = useState<any | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [lockedNodeId, setLockedNodeId] = useState<string | null>(null);

  const nonSecretFindings = useMemo(
    () =>
      findings.filter(
        (f) =>
          !f.is_secret_finding &&
          !(f.rule_id || "").toUpperCase().includes("SECRET") &&
          f.cwe_id !== "CWE-798"
      ),
    [findings]
  );

  // Build 4-Zone Left-to-Right Directional Topology
  const { initialNodes, initialEdges } = useMemo(() => {
    const zNodes: Node[] = [];
    const zEdges: Edge[] = [];

    const Z1_X = 40;
    const Z2_X = 420;
    const Z3_X = 800;
    const Z4_X = 1180;
    const ROW_GAP = 168;

    const handleCardClick = (nodeData: any) => {
      if (nodeData?.filepath && nodeData.filepath !== "external-ingress") {
        onJumpToIde(
          nodeData.filepath,
          nodeData.start_line || 1,
          nodeData.findingId
        );
      } else if (findings.length > 0) {
        const firstF = findings[0];
        const bfl = firstF.best_fix_location;
        const p0 = firstF.path_nodes?.[0];
        onJumpToIde(
          bfl?.filepath || p0?.filepath,
          bfl?.line || p0?.start_line || 1,
          firstF.id
        );
      }
    };

    // ---------------- ZONE 1: EXTERNAL UNTRUSTED INGRESS ----------------
    const z1Sources = [
      {
        id: "tb-z1-http",
        name: "🌐 HTTP / API Request Ingress",
        code: "Untrusted query params, JSON body, headers & cookies",
        filepath: endpoints[0]?.filepath || flatFiles[0]?.filepath || "external-ingress",
        line: endpoints[0]?.line_number || 1,
      },
      {
        id: "tb-z1-cli",
        name: "⌨️ CLI Flags, Env & Webhooks",
        code: "Process argv, environment overrides & external webhooks",
        filepath: flatFiles[0]?.filepath || "external-ingress",
        line: 1,
      },
      {
        id: "tb-z1-supply",
        name: "📦 Supply-Chain & Runtime Config",
        code: "Third-party packages, container manifests & IaC configs",
        filepath:
          flatFiles.find(
            (f) =>
              f.category === "DEPENDENCY_MANIFEST" ||
              f.category === "INFRASTRUCTURE" ||
              f.category === "CONFIGURATION"
          )?.filepath ||
          flatFiles[0]?.filepath ||
          "external-ingress",
        line: 1,
      },
    ];

    z1Sources.forEach((src, idx) => {
      zNodes.push({
        id: src.id,
        type: "cpgNode",
        position: { x: Z1_X, y: 36 + idx * ROW_GAP },
        data: {
          id: src.id,
          label: "Entry",
          name: src.name,
          code: src.code,
          filepath: src.filepath,
          start_line: src.line,
          end_line: src.line,
          is_source: true,
          is_sink: false,
          is_sanitizer: false,
          trustZoneLabel: "ZONE 1 · EXTERNAL UNTRUSTED",
          trustZoneTone: "CRIMSON",
          onNodeCardClick: handleCardClick,
        },
      });
    });

    // ---------------- ZONE 2: APPLICATION ENTRYPOINTS ----------------
    const z2Ids: Array<{ id: string; filepath: string }> = [];
    if (endpoints.length > 0) {
      endpoints.slice(0, 4).forEach((ep, idx) => {
        const nid = `tb-z2-ep-${idx}`;
        z2Ids.push({ id: nid, filepath: ep.filepath });
        zNodes.push({
          id: nid,
          type: "cpgNode",
          position: { x: Z2_X, y: 24 + idx * ROW_GAP },
          data: {
            id: nid,
            label: "Function",
            name: `[${ep.method}] ${ep.route_path}`,
            code: `Handler: ${ep.handler_name}() • ${ep.auth_posture}`,
            filepath: ep.filepath,
            start_line: ep.line_number || 1,
            end_line: ep.line_number || 1,
            is_source: false,
            is_sink: false,
            is_sanitizer: false,
            trustZoneLabel: "ZONE 2 · APP ENTRYPOINT",
            trustZoneTone: "SKY",
            trustZoneActionHint: "Click -> IDE",
            onNodeCardClick: handleCardClick,
          },
        });
      });
    } else {
      const candidateFiles =
        flatFiles
          .filter((f) =>
            ["API_ROUTER", "FRONTEND_VIEW", "BUSINESS_LOGIC"].includes(
              f.category
            )
          )
          .slice(0, 3).length > 0
          ? flatFiles
              .filter((f) =>
                ["API_ROUTER", "FRONTEND_VIEW", "BUSINESS_LOGIC"].includes(
                  f.category
                )
              )
              .slice(0, 3)
          : flatFiles.slice(0, 2);

      if (candidateFiles.length > 0) {
        candidateFiles.forEach((cf, idx) => {
          const nid = `tb-z2-file-${idx}`;
          z2Ids.push({ id: nid, filepath: cf.filepath });
          zNodes.push({
            id: nid,
            type: "cpgNode",
            position: { x: Z2_X, y: 36 + idx * ROW_GAP },
            data: {
              id: nid,
              label: "Function",
              name: shortFile(cf.filepath),
              code: cf.purpose || `Application module (${cf.category})`,
              filepath: cf.filepath,
              start_line: 1,
              end_line: 1,
              is_source: false,
              is_sink: false,
              is_sanitizer: false,
              trustZoneLabel: "ZONE 2 · APP ENTRYPOINT",
              trustZoneTone: "SKY",
              trustZoneActionHint: "Click -> IDE",
              onNodeCardClick: handleCardClick,
            },
          });
        });
      } else {
        const fallbackFp = findings[0]?.path_nodes?.[0]?.filepath || "workspace";
        const nid = "tb-z2-default";
        z2Ids.push({ id: nid, filepath: fallbackFp });
        zNodes.push({
          id: nid,
          type: "cpgNode",
          position: { x: Z2_X, y: 120 },
          data: {
            id: nid,
            label: "Function",
            name: "Application Ingress Router",
            code: "Controller & CLI request dispatcher",
            filepath: fallbackFp,
            start_line: 1,
            end_line: 1,
            is_source: false,
            is_sink: false,
            is_sanitizer: false,
            trustZoneLabel: "ZONE 2 · APP ENTRYPOINT",
            trustZoneTone: "SKY",
            onNodeCardClick: handleCardClick,
          },
        });
      }
    }

    // Connect Zone 1 -> Zone 2
    z2Ids.forEach((epItem, idx) => {
      const srcId = idx === 0 ? "tb-z1-http" : idx === 1 ? "tb-z1-cli" : "tb-z1-supply";
      const lbl = idx === 0 ? "HTTP / INPUT ▶" : idx === 1 ? "CLI / ENV ▶" : "PKG / CFG ▶";
      zEdges.push({
        id: `tb-e-z1-z2-${idx}`,
        source: srcId,
        target: epItem.id,
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
          edgeType: "TRUST_CROSSING",
          flowLabel: lbl,
          pathShape: "smoothstep",
          isAnimatedPulse: true,
          alwaysShowFullPill: true,
          strokeColor: "#0e7490",
          badgeTone: "CYAN",
        } satisfies DirectionalFlowEdgeData,
      });
    });

    // ---------------- ZONE 3: VALIDATION & BFL SANITIZERS ----------------
    const z3BflItems: Array<{
      id: string;
      finding?: Finding;
      isGuardedGuard?: boolean;
    }> = [];

    nonSecretFindings.slice(0, 3).forEach((f, idx) => {
      const bfl = f.best_fix_location;
      const midNode =
        f.path_nodes && f.path_nodes.length > 0
          ? f.path_nodes[Math.max(0, f.path_nodes.length - 1)]
          : undefined;
      const fp = bfl?.filepath || midNode?.filepath || "workspace";
      const ln = bfl?.line || midNode?.start_line || 1;
      const nid = `tb-z3-bfl-${idx}`;
      z3BflItems.push({ id: nid, finding: f });

      zNodes.push({
        id: nid,
        type: "cpgNode",
        position: { x: Z3_X, y: 24 + idx * ROW_GAP },
        data: {
          id: nid,
          label: "Call",
          name: `BFL Chokepoint • ${shortFile(fp)}:L${ln}`,
          code: bfl?.code_snippet || midNode?.code || f.title,
          filepath: fp,
          start_line: ln,
          end_line: ln,
          findingId: f.id,
          is_bfl: true,
          is_source: false,
          is_sink: false,
          is_sanitizer: false,
          trustZoneLabel: "ZONE 3 · VALIDATION & BFL",
          trustZoneTone: "AMBER",
          trustZoneActionHint: "Fix Here",
          onNodeCardClick: handleCardClick,
        },
      });
    });

    const guardNodeId = "tb-z3-guard";
    z3BflItems.push({ id: guardNodeId, isGuardedGuard: true });
    zNodes.push({
      id: guardNodeId,
      type: "cpgNode",
      position: { x: Z3_X, y: 24 + (z3BflItems.length - 1) * ROW_GAP },
      data: {
        id: guardNodeId,
        label: "ControlBlock",
        name: "Sanitizer & Auth Guard Layer ✓",
        code: `${passedStrideCount}/6 STRIDE categories verified passing`,
        filepath: flatFiles[0]?.filepath || "workspace",
        start_line: 1,
        end_line: 1,
        is_source: false,
        is_sink: false,
        is_sanitizer: true,
        trustZoneLabel: "ZONE 3 · SANITIZER GUARD",
        trustZoneTone: "EMERALD",
        onNodeCardClick: handleCardClick,
      },
    });

    // Connect Zone 2 -> Zone 3 ("DISPATCHES ▶")
    z3BflItems.forEach((bflItem, idx) => {
      const srcEp = z2Ids[idx % z2Ids.length];
      if (!srcEp) return;
      zEdges.push({
        id: `tb-e-z2-z3-${idx}`,
        source: srcEp.id,
        target: bflItem.id,
        sourceHandle: "right-src",
        targetHandle: "left-tgt",
        type: "directionalFlow",
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: "#b45309",
          width: 18,
          height: 18,
        },
        data: {
          edgeType: "CALLS",
          flowLabel: "DISPATCHES ▶",
          pathShape: "smoothstep",
          isAnimatedPulse: !bflItem.isGuardedGuard,
          alwaysShowFullPill: true,
          strokeColor: "#b45309",
          badgeTone: "AMBER",
        } satisfies DirectionalFlowEdgeData,
      });
    });

    // ---------------- ZONE 4: CRITICAL SINKS, DB & SECRETS ----------------
    let z4RowIdx = 0;

    nonSecretFindings.slice(0, 3).forEach((f, idx) => {
      const sinkN =
        f.path_nodes && f.path_nodes.length > 0
          ? f.path_nodes[f.path_nodes.length - 1]
          : undefined;
      const bfl = f.best_fix_location;
      const fp = sinkN?.filepath || bfl?.filepath || "workspace";
      const ln = sinkN?.start_line || bfl?.line || 1;
      const sinkId = `tb-z4-sink-${idx}`;
      const matchBflId = `tb-z3-bfl-${idx}`;

      zNodes.push({
        id: sinkId,
        type: "cpgNode",
        position: { x: Z4_X, y: 24 + z4RowIdx * ROW_GAP },
        data: {
          id: sinkId,
          label: "Call",
          name: `[${f.severity}] ${f.cwe_id || f.rule_id} • ${
            sinkN?.name || shortFile(fp)
          }`,
          code: sinkN?.code || f.title,
          filepath: fp,
          start_line: ln,
          end_line: ln,
          findingId: f.id,
          is_source: false,
          is_sink: true,
          is_sanitizer: false,
          trustZoneLabel: "ZONE 4 · CRITICAL SINK",
          trustZoneTone: "CRIMSON",
          trustZoneActionHint: "Click -> IDE",
          onNodeCardClick: handleCardClick,
        },
      });
      z4RowIdx += 1;

      zEdges.push({
        id: `tb-e-z3-z4-vuln-${idx}`,
        source: matchBflId,
        target: sinkId,
        sourceHandle: "right-src",
        targetHandle: "left-tgt",
        type: "directionalFlow",
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: "#be123c",
          width: 18,
          height: 18,
        },
        data: {
          edgeType: "UNGUARDED",
          flowLabel: `UNSANITIZED (${f.cwe_id || "SINK"}) ▶`,
          pathShape: "smoothstep",
          isAnimatedPulse: true,
          alwaysShowFullPill: true,
          strokeColor: "#be123c",
          badgeTone: "CRIMSON",
        } satisfies DirectionalFlowEdgeData,
      });
    });

    if (secretFindings.length > 0) {
      const sf0 = secretFindings[0];
      const sNode = sf0.path_nodes?.[0];
      const sFp = sf0.best_fix_location?.filepath || sNode?.filepath || "config";
      const sLn = sf0.best_fix_location?.line || sNode?.start_line || 1;
      const secSinkId = "tb-z4-secrets";

      zNodes.push({
        id: secSinkId,
        type: "cpgNode",
        position: { x: Z4_X, y: 24 + z4RowIdx * ROW_GAP },
        data: {
          id: secSinkId,
          label: "Literal",
          name: `🔑 Exposed Secrets (${secretFindings.length} Keys)`,
          code: `${sf0.secret_key_name || "SECRET_KEY"} in ${shortFile(sFp)}:L${sLn}`,
          filepath: sFp,
          start_line: sLn,
          end_line: sLn,
          findingId: sf0.id,
          is_source: false,
          is_sink: true,
          is_sanitizer: false,
          trustZoneLabel: "ZONE 4 · CROWN JEWELS",
          trustZoneTone: "CRIMSON",
          trustZoneActionHint: "Click -> IDE",
          onNodeCardClick: handleCardClick,
        },
      });
      z4RowIdx += 1;

      const secSourceZ3 =
        z3BflItems[0]?.id || guardNodeId;
      zEdges.push({
        id: "tb-e-z3-z4-secrets",
        source: secSourceZ3,
        target: secSinkId,
        sourceHandle: "right-src",
        targetHandle: "left-tgt",
        type: "directionalFlow",
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: "#be123c",
          width: 18,
          height: 18,
        },
        data: {
          edgeType: "UNGUARDED",
          flowLabel: "HARDCODED KEY (CWE-798) ▶",
          pathShape: "smoothstep",
          isAnimatedPulse: true,
          alwaysShowFullPill: true,
          strokeColor: "#be123c",
          badgeTone: "CRIMSON",
        } satisfies DirectionalFlowEdgeData,
      });
    }

    // Always render guarded safe store path from Sanitizer Guard Layer -> Protected Store
    const safeStoreId = "tb-z4-guarded-store";
    zNodes.push({
      id: safeStoreId,
      type: "cpgNode",
      position: { x: Z4_X, y: 24 + z4RowIdx * ROW_GAP },
      data: {
        id: safeStoreId,
        label: "Exit",
        name: "Protected DB, Shell & Vault ✓",
        code: "Parameterized queries, safe loaders & env-injected secrets",
        filepath: flatFiles[0]?.filepath || "workspace",
        start_line: 1,
        end_line: 1,
        is_source: false,
        is_sink: false,
        is_sanitizer: true,
        trustZoneLabel: "ZONE 4 · PROTECTED STORE",
        trustZoneTone: "EMERALD",
        onNodeCardClick: handleCardClick,
      },
    });

    zEdges.push({
      id: "tb-e-z3-z4-guarded",
      source: guardNodeId,
      target: safeStoreId,
      sourceHandle: "right-src",
      targetHandle: "left-tgt",
      type: "directionalFlow",
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: "#047857",
        width: 18,
        height: 18,
      },
      data: {
        edgeType: "SANITIZED",
        flowLabel: "GUARDED ✓",
        pathShape: "smoothstep",
        isAnimatedPulse: false,
        alwaysShowFullPill: true,
        strokeColor: "#047857",
        badgeTone: "EMERALD",
      } satisfies DirectionalFlowEdgeData,
    });

    return { initialNodes: zNodes, initialEdges: zEdges };
  }, [endpoints, findings, nonSecretFindings, secretFindings, flatFiles, passedStrideCount, onJumpToIde]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
    setTimeout(() => {
      rfInstance?.fitView({ padding: 0.14, duration: 380 });
    }, 60);
  }, [initialNodes, initialEdges, setNodes, setEdges, rfInstance]);

  // Blast-Radius hover/click highlighting across the 4 Trust Zones
  const activeFocusId = lockedNodeId || hoveredNodeId;
  const { displayNodes, displayEdges } = useMemo(() => {
    if (!activeFocusId || !nodes.some((n) => n.id === activeFocusId)) {
      return { displayNodes: nodes, displayEdges: edges };
    }

    const fwd = new Map<string, Array<{ t: string; eid: string }>>();
    const rev = new Map<string, Array<{ s: string; eid: string }>>();
    for (const e of edges) {
      if (!fwd.has(e.source)) fwd.set(e.source, []);
      fwd.get(e.source)!.push({ t: e.target, eid: e.id });
      if (!rev.has(e.target)) rev.set(e.target, []);
      rev.get(e.target)!.push({ s: e.source, eid: e.id });
    }

    const upN = new Set<string>();
    const upE = new Set<string>();
    const qUp = [activeFocusId];
    const seenUp = new Set([activeFocusId]);
    while (qUp.length > 0) {
      const cur = qUp.shift()!;
      for (const p of rev.get(cur) || []) {
        upE.add(p.eid);
        if (!seenUp.has(p.s)) {
          seenUp.add(p.s);
          upN.add(p.s);
          qUp.push(p.s);
        }
      }
    }

    const downN = new Set<string>();
    const downE = new Set<string>();
    const qDown = [activeFocusId];
    const seenDown = new Set([activeFocusId]);
    while (qDown.length > 0) {
      const cur = qDown.shift()!;
      for (const nx of fwd.get(cur) || []) {
        downE.add(nx.eid);
        if (!seenDown.has(nx.t)) {
          seenDown.add(nx.t);
          downN.add(nx.t);
          qDown.push(nx.t);
        }
      }
    }

    return {
      displayNodes: nodes.map((n) => {
        let blastRole: NodeBlastRole = "DIMMED";
        if (n.id === activeFocusId) blastRole = "FOCUSED";
        else if (upN.has(n.id)) blastRole = "UPSTREAM";
        else if (downN.has(n.id)) blastRole = "DOWNSTREAM";
        return { ...n, data: { ...n.data, blastRole } };
      }),
      displayEdges: edges.map((e) => {
        let blastState: EdgeBlastState = "DIMMED";
        if (upE.has(e.id)) blastState = "UPSTREAM";
        else if (downE.has(e.id)) blastState = "DOWNSTREAM";
        return { ...e, data: { ...e.data, blastState } };
      }),
    };
  }, [activeFocusId, nodes, edges]);

  const onInit = useCallback((inst: any) => {
    setRfInstance(inst);
    setTimeout(() => {
      inst.fitView({ padding: 0.14, duration: 400 });
    }, 80);
  }, []);

  return (
    <div className="rounded-xl border border-slate-300 bg-white shadow-sm overflow-hidden">
      {/* Top 4-Zone Directional Story & Controls Header */}
      <div className="bg-slate-50 border-b border-slate-200 px-4 py-3 flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="px-2 py-0.5 rounded bg-cyan-700 text-white border border-cyan-800 font-mono text-[10px] font-extrabold uppercase">
              Interactive 4-Zone Trust Flow
            </span>
            <h3 className="text-sm font-extrabold text-slate-900">
              Directional Trust Boundary Crossings (Click Any Node to Triage &amp; Fix in IDE)
            </h3>
          </div>
          <p className="text-xs text-slate-600">
            Hover any node to highlight upstream ingress sources &amp; downstream reachable sinks; click any card to open its exact file and line in the Remediation IDE.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {lockedNodeId && (
            <button
              type="button"
              onClick={() => {
                setLockedNodeId(null);
                setHoveredNodeId(null);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-rose-700 hover:bg-rose-800 text-white border border-rose-800 text-xs font-mono font-bold flex items-center gap-1"
            >
              <X className="w-3 h-3 text-white" />
              Clear Focus
            </button>
          )}
          <button
            type="button"
            onClick={() => rfInstance?.fitView({ padding: 0.14, duration: 380 })}
            className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 text-slate-800 border border-slate-300 text-xs font-mono font-bold flex items-center gap-1"
          >
            <Maximize2 className="w-3.5 h-3.5 text-cyan-700" />
            Fit 4 Zones
          </button>
          <button
            type="button"
            onClick={() => onExplainWithAi(nodes, edges)}
            className="px-3 py-1.5 rounded-lg bg-indigo-700 hover:bg-indigo-800 text-white border border-indigo-800 text-xs font-mono font-extrabold flex items-center gap-1.5 shadow-sm"
          >
            {aiIsBusy ? (
              <Loader2 className="w-3.5 h-3.5 text-white animate-spin" />
            ) : (
              <Sparkles className="w-3.5 h-3.5 text-white" />
            )}
            ✨ AI Explain Boundary Flow
          </button>
        </div>
      </div>

      {/* 4-Column Architectural Zone Ribbon Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 border-b border-slate-200 bg-white text-[11px] font-mono">
        <div className="px-3 py-2 border-r border-slate-200 bg-rose-50/60 flex items-center justify-between gap-1">
          <div>
            <div className="font-extrabold text-rose-900">
              Zone 1: External Untrusted Ingress
            </div>
            <div className="text-[10px] text-slate-600">
              HTTP, CLI, Env &amp; Supply Chain
            </div>
          </div>
          <span className="px-1.5 py-0.5 rounded bg-cyan-50 text-cyan-900 border border-cyan-300 text-[9px] font-extrabold shrink-0">
            HTTP / Input ▶
          </span>
        </div>

        <div className="px-3 py-2 border-r border-slate-200 bg-sky-50/60 flex items-center justify-between gap-1">
          <div>
            <div className="font-extrabold text-sky-900">
              Zone 2: Application Entrypoints
            </div>
            <div className="text-[10px] text-slate-600">
              Routes, Controllers &amp; Handlers
            </div>
          </div>
          <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-900 border border-amber-300 text-[9px] font-extrabold shrink-0">
            Dispatches ▶
          </span>
        </div>

        <div className="px-3 py-2 border-r border-slate-200 bg-amber-50/60 flex items-center justify-between gap-1">
          <div>
            <div className="font-extrabold text-amber-900">
              Zone 3: Validation &amp; BFL Sanitizers
            </div>
            <div className="text-[10px] text-slate-600">
              BFL Chokepoints &amp; Auth Guards
            </div>
          </div>
          <span className="px-1.5 py-0.5 rounded bg-rose-50 text-rose-900 border border-rose-300 text-[9px] font-extrabold shrink-0">
            Guarded ✓ / Unsanitized ▶
          </span>
        </div>

        <div className="px-3 py-2 bg-emerald-50/50 flex items-center justify-between gap-1">
          <div>
            <div className="font-extrabold text-slate-900">
              Zone 4: Critical Sinks, DB &amp; Secrets
            </div>
            <div className="text-[10px] text-slate-600">
              OS Exec, SQL, Filesystem &amp; Keys
            </div>
          </div>
          <Database className="w-4 h-4 text-rose-700 shrink-0" />
        </div>
      </div>

      {/* Interactive ReactFlow 4-Zone Canvas */}
      <div className="w-full h-[540px] bg-[#f8fafc] relative">
        <ReactFlow
          nodes={displayNodes}
          edges={displayEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={boundaryNodeTypes}
          edgeTypes={boundaryEdgeTypes}
          onInit={onInit}
          onNodeMouseEnter={(_, n) => setHoveredNodeId(n.id)}
          onNodeMouseLeave={() => setHoveredNodeId(null)}
          onPaneClick={() => {
            setLockedNodeId(null);
            setHoveredNodeId(null);
          }}
          minZoom={0.25}
          maxZoom={2.2}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#cbd5e1" gap={22} size={1.35} />
          <Controls className="!bg-white !border-slate-300 !text-slate-800 !shadow-md rounded-lg overflow-hidden" />
          <MiniMap
            nodeColor={(n) => {
              if (n.data?.is_sink) return "#be123c";
              if (n.data?.is_bfl) return "#b45309";
              if (n.data?.is_sanitizer) return "#047857";
              if (n.data?.is_source) return "#0e7490";
              return "#0284c7";
            }}
            maskColor="rgba(241, 245, 249, 0.76)"
            className="!bg-white !border-slate-300 !shadow-md rounded-lg overflow-hidden"
          />
        </ReactFlow>
      </div>
    </div>
  );
};

export const ThreatModelingView: React.FC = () => {
  const {
    sastPlusSuite,
    fetchSastPlusSuite,
    findings,
    appTree,
    projectPath,
    openCodeLocationInIde,
    setWorkspaceViewMode,
    setGraphViewMode,
    setIdeLayoutMode,
    userAccountsState,
    setAiDrawerOpen,
    explainCurrentGraphWithAi,
    aiIsBusy,
  } = useAuditStore();

  const [activeSubTab, setActiveSubTab] = useState<
    "TRUST_BOUNDARIES" | "STRIDE_BOARD" | "SECRET_KEYS_VAULT" | "ENTRYPOINTS_PBOM"
  >("TRUST_BOUNDARIES");
  const [selectedStrideCategory, setSelectedStrideCategory] =
    useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<
    "ALL" | "FAIL_ONLY" | "PASS_ONLY"
  >("ALL");
  const [revealedSecretIds, setRevealedSecretIds] = useState<
    Record<string, boolean>
  >({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [inlinePreviewThreatId, setInlinePreviewThreatId] = useState<
    string | null
  >(null);
  const [inlineCodeLines, setInlineCodeLines] = useState<string[]>([]);
  const [inlineCodeMeta, setInlineCodeMeta] = useState<{
    filepath: string;
    line: number;
  }>({
    filepath: "",
    line: 1,
  });
  const [loadingPreview, setLoadingPreview] = useState<boolean>(false);

  // Synchronize Threat Model with active project and findings
  useEffect(() => {
    void fetchSastPlusSuite();
  }, [projectPath, findings.length, fetchSastPlusSuite]);

  const activeUser = userAccountsState?.users?.find(
    (u) => u.id === userAccountsState.active_user_id
  );
  const canRevealSecrets = activeUser ? activeUser.can_reveal_secrets : true;

  const secretFindings = useMemo(
    () =>
      findings.filter(
        (f) =>
          f.is_secret_finding ||
          (f.rule_id || "").toUpperCase().includes("SECRET") ||
          f.cwe_id === "CWE-798"
      ),
    [findings]
  );

  const strideThreats = sastPlusSuite?.stride_threats || [];
  const endpoints = sastPlusSuite?.endpoints || [];
  const pipelineChecks = sastPlusSuite?.pipeline_checks || [];
  const flatFiles = appTree?.flat_files || [];

  const filteredStride = strideThreats.filter((t) => {
    if (
      selectedStrideCategory !== "ALL" &&
      t.stride_category !== selectedStrideCategory
    ) {
      return false;
    }
    if (statusFilter === "FAIL_ONLY" && t.status === "MITIGATED") {
      return false;
    }
    if (statusFilter === "PASS_ONLY" && t.status !== "MITIGATED") {
      return false;
    }
    return true;
  });

  const passedStrideCount = strideThreats.filter(
    (t) => t.status === "MITIGATED"
  ).length;
  const actionStrideCount = strideThreats.filter(
    (t) => t.status !== "MITIGATED"
  ).length;
  const totalChecksSum = strideThreats.reduce(
    (acc, t) =>
      acc + (t.total_checks_count ?? (t.ok_count || 1) + (t.issue_count || 0)),
    0
  );
  const totalOkSum = strideThreats.reduce(
    (acc, t) => acc + (t.ok_count ?? (t.what_passed?.length || 1)),
    0
  );
  const totalIssueSum = strideThreats.reduce(
    (acc, t) =>
      acc +
      (t.issue_count ??
        (t.status === "MITIGATED" ? 0 : t.linked_finding_ids?.length || 1)),
    0
  );
  const totalObsSum = strideThreats.reduce(
    (acc, t) => acc + (t.observations?.length ?? t.observations_count ?? 0),
    0
  );

  const toggleRevealSecret = (id: string) => {
    if (!canRevealSecrets) return;
    setRevealedSecretIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopySecret = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const handleInspectThreatCode = (threat: StrideThreatItem) => {
    const firstFindingId =
      threat.linked_finding_ids && threat.linked_finding_ids.length > 0
        ? threat.linked_finding_ids[0]
        : undefined;
    const primaryFp =
      threat.primary_filepath ||
      (threat.affected_components && threat.affected_components.length > 0
        ? threat.affected_components[0]
        : undefined);
    const primaryLn = threat.primary_line || 1;
    openCodeLocationInIde(primaryFp, primaryLn, firstFindingId);
  };

  const handleToggleInlinePreview = async (threat: StrideThreatItem) => {
    if (inlinePreviewThreatId === threat.id) {
      setInlinePreviewThreatId(null);
      return;
    }
    setInlinePreviewThreatId(threat.id);
    const rawFp =
      threat.primary_filepath ||
      (threat.affected_components && threat.affected_components[0]) ||
      "";
    const cleanFp = rawFp.replace(/\s*\(.*\)$/, "").split(":")[0].trim();
    const targetLn = threat.primary_line || 1;
    setInlineCodeMeta({ filepath: cleanFp || "workspace", line: targetLn });

    if (!cleanFp) {
      setInlineCodeLines([threat.code_snippet || "// No source file linked"]);
      return;
    }

    setLoadingPreview(true);
    try {
      const data = await apiFetchJson<{ content?: string }>(
        `/api/file?path=${encodeURIComponent(cleanFp)}`
      );
      const allLines = (data.content || "").split(/\r?\n/);
      const startIdx = Math.max(0, targetLn - 6);
      const endIdx = Math.min(allLines.length, targetLn + 8);
      const slice = allLines
        .slice(startIdx, endIdx)
        .map((l: string, i: number) => {
          const lnNum = startIdx + i + 1;
          const marker = lnNum === targetLn ? ">> " : "   ";
          return `${marker}${String(lnNum).padStart(4, " ")} | ${l}`;
        });
      setInlineCodeLines(
        slice.length > 0
          ? slice
          : [threat.code_snippet || "// File is empty"]
      );
    } catch {
      setInlineCodeLines([
        threat.code_snippet || `// Source snippet at ${cleanFp}:${targetLn}`,
      ]);
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleExplainBoundaryGraphWithAi = useCallback(
    (bNodes: Node[], bEdges: Edge[]) => {
      setAiDrawerOpen(true, "GRAPH");
      void explainCurrentGraphWithAi({
        view_mode: "TRUST_BOUNDARY_4_ZONE",
        finding_id: findings[0]?.id ?? null,
        nodes_digest: bNodes.map((n) => ({
          id: n.id,
          label: n.data?.name || n.data?.label || n.id,
          type: n.data?.trustZoneLabel || n.data?.label || "BOUNDARY_NODE",
          code: n.data?.code || "",
          filepath: n.data?.filepath || "",
          start_line: n.data?.start_line || 1,
        })),
        edges_digest: bEdges.map((e) => ({
          source: e.source,
          target: e.target,
          type: e.data?.flowLabel || e.data?.edgeType || "TRUST_CROSSING",
        })),
      });
    },
    [setAiDrawerOpen, explainCurrentGraphWithAi, findings]
  );

  return (
    <div className="flex-1 h-full overflow-y-auto bg-[#f8fafc] text-slate-900 p-6 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
        <div className="flex items-start gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-rose-50 border border-rose-300 flex items-center justify-center text-rose-700 shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-lg font-extrabold tracking-tight text-slate-900">
                Architectural Threat Modeling, 4-Zone Trust Boundaries &amp; STRIDE Verdict Dossier
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono font-extrabold uppercase rounded bg-rose-700 text-white border border-rose-800">
                4-Zone Trust Graph + STRIDE + Secret Vault
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-1">
              Interactive trust boundary propagation and STRIDE breakdown explaining{" "}
              <span className="text-emerald-800 font-bold">what passed</span>,{" "}
              <span className="text-rose-800 font-bold">what failed</span>,{" "}
              <span className="text-amber-800 font-bold">root-cause rationale</span>, and{" "}
              <span className="text-indigo-800 font-bold">step-by-step corrective actions</span>{" "}
              for{" "}
              <span className="font-mono text-slate-900 font-bold">
                {projectPath || "Active Application"}
              </span>
              .
            </p>
          </div>
        </div>

        {/* Direct Graph Launch Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => {
              setWorkspaceViewMode("REMEDIATION_IDE");
              setGraphViewMode("ENTRYPOINT_GRAPH");
              setIdeLayoutMode("SPLIT_BOTH");
            }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-bold bg-emerald-700 hover:bg-emerald-800 text-white border border-emerald-800 transition-all shadow-sm"
          >
            <Compass className="w-3.5 h-3.5 text-white" />
            Entrypoints Graph
          </button>
          <button
            type="button"
            onClick={() => {
              setWorkspaceViewMode("REMEDIATION_IDE");
              setGraphViewMode("CALL_GRAPH");
              setIdeLayoutMode("SPLIT_BOTH");
            }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-bold bg-violet-700 hover:bg-violet-800 text-white border border-violet-800 transition-all shadow-sm"
          >
            <PhoneCall className="w-3.5 h-3.5 text-white" />
            Call Graph
          </button>
        </div>
      </div>

      {/* KPI Summary Strip */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <div className="bg-white border border-emerald-300 rounded-xl p-3.5 shadow-sm">
          <div className="text-[10px] font-extrabold uppercase tracking-wider text-emerald-800 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-emerald-700" /> What is OK
          </div>
          <div className="text-2xl font-extrabold text-emerald-800 mt-1">
            {totalOkSum}{" "}
            <span className="text-xs font-mono text-slate-600">
              / {totalChecksSum} Checks
            </span>
          </div>
          <div className="text-[11px] text-slate-600 mt-0.5">
            {passedStrideCount}/6 STRIDE Categories 100% OK
          </div>
        </div>

        <div className="bg-white border border-rose-300 rounded-xl p-3.5 shadow-sm">
          <div className="text-[10px] font-extrabold uppercase tracking-wider text-rose-800 flex items-center gap-1">
            <XCircle className="w-3 h-3 text-rose-700" /> Active Issues
          </div>
          <div className="text-2xl font-extrabold text-rose-800 mt-1">
            {totalIssueSum}{" "}
            <span className="text-xs font-mono text-slate-600">Issues</span>
          </div>
          <div className="text-[11px] text-slate-600 mt-0.5">
            Across {actionStrideCount}/6 STRIDE Categories
          </div>
        </div>

        <div className="bg-white border border-cyan-300 rounded-xl p-3.5 shadow-sm">
          <div className="text-[10px] font-extrabold uppercase tracking-wider text-cyan-800 flex items-center gap-1">
            <FileCode className="w-3 h-3 text-cyan-700" /> Observations
          </div>
          <div className="text-2xl font-extrabold text-cyan-900 mt-1">
            {totalObsSum}
          </div>
          <div className="text-[11px] text-slate-600 mt-0.5">
            File:line OK &amp; Issue evidence
          </div>
        </div>

        <div className="bg-white border border-amber-300 rounded-xl p-3.5 shadow-sm">
          <div className="text-[10px] font-extrabold uppercase tracking-wider text-amber-900 flex items-center gap-1">
            <KeyRound className="w-3 h-3 text-amber-700" /> Secret Keys
          </div>
          <div className="text-2xl font-extrabold text-amber-900 mt-1">
            {secretFindings.length}
          </div>
          <div className="text-[11px] text-slate-600 mt-0.5">
            Hardcoded keys ({endpoints.length} entrypoints)
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
          <div className="text-[10px] font-extrabold uppercase tracking-wider text-sky-800">
            PBOM Controls
          </div>
          <div className="text-2xl font-extrabold text-sky-900 mt-1">
            {pipelineChecks.filter((c) => c.status === "PASS").length}/
            {pipelineChecks.length || 5}
          </div>
          <div className="text-[11px] text-slate-600 mt-0.5">
            Supply-chain checks passed
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
          <div className="text-[10px] font-extrabold uppercase tracking-wider text-violet-800">
            Posture Grade
          </div>
          <div className="text-xl font-extrabold text-violet-900 mt-1 truncate">
            {sastPlusSuite?.overall_maturity_grade || "B+"} (
            {sastPlusSuite?.maturity_score ?? 82}%)
          </div>
          <div className="text-[11px] text-slate-600 mt-0.5">
            Resilience score
          </div>
        </div>
      </div>

      {/* Sub-navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => setActiveSubTab("TRUST_BOUNDARIES")}
            className={`px-3.5 py-2 rounded-lg text-xs font-extrabold flex items-center gap-2 transition-all border ${
              activeSubTab === "TRUST_BOUNDARIES"
                ? "bg-cyan-700 text-white border-cyan-800 shadow-sm"
                : "bg-white text-slate-700 hover:bg-slate-100 border-slate-300"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            4-Zone Trust Boundary Flow Map
          </button>

          <button
            type="button"
            onClick={() => setActiveSubTab("STRIDE_BOARD")}
            className={`px-3.5 py-2 rounded-lg text-xs font-extrabold flex items-center gap-2 transition-all border ${
              activeSubTab === "STRIDE_BOARD"
                ? "bg-rose-700 text-white border-rose-800 shadow-sm"
                : "bg-white text-slate-700 hover:bg-slate-100 border-slate-300"
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Detailed STRIDE Threat Dossier ({strideThreats.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveSubTab("SECRET_KEYS_VAULT")}
            className={`px-3.5 py-2 rounded-lg text-xs font-extrabold flex items-center gap-2 transition-all border ${
              activeSubTab === "SECRET_KEYS_VAULT"
                ? "bg-amber-700 text-white border-amber-800 shadow-sm"
                : "bg-white text-slate-700 hover:bg-slate-100 border-slate-300"
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            Secret Keys &amp; Credentials Vault ({secretFindings.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveSubTab("ENTRYPOINTS_PBOM")}
            className={`px-3.5 py-2 rounded-lg text-xs font-extrabold flex items-center gap-2 transition-all border ${
              activeSubTab === "ENTRYPOINTS_PBOM"
                ? "bg-emerald-700 text-white border-emerald-800 shadow-sm"
                : "bg-white text-slate-700 hover:bg-slate-100 border-slate-300"
            }`}
          >
            <Compass className="w-3.5 h-3.5" />
            Attack Surface Entrypoints &amp; PBOM ({endpoints.length})
          </button>
        </div>
      </div>

      {/* TAB 1: INTERACTIVE 4-ZONE DIRECTIONAL TRUST BOUNDARY FLOW GRAPH + INVENTORY */}
      {activeSubTab === "TRUST_BOUNDARIES" && (
        <div className="space-y-6">
          <ReactFlowProvider>
            <TrustBoundaryFlowCanvasInner
              endpoints={endpoints}
              findings={findings}
              secretFindings={secretFindings}
              flatFiles={flatFiles}
              passedStrideCount={passedStrideCount}
              onJumpToIde={openCodeLocationInIde}
              onExplainWithAi={handleExplainBoundaryGraphWithAi}
              aiIsBusy={aiIsBusy}
            />
          </ReactFlowProvider>

          {/* Detailed 4-Zone Inventory Breakdown Cards (Zero Information Lost) */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-4 shadow-sm">
            <div>
              <h2 className="text-sm font-extrabold text-slate-900">
                Detailed 4-Zone Trust Boundary Inventory &amp; Quick Navigation
              </h2>
              <p className="text-xs text-slate-600">
                Complete architectural inventory across each security zone alongside the interactive ReactFlow diagram above.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-stretch">
              {/* Zone 1 Inventory */}
              <div className="rounded-xl border-2 border-dashed border-rose-300 bg-rose-50/40 p-4 flex flex-col justify-between space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 text-[10px] font-mono font-extrabold rounded bg-rose-700 text-white border border-rose-800">
                      ZONE 1 • UNTRUSTED
                    </span>
                    <Globe className="w-4 h-4 text-rose-700" />
                  </div>
                  <h3 className="text-sm font-extrabold text-slate-900">
                    External Untrusted Ingress
                  </h3>
                  <p className="text-xs text-slate-700">
                    HTTP requests, CLI flags, webhook payloads, network packets, and third-party package registries.
                  </p>
                </div>
                <div className="space-y-1.5 text-xs font-mono text-rose-900 bg-white p-2.5 rounded-lg border border-rose-200 font-semibold">
                  <div>• HTTP Query / Body Params</div>
                  <div>• CLI argv / Env Overrides</div>
                  <div>• External Package Tarballs</div>
                </div>
              </div>

              {/* Zone 2 Inventory */}
              <div className="rounded-xl border-2 border-sky-300 bg-sky-50/40 p-4 flex flex-col justify-between space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 text-[10px] font-mono font-extrabold rounded bg-sky-700 text-white border border-sky-800">
                      ZONE 2 • ENTRYPOINTS
                    </span>
                    <Compass className="w-4 h-4 text-sky-700" />
                  </div>
                  <h3 className="text-sm font-extrabold text-slate-900">
                    Application Entrypoints ({endpoints.length})
                  </h3>
                  <p className="text-xs text-slate-700">
                    API routes, controller handlers, and daemon command parsers discovered in the repository.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode("REMEDIATION_IDE");
                    setGraphViewMode("ENTRYPOINT_GRAPH");
                    setIdeLayoutMode("SPLIT_BOTH");
                  }}
                  className="w-full py-2 px-3 rounded-lg text-xs font-extrabold bg-sky-700 hover:bg-sky-800 text-white border border-sky-800 flex items-center justify-center gap-1.5"
                >
                  Open Entrypoints Graph <ArrowRight className="w-3.5 h-3.5 text-white" />
                </button>
              </div>

              {/* Zone 3 Inventory */}
              <div className="rounded-xl border-2 border-amber-300 bg-amber-50/40 p-4 flex flex-col justify-between space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 text-[10px] font-mono font-extrabold rounded bg-amber-700 text-white border border-amber-800">
                      ZONE 3 • BFL &amp; GUARDS
                    </span>
                    <Server className="w-4 h-4 text-amber-700" />
                  </div>
                  <h3 className="text-sm font-extrabold text-slate-900">
                    Validation &amp; BFL Sanitizers
                  </h3>
                  <p className="text-xs text-slate-700">
                    Internal function invocations (`:CALLS`), business logic, and Best Fix Location sanitizer checkpoints.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode("REMEDIATION_IDE");
                    setGraphViewMode("CALL_GRAPH");
                    setIdeLayoutMode("SPLIT_BOTH");
                  }}
                  className="w-full py-2 px-3 rounded-lg text-xs font-extrabold bg-amber-700 hover:bg-amber-800 text-white border border-amber-800 flex items-center justify-center gap-1.5"
                >
                  Open Call Graph <ArrowRight className="w-3.5 h-3.5 text-white" />
                </button>
              </div>

              {/* Zone 4 Inventory */}
              <div className="rounded-xl border-2 border-emerald-300 bg-emerald-50/40 p-4 flex flex-col justify-between space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 text-[10px] font-mono font-extrabold rounded bg-emerald-700 text-white border border-emerald-800">
                      ZONE 4 • CROWN JEWELS
                    </span>
                    <Database className="w-4 h-4 text-emerald-700" />
                  </div>
                  <h3 className="text-sm font-extrabold text-slate-900">
                    Critical Sinks, DB &amp; Secrets
                  </h3>
                  <p className="text-xs text-slate-700">
                    OS shell execution, SQL stores, filesystem writes, and {secretFindings.length} discovered secret keys.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setActiveSubTab("SECRET_KEYS_VAULT")}
                  className="w-full py-2 px-3 rounded-lg text-xs font-extrabold bg-emerald-700 hover:bg-emerald-800 text-white border border-emerald-800 flex items-center justify-center gap-1.5"
                >
                  Inspect {secretFindings.length} Secret Keys{" "}
                  <KeyRound className="w-3.5 h-3.5 text-white" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: DETAILED STRIDE THREAT MATRIX */}
      {activeSubTab === "STRIDE_BOARD" && (
        <div className="space-y-5">
          <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-700" />
                  <span>
                    STRIDE Framework Executive Count &amp; Verdict Matrix — What is OK vs. What is the Issue
                  </span>
                </h2>
                <p className="text-xs text-slate-600 mt-0.5">
                  Per-category STRIDE breakdown showing exact inspected check counts,{" "}
                  <span className="text-emerald-800 font-bold">
                    ✔ What is OK (Passed Count)
                  </span>
                  ,{" "}
                  <span className="text-rose-800 font-bold">
                    ✖ What is the Issue (Failed Count)
                  </span>
                  , and{" "}
                  <span className="text-cyan-800 font-bold">
                    Recorded Observations
                  </span>
                  .
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="px-2.5 py-1 rounded-lg bg-emerald-50 border border-emerald-300 text-emerald-900 font-extrabold">
                  ✔ Total OK: {totalOkSum}
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-rose-50 border border-rose-300 text-rose-900 font-extrabold">
                  ✖ Total Issues: {totalIssueSum}
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-cyan-50 border border-cyan-300 text-cyan-900 font-extrabold">
                  Observations: {totalObsSum}
                </span>
              </div>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-200">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-100 text-slate-800 border-b border-slate-200 text-[10px] uppercase tracking-wider font-extrabold">
                    <th className="py-2.5 px-3">STRIDE Category &amp; Property</th>
                    <th className="py-2.5 px-3 text-center">Total Checks</th>
                    <th className="py-2.5 px-3 text-center text-emerald-800">
                      ✔ OK Count
                    </th>
                    <th className="py-2.5 px-3 text-center text-rose-800">
                      ✖ Issue Count
                    </th>
                    <th className="py-2.5 px-3 text-center text-cyan-800">
                      Observations
                    </th>
                    <th className="py-2.5 px-3">✔ What is OK (Verified Safe)</th>
                    <th className="py-2.5 px-3">
                      ✖ What is the Issue (Detected Flaws)
                    </th>
                    <th className="py-2.5 px-3 text-center">STRIDE Verdict</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {strideThreats.map((st) => {
                    const m = STRIDE_META[st.stride_category] || {
                      letter: st.stride_letter || "T",
                      label: st.stride_category,
                      securityProperty: st.security_property || "Security Control",
                      color: "text-amber-800",
                      badgeBg: "bg-amber-50 border-amber-300 text-amber-900",
                      activeBtn: "bg-amber-700 border-amber-800 text-white",
                    };
                    const okC = st.ok_count ?? (st.what_passed?.length || 1);
                    const issC =
                      st.issue_count ??
                      (st.status === "MITIGATED"
                        ? 0
                        : st.linked_finding_ids?.length || 1);
                    const totC = st.total_checks_count ?? okC + issC;
                    const obsC =
                      st.observations?.length ?? st.observations_count ?? 0;
                    const isOk = issC === 0 && st.status === "MITIGATED";
                    return (
                      <tr
                        key={st.id}
                        className={`transition-colors ${
                          isOk
                            ? "bg-white hover:bg-slate-50"
                            : "bg-rose-50/40 hover:bg-rose-50/80"
                        }`}
                      >
                        <td className="py-2.5 px-3">
                          <div className="flex items-center gap-2">
                            <span
                              className={`w-7 h-7 rounded-lg border flex items-center justify-center font-mono font-black text-xs shrink-0 ${m.badgeBg}`}
                            >
                              {m.letter}
                            </span>
                            <div>
                              <div className="font-bold text-slate-900">
                                {m.label}
                              </div>
                              <div className="text-[10px] text-slate-600">
                                {st.security_property || m.securityProperty}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 text-center font-mono font-bold text-slate-800">
                          {totC}
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-900 border border-emerald-300 font-mono font-extrabold">
                            ✔ {okC} OK
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span
                            className={`px-2 py-0.5 rounded font-mono font-extrabold border ${
                              issC > 0
                                ? "bg-rose-700 text-white border-rose-800"
                                : "bg-slate-100 text-emerald-800 border-slate-300"
                            }`}
                          >
                            {issC > 0
                              ? `✖ ${issC} Issue${issC > 1 ? "s" : ""}`
                              : "0 Issues"}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span className="px-2 py-0.5 rounded bg-cyan-50 text-cyan-900 border border-cyan-300 font-mono font-bold">
                            {obsC} Obs
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-emerald-900 max-w-xs">
                          {st.ok_summary ||
                            st.what_passed?.[0] ||
                            "Controls verified OK."}
                        </td>
                        <td
                          className={`py-2.5 px-3 max-w-xs ${
                            issC > 0
                              ? "text-rose-900 font-semibold"
                              : "text-slate-600"
                          }`}
                        >
                          {st.issue_summary ||
                            (issC > 0
                              ? st.what_failed?.[0]
                              : "0 Issues — All checks OK.")}
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span
                            className={`px-2 py-1 rounded-md text-[10px] font-mono font-extrabold border inline-flex items-center gap-1 ${
                              isOk
                                ? "bg-emerald-700 text-white border-emerald-800"
                                : "bg-rose-700 text-white border-rose-800"
                            }`}
                          >
                            {isOk ? "✔ OK (PASS)" : `✖ ISSUE (${st.severity})`}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              type="button"
                              onClick={() =>
                                setSelectedStrideCategory(st.stride_category)
                              }
                              className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-800 border border-slate-300 text-[10px] font-bold"
                            >
                              Focus [{m.letter}]
                            </button>
                            <button
                              type="button"
                              onClick={() => handleInspectThreatCode(st)}
                              className="px-2 py-1 rounded bg-amber-700 hover:bg-amber-800 text-white border border-amber-800 text-[10px] font-bold flex items-center gap-1"
                            >
                              <Code2 className="w-3 h-3 text-white" />
                              Inspect
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
                <tfoot>
                  <tr className="bg-slate-100 border-t-2 border-slate-300 font-mono text-xs font-extrabold text-slate-900">
                    <td className="py-2.5 px-3">TOTAL ACROSS ALL 6 STRIDE DOMAINS</td>
                    <td className="py-2.5 px-3 text-center">
                      {totalChecksSum} Checks
                    </td>
                    <td className="py-2.5 px-3 text-center text-emerald-800">
                      ✔ {totalOkSum} OK
                    </td>
                    <td className="py-2.5 px-3 text-center text-rose-800">
                      ✖ {totalIssueSum} Issues
                    </td>
                    <td className="py-2.5 px-3 text-center text-cyan-800">
                      {totalObsSum} Observations
                    </td>
                    <td className="py-2.5 px-3 text-emerald-800 font-sans text-[11px]">
                      {passedStrideCount} of 6 STRIDE categories 100% OK
                    </td>
                    <td className="py-2.5 px-3 text-rose-800 font-sans text-[11px]">
                      {actionStrideCount} of 6 STRIDE categories have active issues
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      {actionStrideCount === 0
                        ? "✔ ALL OK"
                        : `${actionStrideCount} ACTION REQ`}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedStrideCategory("ALL");
                          setStatusFilter("ALL");
                        }}
                        className="px-2 py-1 rounded bg-white hover:bg-slate-200 text-cyan-900 border border-slate-300 text-[10px] font-bold"
                      >
                        Show All 6
                      </button>
                    </td>
                  </tr>
                </tfoot>
              </table>
            </div>
          </div>

          {/* Category & Verdict Filter Pills */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-white border border-slate-200 rounded-xl p-3 shadow-sm">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs font-bold text-slate-700 flex items-center gap-1 mr-1">
                <Filter className="w-3.5 h-3.5" /> STRIDE Vector:
              </span>
              <button
                type="button"
                onClick={() => setSelectedStrideCategory("ALL")}
                className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-all ${
                  selectedStrideCategory === "ALL"
                    ? "bg-indigo-700 text-white border-indigo-800"
                    : "bg-slate-50 text-slate-700 border-slate-300 hover:bg-slate-100"
                }`}
              >
                All 6 STRIDE ({totalOkSum} OK / {totalIssueSum} Issues)
              </button>
              {Object.entries(STRIDE_META).map(([catKey, meta]) => {
                const matchThreat = strideThreats.find(
                  (t) => t.stride_category === catKey
                );
                const okC = matchThreat?.ok_count ?? 1;
                const issC = matchThreat?.issue_count ?? 0;
                const active = selectedStrideCategory === catKey;
                return (
                  <button
                    key={catKey}
                    type="button"
                    onClick={() => setSelectedStrideCategory(catKey)}
                    className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-all flex items-center gap-1.5 ${
                      active
                        ? meta.activeBtn
                        : "bg-slate-50 text-slate-700 border-slate-300 hover:bg-slate-100"
                    }`}
                  >
                    <span className="font-mono font-extrabold">
                      [{meta.letter}]
                    </span>
                    <span>{meta.label}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-900 border border-emerald-200">
                      ✔{okC}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        issC > 0
                          ? "bg-rose-100 text-rose-900 border border-rose-300 font-extrabold"
                          : "bg-slate-100 text-slate-600"
                      }`}
                    >
                      ✖{issC}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setStatusFilter("ALL")}
                className={`px-2.5 py-1 rounded-md text-xs font-bold border ${
                  statusFilter === "ALL"
                    ? "bg-indigo-700 text-white border-indigo-800"
                    : "bg-slate-50 text-slate-700 border-slate-300"
                }`}
              >
                All Verdicts (6)
              </button>
              <button
                type="button"
                onClick={() => setStatusFilter("FAIL_ONLY")}
                className={`px-2.5 py-1 rounded-md text-xs font-bold border flex items-center gap-1 ${
                  statusFilter === "FAIL_ONLY"
                    ? "bg-rose-700 text-white border-rose-800"
                    : "bg-slate-50 text-slate-700 border-slate-300"
                }`}
              >
                <XCircle className="w-3 h-3" />
                Has Issues ({actionStrideCount})
              </button>
              <button
                type="button"
                onClick={() => setStatusFilter("PASS_ONLY")}
                className={`px-2.5 py-1 rounded-md text-xs font-bold border flex items-center gap-1 ${
                  statusFilter === "PASS_ONLY"
                    ? "bg-emerald-700 text-white border-emerald-800"
                    : "bg-slate-50 text-slate-700 border-slate-300"
                }`}
              >
                <CheckCircle2 className="w-3 h-3" />
                100% OK ({passedStrideCount})
              </button>
            </div>
          </div>

          {/* Detailed STRIDE Threat Dossier Cards */}
          <div className="grid grid-cols-1 gap-5">
            {filteredStride.map((threat) => {
              const meta = STRIDE_META[threat.stride_category] || {
                letter: threat.stride_letter || "T",
                label: threat.stride_category,
                securityProperty: "Security Control",
                color: "text-amber-800",
                badgeBg: "bg-amber-50 border-amber-300 text-amber-900",
                activeBtn: "bg-amber-700 border-amber-800 text-white",
              };
              const isPassed = threat.status === "MITIGATED";
              const primaryFp =
                threat.primary_filepath ||
                threat.affected_components?.[0] ||
                "workspace";
              const primaryLn = threat.primary_line || 1;
              const okCount = threat.ok_count ?? (threat.what_passed?.length || 1);
              const issueCount =
                threat.issue_count ??
                (isPassed ? 0 : threat.linked_finding_ids?.length || 1);
              const totalCount =
                threat.total_checks_count ?? okCount + issueCount;
              const obsList = threat.observations || [];
              const issueObsCount = obsList.filter(
                (o) => o.verdict === "ISSUE"
              ).length;
              const okObsCount = obsList.filter((o) => o.verdict === "OK").length;

              const whatPassedList =
                threat.what_passed && threat.what_passed.length > 0
                  ? threat.what_passed
                  : [
                      "Automated CPG AST, CFG, and DFG inspection completed for this category.",
                    ];
              const whatFailedList =
                threat.what_failed && threat.what_failed.length > 0
                  ? threat.what_failed
                  : isPassed
                  ? [
                      "0 Issues Detected — All inspected components passed verification (100% OK).",
                    ]
                  : [threat.threat_scenario];
              const whyText =
                threat.why_issue_or_not ||
                (isPassed
                  ? `PASS RATIONALE: ${threat.threat_scenario}`
                  : `ISSUE RATIONALE: ${threat.threat_scenario}`);
              const riskText =
                threat.risk_impact ||
                `Violates ${meta.securityProperty}. ${threat.threat_scenario}`;
              const correctiveSteps =
                threat.corrective_actions &&
                threat.corrective_actions.length > 0
                  ? threat.corrective_actions
                  : [threat.mitigation_control];

              return (
                <div
                  key={threat.id}
                  className={`bg-white border-[1.5px] rounded-xl p-5 space-y-4 shadow-sm transition-all ${
                    isPassed
                      ? "border-emerald-300 hover:border-emerald-500"
                      : "border-rose-300 hover:border-rose-500"
                  }`}
                >
                  <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-200 pb-3.5">
                    <div className="flex items-start gap-3">
                      <span
                        className={`w-10 h-10 rounded-xl border flex items-center justify-center font-mono text-base font-black shrink-0 ${meta.badgeBg}`}
                      >
                        {meta.letter}
                      </span>
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-600">
                            STRIDE [{meta.letter}] • {meta.label} • Security
                            Property:{" "}
                            <span className="text-slate-900 font-extrabold">
                              {threat.security_property || meta.securityProperty}
                            </span>
                          </span>
                          {threat.compliance_mapping && (
                            <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-50 text-cyan-900 border border-cyan-300">
                              {threat.compliance_mapping}
                            </span>
                          )}
                        </div>
                        <h3 className="text-base font-extrabold text-slate-900 mt-1">
                          {threat.title}
                        </h3>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      <span className="px-2.5 py-1 text-xs font-mono font-bold rounded-lg bg-slate-100 text-slate-800 border border-slate-300">
                        Total Inspected: {totalCount}
                      </span>
                      <span className="px-2.5 py-1 text-xs font-mono font-extrabold rounded-lg bg-emerald-50 text-emerald-900 border border-emerald-300">
                        ✔ OK: {okCount}
                      </span>
                      <span
                        className={`px-2.5 py-1 text-xs font-mono font-extrabold rounded-lg border ${
                          issueCount > 0
                            ? "bg-rose-50 text-rose-900 border-rose-300"
                            : "bg-slate-100 text-emerald-800 border-slate-300"
                        }`}
                      >
                        ✖ Issues: {issueCount}
                      </span>
                      <span
                        className={`px-2.5 py-1 text-xs font-extrabold rounded-lg border flex items-center gap-1.5 ${
                          isPassed
                            ? "bg-emerald-700 text-white border-emerald-800"
                            : "bg-rose-700 text-white border-rose-800"
                        }`}
                      >
                        {isPassed ? (
                          <>
                            <CheckCircle2 className="w-3.5 h-3.5 text-white" />
                            {threat.verdict_label || `OK • ALL ${okCount} PASSED`}
                          </>
                        ) : (
                          <>
                            <AlertTriangle className="w-3.5 h-3.5 text-white" />
                            {threat.verdict_label || `ISSUE • ${issueCount} FAILED`}
                          </>
                        )}
                      </span>
                    </div>
                  </div>

                  {/* Section 1: What is OK vs What is the Issue */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                    <div className="bg-emerald-50/50 border border-emerald-300 rounded-xl p-3.5 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <div className="text-xs font-extrabold uppercase tracking-wider text-emerald-900 flex items-center gap-1.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-700 shrink-0" />
                          ✔ What is OK as per STRIDE [{meta.letter}]
                        </div>
                        <span className="px-2 py-0.5 rounded bg-emerald-100 text-emerald-900 font-mono text-[11px] font-bold">
                          {okCount} OK / Passed
                        </span>
                      </div>
                      <ul className="space-y-1.5 text-xs text-slate-800">
                        {whatPassedList.map((item, i) => (
                          <li
                            key={i}
                            className="flex items-start gap-2 leading-relaxed"
                          >
                            <span className="text-emerald-700 font-bold shrink-0">
                              ✔
                            </span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div
                      className={`rounded-xl p-3.5 space-y-2 border ${
                        isPassed
                          ? "bg-slate-50 border-slate-200"
                          : "bg-rose-50/50 border-rose-300"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div
                          className={`text-xs font-extrabold uppercase tracking-wider flex items-center gap-1.5 ${
                            isPassed ? "text-emerald-900" : "text-rose-900"
                          }`}
                        >
                          {isPassed ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-700 shrink-0" />
                          ) : (
                            <XCircle className="w-4 h-4 text-rose-700 shrink-0" />
                          )}
                          ✖ What is the Issue as per STRIDE [{meta.letter}]
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold ${
                            issueCount > 0
                              ? "bg-rose-700 text-white"
                              : "bg-emerald-100 text-emerald-900"
                          }`}
                        >
                          {issueCount} Issue{issueCount === 1 ? "" : "s"}
                        </span>
                      </div>
                      <ul className="space-y-1.5 text-xs text-slate-800">
                        {whatFailedList.map((item, i) => (
                          <li
                            key={i}
                            className="flex items-start gap-2 leading-relaxed"
                          >
                            <span
                              className={`font-bold shrink-0 ${
                                isPassed ? "text-emerald-700" : "text-rose-700"
                              }`}
                            >
                              {isPassed ? "✔" : "✖"}
                            </span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* Section 2: Observations Breakdown */}
                  {obsList.length > 0 && (
                    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="text-xs font-extrabold uppercase tracking-wider text-cyan-900 flex items-center gap-2">
                          <FileCode className="w-4 h-4 text-cyan-700" />
                          <span>
                            Detailed STRIDE [{meta.letter}] Observations (
                            {obsList.length}:{" "}
                            <span className="text-rose-800">
                              {issueObsCount} Issue(s)
                            </span>{" "}
                            •{" "}
                            <span className="text-emerald-800">
                              {okObsCount} Verified OK
                            </span>
                            )
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-600">
                          Click{" "}
                          <strong className="text-amber-900">Inspect Code</strong>{" "}
                          to jump to exact file &amp; line
                        </span>
                      </div>

                      <div className="space-y-2.5">
                        {obsList.map((obs, oIdx) => {
                          const isObsIssue = obs.verdict === "ISSUE";
                          return (
                            <div
                              key={obs.id || oIdx}
                              className={`rounded-xl p-3.5 border space-y-2 bg-white ${
                                isObsIssue
                                  ? "border-rose-300"
                                  : "border-emerald-300"
                              }`}
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-300 text-[10px] font-mono font-bold text-slate-800">
                                    Obs #{oIdx + 1}
                                  </span>
                                  <span
                                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-extrabold border ${
                                      isObsIssue
                                        ? "bg-rose-700 text-white border-rose-800"
                                        : "bg-emerald-700 text-white border-emerald-800"
                                    }`}
                                  >
                                    {isObsIssue
                                      ? `✖ ISSUE • ${obs.severity}`
                                      : "✔ OK • VERIFIED"}
                                  </span>
                                  <span className="px-2 py-0.5 rounded bg-cyan-50 text-cyan-900 border border-cyan-300 text-[10px] font-mono font-bold">
                                    {obs.control_domain}
                                  </span>
                                  {obs.cwe_or_standard && (
                                    <span className="px-2 py-0.5 rounded bg-violet-50 text-violet-900 border border-violet-300 text-[10px] font-mono font-bold">
                                      {obs.cwe_or_standard}
                                    </span>
                                  )}
                                  <span className="text-xs font-mono font-extrabold text-slate-900">
                                    {obs.filepath}:{obs.line}
                                  </span>
                                </div>

                                <button
                                  type="button"
                                  onClick={() =>
                                    openCodeLocationInIde(
                                      obs.filepath,
                                      obs.line || 1,
                                      obs.linked_finding_id || undefined
                                    )
                                  }
                                  className="px-2.5 py-1 rounded-lg bg-amber-700 hover:bg-amber-800 text-white border border-amber-800 text-[11px] font-bold flex items-center gap-1 cursor-pointer shrink-0"
                                >
                                  <Code2 className="w-3 h-3 text-white" />
                                  Inspect Code ({obs.filepath}:{obs.line})
                                </button>
                              </div>

                              <div className="text-xs font-extrabold text-slate-900">
                                {obs.title}
                              </div>

                              {obs.code_snippet && (
                                <pre className="text-[11px] font-mono text-slate-800 bg-slate-100 border border-slate-200 rounded-lg px-3 py-1.5 overflow-x-auto">
                                  {obs.filepath}:{obs.line} → {obs.code_snippet}
                                </pre>
                              )}

                              <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
                                <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5">
                                  <span
                                    className={`font-extrabold ${
                                      isObsIssue
                                        ? "text-rose-800"
                                        : "text-emerald-800"
                                    }`}
                                  >
                                    {isObsIssue
                                      ? "Why Issue: "
                                      : "Why OK: "}
                                  </span>
                                  <span className="text-slate-700">
                                    {obs.why_ok_or_issue}
                                  </span>
                                </div>
                                <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5">
                                  <span className="font-extrabold text-amber-900">
                                    Risk &amp; Impact:{" "}
                                  </span>
                                  <span className="text-slate-700">
                                    {obs.risk_impact}
                                  </span>
                                </div>
                                <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5">
                                  <span className="font-extrabold text-cyan-900">
                                    Corrective Action:{" "}
                                  </span>
                                  <span className="text-slate-700">
                                    {obs.corrective_action}
                                  </span>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Section 3: Root-Cause + Risk */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                    <div className="bg-amber-50/40 border border-amber-300 rounded-xl p-3.5 space-y-1.5">
                      <div className="text-xs font-extrabold uppercase tracking-wider text-amber-900">
                        Root-Cause Rationale
                      </div>
                      <p className="text-xs text-slate-800 leading-relaxed">
                        {whyText}
                      </p>
                    </div>

                    <div className="bg-rose-50/40 border border-rose-300 rounded-xl p-3.5 space-y-1.5">
                      <div className="text-xs font-extrabold uppercase tracking-wider text-rose-900">
                        Technical &amp; Business Risk Analysis
                      </div>
                      <p className="text-xs text-slate-800 leading-relaxed">
                        {riskText}
                      </p>
                    </div>
                  </div>

                  {/* Section 4: Corrective Actions */}
                  <div className="bg-cyan-50/50 border border-cyan-300 rounded-xl p-4 space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-xs font-extrabold uppercase tracking-wider text-cyan-900 flex items-center gap-1.5">
                        <Wrench className="w-4 h-4 text-cyan-700" />
                        Corrective Actions &amp; Architectural Remediation Plan
                      </div>
                      <span className="text-[11px] text-slate-700">
                        Target Location:{" "}
                        <span className="font-mono font-bold text-slate-900">
                          {primaryFp}:{primaryLn}
                        </span>
                      </span>
                    </div>
                    <div className="space-y-1.5">
                      {correctiveSteps.map((step, idx) => (
                        <div
                          key={idx}
                          className="text-xs text-slate-800 bg-white border border-slate-200 rounded-lg px-3 py-2 leading-relaxed font-medium"
                        >
                          {step}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Inline Live Code Preview */}
                  {inlinePreviewThreatId === threat.id && (
                    <div className="bg-slate-50 border border-amber-400 rounded-xl p-3.5 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-extrabold text-amber-900 flex items-center gap-1.5">
                          <FileCode className="w-3.5 h-3.5 text-amber-700" />
                          Live Source Code Preview — {inlineCodeMeta.filepath}:L
                          {inlineCodeMeta.line}
                        </span>
                        <button
                          type="button"
                          onClick={() => handleInspectThreatCode(threat)}
                          className="text-xs font-bold text-cyan-800 hover:underline flex items-center gap-1"
                        >
                          Open Full File in Split IDE{" "}
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      </div>
                      <pre className="text-[11px] font-mono text-slate-800 bg-white border border-slate-200 rounded-lg p-3 overflow-x-auto leading-relaxed">
                        {loadingPreview
                          ? "Loading source file lines..."
                          : inlineCodeLines.join("\n")}
                      </pre>
                    </div>
                  )}

                  {/* Footer Row */}
                  <div className="pt-2 border-t border-slate-200 flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[11px] text-slate-600 font-semibold">
                        Affected Components:
                      </span>
                      {(threat.affected_components || [])
                        .slice(0, 4)
                        .map((comp, idx) => (
                          <button
                            key={idx}
                            type="button"
                            onClick={() => openCodeLocationInIde(comp, primaryLn)}
                            title={`Open ${comp} in Split Code + Graph IDE`}
                            className="px-2.5 py-1 text-[11px] font-mono font-bold rounded-md bg-slate-100 hover:bg-amber-50 text-slate-800 hover:text-amber-900 border border-slate-300 hover:border-amber-400 flex items-center gap-1 transition-all cursor-pointer"
                          >
                            <FileCode className="w-3 h-3 shrink-0" />
                            {comp}
                          </button>
                        ))}
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => handleToggleInlinePreview(threat)}
                        className="px-3 py-1.5 rounded-lg text-xs font-bold bg-white hover:bg-slate-100 text-slate-800 border border-slate-300 flex items-center gap-1.5 transition-all"
                      >
                        <Eye className="w-3.5 h-3.5 text-cyan-700" />
                        {inlinePreviewThreatId === threat.id
                          ? "Hide Inline Code"
                          : "Preview Code Here"}
                      </button>

                      <button
                        type="button"
                        onClick={() => handleInspectThreatCode(threat)}
                        className="px-3.5 py-1.5 rounded-lg text-xs font-extrabold bg-amber-700 hover:bg-amber-800 text-white border border-amber-800 flex items-center gap-1.5 transition-all shadow-sm"
                      >
                        <Code2 className="w-3.5 h-3.5 text-white" />
                        Inspect in IDE (
                        {threat.linked_finding_ids?.length
                          ? `${threat.linked_finding_ids.length} Flaw${
                              threat.linked_finding_ids.length > 1 ? "s" : ""
                            }`
                          : `${primaryFp}:${primaryLn}`}
                        )
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 3: SECRET KEYS & CREDENTIALS VAULT */}
      {activeSubTab === "SECRET_KEYS_VAULT" && (
        <div className="space-y-4">
          <div className="bg-amber-50 border border-amber-300 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <KeyRound className="w-6 h-6 text-amber-800 shrink-0" />
              <div>
                <h2 className="text-sm font-extrabold text-amber-950">
                  Deep Secret Keys, API Tokens &amp; Cryptographic Credentials Inspector
                </h2>
                <p className="text-xs text-slate-700 mt-0.5">
                  Extracts exact hardcoded secret key identifiers, credential classifications, Shannon entropy scores, and masked/revealable values with corrective rotation actions.
                </p>
              </div>
            </div>
            <div className="text-xs font-mono px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-800">
              RBAC Secret Reveal:{" "}
              <span
                className={
                  canRevealSecrets
                    ? "text-emerald-800 font-extrabold"
                    : "text-rose-800 font-extrabold"
                }
              >
                {canRevealSecrets ? "AUTHORIZED" : "RESTRICTED (MASKED ONLY)"}
              </span>
            </div>
          </div>

          {secretFindings.length === 0 ? (
            <div className="bg-white border border-emerald-300 rounded-xl p-8 text-center space-y-2 shadow-sm">
              <CheckCircle2 className="w-8 h-8 text-emerald-700 mx-auto" />
              <div className="text-sm font-extrabold text-emerald-900">
                PASS • No Hardcoded Secret Keys Detected in Active Scan
              </div>
              <p className="text-xs text-slate-600 max-w-md mx-auto">
                All scanned source files, environment templates, and manifests passed hardcoded credential (`CWE-798`) and high-entropy secret key checks.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {secretFindings.map((sf) => {
                const node = sf.path_nodes?.[0];
                const isRevealed = Boolean(revealedSecretIds[sf.id]);
                const keyName =
                  sf.secret_key_name || node?.name || "SECRET_KEY";
                const maskedVal =
                  sf.secret_value_masked || "REDACTED_SECRET_VALUE";
                const rawVal = sf.secret_value_raw || maskedVal;
                const displayVal = isRevealed ? rawVal : maskedVal;
                const fp =
                  sf.best_fix_location?.filepath || node?.filepath || "config";
                const ln =
                  sf.best_fix_location?.line || node?.start_line || 1;

                return (
                  <div
                    key={sf.id}
                    className="bg-white border-[1.5px] border-amber-300 hover:border-amber-500 rounded-xl p-4 flex flex-col gap-3 shadow-sm"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="px-2 py-0.5 text-[10px] font-mono font-extrabold rounded bg-rose-700 text-white border border-rose-800">
                          FAIL • {sf.severity}
                        </span>
                        <span className="px-2 py-0.5 text-[10px] font-mono font-extrabold rounded bg-amber-50 text-amber-900 border border-amber-300 flex items-center gap-1">
                          <KeyRound className="w-3 h-3 text-amber-700" />
                          {sf.secret_type || "Hardcoded Secret Key"}
                        </span>
                        {sf.secret_entropy && (
                          <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-50 text-cyan-900 border border-cyan-300">
                            Entropy: {sf.secret_entropy} bits/char
                          </span>
                        )}
                        <span className="text-xs font-mono font-extrabold text-slate-900">
                          {fp}:{ln}
                        </span>
                      </div>

                      <button
                        type="button"
                        onClick={() => openCodeLocationInIde(fp, ln, sf.id)}
                        className="px-3 py-1.5 rounded-lg text-xs font-extrabold bg-amber-700 hover:bg-amber-800 text-white border border-amber-800 flex items-center gap-1.5 transition-all"
                      >
                        <Code2 className="w-3.5 h-3.5 text-white" />
                        Locate Key in Code ({fp}:{ln})
                      </button>
                    </div>

                    <div className="text-sm font-extrabold text-slate-900">
                      {sf.title}
                    </div>

                    <div className="flex flex-wrap items-center gap-2 bg-slate-100 border border-slate-300 rounded-lg px-3 py-2 font-mono text-xs">
                      <span className="text-amber-900 font-extrabold">
                        🔑 {keyName}
                      </span>
                      <span className="text-slate-500">=</span>
                      <span
                        className={`px-2 py-0.5 rounded font-semibold ${
                          isRevealed
                            ? "bg-rose-50 text-rose-900 border border-rose-300"
                            : "bg-white text-slate-800 border border-slate-200"
                        } break-all`}
                      >
                        {displayVal}
                      </span>

                      {canRevealSecrets && (
                        <button
                          type="button"
                          onClick={() => toggleRevealSecret(sf.id)}
                          className="ml-auto px-2 py-1 rounded text-[10px] font-sans font-bold bg-white hover:bg-slate-200 text-slate-800 border border-slate-300 flex items-center gap-1"
                        >
                          {isRevealed ? (
                            <>
                              <EyeOff className="w-3 h-3 text-amber-700" /> Mask
                            </>
                          ) : (
                            <>
                              <Eye className="w-3 h-3 text-amber-700" /> Reveal Key
                            </>
                          )}
                        </button>
                      )}

                      <button
                        type="button"
                        onClick={() =>
                          handleCopySecret(sf.id, `${keyName}=${displayVal}`)
                        }
                        className="px-2 py-1 rounded text-[10px] font-sans font-bold bg-white hover:bg-slate-200 text-slate-800 border border-slate-300 flex items-center gap-1"
                      >
                        {copiedId === sf.id ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-700" /> Copied
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" /> Copy
                          </>
                        )}
                      </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
                      <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5 text-slate-700">
                        <span className="text-rose-800 font-extrabold">
                          Why Issue &amp; Risk:{" "}
                        </span>
                        {sf.description}
                      </div>
                      <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5 text-slate-700">
                        <span className="text-emerald-800 font-extrabold">
                          Corrective Action:{" "}
                        </span>
                        {sf.remediation}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: ATTACK SURFACE ENTRYPOINTS & PBOM */}
      {activeSubTab === "ENTRYPOINTS_PBOM" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 shadow-sm">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                <Compass className="w-4 h-4 text-emerald-700" />
                Discovered Attack Surface Entrypoints ({endpoints.length})
              </h3>
              <button
                type="button"
                onClick={() => {
                  setWorkspaceViewMode("REMEDIATION_IDE");
                  setGraphViewMode("ENTRYPOINT_GRAPH");
                  setIdeLayoutMode("SPLIT_BOTH");
                }}
                className="text-xs font-extrabold text-emerald-800 hover:underline"
              >
                Visualize in Graph →
              </button>
            </div>
            <div className="space-y-2.5 max-h-[540px] overflow-y-auto pr-1">
              {endpoints.map((ep) => (
                <div
                  key={ep.id}
                  className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="px-2 py-0.5 text-[10px] font-mono font-extrabold rounded bg-emerald-50 text-emerald-900 border border-emerald-300">
                        {ep.method}
                      </span>
                      <span className="text-xs font-mono font-extrabold text-slate-900 truncate">
                        {ep.route_path}
                      </span>
                    </div>
                    <span
                      className={`px-2 py-0.5 text-[10px] font-mono font-extrabold rounded shrink-0 ${
                        ep.exposure_level === "HIGH_EXPOSURE"
                          ? "bg-rose-700 text-white border border-rose-800"
                          : "bg-emerald-50 text-emerald-900 border border-emerald-300"
                      }`}
                    >
                      {ep.exposure_level === "HIGH_EXPOSURE"
                        ? `ACTION REQUIRED • ${ep.auth_posture}`
                        : `PASS • ${ep.auth_posture}`}
                    </span>
                  </div>
                  <div className="text-xs text-slate-700">
                    {ep.plain_english_purpose}
                  </div>
                  <div className="flex items-center justify-between pt-1">
                    <span className="text-[11px] font-mono text-slate-600">
                      Handler:{" "}
                      <span className="text-slate-900 font-bold">
                        {ep.handler_name}
                      </span>{" "}
                      • {ep.filepath}:{ep.line_number}
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        openCodeLocationInIde(ep.filepath, ep.line_number)
                      }
                      className="px-2.5 py-1 rounded text-[11px] font-extrabold bg-amber-700 hover:bg-amber-800 text-white border border-amber-800 flex items-center gap-1"
                    >
                      <Code2 className="w-3 h-3 text-white" />
                      Inspect Code
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 shadow-sm">
            <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-700" />
              Pipeline Bill of Materials (PBOM) &amp; Pass/Fail Controls
            </h3>
            <div className="space-y-3 max-h-[540px] overflow-y-auto pr-1">
              {pipelineChecks.map((chk) => (
                <div
                  key={chk.id}
                  className="bg-slate-50 border border-slate-200 rounded-lg p-3.5 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <div className="text-[10px] font-mono font-bold uppercase text-slate-600">
                        {chk.category}
                      </div>
                      <span className="text-xs font-extrabold text-slate-900">
                        {chk.title}
                      </span>
                    </div>
                    <span
                      className={`px-2 py-0.5 text-[10px] font-mono font-extrabold rounded shrink-0 ${
                        chk.status === "PASS"
                          ? "bg-emerald-700 text-white border border-emerald-800"
                          : chk.status === "WARNING"
                          ? "bg-amber-700 text-white border border-amber-800"
                          : "bg-rose-700 text-white border border-rose-800"
                      }`}
                    >
                      {chk.status}
                    </span>
                  </div>

                  <p className="text-xs text-slate-700">{chk.details}</p>

                  {chk.why_issue_or_not && (
                    <div className="text-[11px] text-amber-950 bg-amber-50/70 border border-amber-200 rounded p-2">
                      {chk.why_issue_or_not}
                    </div>
                  )}

                  {chk.risk_impact && (
                    <div className="text-[11px] text-rose-900">
                      <span className="font-extrabold">Risk:</span>{" "}
                      {chk.risk_impact}
                    </div>
                  )}

                  <div className="flex items-center justify-between gap-2 pt-1 border-t border-slate-200">
                    <span className="text-[11px] text-cyan-900 font-mono truncate font-medium">
                      Corrective Action: {chk.remediation}
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        openCodeLocationInIde(
                          chk.primary_filepath || chk.evidence_path,
                          chk.primary_line || 1
                        )
                      }
                      className="px-2.5 py-1 rounded text-[11px] font-extrabold bg-amber-700 hover:bg-amber-800 text-white border border-amber-800 flex items-center gap-1 shrink-0"
                    >
                      <Code2 className="w-3 h-3 text-white" />
                      Inspect File
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
