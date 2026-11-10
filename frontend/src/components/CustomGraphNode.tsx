"use client";

import React, { memo } from "react";
import { Handle, Position, NodeProps } from "reactflow";
import { useAuditStore } from "@/store/useAuditStore";
import { formatCircledStep } from "./DirectionalFlowEdge";
import {
  Folder,
  FolderOpen,
  FileCode,
  Server,
  Layout,
  Terminal,
  Settings,
  Package,
  Flame,
  Code2,
  Cpu,
  ChevronRight,
  ChevronDown,
  Crosshair,
  GitBranch,
  ShieldCheck,
} from "lucide-react";

export type NodeBlastRole =
  | "NONE"
  | "FOCUSED"
  | "UPSTREAM"
  | "DOWNSTREAM"
  | "DIMMED";

const LABEL_COLORS: Record<string, string> = {
  Function: "bg-cyan-50 text-cyan-900 border-cyan-300",
  Call: "bg-amber-50 text-amber-900 border-amber-300",
  Variable: "bg-emerald-50 text-emerald-900 border-emerald-300",
  Parameter: "bg-sky-50 text-sky-900 border-sky-300",
  Assignment: "bg-amber-50 text-amber-900 border-amber-300",
  LoopBlock: "bg-violet-50 text-violet-900 border-violet-300",
  ControlBlock: "bg-cyan-50 text-cyan-900 border-cyan-300",
  Return: "bg-rose-50 text-rose-900 border-rose-300",
  Entry: "bg-sky-50 text-sky-900 border-sky-300",
  Exit: "bg-slate-100 text-slate-800 border-slate-300",
  Literal: "bg-slate-100 text-slate-800 border-slate-300",
  AppDirectory: "bg-cyan-50 text-cyan-900 border-cyan-300",
  AppFile: "bg-emerald-50 text-emerald-900 border-emerald-300",
  AppElement: "bg-amber-50 text-amber-900 border-amber-300",
};

function getCategoryStyle(category?: string) {
  switch (category) {
    case "API_ROUTER":
      return {
        border: "border-emerald-500 hover:border-emerald-600",
        badge: "bg-emerald-50 text-emerald-900 border-emerald-300",
        handleDot: "!bg-emerald-600",
        icon: <Server className="w-3.5 h-3.5 text-emerald-700 shrink-0" />,
      };
    case "FRONTEND_VIEW":
      return {
        border: "border-sky-500 hover:border-sky-600",
        badge: "bg-sky-50 text-sky-900 border-sky-300",
        handleDot: "!bg-sky-600",
        icon: <Layout className="w-3.5 h-3.5 text-sky-700 shrink-0" />,
      };
    case "BUSINESS_LOGIC":
      return {
        border: "border-cyan-500 hover:border-cyan-600",
        badge: "bg-cyan-50 text-cyan-900 border-cyan-300",
        handleDot: "!bg-cyan-600",
        icon: <Code2 className="w-3.5 h-3.5 text-cyan-700 shrink-0" />,
      };
    case "INFRASTRUCTURE":
      return {
        border: "border-amber-500 hover:border-amber-600",
        badge: "bg-amber-50 text-amber-900 border-amber-300",
        handleDot: "!bg-amber-600",
        icon: <Terminal className="w-3.5 h-3.5 text-amber-700 shrink-0" />,
      };
    case "DEPENDENCY_MANIFEST":
      return {
        border: "border-rose-500 hover:border-rose-600",
        badge: "bg-rose-50 text-rose-900 border-rose-300",
        handleDot: "!bg-rose-600",
        icon: <Package className="w-3.5 h-3.5 text-rose-700 shrink-0" />,
      };
    case "CONFIGURATION":
    case "BUILD_TOOLING":
      return {
        border: "border-amber-500 hover:border-amber-600",
        badge: "bg-amber-50 text-amber-900 border-amber-300",
        handleDot: "!bg-amber-600",
        icon: <Settings className="w-3.5 h-3.5 text-amber-700 shrink-0" />,
      };
    default:
      return {
        border: "border-slate-300 hover:border-cyan-600",
        badge: "bg-slate-100 text-slate-800 border-slate-300",
        handleDot: "!bg-slate-500",
        icon: <FileCode className="w-3.5 h-3.5 text-cyan-700 shrink-0" />,
      };
  }
}

/**
 * Renders all 4 outer-perimeter source & target handle pairs so every directional
 * edge docks cleanly outside card borders in LR, TB, Mind-Map, and 360° Spider layouts.
 */
function PerimeterHandles({ dotClass = "!bg-cyan-600" }: { dotClass?: string }) {
  const baseCls = `!w-2 !h-2 !border-[1.5px] !border-white ${dotClass}`;
  const hiddenFallbackCls =
    "!w-2 !h-2 !opacity-0 !pointer-events-none !border-0";

  return (
    <>
      {/* Unnamed fallback perimeter handles */}
      <Handle type="target" position={Position.Top} className={hiddenFallbackCls} />
      <Handle type="source" position={Position.Bottom} className={hiddenFallbackCls} />

      {/* Top Perimeter Pair */}
      <Handle id="top-tgt" type="target" position={Position.Top} className={baseCls} />
      <Handle id="top-src" type="source" position={Position.Top} className={baseCls} />

      {/* Right Perimeter Pair */}
      <Handle id="right-tgt" type="target" position={Position.Right} className={baseCls} />
      <Handle id="right-src" type="source" position={Position.Right} className={baseCls} />

      {/* Bottom Perimeter Pair */}
      <Handle id="bottom-tgt" type="target" position={Position.Bottom} className={baseCls} />
      <Handle id="bottom-src" type="source" position={Position.Bottom} className={baseCls} />

      {/* Left Perimeter Pair */}
      <Handle id="left-tgt" type="target" position={Position.Left} className={baseCls} />
      <Handle id="left-src" type="source" position={Position.Left} className={baseCls} />
    </>
  );
}

function getBlastRingClasses(blastRole: NodeBlastRole): string {
  switch (blastRole) {
    case "FOCUSED":
      return "!border-indigo-700 ring-2 ring-indigo-600/45 shadow-[0_8px_24px_rgba(67,56,202,0.18)]";
    case "UPSTREAM":
      return "!border-sky-600 ring-2 ring-sky-500/35 shadow-[0_6px_18px_rgba(3,105,161,0.14)]";
    case "DOWNSTREAM":
      return "!border-rose-600 ring-2 ring-rose-500/35 shadow-[0_6px_18px_rgba(190,18,60,0.14)]";
    case "DIMMED":
      return "opacity-25";
    default:
      return "";
  }
}

function BlastRoleChip({ blastRole }: { blastRole: NodeBlastRole }) {
  if (blastRole === "FOCUSED") {
    return (
      <span className="px-1.5 py-0.5 rounded bg-indigo-700 text-white border border-indigo-800 text-[8.5px] font-mono font-extrabold tracking-wider shrink-0">
        🎯 FOCUS
      </span>
    );
  }
  if (blastRole === "UPSTREAM") {
    return (
      <span className="px-1.5 py-0.5 rounded bg-sky-700 text-white border border-sky-800 text-[8.5px] font-mono font-extrabold tracking-wider shrink-0">
        ⬆ UPSTREAM
      </span>
    );
  }
  if (blastRole === "DOWNSTREAM") {
    return (
      <span className="px-1.5 py-0.5 rounded bg-rose-700 text-white border border-rose-800 text-[8.5px] font-mono font-extrabold tracking-wider shrink-0">
        ⬇ BLAST
      </span>
    );
  }
  return null;
}

export const CustomGraphNode = memo(({ data, id }: NodeProps<any>) => {
  const selectedNodeId = useAuditStore((s) => s.selectedGraphNodeId);
  const selectGraphNode = useAuditStore((s) => s.selectGraphNode);
  const isSelected = selectedNodeId === id;
  const isSpider = Boolean(data.isSpiderMode);
  const blastRole: NodeBlastRole =
    data.blastRole || (data.isDimmed ? "DIMMED" : "NONE");
  const isDimmed = Boolean(data.isDimmed) || blastRole === "DIMMED";
  const isSevered = Boolean(data.isSevered);

  const nodeLabel =
    data.label ||
    (data.path !== undefined ? "AppDirectory" : data.filepath ? "AppFile" : "Node");
  const labelColor =
    LABEL_COLORS[nodeLabel] || "bg-slate-100 text-slate-800 border-slate-300";

  const blastOverrideCls = getBlastRingClasses(blastRole);

  // 1. SPIDER CENTRAL HUB NODE (Workspace Root)
  if (nodeLabel === "SpiderHub") {
    return (
      <div
        onClick={() => {
          selectGraphNode(data);
          data.onSelectInspect?.(data);
          data.onNodeCardClick?.(data);
        }}
        className={`relative w-52 h-52 rounded-full border-2 bg-white flex flex-col items-center justify-center text-center p-4 cursor-pointer transition-all duration-200 select-none ${
          isDimmed ? "opacity-25" : "opacity-100"
        } ${
          isSelected
            ? "border-cyan-700 ring-4 ring-cyan-500/30 shadow-[0_10px_30px_rgba(14,116,144,0.22)]"
            : "border-cyan-600 hover:border-cyan-700 shadow-[0_8px_24px_rgba(15,23,42,0.10)]"
        } ${blastOverrideCls}`}
      >
        <PerimeterHandles dotClass="!bg-cyan-600" />
        <div className="absolute inset-2.5 rounded-full border border-dashed border-cyan-300 pointer-events-none" />
        <div className="w-10 h-10 rounded-full bg-cyan-700 text-white flex items-center justify-center shadow-md mb-1.5">
          <Cpu className="w-5 h-5 text-white" />
        </div>
        <span className="text-[9px] font-mono uppercase tracking-widest text-cyan-800 font-extrabold">
          ARCHITECTURE HUB
        </span>
        <div className="text-xs font-mono font-extrabold text-slate-900 truncate max-w-[165px] mt-0.5">
          {data.name || "Project Root"}
        </div>
        <div className="flex items-center gap-2 mt-2 text-[10px] font-mono text-slate-700 bg-slate-100 px-2.5 py-0.5 rounded-full border border-slate-300">
          <span className="text-emerald-800 font-extrabold">
            {data.totalFiles ?? 0}
          </span>{" "}
          files
          <span className="text-slate-400">•</span>
          <span className="text-cyan-800 font-extrabold">
            {data.totalLines ?? 0}
          </span>{" "}
          LOC
        </div>
        {blastRole !== "NONE" && blastRole !== "DIMMED" && (
          <div className="mt-1">
            <BlastRoleChip blastRole={blastRole} />
          </div>
        )}
      </div>
    );
  }

  // 2. SPIDER SATELLITE ELEMENT / REFERENCE NODE (Functions, Routes, Classes, Deps)
  if (nodeLabel === "AppElement") {
    return (
      <div
        onClick={() => {
          selectGraphNode({
            ...data,
            start_line: data.line_number || data.start_line || 1,
            end_line: data.line_number || data.end_line || 1,
          });
          data.onSelectInspect?.(data);
          data.onNodeCardClick?.(data);
        }}
        className={`relative w-48 rounded-full border-[1.5px] bg-white px-3 py-1.5 transition-all duration-200 cursor-pointer text-left flex items-center justify-between gap-1.5 ${
          isDimmed ? "opacity-25" : "opacity-100"
        } ${
          isSelected
            ? "border-amber-600 ring-2 ring-amber-500/35 shadow-md"
            : "border-amber-400 hover:border-amber-600 shadow-sm"
        } ${blastOverrideCls}`}
        title={`${data.element_type}: ${data.signature || data.name} (Click to jump to L${
          data.line_number || 1
        })`}
      >
        <PerimeterHandles dotClass="!bg-amber-600" />
        <div className="flex items-center gap-1.5 truncate min-w-0">
          <span className="text-[9px] font-mono font-extrabold px-1.5 py-0.2 rounded-full bg-amber-50 text-amber-900 border border-amber-300 shrink-0">
            {(data.element_type || "REF").slice(0, 4)}
          </span>
          <span className="text-[11px] font-mono font-bold text-slate-900 truncate">
            {data.name}
          </span>
        </div>
        <span className="text-[10px] font-mono text-amber-800 font-extrabold shrink-0">
          :L{data.line_number || data.start_line || 1}
        </span>
      </div>
    );
  }

  // 3. APPLICATION DIRECTORY NODE (Spider Web & Hierarchy)
  if (nodeLabel === "AppDirectory" || data.path !== undefined) {
    const isCollapsed = Boolean(data.isCollapsed);
    return (
      <div
        onClick={() => {
          selectGraphNode(data);
          data.onSelectInspect?.(data);
          data.onNodeCardClick?.(data);
        }}
        className={`relative ${
          isSpider ? "w-52 rounded-2xl" : "w-64 rounded-xl"
        } border-[1.5px] bg-white p-2.5 shadow-[0_4px_14px_rgba(15,23,42,0.08)] transition-all duration-200 cursor-pointer text-left ${
          isDimmed ? "opacity-25" : "opacity-100"
        } ${
          isSelected
            ? "border-cyan-700 ring-2 ring-cyan-500/35 shadow-md"
            : "border-cyan-500 hover:border-cyan-700"
        } ${blastOverrideCls}`}
      >
        <PerimeterHandles dotClass="!bg-cyan-600" />
        <div className="flex items-center justify-between gap-1.5 mb-1">
          <div className="flex items-center gap-1.5 truncate">
            {isCollapsed ? (
              <Folder className="w-4 h-4 text-cyan-700 shrink-0" />
            ) : (
              <FolderOpen className="w-4 h-4 text-cyan-700 shrink-0" />
            )}
            <span className="text-[9.5px] font-mono font-extrabold px-1.5 py-0.2 rounded bg-cyan-50 text-cyan-900 border border-cyan-300">
              DIR
            </span>
            <BlastRoleChip blastRole={blastRole} />
          </div>

          <div className="flex items-center gap-1">
            {data.childCount !== undefined && (
              <span className="text-[10px] font-mono font-semibold px-1.5 py-0.2 rounded-full bg-slate-100 text-slate-800 border border-slate-300">
                {data.childCount} items
              </span>
            )}
            {data.onToggleCollapse && data.path && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  data.onToggleCollapse(data.path);
                }}
                title={isCollapsed ? "Expand folder branch" : "Collapse folder branch"}
                className="p-0.5 rounded bg-cyan-50 hover:bg-cyan-100 text-cyan-900 border border-cyan-300 transition-colors"
              >
                {isCollapsed ? (
                  <ChevronRight className="w-3 h-3" />
                ) : (
                  <ChevronDown className="w-3 h-3" />
                )}
              </button>
            )}
          </div>
        </div>

        <div className="text-xs font-mono font-extrabold text-slate-900 truncate mb-1">
          {data.name || data.path || "root"}
        </div>
        <div className="text-[10px] text-slate-700 bg-slate-50 p-1.5 rounded-lg border border-slate-200 line-clamp-2 leading-snug">
          {data.purpose || `Directory: ${data.name || data.path}`}
        </div>
      </div>
    );
  }

  // 4. APPLICATION FILE NODE (Spider Web & Hierarchy)
  if (nodeLabel === "AppFile" || (data.category && data.filename)) {
    const catStyle = getCategoryStyle(data.category);
    const elementsList = data.elements || [];
    const flawCount = data.flawCount || 0;
    const crossEdgeCount = data.crossEdgeCount || 0;

    return (
      <div
        onClick={() => {
          selectGraphNode(data);
          if (data.filepath) {
            useAuditStore.getState().selectTreeFile({
              filepath: data.filepath,
              filename: data.filename || data.filepath,
              extension: data.extension || "",
              category: data.category || "BUSINESS_LOGIC",
              purpose: data.purpose || "",
              language: data.language || "",
              line_count: data.line_count || 1,
              size_bytes: data.size_bytes || 0,
              sha256: data.sha256 || "",
              elements: elementsList,
              is_cpg_supported: data.is_cpg_supported ?? true,
              security_tags: data.security_tags || [],
              imports_files: data.imports_files || [],
            });
          }
          data.onSelectInspect?.(data);
          data.onNodeCardClick?.(data);
        }}
        className={`relative ${
          isSpider ? "w-56 rounded-2xl" : "w-64 rounded-xl"
        } border-[1.5px] bg-white p-2.5 shadow-[0_4px_14px_rgba(15,23,42,0.08)] transition-all duration-200 cursor-pointer text-left ${
          isDimmed ? "opacity-25" : "opacity-100"
        } ${
          isSelected
            ? "border-emerald-700 ring-2 ring-emerald-500/35 shadow-md"
            : catStyle.border
        } ${blastOverrideCls}`}
      >
        <PerimeterHandles
          dotClass={flawCount > 0 ? "!bg-rose-600" : catStyle.handleDot}
        />

        <div className="flex items-center justify-between gap-1 mb-1">
          <div className="flex items-center gap-1.5 truncate">
            {catStyle.icon}
            <span
              className={`text-[9px] font-mono font-extrabold px-1.5 py-0.2 rounded border ${catStyle.badge}`}
            >
              {(data.category || "FILE").replace(/_/g, " ")}
            </span>
            <BlastRoleChip blastRole={blastRole} />
          </div>

          <div className="flex items-center gap-1 shrink-0">
            {flawCount > 0 && (
              <span
                className="flex items-center gap-0.5 px-1.5 py-0.2 rounded-full bg-rose-700 text-white border border-rose-800 text-[9px] font-mono font-extrabold"
                title={`${flawCount} security flaw(s) detected in this file`}
              >
                <Flame className="w-2.5 h-2.5 text-white" />
                {flawCount}
              </span>
            )}
            {data.line_count && (
              <span className="text-[9px] font-mono font-semibold text-slate-700 bg-slate-100 border border-slate-200 px-1 rounded">
                {data.line_count}L
              </span>
            )}
          </div>
        </div>

        <div className="text-xs font-mono font-extrabold text-slate-900 truncate mb-1">
          {data.filename || data.filepath}
        </div>

        <div className="text-[10px] text-slate-700 bg-slate-50 p-1.5 rounded-lg border border-slate-200 line-clamp-2 leading-snug">
          {data.purpose || data.filepath}
        </div>

        {/* Footer: Reference / Cross-File Counter & Expand Satellite Toggle */}
        <div className="mt-1.5 pt-1 border-t border-slate-200 flex items-center justify-between text-[10px] font-mono gap-1">
          <div className="flex items-center gap-1.5 truncate">
            <span className="text-slate-700 flex items-center gap-1">
              <GitBranch className="w-3 h-3 text-amber-700 shrink-0" />
              <span>{elementsList.length} refs</span>
            </span>
            {crossEdgeCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-violet-50 text-violet-900 border border-violet-300 text-[9px] font-extrabold shrink-0">
                {crossEdgeCount} x-file
              </span>
            )}
          </div>

          {data.onToggleElements && elementsList.length > 0 && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                data.onToggleElements(data.filepath);
              }}
              className={`px-1.5 py-0.2 rounded text-[9px] font-extrabold border transition-colors flex items-center gap-0.5 shrink-0 ${
                data.isExpandedElements
                  ? "bg-amber-700 text-white border-amber-800"
                  : "bg-slate-100 text-cyan-900 border-slate-300 hover:border-cyan-600 hover:bg-cyan-50"
              }`}
              title="Toggle satellite reference nodes (functions, classes, routes, dependencies)"
            >
              <Crosshair className="w-2.5 h-2.5" />
              <span>{data.isExpandedElements ? "Hide Refs" : "Show Refs"}</span>
            </button>
          )}
        </div>
      </div>
    );
  }

  // 5. STANDARD CPG & TRUST BOUNDARY NODE RENDERING (AST / CFG / DFG / Call / Boundary)
  const semanticBorderClass = isSevered
    ? "border-emerald-600 ring-2 ring-emerald-500/30"
    : isSelected
    ? "border-indigo-700 ring-2 ring-indigo-500/35"
    : data.is_bfl
    ? "border-amber-600 ring-1 ring-amber-500/30"
    : data.is_sink
    ? "border-rose-600 ring-1 ring-rose-500/25"
    : data.is_source
    ? "border-cyan-600 ring-1 ring-cyan-500/25"
    : data.is_sanitizer
    ? "border-emerald-600 ring-1 ring-emerald-500/25"
    : "border-slate-300 hover:border-slate-500";

  const handleDotClass = isSevered
    ? "!bg-emerald-600"
    : data.is_bfl
    ? "!bg-amber-600"
    : data.is_sink
    ? "!bg-rose-600"
    : data.is_sanitizer
    ? "!bg-emerald-600"
    : "!bg-cyan-600";

  const stepCircle = data.stepNumber ? formatCircledStep(data.stepNumber) : "";

  return (
    <div
      onClick={() => {
        if (data.onNodeCardClick) {
          data.onNodeCardClick(data);
          return;
        }
        selectGraphNode(data);
        data.onSelectInspect?.(data);
      }}
      className={`relative w-64 rounded-xl border-[1.5px] bg-white p-3 shadow-[0_4px_14px_rgba(15,23,42,0.08)] transition-all duration-200 cursor-pointer text-left ${
        isDimmed ? "opacity-25" : "opacity-100"
      } ${semanticBorderClass} ${blastOverrideCls}`}
    >
      <PerimeterHandles dotClass={handleDotClass} />

      {/* Optional Architectural Trust Zone Ribbon */}
      {data.trustZoneLabel && (
        <div
          className={`mb-1.5 px-2 py-0.5 rounded-md text-[9px] font-mono font-extrabold uppercase tracking-wider border flex items-center justify-between ${
            data.trustZoneTone === "CRIMSON"
              ? "bg-rose-50 text-rose-900 border-rose-300"
              : data.trustZoneTone === "EMERALD"
              ? "bg-emerald-50 text-emerald-900 border-emerald-300"
              : data.trustZoneTone === "AMBER"
              ? "bg-amber-50 text-amber-900 border-amber-300"
              : "bg-sky-50 text-sky-900 border-sky-300"
          }`}
        >
          <span>{data.trustZoneLabel}</span>
          {data.trustZoneActionHint && (
            <span className="text-[8.5px] opacity-80">{data.trustZoneActionHint}</span>
          )}
        </div>
      )}

      {/* Header: Step Numeral, Node Label & Semantic Role Badges */}
      <div className="flex items-center justify-between gap-1 mb-1.5">
        <div className="flex items-center gap-1 min-w-0">
          {stepCircle && (
            <span className="text-xs font-mono font-black text-slate-900 shrink-0">
              {stepCircle}
            </span>
          )}
          <span
            className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border truncate ${labelColor}`}
          >
            {data.label}
          </span>
        </div>

        <div className="flex items-center gap-1 flex-wrap justify-end">
          <BlastRoleChip blastRole={blastRole} />
          {isSevered && (
            <span className="text-[9px] font-mono font-extrabold tracking-wider px-1.5 py-0.5 rounded bg-emerald-700 text-white border border-emerald-800 flex items-center gap-0.5">
              <ShieldCheck className="w-2.5 h-2.5 text-white" />
              SEVERED
            </span>
          )}
          {data.is_bfl && (
            <span className="text-[9px] font-mono font-extrabold tracking-wider px-1.5 py-0.5 rounded bg-amber-700 text-white border border-amber-800">
              BFL CHOKEPOINT
            </span>
          )}
          {data.is_source && (
            <span className="text-[9px] font-mono font-extrabold tracking-wider px-1.5 py-0.5 rounded bg-cyan-700 text-white border border-cyan-800">
              SOURCE
            </span>
          )}
          {data.is_sink && (
            <span
              className={`text-[9px] font-mono font-extrabold tracking-wider px-1.5 py-0.5 rounded border ${
                isSevered
                  ? "bg-emerald-50 text-emerald-900 border-emerald-400 line-through"
                  : "bg-rose-700 text-white border-rose-800"
              }`}
            >
              SINK
            </span>
          )}
          {data.is_sanitizer && !isSevered && (
            <span className="text-[9px] font-mono font-extrabold tracking-wider px-1.5 py-0.5 rounded bg-emerald-700 text-white border border-emerald-800">
              SANITIZER
            </span>
          )}
          {data.is_synthesized_context && (
            <span className="text-[8.5px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-300">
              CONTEXT
            </span>
          )}
        </div>
      </div>

      {/* Identifier Name (#0f172a) */}
      <div className="text-xs font-mono font-extrabold text-slate-900 truncate mb-1">
        {data.name}
      </div>

      {/* Code Snippet Pill (#1e293b text on #f1f5f9 pill) */}
      <div className="bg-slate-100 rounded-lg border border-slate-200 px-2 py-1.5 text-[11px] font-mono text-slate-800 overflow-x-hidden line-clamp-2 select-none leading-snug">
        {data.code || "<no snippet>"}
      </div>

      {/* File Location Footer */}
      <div className="mt-2 text-[10px] font-mono text-slate-600 flex items-center justify-between border-t border-slate-200 pt-1">
        <span className="truncate max-w-[175px]" title={data.filepath}>
          {data.filepath || "workspace"}
        </span>
        {data.start_line ? (
          <span className="text-slate-800 font-extrabold">L{data.start_line}</span>
        ) : null}
      </div>
    </div>
  );
});

CustomGraphNode.displayName = "CustomGraphNode";
