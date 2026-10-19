"use client";

import React, { memo } from "react";
import { Handle, Position, NodeProps } from "reactflow";
import { useAuditStore } from "@/store/useAuditStore";
import {
  Folder,
  FolderOpen,
  FileCode,
  Layers,
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
} from "lucide-react";

const LABEL_COLORS: Record<string, string> = {
  Function: "bg-purple-900/50 text-purple-300 border-purple-700/60",
  Call: "bg-blue-900/50 text-blue-300 border-blue-700/60",
  Variable: "bg-emerald-900/50 text-emerald-300 border-emerald-700/60",
  Assignment: "bg-amber-900/50 text-amber-300 border-amber-700/60",
  LoopBlock: "bg-pink-900/50 text-pink-300 border-pink-700/60",
  ControlBlock: "bg-indigo-900/50 text-indigo-300 border-indigo-700/60",
  Return: "bg-rose-900/50 text-rose-300 border-rose-700/60",
  Entry: "bg-teal-900/50 text-teal-300 border-teal-700/60",
  Exit: "bg-slate-800 text-slate-300 border-slate-700",
  Literal: "bg-zinc-800 text-zinc-300 border-zinc-700",
  AppDirectory: "bg-cyan-950 text-cyan-300 border-cyan-800",
  AppFile: "bg-emerald-950 text-emerald-300 border-emerald-800",
  AppElement: "bg-amber-950 text-amber-300 border-amber-800",
};

function getCategoryStyle(category?: string) {
  switch (category) {
    case "API_ROUTER":
      return {
        border: "border-emerald-500/70 hover:border-emerald-400",
        badge: "bg-emerald-950 text-emerald-300 border-emerald-700",
        glow: "shadow-emerald-950/50",
        icon: <Server className="w-3.5 h-3.5 text-emerald-400 shrink-0" />,
      };
    case "FRONTEND_VIEW":
      return {
        border: "border-purple-500/70 hover:border-purple-400",
        badge: "bg-purple-950 text-purple-300 border-purple-700",
        glow: "shadow-purple-950/50",
        icon: <Layout className="w-3.5 h-3.5 text-purple-400 shrink-0" />,
      };
    case "BUSINESS_LOGIC":
      return {
        border: "border-cyan-500/70 hover:border-cyan-400",
        badge: "bg-cyan-950 text-cyan-300 border-cyan-700",
        glow: "shadow-cyan-950/50",
        icon: <Code2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />,
      };
    case "INFRASTRUCTURE":
      return {
        border: "border-blue-500/70 hover:border-blue-400",
        badge: "bg-blue-950 text-blue-300 border-blue-700",
        glow: "shadow-blue-950/50",
        icon: <Terminal className="w-3.5 h-3.5 text-blue-400 shrink-0" />,
      };
    case "DEPENDENCY_MANIFEST":
      return {
        border: "border-rose-500/70 hover:border-rose-400",
        badge: "bg-rose-950 text-rose-300 border-rose-700",
        glow: "shadow-rose-950/50",
        icon: <Package className="w-3.5 h-3.5 text-rose-400 shrink-0" />,
      };
    case "CONFIGURATION":
    case "BUILD_TOOLING":
      return {
        border: "border-amber-500/70 hover:border-amber-400",
        badge: "bg-amber-950 text-amber-300 border-amber-700",
        glow: "shadow-amber-950/50",
        icon: <Settings className="w-3.5 h-3.5 text-amber-400 shrink-0" />,
      };
    default:
      return {
        border: "border-zinc-700 hover:border-cyan-500",
        badge: "bg-zinc-900 text-zinc-300 border-zinc-700",
        glow: "shadow-zinc-950/50",
        icon: <FileCode className="w-3.5 h-3.5 text-cyan-400 shrink-0" />,
      };
  }
}

export const CustomGraphNode = memo(({ data, id }: NodeProps<any>) => {
  const selectedNodeId = useAuditStore((s) => s.selectedGraphNodeId);
  const selectGraphNode = useAuditStore((s) => s.selectGraphNode);
  const isSelected = selectedNodeId === id;
  const isSpider = Boolean(data.isSpiderMode);
  const isDimmed = Boolean(data.isDimmed);

  const nodeLabel =
    data.label ||
    (data.path !== undefined ? "AppDirectory" : data.filepath ? "AppFile" : "Node");
  const labelColor =
    LABEL_COLORS[nodeLabel] || "bg-zinc-900 text-zinc-300 border-zinc-700";

  const centerHandleStyle: React.CSSProperties | undefined = isSpider
    ? {
        top: "50%",
        left: "50%",
        transform: "translate(-50%, -50%)",
        width: 6,
        height: 6,
        opacity: 0,
        pointerEvents: "none",
      }
    : undefined;

  // 1. SPIDER CENTRAL HUB NODE (Workspace Root)
  if (nodeLabel === "SpiderHub") {
    return (
      <div
        onClick={() => {
          selectGraphNode(data);
          data.onSelectInspect?.(data);
        }}
        className={`relative w-52 h-52 rounded-full border-2 flex flex-col items-center justify-center text-center p-4 cursor-pointer transition-all duration-300 select-none ${
          isSelected
            ? "bg-cyan-950/90 border-cyan-300 ring-4 ring-cyan-500/40 shadow-[0_0_45px_rgba(6,182,212,0.7)]"
            : "bg-zinc-950/95 border-cyan-500/80 hover:border-cyan-300 shadow-[0_0_30px_rgba(6,182,212,0.35)]"
        }`}
      >
        <Handle type="target" position={Position.Top} style={centerHandleStyle} />
        {/* Concentric decorative pulse ring */}
        <div className="absolute inset-2 rounded-full border border-dashed border-cyan-500/40 pointer-events-none animate-spin [animation-duration:35s]" />
        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/30 mb-1.5">
          <Cpu className="w-5 h-5 text-white" />
        </div>
        <span className="text-[9px] font-mono uppercase tracking-widest text-cyan-400 font-bold">
          SPIDER CORE HUB
        </span>
        <div className="text-xs font-mono font-bold text-white truncate max-w-[165px] mt-0.5">
          {data.name || "Project Root"}
        </div>
        <div className="flex items-center gap-2 mt-2 text-[10px] font-mono text-zinc-300 bg-zinc-900/90 px-2.5 py-0.5 rounded-full border border-zinc-700">
          <span className="text-emerald-400 font-bold">{data.totalFiles ?? 0}</span> files
          <span className="text-zinc-600">•</span>
          <span className="text-cyan-400 font-bold">{data.totalLines ?? 0}</span> LOC
        </div>
        <Handle type="source" position={Position.Bottom} style={centerHandleStyle} />
      </div>
    );
  }

  // 2. SPIDER SATELLITE ELEMENT / REFERENCE NODE (Functions, Routes, Classes, Deps)
  if (nodeLabel === "AppElement") {
    return (
      <div
        onClick={(e) => {
          e.stopPropagation();
          selectGraphNode({
            ...data,
            start_line: data.line_number || data.start_line || 1,
            end_line: data.line_number || data.end_line || 1,
          });
          data.onSelectInspect?.(data);
        }}
        className={`relative w-48 rounded-full border px-3 py-1.5 backdrop-blur-md transition-all duration-200 cursor-pointer text-left flex items-center justify-between gap-1.5 ${
          isDimmed ? "opacity-25" : "opacity-100"
        } ${
          isSelected
            ? "bg-amber-950/90 border-amber-400 ring-2 ring-amber-400/50 shadow-lg shadow-amber-900/40"
            : "bg-zinc-950/95 border-amber-700/70 hover:border-amber-400 shadow-md"
        }`}
        title={`${data.element_type}: ${data.signature || data.name} (Click to jump to L${data.line_number || 1})`}
      >
        <Handle type="target" position={Position.Top} style={centerHandleStyle} />
        <div className="flex items-center gap-1.5 truncate min-w-0">
          <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 shrink-0">
            {(data.element_type || "REF").slice(0, 4)}
          </span>
          <span className="text-[11px] font-mono font-semibold text-zinc-100 truncate">
            {data.name}
          </span>
        </div>
        <span className="text-[10px] font-mono text-amber-400 font-bold shrink-0">
          :L{data.line_number || data.start_line || 1}
        </span>
        <Handle type="source" position={Position.Bottom} style={centerHandleStyle} />
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
        }}
        className={`relative ${
          isSpider ? "w-52 rounded-2xl" : "w-64 rounded-lg"
        } border bg-zinc-950/95 backdrop-blur-md p-2.5 shadow-xl transition-all duration-200 cursor-pointer text-left ${
          isDimmed ? "opacity-25 scale-95" : "opacity-100"
        } ${
          isSelected
            ? "border-cyan-400 ring-2 ring-cyan-500/50 shadow-[0_0_25px_rgba(6,182,212,0.4)]"
            : "border-cyan-800/80 hover:border-cyan-400 hover:shadow-cyan-950/40"
        }`}
      >
        <Handle
          type="target"
          position={Position.Top}
          style={centerHandleStyle}
          className="!w-2.5 !h-2.5 !bg-cyan-400 !border-2 !border-zinc-900"
        />
        <div className="flex items-center justify-between gap-1.5 mb-1">
          <div className="flex items-center gap-1.5 truncate">
            {isCollapsed ? (
              <Folder className="w-4 h-4 text-cyan-400 shrink-0" />
            ) : (
              <FolderOpen className="w-4 h-4 text-cyan-400 shrink-0" />
            )}
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
              DIR
            </span>
          </div>

          <div className="flex items-center gap-1">
            {data.childCount !== undefined && (
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-zinc-900 text-zinc-300 border border-zinc-700">
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
                className="p-0.5 rounded bg-cyan-950 hover:bg-cyan-800 text-cyan-300 border border-cyan-700 transition-colors"
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

        <div className="text-xs font-mono font-bold text-zinc-100 truncate mb-1">
          {data.name || data.path || "root"}
        </div>
        <div className="text-[10px] text-zinc-400 bg-zinc-900/80 p-1.5 rounded border border-zinc-800/80 line-clamp-2 leading-snug">
          {data.purpose || `Directory: ${data.name || data.path}`}
        </div>
        <Handle
          type="source"
          position={Position.Bottom}
          style={centerHandleStyle}
          className="!w-2.5 !h-2.5 !bg-cyan-400 !border-2 !border-zinc-900"
        />
      </div>
    );
  }

  // 4. APPLICATION FILE NODE (Spider Web & Hierarchy)
  if (nodeLabel === "AppFile" || (data.category && data.filename)) {
    const catStyle = getCategoryStyle(data.category);
    const elementsList = data.elements || [];
    const flawCount = data.flawCount || 0;

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
            });
          }
          data.onSelectInspect?.(data);
        }}
        className={`relative ${
          isSpider ? "w-56 rounded-2xl" : "w-64 rounded-lg"
        } border bg-zinc-950/95 backdrop-blur-md p-2.5 shadow-xl transition-all duration-200 cursor-pointer text-left ${
          isDimmed ? "opacity-25 scale-95" : "opacity-100"
        } ${
          isSelected
            ? "border-emerald-400 ring-2 ring-emerald-500/50 shadow-[0_0_25px_rgba(16,185,129,0.4)]"
            : `${catStyle.border} ${catStyle.glow}`
        }`}
      >
        <Handle
          type="target"
          position={Position.Top}
          style={centerHandleStyle}
          className="!w-2.5 !h-2.5 !bg-emerald-400 !border-2 !border-zinc-900"
        />
        <div className="flex items-center justify-between gap-1 mb-1">
          <div className="flex items-center gap-1.5 truncate">
            {catStyle.icon}
            <span
              className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border ${catStyle.badge}`}
            >
              {(data.category || "FILE").replace("_", " ")}
            </span>
          </div>

          <div className="flex items-center gap-1 shrink-0">
            {flawCount > 0 && (
              <span
                className="flex items-center gap-0.5 px-1.5 py-0.2 rounded-full bg-red-950 text-red-300 border border-red-700 text-[9px] font-mono font-bold animate-pulse"
                title={`${flawCount} security flaw(s) detected in this file`}
              >
                <Flame className="w-2.5 h-2.5 text-red-400" />
                {flawCount}
              </span>
            )}
            {data.line_count && (
              <span className="text-[9px] font-mono text-zinc-400 bg-zinc-900 px-1 rounded">
                {data.line_count}L
              </span>
            )}
          </div>
        </div>

        <div className="text-xs font-mono font-bold text-zinc-100 truncate mb-1">
          {data.filename || data.filepath}
        </div>

        <div className="text-[10px] text-zinc-400 bg-zinc-900/80 p-1.5 rounded border border-zinc-800/80 line-clamp-2 leading-snug">
          {data.purpose || data.filepath}
        </div>

        {/* Footer: Reference / Elements Counter & Expand Satellite Toggle */}
        <div className="mt-1.5 pt-1 border-t border-zinc-800/80 flex items-center justify-between text-[10px] font-mono">
          <span className="text-zinc-400 flex items-center gap-1">
            <GitBranch className="w-3 h-3 text-amber-400" />
            <span>{elementsList.length} refs/symbols</span>
          </span>

          {data.onToggleElements && elementsList.length > 0 && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                data.onToggleElements(data.filepath);
              }}
              className={`px-1.5 py-0.2 rounded text-[9px] font-bold border transition-colors flex items-center gap-0.5 ${
                data.isExpandedElements
                  ? "bg-amber-950 text-amber-300 border-amber-600"
                  : "bg-zinc-900 text-cyan-400 border-zinc-700 hover:border-cyan-500"
              }`}
              title="Toggle satellite reference nodes (functions, classes, routes, dependencies)"
            >
              <Crosshair className="w-2.5 h-2.5" />
              <span>{data.isExpandedElements ? "Hide Refs" : "Show Refs"}</span>
            </button>
          )}
        </div>

        <Handle
          type="source"
          position={Position.Bottom}
          style={centerHandleStyle}
          className="!w-2.5 !h-2.5 !bg-emerald-400 !border-2 !border-zinc-900"
        />
      </div>
    );
  }

  // 5. STANDARD CPG NODE RENDERING (AST / CFG / DFG / Call Graph)
  return (
    <div
      onClick={() => selectGraphNode(data)}
      className={`relative w-64 rounded-lg border bg-zinc-950/90 backdrop-blur-md p-3 shadow-xl transition-all duration-200 cursor-pointer text-left ${
        isSelected
          ? "border-cyan-400 ring-2 ring-cyan-500/50 shadow-cyan-900/40"
          : data.is_bfl
          ? "border-emerald-400 ring-1 ring-emerald-500/40 shadow-emerald-950/40"
          : "border-zinc-800 hover:border-zinc-600 hover:shadow-black"
      }`}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="!w-2.5 !h-2.5 !bg-cyan-400 !border-2 !border-zinc-900"
      />

      {/* Header: Label and Badges */}
      <div className="flex items-center justify-between gap-1 mb-2">
        <span
          className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${labelColor}`}
        >
          {data.label}
        </span>

        <div className="flex items-center gap-1 flex-wrap justify-end">
          {data.is_bfl && (
            <span className="text-[9px] font-bold tracking-wider px-1.5 py-0.5 rounded bg-emerald-600 text-white border border-emerald-400">
              BEST FIX (BFL)
            </span>
          )}
          {data.is_source && (
            <span className="text-[9px] font-bold tracking-wider px-1.5 py-0.5 rounded bg-red-600 text-white animate-pulse">
              SOURCE
            </span>
          )}
          {data.is_sink && (
            <span className="text-[9px] font-bold tracking-wider px-1.5 py-0.5 rounded bg-rose-500 text-white">
              SINK
            </span>
          )}
          {data.is_sanitizer && (
            <span className="text-[9px] font-bold tracking-wider px-1.5 py-0.5 rounded bg-teal-500 text-black">
              SANITIZER
            </span>
          )}
        </div>
      </div>

      {/* Identifier Name */}
      <div className="text-xs font-mono font-bold text-zinc-100 truncate mb-1">
        {data.name}
      </div>

      {/* Code Snippet */}
      <div className="bg-zinc-900/80 rounded border border-zinc-800/80 p-1.5 text-[11px] font-mono text-zinc-300 overflow-x-hidden line-clamp-2 select-none">
        {data.code || "<no snippet>"}
      </div>

      {/* File Location Footer */}
      <div className="mt-2 text-[10px] font-mono text-zinc-500 flex items-center justify-between border-t border-zinc-900 pt-1">
        <span className="truncate max-w-[170px]" title={data.filepath}>
          {data.filepath}
        </span>
        {data.start_line && (
          <span className="text-zinc-400 font-bold">L{data.start_line}</span>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-2.5 !h-2.5 !bg-cyan-400 !border-2 !border-zinc-900"
      />
    </div>
  );
});

CustomGraphNode.displayName = "CustomGraphNode";
