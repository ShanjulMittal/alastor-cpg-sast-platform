"use client";

import React, { useMemo, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  FolderGit2,
  RefreshCw,
  Check,
  Copy,
  FolderOpen,
  Clock,
  GitCompare,
  PanelLeftClose,
  PanelLeftOpen,
  Columns,
  Code2,
  Network,
  Sparkles,
} from "lucide-react";

export function ActiveApplicationBanner() {
  const projectPath = useAuditStore((s) => s.projectPath);
  const appTree = useAuditStore((s) => s.appTree);
  const projects = useAuditStore((s) => s.projects);
  const findings = useAuditStore((s) => s.findings);
  const selectedFinding = useAuditStore((s) => s.selectedFinding);
  const activateProject = useAuditStore((s) => s.activateProject);
  const triggerScan = useAuditStore((s) => s.triggerScan);
  const isScanning = useAuditStore((s) => s.isScanning);

  const ideLayoutMode = useAuditStore((s) => s.ideLayoutMode);
  const setIdeLayoutMode = useAuditStore((s) => s.setIdeLayoutMode);
  const isSidebarCollapsed = useAuditStore((s) => s.isSidebarCollapsed);
  const setSidebarCollapsed = useAuditStore((s) => s.setSidebarCollapsed);
  const isDiffEditorOpen = useAuditStore((s) => s.isDiffEditorOpen);
  const setDiffEditorOpen = useAuditStore((s) => s.setDiffEditorOpen);
  const setAiDrawerOpen = useAuditStore((s) => s.setAiDrawerOpen);

  const trackChanges = useAuditStore((s) => s.trackChanges);
  const isTrackChangesMode = useAuditStore((s) => s.isTrackChangesMode);
  const setTrackChangesMode = useAuditStore((s) => s.setTrackChangesMode);
  const isTrackChangesPanelOpen = useAuditStore(
    (s) => s.isTrackChangesPanelOpen
  );
  const setTrackChangesPanelOpen = useAuditStore(
    (s) => s.setTrackChangesPanelOpen
  );
  const uiDensityMode = useAuditStore((s) => s.uiDensityMode);

  const [copiedPath, setCopiedPath] = useState(false);

  const resolvedPath = useMemo(() => {
    if (appTree?.root_path) return appTree.root_path;
    if (projectPath) return projectPath;
    const activeProj = projects.find((p) => p.is_active) || projects[0];
    return activeProj?.target_path || "";
  }, [appTree, projectPath, projects]);

  const activeProjectObj = useMemo(() => {
    const normResolved = resolvedPath.replace(/\\/g, "/").toLowerCase();
    return (
      projects.find((p) => p.is_active) ||
      projects.find(
        (p) => p.target_path.replace(/\\/g, "/").toLowerCase() === normResolved
      ) ||
      null
    );
  }, [projects, resolvedPath]);

  const applicationName = useMemo(() => {
    if (resolvedPath) {
      const cleaned = resolvedPath.replace(/[\\/]+$/, "");
      const parts = cleaned.split(/[\\/]/);
      const folderName = parts[parts.length - 1];
      if (folderName && folderName !== ".") {
        return folderName;
      }
    }
    if (activeProjectObj?.name) {
      return activeProjectObj.name;
    }
    return "cpg-sast-platform";
  }, [resolvedPath, activeProjectObj]);

  const lastScannedAt =
    trackChanges?.last_scanned_at || activeProjectObj?.last_scan_at || null;
  const scanCount =
    trackChanges?.scan_count ||
    activeProjectObj?.scan_count ||
    (lastScannedAt ? 1 : 0);

  const fixedCount =
    trackChanges?.fixed_count ?? activeProjectObj?.fixed_since_last_scan ?? 0;
  const newCount =
    trackChanges?.new_count ??
    activeProjectObj?.new_since_last_scan ??
    findings.filter(
      (f) => f.change_status === "NEW" || f.change_status === "REOPENED"
    ).length;
  const unchangedCount =
    trackChanges?.unchanged_count ??
    activeProjectObj?.unchanged_since_last_scan ??
    findings.filter((f) => f.change_status === "UNCHANGED").length;

  const handleCopyPath = () => {
    if (!resolvedPath) return;
    navigator.clipboard?.writeText(resolvedPath);
    setCopiedPath(true);
    setTimeout(() => setCopiedPath(false), 1800);
  };

  const handleProjectDropdownChange = async (projectId: string) => {
    if (!projectId) return;
    await activateProject(projectId, false);
  };

  return (
    <div className="relative z-20 bg-[var(--surface-panel)] border-b border-[var(--border-hairline)] text-[var(--ink-primary)] shrink-0">
      <div className="px-3 py-1.5 flex items-center justify-between gap-2 flex-wrap">
        {/* Left: Sidebar Toggle + Active Application + Last Scanned */}
        <div className="flex items-center gap-2 flex-wrap min-w-0">
          <button
            type="button"
            onClick={() => setSidebarCollapsed(!isSidebarCollapsed)}
            title={
              isSidebarCollapsed
                ? "Expand Flaw Explorer Sidebar (Shortcut: b)"
                : "Collapse Flaw Explorer Sidebar (Shortcut: b)"
            }
            className="h-7 px-2 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-primary)] text-[11px] font-semibold flex items-center gap-1.5 transition-colors"
          >
            {isSidebarCollapsed ? (
              <PanelLeftOpen className="w-3.5 h-3.5 text-sky-700" />
            ) : (
              <PanelLeftClose className="w-3.5 h-3.5 text-sky-700" />
            )}
            <span className="hidden sm:inline">
              {isSidebarCollapsed ? "Show Explorer" : "Explorer"}
            </span>
          </button>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[var(--surface-elevated)] border border-sky-300">
            <FolderGit2 className="w-3.5 h-3.5 text-sky-700 shrink-0" />
            <span className="text-[11px] font-medium text-[var(--ink-muted)] hidden md:inline">
              Target:
            </span>
            <span className="text-xs font-bold text-[var(--ink-primary)] tracking-tight truncate max-w-[160px]">
              {applicationName}
            </span>
            {projects.length > 1 && (
              <select
                value={activeProjectObj?.id || ""}
                onChange={(e) => handleProjectDropdownChange(e.target.value)}
                disabled={isScanning}
                title="Switch active application using saved scan snapshot"
                className="ml-1 bg-white border border-slate-300 hover:border-sky-500 rounded-md px-1.5 py-0.5 text-[10px] font-mono font-semibold text-sky-800 focus:outline-none cursor-pointer max-w-[160px]"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    Switch: {p.name}
                  </option>
                ))}
              </select>
            )}
          </div>

          {uiDensityMode === "PRO_DETAILED" && resolvedPath && (
            <div
              className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-200 text-[10px] font-mono text-slate-700 max-w-xs truncate"
              title={`Active Workspace Path on Disk: ${resolvedPath}`}
            >
              <FolderOpen className="w-3 h-3 text-amber-700 shrink-0" />
              <span className="truncate">{resolvedPath}</span>
              <button
                type="button"
                onClick={handleCopyPath}
                title="Copy full application folder path"
                className="p-0.5 rounded hover:bg-slate-200 text-slate-600 hover:text-slate-900 transition-colors shrink-0"
              >
                {copiedPath ? (
                  <Check className="w-3 h-3 text-emerald-700" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
              </button>
            </div>
          )}

          <button
            type="button"
            onClick={() => setTrackChangesPanelOpen(!isTrackChangesPanelOpen)}
            title="Inspect saved scan snapshot & Track Changes comparison"
            className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white hover:bg-slate-50 border border-[var(--border-hairline)] text-[11px] transition-colors"
          >
            <Clock className="w-3.5 h-3.5 text-amber-700 shrink-0" />
            {lastScannedAt ? (
              <span className="text-slate-800 font-mono font-semibold text-[10px]">
                Scan #{scanCount} • {lastScannedAt}
              </span>
            ) : (
              <span className="text-slate-500 italic text-[10px]">
                Snapshot Ready
              </span>
            )}
          </button>
        </div>

        {/* Right: Split · Code · Graph Layout Switcher + Preview Diff + Track Changes + Re-Scan */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {/* Segmented Split · Code · Graph Layout Switch */}
          <div
            role="group"
            aria-label="Triage & Fix Layout"
            className="flex items-center bg-slate-100 border border-slate-300 rounded-lg p-0.5 text-[11px] font-semibold"
          >
            {(
              [
                {
                  id: "SPLIT_BOTH",
                  label: "Split",
                  keyHint: "2",
                  icon: <Columns className="w-3 h-3" />,
                },
                {
                  id: "CODE_FOCUS",
                  label: "Code",
                  keyHint: "1",
                  icon: <Code2 className="w-3 h-3" />,
                },
                {
                  id: "GRAPH_FOCUS",
                  label: "Graph",
                  keyHint: "3",
                  icon: <Network className="w-3 h-3" />,
                },
              ] as const
            ).map((mode) => {
              const active = ideLayoutMode === mode.id;
              return (
                <button
                  key={mode.id}
                  type="button"
                  onClick={() => setIdeLayoutMode(mode.id)}
                  title={`Switch to ${mode.label} layout (Shortcut: ${mode.keyHint})`}
                  className={`px-2 py-0.5 rounded-md flex items-center gap-1 transition-colors ${
                    active
                      ? "bg-sky-700 text-white font-bold shadow-sm"
                      : "text-slate-700 hover:text-slate-950"
                  }`}
                >
                  {mode.icon}
                  <span>{mode.label}</span>
                </button>
              );
            })}
          </div>

          {/* Quick BFL Diff Preview Toggle when a finding is active */}
          {selectedFinding && (
            <button
              type="button"
              onClick={() => setDiffEditorOpen(!isDiffEditorOpen)}
              title="Toggle live Monaco Chokepoint BFL DiffEditor (Shortcut: d)"
              className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono font-bold flex items-center gap-1 transition-colors ${
                isDiffEditorOpen
                  ? "bg-amber-700 text-white border-amber-800"
                  : "bg-amber-50 hover:bg-amber-100 border-amber-300 text-amber-900"
              }`}
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>{isDiffEditorOpen ? "Exit Diff" : "Preview Diff (d)"}</span>
            </button>
          )}

          {/* Quick AI Patch Helper when a finding is active */}
          {selectedFinding && (
            <button
              type="button"
              onClick={() => setAiDrawerOpen(true, "PATCH")}
              title="Synthesize or inspect AI surgical patch for selected finding"
              className="hidden md:flex px-2.5 py-1 rounded-lg bg-indigo-50 hover:bg-indigo-100 border border-indigo-300 text-indigo-900 text-[11px] font-bold items-center gap-1 transition-colors"
            >
              <Sparkles className="w-3 h-3 text-indigo-700" />
              <span>AI Patch</span>
            </button>
          )}

          {/* Compact Track Changes Delta Pill */}
          <div className="hidden xl:flex items-center gap-1 px-2 py-0.5 rounded-lg bg-slate-50 border border-slate-200 text-[10px] font-mono">
            <button
              type="button"
              onClick={() => setTrackChangesMode(!isTrackChangesMode)}
              title="Toggle Continuous Track Changes Mode"
              className={`flex items-center gap-1 font-bold ${
                isTrackChangesMode ? "text-indigo-800" : "text-slate-500"
              }`}
            >
              <GitCompare className="w-3 h-3 text-indigo-700" />
              <span>Δ:</span>
            </button>
            {isTrackChangesMode ? (
              <button
                type="button"
                onClick={() => setTrackChangesPanelOpen(!isTrackChangesPanelOpen)}
                className="flex items-center gap-1.5 hover:underline"
              >
                <span className="text-emerald-800 font-bold">
                  +{fixedCount} Fixed
                </span>
                <span className="text-slate-400">·</span>
                <span className="text-amber-800 font-bold">+{newCount} New</span>
                <span className="text-slate-500">· {unchangedCount} Same</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setTrackChangesMode(true)}
                className="text-indigo-800 underline font-semibold"
              >
                Enable
              </button>
            )}
          </div>

          {/* Explicit Re-Scan Button */}
          <button
            type="button"
            disabled={isScanning}
            onClick={() => triggerScan(resolvedPath)}
            title={`Run a fresh scan on ${applicationName} and compare changes against the last scan`}
            className="px-2.5 py-1 rounded-lg bg-sky-700 hover:bg-sky-800 text-white text-[11px] font-bold flex items-center gap-1 transition-colors disabled:opacity-50 shadow-sm"
          >
            <RefreshCw
              className={`w-3 h-3 ${isScanning ? "animate-spin" : ""}`}
            />
            <span>{isScanning ? "Scanning..." : "Re-Scan"}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
