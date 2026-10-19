"use client";

import React, { useMemo, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { Finding } from "@/types/cpg";
import {
  FolderGit2,
  ShieldCheck,
  ShieldAlert,
  Layers,
  Code2,
  RefreshCw,
  Check,
  Copy,
  ChevronRight,
  FolderOpen,
  Clock,
  GitCompare,
  CheckCircle2,
  Sparkles,
  History,
  Eye,
  X,
  ArrowUpRight,
} from "lucide-react";

export function ActiveApplicationBanner() {
  const projectPath = useAuditStore((s) => s.projectPath);
  const appTree = useAuditStore((s) => s.appTree);
  const projects = useAuditStore((s) => s.projects);
  const findings = useAuditStore((s) => s.findings);
  const metrics = useAuditStore((s) => s.metrics);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);
  const activateProject = useAuditStore((s) => s.activateProject);
  const triggerScan = useAuditStore((s) => s.triggerScan);
  const isScanning = useAuditStore((s) => s.isScanning);
  const selectFinding = useAuditStore((s) => s.selectFinding);

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
  const [activeDeltaTab, setActiveDeltaTab] = useState<
    "FIXED" | "NEW" | "UNCHANGED" | "HISTORY"
  >("FIXED");

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

  const techStackList = useMemo(() => {
    if (appTree?.detected_tech_stack && appTree.detected_tech_stack.length > 0) {
      return appTree.detected_tech_stack.slice(0, 4).join(" • ");
    }
    if (activeProjectObj?.languages && activeProjectObj.languages.length > 0) {
      return activeProjectObj.languages.slice(0, 4).join(" • ");
    }
    return "Python • TypeScript/React";
  }, [appTree, activeProjectObj]);

  // Last Scanned & Track Changes Telemetry
  const lastScannedAt =
    trackChanges?.last_scanned_at || activeProjectObj?.last_scan_at || null;
  const previousScannedAt =
    trackChanges?.previous_scanned_at ||
    activeProjectObj?.previous_scan_at ||
    null;
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

  // Switch project using SAVED SCAN DETAILS by default (no forced re-scan!)
  const handleProjectDropdownChange = async (projectId: string) => {
    if (!projectId) return;
    await activateProject(projectId, false);
  };

  const handleOpenDeltaTab = (
    tab: "FIXED" | "NEW" | "UNCHANGED" | "HISTORY"
  ) => {
    setActiveDeltaTab(tab);
    setTrackChangesPanelOpen(true);
  };

  const handleInspectFindingInIde = (finding: Finding) => {
    selectFinding(finding);
    setWorkspaceViewMode("REMEDIATION_IDE");
    setTrackChangesPanelOpen(false);
  };

  return (
    <div className="relative z-20 bg-zinc-900/90 border-b border-zinc-800 text-zinc-100">
      {/* Streamlined Persistent Application & Track Changes Context Bar */}
      <div className="px-4 py-1.5 flex items-center justify-between gap-3 flex-wrap">
        {/* Left: Application Under Review + Quick Switcher + Last Scanned Timestamp */}
        <div className="flex items-center gap-2.5 flex-wrap min-w-0">
          <div className="flex items-center gap-2 px-3 py-1 rounded-xl bg-zinc-950 border border-cyan-500/50">
            <FolderGit2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="text-[11px] font-medium text-zinc-400">
              Active App:
            </span>
            <span className="text-xs font-bold text-white tracking-tight">
              {applicationName}
            </span>
            {projects.length > 1 && (
              <select
                value={activeProjectObj?.id || ""}
                onChange={(e) => handleProjectDropdownChange(e.target.value)}
                disabled={isScanning}
                title="Switch active application and view its saved scan snapshot immediately without re-scanning"
                className="ml-1 bg-zinc-900 border border-zinc-700 hover:border-cyan-500 rounded-lg px-2 py-0.5 text-[11px] font-medium text-cyan-300 focus:outline-none cursor-pointer max-w-[200px]"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    Switch: {p.name}
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Full Disk Path Pill (Visible in Pro View or inside Saved Details Drawer) */}
          {uiDensityMode === "PRO_DETAILED" && (
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-zinc-950/80 border border-zinc-800 text-[11px] font-mono text-zinc-300 max-w-md truncate"
              title={`Active Workspace Path on Disk: ${resolvedPath}`}
            >
              <FolderOpen className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span className="text-zinc-100 truncate">
                {resolvedPath || "Loading workspace..."}
              </span>
              <button
                type="button"
                onClick={handleCopyPath}
                title="Copy full application folder path"
                className="p-0.5 rounded hover:bg-zinc-800 text-zinc-400 hover:text-cyan-300 transition-colors shrink-0"
              >
                {copiedPath ? (
                  <Check className="w-3 h-3 text-emerald-400" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
              </button>
            </div>
          )}

          {/* Last Scanned Timestamp Badge */}
          <button
            type="button"
            onClick={() => setTrackChangesPanelOpen(!isTrackChangesPanelOpen)}
            title="Click to view saved scan snapshot details & Track Changes comparison without re-scanning"
            className="flex items-center gap-1.5 px-3 py-1 rounded-xl bg-zinc-950/90 hover:bg-zinc-900 border border-zinc-800 hover:border-amber-500/50 text-xs transition-colors cursor-pointer"
          >
            <Clock className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            <span className="text-zinc-400 text-[11px]">Last Scanned:</span>
            {lastScannedAt ? (
              <span className="text-amber-300 font-semibold text-[11px]">
                {lastScannedAt} (Scan #{scanCount})
              </span>
            ) : (
              <span className="text-zinc-400 italic text-[11px]">Not Scanned Yet</span>
            )}
          </button>
        </div>

        {/* Right: Track Changes Summary + View Saved Details + Re-Scan */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Continuous Track Changes Summary Pill */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-zinc-950 border border-zinc-800 text-[11px]">
            <button
              type="button"
              onClick={() => setTrackChangesMode(!isTrackChangesMode)}
              title="Toggle Continuous Track Changes Mode across all review pages"
              className={`flex items-center gap-1 font-semibold transition-colors ${
                isTrackChangesMode ? "text-indigo-300" : "text-zinc-500"
              }`}
            >
              <GitCompare className="w-3.5 h-3.5 text-indigo-400" />
              <span>Track Changes:</span>
            </button>

            {isTrackChangesMode ? (
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => handleOpenDeltaTab("FIXED")}
                  className="px-2 py-0.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900/80 border border-emerald-700/50 text-emerald-300 font-semibold transition-colors"
                >
                  ✅ {fixedCount} Fixed
                </button>
                <button
                  type="button"
                  onClick={() => handleOpenDeltaTab("NEW")}
                  className="px-2 py-0.5 rounded-lg bg-amber-950/80 hover:bg-amber-900/80 border border-amber-700/50 text-amber-300 font-semibold transition-colors"
                >
                  🆕 {newCount} New
                </button>
                <button
                  type="button"
                  onClick={() => handleOpenDeltaTab("UNCHANGED")}
                  className="px-2 py-0.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-300 font-medium transition-colors"
                >
                  ⏳ {unchangedCount} Unchanged
                </button>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => setTrackChangesMode(true)}
                className="text-zinc-400 hover:text-indigo-300 underline"
              >
                Enable
              </button>
            )}
          </div>

          {/* View Saved Scan Details Button (No Re-Scan Required) */}
          <button
            type="button"
            onClick={() => setTrackChangesPanelOpen(!isTrackChangesPanelOpen)}
            title="Inspect saved scan snapshot, full path, timestamp, and fixed/new finding changes without running a new scan"
            className={`px-3 py-1 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              isTrackChangesPanelOpen
                ? "bg-amber-500 text-zinc-950 border-amber-400"
                : "bg-zinc-950 hover:bg-zinc-900 border-zinc-700 text-amber-300"
            }`}
          >
            <Eye className="w-3.5 h-3.5" />
            <span>
              {isTrackChangesPanelOpen ? "Hide Scan Details" : "Saved Scan Details"}
            </span>
          </button>

          {/* Explicit Re-Scan Button */}
          <button
            type="button"
            disabled={isScanning}
            onClick={() => triggerScan(resolvedPath)}
            title={`Run a fresh scan on ${applicationName} and compare changes against the last scan`}
            className="px-3 py-1 rounded-xl bg-cyan-950/90 hover:bg-cyan-900 border border-cyan-600/60 text-xs font-semibold text-cyan-200 flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 text-cyan-400 ${
                isScanning ? "animate-spin" : ""
              }`}
            />
            <span>{isScanning ? "Re-Scanning..." : "Re-Scan"}</span>
          </button>
        </div>
      </div>

      {/* Expandable Saved Scan Details & Continuous Track Changes Inspector Drawer */}
      {isTrackChangesPanelOpen && (
        <div className="px-4 py-3 bg-zinc-950/95 border-t border-cyan-800/60 text-xs animate-in fade-in duration-150">
          <div className="max-w-7xl mx-auto space-y-3">
            {/* Top Summary Header of Saved Scan Snapshot */}
            <div className="flex items-center justify-between gap-4 flex-wrap pb-2.5 border-b border-zinc-800">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="px-2.5 py-1 rounded-md bg-amber-500/15 border border-amber-500/40 text-amber-300 font-mono text-[11px] font-bold flex items-center gap-1.5">
                  <History className="w-3.5 h-3.5 text-amber-400" />
                  SAVED SCAN SNAPSHOT & CONTINUOUS TRACK CHANGES
                </span>
                <span className="text-zinc-300 font-mono text-[11px]">
                  Application:{" "}
                  <strong className="text-white">{applicationName}</strong>
                </span>
                <span className="text-zinc-600">•</span>
                <span className="text-zinc-300 font-mono text-[11px]">
                  Last Scanned:{" "}
                  <strong className="text-amber-300">
                    {lastScannedAt || "Never"}
                  </strong>{" "}
                  (Scan #{scanCount})
                </span>
                {previousScannedAt && (
                  <>
                    <span className="text-zinc-600">•</span>
                    <span className="text-zinc-400 font-mono text-[11px]">
                      Compared Against Baseline:{" "}
                      <strong className="text-zinc-200">
                        {previousScannedAt}
                      </strong>
                    </span>
                  </>
                )}
                <span className="text-zinc-600">•</span>
                <span className="text-zinc-400 font-mono text-[11px]">
                  Scope:{" "}
                  <strong className="text-cyan-300">
                    {appTree?.total_files ?? 0} files
                  </strong>{" "}
                  ({metrics?.total_nodes ?? 0} CPG nodes / {techStackList})
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isScanning}
                  onClick={() => triggerScan(resolvedPath)}
                  className="px-3 py-1 rounded-md bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-mono text-[11px] font-bold flex items-center gap-1.5 transition-colors disabled:opacity-50"
                >
                  <RefreshCw
                    className={`w-3.5 h-3.5 ${isScanning ? "animate-spin" : ""}`}
                  />
                  <span>Re-Scan Now & Refresh Delta</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTrackChangesPanelOpen(false)}
                  className="p-1 rounded-md bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-400 hover:text-white"
                  title="Close Saved Scan & Track Changes Inspector"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Track Changes Delta Tabs */}
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  type="button"
                  onClick={() => setActiveDeltaTab("FIXED")}
                  className={`px-3 py-1.5 rounded-lg font-mono text-xs font-bold flex items-center gap-1.5 border transition-colors ${
                    activeDeltaTab === "FIXED"
                      ? "bg-emerald-950/90 border-emerald-500 text-emerald-200"
                      : "bg-zinc-900/80 border-zinc-800 text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>✅ Old Issues Fixed ({fixedCount})</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveDeltaTab("NEW")}
                  className={`px-3 py-1.5 rounded-lg font-mono text-xs font-bold flex items-center gap-1.5 border transition-colors ${
                    activeDeltaTab === "NEW"
                      ? "bg-amber-950/90 border-amber-500 text-amber-200"
                      : "bg-zinc-900/80 border-zinc-800 text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                  <span>🆕 New Issues Came ({newCount})</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveDeltaTab("UNCHANGED")}
                  className={`px-3 py-1.5 rounded-lg font-mono text-xs font-bold flex items-center gap-1.5 border transition-colors ${
                    activeDeltaTab === "UNCHANGED"
                      ? "bg-indigo-950/90 border-indigo-500 text-indigo-200"
                      : "bg-zinc-900/80 border-zinc-800 text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Layers className="w-3.5 h-3.5 text-indigo-400" />
                  <span>⏳ Unchanged Active Issues ({unchangedCount})</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveDeltaTab("HISTORY")}
                  className={`px-3 py-1.5 rounded-lg font-mono text-xs font-bold flex items-center gap-1.5 border transition-colors ${
                    activeDeltaTab === "HISTORY"
                      ? "bg-cyan-950/90 border-cyan-500 text-cyan-200"
                      : "bg-zinc-900/80 border-zinc-800 text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Clock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>
                    🕒 Saved Scan History (
                    {trackChanges?.scan_history?.length ?? 0})
                  </span>
                </button>
              </div>

              <div className="text-[11px] font-mono text-zinc-400">
                Viewing cached scan snapshot —{" "}
                <strong className="text-emerald-300">
                  no re-scan required
                </strong>{" "}
                when switching tabs or projects.
              </div>
            </div>

            {/* Tab Content Area */}
            <div className="max-h-56 overflow-y-auto pr-1 space-y-1.5">
              {activeDeltaTab === "FIXED" && (
                <>
                  {(trackChanges?.fixed_findings?.length ?? 0) === 0 ? (
                    <div className="p-3 rounded-lg bg-zinc-900/70 border border-zinc-800 text-zinc-400 font-mono text-xs flex items-center justify-between">
                      <span>
                        {findings.length === 0
                          ? `✅ All previous vulnerabilities in ${applicationName} have been remediated and verified clean (0 active findings remaining).`
                          : "No previously recorded vulnerabilities have transitioned to FIXED yet. Remediate a finding or mark it RESOLVED, then click Re-Scan & Track Changes."}
                      </span>
                    </div>
                  ) : (
                    trackChanges!.fixed_findings.map((f) => {
                      const fp = f.path_nodes?.[0]?.filepath || "source";
                      const ln = f.path_nodes?.[0]?.start_line || 1;
                      return (
                        <div
                          key={f.id}
                          className="p-2.5 rounded-lg bg-emerald-950/25 border border-emerald-700/50 space-y-1.5"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-2.5 min-w-0 flex-wrap">
                              <span className="px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/50 text-emerald-300 font-mono text-[10px] font-bold shrink-0">
                                ✅ FIXED
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 font-mono text-[10px] shrink-0">
                                {f.severity} • {f.cwe_id}
                              </span>
                              <span className="font-semibold text-zinc-100">
                                {f.title}
                              </span>
                              <span className="text-zinc-400 font-mono text-[11px]">
                                ({fp}:{ln})
                              </span>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              {f.fixed_at && (
                                <span className="text-[10px] font-mono text-emerald-300">
                                  Fixed at: {f.fixed_at}
                                </span>
                              )}
                              <button
                                type="button"
                                onClick={() => handleInspectFindingInIde(f)}
                                className="px-2 py-1 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-cyan-300 font-mono text-[10px] flex items-center gap-1"
                              >
                                <span>Inspect Code</span>
                                <ArrowUpRight className="w-3 h-3" />
                              </button>
                            </div>
                          </div>
                          {f.description && (
                            <div className="text-[11px] text-zinc-300 leading-relaxed bg-zinc-950/70 border border-zinc-800/80 rounded px-2.5 py-1.5">
                              <span className="text-emerald-300 font-bold">
                                Written Details:{" "}
                              </span>
                              {f.description}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </>
              )}

              {activeDeltaTab === "NEW" && (
                <>
                  {(trackChanges?.new_findings?.length ?? 0) === 0 ? (
                    <div className="p-3 rounded-lg bg-zinc-900/70 border border-zinc-800 text-emerald-300 font-mono text-xs">
                      🎉 Zero new vulnerabilities introduced in the latest scan (
                      {lastScannedAt || "current snapshot"})!
                    </div>
                  ) : (
                    trackChanges!.new_findings.map((f) => {
                      const fp = f.path_nodes?.[0]?.filepath || "source";
                      const ln = f.path_nodes?.[0]?.start_line || 1;
                      return (
                        <div
                          key={f.id}
                          className="p-2.5 rounded-lg bg-amber-950/25 border border-amber-700/50 space-y-1.5"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-2.5 min-w-0 flex-wrap">
                              <span className="px-2 py-0.5 rounded bg-amber-500/20 border border-amber-500/50 text-amber-300 font-mono text-[10px] font-bold shrink-0">
                                🆕 {f.change_status === "REOPENED" ? "REOPENED" : "NEW"}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-rose-300 font-mono text-[10px] font-bold shrink-0">
                                {f.severity} • {f.cwe_id}
                              </span>
                              <span className="font-semibold text-zinc-100">
                                {f.title}
                              </span>
                              <span className="text-zinc-400 font-mono text-[11px]">
                                ({fp}:{ln})
                              </span>
                            </div>
                            <button
                              type="button"
                              onClick={() => handleInspectFindingInIde(f)}
                              className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/50 text-amber-200 font-mono text-[10px] font-bold flex items-center gap-1 shrink-0"
                            >
                              <span>Review in IDE</span>
                              <ArrowUpRight className="w-3 h-3" />
                            </button>
                          </div>
                          {f.description && (
                            <div className="text-[11px] text-zinc-200 leading-relaxed bg-zinc-950/80 border border-amber-900/40 rounded px-2.5 py-1.5">
                              <span className="text-amber-300 font-bold">
                                What Is Wrong:{" "}
                              </span>
                              {f.description}
                            </div>
                          )}
                          {f.remediation && (
                            <div className="text-[11px] text-emerald-200/90 leading-relaxed bg-emerald-950/20 border border-emerald-900/40 rounded px-2.5 py-1.5">
                              <span className="text-emerald-400 font-bold">
                                How to Fix:{" "}
                              </span>
                              {f.remediation}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </>
              )}

              {activeDeltaTab === "UNCHANGED" && (
                <>
                  {(trackChanges?.unchanged_findings?.length ?? 0) === 0 ? (
                    <div className="p-3 rounded-lg bg-zinc-900/70 border border-zinc-800 text-zinc-400 font-mono text-xs">
                      Zero unchanged carry-over findings in {applicationName}.
                    </div>
                  ) : (
                    trackChanges!.unchanged_findings.map((f) => {
                      const fp = f.path_nodes?.[0]?.filepath || "source";
                      const ln = f.path_nodes?.[0]?.start_line || 1;
                      return (
                        <div
                          key={f.id}
                          className="p-2.5 rounded-lg bg-zinc-900/80 border border-zinc-800 space-y-1.5"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-2.5 min-w-0 flex-wrap">
                              <span className="px-2 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-300 font-mono text-[10px] font-bold shrink-0">
                                ⏳ UNCHANGED
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-amber-300 font-mono text-[10px] shrink-0">
                                {f.severity} • {f.cwe_id}
                              </span>
                              <span className="font-semibold text-zinc-100">
                                {f.title}
                              </span>
                              <span className="text-zinc-400 font-mono text-[11px]">
                                ({fp}:{ln})
                              </span>
                            </div>
                            <button
                              type="button"
                              onClick={() => handleInspectFindingInIde(f)}
                              className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-cyan-300 font-mono text-[10px] flex items-center gap-1 shrink-0"
                            >
                              <span>Review in IDE</span>
                              <ArrowUpRight className="w-3 h-3" />
                            </button>
                          </div>
                          {f.description && (
                            <div className="text-[11px] text-zinc-200 leading-relaxed bg-zinc-950/80 border border-zinc-800 rounded px-2.5 py-1.5">
                              <span className="text-amber-300 font-bold">
                                What Is Wrong:{" "}
                              </span>
                              {f.description}
                            </div>
                          )}
                          {f.remediation && (
                            <div className="text-[11px] text-emerald-200/90 leading-relaxed bg-emerald-950/20 border border-emerald-900/40 rounded px-2.5 py-1.5">
                              <span className="text-emerald-400 font-bold">
                                How to Fix:{" "}
                              </span>
                              {f.remediation}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </>
              )}

              {activeDeltaTab === "HISTORY" && (
                <>
                  {(trackChanges?.scan_history?.length ?? 0) === 0 ? (
                    <div className="p-3 rounded-lg bg-zinc-900/70 border border-zinc-800 text-zinc-400 font-mono text-xs">
                      No scan snapshots recorded yet for {applicationName}.
                    </div>
                  ) : (
                    trackChanges!.scan_history.map((snap) => (
                      <div
                        key={snap.scan_id}
                        className="p-2.5 rounded-lg bg-zinc-900/85 border border-zinc-800 flex items-center justify-between gap-3 flex-wrap font-mono text-[11px]"
                      >
                        <div className="flex items-center gap-2.5">
                          <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-700/70 text-cyan-300 font-bold">
                            Scan #{snap.scan_number}
                          </span>
                          <span className="text-amber-300 font-bold">
                            {snap.scanned_at}
                          </span>
                          <span className="text-zinc-400">
                            • {snap.files_scanned} files ({snap.nodes_created} CPG
                            nodes)
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-zinc-200">
                            Total Active: <strong>{snap.total_findings}</strong>
                          </span>
                          <span className="px-2 py-0.5 rounded bg-emerald-950/70 border border-emerald-700/60 text-emerald-300">
                            ✅ {snap.fixed_count} Fixed
                          </span>
                          <span className="px-2 py-0.5 rounded bg-amber-950/70 border border-amber-700/60 text-amber-300">
                            🆕 {snap.new_count} New
                          </span>
                          <span className="px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-zinc-400">
                            ⏳ {snap.unchanged_count} Unchanged
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
