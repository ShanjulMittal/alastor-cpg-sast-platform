"use client";

import React, { useMemo, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { Finding } from "@/types/cpg";
import {
  Database,
  GitCompare,
  Sliders,
  Building2,
  Download,
  RefreshCw,
  Check,
  Copy,
  FolderOpen,
  Clock,
  CheckCircle2,
  Sparkles,
  History,
  Layers,
  X,
  ArrowUpRight,
  Keyboard,
  Cpu,
} from "lucide-react";

export function StudioStatusBar() {
  const projectPath = useAuditStore((s) => s.projectPath);
  const appTree = useAuditStore((s) => s.appTree);
  const projects = useAuditStore((s) => s.projects);
  const findings = useAuditStore((s) => s.findings);
  const metrics = useAuditStore((s) => s.metrics);
  const isScanning = useAuditStore((s) => s.isScanning);
  const setPrimaryStage = useAuditStore((s) => s.setPrimaryStage);
  const setAspmSubSection = useAuditStore((s) => s.setAspmSubSection);
  const setEngineAccessTab = useAuditStore((s) => s.setEngineAccessTab);
  const triggerScan = useAuditStore((s) => s.triggerScan);
  const selectFinding = useAuditStore((s) => s.selectFinding);
  const exportAuditReport = useAuditStore((s) => s.exportAuditReport);
  const platformSettings = useAuditStore((s) => s.platformSettings);
  const userAccountsState = useAuditStore((s) => s.userAccountsState);
  const activeOperator = useAuditStore((s) => s.activeOperator);
  const aiConfig = useAuditStore((s) => s.aiConfig);
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

  const activePresetId =
    platformSettings?.active_preset_id || "preset-optimized";
  const presets = platformSettings?.presets || [];
  const activePreset = presets.find((p) => p.id === activePresetId);

  const accounts = userAccountsState?.accounts || [];
  const users = userAccountsState?.users || [];
  const activeAccount =
    accounts.find((a) => a.id === userAccountsState?.active_account_id) ||
    accounts[0];
  const activeUser =
    users.find((u) => u.id === userAccountsState?.active_user_id) || users[0];

  const aiSavingsPct = aiConfig?.token_telemetry?.overall_savings_pct
    ? Math.round(aiConfig.token_telemetry.overall_savings_pct)
    : null;

  const handleCopyPath = () => {
    if (!resolvedPath) return;
    navigator.clipboard?.writeText(resolvedPath);
    setCopiedPath(true);
    setTimeout(() => setCopiedPath(false), 1800);
  };

  const handleInspectFindingInIde = (finding: Finding) => {
    selectFinding(finding);
    setPrimaryStage("TRIAGE_FIX");
    setTrackChangesPanelOpen(false);
  };

  return (
    <>
      {/* Slide-Up / Modal Track Changes & Saved Scan Delta Inspector Drawer */}
      {isTrackChangesPanelOpen && (
        <div className="fixed inset-x-0 bottom-[26px] z-[140] bg-[var(--surface-panel)] border-t-2 border-amber-500/60 text-[var(--ink-primary)] shadow-2xl px-4 py-3 text-xs">
          <div className="max-w-7xl mx-auto space-y-2.5">
            {/* Top Summary Header of Saved Scan Snapshot */}
            <div className="flex items-center justify-between gap-4 flex-wrap pb-2 border-b border-[var(--border-hairline)]">
              <div className="flex items-center gap-2.5 flex-wrap">
                <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-300 text-amber-900 font-mono text-[10px] font-bold flex items-center gap-1.5">
                  <History className="w-3.5 h-3.5 text-amber-700" />
                  SAVED SCAN SNAPSHOT &amp; CONTINUOUS TRACK CHANGES
                </span>
                <span className="text-[var(--ink-muted)] font-mono text-[11px]">
                  App:{" "}
                  <strong className="text-[var(--ink-primary)]">
                    {applicationName}
                  </strong>
                </span>
                <span className="text-[var(--ink-muted)]">•</span>
                <span className="text-[var(--ink-muted)] font-mono text-[11px]">
                  Last Scanned:{" "}
                  <strong className="text-amber-800">
                    {lastScannedAt || "Never"}
                  </strong>{" "}
                  (Scan #{scanCount})
                </span>
                {previousScannedAt && (
                  <>
                    <span className="text-[var(--ink-muted)]">•</span>
                    <span className="text-[var(--ink-muted)] font-mono text-[11px]">
                      Baseline:{" "}
                      <strong className="text-[var(--ink-primary)]">
                        {previousScannedAt}
                      </strong>
                    </span>
                  </>
                )}
                <span className="text-[var(--ink-muted)]">•</span>
                <span className="text-[var(--ink-muted)] font-mono text-[11px]">
                  Scope:{" "}
                  <strong className="text-sky-800">
                    {appTree?.total_files ?? 0} files
                  </strong>{" "}
                  ({metrics?.total_nodes ?? 0} CPG nodes / {techStackList})
                </span>

                {/* Disk Path Copy Pill */}
                {resolvedPath && (
                  <button
                    type="button"
                    onClick={handleCopyPath}
                    title={`Copy full path: ${resolvedPath}`}
                    className="px-2 py-0.5 rounded bg-[var(--surface-void)] hover:bg-[var(--surface-elevated)] border border-[var(--border-hairline)] font-mono text-[10px] text-[var(--ink-secondary)] hover:text-[var(--ink-primary)] flex items-center gap-1 max-w-[260px] truncate"
                  >
                    <FolderOpen className="w-3 h-3 text-amber-700 shrink-0" />
                    <span className="truncate">{resolvedPath}</span>
                    {copiedPath ? (
                      <Check className="w-3 h-3 text-emerald-700 shrink-0" />
                    ) : (
                      <Copy className="w-3 h-3 shrink-0" />
                    )}
                  </button>
                )}
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setTrackChangesMode(!isTrackChangesMode)}
                  className={`px-2 py-1 rounded border font-mono text-[10px] font-semibold ${
                    isTrackChangesMode
                      ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                      : "bg-[var(--surface-void)] text-[var(--ink-muted)] border-[var(--border-hairline)]"
                  }`}
                >
                  Track Mode: {isTrackChangesMode ? "ON" : "OFF"}
                </button>
                <button
                  type="button"
                  disabled={isScanning}
                  onClick={() => {
                    void triggerScan(resolvedPath);
                  }}
                  className="px-2.5 py-1 rounded bg-sky-700 hover:bg-sky-800 text-white font-mono text-[10px] font-bold flex items-center gap-1.5 transition-colors disabled:opacity-50 shadow-sm"
                >
                  <RefreshCw
                    className={`w-3 h-3 ${isScanning ? "animate-spin" : ""}`}
                  />
                  <span>Re-Scan Now &amp; Refresh Delta</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTrackChangesPanelOpen(false)}
                  className="p-1 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  title="Close Saved Scan & Track Changes Inspector"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Track Changes Delta Tabs */}
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-1.5 flex-wrap">
                <button
                  type="button"
                  onClick={() => setActiveDeltaTab("FIXED")}
                  className={`px-2.5 py-1 rounded-md font-mono text-[11px] font-bold flex items-center gap-1.5 border transition-colors ${
                    activeDeltaTab === "FIXED"
                      ? "bg-emerald-50 border-emerald-400 text-emerald-900"
                      : "bg-[var(--surface-void)] border-[var(--border-hairline)] text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700" />
                  <span>Old Issues Fixed ({fixedCount})</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveDeltaTab("NEW")}
                  className={`px-2.5 py-1 rounded-md font-mono text-[11px] font-bold flex items-center gap-1.5 border transition-colors ${
                    activeDeltaTab === "NEW"
                      ? "bg-amber-50 border-amber-400 text-amber-900"
                      : "bg-[var(--surface-void)] border-[var(--border-hairline)] text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5 text-amber-700" />
                  <span>New Issues Came ({newCount})</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveDeltaTab("UNCHANGED")}
                  className={`px-2.5 py-1 rounded-md font-mono text-[11px] font-bold flex items-center gap-1.5 border transition-colors ${
                    activeDeltaTab === "UNCHANGED"
                      ? "bg-sky-50 border-sky-400 text-sky-900"
                      : "bg-[var(--surface-void)] border-[var(--border-hairline)] text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <Layers className="w-3.5 h-3.5 text-sky-700" />
                  <span>Unchanged Active Issues ({unchangedCount})</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveDeltaTab("HISTORY")}
                  className={`px-2.5 py-1 rounded-md font-mono text-[11px] font-bold flex items-center gap-1.5 border transition-colors ${
                    activeDeltaTab === "HISTORY"
                      ? "bg-sky-50 border-sky-400 text-sky-900"
                      : "bg-[var(--surface-void)] border-[var(--border-hairline)] text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <Clock className="w-3.5 h-3.5 text-sky-700" />
                  <span>
                    Saved Scan History (
                    {trackChanges?.scan_history?.length ?? 0})
                  </span>
                </button>
              </div>

              <div className="text-[10px] font-mono text-[var(--ink-muted)]">
                Viewing cached scan snapshot —{" "}
                <strong className="text-emerald-800">
                  no re-scan required
                </strong>{" "}
                when switching stages or projects.
              </div>
            </div>

            {/* Tab Content Area */}
            <div className="max-h-52 overflow-y-auto pr-1 space-y-1.5">
              {activeDeltaTab === "FIXED" && (
                <>
                  {(trackChanges?.fixed_findings?.length ?? 0) === 0 ? (
                    <div className="p-2.5 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-muted)] font-mono text-xs">
                      {findings.length === 0
                        ? `All previous vulnerabilities in ${applicationName} have been remediated and verified clean (0 active findings remaining).`
                        : "No previously recorded vulnerabilities have transitioned to FIXED yet. Apply a BFL patch or Fix All Safe Issues, then re-scan."}
                    </div>
                  ) : (
                    trackChanges!.fixed_findings.map((f) => {
                      const fp = f.path_nodes?.[0]?.filepath || "source";
                      const ln = f.path_nodes?.[0]?.start_line || 1;
                      return (
                        <div
                          key={f.id}
                          className="p-2 rounded-lg bg-emerald-50/40 border border-emerald-200 space-y-1"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-2 min-w-0 flex-wrap">
                              <span className="px-1.5 py-0.5 rounded bg-emerald-100 border border-emerald-300 text-emerald-900 font-mono text-[10px] font-bold shrink-0">
                                FIXED
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[var(--ink-secondary)] font-mono text-[10px] shrink-0">
                                {f.severity} • {f.cwe_id}
                              </span>
                              <span className="font-semibold text-[var(--ink-primary)]">
                                {f.title}
                              </span>
                              <span className="text-[var(--ink-muted)] font-mono text-[11px]">
                                ({fp}:{ln})
                              </span>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              {f.fixed_at && (
                                <span className="text-[10px] font-mono text-emerald-800 font-semibold">
                                  Fixed: {f.fixed_at}
                                </span>
                              )}
                              <button
                                type="button"
                                onClick={() => handleInspectFindingInIde(f)}
                                className="px-2 py-0.5 rounded bg-[var(--surface-panel)] hover:bg-sky-50 border border-[var(--border-hairline)] text-sky-800 font-mono font-semibold text-[10px] flex items-center gap-1"
                              >
                                <span>Inspect Code</span>
                                <ArrowUpRight className="w-3 h-3" />
                              </button>
                            </div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </>
              )}

              {activeDeltaTab === "NEW" && (
                <>
                  {(trackChanges?.new_findings?.length ?? 0) === 0 ? (
                    <div className="p-2.5 rounded-lg bg-emerald-50/50 border border-emerald-200 text-emerald-900 font-mono text-xs font-medium">
                      Zero new vulnerabilities introduced in the latest scan (
                      {lastScannedAt || "current snapshot"})!
                    </div>
                  ) : (
                    trackChanges!.new_findings.map((f) => {
                      const fp = f.path_nodes?.[0]?.filepath || "source";
                      const ln = f.path_nodes?.[0]?.start_line || 1;
                      return (
                        <div
                          key={f.id}
                          className="p-2 rounded-lg bg-amber-50/40 border border-amber-200 space-y-1"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-2 min-w-0 flex-wrap">
                              <span className="px-1.5 py-0.5 rounded bg-amber-100 border border-amber-300 text-amber-900 font-mono text-[10px] font-bold shrink-0">
                                {f.change_status === "REOPENED"
                                  ? "REOPENED"
                                  : "NEW"}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-rose-50 border border-rose-200 text-rose-800 font-mono text-[10px] font-bold shrink-0">
                                {f.severity} • {f.cwe_id}
                              </span>
                              <span className="font-semibold text-[var(--ink-primary)]">
                                {f.title}
                              </span>
                              <span className="text-[var(--ink-muted)] font-mono text-[11px]">
                                ({fp}:{ln})
                              </span>
                            </div>
                            <button
                              type="button"
                              onClick={() => handleInspectFindingInIde(f)}
                              className="px-2 py-0.5 rounded bg-[var(--surface-panel)] hover:bg-amber-50 border border-amber-300 text-amber-900 font-mono text-[10px] font-bold flex items-center gap-1 shrink-0"
                            >
                              <span>Review in Stage 2</span>
                              <ArrowUpRight className="w-3 h-3" />
                            </button>
                          </div>
                        </div>
                      );
                    })
                  )}
                </>
              )}

              {activeDeltaTab === "UNCHANGED" && (
                <>
                  {(trackChanges?.unchanged_findings?.length ?? 0) === 0 ? (
                    <div className="p-2.5 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-muted)] font-mono text-xs">
                      Zero unchanged carry-over findings in {applicationName}.
                    </div>
                  ) : (
                    trackChanges!.unchanged_findings.map((f) => {
                      const fp = f.path_nodes?.[0]?.filepath || "source";
                      const ln = f.path_nodes?.[0]?.start_line || 1;
                      return (
                        <div
                          key={f.id}
                          className="p-2 rounded-lg bg-[var(--surface-elevated)] border border-[var(--border-hairline)] flex items-center justify-between gap-3"
                        >
                          <div className="flex items-center gap-2 min-w-0 flex-wrap">
                            <span className="px-1.5 py-0.5 rounded bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[var(--ink-secondary)] font-mono text-[10px] font-bold shrink-0">
                              UNCHANGED
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-900 font-mono text-[10px] font-semibold shrink-0">
                              {f.severity} • {f.cwe_id}
                            </span>
                            <span className="font-semibold text-[var(--ink-primary)]">
                              {f.title}
                            </span>
                            <span className="text-[var(--ink-muted)] font-mono text-[11px]">
                              ({fp}:{ln})
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleInspectFindingInIde(f)}
                            className="px-2 py-0.5 rounded bg-[var(--surface-panel)] hover:bg-sky-50 border border-[var(--border-hairline)] text-sky-800 font-mono font-semibold text-[10px] flex items-center gap-1 shrink-0"
                          >
                            <span>Review in Stage 2</span>
                            <ArrowUpRight className="w-3 h-3" />
                          </button>
                        </div>
                      );
                    })
                  )}
                </>
              )}

              {activeDeltaTab === "HISTORY" && (
                <>
                  {(trackChanges?.scan_history?.length ?? 0) === 0 ? (
                    <div className="p-2.5 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-muted)] font-mono text-xs">
                      No scan snapshots recorded yet for {applicationName}.
                    </div>
                  ) : (
                    trackChanges!.scan_history.map((snap) => (
                      <div
                        key={snap.scan_id}
                        className="p-2 rounded-lg bg-[var(--surface-elevated)] border border-[var(--border-hairline)] flex items-center justify-between gap-3 flex-wrap font-mono text-[11px]"
                      >
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-sky-50 border border-sky-300 text-sky-900 font-bold">
                            Scan #{snap.scan_number}
                          </span>
                          <span className="text-amber-800 font-bold">
                            {snap.scanned_at}
                          </span>
                          <span className="text-[var(--ink-muted)]">
                            • {snap.files_scanned} files ({snap.nodes_created}{" "}
                            CPG nodes)
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[var(--ink-primary)]">
                            Active: <strong>{snap.total_findings}</strong>
                          </span>
                          <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 font-semibold">
                            +{snap.fixed_count} Fixed
                          </span>
                          <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-300 text-amber-900 font-semibold">
                            +{snap.new_count} New
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

      {/* 26px Precision Bottom Studio Status Bar */}
      <footer
        aria-label="ALASTOR Studio Telemetry Status Bar"
        className="h-[26px] px-3 bg-[var(--surface-panel)] border-t border-[var(--border-hairline)] text-[var(--ink-primary)] flex items-center justify-between gap-2 text-[10px] font-mono select-none relative z-40 shrink-0 whitespace-nowrap overflow-hidden"
      >
        {/* LEFT CLUSTER: Neo4j CPG Telemetry + Δ Track Changes + Active Rule Profile */}
        <div className="flex items-center gap-2 min-w-0 shrink-0 whitespace-nowrap">
          {/* Live Neo4j CPG Status + Node/Edge Counter */}
          <div
            title={`Neo4j CPG Graph Store — ${
              metrics?.total_nodes ?? 0
            } AST/CFG/DFG nodes, ${metrics?.total_edges ?? 0} edges across ${
              appTree?.total_files ?? metrics?.total_app_files ?? 0
            } files`}
            className="flex items-center gap-1.5 shrink-0"
          >
            <span
              className={`w-2 h-2 rounded-full ${
                isScanning ? "bg-sky-600 animate-pulse" : "bg-emerald-600"
              }`}
            />
            <Database className="w-3 h-3 text-sky-700" />
            <span className="text-[var(--ink-muted)] hidden sm:inline">
              Neo4j CPG:
            </span>
            <span className="font-semibold text-[var(--ink-primary)]">
              {(metrics?.total_nodes ?? 0).toLocaleString()}n /{" "}
              {(metrics?.total_edges ?? 0).toLocaleString()}e
            </span>
          </div>

          <span className="text-[var(--border-hairline)]">|</span>

          {/* Clickable Δ Track Changes Delta Pill */}
          <button
            type="button"
            onClick={() => setTrackChangesPanelOpen(!isTrackChangesPanelOpen)}
            title="Click to toggle Saved Scan Snapshot & Continuous Track Changes Delta Inspector"
            className={`px-1.5 py-0.5 rounded flex items-center gap-1.5 transition-colors border shrink-0 whitespace-nowrap ${
              isTrackChangesPanelOpen
                ? "bg-amber-50 border-amber-400 text-amber-900 font-bold"
                : "hover:bg-[var(--surface-elevated)] border-transparent text-[var(--ink-primary)]"
            }`}
          >
            <GitCompare className="w-3 h-3 text-amber-700" />
            <span className="text-[var(--ink-muted)] hidden md:inline">
              Δ Track:
            </span>
            <span className="text-emerald-800 font-semibold">
              +{fixedCount} Fixed
            </span>
            <span className="text-[var(--ink-muted)]">·</span>
            <span className="text-amber-800 font-semibold">
              +{newCount} New
            </span>
            <span className="text-[var(--ink-muted)] hidden xl:inline">
              · {unchangedCount} Unchanged
            </span>
          </button>

          <span className="text-[var(--border-hairline)] hidden sm:inline">
            |
          </span>

          {/* Active Rule Profile Chip */}
          <button
            type="button"
            onClick={() => {
              setPrimaryStage("ASPM_GOVERNANCE");
              setAspmSubSection("RULES_ENGINE");
              setEngineAccessTab("RULE_PROFILES");
            }}
            title="Active Rule Profile — Click to open Stage 4 Rules & 21-Rule Matrix"
            className="hidden sm:flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-[var(--surface-elevated)] text-[var(--ink-muted)] hover:text-[var(--ink-primary)] transition-colors shrink-0 whitespace-nowrap"
          >
            <Sliders className="w-3 h-3 text-sky-700 shrink-0" />
            <span>Profile:</span>
            <strong className="text-amber-800">
              {activePreset?.badge || "OPTIMIZED"}
            </strong>
          </button>

          <span className="text-[var(--border-hairline)] hidden lg:inline">
            |
          </span>

          {/* Frontier AI Token Efficiency Telemetry Chip */}
          <button
            type="button"
            onClick={() => setAiDrawerOpen(true, "SETTINGS")}
            title="Frontier AI Copilot & CPG Micro-Slicing Token Efficiency"
            className="hidden lg:flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-indigo-50 text-indigo-800 transition-colors shrink-0 whitespace-nowrap"
          >
            <Sparkles className="w-3 h-3 text-indigo-700 shrink-0" />
            <span>AI:</span>
            <strong>
              {aiSavingsPct !== null
                ? `${aiSavingsPct}% Saved`
                : aiConfig?.has_api_key
                ? "Ready"
                : "BYOK"}
            </strong>
          </button>
        </div>

        {/* RIGHT CLUSTER: Keyboard Hint + Polyglot Engine Readiness + Tenant Account + SARIF v2.1.0 Export */}
        <div className="flex items-center gap-2 shrink-0 whitespace-nowrap">
          {/* Keyboard Triage Legend */}
          <div
            title="Keyboard-First Triage Shortcuts inside Stage 2: Triage & Fix"
            className="hidden 2xl:flex items-center gap-1 text-[var(--ink-muted)] shrink-0 whitespace-nowrap"
          >
            <Keyboard className="w-3 h-3 text-amber-700" />
            <span>j/k Flaws · d BFL Diff · [/] Hops · Ctrl+K</span>
          </div>

          <span className="text-[var(--border-hairline)] hidden 2xl:inline">
            |
          </span>

          {/* Active Tech Stack & Polyglot Readiness Pill */}
          <div
            title={`Detected Stack: ${techStackList} • Polyglot CPG Hooks Ready`}
            className="hidden xl:flex items-center gap-1 text-[var(--ink-muted)] shrink-0 whitespace-nowrap"
          >
            <Cpu className="w-3 h-3 text-sky-700" />
            <span>Py · TS/JS · Go/Rust/C++ Ready</span>
          </div>

          <span className="text-[var(--border-hairline)] hidden md:inline">
            |
          </span>

          {/* Active Tenant Account / Operator Chip */}
          <button
            type="button"
            onClick={() => {
              setPrimaryStage("ASPM_GOVERNANCE");
              setAspmSubSection("GOVERNANCE");
              setEngineAccessTab("ACCOUNTS_RBAC");
            }}
            title="Active Multi-Tenant Account & Operator — Click to manage RBAC in Stage 4"
            className="hidden md:flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-[var(--surface-elevated)] text-[var(--ink-muted)] hover:text-[var(--ink-primary)] transition-colors"
          >
            <Building2 className="w-3 h-3 text-emerald-700" />
            <span className="truncate max-w-[120px]">
              {activeAccount?.name || "Enterprise HQ"}
            </span>
            <span>·</span>
            <strong className="text-[var(--ink-primary)] truncate max-w-[100px]">
              {activeUser?.name || activeOperator?.name || "Operator"}
            </strong>
          </button>

          <span className="text-[var(--border-hairline)]">|</span>

          {/* 1-Click SARIF v2.1.0 Export Trigger */}
          <button
            type="button"
            onClick={() => {
              void exportAuditReport("sarif");
            }}
            title="Export CI/CD SARIF v2.1.0 Report (.sarif.json)"
            className="px-1.5 py-0.5 rounded bg-emerald-50 hover:bg-emerald-100 border border-emerald-300 text-emerald-900 font-semibold flex items-center gap-1 transition-colors"
          >
            <Download className="w-2.5 h-2.5 text-emerald-800" />
            <span>SARIF v2.1.0</span>
          </button>
        </div>
      </footer>
    </>
  );
}

export default StudioStatusBar;
