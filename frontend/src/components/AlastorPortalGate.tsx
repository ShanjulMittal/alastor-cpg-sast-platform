"use client";

import React, { useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  AlastorMythicBackground,
  AlastorDemonCrestSvg,
  AlastorThemeSwitcher,
} from "./AlastorBranding";
import { WorkspaceViewMode } from "@/types/cpg";
import {
  ShieldCheck,
  ArrowRight,
  Lock,
  UserCheck,
  FolderGit2,
  Code2,
  Flame,
  Sparkles,
  KeyRound,
  Clock,
  RefreshCw,
  GitCompare,
  Eye,
  ShieldAlert,
  Layers,
  Sliders,
  Play,
} from "lucide-react";

interface AlastorPortalGateProps {
  onEnterApp: (
    mode?: WorkspaceViewMode,
    operator?: { name: string; role: string; email: string }
  ) => void;
}

export function AlastorPortalGate({ onEnterApp }: AlastorPortalGateProps) {
  const metrics = useAuditStore((s) => s.metrics);
  const projects = useAuditStore((s) => s.projects);
  const trackChanges = useAuditStore((s) => s.trackChanges);
  const triggerScan = useAuditStore((s) => s.triggerScan);
  const isScanning = useAuditStore((s) => s.isScanning);
  const openTargetPicker = useAuditStore((s) => s.openTargetPicker);
  const setTrackChangesPanelOpen = useAuditStore(
    (s) => s.setTrackChangesPanelOpen
  );
  const setTrackChangesMode = useAuditStore((s) => s.setTrackChangesMode);

  const [operatorName, setOperatorName] = useState("");
  const [quickGithubUrl, setQuickGithubUrl] = useState("");
  const [quickScanError, setQuickScanError] = useState<string | null>(null);
  const [imgError, setImgError] = useState(false);

  const activeProj = projects.find((p) => p.is_active) || projects[0] || null;
  const lastScannedAt =
    trackChanges?.last_scanned_at || activeProj?.last_scan_at || null;
  const scanCount =
    trackChanges?.scan_count || activeProj?.scan_count || (lastScannedAt ? 1 : 0);
  const fixedCount =
    trackChanges?.fixed_count ?? activeProj?.fixed_since_last_scan ?? 0;
  const newCount =
    trackChanges?.new_count ?? activeProj?.new_since_last_scan ?? 0;
  const unchangedCount =
    trackChanges?.unchanged_count ?? activeProj?.unchanged_since_last_scan ?? 0;

  const handleEnterWorkspace = (mode: WorkspaceViewMode = "REMEDIATION_IDE") => {
    const cleanName = operatorName.trim() || "Local Operator";
    onEnterApp(mode, {
      name: cleanName,
      role: "Standalone Local Mode",
      email: "",
    });
  };

  const handleViewLastScanDetails = () => {
    setTrackChangesMode(true);
    setTrackChangesPanelOpen(true);
    handleEnterWorkspace("REMEDIATION_IDE");
  };

  const handleRescanAndTrackChanges = async () => {
    setTrackChangesMode(true);
    setTrackChangesPanelOpen(true);
    await triggerScan(
      activeProj?.target_path || trackChanges?.project_path || undefined
    );
    handleEnterWorkspace("REMEDIATION_IDE");
  };

  const handleQuickPublicRepoScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanUrl = quickGithubUrl.trim();
    if (!cleanUrl) {
      setQuickScanError(
        "Paste a GitHub repository URL (e.g. https://github.com/owner/repo) to start an instant CPG scan."
      );
      return;
    }
    setQuickScanError(null);
    handleEnterWorkspace("REMEDIATION_IDE");
    const outcome = await triggerScan(cleanUrl, {
      repo_visibility: "AUTO",
    });
    if (!outcome.ok && outcome.authRequired) {
      openTargetPicker("URL", cleanUrl, true, outcome.error || null);
    }
  };

  const handleQuickPrivateRepoModal = () => {
    const cleanUrl = quickGithubUrl.trim();
    handleEnterWorkspace("REMEDIATION_IDE");
    openTargetPicker("URL", cleanUrl, true, null);
  };

  return (
    <div className="relative min-h-screen w-screen overflow-y-auto bg-[var(--surface-void)] text-[var(--ink-primary)] flex flex-col justify-between select-none">
      {/* Mythological Sanctuary Wallpaper & Arcane CPG Sigil */}
      <AlastorMythicBackground />

      {/* Top Portal Navigation Bar */}
      <header className="relative z-30 h-14 px-6 flex items-center justify-between border-b border-[var(--border-hairline)] bg-[var(--surface-panel)]/95 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-[var(--surface-elevated)] p-0.5 border border-[var(--sig-gold)]/70 shadow-sm flex items-center justify-center overflow-hidden">
            {!imgError ? (
              <img
                src="/alastor-demon-logo.png"
                alt="Alastor Demon Logo"
                onError={() => setImgError(true)}
                className="w-full h-full object-cover rounded-[9px]"
              />
            ) : (
              <AlastorDemonCrestSvg className="w-7 h-7" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-display text-base font-bold tracking-[0.14em] text-[var(--sig-gold)]">
                ALASTOR
              </span>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[var(--surface-elevated)] text-[var(--sig-crimson)] border border-[var(--sig-crimson)]/40">
                Ἀλάστωρ • CPG SAST • SCA • IaC
              </span>
            </div>
            <p className="text-[11px] text-[var(--ink-muted)]">
              Deterministic Code Property Graph &amp; Chokepoint Remediation Studio
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <AlastorThemeSwitcher />

          <button
            type="button"
            onClick={() => handleEnterWorkspace("REMEDIATION_IDE")}
            className="px-4 py-2 rounded-xl bg-[var(--sig-crimson)] hover:opacity-95 text-white font-bold text-xs flex items-center gap-2 shadow-sm border border-[var(--sig-gold)]/40 transition-all"
          >
            <span>Resume Active Workspace</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Center Hero & Launch Gate Grid */}
      <main className="relative z-10 flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-6xl grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column (7 cols): Sculptural Cinzel Header, Instant GitHub Quick-Scan, Saved Scan Delta & 5 Studio Workspaces */}
          <div className="lg:col-span-7 space-y-4 bg-[var(--surface-panel)]/90 backdrop-blur-md border border-[var(--border-hairline)] rounded-2xl p-6 shadow-2xl">
            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-5">
              {/* Mythological Demon Emblem Card */}
              <div className="relative w-28 h-28 sm:w-32 sm:h-32 rounded-2xl bg-[var(--surface-void)] border border-[var(--sig-gold)]/60 shadow-lg overflow-hidden shrink-0 flex items-center justify-center group">
                {!imgError ? (
                  <img
                    src="/alastor-demon-logo.png"
                    alt="Alastor Mythological Demon Crest"
                    onError={() => setImgError(true)}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                  />
                ) : (
                  <AlastorDemonCrestSvg className="w-24 h-24" />
                )}
              </div>

              <div className="space-y-2 text-center sm:text-left">
                <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[var(--surface-elevated)] border border-[var(--sig-gold)]/50 text-[var(--sig-gold)] text-[10px] font-mono font-bold uppercase tracking-wider">
                  <Flame className="w-3 h-3 text-[var(--sig-crimson)]" />
                  Ἀλάστωρ • Avenging Daimon of Code Security
                </div>
                <h1 className="font-display text-2xl sm:text-3xl font-bold tracking-[0.12em] text-[var(--ink-primary)] leading-tight">
                  ALASTOR STUDIO
                </h1>
                <p className="text-xs text-[var(--ink-muted)] leading-relaxed">
                  Deterministic 7-pass <b>Code Property Graph</b> (Tree-Sitter AST,
                  CFG, DFG &amp; Inter-Procedural Call Graph) coupled with live{" "}
                  <b>Sever the Thread</b> Best Fix Location (`BFL`) surgical patching.
                </p>
              </div>
            </div>

            {/* Instant GitHub Repository Quick-Scan Bar */}
            <form
              onSubmit={handleQuickPublicRepoScan}
              className="p-3.5 rounded-xl bg-[var(--surface-elevated)] border border-[var(--border-hairline)] space-y-2"
            >
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <label
                  htmlFor="launch-hub-github-url"
                  className="text-[11px] font-mono font-bold uppercase tracking-wider text-[var(--sig-cyan)] flex items-center gap-1.5"
                >
                  <FolderGit2 className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
                  <span>Instant GitHub Repository Quick-Scan Bar</span>
                </label>
                <span className="text-[10px] font-mono text-[var(--ink-muted)]">
                  Zero-Token Public Clone or Private PAT Auth
                </span>
              </div>

              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                <input
                  id="launch-hub-github-url"
                  type="text"
                  value={quickGithubUrl}
                  onChange={(e) => {
                    setQuickGithubUrl(e.target.value);
                    if (quickScanError) setQuickScanError(null);
                  }}
                  placeholder="https://github.com/owner/repo"
                  className="flex-1 bg-[var(--surface-void)] border border-[var(--border-hairline)] focus:border-[var(--sig-cyan)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--ink-primary)] placeholder:text-[var(--ink-muted)] focus:outline-none"
                />
                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="submit"
                    disabled={isScanning}
                    className="px-3.5 py-2 rounded-lg bg-[var(--sig-emerald)] hover:opacity-95 disabled:opacity-50 text-white font-bold text-xs flex items-center gap-1.5 transition-opacity"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Scan Public Repo</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleQuickPrivateRepoModal}
                    className="px-3 py-2 rounded-lg bg-[var(--surface-panel)] hover:bg-[var(--surface-void)] border border-[var(--sig-gold)]/50 text-[var(--sig-gold)] font-mono font-bold text-xs flex items-center gap-1.5 transition-colors"
                  >
                    <KeyRound className="w-3.5 h-3.5" />
                    <span>Private PAT...</span>
                  </button>
                </div>
              </div>

              {quickScanError && (
                <p className="text-[11px] font-mono text-[var(--sig-crimson)]">
                  {quickScanError}
                </p>
              )}
            </form>

            {/* Saved Scan Snapshot & Continuous Track Changes Bar */}
            <div className="p-4 rounded-xl bg-[var(--surface-elevated)] border border-[var(--sig-gold)]/40 space-y-3">
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
                <div className="space-y-1 text-center sm:text-left">
                  <div className="text-xs font-bold text-[var(--ink-primary)] flex items-center justify-center sm:justify-start gap-2 flex-wrap">
                    <Sparkles className="w-4 h-4 text-[var(--sig-gold)]" />
                    <span>
                      Active Target:{" "}
                      <strong className="text-[var(--sig-cyan)] font-mono">
                        {activeProj?.name ||
                          trackChanges?.application_name ||
                          "cpg-sast-platform"}
                      </strong>
                    </span>
                    <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[10px] font-mono text-[var(--sig-gold)] flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {lastScannedAt
                        ? `Last Scanned: ${lastScannedAt} (Scan #${scanCount})`
                        : "Ready for Scan"}
                    </span>
                  </div>
                  <p className="text-[11px] text-[var(--ink-muted)]">
                    Saved scan snapshot is ready in memory — resume immediately
                    without re-scanning, or run a fresh delta comparison.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("REMEDIATION_IDE")}
                  className="w-full sm:w-auto px-4 py-2 rounded-xl bg-[var(--sig-gold)] text-black font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm shrink-0"
                >
                  <span>Open Workbench</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>

              <div className="pt-2.5 border-t border-[var(--border-hairline)] flex flex-col sm:flex-row items-center justify-between gap-2.5 text-[11px] font-mono">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="flex items-center gap-1 text-[var(--ink-muted)] font-bold">
                    <GitCompare className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
                    Saved Scan Delta:
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--sig-emerald)]/50 text-[var(--sig-emerald)] font-bold">
                    +{fixedCount} Fixed
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--sig-gold)]/50 text-[var(--sig-gold)] font-bold">
                    +{newCount} New
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-muted)]">
                    {unchangedCount} Unchanged
                  </span>
                </div>

                <div className="flex items-center gap-2 w-full sm:w-auto justify-center">
                  <button
                    type="button"
                    onClick={handleViewLastScanDetails}
                    className="px-2.5 py-1 rounded-lg bg-[var(--surface-void)] hover:bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[var(--sig-gold)] font-bold text-[11px] flex items-center gap-1"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>Delta Inspector</span>
                  </button>
                  <button
                    type="button"
                    disabled={isScanning}
                    onClick={handleRescanAndTrackChanges}
                    className="px-2.5 py-1 rounded-lg bg-[var(--sig-cyan)] text-white font-bold text-[11px] flex items-center gap-1 disabled:opacity-50"
                  >
                    <RefreshCw
                      className={`w-3.5 h-3.5 ${isScanning ? "animate-spin" : ""}`}
                    />
                    <span>{isScanning ? "Scanning..." : "Re-Scan Target"}</span>
                  </button>
                </div>
              </div>
            </div>

            {/* 5 Focused Studio Workspaces */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--ink-muted)] font-bold">
                Launch Directly Into Any of the 5 Unified Studio Workspaces:
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-5 gap-2">
                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("REMEDIATION_IDE")}
                  className="p-2.5 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] hover:border-[var(--sig-gold)] text-left transition-all group space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <Code2 className="w-4 h-4 text-[var(--sig-emerald)]" />
                    <ArrowRight className="w-3.5 h-3.5 text-[var(--ink-muted)] group-hover:text-[var(--sig-gold)] transition-colors" />
                  </div>
                  <div className="text-xs font-bold text-[var(--ink-primary)]">
                    1. Workbench
                  </div>
                  <p className="text-[10px] text-[var(--ink-muted)] leading-snug">
                    Monaco BFL DiffEditor, Flaw Explorer &amp; 7 CPG Graphs
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("THREAT_MODELING")}
                  className="p-2.5 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] hover:border-[var(--sig-crimson)] text-left transition-all group space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <ShieldAlert className="w-4 h-4 text-[var(--sig-crimson)]" />
                    <ArrowRight className="w-3.5 h-3.5 text-[var(--ink-muted)] group-hover:text-[var(--sig-crimson)] transition-colors" />
                  </div>
                  <div className="text-xs font-bold text-[var(--ink-primary)]">
                    2. Threats &amp; Vault
                  </div>
                  <p className="text-[10px] text-[var(--ink-muted)] leading-snug">
                    STRIDE Verdict Matrix, Trust Zones &amp; Secret Vault
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("EXECUTIVE_ASPM")}
                  className="p-2.5 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] hover:border-[var(--sig-gold)] text-left transition-all group space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <Layers className="w-4 h-4 text-[var(--sig-gold)]" />
                    <ArrowRight className="w-3.5 h-3.5 text-[var(--ink-muted)] group-hover:text-[var(--sig-gold)] transition-colors" />
                  </div>
                  <div className="text-xs font-bold text-[var(--ink-primary)]">
                    3. Executive ASPM
                  </div>
                  <p className="text-[10px] text-[var(--ink-muted)] leading-snug">
                    Plain-English Impact, CycloneDX SBOM, Analytics &amp; RACI
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("PROJECTS_HUB")}
                  className="p-2.5 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] hover:border-[var(--sig-cyan)] text-left transition-all group space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <FolderGit2 className="w-4 h-4 text-[var(--sig-cyan)]" />
                    <ArrowRight className="w-3.5 h-3.5 text-[var(--ink-muted)] group-hover:text-[var(--sig-cyan)] transition-colors" />
                  </div>
                  <div className="text-xs font-bold text-[var(--ink-primary)]">
                    4. Repositories
                  </div>
                  <p className="text-[10px] text-[var(--ink-muted)] leading-snug">
                    Local Auto-Discovery, GitHub Clone &amp; Scan Snapshots
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("ENGINE_ACCESS")}
                  className="p-2.5 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] hover:border-[var(--sig-emerald)] text-left transition-all group space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <Sliders className="w-4 h-4 text-[var(--sig-emerald)]" />
                    <ArrowRight className="w-3.5 h-3.5 text-[var(--ink-muted)] group-hover:text-[var(--sig-emerald)] transition-colors" />
                  </div>
                  <div className="text-xs font-bold text-[var(--ink-primary)]">
                    5. Engine &amp; Access
                  </div>
                  <p className="text-[10px] text-[var(--ink-muted)] leading-snug">
                    18-Rule Matrix, Cypher Sanitizers, RBAC &amp; Jira/GitHub
                  </p>
                </button>
              </div>
            </div>

            {/* Live Engine Telemetry Footer */}
            <div className="pt-2 border-t border-[var(--border-hairline)] flex items-center justify-between flex-wrap gap-2 text-[11px] font-mono text-[var(--ink-muted)]">
              <span className="flex items-center gap-1.5">
                <span
                  className={`w-2 h-2 rounded-full ${
                    metrics ? "bg-[var(--sig-emerald)]" : "bg-[var(--sig-gold)]"
                  }`}
                />
                <span
                  className={
                    metrics
                      ? "text-[var(--sig-emerald)] font-bold"
                      : "text-[var(--sig-gold)] font-bold"
                  }
                >
                  {metrics ? "Neo4j CPG Connected" : "Awaiting Backend Telemetry"}
                </span>
              </span>
              <span>
                Projects:{" "}
                <b className="text-[var(--ink-primary)]">{projects.length}</b>
              </span>
              <span>
                CPG Nodes:{" "}
                <b className="text-[var(--sig-cyan)]">
                  {metrics?.total_nodes ?? 0}
                </b>
              </span>
              <span>
                Active Flaws:{" "}
                <b className="text-[var(--sig-crimson)]">
                  {metrics?.total_findings ?? 0}
                </b>
              </span>
            </div>
          </div>

          {/* Right Column (5 cols): Standalone Mode Entry & Authentication Status Notice */}
          <div className="lg:col-span-5 bg-[var(--surface-panel)]/90 backdrop-blur-md border border-[var(--border-hairline)] rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[var(--border-hairline)] pb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-xl bg-[var(--surface-elevated)] border border-[var(--sig-gold)]/50 flex items-center justify-center">
                  <Lock className="w-4 h-4 text-[var(--sig-gold)]" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-[var(--ink-primary)]">
                    Operator Session &amp; Auth Status
                  </h2>
                  <p className="text-[11px] text-[var(--ink-muted)]">
                    Local standalone execution environment
                  </p>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] text-[var(--sig-gold)] border border-[var(--sig-gold)]/50 font-mono text-[9px] font-bold">
                STANDALONE LOCAL
              </span>
            </div>

            <div className="p-3 rounded-xl bg-[var(--surface-elevated)] border border-[var(--border-hairline)] text-[11px] text-[var(--ink-muted)] space-y-1.5">
              <div className="font-bold font-mono uppercase tracking-wider text-[var(--sig-gold)]">
                Zero-Cloud Local Execution Guarantee
              </div>
              <p className="leading-relaxed">
                All AST, CFG, DFG, OSV Supply-Chain, and BFL Patch operations execute
                100% locally on your workstation. Session state and split ratios
                persist automatically across reloads.
              </p>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-[10px] font-mono uppercase tracking-wider text-[var(--ink-muted)] mb-1">
                  Optional Local Auditor Name (Used in Triage &amp; Patch Journals)
                </label>
                <div className="relative">
                  <UserCheck className="w-3.5 h-3.5 text-[var(--sig-gold)] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={operatorName}
                    onChange={(e) => setOperatorName(e.target.value)}
                    placeholder="Local Operator (optional)"
                    className="w-full bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-xl pl-9 pr-3 py-2 text-xs text-[var(--ink-primary)] font-mono focus:outline-none focus:border-[var(--sig-gold)]"
                  />
                </div>
              </div>

              <button
                type="button"
                onClick={() => handleEnterWorkspace("REMEDIATION_IDE")}
                className="w-full py-2.5 px-4 rounded-xl bg-[var(--sig-crimson)] hover:opacity-95 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-md border border-[var(--sig-gold)]/40 transition-all"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Launch ALASTOR Studio Workbench</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>

            <div className="pt-2 border-t border-[var(--border-hairline)] space-y-1.5 text-[10px] font-mono text-[var(--ink-muted)]">
              <div className="text-[var(--ink-primary)] font-bold">
                Studio Capabilities Ready:
              </div>
              <div>
                •{" "}
                <span className="text-[var(--sig-emerald)] font-bold">
                  Sever the Thread:
                </span>{" "}
                Live Monaco BFL DiffEditor, SHA256 Undo Journal &amp; instant CPG re-verification.
              </div>
              <div>
                •{" "}
                <span className="text-[var(--sig-cyan)] font-bold">
                  Keyboard Triage:
                </span>{" "}
                Press <code>j/k</code> to step findings, <code>[ / ]</code> to trace CPG hops, and <code>d</code> to preview BFL diff.
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Bottom Mythological Status Strip */}
      <footer className="relative z-20 px-6 py-2 border-t border-[var(--border-hairline)] bg-[var(--surface-panel)]/90 flex items-center justify-between text-[11px] font-mono text-[var(--ink-muted)]">
        <span className="font-display tracking-widest text-[var(--sig-gold)]">
          ALASTOR v3.0 • PRECISION CPG SECURITY STUDIO
        </span>
        <span>
          SAST • SCA • IaC • Live BFL Patching • CycloneDX v1.5 SBOM
        </span>
      </footer>
    </div>
  );
}

export default AlastorPortalGate;
