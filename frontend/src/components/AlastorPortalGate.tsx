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
  PieChart,
  Code2,
  Flame,
  Sparkles,
  KeyRound,
  Terminal,
  Clock,
  RefreshCw,
  GitCompare,
  Eye,
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
  const setTrackChangesPanelOpen = useAuditStore(
    (s) => s.setTrackChangesPanelOpen
  );
  const setTrackChangesMode = useAuditStore((s) => s.setTrackChangesMode);

  const [operatorName, setOperatorName] = useState("");
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
    await triggerScan(activeProj?.target_path || trackChanges?.project_path || undefined);
    handleEnterWorkspace("REMEDIATION_IDE");
  };

  return (
    <div className="relative min-h-screen w-screen overflow-y-auto bg-zinc-950 text-zinc-100 flex flex-col justify-between select-none">
      {/* Mythological Sanctuary Wallpaper & Rotating Arcane CPG Sigil */}
      <AlastorMythicBackground />

      {/* Top Portal Navigation Bar */}
      <header className="relative z-30 h-16 px-6 flex items-center justify-between border-b border-zinc-800/80 bg-zinc-950/95">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-rose-950 via-zinc-950 to-amber-950 p-0.5 border border-amber-500/70 shadow-lg shadow-rose-600/25 flex items-center justify-center overflow-hidden">
            {!imgError ? (
              <img
                src="/alastor-demon-logo.png"
                alt="Alastor Demon Logo"
                onError={() => setImgError(true)}
                className="w-full h-full object-cover rounded-[10px]"
              />
            ) : (
              <AlastorDemonCrestSvg className="w-8 h-8" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-black tracking-widest bg-gradient-to-r from-amber-300 via-rose-500 to-amber-300 bg-clip-text text-transparent">
                ALASTOR
              </span>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-950 text-amber-300 border border-rose-700/80">
                DAIMON CPG • SAST • SCA • IaC
              </span>
            </div>
            <p className="text-[11px] text-zinc-400">
              Deterministic Code Property Graph &amp; Vulnerability Analysis Engine
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Theme & Light Mode Switcher right on the Portal Header */}
          <AlastorThemeSwitcher />

          {/* Direct 1-Click "Go to App" Button in Header */}
          <button
            type="button"
            onClick={() => handleEnterWorkspace("REMEDIATION_IDE")}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-rose-600 via-red-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-rose-900/50 border border-amber-400/40 transition-all hover:scale-[1.02]"
          >
            <span>Go to App</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Center Hero & Launch Gate Grid */}
      <main className="relative z-10 flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          {/* Left Column (7 cols): Mythological Crest Showcase, Real Telemetry & Quick-Launch Modes */}
          <div className="lg:col-span-7 space-y-5 bg-zinc-950/80 backdrop-blur-md border border-zinc-800/90 rounded-3xl p-6 shadow-2xl">
            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-5">
              {/* Large Mythological Demon Emblem Card */}
              <div className="relative w-32 h-32 sm:w-36 sm:h-36 rounded-2xl bg-black border-2 border-amber-500/60 shadow-2xl shadow-rose-600/30 overflow-hidden shrink-0 flex items-center justify-center group">
                {!imgError ? (
                  <img
                    src="/alastor-demon-logo.png"
                    alt="Alastor Mythological Demon Crest"
                    onError={() => setImgError(true)}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                  />
                ) : (
                  <AlastorDemonCrestSvg className="w-28 h-28" />
                )}
                <div className="absolute inset-0 ring-1 ring-inset ring-amber-400/30 rounded-2xl pointer-events-none" />
              </div>

              <div className="space-y-2 text-center sm:text-left">
                <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-rose-950/90 border border-rose-700/80 text-amber-300 text-[10px] font-mono font-bold uppercase tracking-wider">
                  <Flame className="w-3 h-3 text-rose-400" />
                  Ἀλάστωρ • Avenging Daimon of Code Security
                </div>
                <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-zinc-100 leading-tight">
                  Welcome to{" "}
                  <span className="bg-gradient-to-r from-amber-400 via-rose-500 to-amber-300 bg-clip-text text-transparent">
                    ALASTOR
                  </span>
                </h1>
                <p className="text-xs text-zinc-300 leading-relaxed">
                  Named after the relentless spirit of retribution in Greek mythology,{" "}
                  <b>ALASTOR</b> fuses deterministic <b>Code Property Graphs</b> (Tree-Sitter AST,
                  CFG &amp; DFG) with unified <b>SAST</b>, <b>SCA</b>, and <b>IaC</b> engines over
                  your actual local codebase.
                </p>
              </div>
            </div>

            {/* Prominent Primary "Go to App" + Saved Scan Snapshot & Track Changes Bar */}
            <div className="p-4 rounded-2xl bg-gradient-to-r from-rose-950/70 via-zinc-900/90 to-amber-950/60 border border-amber-500/40 space-y-3">
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
                <div className="space-y-1 text-center sm:text-left">
                  <div className="text-xs font-bold text-zinc-100 flex items-center justify-center sm:justify-start gap-2 flex-wrap">
                    <Sparkles className="w-4 h-4 text-amber-400" />
                    <span>
                      Active App:{" "}
                      <strong className="text-cyan-300">
                        {activeProj?.name ||
                          trackChanges?.application_name ||
                          "cpg-sast-platform"}
                      </strong>
                    </span>
                    <span className="px-2 py-0.5 rounded bg-amber-950/90 border border-amber-600/70 text-[10px] font-mono text-amber-200 flex items-center gap-1">
                      <Clock className="w-3 h-3 text-amber-400" />
                      {lastScannedAt
                        ? `Last Scanned: ${lastScannedAt} (Scan #${scanCount})`
                        : "Ready for Scan"}
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-300">
                    Saved scan snapshot is ready — view previous scan details
                    immediately without scanning every time, or trigger a
                    fresh re-scan with <b>Continuous Track Changes Mode</b>.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("REMEDIATION_IDE")}
                  className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 via-red-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-rose-900/50 border border-amber-300/40 transition-all hover:scale-[1.02] shrink-0"
                >
                  <span>Go to App (Saved Scan)</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>

              {/* Track Changes Status & Quick Action Strip on Main Page */}
              <div className="pt-2.5 border-t border-zinc-800/80 flex flex-col sm:flex-row items-center justify-between gap-2.5 text-[11px] font-mono">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="flex items-center gap-1 text-indigo-300 font-bold">
                    <GitCompare className="w-3.5 h-3.5 text-indigo-400" />
                    Track Changes Mode:
                  </span>
                  <span className="px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-700/70 text-emerald-300 font-bold">
                    ✅ {fixedCount} Old Fixed
                  </span>
                  <span className="px-2 py-0.5 rounded bg-amber-950/80 border border-amber-700/70 text-amber-300 font-bold">
                    🆕 {newCount} New Came
                  </span>
                  <span className="px-2 py-0.5 rounded bg-zinc-950 border border-zinc-700 text-zinc-300">
                    ⏳ {unchangedCount} Unchanged
                  </span>
                </div>

                <div className="flex items-center gap-2 w-full sm:w-auto justify-center">
                  <button
                    type="button"
                    onClick={handleViewLastScanDetails}
                    className="px-3 py-1.5 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/60 text-amber-200 font-bold text-[11px] flex items-center gap-1.5 transition-colors"
                  >
                    <Eye className="w-3.5 h-3.5 text-amber-400" />
                    <span>View Last Scan Details</span>
                  </button>
                  <button
                    type="button"
                    disabled={isScanning}
                    onClick={handleRescanAndTrackChanges}
                    className="px-3 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-bold text-[11px] flex items-center gap-1.5 transition-colors"
                  >
                    <RefreshCw
                      className={`w-3.5 h-3.5 ${
                        isScanning ? "animate-spin" : ""
                      }`}
                    />
                    <span>
                      {isScanning ? "Re-Scanning..." : "Re-Scan & Track Changes"}
                    </span>
                  </button>
                </div>
              </div>
            </div>

            {/* 5 Direct Workspace Launch Cards (Including RACI Governance & SAST++++++ Suite) */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 font-bold">
                Launch Directly Into Any Workspace View (Pro Engineer or Non-Coder Student Mode):
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-5 gap-2">
                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("PROJECTS_HUB")}
                  className="p-2.5 rounded-xl bg-zinc-900/80 hover:bg-zinc-800/90 border border-zinc-800 hover:border-cyan-500/70 text-left transition-all group space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <FolderGit2 className="w-4 h-4 text-cyan-400" />
                    <ArrowRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
                  </div>
                  <div className="text-xs font-bold text-zinc-100">
                    1. Projects Hub
                  </div>
                  <p className="text-[10px] text-zinc-400 leading-snug">
                    Local project directories &amp; Multi-Site Web Vulnerability Scanner
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("DEEP_DIVE")}
                  className="p-2.5 rounded-xl bg-zinc-900/80 hover:bg-zinc-800/90 border border-zinc-800 hover:border-indigo-500/70 text-left transition-all group space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <PieChart className="w-4 h-4 text-indigo-400" />
                    <ArrowRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-indigo-400 group-hover:translate-x-0.5 transition-all" />
                  </div>
                  <div className="text-xs font-bold text-zinc-100">
                    2. Deep Dive
                  </div>
                  <p className="text-[10px] text-zinc-400 leading-snug">
                    Severity breakdown, aging, OWASP/PCI compliance &amp; engines
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("REMEDIATION_IDE")}
                  className="p-2.5 rounded-xl bg-zinc-900/80 hover:bg-zinc-800/90 border border-zinc-800 hover:border-emerald-500/70 text-left transition-all group space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <Code2 className="w-4 h-4 text-emerald-400" />
                    <ArrowRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-emerald-400 group-hover:translate-x-0.5 transition-all" />
                  </div>
                  <div className="text-xs font-bold text-zinc-100">
                    3. Remediation IDE
                  </div>
                  <p className="text-[10px] text-zinc-400 leading-snug">
                    Findings browser, CPG taint flow, BFL &amp; Plain-English guide
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("RACI_GOVERNANCE")}
                  className="p-2.5 rounded-xl bg-zinc-900/80 hover:bg-zinc-800/90 border border-zinc-800 hover:border-amber-500/70 text-left transition-all group space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <UserCheck className="w-4 h-4 text-amber-400" />
                    <ArrowRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-amber-400 group-hover:translate-x-0.5 transition-all" />
                  </div>
                  <div className="text-xs font-bold text-zinc-100">
                    4. RACI Matrix
                  </div>
                  <p className="text-[10px] text-zinc-400 leading-snug">
                    Interactive R-A-C-I Governance, PMI/COBIT checks &amp; role ownership
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleEnterWorkspace("SAST_PLUS_SUITE")}
                  className="p-2.5 rounded-xl bg-zinc-900/80 hover:bg-zinc-800/90 border border-zinc-800 hover:border-rose-500/70 text-left transition-all group space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <Sparkles className="w-4 h-4 text-rose-400" />
                    <ArrowRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-rose-400 group-hover:translate-x-0.5 transition-all" />
                  </div>
                  <div className="text-xs font-bold text-zinc-100">
                    5. SAST++++++
                  </div>
                  <p className="text-[10px] text-zinc-400 leading-snug">
                    Plain-English Translator, Live SBOM, Attack Surface &amp; Roadmap
                  </p>
                </button>
              </div>
            </div>

            {/* Live Engine Telemetry Footer (Only Real Numbers, Zero Dummy Fallbacks) */}
            <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between flex-wrap gap-2 text-[11px] font-mono text-zinc-400">
              <span className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${metrics ? "bg-emerald-400" : "bg-amber-400"}`} />
                <span className={metrics ? "text-emerald-400 font-bold" : "text-amber-400 font-bold"}>
                  {metrics ? "Neo4j CPG Connected" : "Awaiting Backend Telemetry"}
                </span>
              </span>
              <span>
                Projects: <b className="text-zinc-200">{projects.length}</b>
              </span>
              <span>
                CPG Nodes: <b className="text-cyan-400">{metrics?.total_nodes ?? 0}</b>
              </span>
              <span>
                Active Flaws: <b className="text-rose-400">{metrics?.total_findings ?? 0}</b>
              </span>
            </div>
          </div>

          {/* Right Column (5 cols): Standalone Mode Entry & Authentication Status Notice */}
          <div className="lg:col-span-5 bg-zinc-950/85 backdrop-blur-md border border-amber-500/40 rounded-3xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-xl bg-rose-950 border border-rose-700 flex items-center justify-center">
                  <Lock className="w-4 h-4 text-amber-400" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-zinc-100">
                    Operator Session &amp; Auth Status
                  </h2>
                  <p className="text-[11px] text-zinc-400">
                    Local standalone execution environment
                  </p>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700 font-mono text-[9px] font-bold">
                AUTH: NOT WORKING FOR NOW
              </span>
            </div>

            <div className="p-3 rounded-xl bg-amber-950/30 border border-amber-800/60 text-[11px] text-amber-200/90 space-y-1.5">
              <div className="font-bold font-mono uppercase tracking-wider text-amber-300">
                Corporate SSO / OAuth Login — Not Working For Now
              </div>
              <p className="text-zinc-300 leading-relaxed">
                External identity provider authentication (SAML / OIDC / OAuth2) is{" "}
                <b>not working for now</b> in local standalone mode. No dummy credentials or
                simulated logins are used.
              </p>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-[10px] font-mono uppercase tracking-wider text-zinc-400 mb-1">
                  Optional Local Auditor Name (Used in Triage &amp; Ticket Comments)
                </label>
                <div className="relative">
                  <UserCheck className="w-3.5 h-3.5 text-amber-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={operatorName}
                    onChange={(e) => setOperatorName(e.target.value)}
                    placeholder="Local Operator (optional)"
                    className="w-full bg-zinc-900 border border-zinc-700 rounded-xl pl-9 pr-3 py-2 text-xs text-zinc-100 font-mono focus:outline-none focus:border-amber-500"
                  />
                </div>
              </div>

              <button
                type="button"
                onClick={() => handleEnterWorkspace("REMEDIATION_IDE")}
                className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-rose-600 via-red-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-rose-950/60 border border-amber-400/40 transition-all"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Launch ALASTOR Workspace</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>

            <div className="pt-2 border-t border-zinc-800 space-y-1.5 text-[10px] font-mono text-zinc-400">
              <div className="text-zinc-300 font-bold">What is Working vs. Not Working For Now:</div>
              <div>• <span className="text-emerald-400 font-bold">Working:</span> Local AST/CFG/DFG Neo4j CPG scan, SAST/SCA/IaC rules, BFL highlighting, Triage suppression, Local Ticket Tracker.</div>
              <div>• <span className="text-amber-400 font-bold">Not Working For Now:</span> Corporate SSO Login, Incoming Cloud GitHub/GitLab Webhooks (localhost has no public tunnel), Live Jira Cloud sync without user API token.</div>
            </div>
          </div>
        </div>
      </main>

      {/* Bottom Mythological Status Strip */}
      <footer className="relative z-20 px-6 py-2.5 border-t border-zinc-800/80 bg-zinc-950/75 backdrop-blur-md flex items-center justify-between text-[11px] font-mono text-zinc-400">
        <span>ALASTOR v2.5 • Deterministic Code Property Graph Security Platform</span>
        <span>SAST • SCA • IaC • Best Fixed Location (BFL) • Jira &amp; GitHub Integration</span>
      </footer>
    </div>
  );
}
