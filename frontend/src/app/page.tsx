"use client";

import React, { useEffect } from "react";
import dynamic from "next/dynamic";
import { TopMetricsBar } from "@/components/TopMetricsBar";
import { AppMenuBar } from "@/components/AppMenuBar";
import { ActiveApplicationBanner } from "@/components/ActiveApplicationBanner";
import { FlawExplorerSidebar } from "@/components/FlawExplorerSidebar";
import { ProjectsHubView } from "@/components/ProjectsHubView";
import { DeepDiveDashboard } from "@/components/DeepDiveDashboard";
import { RaciGovernanceView } from "@/components/RaciGovernanceView";
import { SastPlusSuiteView } from "@/components/SastPlusSuiteView";
import { SettingsCustomizationModal } from "@/components/SettingsCustomizationModal";
import { IntegrationHubModal } from "@/components/IntegrationHubModal";
import { AlastorMythicBackground } from "@/components/AlastorBranding";
import { AlastorPortalGate } from "@/components/AlastorPortalGate";
import QuickCommandModal from "@/components/QuickCommandModal";
import { useAuditStore } from "@/store/useAuditStore";
import { WorkspaceViewMode } from "@/types/cpg";
import {
  Loader2,
  PanelLeftClose,
  PanelLeftOpen,
  Code2,
  Network,
  Columns,
  GraduationCap,
  Cpu,
  Globe,
  Maximize2,
} from "lucide-react";

// Dynamically import Monaco Editor and ReactFlow Canvas with SSR disabled
// to guarantee zero hydration mismatches and prevent DOM measurement failures.
const MonacoCodePane = dynamic(
  () => import("@/components/MonacoCodePane").then((mod) => mod.MonacoCodePane),
  {
    ssr: false,
    loading: () => (
      <div className="flex flex-col items-center justify-center h-full bg-zinc-950/75 text-zinc-400 font-mono text-xs gap-2">
        <Loader2 className="w-5 h-5 animate-spin text-rose-500" />
        <span>Summoning ALASTOR Source Inspector...</span>
      </div>
    ),
  }
);

const ReactFlowGraphPane = dynamic(
  () => import("@/components/ReactFlowGraphPane").then((mod) => mod.ReactFlowGraphPane),
  {
    ssr: false,
    loading: () => (
      <div className="flex flex-col items-center justify-center h-full bg-zinc-950/75 text-zinc-400 font-mono text-xs gap-2">
        <Loader2 className="w-5 h-5 animate-spin text-amber-500" />
        <span>Summoning ALASTOR CPG Sigil Canvas...</span>
      </div>
    ),
  }
);

export default function AuditPage() {
  const workspaceViewMode = useAuditStore((s) => s.workspaceViewMode);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);
  const showPortalGate = useAuditStore((s) => s.showPortalGate);
  const setShowPortalGate = useAuditStore((s) => s.setShowPortalGate);
  const ideLayoutMode = useAuditStore((s) => s.ideLayoutMode);
  const setIdeLayoutMode = useAuditStore((s) => s.setIdeLayoutMode);
  const isSidebarCollapsed = useAuditStore((s) => s.isSidebarCollapsed);
  const setSidebarCollapsed = useAuditStore((s) => s.setSidebarCollapsed);
  const audienceMode = useAuditStore((s) => s.audienceMode);
  const setAudienceMode = useAuditStore((s) => s.setAudienceMode);
  const setActiveSidebarTab = useAuditStore((s) => s.setActiveSidebarTab);
  const setGraphFullscreen = useAuditStore((s) => s.setGraphFullscreen);
  const findings = useAuditStore((s) => s.findings);

  const fetchFindings = useAuditStore((s) => s.fetchFindings);
  const fetchMetrics = useAuditStore((s) => s.fetchMetrics);
  const fetchAppTree = useAuditStore((s) => s.fetchAppTree);
  const fetchProjects = useAuditStore((s) => s.fetchProjects);
  const fetchDeepDiveAnalytics = useAuditStore((s) => s.fetchDeepDiveAnalytics);
  const fetchPlatformSettings = useAuditStore((s) => s.fetchPlatformSettings);
  const fetchIntegrations = useAuditStore((s) => s.fetchIntegrations);
  const fetchRaciGovernance = useAuditStore((s) => s.fetchRaciGovernance);
  const fetchSastPlusSuite = useAuditStore((s) => s.fetchSastPlusSuite);
  const fetchTrackChanges = useAuditStore((s) => s.fetchTrackChanges);

  useEffect(() => {
    fetchFindings();
    fetchMetrics();
    fetchAppTree();
    fetchProjects();
    fetchDeepDiveAnalytics();
    fetchPlatformSettings();
    fetchIntegrations();
    fetchRaciGovernance();
    fetchSastPlusSuite();
    fetchTrackChanges();
  }, [
    fetchFindings,
    fetchMetrics,
    fetchAppTree,
    fetchProjects,
    fetchDeepDiveAnalytics,
    fetchPlatformSettings,
    fetchIntegrations,
    fetchRaciGovernance,
    fetchSastPlusSuite,
    fetchTrackChanges,
  ]);

  const handleEnterApp = (
    mode: WorkspaceViewMode = "REMEDIATION_IDE",
    operator?: { name: string; role: string; email: string }
  ) => {
    setWorkspaceViewMode(mode);
    setShowPortalGate(false, operator);
  };

  if (showPortalGate) {
    return <AlastorPortalGate onEnterApp={handleEnterApp} />;
  }

  return (
    <div className="relative flex flex-col h-screen w-screen overflow-hidden bg-zinc-950 select-none">
      {/* Mythological Demon Sanctuary & Arcane CPG Sigil Backdrop */}
      <AlastorMythicBackground />

      {/* Top Application Menu Bar & Collapsible Quick Settings Ribbon */}
      <AppMenuBar />

      {/* Top Executive Metrics, Brand Crest, Theme Switcher & Scan Action Bar */}
      <TopMetricsBar />

      {/* Persistent Active Application Under Review Context Banner across all 5 review pages */}
      <ActiveApplicationBanner />

      {/* Enterprise Workspace Router: 1. Projects Hub | 2. Deep Dive | 3. Remediation IDE | 4. RACI Matrix | 5. SAST++++++ Suite */}
      {workspaceViewMode === "PROJECTS_HUB" ? (
        <main className="relative z-10 flex-1 flex overflow-hidden">
          <ProjectsHubView />
        </main>
      ) : workspaceViewMode === "DEEP_DIVE" ? (
        <main className="relative z-10 flex-1 flex overflow-hidden">
          <DeepDiveDashboard />
        </main>
      ) : workspaceViewMode === "RACI_GOVERNANCE" ? (
        <main className="relative z-10 flex-1 flex overflow-hidden">
          <RaciGovernanceView />
        </main>
      ) : workspaceViewMode === "SAST_PLUS_SUITE" ? (
        <main className="relative z-10 flex-1 flex overflow-hidden">
          <SastPlusSuiteView />
        </main>
      ) : (
        <div className="relative z-10 flex-1 flex flex-col overflow-hidden">
          {/* Clean Workspace Focus & Layout Switcher Bar for Code & Graph Review */}
          <div className="px-4 py-1.5 bg-zinc-950/90 border-b border-zinc-800/80 flex items-center justify-between gap-3 flex-wrap">
            {/* Left: Sidebar Collapse/Expand + Layout Focus Mode Switcher */}
            <div className="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                onClick={() => setSidebarCollapsed(!isSidebarCollapsed)}
                title={
                  isSidebarCollapsed
                    ? "Expand Left Sidebar (Findings, Files & Web Advisories)"
                    : "Collapse Left Sidebar for More Screen Space"
                }
                className="px-2.5 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-xs font-medium text-zinc-200 flex items-center gap-1.5 transition-colors"
              >
                {isSidebarCollapsed ? (
                  <>
                    <PanelLeftOpen className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Show Sidebar ({findings.length})</span>
                  </>
                ) : (
                  <>
                    <PanelLeftClose className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Hide Sidebar</span>
                  </>
                )}
              </button>

              {/* Workspace Layout Switcher: Split vs Code Focus vs Graph Focus */}
              <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setIdeLayoutMode("CODE_FOCUS")}
                  title="Code & Plain-English Fix Focus: Give full width to Source Code & Storyboard"
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md transition-all ${
                    ideLayoutMode === "CODE_FOCUS"
                      ? "bg-emerald-950 text-emerald-300 border border-emerald-700/80 font-bold"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Code &amp; Fix Focus</span>
                </button>
                <button
                  type="button"
                  onClick={() => setIdeLayoutMode("GRAPH_FOCUS")}
                  title="Visual Graph Focus: Give full width to the CPG Graph & 360° Architecture Spider Map"
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md transition-all ${
                    ideLayoutMode === "GRAPH_FOCUS"
                      ? "bg-cyan-950 text-cyan-300 border border-cyan-700/80 font-bold"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Network className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Visual Graph Focus</span>
                </button>
                <button
                  type="button"
                  onClick={() => setIdeLayoutMode("SPLIT_BOTH")}
                  title="Split View: View Source Code and Interactive CPG Graph Side-by-Side"
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md transition-all ${
                    ideLayoutMode === "SPLIT_BOTH"
                      ? "bg-indigo-950 text-indigo-300 border border-indigo-700/80 font-bold"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Columns className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Split View (Code + Graph)</span>
                </button>
              </div>
            </div>

            {/* Right: Audience Persona Switcher + Web Advisories + Fullscreen Graph */}
            <div className="flex items-center gap-2 flex-wrap">
              {/* Simple Non-Coder vs Pro Engineer Mode */}
              <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setAudienceMode("NON_CODER_MANAGEMENT")}
                  className={`flex items-center gap-1 px-2.5 py-1 rounded-md transition-all ${
                    audienceMode === "NON_CODER_MANAGEMENT"
                      ? "bg-emerald-950 text-emerald-300 border border-emerald-700/80 font-bold"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <GraduationCap className="w-3.5 h-3.5 text-emerald-400" />
                  <span>🎓 Simple Student / Manager</span>
                </button>
                <button
                  type="button"
                  onClick={() => setAudienceMode("TECHNICAL_ENGINEER")}
                  className={`flex items-center gap-1 px-2.5 py-1 rounded-md transition-all ${
                    audienceMode === "TECHNICAL_ENGINEER"
                      ? "bg-cyan-950 text-cyan-300 border border-cyan-700/80 font-bold"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                  <span>⚡ Pro Engineer</span>
                </button>
              </div>

              <button
                type="button"
                onClick={() => {
                  setSidebarCollapsed(false);
                  setActiveSidebarTab("SITE_EXTRACTOR");
                }}
                title="Open Live Web Advisory & CVE Extractor in the Left Sidebar"
                className="px-2.5 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-xs font-medium text-indigo-300 flex items-center gap-1.5 transition-colors"
              >
                <Globe className="w-3.5 h-3.5 text-indigo-400" />
                <span className="hidden lg:inline">Web Advisories</span>
              </button>

              <button
                type="button"
                onClick={() => setGraphFullscreen(true)}
                title="Open Full-Screen Graph Presentation Mode"
                className="px-2.5 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-xs font-medium text-cyan-300 flex items-center gap-1.5 transition-colors"
              >
                <Maximize2 className="w-3.5 h-3.5 text-cyan-400" />
                <span className="hidden lg:inline">Full-Screen Graph</span>
              </button>
            </div>
          </div>

          {/* Main Workspace Panes */}
          <main className="flex-1 flex overflow-hidden">
            {/* Left Pane: Collapsible Flaw & Architecture Explorer Sidebar */}
            {!isSidebarCollapsed && <FlawExplorerSidebar />}

            {/* Center Pane: Monaco Source Viewer & Plain-English Storyboard */}
            {(ideLayoutMode === "SPLIT_BOTH" || ideLayoutMode === "CODE_FOCUS") && (
              <section className="flex-1 min-w-[340px] h-full overflow-hidden">
                <MonacoCodePane />
              </section>
            )}

            {/* Right Pane: ReactFlow Interactive CPG Graph & 360° Spider Map */}
            {(ideLayoutMode === "SPLIT_BOTH" || ideLayoutMode === "GRAPH_FOCUS") && (
              <section className="flex-1 min-w-[380px] h-full overflow-hidden">
                <ReactFlowGraphPane />
              </section>
            )}
          </main>
        </div>
      )}

      {/* Global Enterprise Modals (Quick Find Ctrl+K, Gear Icon Settings & Integration Hub) */}
      <QuickCommandModal />
      <SettingsCustomizationModal />
      <IntegrationHubModal />
    </div>
  );
}
