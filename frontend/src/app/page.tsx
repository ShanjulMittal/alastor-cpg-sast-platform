"use client";

import React, { useEffect } from "react";
import dynamic from "next/dynamic";
import { TopMetricsBar } from "@/components/TopMetricsBar";
import { AppMenuBar } from "@/components/AppMenuBar";
import { LeftFunctionBar } from "@/components/LeftFunctionBar";
import { ActiveApplicationBanner } from "@/components/ActiveApplicationBanner";
import { FlawExplorerSidebar } from "@/components/FlawExplorerSidebar";
import { ProjectsHubView } from "@/components/ProjectsHubView";
import { DeepDiveDashboard } from "@/components/DeepDiveDashboard";
import { RaciGovernanceView } from "@/components/RaciGovernanceView";
import { SastPlusSuiteView } from "@/components/SastPlusSuiteView";
import { ThreatModelingView } from "@/components/ThreatModelingView";
import { RuleEngineProfilesView } from "@/components/RuleEngineProfilesView";
import { UserAccountProfileView } from "@/components/UserAccountProfileView";
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
  const fetchUserAccounts = useAuditStore((s) => s.fetchUserAccounts);

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
    fetchUserAccounts();
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
    fetchUserAccounts,
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

      {/* Persistent Active Application Under Review Context Banner */}
      <ActiveApplicationBanner />

      {/* Main Enterprise Shell: Left Side Function Bar + Active Workspace View */}
      <div className="relative z-10 flex-1 flex overflow-hidden">
        {/* Always-Visible Left Side Function Bar (Vertical Activity Rail) */}
        <LeftFunctionBar />

        {/* Enterprise Workspace Router */}
        {workspaceViewMode === "THREAT_MODELING" ? (
          <main className="flex-1 flex overflow-hidden">
            <ThreatModelingView />
          </main>
        ) : workspaceViewMode === "RULE_ENGINE_PROFILES" ? (
          <main className="flex-1 flex overflow-hidden">
            <RuleEngineProfilesView />
          </main>
        ) : workspaceViewMode === "USER_PROFILES" ? (
          <main className="flex-1 flex overflow-hidden">
            <UserAccountProfileView />
          </main>
        ) : workspaceViewMode === "PROJECTS_HUB" ? (
          <main className="flex-1 flex overflow-hidden">
            <ProjectsHubView />
          </main>
        ) : workspaceViewMode === "DEEP_DIVE" ? (
          <main className="flex-1 flex overflow-hidden">
            <DeepDiveDashboard />
          </main>
        ) : workspaceViewMode === "RACI_GOVERNANCE" ? (
          <main className="flex-1 flex overflow-hidden">
            <RaciGovernanceView />
          </main>
        ) : workspaceViewMode === "SAST_PLUS_SUITE" ? (
          <main className="flex-1 flex overflow-hidden">
            <SastPlusSuiteView />
          </main>
        ) : (
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Compact Workbench Layout & Focus Bar */}
            <div className="px-3 py-1 bg-zinc-950/90 border-b border-zinc-800/80 flex items-center justify-between gap-2 flex-wrap">
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  type="button"
                  onClick={() => setSidebarCollapsed(!isSidebarCollapsed)}
                  className="px-2.5 py-0.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-[11px] font-medium text-zinc-200 flex items-center gap-1.5 transition-colors"
                >
                  {isSidebarCollapsed ? (
                    <>
                      <PanelLeftOpen className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Show Explorer ({findings.length})</span>
                    </>
                  ) : (
                    <>
                      <PanelLeftClose className="w-3.5 h-3.5 text-zinc-400" />
                      <span>Hide Explorer</span>
                    </>
                  )}
                </button>

                <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 text-[11px]">
                  <button
                    type="button"
                    onClick={() => setIdeLayoutMode("CODE_FOCUS")}
                    className={`flex items-center gap-1 px-2 py-0.5 rounded-md transition-all ${
                      ideLayoutMode === "CODE_FOCUS"
                        ? "bg-emerald-950 text-emerald-300 border border-emerald-700/80 font-bold"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    <Code2 className="w-3 h-3 text-emerald-400" />
                    <span>Code Focus</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setIdeLayoutMode("GRAPH_FOCUS")}
                    className={`flex items-center gap-1 px-2 py-0.5 rounded-md transition-all ${
                      ideLayoutMode === "GRAPH_FOCUS"
                        ? "bg-cyan-950 text-cyan-300 border border-cyan-700/80 font-bold"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    <Network className="w-3 h-3 text-cyan-400" />
                    <span>Graph Focus</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setIdeLayoutMode("SPLIT_BOTH")}
                    className={`flex items-center gap-1 px-2 py-0.5 rounded-md transition-all ${
                      ideLayoutMode === "SPLIT_BOTH"
                        ? "bg-indigo-950 text-indigo-300 border border-indigo-700/80 font-bold"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    <Columns className="w-3 h-3 text-indigo-400" />
                    <span>Split (Code + Graph)</span>
                  </button>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setSidebarCollapsed(false);
                    setActiveSidebarTab("SITE_EXTRACTOR");
                  }}
                  className="px-2 py-0.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-[11px] font-medium text-indigo-300 flex items-center gap-1 transition-colors"
                >
                  <Globe className="w-3 h-3 text-indigo-400" />
                  <span>Web Advisories</span>
                </button>

                <button
                  type="button"
                  onClick={() => setGraphFullscreen(true)}
                  className="px-2 py-0.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-[11px] font-medium text-cyan-300 flex items-center gap-1 transition-colors"
                >
                  <Maximize2 className="w-3 h-3 text-cyan-400" />
                  <span>Full-Screen Graph</span>
                </button>
              </div>
            </div>

            {/* Main Workspace Panes */}
            <main className="flex-1 flex overflow-hidden">
              {!isSidebarCollapsed && <FlawExplorerSidebar />}

              {(ideLayoutMode === "SPLIT_BOTH" || ideLayoutMode === "CODE_FOCUS") && (
                <section className="flex-1 min-w-[340px] h-full overflow-hidden">
                  <MonacoCodePane />
                </section>
              )}

              {(ideLayoutMode === "SPLIT_BOTH" || ideLayoutMode === "GRAPH_FOCUS") && (
                <section className="flex-1 min-w-[380px] h-full overflow-hidden">
                  <ReactFlowGraphPane />
                </section>
              )}
            </main>
          </div>
        )}
      </div>

      {/* Global Enterprise Modals (Quick Find Ctrl+K, Gear Icon Settings & Integration Hub) */}
      <QuickCommandModal />
      <SettingsCustomizationModal />
      <IntegrationHubModal />
    </div>
  );
}
