"use client";

import React, { useEffect } from "react";
import dynamic from "next/dynamic";
import { StudioCommandHeader } from "@/components/StudioCommandHeader";
import { StudioStatusBar } from "@/components/StudioStatusBar";
import { ResizableSplitPane } from "@/components/ResizableSplitPane";
import { LeftFunctionBar } from "@/components/LeftFunctionBar";
import { FlawExplorerSidebar } from "@/components/FlawExplorerSidebar";
import { ProjectsHubView } from "@/components/ProjectsHubView";
import { ThreatModelingView } from "@/components/ThreatModelingView";
import { ExecutiveAspmWorkspace } from "@/components/ExecutiveAspmWorkspace";
import { EngineAccessWorkspace } from "@/components/EngineAccessWorkspace";
import { SettingsCustomizationModal } from "@/components/SettingsCustomizationModal";
import { IntegrationHubModal } from "@/components/IntegrationHubModal";
import { AlastorMythicBackground } from "@/components/AlastorBranding";
import { AlastorPortalGate } from "@/components/AlastorPortalGate";
import QuickCommandModal from "@/components/QuickCommandModal";
import { useAuditStore } from "@/store/useAuditStore";
import { WorkspaceViewMode } from "@/types/cpg";
import { Loader2 } from "lucide-react";

// Dynamically import Monaco Editor and ReactFlow Canvas with SSR disabled
// to guarantee zero hydration mismatches and prevent DOM measurement failures.
const MonacoCodePane = dynamic(
  () => import("@/components/MonacoCodePane").then((mod) => mod.MonacoCodePane),
  {
    ssr: false,
    loading: () => (
      <div className="flex flex-col items-center justify-center h-full bg-[var(--surface-void)] text-[var(--ink-muted)] font-mono text-xs gap-2">
        <Loader2 className="w-5 h-5 animate-spin text-[var(--sig-crimson)]" />
        <span>Summoning ALASTOR Source &amp; BFL Inspector...</span>
      </div>
    ),
  }
);

const ReactFlowGraphPane = dynamic(
  () =>
    import("@/components/ReactFlowGraphPane").then(
      (mod) => mod.ReactFlowGraphPane
    ),
  {
    ssr: false,
    loading: () => (
      <div className="flex flex-col items-center justify-center h-full bg-[var(--surface-void)] text-[var(--ink-muted)] font-mono text-xs gap-2">
        <Loader2 className="w-5 h-5 animate-spin text-[var(--sig-gold)]" />
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
  const isSidebarCollapsed = useAuditStore((s) => s.isSidebarCollapsed);
  const explorerWidth = useAuditStore((s) => s.explorerWidth);
  const setExplorerWidth = useAuditStore((s) => s.setExplorerWidth);
  const codeGraphRatio = useAuditStore((s) => s.codeGraphRatio);
  const setCodeGraphRatio = useAuditStore((s) => s.setCodeGraphRatio);
  const hydrateUiPreferences = useAuditStore((s) => s.hydrateUiPreferences);

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
    hydrateUiPreferences();
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
    hydrateUiPreferences,
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
    <div className="relative flex flex-col h-screen w-screen overflow-hidden bg-[var(--surface-void)] text-[var(--ink-primary)] select-none">
      {/* Mythological Sanctuary & Subtle Arcane CPG Watermark */}
      <AlastorMythicBackground />

      {/* 44px Precision Top Studio Command Header */}
      <StudioCommandHeader />

      {/* Main Studio Shell: 56px Left Activity Rail + Active Workspace Router */}
      <div className="relative z-10 flex-1 flex min-w-0 min-h-0 overflow-hidden">
        <LeftFunctionBar />

        {workspaceViewMode === "THREAT_MODELING" ? (
          <main className="flex-1 flex min-w-0 min-h-0 overflow-hidden">
            <ThreatModelingView />
          </main>
        ) : workspaceViewMode === "PROJECTS_HUB" ? (
          <main className="flex-1 flex min-w-0 min-h-0 overflow-hidden">
            <ProjectsHubView />
          </main>
        ) : workspaceViewMode === "EXECUTIVE_ASPM" ||
          workspaceViewMode === "DEEP_DIVE" ||
          workspaceViewMode === "RACI_GOVERNANCE" ||
          workspaceViewMode === "SAST_PLUS_SUITE" ? (
          <main className="flex-1 flex min-w-0 min-h-0 overflow-hidden">
            <ExecutiveAspmWorkspace />
          </main>
        ) : workspaceViewMode === "ENGINE_ACCESS" ||
          workspaceViewMode === "RULE_ENGINE_PROFILES" ||
          workspaceViewMode === "USER_PROFILES" ? (
          <main className="flex-1 flex min-w-0 min-h-0 overflow-hidden">
            <EngineAccessWorkspace />
          </main>
        ) : (
          <main className="flex-1 flex min-w-0 min-h-0 overflow-hidden">
            <ResizableSplitPane
              mode="fixed-left"
              leftPx={explorerWidth}
              onChangeLeftPx={setExplorerWidth}
              collapsed={isSidebarCollapsed}
              ariaLabel="Resize Flaw Explorer Sidebar"
              left={<FlawExplorerSidebar />}
              right={
                ideLayoutMode === "CODE_FOCUS" ? (
                  <MonacoCodePane />
                ) : ideLayoutMode === "GRAPH_FOCUS" ? (
                  <ReactFlowGraphPane />
                ) : (
                  <ResizableSplitPane
                    mode="ratio"
                    ratio={codeGraphRatio}
                    onChangeRatio={setCodeGraphRatio}
                    ariaLabel="Resize Code Editor and CPG Graph Split"
                    left={<MonacoCodePane />}
                    right={<ReactFlowGraphPane />}
                  />
                )
              }
            />
          </main>
        )}
      </div>

      {/* 26px Precision Bottom Studio Status Bar */}
      <StudioStatusBar />

      {/* Global Studio Modals (Ctrl+K Omnibar, Query/Sanitizer Modal & Issue Connector Modal) */}
      <QuickCommandModal />
      <SettingsCustomizationModal />
      <IntegrationHubModal />
    </div>
  );
}
