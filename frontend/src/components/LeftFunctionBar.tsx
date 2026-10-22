"use client";

import React from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  Code2,
  ShieldAlert,
  Sliders,
  Users,
  FolderGit2,
  BarChart3,
  Scale,
  Layers,
  KeyRound,
  PhoneCall,
  Compass,
  PanelLeftClose,
  PanelLeftOpen,
  Command,
  Ticket,
  Settings,
} from "lucide-react";
import { WorkspaceViewMode } from "@/types/cpg";

export const LeftFunctionBar: React.FC = () => {
  const {
    workspaceViewMode,
    setWorkspaceViewMode,
    graphViewMode,
    setGraphViewMode,
    ideLayoutMode,
    setIdeLayoutMode,
    findings,
    projects,
    platformSettings,
    userAccountsState,
    filterSecretsOnly,
    setFilterSecretsOnly,
    isSidebarCollapsed,
    setSidebarCollapsed,
    setQuickCommandOpen,
    setIntegrationModalOpen,
    setSettingsModalOpen,
  } = useAuditStore();

  const secretFindingsCount = findings.filter(
    (f) =>
      f.is_secret_finding ||
      (f.rule_id || "").toUpperCase().includes("SECRET") ||
      f.cwe_id === "CWE-798"
  ).length;

  const enabledRulesCount =
    platformSettings?.queries?.filter((q) => q.enabled).length || 0;
  const totalRulesCount = platformSettings?.queries?.length || 0;
  const accountsCount = userAccountsState?.accounts?.length || 3;

  const primaryItems: Array<{
    id: WorkspaceViewMode;
    shortLabel: string;
    title: string;
    icon: React.ReactNode;
    badge?: string | number;
    badgeColor?: string;
    accentColor: string;
  }> = [
    {
      id: "REMEDIATION_IDE",
      shortLabel: "Review",
      title: "Code & CPG Review Workbench (AST / CFG / DFG / Call / Entrypoints)",
      icon: <Code2 className="w-4 h-4" />,
      badge: findings.length,
      badgeColor: "bg-red-500/20 text-red-300 border-red-500/40",
      accentColor: "amber",
    },
    {
      id: "THREAT_MODELING",
      shortLabel: "Threats",
      title: "Threat Modeling Workspace (STRIDE, Trust Boundaries, Attack Surface & Secret Keys Vault)",
      icon: <ShieldAlert className="w-4 h-4" />,
      badge: "STRIDE",
      badgeColor: "bg-rose-500/20 text-rose-300 border-rose-500/40",
      accentColor: "rose",
    },
    {
      id: "RULE_ENGINE_PROFILES",
      shortLabel: "Rules",
      title: "Rule Engine & Test Profiles (Select Test Preset & Enable/Disable Individual Rules)",
      icon: <Sliders className="w-4 h-4" />,
      badge: totalRulesCount ? `${enabledRulesCount}/${totalRulesCount}` : "PROFILES",
      badgeColor: "bg-cyan-500/20 text-cyan-300 border-cyan-500/40",
      accentColor: "cyan",
    },
    {
      id: "USER_PROFILES",
      shortLabel: "Accounts",
      title: "User Profiling, RBAC & Multi-Tenant Account Separation",
      icon: <Users className="w-4 h-4" />,
      badge: `${accountsCount} Accts`,
      badgeColor: "bg-violet-500/20 text-violet-300 border-violet-500/40",
      accentColor: "violet",
    },
    {
      id: "PROJECTS_HUB",
      shortLabel: "Projects",
      title: "Projects Hub & Multi-Repo CI/CD Webhooks",
      icon: <FolderGit2 className="w-4 h-4" />,
      badge: projects.length || undefined,
      badgeColor: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
      accentColor: "emerald",
    },
    {
      id: "DEEP_DIVE",
      shortLabel: "Analytics",
      title: "Deep Dive Analytics, SLA Aging & OWASP / PCI-DSS / SOC2 Compliance",
      icon: <BarChart3 className="w-4 h-4" />,
      accentColor: "indigo",
    },
    {
      id: "RACI_GOVERNANCE",
      shortLabel: "RACI",
      title: "RACI Governance & Accountability Matrix",
      icon: <Scale className="w-4 h-4" />,
      accentColor: "amber",
    },
    {
      id: "SAST_PLUS_SUITE",
      shortLabel: "ASPM",
      title: "SAST++++++ ASPM Suite (Plain-English Translator, Live SBOM & Remediation Roadmap)",
      icon: <Layers className="w-4 h-4" />,
      accentColor: "purple",
    },
  ];

  return (
    <aside
      aria-label="Side Function Bar"
      className="w-[68px] shrink-0 bg-[#080b12] border-r border-slate-800/90 flex flex-col items-center justify-between py-2 select-none z-40 shadow-xl"
    >
      {/* Top Primary Workspaces */}
      <div className="flex flex-col items-center gap-1 w-full px-1.5">
        <div className="text-[8px] font-extrabold uppercase tracking-widest text-slate-500 mb-0.5">
          Modules
        </div>

        {primaryItems.map((item) => {
          const isActive = workspaceViewMode === item.id;
          return (
            <button
              key={item.id}
              onClick={() => {
                setWorkspaceViewMode(item.id);
                if (item.id === "REMEDIATION_IDE" && filterSecretsOnly) {
                  setFilterSecretsOnly(false);
                }
              }}
              title={item.title}
              className={`group relative w-full py-1.5 px-1 rounded-lg flex flex-col items-center justify-center gap-0.5 transition-all border ${
                isActive
                  ? "bg-amber-500/15 text-amber-300 border-amber-500/50 shadow-sm shadow-amber-950/50"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-900/90 border-transparent"
              }`}
            >
              {isActive && (
                <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-r bg-amber-400" />
              )}
              <div className="relative flex items-center justify-center">
                {item.icon}
              </div>
              <span className="text-[9px] font-bold tracking-tight leading-tight text-center truncate w-full">
                {item.shortLabel}
              </span>
              {item.badge !== undefined && (
                <span
                  className={`text-[8px] font-mono font-extrabold px-1 py-0 rounded border leading-tight ${
                    item.badgeColor ||
                    "bg-slate-800 text-slate-300 border-slate-700"
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}

        {/* Divider: Quick Graph & Secret Hunters */}
        <div className="w-9 h-px bg-slate-800/90 my-1" />
        <div className="text-[8px] font-extrabold uppercase tracking-widest text-slate-500">
          Direct
        </div>

        {/* Secret Keys Filter Quick Button */}
        <button
          onClick={() => {
            const nextState = !filterSecretsOnly;
            setFilterSecretsOnly(nextState);
            setWorkspaceViewMode("REMEDIATION_IDE");
            if (isSidebarCollapsed) setSidebarCollapsed(false);
          }}
          title={`Secret Keys Hunter (${secretFindingsCount} detected keys) — Click to filter Secret Keys & Credentials`}
          className={`w-full py-1.5 px-1 rounded-lg flex flex-col items-center justify-center gap-0.5 transition-all border ${
            filterSecretsOnly && workspaceViewMode === "REMEDIATION_IDE"
              ? "bg-amber-500/25 text-amber-200 border-amber-400/70 shadow-sm"
              : "text-amber-400/80 hover:text-amber-300 hover:bg-amber-950/30 border-transparent"
          }`}
        >
          <KeyRound className="w-3.5 h-3.5" />
          <span className="text-[9px] font-bold leading-tight">Secrets</span>
          <span className="text-[8px] font-mono font-extrabold px-1 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
            {secretFindingsCount}
          </span>
        </button>

        {/* Call Graph Quick Launch */}
        <button
          onClick={() => {
            setWorkspaceViewMode("REMEDIATION_IDE");
            setGraphViewMode("CALL_GRAPH");
            if (ideLayoutMode === "CODE_FOCUS") setIdeLayoutMode("SPLIT_BOTH");
          }}
          title="Open Inter-Procedural Call Graph (:CALLS relationships)"
          className={`w-full py-1 px-1 rounded-lg flex flex-col items-center justify-center gap-0.5 transition-all border ${
            workspaceViewMode === "REMEDIATION_IDE" &&
            graphViewMode === "CALL_GRAPH"
              ? "bg-purple-500/20 text-purple-200 border-purple-500/50"
              : "text-slate-400 hover:text-purple-300 hover:bg-slate-900/80 border-transparent"
          }`}
        >
          <PhoneCall className="w-3.5 h-3.5" />
          <span className="text-[8.5px] font-bold leading-tight">Call Graph</span>
        </button>

        {/* Entry Points Graph Quick Launch */}
        <button
          onClick={() => {
            setWorkspaceViewMode("REMEDIATION_IDE");
            setGraphViewMode("ENTRYPOINT_GRAPH");
            if (ideLayoutMode === "CODE_FOCUS") setIdeLayoutMode("SPLIT_BOTH");
          }}
          title="Open Attack Surface Entry Points Graph (Routes, CLI, Sources -> Sinks)"
          className={`w-full py-1 px-1 rounded-lg flex flex-col items-center justify-center gap-0.5 transition-all border ${
            workspaceViewMode === "REMEDIATION_IDE" &&
            graphViewMode === "ENTRYPOINT_GRAPH"
              ? "bg-emerald-500/20 text-emerald-200 border-emerald-500/50"
              : "text-slate-400 hover:text-emerald-300 hover:bg-slate-900/80 border-transparent"
          }`}
        >
          <Compass className="w-3.5 h-3.5" />
          <span className="text-[8.5px] font-bold leading-tight">Entrypoints</span>
        </button>
      </div>

      {/* Bottom Utilities */}
      <div className="flex flex-col items-center gap-1 w-full px-1.5 pt-2 border-t border-slate-800/80">
        {workspaceViewMode === "REMEDIATION_IDE" && (
          <button
            onClick={() => setSidebarCollapsed(!isSidebarCollapsed)}
            title={
              isSidebarCollapsed
                ? "Expand Left Flaw Explorer Sidebar"
                : "Collapse Left Flaw Explorer Sidebar"
            }
            className={`w-full py-1.5 rounded-lg flex flex-col items-center justify-center gap-0.5 text-[9px] font-semibold border transition-colors ${
              !isSidebarCollapsed
                ? "bg-slate-900 text-amber-300 border-slate-700"
                : "text-slate-400 hover:text-slate-200 border-transparent hover:bg-slate-900/60"
            }`}
          >
            {isSidebarCollapsed ? (
              <PanelLeftOpen className="w-3.5 h-3.5" />
            ) : (
              <PanelLeftClose className="w-3.5 h-3.5" />
            )}
            <span className="text-[8px]">Explorer</span>
          </button>
        )}

        <button
          onClick={() => setIntegrationModalOpen(true)}
          title="Jira & GitHub Issues Bi-Directional Connectors"
          className="w-full py-1.5 rounded-lg flex flex-col items-center justify-center gap-0.5 text-slate-400 hover:text-indigo-300 hover:bg-slate-900/70 transition-colors"
        >
          <Ticket className="w-3.5 h-3.5" />
          <span className="text-[8px] font-semibold">Tickets</span>
        </button>

        <button
          onClick={() => setQuickCommandOpen(true)}
          title="Quick Command Palette (Ctrl+K)"
          className="w-full py-1.5 rounded-lg flex flex-col items-center justify-center gap-0.5 text-slate-400 hover:text-amber-300 hover:bg-slate-900/70 transition-colors"
        >
          <Command className="w-3.5 h-3.5" />
          <span className="text-[8px] font-semibold">Ctrl+K</span>
        </button>

        <button
          onClick={() => setSettingsModalOpen(true, "GLOBAL_PROJECT")}
          title="Engine Thresholds & Custom Sanitizers"
          className="w-full py-1.5 rounded-lg flex flex-col items-center justify-center gap-0.5 text-slate-400 hover:text-cyan-300 hover:bg-slate-900/70 transition-colors"
        >
          <Settings className="w-3.5 h-3.5" />
          <span className="text-[8px] font-semibold">Config</span>
        </button>
      </div>
    </aside>
  );
};
