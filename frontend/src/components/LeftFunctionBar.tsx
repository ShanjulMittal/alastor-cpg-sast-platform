"use client";

import React from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  Code2,
  ShieldAlert,
  Sliders,
  FolderGit2,
  Layers,
  KeyRound,
  PhoneCall,
  PanelLeftClose,
  PanelLeftOpen,
  Command,
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
    filterSecretsOnly,
    setFilterSecretsOnly,
    isSidebarCollapsed,
    setSidebarCollapsed,
    setQuickCommandOpen,
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

  const primaryWorkspaces: Array<{
    id: WorkspaceViewMode;
    shortLabel: string;
    title: string;
    icon: React.ReactNode;
    isActive: boolean;
    badge?: string | number;
    isCriticalBadge?: boolean;
  }> = [
    {
      id: "REMEDIATION_IDE",
      shortLabel: "Workbench",
      title:
        "1. Workbench — Flaw Explorer, Monaco Editor, Live BFL DiffEditor & 7 CPG Graphs (AST/CFG/DFG/Call/Entrypoints)",
      icon: <Code2 className="w-4 h-4" />,
      isActive: workspaceViewMode === "REMEDIATION_IDE",
      badge: findings.length > 0 ? findings.length : undefined,
      isCriticalBadge: findings.length > 0,
    },
    {
      id: "THREAT_MODELING",
      shortLabel: "Threats",
      title:
        "2. Threats — STRIDE Verdict Matrix, Trust Boundary Zones, Entrypoints & Cryptographic Secret Vault",
      icon: <ShieldAlert className="w-4 h-4" />,
      isActive: workspaceViewMode === "THREAT_MODELING",
      badge: "STRIDE",
    },
    {
      id: "EXECUTIVE_ASPM",
      shortLabel: "ASPM",
      title:
        "3. ASPM — Impact Translator, CycloneDX v1.5 SBOM, API Attack Surface, Compliance Analytics, RACI Matrix & Roadmap",
      icon: <Layers className="w-4 h-4" />,
      isActive:
        workspaceViewMode === "EXECUTIVE_ASPM" ||
        workspaceViewMode === "DEEP_DIVE" ||
        workspaceViewMode === "RACI_GOVERNANCE" ||
        workspaceViewMode === "SAST_PLUS_SUITE",
    },
    {
      id: "PROJECTS_HUB",
      shortLabel: "Repos",
      title:
        "4. Repos — Local Auto-Discovery, Public/Private GitHub Import, Scan Snapshots & CI/CD Webhooks",
      icon: <FolderGit2 className="w-4 h-4" />,
      isActive: workspaceViewMode === "PROJECTS_HUB",
      badge: projects.length > 0 ? projects.length : undefined,
    },
    {
      id: "ENGINE_ACCESS",
      shortLabel: "Engine",
      title:
        "5. Engine — Rule Profiles & 21-Rule Matrix, AST Sanitizers, Multi-Tenant Accounts/RBAC & Issue Connectors",
      icon: <Sliders className="w-4 h-4" />,
      isActive:
        workspaceViewMode === "ENGINE_ACCESS" ||
        workspaceViewMode === "RULE_ENGINE_PROFILES" ||
        workspaceViewMode === "USER_PROFILES",
      badge: totalRulesCount
        ? `${enabledRulesCount}/${totalRulesCount}`
        : undefined,
    },
  ];

  return (
    <aside
      aria-label="Studio 5-Workspace Activity Rail"
      className="w-14 shrink-0 bg-[var(--surface-panel)] border-r border-[var(--border-hairline)] text-[var(--ink-primary)] flex flex-col items-center justify-between py-2 select-none z-40"
    >
      {/* Top 5 Focused Studio Workspaces */}
      <div className="flex flex-col items-center gap-1 w-full px-1">
        {primaryWorkspaces.map((item) => {
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setWorkspaceViewMode(item.id);
                if (item.id === "REMEDIATION_IDE" && filterSecretsOnly) {
                  setFilterSecretsOnly(false);
                }
              }}
              title={item.title}
              className={`group relative w-full py-1.5 px-0.5 rounded-lg flex flex-col items-center justify-center gap-0.5 transition-all border ${
                item.isActive
                  ? "bg-[var(--surface-elevated)] text-[var(--ink-primary)] border-[var(--sig-gold)]/50 shadow-sm"
                  : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)] hover:bg-[var(--surface-elevated)] border-transparent"
              }`}
            >
              {item.isActive && (
                <span className="absolute left-0 top-1.5 bottom-1.5 w-[2.5px] rounded-r bg-[var(--sig-gold)]" />
              )}
              <div
                className={`relative flex items-center justify-center ${
                  item.isActive ? "text-[var(--sig-gold)]" : ""
                }`}
              >
                {item.icon}
              </div>
              <span className="text-[8.5px] font-semibold tracking-tight leading-tight text-center truncate w-full">
                {item.shortLabel}
              </span>
              {item.badge !== undefined && (
                <span
                  className={`text-[7.5px] font-mono font-bold px-1 py-0 rounded border leading-tight ${
                    item.isCriticalBadge
                      ? "bg-[var(--surface-void)] text-[var(--sig-crimson)] border-[var(--sig-crimson)]/50"
                      : "bg-[var(--surface-void)] text-[var(--ink-muted)] border-[var(--border-hairline)]"
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Bottom Quick-Toggles & Utilities */}
      <div className="flex flex-col items-center gap-1 w-full px-1 pt-2 border-t border-[var(--border-hairline)]">
        {/* Secrets Quick Filter */}
        <button
          type="button"
          onClick={() => {
            const nextState = !filterSecretsOnly;
            setFilterSecretsOnly(nextState);
            setWorkspaceViewMode("REMEDIATION_IDE");
            if (isSidebarCollapsed) setSidebarCollapsed(false);
          }}
          title={`Secret Keys Filter (${secretFindingsCount} detected keys) — Click to filter Secret Keys & Credentials in Workbench`}
          className={`w-full py-1 px-0.5 rounded-lg flex flex-col items-center justify-center gap-0.5 transition-all border ${
            filterSecretsOnly && workspaceViewMode === "REMEDIATION_IDE"
              ? "bg-[var(--surface-elevated)] text-[var(--sig-gold)] border-[var(--sig-gold)]"
              : "text-[var(--ink-muted)] hover:text-[var(--sig-gold)] hover:bg-[var(--surface-elevated)] border-transparent"
          }`}
        >
          <KeyRound className="w-3.5 h-3.5" />
          <span className="text-[8px] font-semibold leading-tight">
            Secrets
          </span>
          {secretFindingsCount > 0 && (
            <span className="text-[7.5px] font-mono font-bold px-1 rounded bg-[var(--surface-void)] text-[var(--sig-gold)] border border-[var(--sig-gold)]/40">
              {secretFindingsCount}
            </span>
          )}
        </button>

        {/* Call Graph Quick Launch */}
        <button
          type="button"
          onClick={() => {
            setWorkspaceViewMode("REMEDIATION_IDE");
            setGraphViewMode("CALL_GRAPH");
            if (ideLayoutMode === "CODE_FOCUS") setIdeLayoutMode("SPLIT_BOTH");
          }}
          title="Open Inter-Procedural Call Graph (:CALLS relationships)"
          className={`w-full py-1 px-0.5 rounded-lg flex flex-col items-center justify-center gap-0.5 transition-all border ${
            workspaceViewMode === "REMEDIATION_IDE" &&
            graphViewMode === "CALL_GRAPH"
              ? "bg-[var(--surface-elevated)] text-[var(--sig-cyan)] border-[var(--sig-cyan)]/60"
              : "text-[var(--ink-muted)] hover:text-[var(--sig-cyan)] hover:bg-[var(--surface-elevated)] border-transparent"
          }`}
        >
          <PhoneCall className="w-3.5 h-3.5" />
          <span className="text-[8px] font-semibold leading-tight">
            Calls
          </span>
        </button>

        {/* Explorer Sidebar Collapse Toggle */}
        <button
          type="button"
          onClick={() => setSidebarCollapsed(!isSidebarCollapsed)}
          title={
            isSidebarCollapsed
              ? "Expand Left Flaw Explorer Sidebar (Shortcut: b)"
              : "Collapse Left Flaw Explorer Sidebar (Shortcut: b)"
          }
          className={`w-full py-1 px-0.5 rounded-lg flex flex-col items-center justify-center gap-0.5 text-[8px] font-semibold border transition-colors ${
            !isSidebarCollapsed && workspaceViewMode === "REMEDIATION_IDE"
              ? "bg-[var(--surface-elevated)] text-[var(--sig-gold)] border-[var(--border-hairline)]"
              : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)] border-transparent hover:bg-[var(--surface-elevated)]"
          }`}
        >
          {isSidebarCollapsed ? (
            <PanelLeftOpen className="w-3.5 h-3.5" />
          ) : (
            <PanelLeftClose className="w-3.5 h-3.5" />
          )}
          <span>Explorer</span>
        </button>

        {/* Quick Command Palette (Ctrl+K) */}
        <button
          type="button"
          onClick={() => setQuickCommandOpen(true)}
          title="Quick Command Palette (Ctrl+K)"
          className="w-full py-1 px-0.5 rounded-lg flex flex-col items-center justify-center gap-0.5 text-[var(--ink-muted)] hover:text-[var(--sig-gold)] hover:bg-[var(--surface-elevated)] transition-colors"
        >
          <Command className="w-3.5 h-3.5" />
          <span className="text-[8px] font-semibold">Ctrl+K</span>
        </button>

        {/* Engine & Sanitizer Settings */}
        <button
          type="button"
          onClick={() => setSettingsModalOpen(true, "GLOBAL_PROJECT")}
          title="Engine Thresholds & Custom Sanitizers"
          className="w-full py-1 px-0.5 rounded-lg flex flex-col items-center justify-center gap-0.5 text-[var(--ink-muted)] hover:text-[var(--sig-cyan)] hover:bg-[var(--surface-elevated)] transition-colors"
        >
          <Settings className="w-3.5 h-3.5" />
          <span className="text-[8px] font-semibold">Settings</span>
        </button>
      </div>
    </aside>
  );
};

export default LeftFunctionBar;
