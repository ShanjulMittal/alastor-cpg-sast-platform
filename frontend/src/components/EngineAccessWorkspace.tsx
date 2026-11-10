"use client";

import React, { useEffect, useRef, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { EngineAccessTab, SecurityQueryRule } from "@/types/cpg";
import { RuleEngineProfilesView } from "./RuleEngineProfilesView";
import { UserAccountProfileView } from "./UserAccountProfileView";
import {
  Sliders,
  Code2,
  Users,
  Ticket,
  ShieldCheck,
  Plus,
  Wrench,
  CheckCircle2,
  RefreshCw,
  ExternalLink,
  Settings,
  Database,
  ArrowUpRight,
} from "lucide-react";

export const EngineAccessWorkspace: React.FC = () => {
  const engineAccessTab = useAuditStore((s) => s.engineAccessTab);
  const setEngineAccessTab = useAuditStore((s) => s.setEngineAccessTab);
  const platformSettings = useAuditStore((s) => s.platformSettings);
  const fetchPlatformSettings = useAuditStore((s) => s.fetchPlatformSettings);
  const updatePlatformSettings = useAuditStore((s) => s.updatePlatformSettings);
  const toggleQueryRule = useAuditStore((s) => s.toggleQueryRule);
  const addCustomSanitizer = useAuditStore((s) => s.addCustomSanitizer);
  const toggleCustomSanitizer = useAuditStore((s) => s.toggleCustomSanitizer);
  const setSettingsModalOpen = useAuditStore((s) => s.setSettingsModalOpen);

  const userAccountsState = useAuditStore((s) => s.userAccountsState);
  const fetchUserAccounts = useAuditStore((s) => s.fetchUserAccounts);

  const integrationState = useAuditStore((s) => s.integrationState);
  const fetchIntegrations = useAuditStore((s) => s.fetchIntegrations);
  const autoSyncTickets = useAuditStore((s) => s.autoSyncTickets);
  const updateTicket = useAuditStore((s) => s.updateTicket);
  const setIntegrationModalOpen = useAuditStore(
    (s) => s.setIntegrationModalOpen
  );
  const findings = useAuditStore((s) => s.findings);
  const selectFinding = useAuditStore((s) => s.selectFinding);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);

  // Cypher & Sanitizer Inline Studio State
  const [selectedRuleId, setSelectedRuleId] = useState<string>("");
  const [sanName, setSanName] = useState("");
  const [sanLang, setSanLang] = useState("Python");
  const [sanCwe, setSanCwe] = useState("CWE-78");
  const [sanDesc, setSanDesc] = useState("");
  const [statusBanner, setStatusBanner] = useState<string | null>(null);
  const [isSyncingTickets, setIsSyncingTickets] = useState(false);
  const bannerTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showTransientBanner = (msg: string, ms = 3500) => {
    if (bannerTimerRef.current) {
      clearTimeout(bannerTimerRef.current);
    }
    setStatusBanner(msg);
    bannerTimerRef.current = setTimeout(() => {
      setStatusBanner(null);
      bannerTimerRef.current = null;
    }, ms);
  };

  useEffect(() => {
    return () => {
      if (bannerTimerRef.current) {
        clearTimeout(bannerTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (!platformSettings) fetchPlatformSettings();
    if (!userAccountsState) fetchUserAccounts();
    if (!integrationState) fetchIntegrations();
  }, [
    platformSettings,
    userAccountsState,
    integrationState,
    fetchPlatformSettings,
    fetchUserAccounts,
    fetchIntegrations,
  ]);

  const queries = platformSettings?.queries || [];
  const sanitizers = platformSettings?.custom_sanitizers || [];
  const enabledRulesCount = queries.filter((q) => q.enabled).length;
  const totalRulesCount = queries.length || 18;
  const maxDfgDepth = platformSettings?.max_dfg_depth ?? 12;

  const selectedRule: SecurityQueryRule | null =
    queries.find((q) => q.id === selectedRuleId) || queries[0] || null;

  const accountsCount = userAccountsState?.accounts?.length ?? 0;
  const usersCount = userAccountsState?.users?.length ?? 0;
  const tickets = integrationState?.tickets || [];
  const connectorCfg = integrationState?.config;

  const handleRegisterSanitizer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sanName.trim()) return;
    await addCustomSanitizer({
      function_name: sanName.trim(),
      language: sanLang,
      target_cwe: sanCwe,
      description:
        sanDesc.trim() ||
        `AST-verified custom sanitizer neutralizing tainted DFG paths for ${sanCwe}`,
    });
    setSanName("");
    setSanDesc("");
    showTransientBanner(
      `Registered AST Sanitizer '${sanName.trim()}' (${sanLang} • ${sanCwe})`,
      3500
    );
  };

  const handleDfgDepthChange = async (depth: number) => {
    await updatePlatformSettings({
      scope: platformSettings?.active_scope || "GLOBAL",
      max_dfg_depth: depth,
    });
    showTransientBanner(`Updated Neo4j DFG Inter-Procedural Hop Depth to ${depth}`, 3000);
  };

  const handleAutoSyncIssues = async () => {
    setIsSyncingTickets(true);
    await autoSyncTickets();
    setIsSyncingTickets(false);
    showTransientBanner("Synchronized Issue Tracker with active CPG findings.", 3500);
  };

  const tabs: Array<{
    id: EngineAccessTab;
    label: string;
    icon: React.ReactNode;
    badge?: string | number;
  }> = [
    {
      id: "RULE_PROFILES",
      label: `1. Rule Profiles (${enabledRulesCount || 18}/${totalRulesCount})`,
      icon: <Sliders className="w-3.5 h-3.5 text-[var(--sig-gold)]" />,
    },
    {
      id: "CYPHER_SANITIZERS",
      label: "2. Sanitizer & Cypher Studio",
      icon: <Code2 className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />,
      badge: `${sanitizers.length} Sanitizers`,
    },
    {
      id: "ACCOUNTS_RBAC",
      label: "3. Multi-Tenant RBAC",
      icon: <Users className="w-3.5 h-3.5 text-[var(--sig-emerald)]" />,
      badge: accountsCount ? `${accountsCount} Tenants · ${usersCount} Users` : undefined,
    },
    {
      id: "ISSUE_CONNECTORS",
      label: "4. Jira & GitHub Sync",
      icon: <Ticket className="w-3.5 h-3.5 text-[var(--sig-gold)]" />,
      badge: tickets.length,
    },
  ];

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden bg-[var(--surface-void)] text-[var(--ink-primary)]">
      {/* Sleek 38px Studio Sub-Navigation Bar */}
      <nav
        aria-label="Engine & Access Sub-Navigation"
        className="h-[38px] px-3 bg-[var(--surface-panel)] border-b border-[var(--border-hairline)] flex items-center justify-between gap-2 shrink-0 overflow-x-auto select-none"
      >
        <div className="flex items-center gap-1 min-w-max">
          {tabs.map((tab) => {
            const isActive = engineAccessTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setEngineAccessTab(tab.id)}
                className={`h-7 px-2.5 rounded-md text-[11px] font-semibold flex items-center gap-1.5 transition-all border ${
                  isActive
                    ? "bg-[var(--surface-elevated)] text-[var(--ink-primary)] border-[var(--sig-gold)]/60 shadow-sm"
                    : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)] hover:bg-[var(--surface-elevated)] border-transparent"
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
                {tab.badge !== undefined && (
                  <span
                    className={`px-1.5 py-0 rounded text-[9.5px] font-mono font-bold border ${
                      isActive
                        ? "bg-[var(--surface-void)] text-[var(--sig-gold)] border-[var(--sig-gold)]/40"
                        : "bg-[var(--surface-void)] text-[var(--ink-muted)] border-[var(--border-hairline)]"
                    }`}
                  >
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Right: Quick Modal Launchers */}
        <div className="hidden lg:flex items-center gap-2 shrink-0 font-mono text-[10px]">
          <button
            type="button"
            onClick={() => setSettingsModalOpen(true, "QUERY_VIEWER")}
            className="px-2.5 py-1 rounded-md bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--sig-cyan)] font-semibold flex items-center gap-1 transition-colors"
          >
            <Settings className="w-3 h-3" />
            <span>Full Query &amp; Threshold Modal</span>
          </button>

          <button
            type="button"
            onClick={() => setIntegrationModalOpen(true)}
            className="px-2.5 py-1 rounded-md bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--sig-gold)] font-semibold flex items-center gap-1 transition-colors"
          >
            <Ticket className="w-3 h-3" />
            <span>Configure Connectors</span>
          </button>
        </div>
      </nav>

      {statusBanner && (
        <div className="px-4 py-1.5 bg-[var(--surface-elevated)] border-b border-[var(--sig-emerald)]/50 text-[var(--sig-emerald)] text-xs font-mono flex items-center gap-2 shrink-0">
          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
          <span>{statusBanner}</span>
        </div>
      )}

      {/* Active Sub-Workspace Content */}
      <div className="flex-1 flex min-w-0 min-h-0 overflow-hidden">
        {engineAccessTab === "RULE_PROFILES" ? (
          <RuleEngineProfilesView />
        ) : engineAccessTab === "ACCOUNTS_RBAC" ? (
          <UserAccountProfileView />
        ) : engineAccessTab === "CYPHER_SANITIZERS" ? (
          /* INLINE SANITIZER & NEO4J CYPHER STUDIO */
          <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-[var(--surface-void)]">
            {/* Top Header & DFG Depth Controls */}
            <div className="p-4 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-hairline)] flex items-center justify-between gap-4 flex-wrap">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Database className="w-4 h-4 text-[var(--sig-cyan)]" />
                  <h2 className="text-sm font-bold text-[var(--ink-primary)]">
                    Neo4j Cypher Rule Inspector &amp; AST Sanitizer Workbench
                  </h2>
                  <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[10px] font-mono text-[var(--sig-emerald)]">
                    0% FP TAINT ENGINE
                  </span>
                </div>
                <p className="text-xs text-[var(--ink-muted)]">
                  Inspect live Neo4j Cypher traversal queries across AST/CFG/DFG edges, tune inter-procedural DFG hop depth, and register custom codebase sanitizer functions.
                </p>
              </div>

              <div className="flex items-center gap-3 flex-wrap">
                <div className="flex items-center gap-2 bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-lg px-3 py-1.5 text-xs font-mono">
                  <span className="text-[var(--ink-muted)]">Max DFG Hops:</span>
                  {[8, 12, 16, 24].map((hop) => (
                    <button
                      key={hop}
                      type="button"
                      onClick={() => handleDfgDepthChange(hop)}
                      className={`px-2 py-0.5 rounded text-[11px] font-bold transition-colors ${
                        maxDfgDepth === hop
                          ? "bg-[var(--surface-elevated)] text-[var(--sig-gold)] border border-[var(--sig-gold)]/60"
                          : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                      }`}
                    >
                      {hop}
                    </button>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={() => setSettingsModalOpen(true, "CUSTOMIZATION")}
                  className="px-3 py-1.5 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--sig-cyan)]/60 text-[var(--sig-cyan)] text-xs font-semibold flex items-center gap-1.5"
                >
                  <Wrench className="w-3.5 h-3.5" />
                  <span>Open Full Query Authoring Modal</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* Left 7 Cols: Neo4j Cypher Query Inspector */}
              <div className="lg:col-span-7 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-hairline)] p-4 space-y-3 flex flex-col">
                <div className="flex items-center justify-between gap-2 border-b border-[var(--border-hairline)] pb-2.5">
                  <div className="text-xs font-bold text-[var(--ink-primary)] flex items-center gap-2">
                    <Code2 className="w-4 h-4 text-[var(--sig-cyan)]" />
                    <span>Compiled Neo4j Cypher Security Queries ({queries.length})</span>
                  </div>
                  <select
                    aria-label="Select Security Query Rule"
                    value={selectedRule?.id || ""}
                    onChange={(e) => setSelectedRuleId(e.target.value)}
                    className="bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-lg px-2.5 py-1 text-xs font-mono text-[var(--ink-primary)]"
                  >
                    {queries.map((q) => (
                      <option key={q.id} value={q.id}>
                        {q.id} — {q.name} ({q.cwe_id})
                      </option>
                    ))}
                  </select>
                </div>

                {selectedRule ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--sig-gold)]/50 text-[var(--sig-gold)] font-mono text-[10px] font-bold">
                          {selectedRule.id}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--sig-cyan)] font-mono text-[10px]">
                          {selectedRule.engine} • {selectedRule.language} • {selectedRule.cwe_id}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-muted)] font-mono text-[10px]">
                          CVSS {selectedRule.cvss_score}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => toggleQueryRule(selectedRule.id)}
                        className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold border ${
                          selectedRule.enabled
                            ? "bg-[var(--surface-elevated)] text-[var(--sig-emerald)] border-[var(--sig-emerald)]/60"
                            : "bg-[var(--surface-void)] text-[var(--ink-muted)] border-[var(--border-hairline)]"
                        }`}
                      >
                        {selectedRule.enabled ? "✓ ENABLED" : "DISABLED"}
                      </button>
                    </div>

                    <p className="text-xs text-[var(--ink-muted)] leading-relaxed">
                      {selectedRule.description}
                    </p>

                    <div className="space-y-1">
                      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--sig-cyan)] font-bold">
                        Underlying Neo4j CPG Traversal Query (Cypher)
                      </div>
                      <pre className="p-3 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)] font-mono text-[11px] text-[var(--sig-cyan)] overflow-x-auto leading-relaxed">
                        {selectedRule.cypher}
                      </pre>
                    </div>

                    <div className="p-2.5 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)] text-xs text-[var(--ink-muted)]">
                      <strong className="text-[var(--sig-emerald)]">BFL Remediation Guidance: </strong>
                      {selectedRule.remediation}
                    </div>
                  </div>
                ) : (
                  <div className="text-xs font-mono text-[var(--ink-muted)] py-6 text-center">
                    Loading compiled CPG queries...
                  </div>
                )}
              </div>

              {/* Right 5 Cols: Custom AST Sanitizer Registration */}
              <div className="lg:col-span-5 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-hairline)] p-4 space-y-3 flex flex-col">
                <div className="flex items-center justify-between border-b border-[var(--border-hairline)] pb-2.5">
                  <div className="text-xs font-bold text-[var(--ink-primary)] flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-[var(--sig-emerald)]" />
                    <span>Custom AST Sanitizers ({sanitizers.length})</span>
                  </div>
                  <span className="text-[10px] font-mono text-[var(--sig-emerald)]">
                    Sever DFG Paths Automatically
                  </span>
                </div>

                <form onSubmit={handleRegisterSanitizer} className="space-y-2.5">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    <input
                      type="text"
                      value={sanName}
                      onChange={(e) => setSanName(e.target.value)}
                      placeholder="Function (e.g. sanitize_sql)"
                      className="sm:col-span-1 bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-lg px-2.5 py-1.5 text-xs font-mono text-[var(--ink-primary)]"
                    />
                    <select
                      aria-label="Sanitizer Language"
                      value={sanLang}
                      onChange={(e) => setSanLang(e.target.value)}
                      className="bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-lg px-2 py-1.5 text-xs font-mono text-[var(--ink-primary)]"
                    >
                      <option value="Python">Python</option>
                      <option value="TypeScript">TypeScript / JS</option>
                      <option value="Go">Go</option>
                      <option value="Rust">Rust</option>
                    </select>
                    <input
                      type="text"
                      value={sanCwe}
                      onChange={(e) => setSanCwe(e.target.value)}
                      placeholder="CWE-78"
                      className="bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-lg px-2.5 py-1.5 text-xs font-mono text-[var(--ink-primary)]"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={sanDesc}
                      onChange={(e) => setSanDesc(e.target.value)}
                      placeholder="Rationale (why this function neutralizes taint)..."
                      className="flex-1 bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--ink-primary)]"
                    />
                    <button
                      type="submit"
                      className="px-3 py-1.5 rounded-lg bg-[var(--sig-emerald)] text-white text-xs font-bold flex items-center gap-1 shrink-0"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      <span>Register</span>
                    </button>
                  </div>
                </form>

                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {sanitizers.map((san) => (
                    <div
                      key={san.id}
                      className="p-2.5 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)] flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-[var(--sig-emerald)]">
                            {san.function_name}()
                          </span>
                          <span className="text-[10px] font-mono text-[var(--ink-muted)]">
                            {san.language} • {san.target_cwe}
                          </span>
                        </div>
                        <p className="text-[11px] text-[var(--ink-muted)] truncate">
                          {san.description}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => toggleCustomSanitizer(san.id)}
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border shrink-0 ${
                          san.active
                            ? "bg-[var(--surface-elevated)] text-[var(--sig-emerald)] border-[var(--sig-emerald)]/50"
                            : "bg-[var(--surface-panel)] text-[var(--ink-muted)] border-[var(--border-hairline)]"
                        }`}
                      >
                        {san.active ? "ACTIVE" : "PAUSED"}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ) : (
          /* INLINE JIRA & GITHUB ISSUE CONNECTOR HUB */
          <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-[var(--surface-void)]">
            <div className="p-4 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-hairline)] flex items-center justify-between gap-4 flex-wrap">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Ticket className="w-4 h-4 text-[var(--sig-gold)]" />
                  <h2 className="text-sm font-bold text-[var(--ink-primary)]">
                    Jira &amp; GitHub Issues Bi-Directional Remediation Sync
                  </h2>
                </div>
                <p className="text-xs text-[var(--ink-muted)]">
                  Track remediation tickets linked to Best Fix Locations (BFL) and synchronize triage status with Jira Cloud or GitHub Issues.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={isSyncingTickets}
                  onClick={handleAutoSyncIssues}
                  className="px-3 py-1.5 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--sig-emerald)]/50 text-[var(--sig-emerald)] text-xs font-bold flex items-center gap-1.5 disabled:opacity-50"
                >
                  <RefreshCw
                    className={`w-3.5 h-3.5 ${isSyncingTickets ? "animate-spin" : ""}`}
                  />
                  <span>Auto-Generate Tickets for Active Flaws</span>
                </button>
                <button
                  type="button"
                  onClick={() => setIntegrationModalOpen(true)}
                  className="px-3.5 py-1.5 rounded-lg bg-[var(--sig-gold)] text-black text-xs font-bold flex items-center gap-1.5"
                >
                  <Settings className="w-3.5 h-3.5" />
                  <span>Configure / Create Ticket</span>
                </button>
              </div>
            </div>

            {/* Connector Status Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-hairline)] flex items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="text-xs font-bold text-[var(--ink-primary)] flex items-center gap-2">
                    <span>Jira Software / Cloud Connector</span>
                    <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[10px] font-mono text-[var(--sig-cyan)]">
                      Key: {connectorCfg?.jira_project_key || "SEC"}
                    </span>
                  </div>
                  <p className="text-[11px] font-mono text-[var(--ink-muted)]">
                    {connectorCfg?.jira_url || "Local Tracker Mode (Click Configure to attach Jira REST URL)"}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setIntegrationModalOpen(true)}
                  className="px-2.5 py-1 rounded-lg bg-[var(--surface-elevated)] border border-[var(--border-hairline)] text-xs font-mono text-[var(--sig-cyan)] flex items-center gap-1 shrink-0"
                >
                  <span>Settings</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              </div>

              <div className="p-4 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-hairline)] flex items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="text-xs font-bold text-[var(--ink-primary)] flex items-center gap-2">
                    <span>GitHub Issues Connector</span>
                    <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[10px] font-mono text-[var(--sig-emerald)]">
                      BFL Labels Ready
                    </span>
                  </div>
                  <p className="text-[11px] font-mono text-[var(--ink-muted)]">
                    {connectorCfg?.github_repo || "Local Tracker Mode (Click Configure to attach owner/repo)"}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setIntegrationModalOpen(true)}
                  className="px-2.5 py-1 rounded-lg bg-[var(--surface-elevated)] border border-[var(--border-hairline)] text-xs font-mono text-[var(--sig-emerald)] flex items-center gap-1 shrink-0"
                >
                  <span>Settings</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              </div>
            </div>

            {/* Ticket Table */}
            <div className="rounded-xl bg-[var(--surface-panel)] border border-[var(--border-hairline)] overflow-hidden">
              <div className="px-4 py-2.5 border-b border-[var(--border-hairline)] flex items-center justify-between">
                <span className="text-xs font-bold text-[var(--ink-primary)]">
                  Active Remediation Tickets ({tickets.length})
                </span>
                <span className="text-[10px] font-mono text-[var(--ink-muted)]">
                  Bi-Directional Triage Sync Enabled
                </span>
              </div>

              {tickets.length === 0 ? (
                <div className="p-8 text-center space-y-2">
                  <p className="text-xs text-[var(--ink-muted)] font-mono">
                    No remediation tickets generated yet for the active scan.
                  </p>
                  <button
                    type="button"
                    onClick={handleAutoSyncIssues}
                    className="px-3 py-1.5 rounded-lg bg-[var(--surface-elevated)] border border-[var(--sig-gold)]/50 text-[var(--sig-gold)] text-xs font-bold"
                  >
                    Generate Tickets From Active Findings
                  </button>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="bg-[var(--surface-void)] border-b border-[var(--border-hairline)] text-[10px] font-mono uppercase text-[var(--ink-muted)]">
                        <th className="p-3">Ticket Key</th>
                        <th className="p-3">Provider</th>
                        <th className="p-3">Vulnerability &amp; BFL</th>
                        <th className="p-3">Location</th>
                        <th className="p-3">Status</th>
                        <th className="p-3">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border-hairline)]">
                      {tickets.map((t) => {
                        const linkedF = findings.find((f) => f.id === t.finding_id);
                        return (
                          <tr
                            key={t.id}
                            className="hover:bg-[var(--surface-elevated)] transition-colors"
                          >
                            <td className="p-3 font-mono font-bold text-[var(--sig-gold)]">
                              {t.ticket_key}
                            </td>
                            <td className="p-3 font-mono text-[11px] text-[var(--ink-muted)]">
                              {t.provider}
                            </td>
                            <td className="p-3">
                              <div className="font-semibold text-[var(--ink-primary)]">
                                {t.finding_title}
                              </div>
                              <div className="text-[11px] text-[var(--ink-muted)] truncate max-w-md">
                                {t.bfl_summary}
                              </div>
                            </td>
                            <td className="p-3 font-mono text-[var(--sig-cyan)]">
                              {t.filepath}:L{t.line}
                            </td>
                            <td className="p-3">
                              <select
                                aria-label={`Status for ticket ${t.ticket_key}`}
                                value={t.status}
                                onChange={(e) =>
                                  updateTicket(t.id, {
                                    status: e.target.value as
                                      | "OPEN"
                                      | "IN_PROGRESS"
                                      | "RESOLVED",
                                  })
                                }
                                className="bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded px-2 py-1 text-[11px] font-mono text-[var(--ink-primary)]"
                              >
                                <option value="OPEN">OPEN</option>
                                <option value="IN_PROGRESS">IN_PROGRESS</option>
                                <option value="RESOLVED">RESOLVED</option>
                              </select>
                            </td>
                            <td className="p-3">
                              {linkedF ? (
                                <button
                                  type="button"
                                  onClick={() => {
                                    selectFinding(linkedF);
                                    setWorkspaceViewMode("REMEDIATION_IDE");
                                  }}
                                  className="px-2.5 py-1 rounded bg-[var(--surface-void)] hover:bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[var(--sig-emerald)] font-mono text-[10px] font-bold flex items-center gap-1"
                                >
                                  <span>Inspect in IDE</span>
                                  <ArrowUpRight className="w-3 h-3" />
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => setIntegrationModalOpen(true)}
                                  className="px-2.5 py-1 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-muted)] font-mono text-[10px]"
                                >
                                  Details
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EngineAccessWorkspace;
