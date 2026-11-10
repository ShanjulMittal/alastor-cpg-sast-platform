"use client";

import React, { useState, useEffect, useMemo } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  Search,
  X,
  FolderGit2,
  BarChart3,
  Shield,
  Users,
  Sparkles,
  RefreshCw,
  GitCompare,
  Settings,
  Ticket,
  Download,
  Code2,
  Network,
  Columns,
  GraduationCap,
  Cpu,
  AlertTriangle,
  FileCode2,
  Layers,
  BookOpen,
  ShieldAlert,
  Sliders,
  Compass,
  GitPullRequest,
  KeyRound,
} from "lucide-react";

interface QuickCommandItem {
  id: string;
  category:
    | "5 Studio Workspaces"
    | "ASPM & Engine Sub-Tabs"
    | "Scan & Remediation Actions"
    | "Layout & Lens"
    | "Exports & Integrations";
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  badge?: string;
  action: () => void;
}

export function QuickCommandModal() {
  const {
    isQuickCommandOpen,
    setQuickCommandOpen,
    setWorkspaceViewMode,
    setExecutiveAspmTab,
    setEngineAccessTab,
    triggerScan,
    projectPath,
    openTargetPicker,
    isDiffEditorOpen,
    setDiffEditorOpen,
    setTrackChangesPanelOpen,
    isTrackChangesMode,
    setTrackChangesMode,
    ideLayoutMode,
    setIdeLayoutMode,
    audienceMode,
    setAudienceMode,
    setSettingsModalOpen,
    setIntegrationModalOpen,
    exportAuditReport,
    findings,
    selectFinding,
    appTree,
    selectTreeFile,
    setShowPortalGate,
    setFilterSecretsOnly,
  } = useAuditStore();

  const [query, setQuery] = useState("");

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setQuickCommandOpen(!isQuickCommandOpen);
      } else if (e.key === "Escape" && isQuickCommandOpen) {
        setQuickCommandOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isQuickCommandOpen, setQuickCommandOpen]);

  const commands: QuickCommandItem[] = useMemo(
    () => [
      // 1. 5 Primary Studio Workspaces
      {
        id: "ws-workbench",
        category: "5 Studio Workspaces",
        title: "1. Workbench (Code, BFL DiffEditor & 7 CPG Graphs)",
        subtitle:
          "Inspect findings, preview surgical BFL patches, and explore AST/CFG/DFG/Call graphs",
        icon: <Code2 className="w-4 h-4 text-[var(--sig-emerald)]" />,
        badge: "Workspace 1",
        action: () => setWorkspaceViewMode("REMEDIATION_IDE"),
      },
      {
        id: "ws-threats",
        category: "5 Studio Workspaces",
        title: "2. Threats & Vault (STRIDE Matrix & Secret Vault)",
        subtitle:
          "STRIDE Verdict Matrix (OK vs Issue), Trust Boundary Zones, and Cryptographic Secret Vault",
        icon: <ShieldAlert className="w-4 h-4 text-[var(--sig-crimson)]" />,
        badge: "Workspace 2",
        action: () => setWorkspaceViewMode("THREAT_MODELING"),
      },
      {
        id: "ws-aspm",
        category: "5 Studio Workspaces",
        title: "3. Executive ASPM (Impact, SBOM, Compliance & RACI)",
        subtitle:
          "Unified 7-tab ASPM command center: Impact Translator, CycloneDX v1.5 SBOM, Analytics & RACI",
        icon: <Layers className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: "Workspace 3",
        action: () => setWorkspaceViewMode("EXECUTIVE_ASPM"),
      },
      {
        id: "ws-repos",
        category: "5 Studio Workspaces",
        title: "4. Repositories (Local Discovery & GitHub Import)",
        subtitle:
          "Switch applications, clone public/private GitHub repos, or inspect saved scan snapshots",
        icon: <FolderGit2 className="w-4 h-4 text-[var(--sig-cyan)]" />,
        badge: "Workspace 4",
        action: () => setWorkspaceViewMode("PROJECTS_HUB"),
      },
      {
        id: "ws-engine",
        category: "5 Studio Workspaces",
        title: "5. Engine & Access (Rule Profiles, Cypher, RBAC & Jira)",
        subtitle:
          "21-Rule Matrix, Neo4j Cypher & AST Sanitizers, Multi-Tenant RBAC, and Jira/GitHub Sync",
        icon: <Sliders className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: "Workspace 5",
        action: () => setWorkspaceViewMode("ENGINE_ACCESS"),
      },

      // 2. All ExecutiveAspmTab & EngineAccessTab Sub-Tabs
      {
        id: "sub-aspm-translator",
        category: "ASPM & Engine Sub-Tabs",
        title: "Plain-English Impact Translator",
        subtitle:
          "Business impact stories, non-coder analogies, and 3-step management action plans",
        icon: <GraduationCap className="w-4 h-4 text-[var(--sig-emerald)]" />,
        badge: "ASPM • Tab 1",
        action: () => setExecutiveAspmTab("TRANSLATOR"),
      },
      {
        id: "sub-aspm-sbom",
        category: "ASPM & Engine Sub-Tabs",
        title: "CycloneDX SBOM & Supply-Chain Inspector",
        subtitle:
          "Inspect live package manifests (requirements.txt, package.json) and export .cdx.json",
        icon: <Layers className="w-4 h-4 text-[var(--sig-cyan)]" />,
        badge: "ASPM • Tab 2",
        action: () => setExecutiveAspmTab("SBOM"),
      },
      {
        id: "sub-aspm-attack-surface",
        category: "ASPM & Engine Sub-Tabs",
        title: "API Attack Surface & Entrypoints",
        subtitle:
          "Inspect discovered HTTP routes, callable entrypoints, and adjacent vulnerabilities",
        icon: <Compass className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: "ASPM • Tab 3",
        action: () => setExecutiveAspmTab("ATTACK_SURFACE"),
      },
      {
        id: "sub-aspm-analytics",
        category: "ASPM & Engine Sub-Tabs",
        title: "Compliance & Analytics (OWASP / PCI-DSS / SOC2)",
        subtitle:
          "Executive posture score, SLA aging buckets, and regulatory compliance scorecards",
        icon: <BarChart3 className="w-4 h-4 text-[var(--sig-cyan)]" />,
        badge: "ASPM • Tab 4",
        action: () => setExecutiveAspmTab("ANALYTICS"),
      },
      {
        id: "sub-aspm-raci",
        category: "ASPM & Engine Sub-Tabs",
        title: "RACI Matrix & Governance Accountability",
        subtitle:
          "Assign Responsible, Accountable, Consulted, and Informed owners with PMI/COBIT validation",
        icon: <Users className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: "ASPM • Tab 5",
        action: () => setExecutiveAspmTab("RACI"),
      },
      {
        id: "sub-aspm-roadmap",
        category: "ASPM & Engine Sub-Tabs",
        title: "Remediation Roadmap (Phased Sprint Plan)",
        subtitle:
          "Prioritized Phase 1 (24-72h), Phase 2 (Sprint), and Phase 3 (Hardening) fix plan",
        icon: <Sparkles className="w-4 h-4 text-[var(--sig-emerald)]" />,
        badge: "ASPM • Tab 6",
        action: () => setExecutiveAspmTab("ROADMAP"),
      },
      {
        id: "sub-aspm-academy",
        category: "ASPM & Engine Sub-Tabs",
        title: "Security Academy & Non-Coder Glossary",
        subtitle:
          "Learn CPG, AST/CFG/DFG, BFL Chokepoints, CWE/CVE/CVSS, and SBOM fundamentals",
        icon: <BookOpen className="w-4 h-4 text-[var(--sig-crimson)]" />,
        badge: "ASPM • Tab 7",
        action: () => setExecutiveAspmTab("ACADEMY"),
      },
      {
        id: "sub-engine-rules",
        category: "ASPM & Engine Sub-Tabs",
        title: "Rule Profiles & 21-Rule Security Matrix",
        subtitle:
          "Toggle SAST, SCA, IaC, and Secret rules or switch between Optimized and Zero-Trust profiles",
        icon: <Sliders className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: "Engine • Tab 1",
        action: () => setEngineAccessTab("RULE_PROFILES"),
      },
      {
        id: "sub-engine-cypher",
        category: "ASPM & Engine Sub-Tabs",
        title: "Cypher & Sanitizer Studio",
        subtitle:
          "Inspect Neo4j Cypher taint queries, tune DFG hop depth, and register custom AST sanitizers",
        icon: <Code2 className="w-4 h-4 text-[var(--sig-cyan)]" />,
        badge: "Engine • Tab 2",
        action: () => setEngineAccessTab("CYPHER_SANITIZERS"),
      },
      {
        id: "sub-engine-accounts",
        category: "ASPM & Engine Sub-Tabs",
        title: "Multi-Tenant Accounts & RBAC",
        subtitle:
          "Manage isolated tenant accounts, operator roles, and granular RBAC permissions",
        icon: <Users className="w-4 h-4 text-[var(--sig-emerald)]" />,
        badge: "Engine • Tab 3",
        action: () => setEngineAccessTab("ACCOUNTS_RBAC"),
      },
      {
        id: "sub-engine-connectors",
        category: "ASPM & Engine Sub-Tabs",
        title: "Jira & GitHub Sync (Issue Connectors)",
        subtitle:
          "Manage remediation tickets, bi-directional triage sync, and Jira/GitHub connectors",
        icon: <Ticket className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: "Engine • Tab 4",
        action: () => setEngineAccessTab("ISSUE_CONNECTORS"),
      },

      // 3. Scan & Remediation Actions
      {
        id: "act-toggle-bfl-diff",
        category: "Scan & Remediation Actions",
        title: "Toggle BFL Patch Diff Preview (d)",
        subtitle:
          "Switch Monaco between source inspection and side-by-side Best Fix Location (BFL) DiffEditor",
        icon: <GitPullRequest className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: isDiffEditorOpen ? "Diff Active" : "Shortcut: d",
        action: () => {
          setWorkspaceViewMode("REMEDIATION_IDE");
          setDiffEditorOpen(!isDiffEditorOpen);
        },
      },
      {
        id: "act-scan-github-repo",
        category: "Scan & Remediation Actions",
        title: "Scan GitHub Repository (Public URL / Private Token)",
        subtitle:
          "Open the GitHub Repository Scanner modal for public zero-token or private PAT clones",
        icon: <FolderGit2 className="w-4 h-4 text-[var(--sig-cyan)]" />,
        badge: "GitHub Clone",
        action: () => openTargetPicker("URL"),
      },
      {
        id: "act-filter-secrets",
        category: "Scan & Remediation Actions",
        title: "Secret Vault & Hardcoded Key Filter",
        subtitle:
          "Filter Workbench Flaw Explorer to show detected API keys, tokens, and credentials",
        icon: <KeyRound className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: "Secrets",
        action: () => {
          setFilterSecretsOnly(true);
          setWorkspaceViewMode("REMEDIATION_IDE");
        },
      },
      {
        id: "scan-rescan",
        category: "Scan & Remediation Actions",
        title: "Re-Scan Active Application Now",
        subtitle: projectPath
          ? `Run fresh 7-pass CPG SAST + SCA + Secrets scan on ${projectPath}`
          : "Run fresh 7-pass CPG scan on the active target application",
        icon: <RefreshCw className="w-4 h-4 text-[var(--sig-emerald)]" />,
        badge: "7-Pass Scan",
        action: () => triggerScan(projectPath || undefined),
      },
      {
        id: "scan-track-changes-panel",
        category: "Scan & Remediation Actions",
        title: "Open Saved Scan Details & Track Changes Comparison",
        subtitle:
          "Compare current scan vs previous scan (Fixed, New, and Unchanged delta)",
        icon: <GitCompare className="w-4 h-4 text-[var(--sig-cyan)]" />,
        badge: "Delta Tracker",
        action: () => setTrackChangesPanelOpen(true),
      },
      {
        id: "scan-toggle-track-mode",
        category: "Scan & Remediation Actions",
        title: isTrackChangesMode
          ? "Disable Continuous Track Changes Badges"
          : "Enable Continuous Track Changes Badges",
        subtitle: "Toggle Fixed / New / Unchanged badges across all review views",
        icon: <GitCompare className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: isTrackChangesMode ? "Currently ON" : "Currently OFF",
        action: () => setTrackChangesMode(!isTrackChangesMode),
      },
      {
        id: "scan-portal-gate",
        category: "Scan & Remediation Actions",
        title: "Open Launch Hub (Ἀλάστωρ Portal Gate)",
        subtitle:
          "Return to the Launch Hub with Instant GitHub Quick-Scan and Saved Scan overview",
        icon: <Shield className="w-4 h-4 text-[var(--sig-gold)]" />,
        action: () => setShowPortalGate(true),
      },

      // 4. Layout & Lens
      {
        id: "layout-code-focus",
        category: "Layout & Lens",
        title: "Code & Fix Focus Layout (1)",
        subtitle: "Maximize the Monaco Code & BFL DiffEditor pane",
        icon: <Code2 className="w-4 h-4 text-[var(--sig-emerald)]" />,
        badge: ideLayoutMode === "CODE_FOCUS" ? "Active" : "Key: 1",
        action: () => {
          setWorkspaceViewMode("REMEDIATION_IDE");
          setIdeLayoutMode("CODE_FOCUS");
        },
      },
      {
        id: "layout-split-both",
        category: "Layout & Lens",
        title: "Split Code + Graph Layout (2)",
        subtitle: "Show Monaco Editor and Interactive CPG Graph side-by-side",
        icon: <Columns className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: ideLayoutMode === "SPLIT_BOTH" ? "Active" : "Key: 2",
        action: () => {
          setWorkspaceViewMode("REMEDIATION_IDE");
          setIdeLayoutMode("SPLIT_BOTH");
        },
      },
      {
        id: "layout-graph-focus",
        category: "Layout & Lens",
        title: "Visual Graph Focus Layout (3)",
        subtitle: "Maximize the interactive ReactFlow CPG & 360° Architecture Canvas",
        icon: <Network className="w-4 h-4 text-[var(--sig-cyan)]" />,
        badge: ideLayoutMode === "GRAPH_FOCUS" ? "Active" : "Key: 3",
        action: () => {
          setWorkspaceViewMode("REMEDIATION_IDE");
          setIdeLayoutMode("GRAPH_FOCUS");
        },
      },
      {
        id: "layout-audience-toggle",
        category: "Layout & Lens",
        title:
          audienceMode === "NON_CODER_MANAGEMENT"
            ? "Switch to Technical Engineer Lens"
            : "Switch to Executive / Non-Coder Lens",
        subtitle:
          "Tailor terminology and explanations for security engineers or executive leaders",
        icon:
          audienceMode === "NON_CODER_MANAGEMENT" ? (
            <Cpu className="w-4 h-4 text-[var(--sig-cyan)]" />
          ) : (
            <GraduationCap className="w-4 h-4 text-[var(--sig-gold)]" />
          ),
        badge:
          audienceMode === "NON_CODER_MANAGEMENT" ? "Executive" : "Engineer",
        action: () =>
          setAudienceMode(
            audienceMode === "NON_CODER_MANAGEMENT"
              ? "TECHNICAL_ENGINEER"
              : "NON_CODER_MANAGEMENT"
          ),
      },

      // 5. Exports & Integrations
      {
        id: "settings-presets",
        category: "Exports & Integrations",
        title: "Open Full Query & Sanitizer Customization Modal",
        subtitle:
          "Author custom Neo4j Cypher rules, tune SLA gates, and configure global overrides",
        icon: <Settings className="w-4 h-4 text-[var(--sig-cyan)]" />,
        action: () => setSettingsModalOpen(true, "PRESETS"),
      },
      {
        id: "settings-integrations",
        category: "Exports & Integrations",
        title: "Open Jira & GitHub Issues Connector Modal",
        subtitle:
          "Configure live REST connectors, test connection, and manage issue tickets",
        icon: <Ticket className="w-4 h-4 text-[var(--sig-gold)]" />,
        action: () => setIntegrationModalOpen(true),
      },
      {
        id: "export-md",
        category: "Exports & Integrations",
        title: "Export Executive & Technical Audit Report (.md)",
        subtitle:
          "Download full Markdown security audit report for the active application",
        icon: <Download className="w-4 h-4 text-[var(--sig-emerald)]" />,
        badge: "Markdown",
        action: () => exportAuditReport("markdown"),
      },
      {
        id: "export-json",
        category: "Exports & Integrations",
        title: "Export Machine-Readable Audit Data (.json)",
        subtitle: "Download structured JSON payload with all findings and metrics",
        icon: <Download className="w-4 h-4 text-[var(--sig-cyan)]" />,
        badge: "JSON",
        action: () => exportAuditReport("json"),
      },
      {
        id: "export-sarif",
        category: "Exports & Integrations",
        title: "Export OASIS SARIF v2.1.0 Report (.sarif.json)",
        subtitle:
          "Download GitHub Advanced Security / IDE compatible SARIF v2.1.0 report",
        icon: <Download className="w-4 h-4 text-[var(--sig-gold)]" />,
        badge: "SARIF",
        action: () => exportAuditReport("sarif"),
      },
    ],
    [
      projectPath,
      isDiffEditorOpen,
      isTrackChangesMode,
      ideLayoutMode,
      audienceMode,
      setWorkspaceViewMode,
      setExecutiveAspmTab,
      setEngineAccessTab,
      openTargetPicker,
      setDiffEditorOpen,
      setFilterSecretsOnly,
      triggerScan,
      setTrackChangesPanelOpen,
      setTrackChangesMode,
      setShowPortalGate,
      setIdeLayoutMode,
      setAudienceMode,
      setSettingsModalOpen,
      setIntegrationModalOpen,
      exportAuditReport,
    ]
  );

  const q = query.trim().toLowerCase();

  const filteredCommands = useMemo(() => {
    if (!q) return commands;
    return commands.filter(
      (c) =>
        c.title.toLowerCase().includes(q) ||
        c.subtitle.toLowerCase().includes(q) ||
        c.category.toLowerCase().includes(q) ||
        (c.badge && c.badge.toLowerCase().includes(q))
    );
  }, [commands, q]);

  const matchingFindings = useMemo(() => {
    if (!q) return findings.slice(0, 5);
    return findings
      .filter((f) => {
        const sinkNode = f.path_nodes?.[f.path_nodes.length - 1];
        const fp = sinkNode?.filepath || "";
        return (
          f.title.toLowerCase().includes(q) ||
          fp.toLowerCase().includes(q) ||
          (f.cwe_id || "").toLowerCase().includes(q) ||
          f.severity.toLowerCase().includes(q)
        );
      })
      .slice(0, 6);
  }, [findings, q]);

  const matchingFiles = useMemo(() => {
    if (!q || !appTree?.flat_files) return [];
    return appTree.flat_files
      .filter(
        (f) =>
          f.filepath.toLowerCase().includes(q) ||
          f.purpose.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q)
      )
      .slice(0, 5);
  }, [appTree, q]);

  if (!isQuickCommandOpen) return null;

  return (
    <div
      className="fixed inset-0 z-[180] bg-black/70 backdrop-blur-sm flex items-start justify-center pt-16 p-4"
      onClick={() => setQuickCommandOpen(false)}
    >
      <div
        className="w-full max-w-2xl bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[var(--ink-primary)] rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[80vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Header */}
        <div className="px-4 py-3 border-b border-[var(--border-hairline)] flex items-center gap-3 bg-[var(--surface-void)]">
          <Search className="w-4 h-4 text-[var(--sig-gold)] shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Jump to any workspace, sub-tab (SBOM, RACI, Rule Profiles), BFL diff (d), finding, or file..."
            className="w-full bg-transparent text-xs font-sans text-[var(--ink-primary)] placeholder:text-[var(--ink-muted)] focus:outline-none"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              className="text-[11px] font-mono text-[var(--ink-muted)] hover:text-[var(--ink-primary)] px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-hairline)]"
            >
              Clear
            </button>
          )}
          <button
            type="button"
            onClick={() => setQuickCommandOpen(false)}
            className="p-1 rounded-lg text-[var(--ink-muted)] hover:text-[var(--ink-primary)] hover:bg-[var(--surface-elevated)]"
            title="Close (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results Body */}
        <div className="flex-1 overflow-y-auto p-3 space-y-4">
          {/* Matching Findings */}
          {matchingFindings.length > 0 && (
            <div>
              <div className="px-2 pb-1.5 text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--sig-gold)] flex items-center justify-between">
                <span>Active Application Findings ({findings.length} total)</span>
                <span className="font-normal text-[var(--ink-muted)]">
                  Click to inspect in Workbench
                </span>
              </div>
              <div className="space-y-1">
                {matchingFindings.map((f) => {
                  const sinkNode = f.path_nodes?.[f.path_nodes.length - 1];
                  return (
                    <button
                      key={f.id}
                      type="button"
                      onClick={() => {
                        setWorkspaceViewMode("REMEDIATION_IDE");
                        selectFinding(f);
                        setQuickCommandOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-xl hover:bg-[var(--surface-elevated)] border border-transparent hover:border-[var(--border-hairline)] flex items-center justify-between gap-3 transition-colors"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <AlertTriangle className="w-4 h-4 text-[var(--sig-crimson)] shrink-0" />
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-[var(--ink-primary)] truncate">
                            {f.title}
                          </div>
                          <div className="text-[11px] text-[var(--ink-muted)] font-mono truncate">
                            {sinkNode?.filepath || f.rule_id}:
                            {sinkNode?.start_line || 1} • {f.cwe_id || "CWE"}
                          </div>
                        </div>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[var(--surface-void)] text-[var(--sig-crimson)] border border-[var(--sig-crimson)]/50 shrink-0">
                        {f.severity}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Matching Files */}
          {matchingFiles.length > 0 && (
            <div>
              <div className="px-2 pb-1.5 text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--sig-cyan)]">
                Matching Source Files
              </div>
              <div className="space-y-1">
                {matchingFiles.map((file) => (
                  <button
                    key={file.filepath}
                    type="button"
                    onClick={() => {
                      setWorkspaceViewMode("REMEDIATION_IDE");
                      selectTreeFile(file);
                      setQuickCommandOpen(false);
                    }}
                    className="w-full text-left px-3 py-2 rounded-xl hover:bg-[var(--surface-elevated)] border border-transparent hover:border-[var(--border-hairline)] flex items-center justify-between gap-3 transition-colors"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <FileCode2 className="w-4 h-4 text-[var(--sig-cyan)] shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-mono font-bold text-[var(--ink-primary)] truncate">
                          {file.filepath}
                        </div>
                        <div className="text-[11px] text-[var(--ink-muted)] truncate">
                          {file.purpose}
                        </div>
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[var(--surface-void)] text-[var(--ink-muted)] border border-[var(--border-hairline)] shrink-0">
                      {file.language}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Grouped Platform Commands */}
          {(
            [
              "5 Studio Workspaces",
              "ASPM & Engine Sub-Tabs",
              "Scan & Remediation Actions",
              "Layout & Lens",
              "Exports & Integrations",
            ] as const
          ).map((category) => {
            const catItems = filteredCommands.filter(
              (c) => c.category === category
            );
            if (catItems.length === 0) return null;
            return (
              <div key={category}>
                <div className="px-2 pb-1.5 text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--ink-muted)]">
                  {category}
                </div>
                <div className="space-y-1">
                  {catItems.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        item.action();
                        setQuickCommandOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-xl hover:bg-[var(--surface-elevated)] border border-transparent hover:border-[var(--border-hairline)] flex items-center justify-between gap-3 transition-colors group"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="p-2 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)] shrink-0">
                          {item.icon}
                        </div>
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-[var(--ink-primary)] group-hover:text-[var(--sig-gold)] transition-colors truncate">
                            {item.title}
                          </div>
                          <div className="text-[11px] text-[var(--ink-muted)] truncate">
                            {item.subtitle}
                          </div>
                        </div>
                      </div>
                      {item.badge && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[var(--surface-void)] text-[var(--sig-gold)] border border-[var(--border-hairline)] shrink-0">
                          {item.badge}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            );
          })}

          {filteredCommands.length === 0 &&
            matchingFindings.length === 0 &&
            matchingFiles.length === 0 && (
              <div className="py-10 text-center text-[var(--ink-muted)] text-xs font-mono">
                No matching features, findings, or files found for &ldquo;{query}
                &rdquo;.
              </div>
            )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 bg-[var(--surface-void)] border-t border-[var(--border-hairline)] flex items-center justify-between text-[10px] font-mono text-[var(--ink-muted)]">
          <span>
            Press{" "}
            <kbd className="px-1.5 py-0.5 rounded bg-[var(--surface-elevated)] text-[var(--ink-primary)] border border-[var(--border-hairline)]">
              Ctrl+K
            </kbd>{" "}
            anytime •{" "}
            <kbd className="px-1.5 py-0.5 rounded bg-[var(--surface-elevated)] text-[var(--ink-primary)] border border-[var(--border-hairline)]">
              d
            </kbd>{" "}
            BFL Diff
          </span>
          <span>ALASTOR Studio Command Omnibar</span>
        </div>
      </div>
    </div>
  );
}

export default QuickCommandModal;
