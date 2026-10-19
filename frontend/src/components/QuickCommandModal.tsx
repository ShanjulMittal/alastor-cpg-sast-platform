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
} from "lucide-react";

interface QuickCommandItem {
  id: string;
  category: "Views & Modules" | "Scan & Track Changes" | "Layout & Simplicity" | "Exports & Integrations" | "Settings & Governance";
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  badge?: string;
  action: () => void;
}

export default function QuickCommandModal() {
  const {
    isQuickCommandOpen,
    setQuickCommandOpen,
    setWorkspaceViewMode,
    setSastPlusActiveTab,
    triggerScan,
    projectPath,
    setTrackChangesPanelOpen,
    isTrackChangesMode,
    setTrackChangesMode,
    uiDensityMode,
    setUiDensityMode,
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
      // 1. Views & Modules
      {
        id: "view-projects",
        category: "Views & Modules",
        title: "1. Projects & Saved Scans Hub",
        subtitle: "View saved scan snapshots, switch applications, or register a repository",
        icon: <FolderGit2 className="w-4 h-4 text-cyan-400" />,
        badge: "Page 1",
        action: () => setWorkspaceViewMode("PROJECTS_HUB"),
      },
      {
        id: "view-deep-dive",
        category: "Views & Modules",
        title: "2. Executive Summary & Deep-Dive Analytics",
        subtitle: "Security posture score, OWASP Top 10, SANS Top 25, Fix first list & Triage",
        icon: <BarChart3 className="w-4 h-4 text-emerald-400" />,
        badge: "Page 2",
        action: () => setWorkspaceViewMode("DEEP_DIVE"),
      },
      {
        id: "view-ide",
        category: "Views & Modules",
        title: "3. Code & Graph Review Workspace",
        subtitle: "Inspect findings, code remediation patches, and CPG dataflow graphs",
        icon: <Shield className="w-4 h-4 text-amber-400" />,
        badge: "Page 3",
        action: () => setWorkspaceViewMode("REMEDIATION_IDE"),
      },
      {
        id: "view-raci",
        category: "Views & Modules",
        title: "4. RACI Governance & Role Accountability Matrix",
        subtitle: "Assign Responsible, Accountable, Consulted, and Informed owners across SDLC",
        icon: <Users className="w-4 h-4 text-purple-400" />,
        badge: "Page 4",
        action: () => setWorkspaceViewMode("RACI_GOVERNANCE"),
      },
      {
        id: "view-sast-translator",
        category: "Views & Modules",
        title: "5. SAST++++++ Plain-English Risk Translator",
        subtitle: "Business impact stories, cost of inaction, and non-technical explanations",
        icon: <Sparkles className="w-4 h-4 text-amber-400" />,
        badge: "SAST++++++",
        action: () => setSastPlusActiveTab("TRANSLATOR"),
      },
      {
        id: "view-sast-sbom",
        category: "Views & Modules",
        title: "SAST++++++ CycloneDX SBOM & Dependency Inspector",
        subtitle: "Inspect live package manifests (package.json, requirements.txt, go.mod)",
        icon: <Layers className="w-4 h-4 text-cyan-400" />,
        badge: "SBOM",
        action: () => setSastPlusActiveTab("SBOM"),
      },
      {
        id: "view-sast-attack",
        category: "Views & Modules",
        title: "SAST++++++ Live Attack Surface & Route Discovery",
        subtitle: "Inspect exposed API endpoints, file inputs, and entry vectors",
        icon: <Network className="w-4 h-4 text-rose-400" />,
        badge: "Attack Surface",
        action: () => setSastPlusActiveTab("ATTACK_SURFACE"),
      },
      {
        id: "view-sast-roadmap",
        category: "Views & Modules",
        title: "SAST++++++ Guided Remediation Sprint Roadmap",
        subtitle: "Step-by-step sprint plan prioritized by effort and risk reduction",
        icon: <BookOpen className="w-4 h-4 text-emerald-400" />,
        badge: "Roadmap",
        action: () => setSastPlusActiveTab("ROADMAP"),
      },

      // 2. Scan & Track Changes
      {
        id: "scan-rescan",
        category: "Scan & Track Changes",
        title: "Re-Scan Active Application Now",
        subtitle: projectPath
          ? `Run fresh CPG SAST + SCA + Secrets scan on ${projectPath} and compute Track Changes`
          : "Select or re-scan the active target application",
        icon: <RefreshCw className="w-4 h-4 text-emerald-400" />,
        badge: "Live Scan",
        action: () => triggerScan(projectPath || undefined),
      },
      {
        id: "scan-track-changes-panel",
        category: "Scan & Track Changes",
        title: "Open Saved Scan Details & Track Changes Comparison",
        subtitle: "Compare current scan vs previous scan (see ✅ Fixed, 🆕 New, and ⏳ Unchanged)",
        icon: <GitCompare className="w-4 h-4 text-cyan-400" />,
        badge: "Delta Tracker",
        action: () => setTrackChangesPanelOpen(true),
      },
      {
        id: "scan-toggle-track-mode",
        category: "Scan & Track Changes",
        title: isTrackChangesMode
          ? "Disable Continuous Track Changes Badges"
          : "Enable Continuous Track Changes Badges",
        subtitle: "Toggle ✅ Fixed / 🆕 New / ⏳ Unchanged badges across all review views",
        icon: <GitCompare className="w-4 h-4 text-amber-400" />,
        badge: isTrackChangesMode ? "Currently ON" : "Currently OFF",
        action: () => setTrackChangesMode(!isTrackChangesMode),
      },
      {
        id: "scan-portal-gate",
        category: "Scan & Track Changes",
        title: "Open Welcome & Saved Scan Overview Screen",
        subtitle: "View the launch portal with saved scan summary and quick start options",
        icon: <Shield className="w-4 h-4 text-cyan-400" />,
        action: () => setShowPortalGate(true),
      },

      // 3. Layout & Simplicity
      {
        id: "layout-simple-clean",
        category: "Layout & Simplicity",
        title:
          uiDensityMode === "SIMPLE_CLEAN"
            ? "Switch to Pro Detailed Toolbar View (Show All Ribbons)"
            : "Switch to Simple Clean View (Hide Extra Toolbars)",
        subtitle: "Toggle between the streamlined Simple Clean View and full multi-ribbon Pro View",
        icon: <Sparkles className="w-4 h-4 text-amber-400" />,
        badge: uiDensityMode === "SIMPLE_CLEAN" ? "Simple Active" : "Pro Active",
        action: () =>
          setUiDensityMode(uiDensityMode === "SIMPLE_CLEAN" ? "PRO_DETAILED" : "SIMPLE_CLEAN"),
      },
      {
        id: "layout-code-focus",
        category: "Layout & Simplicity",
        title: "Code & Fix Focus Layout (Hide Graph Pane)",
        subtitle: "Give full width to the Source Code Editor & Plain-English Remediation Storyboard",
        icon: <Code2 className="w-4 h-4 text-cyan-400" />,
        badge: ideLayoutMode === "CODE_FOCUS" ? "Active" : undefined,
        action: () => {
          setWorkspaceViewMode("REMEDIATION_IDE");
          setIdeLayoutMode("CODE_FOCUS");
        },
      },
      {
        id: "layout-graph-focus",
        category: "Layout & Simplicity",
        title: "Visual Graph Focus Layout (Full-Width CPG / 360° Map)",
        subtitle: "Give full width to the interactive Code Property Graph & 360° Architecture Spider",
        icon: <Network className="w-4 h-4 text-purple-400" />,
        badge: ideLayoutMode === "GRAPH_FOCUS" ? "Active" : undefined,
        action: () => {
          setWorkspaceViewMode("REMEDIATION_IDE");
          setIdeLayoutMode("GRAPH_FOCUS");
        },
      },
      {
        id: "layout-split-both",
        category: "Layout & Simplicity",
        title: "Split Code + Graph Layout (Side-by-Side)",
        subtitle: "Show both Source Code Editor and Interactive CPG Graph side-by-side",
        icon: <Columns className="w-4 h-4 text-emerald-400" />,
        badge: ideLayoutMode === "SPLIT_BOTH" ? "Active" : undefined,
        action: () => {
          setWorkspaceViewMode("REMEDIATION_IDE");
          setIdeLayoutMode("SPLIT_BOTH");
        },
      },
      {
        id: "layout-audience-toggle",
        category: "Layout & Simplicity",
        title:
          audienceMode === "NON_CODER_MANAGEMENT"
            ? "Switch to Pro Engineer Mode (AST/DFG & Technical Details)"
            : "Switch to Simple Student / Manager Mode (Plain-English Explanations)",
        subtitle: "Tailor terminology and explanations for non-coders or security engineers",
        icon:
          audienceMode === "NON_CODER_MANAGEMENT" ? (
            <Cpu className="w-4 h-4 text-cyan-400" />
          ) : (
            <GraduationCap className="w-4 h-4 text-amber-400" />
          ),
        badge: audienceMode === "NON_CODER_MANAGEMENT" ? "Simple Mode" : "Pro Engineer",
        action: () =>
          setAudienceMode(
            audienceMode === "NON_CODER_MANAGEMENT" ? "TECHNICAL_ENGINEER" : "NON_CODER_MANAGEMENT"
          ),
      },

      // 4. Settings & Governance
      {
        id: "settings-presets",
        category: "Settings & Governance",
        title: "Configure Scan Presets, Thresholds & Query Rules",
        subtitle: "Manage severity gates, 18+ language query rules, and custom sanitizers",
        icon: <Settings className="w-4 h-4 text-slate-300" />,
        action: () => setSettingsModalOpen(true, "PRESETS"),
      },
      {
        id: "settings-integrations",
        category: "Settings & Governance",
        title: "Open Jira & GitHub Issues Integration Hub",
        subtitle: "Configure live REST connectors, test connection, and manage issue tickets",
        icon: <Ticket className="w-4 h-4 text-cyan-400" />,
        action: () => setIntegrationModalOpen(true),
      },

      // 5. Exports
      {
        id: "export-md",
        category: "Exports & Integrations",
        title: "Export Executive & Technical Audit Report (.md)",
        subtitle: "Download full Markdown security audit report for the active application",
        icon: <Download className="w-4 h-4 text-emerald-400" />,
        badge: "Markdown",
        action: () => exportAuditReport("markdown"),
      },
      {
        id: "export-json",
        category: "Exports & Integrations",
        title: "Export Machine-Readable Audit Data (.json)",
        subtitle: "Download structured JSON payload with all findings and metrics",
        icon: <Download className="w-4 h-4 text-cyan-400" />,
        badge: "JSON",
        action: () => exportAuditReport("json"),
      },
      {
        id: "export-sarif",
        category: "Exports & Integrations",
        title: "Export OASIS SARIF v2.1.0 Report (.sarif.json)",
        subtitle: "Download GitHub Advanced Security / IDE compatible SARIF report",
        icon: <Download className="w-4 h-4 text-amber-400" />,
        badge: "SARIF",
        action: () => exportAuditReport("sarif"),
      },
    ],
    [
      projectPath,
      isTrackChangesMode,
      uiDensityMode,
      ideLayoutMode,
      audienceMode,
      setWorkspaceViewMode,
      setSastPlusActiveTab,
      triggerScan,
      setTrackChangesPanelOpen,
      setTrackChangesMode,
      setShowPortalGate,
      setUiDensityMode,
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
      className="fixed inset-0 z-50 bg-slate-950/75 backdrop-blur-sm flex items-start justify-center pt-16 p-4"
      onClick={() => setQuickCommandOpen(false)}
    >
      <div
        className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[80vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Header */}
        <div className="px-4 py-3.5 border-b border-slate-800 flex items-center gap-3 bg-slate-950/70">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search any feature, page, scan action, export, finding, or file... (Esc to close)"
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
          />
          {query && (
            <button
              onClick={() => setQuery("")}
              className="text-xs text-slate-400 hover:text-slate-200 px-2 py-0.5 rounded bg-slate-800"
            >
              Clear
            </button>
          )}
          <button
            onClick={() => setQuickCommandOpen(false)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
            title="Close (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results Body */}
        <div className="flex-1 overflow-y-auto p-3 space-y-4">
          {/* Matching Findings (if any exist) */}
          {matchingFindings.length > 0 && (
            <div>
              <div className="px-2 pb-1.5 text-[11px] font-bold uppercase tracking-wider text-amber-400 flex items-center justify-between">
                <span>Active Application Findings ({findings.length} total)</span>
                <span className="text-[10px] font-normal text-slate-400">Click to inspect in Code & Graph</span>
              </div>
              <div className="space-y-1">
                {matchingFindings.map((f) => {
                  const sinkNode = f.path_nodes?.[f.path_nodes.length - 1];
                  return (
                    <button
                      key={f.id}
                      onClick={() => {
                        setWorkspaceViewMode("REMEDIATION_IDE");
                        selectFinding(f);
                        setQuickCommandOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-xl hover:bg-slate-800/80 border border-transparent hover:border-slate-700 flex items-center justify-between gap-3 transition-colors"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-slate-100 truncate">
                            {f.title}
                          </div>
                          <div className="text-[11px] text-slate-400 font-mono truncate">
                            {sinkNode?.filepath || f.rule_id}:{sinkNode?.start_line || 1} • {f.cwe_id || "CWE"}
                          </div>
                        </div>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950/80 text-rose-300 border border-rose-700/50 shrink-0">
                        {f.severity}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Matching Files (when searching) */}
          {matchingFiles.length > 0 && (
            <div>
              <div className="px-2 pb-1.5 text-[11px] font-bold uppercase tracking-wider text-cyan-400">
                Matching Source Files
              </div>
              <div className="space-y-1">
                {matchingFiles.map((file) => (
                  <button
                    key={file.filepath}
                    onClick={() => {
                      setWorkspaceViewMode("REMEDIATION_IDE");
                      selectTreeFile(file);
                      setQuickCommandOpen(false);
                    }}
                    className="w-full text-left px-3 py-2 rounded-xl hover:bg-slate-800/80 border border-transparent hover:border-slate-700 flex items-center justify-between gap-3 transition-colors"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <FileCode2 className="w-4 h-4 text-cyan-400 shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-mono font-bold text-slate-100 truncate">
                          {file.filepath}
                        </div>
                        <div className="text-[11px] text-slate-400 truncate">{file.purpose}</div>
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 shrink-0">
                      {file.language}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Grouped Platform Features & Actions */}
          {(
            [
              "Views & Modules",
              "Scan & Track Changes",
              "Layout & Simplicity",
              "Settings & Governance",
              "Exports & Integrations",
            ] as const
          ).map((category) => {
            const catItems = filteredCommands.filter((c) => c.category === category);
            if (catItems.length === 0) return null;
            return (
              <div key={category}>
                <div className="px-2 pb-1.5 text-[11px] font-bold uppercase tracking-wider text-slate-400">
                  {category}
                </div>
                <div className="space-y-1">
                  {catItems.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => {
                        item.action();
                        setQuickCommandOpen(false);
                      }}
                      className="w-full text-left px-3 py-2.5 rounded-xl hover:bg-slate-800/90 border border-transparent hover:border-slate-700 flex items-center justify-between gap-3 transition-colors group"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 group-hover:border-slate-700 shrink-0">
                          {item.icon}
                        </div>
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-slate-100 group-hover:text-cyan-300 transition-colors truncate">
                            {item.title}
                          </div>
                          <div className="text-[11px] text-slate-400 truncate">{item.subtitle}</div>
                        </div>
                      </div>
                      {item.badge && (
                        <span className="px-2 py-0.5 rounded-md text-[10px] font-bold bg-slate-800 text-cyan-300 border border-slate-700 shrink-0">
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
              <div className="py-10 text-center text-slate-400 text-xs">
                No matching features, findings, or files found for &ldquo;{query}&rdquo;.
              </div>
            )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2.5 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
          <span>
            Tip: Press <kbd className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-200 font-mono">Ctrl+K</kbd> anytime to open Quick Find &amp; Actions
          </span>
          <span>100% of Alastor SAST++++++ features accessible</span>
        </div>
      </div>
    </div>
  );
}
