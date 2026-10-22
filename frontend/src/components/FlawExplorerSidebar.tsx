"use client";

import React, { useState, useMemo } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { Finding, DirectoryTreeNode, ExtractedAdvisory } from "@/types/cpg";
import {
  Flame,
  ShieldAlert,
  AlertTriangle,
  FileCode,
  Bug,
  Code2,
  Folder,
  FolderOpen,
  ChevronRight,
  ChevronDown,
  Layers,
  Search,
  Server,
  Layout,
  Terminal,
  Settings,
  Package,
  FileText,
  Palette,
  CheckCircle2,
  Globe,
  ExternalLink,
  Loader2,
  Sparkles,
  ArrowRight,
  BookOpen,
  Info,
  Crosshair,
  Ticket,
  KeyRound,
  Eye,
  EyeOff,
} from "lucide-react";

function getHumanStoryBadge(f: Finding): { label: string; summary: string; color: string } {
  const rule = (f.rule_id || "").toUpperCase();
  const cwe = (f.cwe_id || "").toUpperCase();

  if (rule.includes("TAINT") || rule.includes("SHELL") || cwe === "CWE-78") {
    return {
      label: "Command Injection",
      summary: "Untrusted input reaches an OS shell command without sanitization.",
      color: "bg-red-950/80 text-red-300 border-red-700/80",
    };
  }
  if (rule.includes("SQLI") || cwe === "CWE-89") {
    return {
      label: "SQL Injection",
      summary: "Database query built with unescaped string formatting.",
      color: "bg-red-950/80 text-red-300 border-red-700/80",
    };
  }
  if (rule.includes("GADGET") || cwe === "CWE-489") {
    return {
      label: "Dormant Exploit Gadget",
      summary: "Unreferenced function contains a dangerous execution sink.",
      color: "bg-amber-950/80 text-amber-300 border-amber-700/80",
    };
  }
  if (rule.includes("INFINITE-LOOP") || cwe === "CWE-835") {
    return {
      label: "Infinite Loop (DoS)",
      summary: "Loop has no reachable exit condition; can hang CPU.",
      color: "bg-amber-950/80 text-amber-300 border-amber-700/80",
    };
  }
  if (rule.includes("DEAD-STORE") || cwe === "CWE-563") {
    return {
      label: "Unused Variable (Dead Store)",
      summary: "Assigned value is never read or used downstream.",
      color: "bg-yellow-950/80 text-yellow-300 border-yellow-700/80",
    };
  }
  if (rule.includes("UNREACHABLE") || cwe === "CWE-561") {
    return {
      label: "Unreachable Code",
      summary: "Code placed after return/break will never execute.",
      color: "bg-blue-950/80 text-blue-300 border-blue-700/80",
    };
  }
  if (rule.includes("SECRET") || cwe === "CWE-798") {
    return {
      label: "Hardcoded Secret",
      summary: "Sensitive key or password embedded directly in source code.",
      color: "bg-rose-950/80 text-rose-300 border-rose-700/80",
    };
  }
  if (rule.includes("DOM-XSS") || cwe === "CWE-79") {
    return {
      label: "DOM XSS / Script Sink",
      summary: "Dynamic data flows into a browser DOM HTML or script sink without sanitization.",
      color: "bg-amber-950/80 text-amber-300 border-amber-700/80",
    };
  }
  if (f.scan_engine === "SCA" || rule.includes("SCA") || cwe === "CWE-1395") {
    return {
      label: "Third-Party Dependency (SCA)",
      summary: f.description || "Third-party software packages use floating or unpinned version specifiers.",
      color: "bg-emerald-950/80 text-emerald-300 border-emerald-700/80",
    };
  }
  if (f.scan_engine === "IaC" || rule.includes("IAC") || cwe === "CWE-250") {
    return {
      label: "Runtime / IaC Config",
      summary: f.description || "Deployment or web runtime configuration is missing security hardening.",
      color: "bg-purple-950/80 text-purple-300 border-purple-700/80",
    };
  }
  return {
    label: f.cwe_id || "Security Risk",
    summary: f.description || f.title,
    color: "bg-indigo-950/80 text-indigo-300 border-indigo-700/80",
  };
}

export function FlawExplorerSidebar() {
  const findings = useAuditStore((s) => s.findings);
  const selectedFinding = useAuditStore((s) => s.selectedFinding);
  const selectFinding = useAuditStore((s) => s.selectFinding);
  const jumpToBestFixLocation = useAuditStore((s) => s.jumpToBestFixLocation);
  const setIntegrationModalOpen = useAuditStore((s) => s.setIntegrationModalOpen);

  const primaryGrouping = useAuditStore((s) => s.primaryGrouping);
  const setPrimaryGrouping = useAuditStore((s) => s.setPrimaryGrouping);
  const activeEngineFilter = useAuditStore((s) => s.activeEngineFilter);
  const setActiveEngineFilter = useAuditStore((s) => s.setActiveEngineFilter);
  const filterSecretsOnly = useAuditStore((s) => s.filterSecretsOnly);
  const setFilterSecretsOnly = useAuditStore((s) => s.setFilterSecretsOnly);
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});

  const appTree = useAuditStore((s) => s.appTree);
  const selectedTreeFile = useAuditStore((s) => s.selectedTreeFile);
  const selectTreeFile = useAuditStore((s) => s.selectTreeFile);

  const activeSidebarTab = useAuditStore((s) => s.activeSidebarTab);
  const setActiveSidebarTab = useAuditStore((s) => s.setActiveSidebarTab);
  const setGraphViewMode = useAuditStore((s) => s.setGraphViewMode);

  const extractedAdvisories = useAuditStore((s) => s.extractedAdvisories);
  const isExtractingIntel = useAuditStore((s) => s.isExtractingIntel);
  const intelStatusMessage = useAuditStore((s) => s.intelStatusMessage);
  const extractAndScanFromSites = useAuditStore((s) => s.extractAndScanFromSites);
  const audienceMode = useAuditStore((s) => s.audienceMode);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);
  const setSastPlusActiveTab = useAuditStore((s) => s.setSastPlusActiveTab);
  const projectPath = useAuditStore((s) => s.projectPath);
  const setProjectPath = useAuditStore((s) => s.setProjectPath);
  const triggerScan = useAuditStore((s) => s.triggerScan);
  const trackChanges = useAuditStore((s) => s.trackChanges);
  const isTrackChangesMode = useAuditStore((s) => s.isTrackChangesMode);

  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");
  const [collapsedDirs, setCollapsedDirs] = useState<Record<string, boolean>>({});

  const [flawSearch, setFlawSearch] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [trackChangeFilter, setTrackChangeFilter] = useState<
    "ALL" | "NEW" | "FIXED" | "UNCHANGED"
  >("ALL");
  const [sourceFilter, setSourceFilter] = useState<"ALL" | "CPG" | "WEB">("ALL");
  const [sortBy, setSortBy] = useState<"SEVERITY" | "CVSS" | "AGE">("SEVERITY");
  const [showSuppressed, setShowSuppressed] = useState<boolean>(true);
  const [visibleCount, setVisibleCount] = useState<number>(40);

  // Site Extractor state
  const [selectedSources, setSelectedSources] = useState<string[]>(["osv", "nvd", "cisa_owasp"]);
  const [customSiteUrl, setCustomSiteUrl] = useState<string>("");
  const [intelSearchQuery, setIntelSearchQuery] = useState<string>("");

  const toggleSource = (src: string) => {
    setSelectedSources((prev) =>
      prev.includes(src) ? prev.filter((s) => s !== src) : [...prev, src]
    );
  };

  const handleRunSiteExtraction = async (e: React.FormEvent) => {
    e.preventDefault();
    const urls = customSiteUrl
      .split(",")
      .map((u) => u.trim())
      .filter(Boolean);
    await extractAndScanFromSites({
      sources: selectedSources,
      customUrls: urls,
      searchQuery: intelSearchQuery,
    });
  };

  const filteredFindings = useMemo(() => {
    const sevRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const sourcePool: Finding[] =
      trackChangeFilter === "FIXED"
        ? trackChanges?.fixed_findings || []
        : findings;

    const filtered = sourcePool.filter((f) => {
      if (trackChangeFilter === "NEW") {
        if (f.change_status !== "NEW" && f.change_status !== "REOPENED") {
          return false;
        }
      } else if (trackChangeFilter === "UNCHANGED") {
        if (f.change_status !== "UNCHANGED") {
          return false;
        }
      }
      if (
        trackChangeFilter !== "FIXED" &&
        !showSuppressed &&
        f.triage_status === "NOT_EXPLOITABLE"
      ) {
        return false;
      }
      if (selectedSeverity !== "ALL" && f.severity !== selectedSeverity) {
        return false;
      }
      if (activeEngineFilter !== "ALL" && (f.scan_engine || "SAST") !== activeEngineFilter) {
        return false;
      }
      if (filterSecretsOnly) {
        const isSec =
          f.is_secret_finding ||
          Boolean(f.secret_key_name) ||
          (f.rule_id || "").toUpperCase().includes("SECRET") ||
          f.cwe_id === "CWE-798";
        if (!isSec) return false;
      }
      const isExternal = (f.rule_id || "").startsWith("EXT-");
      if (sourceFilter === "CPG" && isExternal) return false;
      if (sourceFilter === "WEB" && !isExternal) return false;

      if (flawSearch.trim()) {
        const query = flawSearch.toLowerCase();
        const matchesTitle = f.title.toLowerCase().includes(query);
        const matchesRule = f.rule_id.toLowerCase().includes(query);
        const matchesCwe = (f.cwe_id || "").toLowerCase().includes(query);
        const matchesDesc = (f.description || "").toLowerCase().includes(query);
        const matchesLang = (f.language || "").toLowerCase().includes(query);
        const matchesFile = (f.path_nodes || []).some((n) =>
          (n.filepath || "").toLowerCase().includes(query)
        );
        return (
          matchesTitle ||
          matchesRule ||
          matchesCwe ||
          matchesDesc ||
          matchesLang ||
          matchesFile
        );
      }
      return true;
    });

    return [...filtered].sort((a, b) => {
      if (sortBy === "CVSS") {
        return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
      }
      if (sortBy === "AGE") {
        return (b.age_days ?? 0) - (a.age_days ?? 0);
      }
      return (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0);
    });
  }, [
    findings,
    trackChanges,
    trackChangeFilter,
    selectedSeverity,
    activeEngineFilter,
    filterSecretsOnly,
    sourceFilter,
    flawSearch,
    sortBy,
    showSuppressed,
  ]);

  const displayedFindings = useMemo(() => {
    return filteredFindings.slice(0, visibleCount);
  }, [filteredFindings, visibleCount]);

  const groupedDisplayedFindings = useMemo(() => {
    if (primaryGrouping === "NONE") {
      return [{ groupTitle: null as string | null, items: displayedFindings }];
    }
    const map = new Map<string, Finding[]>();
    for (const f of displayedFindings) {
      let key = "Other";
      if (primaryGrouping === "LANGUAGE") {
        key = f.language || "Python";
      } else if (primaryGrouping === "SEVERITY") {
        key = `${f.severity} SEVERITY`;
      } else if (primaryGrouping === "ENGINE") {
        key = `${f.scan_engine || "SAST"} ENGINE`;
      }
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(f);
    }
    return Array.from(map.entries()).map(([groupTitle, items]) => ({
      groupTitle,
      items,
    }));
  }, [displayedFindings, primaryGrouping]);

  const toggleDir = (dirPath: string) => {
    setCollapsedDirs((prev) => ({ ...prev, [dirPath]: !prev[dirPath] }));
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return {
          icon: <Flame className="w-3.5 h-3.5 text-red-500" />,
          color: "bg-red-950/70 text-red-300 border-red-800",
        };
      case "HIGH":
        return {
          icon: <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />,
          color: "bg-amber-950/70 text-amber-300 border-amber-800",
        };
      case "MEDIUM":
        return {
          icon: <AlertTriangle className="w-3.5 h-3.5 text-yellow-500" />,
          color: "bg-yellow-950/70 text-yellow-300 border-yellow-800",
        };
      default:
        return {
          icon: <Bug className="w-3.5 h-3.5 text-blue-500" />,
          color: "bg-blue-950/70 text-blue-300 border-blue-800",
        };
    }
  };

  const getCategoryBadge = (category: string) => {
    switch (category) {
      case "API_ROUTER":
        return {
          label: "API Route",
          icon: <Server className="w-3 h-3 text-emerald-400" />,
          color: "bg-emerald-950/70 text-emerald-300 border-emerald-800",
        };
      case "FRONTEND_VIEW":
        return {
          label: "UI View",
          icon: <Layout className="w-3 h-3 text-purple-400" />,
          color: "bg-purple-950/70 text-purple-300 border-purple-800",
        };
      case "BUSINESS_LOGIC":
        return {
          label: "Core Logic",
          icon: <Code2 className="w-3 h-3 text-cyan-400" />,
          color: "bg-cyan-950/70 text-cyan-300 border-cyan-800",
        };
      case "INFRASTRUCTURE":
        return {
          label: "Infra",
          icon: <Terminal className="w-3 h-3 text-blue-400" />,
          color: "bg-blue-950/70 text-blue-300 border-blue-800",
        };
      case "DEPENDENCY_MANIFEST":
        return {
          label: "Dependencies",
          icon: <Package className="w-3 h-3 text-rose-400" />,
          color: "bg-rose-950/70 text-rose-300 border-rose-800",
        };
      case "CONFIGURATION":
      case "BUILD_TOOLING":
        return {
          label: "Config",
          icon: <Settings className="w-3 h-3 text-amber-400" />,
          color: "bg-amber-950/70 text-amber-300 border-amber-800",
        };
      case "STYLING_THEME":
        return {
          label: "Styles",
          icon: <Palette className="w-3 h-3 text-pink-400" />,
          color: "bg-pink-950/70 text-pink-300 border-pink-800",
        };
      case "DOCUMENTATION":
        return {
          label: "Docs",
          icon: <FileText className="w-3 h-3 text-zinc-400" />,
          color: "bg-zinc-800 text-zinc-300 border-zinc-700",
        };
      default:
        return {
          label: "Asset",
          icon: <FileCode className="w-3 h-3 text-zinc-400" />,
          color: "bg-zinc-900 text-zinc-400 border-zinc-800",
        };
    }
  };

  const getFileFindingsCount = (filepath: string) => {
    return findings.filter((f) =>
      f.path_nodes.some((n) => n.filepath === filepath || filepath.endsWith(n.filepath))
    ).length;
  };

  const filteredFlatFiles = useMemo(() => {
    if (!appTree) return [];
    return appTree.flat_files.filter((f) => {
      const matchesSearch =
        searchQuery === "" ||
        f.filepath.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.purpose.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.category.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesCat =
        selectedCategory === "ALL" || f.category === selectedCategory;

      return matchesSearch && matchesCat;
    });
  }, [appTree, searchQuery, selectedCategory]);

  const renderDirectoryNode = (dir: DirectoryTreeNode, depth = 0) => {
    const isCollapsed = collapsedDirs[dir.path] || false;
    const fileCount = dir.files.length;
    const subCount = dir.subdirectories.length;

    return (
      <div key={dir.path || "root"} className="space-y-0.5">
        {dir.path && (
          <div
            onClick={() => toggleDir(dir.path)}
            style={{ paddingLeft: `${depth * 12 + 6}px` }}
            className="flex items-center justify-between py-1 px-2 rounded hover:bg-zinc-900/70 cursor-pointer text-xs text-zinc-400 group transition-colors"
          >
            <div className="flex items-center gap-1.5 truncate">
              {isCollapsed ? (
                <ChevronRight className="w-3 h-3 text-zinc-500" />
              ) : (
                <ChevronDown className="w-3 h-3 text-zinc-500" />
              )}
              {isCollapsed ? (
                <Folder className="w-3.5 h-3.5 text-cyan-600" />
              ) : (
                <FolderOpen className="w-3.5 h-3.5 text-cyan-500" />
              )}
              <span className="font-mono text-zinc-300 font-medium truncate">
                {dir.name}
              </span>
            </div>
            <span className="text-[10px] font-mono text-zinc-600 group-hover:text-zinc-500">
              {fileCount + subCount}
            </span>
          </div>
        )}

        {!isCollapsed && (
          <div className="space-y-0.5">
            {dir.subdirectories.map((sub) => renderDirectoryNode(sub, depth + 1))}

            {dir.files.map((file) => {
              const isSelected = selectedTreeFile?.filepath === file.filepath;
              const badge = getCategoryBadge(file.category);
              const fileFindings = getFileFindingsCount(file.filepath);

              return (
                <div
                  key={file.filepath}
                  onClick={() => selectTreeFile(file)}
                  style={{ paddingLeft: `${(depth + (dir.path ? 1 : 0)) * 12 + 10}px` }}
                  className={`group flex items-center justify-between py-1 px-2 rounded cursor-pointer text-xs transition-all ${
                    isSelected
                      ? "bg-zinc-900 text-cyan-300 border border-cyan-500/50 shadow-sm"
                      : "text-zinc-400 hover:bg-zinc-900/60 hover:text-zinc-200 border border-transparent"
                  }`}
                  title={`${file.filepath}\nRole: ${file.purpose}`}
                >
                  <div className="flex items-center gap-1.5 truncate flex-1 mr-2">
                    {badge.icon}
                    <span className="font-mono truncate">{file.filename}</span>
                  </div>

                  <div className="flex items-center gap-1 shrink-0">
                    {fileFindings > 0 && (
                      <span
                        title={`${fileFindings} security findings in this file`}
                        className="flex items-center gap-0.5 px-1 py-0.2 rounded bg-red-950/80 text-red-400 border border-red-800 text-[9px] font-mono font-bold"
                      >
                        <Flame className="w-2.5 h-2.5" />
                        {fileFindings}
                      </span>
                    )}
                    <span className={`text-[9px] font-mono px-1 py-0.2 rounded border ${badge.color}`}>
                      {badge.label}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  return (
    <aside className="w-[340px] h-full bg-zinc-950/75 border-r border-zinc-800 flex flex-col select-none shrink-0">
      {/* Self-Explanatory 3-Tab Navigation Header */}
      <div className="p-1.5 bg-zinc-900 border-b border-zinc-800 grid grid-cols-3 gap-1">
        <button
          onClick={() => {
            setActiveSidebarTab("FLAWS");
            setGraphViewMode("FINDING_PATH");
          }}
          title="View all detected code vulnerabilities and their step-by-step attack stories"
          className={`flex flex-col items-center justify-center py-1.5 px-1 rounded-md transition-all ${
            activeSidebarTab === "FLAWS"
              ? "bg-zinc-800 text-cyan-300 shadow-sm border border-cyan-700/70"
              : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40 border border-transparent"
          }`}
        >
          <div className="flex items-center gap-1 text-[11px] font-bold">
            <Bug className="w-3.5 h-3.5 text-red-400" />
            <span>1. Findings</span>
            <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-zinc-950 text-zinc-200">
              {findings.length}
            </span>
          </div>
          <span className="text-[9px] text-zinc-500">Flaws &amp; Stories</span>
        </button>

        <button
          onClick={() => {
            setActiveSidebarTab("SITE_EXTRACTOR");
          }}
          title="Extract live CVEs & CWEs from external security sites and check your code"
          className={`flex flex-col items-center justify-center py-1.5 px-1 rounded-md transition-all ${
            activeSidebarTab === "SITE_EXTRACTOR"
              ? "bg-zinc-800 text-cyan-300 shadow-sm border border-cyan-700/70"
              : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40 border border-transparent"
          }`}
        >
          <div className="flex items-center gap-1 text-[11px] font-bold">
            <Globe className="w-3.5 h-3.5 text-indigo-400" />
            <span>2. Web Intel</span>
            {extractedAdvisories.length > 0 && (
              <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-indigo-950 text-indigo-300">
                {extractedAdvisories.length}
              </span>
            )}
          </div>
          <span className="text-[9px] text-zinc-500">Extract Site CVEs</span>
        </button>

        <button
          onClick={() => {
            setActiveSidebarTab("APP_TREE");
            setGraphViewMode("APP_TREE");
          }}
          title="Browse project files, architectural purposes, and the 360° Spider App Map"
          className={`flex flex-col items-center justify-center py-1.5 px-1 rounded-md transition-all ${
            activeSidebarTab === "APP_TREE"
              ? "bg-zinc-800 text-cyan-300 shadow-sm border border-cyan-700/70"
              : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40 border border-transparent"
          }`}
        >
          <div className="flex items-center gap-1 text-[11px] font-bold">
            <Layers className="w-3.5 h-3.5 text-emerald-400" />
            <span>3. App Map</span>
            <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-zinc-950 text-zinc-200">
              {appTree?.total_files ?? 0}
            </span>
          </div>
          <span className="text-[9px] text-zinc-500">Files &amp; Spider Web</span>
        </button>
      </div>

      {/* VIEW 1: SECURITY FINDINGS & STORY CARDS */}
      {activeSidebarTab === "FLAWS" && (
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Self-Explanatory Helper Strip */}
          <div className="px-2.5 py-1.5 bg-cyan-950/20 border-b border-zinc-800 text-[10px] text-zinc-400 flex items-center gap-1.5">
            <BookOpen className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>
              App:{" "}
              <b className="text-cyan-300 font-mono">
                {(appTree?.root_path || projectPath || "cpg-sast-platform")
                  .replace(/[\\/]+$/, "")
                  .split(/[\\/]/)
                  .pop()}
              </b>{" "}
              — Click any finding to inspect its <b>Attack Story</b> &amp; <b>Fix Guide</b>.
            </span>
          </div>

          {/* Search, Engine Filter, Primary Grouping & Severity Filter */}
          <div className="p-2 border-b border-zinc-800/80 space-y-2 bg-zinc-900/40">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-zinc-500" />
              <input
                type="text"
                value={flawSearch}
                onChange={(e) => {
                  setFlawSearch(e.target.value);
                  setVisibleCount(40);
                }}
                placeholder="Search by flaw, language, CWE, or file..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md pl-8 pr-2.5 py-1 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Unified Engine Filter (ALL / SAST / SCA / IaC) + Secret Keys Filter */}
            <div className="grid grid-cols-5 gap-1 text-[10px] font-mono">
              {(["ALL", "SAST", "SCA", "IaC"] as const).map((eng) => {
                const cnt =
                  eng === "ALL"
                    ? findings.length
                    : findings.filter((f) => (f.scan_engine || "SAST") === eng).length;
                return (
                  <button
                    key={eng}
                    type="button"
                    onClick={() => {
                      setActiveEngineFilter(eng);
                      if (eng !== "ALL" && filterSecretsOnly) setFilterSecretsOnly(false);
                    }}
                    className={`py-0.5 px-1 rounded border text-center transition-colors ${
                      activeEngineFilter === eng && !filterSecretsOnly
                        ? "bg-cyan-950/90 text-cyan-200 border-cyan-700 font-bold"
                        : "bg-zinc-950 text-zinc-500 border-zinc-800 hover:text-zinc-300"
                    }`}
                  >
                    {eng === "ALL" ? `All (${cnt})` : `${eng} (${cnt})`}
                  </button>
                );
              })}
              <button
                type="button"
                onClick={() => setFilterSecretsOnly(!filterSecretsOnly)}
                title="Filter to show only Hardcoded Secret Keys, API Tokens & Credentials"
                className={`py-0.5 px-1 rounded border text-center transition-colors flex items-center justify-center gap-0.5 ${
                  filterSecretsOnly
                    ? "bg-amber-500/25 text-amber-200 border-amber-400 font-bold"
                    : "bg-amber-950/30 text-amber-300 border-amber-700/60 hover:bg-amber-900/40"
                }`}
              >
                <KeyRound className="w-2.5 h-2.5" />
                <span>
                  Keys (
                  {
                    findings.filter(
                      (f) =>
                        f.is_secret_finding ||
                        Boolean(f.secret_key_name) ||
                        (f.rule_id || "").toUpperCase().includes("SECRET") ||
                        f.cwe_id === "CWE-798"
                    ).length
                  }
                  )
                </span>
              </button>
            </div>

            {/* Primary Grouping Toggle (Language vs Severity vs Engine) & Sort */}
            <div className="flex items-center justify-between gap-1 text-[10px] font-mono">
              <div className="flex items-center gap-1">
                <span className="text-zinc-500">Group:</span>
                {(["NONE", "LANGUAGE", "SEVERITY", "ENGINE"] as const).map((grp) => (
                  <button
                    key={grp}
                    type="button"
                    onClick={() => setPrimaryGrouping(grp)}
                    className={`px-1.5 py-0.5 rounded border transition-colors ${
                      primaryGrouping === grp
                        ? "bg-indigo-950 text-indigo-300 border-indigo-700 font-bold"
                        : "bg-zinc-950 text-zinc-500 border-zinc-800 hover:text-zinc-300"
                    }`}
                  >
                    {grp === "NONE"
                      ? "Flat"
                      : grp === "LANGUAGE"
                      ? "Lang"
                      : grp === "SEVERITY"
                      ? "Sev"
                      : "Engine"}
                  </button>
                ))}
              </div>

              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                title="Sort findings by Severity, CVSS Score, or Persistence Age"
                className="bg-zinc-950 border border-zinc-800 rounded px-1.5 py-0.5 text-[10px] font-mono text-zinc-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="SEVERITY">Sort: Severity</option>
                <option value="CVSS">Sort: CVSS</option>
                <option value="AGE">Sort: Age (Days)</option>
              </select>
            </div>

            {/* Severity Quick Pills */}
            <div className="flex items-center gap-1 overflow-x-auto pb-0.5 text-[10px] font-mono">
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => {
                const count =
                  sev === "ALL"
                    ? findings.length
                    : findings.filter((f) => f.severity === sev).length;
                return (
                  <button
                    key={sev}
                    onClick={() => {
                      setSelectedSeverity(sev);
                      setVisibleCount(40);
                    }}
                    className={`px-1.5 py-0.5 rounded whitespace-nowrap border transition-colors flex items-center gap-1 ${
                      selectedSeverity === sev
                        ? "bg-cyan-950 text-cyan-300 border-cyan-800 font-bold"
                        : "bg-zinc-900 text-zinc-500 border-zinc-800 hover:text-zinc-300"
                    }`}
                  >
                    <span>{sev}</span>
                    <span className="text-[9px] opacity-75">({count})</span>
                  </button>
                );
              })}
            </div>

            {/* Continuous Track Changes Mode Filter Row */}
            {isTrackChangesMode && (
              <div className="flex items-center gap-1 overflow-x-auto pt-1 border-t border-zinc-800/80 text-[9px] font-mono">
                <span className="text-indigo-400 font-bold shrink-0">Delta:</span>
                <button
                  type="button"
                  onClick={() => setTrackChangeFilter("ALL")}
                  className={`px-1.5 py-0.5 rounded border whitespace-nowrap transition-colors ${
                    trackChangeFilter === "ALL"
                      ? "bg-indigo-950 text-indigo-200 border-indigo-600 font-bold"
                      : "bg-zinc-950 text-zinc-400 border-zinc-800 hover:text-zinc-200"
                  }`}
                >
                  Active ({findings.length})
                </button>
                <button
                  type="button"
                  onClick={() => setTrackChangeFilter("NEW")}
                  className={`px-1.5 py-0.5 rounded border whitespace-nowrap transition-colors ${
                    trackChangeFilter === "NEW"
                      ? "bg-amber-950 text-amber-200 border-amber-500 font-bold"
                      : "bg-zinc-950 text-amber-300/80 border-zinc-800 hover:text-amber-200"
                  }`}
                >
                  🆕 New (
                  {trackChanges?.new_count ??
                    findings.filter(
                      (f) =>
                        f.change_status === "NEW" ||
                        f.change_status === "REOPENED"
                    ).length}
                  )
                </button>
                <button
                  type="button"
                  onClick={() => setTrackChangeFilter("FIXED")}
                  className={`px-1.5 py-0.5 rounded border whitespace-nowrap transition-colors ${
                    trackChangeFilter === "FIXED"
                      ? "bg-emerald-950 text-emerald-200 border-emerald-500 font-bold"
                      : "bg-zinc-950 text-emerald-300/80 border-zinc-800 hover:text-emerald-200"
                  }`}
                >
                  ✅ Fixed ({trackChanges?.fixed_count ?? 0})
                </button>
                <button
                  type="button"
                  onClick={() => setTrackChangeFilter("UNCHANGED")}
                  className={`px-1.5 py-0.5 rounded border whitespace-nowrap transition-colors ${
                    trackChangeFilter === "UNCHANGED"
                      ? "bg-zinc-800 text-zinc-100 border-zinc-600 font-bold"
                      : "bg-zinc-950 text-zinc-400 border-zinc-800 hover:text-zinc-200"
                  }`}
                >
                  ⏳ Same (
                  {trackChanges?.unchanged_count ??
                    findings.filter((f) => f.change_status === "UNCHANGED")
                      .length}
                  )
                </button>
              </div>
            )}
          </div>

          {/* Story-Driven & Grouped Findings List */}
          <div className="flex-1 overflow-y-auto p-2 space-y-2.5">
            {filteredFindings.length === 0 ? (
              findings.length === 0 && trackChangeFilter !== "FIXED" ? (
                <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-700/70 space-y-3 text-left">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
                    <div>
                      <div className="text-xs font-extrabold text-emerald-300 uppercase tracking-wide">
                        100% Clean Security Posture Verified
                      </div>
                      <div className="text-[10px] font-mono text-emerald-400/90">
                        0 Critical • 0 High • 0 Medium • 0 Low
                      </div>
                    </div>
                  </div>
                  <p className="text-[11px] text-zinc-200 leading-relaxed">
                    All active engines (<strong>SAST</strong>, <strong>SCA</strong>, and{" "}
                    <strong>IaC</strong>) completed deep Code Property Graph analysis on{" "}
                    <code className="text-cyan-300 font-mono">{projectPath}</code> with{" "}
                    <strong>zero vulnerabilities detected</strong>.
                  </p>
                  <div className="grid grid-cols-2 gap-1.5 pt-1">
                    <button
                      type="button"
                      onClick={() => {
                        setActiveSidebarTab("APP_TREE");
                        setGraphViewMode("APP_TREE");
                      }}
                      className="px-2 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-[10px] font-semibold text-cyan-300 text-center"
                    >
                      🌳 Inspect App Tree
                    </button>
                    <button
                      type="button"
                      onClick={() => setWorkspaceViewMode("RACI_GOVERNANCE")}
                      className="px-2 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-[10px] font-semibold text-amber-300 text-center"
                    >
                      👥 RACI Matrix
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setWorkspaceViewMode("SAST_PLUS_SUITE");
                        setSastPlusActiveTab("SBOM");
                      }}
                      className="px-2 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-[10px] font-semibold text-rose-300 text-center"
                    >
                      📦 Live SBOM Inventory
                    </button>
                    <button
                      type="button"
                      onClick={() => setWorkspaceViewMode("DEEP_DIVE")}
                      className="px-2 py-1.5 rounded-lg bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700 text-[10px] font-bold text-indigo-200 text-center"
                    >
                      📊 Deep Dive &amp; Compliance
                    </button>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 px-4 text-zinc-500 text-xs">
                  <Code2 className="w-8 h-8 mx-auto mb-2 opacity-40 text-zinc-400" />
                  <p className="font-semibold text-zinc-300">No findings match current filter</p>
                  <p className="mt-1 text-[11px]">
                    Try switching to &quot;Active&quot;, &quot;All&quot; engines, or &quot;ALL&quot; severities above.
                  </p>
                </div>
              )
            ) : (
              <>
                {groupedDisplayedFindings.map((group) => (
                  <div key={group.groupTitle || "default"} className="space-y-2">
                    {group.groupTitle && (
                      <div className="px-2 py-1 rounded-md bg-zinc-900 border border-zinc-800 flex items-center justify-between text-[10px] font-mono font-bold text-cyan-300 uppercase tracking-wider">
                        <span>{group.groupTitle}</span>
                        <span className="px-1.5 py-0.2 rounded bg-zinc-950 text-zinc-300">
                          {group.items.length}
                        </span>
                      </div>
                    )}

                    {group.items.map((f: Finding) => {
                      const isSelected = selectedFinding?.id === f.id;
                      const badge = getSeverityBadge(f.severity);
                      const storyBadge = getHumanStoryBadge(f);
                      const nodes = f.path_nodes || [];
                      const firstNode = nodes.length > 0 ? nodes[0] : null;
                      const lastNode = nodes.length > 1 ? nodes[nodes.length - 1] : firstNode;
                      const isSuppressed = f.triage_status === "NOT_EXPLOITABLE";

                      return (
                        <div
                          key={f.id}
                          onClick={() => selectFinding(f)}
                          className={`group p-2.5 rounded-xl border transition-all cursor-pointer text-left ${
                            isSuppressed ? "opacity-60" : ""
                          } ${
                            isSelected
                              ? "bg-zinc-900 border-cyan-500 shadow-md shadow-cyan-950/40"
                              : "bg-zinc-950 border-zinc-800/90 hover:bg-zinc-900/60 hover:border-zinc-700"
                          }`}
                        >
                          {/* Top Row: Engine + Severity + Track Changes Badge + Category Badge */}
                          <div className="flex items-center justify-between gap-1 mb-1.5">
                            <div className="flex items-center gap-1 flex-wrap">
                              {badge.icon}
                              <span
                                className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border ${badge.color}`}
                              >
                                {f.severity}
                              </span>
                              <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded bg-zinc-900 text-cyan-300 border border-zinc-700">
                                {f.scan_engine || "SAST"}
                              </span>
                              {isTrackChangesMode && (
                                <span
                                  className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border ${
                                    f.change_status === "FIXED" ||
                                    trackChangeFilter === "FIXED"
                                      ? "bg-emerald-950/90 text-emerald-300 border-emerald-600"
                                      : f.change_status === "UNCHANGED"
                                      ? "bg-zinc-900 text-zinc-300 border-zinc-700"
                                      : "bg-amber-950/90 text-amber-300 border-amber-600"
                                  }`}
                                >
                                  {f.change_status === "FIXED" ||
                                  trackChangeFilter === "FIXED"
                                    ? "✅ FIXED"
                                    : f.change_status === "UNCHANGED"
                                    ? "⏳ UNCHANGED"
                                    : f.change_status === "REOPENED"
                                    ? "🆕 REOPENED"
                                    : "🆕 NEW"}
                                </span>
                              )}
                              <span
                                className={`text-[10px] font-semibold px-1.5 py-0.2 rounded border ${storyBadge.color}`}
                              >
                                {storyBadge.label}
                              </span>
                            </div>
                            {f.cwe_id && (
                              <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-zinc-900 text-zinc-400 border border-zinc-800 shrink-0">
                                {f.cwe_id}
                              </span>
                            )}
                          </div>

                          {/* Headline */}
                          <h2
                            className={`text-xs font-bold leading-snug group-hover:text-cyan-300 transition-colors ${
                              isSuppressed ? "line-through text-zinc-400" : "text-zinc-100"
                            }`}
                          >
                            {f.title}
                          </h2>

                          {/* Always-Visible Written Explanation & Secret Key / Target Code Box */}
                          <div className="mt-1.5 p-2 rounded-lg bg-zinc-900/85 border border-zinc-800/90 text-[10px] text-zinc-300 space-y-1">
                            {/* Secret Key Inspector OR Target Symbol & EPSS Priority Row */}
                            {f.is_secret_finding ||
                            Boolean(f.secret_key_name) ||
                            (f.rule_id || "").toUpperCase().includes("SECRET") ||
                            f.cwe_id === "CWE-798" ? (
                              <div className="p-1.5 rounded-lg bg-amber-950/40 border border-amber-500/50 space-y-1">
                                <div className="flex items-center justify-between gap-1 font-mono text-[9px]">
                                  <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-200 border border-amber-400/60 font-extrabold flex items-center gap-1">
                                    <KeyRound className="w-3 h-3 text-amber-400" />
                                    {f.secret_type || "SECRET KEY DETECTED"}
                                  </span>
                                  {f.secret_entropy && (
                                    <span className="text-[9px] text-cyan-300">
                                      Entropy: {f.secret_entropy}
                                    </span>
                                  )}
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setRevealedSecrets((prev) => ({
                                        ...prev,
                                        [f.id]: !prev[f.id],
                                      }));
                                    }}
                                    className="px-1.5 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 text-amber-300 border border-amber-500/40 flex items-center gap-0.5 font-sans font-bold"
                                  >
                                    {revealedSecrets[f.id] ? (
                                      <>
                                        <EyeOff className="w-2.5 h-2.5" /> Mask
                                      </>
                                    ) : (
                                      <>
                                        <Eye className="w-2.5 h-2.5" /> Reveal Key
                                      </>
                                    )}
                                  </button>
                                </div>
                                <div className="px-1.5 py-1 rounded bg-zinc-950 border border-amber-500/30 font-mono text-[10px] text-amber-200 break-all">
                                  <span className="text-amber-400 font-bold">
                                    🔑 {f.secret_key_name || firstNode?.name || "SECRET_KEY"}
                                  </span>
                                  <span className="text-zinc-500"> = </span>
                                  <span className="text-rose-200 font-semibold">
                                    {revealedSecrets[f.id]
                                      ? f.secret_value_raw ||
                                        f.secret_value_masked ||
                                        firstNode?.code ||
                                        "SECRET"
                                      : f.secret_value_masked || "REDACTED_SECRET_KEY"}
                                  </span>
                                </div>
                              </div>
                            ) : (
                              <div className="flex items-center gap-1 flex-wrap font-mono text-[9px]">
                                <span className="px-1.5 py-0.5 rounded border font-bold bg-cyan-950/70 text-cyan-200 border-cyan-700/70">
                                  🎯 Target: {lastNode?.name || firstNode?.name || f.rule_id}
                                </span>
                                {typeof f.epss_score === "number" && (
                                  <span className="px-1.5 py-0.5 rounded bg-indigo-950/80 text-indigo-200 border border-indigo-700/70 font-semibold">
                                    EPSS: {(f.epss_score * 100).toFixed(1)}%
                                  </span>
                                )}
                                {f.cisa_kev_listed && (
                                  <span className="px-1.5 py-0.5 rounded bg-red-950 text-red-200 border border-red-600 font-bold">
                                    CISA KEV
                                  </span>
                                )}
                              </div>
                            )}

                            {(f.best_fix_location?.code_snippet || firstNode?.code || firstNode?.name) && (
                              <div className="px-1.5 py-1 rounded bg-zinc-950 border border-amber-800/60 font-mono text-[10px] text-amber-200 break-all">
                                <span className="text-amber-400 font-bold uppercase text-[9px] mr-1">
                                  {f.scan_engine === "SCA" ? "Affected Software:" : "Flagged Code:"}
                                </span>
                                {((f.best_fix_location?.code_snippet || firstNode?.code || firstNode?.name || "") as string)
                                  .replace(/\0/g, "")
                                  .slice(0, 120)}
                              </div>
                            )}
                            <p className="leading-snug text-zinc-200">
                              <strong className="text-emerald-300">What Is Wrong:</strong>{" "}
                              {f.description || f.plain_english_summary || storyBadge.summary}
                            </p>
                            {f.remediation && (
                              <p className="leading-snug text-cyan-200/90">
                                <strong className="text-cyan-300">How to Fix:</strong>{" "}
                                {f.remediation}
                              </p>
                            )}
                            <div className="flex items-center justify-between gap-1 text-[9px] font-mono text-amber-300 pt-0.5">
                              <span>
                                <strong>R (Fixer):</strong> {f.raci_responsible || "App Engineer"}
                              </span>
                              <span>
                                <strong>Effort:</strong> {f.effort_estimate || "15m fix"}
                              </span>
                            </div>
                          </div>

                          {/* Language + Triage Status + Ticket Metadata Row */}
                          <div className="flex items-center justify-between gap-1 mt-1.5 text-[9px] font-mono">
                            <div className="flex items-center gap-1 flex-wrap">
                              {f.language && (
                                <span className="px-1.5 py-0.2 rounded bg-zinc-900 text-zinc-300 border border-zinc-800">
                                  {f.language}
                                </span>
                              )}
                              {f.triage_status && f.triage_status !== "TO_VERIFY" && (
                                <span
                                  className={`px-1.5 py-0.2 rounded border font-bold ${
                                    f.triage_status === "NOT_EXPLOITABLE"
                                      ? "bg-zinc-900 text-zinc-400 border-zinc-700"
                                      : f.triage_status === "CONFIRMED"
                                      ? "bg-red-950 text-red-300 border-red-700"
                                      : "bg-emerald-950 text-emerald-300 border-emerald-700"
                                  }`}
                                >
                                  {f.triage_status.replace("_", " ")}
                                </span>
                              )}
                              {f.linked_ticket_id && (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setIntegrationModalOpen(true);
                                  }}
                                  title="Click to view & manage ticket in Integration Hub"
                                  className="px-1.5 py-0.2 rounded bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 flex items-center gap-0.5 cursor-pointer"
                                >
                                  <Ticket className="w-2.5 h-2.5" />
                                  {f.linked_ticket_id}
                                </button>
                              )}
                            </div>

                            {f.best_fix_location && (
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  jumpToBestFixLocation(f);
                                }}
                                title={`Best Fixed Location (BFL): ${f.best_fix_location.rationale}`}
                                className="px-1.5 py-0.2 rounded bg-emerald-950/90 hover:bg-emerald-900 text-emerald-300 border border-emerald-700 font-bold flex items-center gap-0.5 shrink-0"
                              >
                                <Crosshair className="w-2.5 h-2.5 text-emerald-400" />
                                <span>BFL: L{f.best_fix_location.line}</span>
                              </button>
                            )}
                          </div>

                          {/* Visual Story Flow Bar (Source -> Sink) */}
                          {firstNode && (
                            <div className="mt-2 pt-1.5 border-t border-zinc-800/70 flex flex-col gap-1">
                              {nodes.length > 1 && lastNode ? (
                                <div className="flex items-center justify-between text-[10px] font-mono bg-zinc-900/90 px-2 py-1 rounded border border-zinc-800">
                                  <span
                                    className="text-cyan-300 truncate max-w-[105px]"
                                    title={`Entry: ${firstNode.name}`}
                                  >
                                    Entry: L{firstNode.start_line}
                                  </span>
                                  <span className="text-zinc-500 flex items-center gap-0.5 text-[9px]">
                                    <span>{nodes.length} steps</span>
                                    <ArrowRight className="w-3 h-3 text-cyan-400" />
                                  </span>
                                  <span
                                    className="text-red-300 font-semibold truncate max-w-[105px]"
                                    title={`Sink: ${lastNode.name}`}
                                  >
                                    Sink: L{lastNode.start_line}
                                  </span>
                                </div>
                              ) : (
                                <div className="flex items-center justify-between text-[10px] font-mono bg-zinc-900/70 px-2 py-1 rounded border border-zinc-800/80">
                                  <span
                                    className="text-zinc-300 truncate max-w-[180px]"
                                    title={firstNode.filepath}
                                  >
                                    {firstNode.filepath.split("/").pop()} : Line{" "}
                                    {firstNode.start_line}
                                  </span>
                                  <span className="text-cyan-400 text-[9px] font-semibold">
                                    View Story →
                                  </span>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ))}

                {filteredFindings.length > displayedFindings.length && (
                  <div className="pt-2 pb-1 text-center">
                    <button
                      onClick={() => setVisibleCount((prev) => prev + 50)}
                      className="w-full py-1.5 text-xs font-medium text-cyan-400 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded-md transition-colors"
                    >
                      Show More (+50) — Viewing {displayedFindings.length} of{" "}
                      {filteredFindings.length}
                    </button>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}

      {/* VIEW 2: MULTI-SITE VULNERABILITY EXTRACTOR & CODE IDENTIFIER */}
      {activeSidebarTab === "SITE_EXTRACTOR" && (
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="px-2.5 py-1.5 bg-indigo-950/25 border-b border-zinc-800 text-[10px] text-zinc-400 flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
            <span>
              Extract live advisories from security sites and automatically scan your code for matching vulnerabilities.
            </span>
          </div>

          <form onSubmit={handleRunSiteExtraction} className="p-2.5 border-b border-zinc-800 bg-zinc-900/50 space-y-2.5">
            <div className="space-y-1">
              <label className="text-[10px] font-mono text-zinc-300 font-semibold block">
                Step 1: Choose External Security Databases
              </label>
              <div className="grid grid-cols-1 gap-1 text-[11px]">
                {[
                  { id: "osv", label: "OSV.dev (Open Source Package CVEs)" },
                  { id: "nvd", label: "NIST NVD & GitHub Advisories (GHSA)" },
                  { id: "cisa_owasp", label: "MITRE CWE & OWASP Top 10 Patterns" },
                ].map((src) => {
                  const active = selectedSources.includes(src.id);
                  return (
                    <button
                      type="button"
                      key={src.id}
                      onClick={() => toggleSource(src.id)}
                      className={`flex items-center justify-between px-2.5 py-1.5 rounded-md border text-left font-mono text-[10px] transition-all ${
                        active
                          ? "bg-cyan-950/70 border-cyan-700 text-cyan-200 font-semibold"
                          : "bg-zinc-950 border-zinc-800 text-zinc-500 hover:text-zinc-300"
                      }`}
                    >
                      <span className="truncate">{src.label}</span>
                      <CheckCircle2
                        className={`w-3.5 h-3.5 shrink-0 ${active ? "text-cyan-400" : "text-zinc-700"}`}
                      />
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-mono text-zinc-300 font-semibold block">
                Step 2: Or Paste Any Security Advisory URL (Optional)
              </label>
              <input
                type="text"
                list="preset-security-sites"
                value={customSiteUrl}
                onChange={(e) => setCustomSiteUrl(e.target.value)}
                placeholder="https://cwe.mitre.org/data/definitions/78.html..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-[11px] text-zinc-200 placeholder-zinc-600 font-mono focus:outline-none focus:border-cyan-500"
              />
              <datalist id="preset-security-sites">
                <option value="https://cwe.mitre.org/data/definitions/78.html" />
                <option value="https://cwe.mitre.org/data/definitions/89.html" />
                <option value="https://owasp.org/Top10/A03_2021-Injection/" />
                <option value="https://nvd.nist.gov/vuln/detail/CVE-2024-6345" />
              </datalist>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-mono text-zinc-300 font-semibold block">
                Step 3: Filter by Keyword / CWE (Optional)
              </label>
              <input
                type="text"
                value={intelSearchQuery}
                onChange={(e) => setIntelSearchQuery(e.target.value)}
                placeholder="e.g., command injection, SQL, CWE-78..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-[11px] text-zinc-200 placeholder-zinc-600 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              type="submit"
              disabled={isExtractingIntel}
              className="w-full py-1.5 px-3 rounded-md bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white font-semibold text-xs flex items-center justify-center gap-1.5 shadow-sm shadow-cyan-950"
            >
              {isExtractingIntel ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Extracting &amp; Matching in Code...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Extract Advisories &amp; Find in Code</span>
                </>
              )}
            </button>

            {intelStatusMessage && (
              <div className="text-[10px] font-mono text-cyan-300 bg-cyan-950/40 border border-cyan-900/60 rounded p-1.5 leading-snug">
                {intelStatusMessage}
              </div>
            )}
          </form>

          {/* Extracted Advisories List */}
          <div className="flex-1 overflow-y-auto p-2 space-y-2">
            {extractedAdvisories.length === 0 ? (
              <div className="text-center py-8 px-3 text-zinc-500 text-xs space-y-1.5">
                <Globe className="w-8 h-8 mx-auto opacity-30 text-cyan-400" />
                <p className="font-medium text-zinc-300">Ready to Extract Web Threat Intel</p>
                <p className="text-[11px] text-zinc-500 leading-relaxed">
                  Click <span className="text-cyan-400 font-mono">Extract Advisories &amp; Find in Code</span> above to pull live vulnerability signatures and check every file in your project.
                </p>
              </div>
            ) : (
              extractedAdvisories.map((adv: ExtractedAdvisory) => {
                const badge = getSeverityBadge(adv.severity);
                return (
                  <div
                    key={adv.id}
                    onClick={() => {
                      if (adv.matched_in_code) {
                        const matchedFinding = findings.find(
                          (f) =>
                            (adv.cwe_id && f.cwe_id === adv.cwe_id) ||
                            f.title.includes(adv.cwe_id || "") ||
                            (adv.matched_files.length > 0 &&
                              f.path_nodes.some((n) => n.filepath === adv.matched_files[0]))
                        );
                        if (matchedFinding) {
                          selectFinding(matchedFinding);
                          setActiveSidebarTab("FLAWS");
                        }
                      }
                    }}
                    className={`p-2.5 rounded-xl border transition-all text-left ${
                      adv.matched_in_code
                        ? "bg-zinc-900/90 border-red-700/80 hover:border-cyan-500 cursor-pointer shadow-sm"
                        : "bg-zinc-950 border-zinc-800/80 opacity-80"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <div className="flex items-center gap-1 flex-wrap">
                        {badge.icon}
                        <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border ${badge.color}`}>
                          {adv.severity}
                        </span>
                        {adv.cwe_id && (
                          <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                            {adv.cwe_id}
                          </span>
                        )}
                      </div>
                      <a
                        href={adv.reference_url}
                        target="_blank"
                        rel="noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="text-[10px] font-mono text-cyan-400 hover:underline flex items-center gap-0.5"
                      >
                        <span>{adv.source_site}</span>
                        <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    </div>

                    <h3 className="text-xs font-semibold text-zinc-200 leading-snug">
                      {adv.title}
                    </h3>

                    <p className="text-[10px] text-zinc-400 mt-1 line-clamp-2 leading-relaxed">
                      {adv.summary}
                    </p>

                    <div className="mt-2 pt-1.5 border-t border-zinc-800/70 flex items-center justify-between text-[10px] font-mono">
                      {adv.matched_in_code ? (
                        <span className="px-1.5 py-0.5 rounded bg-red-950/90 text-red-300 border border-red-700 font-bold flex items-center gap-1">
                          <Flame className="w-3 h-3 text-red-400" />
                          FOUND IN CODE ({adv.match_count} {adv.match_count === 1 ? "line" : "lines"}) — Click to Inspect
                        </span>
                      ) : (
                        <span className="text-emerald-400/80">✓ Safe (0 matches in code)</span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* VIEW 3: APPLICATION ARCHITECTURE TREE EXPLORER */}
      {activeSidebarTab === "APP_TREE" && (
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="px-2.5 py-1.5 bg-emerald-950/20 border-b border-zinc-800 text-[10px] text-zinc-400 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span>
              Click any file to open its source code, see its architectural role, and highlight it on the <b>360° Spider Map</b>.
            </span>
          </div>

          <div className="p-2 border-b border-zinc-800/80 space-y-2 bg-zinc-900/40">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-zinc-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search file name or architectural role..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md pl-8 pr-2.5 py-1 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="flex items-center gap-1 overflow-x-auto pb-1 text-[10px] font-mono">
              {[
                { id: "ALL", label: "All Files" },
                { id: "BUSINESS_LOGIC", label: "Core Logic" },
                { id: "API_ROUTER", label: "API Routes" },
                { id: "FRONTEND_VIEW", label: "UI Views" },
                { id: "CONFIGURATION", label: "Configs" },
                { id: "DEPENDENCY_MANIFEST", label: "Dependencies" },
              ].map((cat) => (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCategory(cat.id)}
                  className={`px-1.5 py-0.5 rounded whitespace-nowrap border transition-colors ${
                    selectedCategory === cat.id
                      ? "bg-cyan-950 text-cyan-300 border-cyan-800 font-bold"
                      : "bg-zinc-900 text-zinc-500 border-zinc-800 hover:text-zinc-300"
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-2">
            {!appTree ? (
              <div className="text-center py-12 px-4 text-zinc-500 text-xs">
                <Layers className="w-8 h-8 mx-auto mb-2 opacity-40 text-zinc-400" />
                <p>No project tree loaded.</p>
                <p className="mt-1 text-[11px]">Click &quot;Scan&quot; above to map the codebase architecture.</p>
              </div>
            ) : searchQuery || selectedCategory !== "ALL" ? (
              <div className="space-y-1.5">
                {filteredFlatFiles.length === 0 ? (
                  <p className="text-center py-8 text-zinc-500 text-xs font-mono">
                    No matching files found.
                  </p>
                ) : (
                  filteredFlatFiles.map((file) => {
                    const isSelected = selectedTreeFile?.filepath === file.filepath;
                    const badge = getCategoryBadge(file.category);
                    const fileFindings = getFileFindingsCount(file.filepath);

                    return (
                      <div
                        key={file.filepath}
                        onClick={() => selectTreeFile(file)}
                        className={`p-2 rounded-lg border cursor-pointer transition-all ${
                          isSelected
                            ? "bg-zinc-900 border-cyan-500/80 shadow-sm"
                            : "bg-zinc-950 border-zinc-800/80 hover:bg-zinc-900/60"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1 mb-1">
                          <div className="flex items-center gap-1.5 truncate">
                            {badge.icon}
                            <span className="font-mono text-xs font-semibold text-zinc-200 truncate">
                              {file.filename}
                            </span>
                          </div>
                          <div className="flex items-center gap-1">
                            {fileFindings > 0 && (
                              <span className="flex items-center gap-0.5 px-1 py-0.2 rounded bg-red-950 text-red-400 border border-red-800 text-[9px] font-mono font-bold">
                                <Flame className="w-2.5 h-2.5" />
                                {fileFindings}
                              </span>
                            )}
                            <span className={`text-[9px] font-mono px-1 py-0.2 rounded border ${badge.color}`}>
                              {badge.label}
                            </span>
                          </div>
                        </div>

                        <p className="text-[11px] text-zinc-400 line-clamp-2 leading-relaxed">
                          {file.purpose}
                        </p>

                        <div className="mt-1.5 pt-1 border-t border-zinc-800/50 flex items-center justify-between text-[10px] text-zinc-500 font-mono">
                          <span className="truncate max-w-[180px]">{file.filepath}</span>
                          <span>{file.line_count} lines</span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            ) : (
              renderDirectoryNode(appTree.tree)
            )}
          </div>
        </div>
      )}
    </aside>
  );
}
