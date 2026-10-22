"use client";

import React, { useState, useRef, useEffect } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  FolderGit2,
  PieChart,
  Code2,
  Users,
  Sparkles,
  Settings,
  ShieldCheck,
  ShieldAlert,
  Sliders,
  Download,
  GraduationCap,
  Terminal,
  ChevronDown,
  CheckCircle2,
  Package,
  Globe,
  Compass,
  Ticket,
  Play,
  Layers,
  Flame,
  KeyRound,
  PhoneCall,
  Building2,
  Network,
  Command,
} from "lucide-react";

export function AppMenuBar() {
  const {
    workspaceViewMode,
    setWorkspaceViewMode,
    graphViewMode,
    setGraphViewMode,
    ideLayoutMode,
    setIdeLayoutMode,
    audienceMode,
    setAudienceMode,
    platformSettings,
    fetchPlatformSettings,
    updatePlatformSettings,
    userAccountsState,
    fetchUserAccounts,
    switchUserOrAccount,
    setSettingsModalOpen,
    setIntegrationModalOpen,
    setSastPlusActiveTab,
    raciGovernance,
    sastPlusSuite,
    triggerScan,
    exportAuditReport,
    extractAndScanFromSites,
    setActiveSidebarTab,
    setShowPortalGate,
    setGraphFullscreen,
    appTheme,
    setAppTheme,
    projectPath,
    findings,
    filterSecretsOnly,
    setFilterSecretsOnly,
    setQuickCommandOpen,
  } = useAuditStore();

  const [openMenu, setOpenMenu] = useState<
    | null
    | "FILE"
    | "WORKSPACE"
    | "GRAPHS"
    | "RULES"
    | "THREATS"
    | "ACCOUNTS"
    | "REPORTS"
  >(null);

  const menuContainerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!platformSettings) fetchPlatformSettings();
    if (!userAccountsState) fetchUserAccounts();
  }, [platformSettings, userAccountsState, fetchPlatformSettings, fetchUserAccounts]);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (
        menuContainerRef.current &&
        !menuContainerRef.current.contains(e.target as Node)
      ) {
        setOpenMenu(null);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const enabledEngines = platformSettings?.enabled_engines || [
    "SAST",
    "SCA",
    "IaC",
  ];
  const activePresetId =
    platformSettings?.active_preset_id || "preset-optimized";
  const presets = platformSettings?.presets || [];
  const activePreset = presets.find((p) => p.id === activePresetId);

  const accounts = userAccountsState?.accounts || [];
  const users = userAccountsState?.users || [];
  const activeAccount =
    accounts.find((a) => a.id === userAccountsState?.active_account_id) ||
    accounts[0];
  const activeUser =
    users.find((u) => u.id === userAccountsState?.active_user_id) || users[0];

  const secretCount = findings.filter(
    (f) =>
      f.is_secret_finding ||
      (f.rule_id || "").toUpperCase().includes("SECRET") ||
      f.cwe_id === "CWE-798"
  ).length;

  const handleToggleEngine = async (eng: string) => {
    const exists = enabledEngines.includes(eng);
    const next = exists
      ? enabledEngines.filter((e) => e !== eng)
      : [...enabledEngines, eng];
    if (next.length === 0) return;
    await updatePlatformSettings({
      scope: platformSettings?.active_scope || "GLOBAL",
      enabled_engines: next,
    });
  };

  const handlePresetChange = async (presetId: string) => {
    await updatePlatformSettings({
      scope: platformSettings?.active_scope || "GLOBAL",
      active_preset_id: presetId,
    });
    setOpenMenu(null);
  };

  const handleDownloadCycloneDxSbom = () => {
    setOpenMenu(null);
    const cdx = sastPlusSuite?.cyclonedx_json || {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [],
    };
    const blob = new Blob([JSON.stringify(cdx, null, 2)], {
      type: "application/json",
    });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "alastor-sbom.cdx.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const handleDownloadRaciJson = () => {
    setOpenMenu(null);
    if (!raciGovernance) return;
    const blob = new Blob([JSON.stringify(raciGovernance, null, 2)], {
      type: "application/json",
    });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "alastor-raci-governance-matrix.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  return (
    <nav
      ref={menuContainerRef}
      aria-label="Top Application Menu Bar"
      className="h-9 px-3 bg-[#070a10] border-b border-slate-800/90 flex items-center justify-between text-xs select-none relative z-50 shadow-md"
    >
      {/* Left: Structured Desktop Menus with Dropdown Options */}
      <div className="flex items-center gap-1">
        <span className="text-[10px] font-mono uppercase tracking-widest text-amber-300 font-extrabold px-2 py-0.5 rounded bg-amber-500/15 border border-amber-500/40 mr-1">
          ALASTOR MENU
        </span>

        {/* 1. FILE & SCAN MENU */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setOpenMenu(openMenu === "FILE" ? null : "FILE")}
            className={`px-2.5 py-1 rounded-md flex items-center gap-1 text-[11px] font-semibold transition-colors ${
              openMenu === "FILE"
                ? "bg-slate-800 text-amber-300"
                : "text-slate-300 hover:bg-slate-900 hover:text-white"
            }`}
          >
            <span>File &amp; Scan</span>
            <ChevronDown className="w-3 h-3 text-slate-500" />
          </button>
          {openMenu === "FILE" && (
            <div className="absolute left-0 mt-1 w-72 rounded-xl bg-slate-950 border border-slate-700 shadow-2xl p-1.5 z-50 space-y-1">
              <button
                type="button"
                onClick={() => {
                  setOpenMenu(null);
                  triggerScan(projectPath);
                }}
                className="w-full px-2.5 py-2 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 flex items-center gap-2 text-amber-200 font-bold text-left"
              >
                <Play className="w-3.5 h-3.5 text-amber-400 fill-current" />
                <span>Run Full CPG + Secret Scan Now</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setWorkspaceViewMode("PROJECTS_HUB");
                  setOpenMenu(null);
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center gap-2 text-slate-200 text-left"
              >
                <FolderGit2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Open Projects &amp; Repositories Hub</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setOpenMenu(null);
                  setWorkspaceViewMode("REMEDIATION_IDE");
                  setActiveSidebarTab("SITE_EXTRACTOR");
                  extractAndScanFromSites({
                    sources: ["osv", "nvd", "cisa_owasp"],
                    customUrls: [],
                  });
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center gap-2 text-indigo-300 text-left"
              >
                <Globe className="w-3.5 h-3.5 text-indigo-400" />
                <span>Pull Live Web CVE Advisories (OSV / NVD)</span>
              </button>
              <div className="border-t border-slate-800 my-1" />
              <button
                type="button"
                onClick={() => {
                  setQuickCommandOpen(true);
                  setOpenMenu(null);
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center justify-between text-slate-300 text-left"
              >
                <span className="flex items-center gap-2">
                  <Command className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Command Palette</span>
                </span>
                <kbd className="text-[9px] font-mono bg-slate-900 px-1.5 py-0.5 rounded border border-slate-700">
                  Ctrl+K
                </kbd>
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowPortalGate(true);
                  setOpenMenu(null);
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center gap-2 text-rose-300 text-left"
              >
                <Flame className="w-3.5 h-3.5 text-rose-400" />
                <span>Return to Alastor Portal Gate</span>
              </button>
            </div>
          )}
        </div>

        {/* 2. WORKSPACE & VIEWS MENU */}
        <div className="relative">
          <button
            type="button"
            onClick={() =>
              setOpenMenu(openMenu === "WORKSPACE" ? null : "WORKSPACE")
            }
            className={`px-2.5 py-1 rounded-md flex items-center gap-1 text-[11px] font-semibold transition-colors ${
              openMenu === "WORKSPACE"
                ? "bg-slate-800 text-amber-300"
                : "text-slate-300 hover:bg-slate-900 hover:text-white"
            }`}
          >
            <span>Workspace</span>
            <ChevronDown className="w-3 h-3 text-slate-500" />
          </button>
          {openMenu === "WORKSPACE" && (
            <div className="absolute left-0 mt-1 w-80 rounded-xl bg-slate-950 border border-slate-700 shadow-2xl p-1.5 z-50 space-y-0.5">
              <div className="px-2.5 py-1 text-[9px] font-mono uppercase tracking-wider text-slate-500">
                Primary Enterprise Modules
              </div>
              {(
                [
                  {
                    id: "REMEDIATION_IDE",
                    label: "1. Code & CPG Review Workbench",
                    icon: <Code2 className="w-3.5 h-3.5 text-amber-400" />,
                  },
                  {
                    id: "THREAT_MODELING",
                    label: "2. Threat Modeling & Secret Vault",
                    icon: <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />,
                  },
                  {
                    id: "RULE_ENGINE_PROFILES",
                    label: "3. Rule Engine & Test Profiles",
                    icon: <Sliders className="w-3.5 h-3.5 text-cyan-400" />,
                  },
                  {
                    id: "USER_PROFILES",
                    label: "4. User Profiling & Account Separation",
                    icon: <Users className="w-3.5 h-3.5 text-violet-400" />,
                  },
                  {
                    id: "PROJECTS_HUB",
                    label: "5. Projects Hub & CI/CD Webhooks",
                    icon: <FolderGit2 className="w-3.5 h-3.5 text-emerald-400" />,
                  },
                  {
                    id: "DEEP_DIVE",
                    label: "6. Deep Dive Analytics & Compliance",
                    icon: <PieChart className="w-3.5 h-3.5 text-indigo-400" />,
                  },
                  {
                    id: "RACI_GOVERNANCE",
                    label: "7. RACI Governance Matrix",
                    icon: <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />,
                  },
                  {
                    id: "SAST_PLUS_SUITE",
                    label: "8. SAST++++++ ASPM & Live SBOM",
                    icon: <Sparkles className="w-3.5 h-3.5 text-purple-400" />,
                  },
                ] as const
              ).map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode(item.id);
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center justify-between text-left"
                >
                  <span className="flex items-center gap-2 text-slate-200 font-medium">
                    {item.icon}
                    {item.label}
                  </span>
                  {workspaceViewMode === item.id && (
                    <span className="text-[9px] font-mono text-amber-400 font-bold">
                      ACTIVE
                    </span>
                  )}
                </button>
              ))}
              <div className="border-t border-slate-800 my-1" />
              <div className="px-2.5 py-1 text-[9px] font-mono uppercase tracking-wider text-slate-500">
                Workbench Panel Layout
              </div>
              <div className="grid grid-cols-3 gap-1 px-1 pb-1">
                {(
                  [
                    { id: "SPLIT_BOTH", label: "Split Code+Graph" },
                    { id: "CODE_FOCUS", label: "Code Only" },
                    { id: "GRAPH_FOCUS", label: "Graph Only" },
                  ] as const
                ).map((l) => (
                  <button
                    key={l.id}
                    type="button"
                    onClick={() => {
                      setWorkspaceViewMode("REMEDIATION_IDE");
                      setIdeLayoutMode(l.id);
                      setOpenMenu(null);
                    }}
                    className={`px-2 py-1 rounded text-[10px] font-bold border ${
                      ideLayoutMode === l.id
                        ? "bg-amber-500/20 text-amber-300 border-amber-500/50"
                        : "bg-slate-900 text-slate-400 border-slate-800"
                    }`}
                  >
                    {l.label}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* 3. CPG & GRAPHS MENU */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setOpenMenu(openMenu === "GRAPHS" ? null : "GRAPHS")}
            className={`px-2.5 py-1 rounded-md flex items-center gap-1 text-[11px] font-semibold transition-colors ${
              openMenu === "GRAPHS"
                ? "bg-slate-800 text-cyan-300"
                : "text-slate-300 hover:bg-slate-900 hover:text-white"
            }`}
          >
            <Network className="w-3 h-3 text-cyan-400" />
            <span>CPG &amp; Graphs</span>
            <ChevronDown className="w-3 h-3 text-slate-500" />
          </button>
          {openMenu === "GRAPHS" && (
            <div className="absolute left-0 mt-1 w-80 rounded-xl bg-slate-950 border border-slate-700 shadow-2xl p-1.5 z-50 space-y-1">
              <div className="px-2.5 py-1 text-[9px] font-mono uppercase tracking-wider text-cyan-400">
                Interactive Graph Visualizations
              </div>
              {(
                [
                  {
                    id: "FINDING_PATH",
                    label: "1. Vulnerability Attack Path (Source → Sink)",
                    badge: "TAINT",
                  },
                  {
                    id: "APP_TREE",
                    label: "2. Decluttered 360° Application Spider Map",
                    badge: "360° MAP",
                  },
                  {
                    id: "CALL_GRAPH",
                    label: "3. Inter-Procedural Call Graph (:CALLS)",
                    badge: "CALLS",
                  },
                  {
                    id: "ENTRYPOINT_GRAPH",
                    label: "4. Attack Surface Entry Points Graph",
                    badge: "INGRESS",
                  },
                  {
                    id: "DFG_ONLY",
                    label: "5. Data-Flow Slice (DFG_FLOWS_TO)",
                    badge: "DFG",
                  },
                  {
                    id: "CFG_ONLY",
                    label: "6. Control-Flow Slice (CFG_NEXT)",
                    badge: "CFG",
                  },
                  {
                    id: "FULL_CPG",
                    label: "7. Unified Code Property Graph (AST+CFG+DFG)",
                    badge: "FULL CPG",
                  },
                ] as const
              ).map((g) => (
                <button
                  key={g.id}
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode("REMEDIATION_IDE");
                    setGraphViewMode(g.id);
                    if (ideLayoutMode === "CODE_FOCUS") {
                      setIdeLayoutMode("SPLIT_BOTH");
                    }
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center justify-between text-left"
                >
                  <span className="text-slate-200 font-medium">{g.label}</span>
                  <span
                    className={`px-1.5 py-0.5 text-[9px] font-mono font-bold rounded ${
                      graphViewMode === g.id
                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                        : "bg-slate-900 text-slate-400"
                    }`}
                  >
                    {g.badge}
                  </span>
                </button>
              ))}
              <div className="border-t border-slate-800 my-1" />
              <button
                type="button"
                onClick={() => {
                  setGraphFullscreen(true);
                  setOpenMenu(null);
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center gap-2 text-cyan-300 font-semibold text-left"
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Launch Fullscreen 360° Graph Presentation</span>
              </button>
            </div>
          )}
        </div>

        {/* 4. THREAT MODELING & SECRETS MENU */}
        <div className="relative">
          <button
            type="button"
            onClick={() =>
              setOpenMenu(openMenu === "THREATS" ? null : "THREATS")
            }
            className={`px-2.5 py-1 rounded-md flex items-center gap-1 text-[11px] font-semibold transition-colors ${
              openMenu === "THREATS" || workspaceViewMode === "THREAT_MODELING"
                ? "bg-rose-950/70 text-rose-300 border border-rose-700/60"
                : "text-rose-300/90 hover:bg-slate-900"
            }`}
          >
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            <span>Threat Model &amp; Secrets</span>
            <ChevronDown className="w-3 h-3 text-rose-500/80" />
          </button>
          {openMenu === "THREATS" && (
            <div className="absolute left-0 mt-1 w-80 rounded-xl bg-slate-950 border border-slate-700 shadow-2xl p-1.5 z-50 space-y-1">
              <button
                type="button"
                onClick={() => {
                  setWorkspaceViewMode("THREAT_MODELING");
                  setOpenMenu(null);
                }}
                className="w-full p-2 rounded-lg bg-rose-950/40 hover:bg-rose-950/70 border border-rose-800/60 flex flex-col gap-0.5 text-left"
              >
                <span className="text-xs font-bold text-rose-200 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  Open STRIDE Threat Modeling Workspace
                </span>
                <span className="text-[10px] text-slate-400">
                  Interactive STRIDE threat matrix, trust boundaries, attack entrypoints &amp; Secret Keys Vault
                </span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setFilterSecretsOnly(!filterSecretsOnly);
                  setWorkspaceViewMode("REMEDIATION_IDE");
                  setOpenMenu(null);
                }}
                className="w-full px-2.5 py-2 rounded-lg hover:bg-slate-900 flex items-center justify-between text-left"
              >
                <span className="flex items-center gap-2 text-amber-300 font-semibold">
                  <KeyRound className="w-3.5 h-3.5 text-amber-400" />
                  <span>Filter Detected Secret Keys ({secretCount})</span>
                </span>
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  {filterSecretsOnly ? "FILTER ON" : "SHOW KEYS"}
                </span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setWorkspaceViewMode("REMEDIATION_IDE");
                  setGraphViewMode("ENTRYPOINT_GRAPH");
                  setOpenMenu(null);
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center gap-2 text-emerald-300 text-left"
              >
                <Compass className="w-3.5 h-3.5 text-emerald-400" />
                <span>Inspect Attack Surface Entry Points Graph</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setWorkspaceViewMode("REMEDIATION_IDE");
                  setGraphViewMode("CALL_GRAPH");
                  setOpenMenu(null);
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center gap-2 text-purple-300 text-left"
              >
                <PhoneCall className="w-3.5 h-3.5 text-purple-400" />
                <span>Inspect Inter-Procedural Call Graph</span>
              </button>
            </div>
          )}
        </div>

        {/* 5. RULE ENGINE & TEST PROFILES MENU */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setOpenMenu(openMenu === "RULES" ? null : "RULES")}
            className={`px-2.5 py-1 rounded-md flex items-center gap-1 text-[11px] font-semibold transition-colors ${
              openMenu === "RULES" ||
              workspaceViewMode === "RULE_ENGINE_PROFILES"
                ? "bg-cyan-950/70 text-cyan-300 border border-cyan-700/60"
                : "text-cyan-300/90 hover:bg-slate-900"
            }`}
          >
            <Sliders className="w-3 h-3 text-cyan-400" />
            <span>Rule Engine &amp; Profiles</span>
            <ChevronDown className="w-3 h-3 text-cyan-500/80" />
          </button>
          {openMenu === "RULES" && (
            <div className="absolute left-0 mt-1 w-80 rounded-xl bg-slate-950 border border-slate-700 shadow-2xl p-1.5 z-50 space-y-1">
              <button
                type="button"
                onClick={() => {
                  setWorkspaceViewMode("RULE_ENGINE_PROFILES");
                  setOpenMenu(null);
                }}
                className="w-full p-2 rounded-lg bg-cyan-950/40 hover:bg-cyan-950/70 border border-cyan-800/60 flex flex-col gap-0.5 text-left"
              >
                <span className="text-xs font-bold text-cyan-200 flex items-center gap-1.5">
                  <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                  Open Rule Engine &amp; Test Profiles Matrix
                </span>
                <span className="text-[10px] text-slate-400">
                  Create custom test profiles and check/uncheck which individual security rules to execute
                </span>
              </button>

              <div className="px-2.5 pt-1 text-[9px] font-mono uppercase tracking-wider text-slate-500">
                Quick-Switch Active Test Profile
              </div>
              {presets.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => handlePresetChange(p.id)}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center justify-between text-left"
                >
                  <span className="text-slate-200 font-medium truncate pr-2">
                    {p.name}
                  </span>
                  <span
                    className={`px-1.5 py-0.5 text-[9px] font-mono font-bold rounded shrink-0 ${
                      activePresetId === p.id
                        ? "bg-amber-500 text-slate-950"
                        : "bg-slate-900 text-slate-400 border border-slate-800"
                    }`}
                  >
                    {activePresetId === p.id ? "ACTIVE" : p.badge}
                  </span>
                </button>
              ))}

              <div className="border-t border-slate-800 my-1" />
              <div className="px-2.5 py-1 flex items-center justify-between">
                <span className="text-[10px] text-slate-400 font-semibold">
                  Engines:
                </span>
                <div className="flex items-center gap-1">
                  {(["SAST", "SCA", "IaC"] as const).map((eng) => {
                    const isOn = enabledEngines.includes(eng);
                    return (
                      <button
                        key={eng}
                        type="button"
                        onClick={() => handleToggleEngine(eng)}
                        className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border ${
                          isOn
                            ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                            : "bg-slate-900 text-slate-500 border-slate-800"
                        }`}
                      >
                        {eng}: {isOn ? "ON" : "OFF"}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* 6. ACCOUNTS & USER PROFILES MENU */}
        <div className="relative">
          <button
            type="button"
            onClick={() =>
              setOpenMenu(openMenu === "ACCOUNTS" ? null : "ACCOUNTS")
            }
            className={`px-2.5 py-1 rounded-md flex items-center gap-1 text-[11px] font-semibold transition-colors ${
              openMenu === "ACCOUNTS" || workspaceViewMode === "USER_PROFILES"
                ? "bg-violet-950/70 text-violet-300 border border-violet-700/60"
                : "text-violet-300/90 hover:bg-slate-900"
            }`}
          >
            <Users className="w-3 h-3 text-violet-400" />
            <span>Accounts &amp; Users</span>
            <ChevronDown className="w-3 h-3 text-violet-500/80" />
          </button>
          {openMenu === "ACCOUNTS" && (
            <div className="absolute left-0 mt-1 w-80 rounded-xl bg-slate-950 border border-slate-700 shadow-2xl p-1.5 z-50 space-y-1">
              <button
                type="button"
                onClick={() => {
                  setWorkspaceViewMode("USER_PROFILES");
                  setOpenMenu(null);
                }}
                className="w-full p-2 rounded-lg bg-violet-950/40 hover:bg-violet-950/70 border border-violet-800/60 flex flex-col gap-0.5 text-left"
              >
                <span className="text-xs font-bold text-violet-200 flex items-center gap-1.5">
                  <Users className="w-3.5 h-3.5 text-violet-400" />
                  Open User Profiling &amp; Account Separation
                </span>
                <span className="text-[10px] text-slate-400">
                  Manage isolated tenant accounts, RBAC user profiles, secret reveal clearance &amp; audit trail
                </span>
              </button>

              <div className="px-2.5 pt-1 text-[9px] font-mono uppercase tracking-wider text-slate-500">
                Switch Isolated Tenant Account
              </div>
              {accounts.map((acct) => (
                <button
                  key={acct.id}
                  type="button"
                  onClick={() => {
                    switchUserOrAccount({ account_id: acct.id });
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center justify-between text-left"
                >
                  <span className="flex items-center gap-1.5 text-slate-200 font-medium truncate">
                    <Building2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span className="truncate">{acct.name}</span>
                  </span>
                  {activeAccount?.id === acct.id && (
                    <span className="text-[9px] font-mono text-cyan-400 font-bold shrink-0">
                      ACTIVE
                    </span>
                  )}
                </button>
              ))}

              <div className="px-2.5 pt-1 text-[9px] font-mono uppercase tracking-wider text-slate-500">
                Assume RBAC User Profile
              </div>
              {users.map((u) => (
                <button
                  key={u.id}
                  type="button"
                  onClick={() => {
                    switchUserOrAccount({ user_id: u.id });
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center justify-between text-left"
                >
                  <span className="text-slate-200 font-medium truncate">
                    {u.name}{" "}
                    <span className="text-[10px] text-slate-400">
                      ({u.role})
                    </span>
                  </span>
                  {activeUser?.id === u.id && (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 7. REPORTS & INTEGRATIONS MENU */}
        <div className="relative">
          <button
            type="button"
            onClick={() =>
              setOpenMenu(openMenu === "REPORTS" ? null : "REPORTS")
            }
            className={`px-2.5 py-1 rounded-md flex items-center gap-1 text-[11px] font-semibold transition-colors ${
              openMenu === "REPORTS"
                ? "bg-slate-800 text-emerald-300"
                : "text-slate-300 hover:bg-slate-900 hover:text-white"
            }`}
          >
            <Download className="w-3 h-3 text-emerald-400" />
            <span>Reports &amp; Connectors</span>
            <ChevronDown className="w-3 h-3 text-slate-500" />
          </button>
          {openMenu === "REPORTS" && (
            <div className="absolute left-0 mt-1 w-72 rounded-xl bg-slate-950 border border-slate-700 shadow-2xl p-1.5 z-50 space-y-1">
              <button
                type="button"
                onClick={() => {
                  setOpenMenu(null);
                  exportAuditReport("markdown");
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 text-left text-slate-200"
              >
                Executive Audit Report (.md)
              </button>
              <button
                type="button"
                onClick={() => {
                  setOpenMenu(null);
                  exportAuditReport("json");
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 text-left text-slate-200"
              >
                Full Findings &amp; Metrics Data (.json)
              </button>
              <button
                type="button"
                onClick={() => {
                  setOpenMenu(null);
                  exportAuditReport("sarif");
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 text-left text-slate-200"
              >
                CI/CD SARIF v2.1.0 Report (.sarif.json)
              </button>
              <button
                type="button"
                onClick={handleDownloadCycloneDxSbom}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 text-left text-cyan-300 font-medium"
              >
                CycloneDX v1.5 SBOM (.cdx.json)
              </button>
              <button
                type="button"
                onClick={handleDownloadRaciJson}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 text-left text-amber-300 font-medium"
              >
                RACI Governance Matrix (.json)
              </button>
              <div className="border-t border-slate-800 my-1" />
              <button
                type="button"
                onClick={() => {
                  setIntegrationModalOpen(true);
                  setOpenMenu(null);
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center gap-2 text-indigo-300 font-semibold text-left"
              >
                <Ticket className="w-3.5 h-3.5 text-indigo-400" />
                <span>Jira &amp; GitHub Issues Connectors</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setSettingsModalOpen(true, "GLOBAL_PROJECT");
                  setOpenMenu(null);
                }}
                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-slate-900 flex items-center gap-2 text-slate-300 text-left"
              >
                <Settings className="w-3.5 h-3.5 text-cyan-400" />
                <span>Advanced Engine &amp; Sanitizer Settings</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Right: Active Account Badge, Active User Profile Badge, Active Test Profile Badge & Mode Switcher */}
      <div className="flex items-center gap-2">
        {/* Active Test Profile Pill */}
        <button
          type="button"
          onClick={() => setWorkspaceViewMode("RULE_ENGINE_PROFILES")}
          title="Click to configure Test Profiles & Rule Selection"
          className="hidden lg:flex items-center gap-1.5 px-2.5 py-0.5 rounded-md bg-cyan-950/50 hover:bg-cyan-900/60 border border-cyan-500/40 text-[10px] font-mono text-cyan-300"
        >
          <Sliders className="w-3 h-3 text-cyan-400" />
          <span>Profile:</span>
          <strong className="text-amber-300">
            {activePreset?.badge || "OPTIMIZED"}
          </strong>
        </button>

        {/* Active Tenant Account & Operator Pill */}
        <button
          type="button"
          onClick={() => setWorkspaceViewMode("USER_PROFILES")}
          title="Click to switch Tenant Account or RBAC Operator Profile"
          className="hidden md:flex items-center gap-1.5 px-2.5 py-0.5 rounded-md bg-violet-950/50 hover:bg-violet-900/60 border border-violet-500/40 text-[10px] font-mono text-violet-200"
        >
          <Building2 className="w-3 h-3 text-cyan-400" />
          <span className="truncate max-w-[140px]">
            {activeAccount?.name || "Enterprise Security HQ"}
          </span>
          <span className="text-slate-500">•</span>
          <strong className="text-amber-300">
            {activeUser?.name || "Dr. Elena Vance"}
          </strong>
        </button>

        {/* Audience Mode Toggle */}
        <button
          type="button"
          onClick={() =>
            setAudienceMode(
              audienceMode === "NON_CODER_MANAGEMENT"
                ? "TECHNICAL_ENGINEER"
                : "NON_CODER_MANAGEMENT"
            )
          }
          title="Toggle between Management Plain-English Mode and Technical Engineer Mode"
          className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[10px] font-semibold text-slate-200"
        >
          {audienceMode === "NON_CODER_MANAGEMENT" ? (
            <>
              <GraduationCap className="w-3 h-3 text-emerald-400" />
              <span>Management View</span>
            </>
          ) : (
            <>
              <Terminal className="w-3 h-3 text-cyan-400" />
              <span>Engineer View</span>
            </>
          )}
        </button>
      </div>
    </nav>
  );
}
