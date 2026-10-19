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
  Sliders,
  Download,
  GraduationCap,
  Terminal,
  ChevronDown,
  CheckCircle2,
  AlertTriangle,
  Package,
  Globe,
  Compass,
  BookOpen,
  Ticket,
  Play,
  Layers,
  Eye,
  EyeOff,
  Flame,
} from "lucide-react";

export function AppMenuBar() {
  const workspaceViewMode = useAuditStore((s) => s.workspaceViewMode);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);
  const audienceMode = useAuditStore((s) => s.audienceMode);
  const setAudienceMode = useAuditStore((s) => s.setAudienceMode);
  const isSettingsBarVisible = useAuditStore((s) => s.isSettingsBarVisible);
  const setSettingsBarVisible = useAuditStore((s) => s.setSettingsBarVisible);
  const platformSettings = useAuditStore((s) => s.platformSettings);
  const updatePlatformSettings = useAuditStore((s) => s.updatePlatformSettings);
  const setSettingsModalOpen = useAuditStore((s) => s.setSettingsModalOpen);
  const setIntegrationModalOpen = useAuditStore((s) => s.setIntegrationModalOpen);
  const setSastPlusActiveTab = useAuditStore((s) => s.setSastPlusActiveTab);
  const raciGovernance = useAuditStore((s) => s.raciGovernance);
  const sastPlusSuite = useAuditStore((s) => s.sastPlusSuite);
  const triggerScan = useAuditStore((s) => s.triggerScan);
  const exportAuditReport = useAuditStore((s) => s.exportAuditReport);
  const extractAndScanFromSites = useAuditStore((s) => s.extractAndScanFromSites);
  const setActiveSidebarTab = useAuditStore((s) => s.setActiveSidebarTab);
  const setShowPortalGate = useAuditStore((s) => s.setShowPortalGate);
  const setGraphFullscreen = useAuditStore((s) => s.setGraphFullscreen);
  const appTheme = useAuditStore((s) => s.appTheme);
  const setAppTheme = useAuditStore((s) => s.setAppTheme);
  const projectPath = useAuditStore((s) => s.projectPath);
  const setProjectPath = useAuditStore((s) => s.setProjectPath);
  const findings = useAuditStore((s) => s.findings);
  const isScanning = useAuditStore((s) => s.isScanning);
  const isMenuBarExpanded = useAuditStore((s) => s.isMenuBarExpanded);
  const setMenuBarExpanded = useAuditStore((s) => s.setMenuBarExpanded);
  const uiDensityMode = useAuditStore((s) => s.uiDensityMode);

  const [openMenu, setOpenMenu] = useState<
    null | "WORKSPACE" | "ENGINES" | "RACI" | "SAST_PLUS" | "SETTINGS" | "EXPORT"
  >(null);

  const menuContainerRef = useRef<HTMLDivElement | null>(null);

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

  const enabledEngines = platformSettings?.enabled_engines || ["SAST", "SCA", "IaC"];
  const activePresetId = platformSettings?.active_preset_id || "preset-optimized";
  const presets = platformSettings?.presets || [];

  const handleToggleEngine = async (eng: string) => {
    const exists = enabledEngines.includes(eng);
    const next = exists
      ? enabledEngines.filter((e) => e !== eng)
      : [...enabledEngines, eng];
    if (next.length === 0) return; // keep at least 1 engine enabled
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

  const raciHealth = raciGovernance?.governance_health_score ?? 100;
  const raciWarningsCount = raciGovernance?.validation_warnings?.length ?? 0;

  if (!isMenuBarExpanded && uiDensityMode === "SIMPLE_CLEAN") {
    return null;
  }

  return (
    <div
      ref={menuContainerRef}
      className="flex flex-col bg-zinc-950/95 border-b border-zinc-800/90 text-xs select-none relative z-50"
    >
      {/* ROW 1: Streamlined Desktop Application Menu Bar */}
      <div className="h-8 px-3 flex items-center justify-between border-b border-zinc-900/90 bg-zinc-950">
        <div className="flex items-center gap-1">
          <span className="text-[10px] font-mono uppercase tracking-widest text-rose-400 font-bold px-2 py-0.5 rounded bg-rose-950/50 border border-rose-800/60 mr-1">
            SAST ++++++ MENU
          </span>

          {/* MENU 1: WORKSPACE & VIEWS */}
          <div className="relative">
            <button
              type="button"
              onClick={() =>
                setOpenMenu(openMenu === "WORKSPACE" ? null : "WORKSPACE")
              }
              className={`px-2.5 py-1 rounded flex items-center gap-1 text-[11px] font-medium transition-colors ${
                openMenu === "WORKSPACE"
                  ? "bg-zinc-800 text-cyan-300"
                  : "text-zinc-300 hover:bg-zinc-900 hover:text-white"
              }`}
            >
              <span>Workspace</span>
              <ChevronDown className="w-3 h-3 text-zinc-500" />
            </button>
            {openMenu === "WORKSPACE" && (
              <div className="absolute left-0 mt-1 w-72 rounded-xl bg-zinc-950 border border-zinc-700 shadow-2xl p-1.5 z-50 space-y-0.5">
                <div className="px-2.5 py-1 text-[9px] font-mono uppercase tracking-wider text-zinc-500">
                  Switch Primary Module View
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode("PROJECTS_HUB");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center justify-between text-left"
                >
                  <span className="flex items-center gap-2 text-zinc-200 font-medium">
                    <FolderGit2 className="w-3.5 h-3.5 text-cyan-400" />
                    1. Projects &amp; Risk Hub
                  </span>
                  {workspaceViewMode === "PROJECTS_HUB" && (
                    <span className="text-[9px] font-mono text-cyan-400 font-bold">
                      ACTIVE
                    </span>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode("DEEP_DIVE");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center justify-between text-left"
                >
                  <span className="flex items-center gap-2 text-zinc-200 font-medium">
                    <PieChart className="w-3.5 h-3.5 text-indigo-400" />
                    2. Deep Dive Analytics &amp; Compliance
                  </span>
                  {workspaceViewMode === "DEEP_DIVE" && (
                    <span className="text-[9px] font-mono text-indigo-400 font-bold">
                      ACTIVE
                    </span>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode("REMEDIATION_IDE");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center justify-between text-left"
                >
                  <span className="flex items-center gap-2 text-zinc-200 font-medium">
                    <Code2 className="w-3.5 h-3.5 text-emerald-400" />
                    3. Vulnerability Remediation IDE
                  </span>
                  {workspaceViewMode === "REMEDIATION_IDE" && (
                    <span className="text-[9px] font-mono text-emerald-400 font-bold">
                      ACTIVE
                    </span>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode("RACI_GOVERNANCE");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center justify-between text-left"
                >
                  <span className="flex items-center gap-2 text-amber-200 font-semibold">
                    <Users className="w-3.5 h-3.5 text-amber-400" />
                    4. RACI Governance &amp; Accountability Matrix
                  </span>
                  {workspaceViewMode === "RACI_GOVERNANCE" && (
                    <span className="text-[9px] font-mono text-amber-400 font-bold">
                      ACTIVE
                    </span>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode("SAST_PLUS_SUITE");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center justify-between text-left"
                >
                  <span className="flex items-center gap-2 text-rose-200 font-semibold">
                    <Sparkles className="w-3.5 h-3.5 text-rose-400" />
                    5. SAST ++++++ ASPM &amp; Non-Coder Hub
                  </span>
                  {workspaceViewMode === "SAST_PLUS_SUITE" && (
                    <span className="text-[9px] font-mono text-rose-400 font-bold">
                      ACTIVE
                    </span>
                  )}
                </button>
                <div className="border-t border-zinc-800 my-1" />
                <button
                  type="button"
                  onClick={() => {
                    setGraphFullscreen(true);
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-zinc-300 text-left"
                >
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Full-Screen 360° Spider &amp; Attack Graph</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowPortalGate(true);
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-amber-300 text-left"
                >
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  <span>Return to Alastor Portal Screen</span>
                </button>
              </div>
            )}
          </div>

          {/* MENU 2: SCAN & ENGINES */}
          <div className="relative">
            <button
              type="button"
              onClick={() =>
                setOpenMenu(openMenu === "ENGINES" ? null : "ENGINES")
              }
              className={`px-2.5 py-1 rounded flex items-center gap-1 text-[11px] font-medium transition-colors ${
                openMenu === "ENGINES"
                  ? "bg-zinc-800 text-cyan-300"
                  : "text-zinc-300 hover:bg-zinc-900 hover:text-white"
              }`}
            >
              <span>Scan &amp; Engines</span>
              <ChevronDown className="w-3 h-3 text-zinc-500" />
            </button>
            {openMenu === "ENGINES" && (
              <div className="absolute left-0 mt-1 w-72 rounded-xl bg-zinc-950 border border-zinc-700 shadow-2xl p-1.5 z-50 space-y-1">
                <button
                  type="button"
                  onClick={() => {
                    setOpenMenu(null);
                    triggerScan();
                  }}
                  className="w-full px-2.5 py-2 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/70 border border-cyan-800/80 flex items-center gap-2 text-cyan-200 font-semibold text-left"
                >
                  <Play className="w-3.5 h-3.5 text-cyan-400 fill-current" />
                  <span>Run Full CPG + SAST++++++ Scan Now</span>
                </button>
                <div className="px-2.5 pt-1 text-[9px] font-mono uppercase tracking-wider text-zinc-500">
                  Toggle Unified Scan Engines
                </div>
                {(["SAST", "SCA", "IaC"] as const).map((eng) => {
                  const active = enabledEngines.includes(eng);
                  return (
                    <button
                      key={eng}
                      type="button"
                      onClick={() => handleToggleEngine(eng)}
                      className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center justify-between text-left"
                    >
                      <span className="text-zinc-200 font-medium">
                        {eng === "SAST"
                          ? "SAST Engine (AST + CFG + DFG)"
                          : eng === "SCA"
                          ? "SCA Engine (Supply-Chain & SBOM)"
                          : "IaC Engine (Docker & Cloud Config)"}
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                          active
                            ? "bg-emerald-950 text-emerald-300 border border-emerald-700"
                            : "bg-zinc-900 text-zinc-500 border border-zinc-800"
                        }`}
                      >
                        {active ? "ON" : "OFF"}
                      </span>
                    </button>
                  );
                })}
                <div className="border-t border-zinc-800 my-1" />
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
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-indigo-300 text-left"
                >
                  <Globe className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Pull Live Web Vulnerability Intel (OSV/NVD)</span>
                </button>
              </div>
            )}
          </div>

          {/* MENU 3: RACI & GOVERNANCE */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setOpenMenu(openMenu === "RACI" ? null : "RACI")}
              className={`px-2.5 py-1 rounded flex items-center gap-1 text-[11px] font-semibold transition-colors ${
                openMenu === "RACI" || workspaceViewMode === "RACI_GOVERNANCE"
                  ? "bg-amber-950/70 text-amber-300 border border-amber-700/60"
                  : "text-amber-300/90 hover:bg-zinc-900 hover:text-amber-200"
              }`}
            >
              <Users className="w-3 h-3 text-amber-400" />
              <span>RACI &amp; Governance</span>
              <ChevronDown className="w-3 h-3 text-amber-500/80" />
            </button>
            {openMenu === "RACI" && (
              <div className="absolute left-0 mt-1 w-80 rounded-xl bg-zinc-950 border border-zinc-700 shadow-2xl p-1.5 z-50 space-y-1">
                <div className="px-2.5 py-1 text-[9px] font-mono uppercase tracking-wider text-amber-400">
                  Management &amp; Accountability Governance
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode("RACI_GOVERNANCE");
                    setOpenMenu(null);
                  }}
                  className="w-full p-2 rounded-lg bg-amber-950/40 hover:bg-amber-950/70 border border-amber-800/60 flex flex-col gap-0.5 text-left"
                >
                  <span className="text-xs font-bold text-amber-200 flex items-center gap-1.5">
                    <Users className="w-3.5 h-3.5 text-amber-400" />
                    Interactive RACI Accountability Matrix
                  </span>
                  <span className="text-[10px] text-zinc-400">
                    Assign Responsible, Accountable, Consulted &amp; Informed roles across all security tasks &amp; findings
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setWorkspaceViewMode("DEEP_DIVE");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-zinc-200 text-left"
                >
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Compliance Scorecards (OWASP / PCI-DSS / ISO)</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSettingsModalOpen(true, "GLOBAL_PROJECT");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-zinc-200 text-left"
                >
                  <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Configure SLA Deadlines &amp; Release Gates</span>
                </button>
                <button
                  type="button"
                  onClick={handleDownloadRaciJson}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-zinc-300 text-left"
                >
                  <Download className="w-3.5 h-3.5 text-amber-400" />
                  <span>Export RACI Governance Matrix (.json)</span>
                </button>
              </div>
            )}
          </div>

          {/* MENU 4: SAST ++++++ SUITE */}
          <div className="relative">
            <button
              type="button"
              onClick={() =>
                setOpenMenu(openMenu === "SAST_PLUS" ? null : "SAST_PLUS")
              }
              className={`px-2.5 py-1 rounded flex items-center gap-1 text-[11px] font-semibold transition-colors ${
                openMenu === "SAST_PLUS" || workspaceViewMode === "SAST_PLUS_SUITE"
                  ? "bg-rose-950/70 text-rose-300 border border-rose-700/60"
                  : "text-rose-300/90 hover:bg-zinc-900 hover:text-rose-200"
              }`}
            >
              <Sparkles className="w-3 h-3 text-rose-400" />
              <span>SAST ++++++ Hub</span>
              <ChevronDown className="w-3 h-3 text-rose-500/80" />
            </button>
            {openMenu === "SAST_PLUS" && (
              <div className="absolute left-0 mt-1 w-80 rounded-xl bg-zinc-950 border border-zinc-700 shadow-2xl p-1.5 z-50 space-y-1">
                <div className="px-2.5 py-1 text-[9px] font-mono uppercase tracking-wider text-rose-400">
                  Next-Gen SAST ++++++ &amp; Non-Coder Capabilities
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setSastPlusActiveTab("TRANSLATOR");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-2 rounded-lg hover:bg-zinc-900 flex items-start gap-2.5 text-left"
                >
                  <GraduationCap className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-zinc-100">
                      1. Plain-English Business Impact Translator
                    </div>
                    <div className="text-[10px] text-zinc-400">
                      Real-world analogies, breach impact &amp; management checklists for non-coders
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSastPlusActiveTab("SBOM");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-2 rounded-lg hover:bg-zinc-900 flex items-start gap-2.5 text-left"
                >
                  <Package className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-zinc-100">
                      2. Live SBOM &amp; Supply-Chain Inspector (CycloneDX)
                    </div>
                    <div className="text-[10px] text-zinc-400">
                      Inspect every library, version pin &amp; export CycloneDX 1.5 JSON
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSastPlusActiveTab("ATTACK_SURFACE");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-2 rounded-lg hover:bg-zinc-900 flex items-start gap-2.5 text-left"
                >
                  <Compass className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-zinc-100">
                      3. API &amp; Entrypoint Attack Surface Discovery
                    </div>
                    <div className="text-[10px] text-zinc-400">
                      Discovers exposed routes &amp; callable functions across workspace files
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSastPlusActiveTab("ROADMAP");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-2 rounded-lg hover:bg-zinc-900 flex items-start gap-2.5 text-left"
                >
                  <Layers className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-zinc-100">
                      4. Prioritized Remediation Roadmap &amp; Sprint Planner
                    </div>
                    <div className="text-[10px] text-zinc-400">
                      Phased action plan (Immediate 24h vs. Current Sprint vs. Hardening)
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSastPlusActiveTab("ACADEMY");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-2 rounded-lg hover:bg-zinc-900 flex items-start gap-2.5 text-left"
                >
                  <BookOpen className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-zinc-100">
                      5. Non-Coder Security Academy &amp; Glossary
                    </div>
                    <div className="text-[10px] text-zinc-400">
                      Student-friendly guide to SAST, SCA, IaC, CPG, BFL, RACI &amp; OWASP
                    </div>
                  </div>
                </button>
              </div>
            )}
          </div>

          {/* MENU 5: SETTINGS & CUSTOMIZATION */}
          <div className="relative">
            <button
              type="button"
              onClick={() =>
                setOpenMenu(openMenu === "SETTINGS" ? null : "SETTINGS")
              }
              className={`px-2.5 py-1 rounded flex items-center gap-1 text-[11px] font-medium transition-colors ${
                openMenu === "SETTINGS"
                  ? "bg-zinc-800 text-cyan-300"
                  : "text-zinc-300 hover:bg-zinc-900 hover:text-white"
              }`}
            >
              <Settings className="w-3 h-3 text-cyan-400" />
              <span>Settings Bar &amp; Rules</span>
              <ChevronDown className="w-3 h-3 text-zinc-500" />
            </button>
            {openMenu === "SETTINGS" && (
              <div className="absolute left-0 mt-1 w-72 rounded-xl bg-zinc-950 border border-zinc-700 shadow-2xl p-1.5 z-50 space-y-1">
                <button
                  type="button"
                  onClick={() => {
                    setSettingsModalOpen(true, "PRESETS");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-zinc-200 text-left"
                >
                  <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                  <span>1. Scan Presets (Optimized / Zero-Trust)</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSettingsModalOpen(true, "GLOBAL_PROJECT");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-zinc-200 text-left"
                >
                  <Settings className="w-3.5 h-3.5 text-emerald-400" />
                  <span>2. Global vs. Project Policy Settings</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSettingsModalOpen(true, "QUERY_VIEWER");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-zinc-200 text-left"
                >
                  <Code2 className="w-3.5 h-3.5 text-indigo-400" />
                  <span>3. Security Query Viewer (Cypher Rules)</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSettingsModalOpen(true, "CUSTOMIZATION");
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-zinc-200 text-left"
                >
                  <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                  <span>4. Custom Sanitizer &amp; Rule Engine</span>
                </button>
                <div className="border-t border-zinc-800 my-1" />
                <button
                  type="button"
                  onClick={() => {
                    setIntegrationModalOpen(true);
                    setOpenMenu(null);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 flex items-center gap-2 text-indigo-300 text-left"
                >
                  <Ticket className="w-3.5 h-3.5 text-indigo-400" />
                  <span>5. Integration Hub (Jira &amp; GitHub Issues)</span>
                </button>
              </div>
            )}
          </div>

          {/* MENU 6: EXPORT & REPORTS */}
          <div className="relative">
            <button
              type="button"
              onClick={() =>
                setOpenMenu(openMenu === "EXPORT" ? null : "EXPORT")
              }
              className={`px-2.5 py-1 rounded flex items-center gap-1 text-[11px] font-medium transition-colors ${
                openMenu === "EXPORT"
                  ? "bg-zinc-800 text-cyan-300"
                  : "text-zinc-300 hover:bg-zinc-900 hover:text-white"
              }`}
            >
              <Download className="w-3 h-3 text-emerald-400" />
              <span>Reports</span>
              <ChevronDown className="w-3 h-3 text-zinc-500" />
            </button>
            {openMenu === "EXPORT" && (
              <div className="absolute left-0 mt-1 w-68 rounded-xl bg-zinc-950 border border-zinc-700 shadow-2xl p-1.5 z-50 space-y-1">
                <button
                  type="button"
                  onClick={() => {
                    setOpenMenu(null);
                    exportAuditReport("markdown");
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 text-left text-zinc-200"
                >
                  Executive Audit Report (.md)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setOpenMenu(null);
                    exportAuditReport("json");
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 text-left text-zinc-200"
                >
                  Full Findings &amp; Metrics Data (.json)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setOpenMenu(null);
                    exportAuditReport("sarif");
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 text-left text-zinc-200"
                >
                  CI/CD SARIF v2.1.0 Report (.sarif.json)
                </button>
                <button
                  type="button"
                  onClick={handleDownloadCycloneDxSbom}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 text-left text-cyan-300 font-medium"
                >
                  CycloneDX v1.5 SBOM (.cdx.json)
                </button>
                <button
                  type="button"
                  onClick={handleDownloadRaciJson}
                  className="w-full px-2.5 py-1.5 rounded-lg hover:bg-zinc-900 text-left text-amber-300 font-medium"
                >
                  RACI Governance Matrix (.json)
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Right Side of Menu Bar: 1-Click Theme Swatch Bar, Audience Switcher & Ribbon Toggle */}
        <div className="flex items-center gap-2">
          {/* 1-Click Visual Theme Swatch Pills */}
          <div
            className="hidden xl:flex items-center gap-0.5 bg-zinc-900 border border-zinc-800 rounded-md p-0.5"
            title="Instant 1-Click Visual Theme Switcher (Light & Dark Modes)"
          >
            {(
              [
                { id: "olympian-light", label: "☀️ Daylight" },
                { id: "athena-parchment", label: "📜 Parchment" },
                { id: "hyperborean-light", label: "❄️ Frost" },
                { id: "alastor-infernal", label: "🔥 Infernal" },
                { id: "hecate-arcane", label: "🔮 Arcane" },
                { id: "stygian-abyss", label: "💎 Abyss" },
              ] as const
            ).map((th) => (
              <button
                key={th.id}
                type="button"
                onClick={() => setAppTheme(th.id)}
                className={`px-1.5 py-0.5 rounded text-[9px] font-semibold transition-all ${
                  appTheme === th.id
                    ? "bg-cyan-950 text-cyan-300 border border-cyan-700/80 shadow-sm font-bold"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {th.label}
              </button>
            ))}
          </div>

          {/* Non-Coder / Management Student Mode vs Technical Mode Switcher */}
          <div
            className="flex items-center bg-zinc-900 border border-zinc-800 rounded-md p-0.5"
            title="Switch between Non-Coder / Management Student Friendly Mode (Plain-English Analogies, RACI, Business Impact) and Pro Engineer Mode"
          >
            <button
              type="button"
              onClick={() => setAudienceMode("NON_CODER_MANAGEMENT")}
              className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold transition-all ${
                audienceMode === "NON_CODER_MANAGEMENT"
                  ? "bg-emerald-950 text-emerald-300 border border-emerald-700/80 shadow-sm"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <GraduationCap className="w-3 h-3 text-emerald-400" />
              <span>🎓 Non-Coder / Management Mode</span>
            </button>
            <button
              type="button"
              onClick={() => setAudienceMode("TECHNICAL_ENGINEER")}
              className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold transition-all ${
                audienceMode === "TECHNICAL_ENGINEER"
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-700/80 shadow-sm"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Terminal className="w-3 h-3 text-cyan-400" />
              <span>⚡ Pro Engineer Mode</span>
            </button>
          </div>

          <button
            type="button"
            onClick={() => setSettingsBarVisible(!isSettingsBarVisible)}
            title="Show or Hide the Quick Settings Ribbon Bar"
            className="px-2 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-[10px] font-mono text-zinc-400 hover:text-zinc-200 flex items-center gap-1"
          >
            {isSettingsBarVisible ? (
              <>
                <EyeOff className="w-3 h-3 text-zinc-400" />
                <span className="hidden md:inline">Hide Settings Bar</span>
              </>
            ) : (
              <>
                <Eye className="w-3 h-3 text-cyan-400" />
                <span className="hidden md:inline">Show Settings Bar</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* ROW 2: Streamlined Quick Settings Bar (Ribbon) */}
      {isSettingsBarVisible && (
        <div className="px-3 py-1.5 bg-zinc-900/75 border-b border-zinc-800/80 flex items-center justify-between gap-2 flex-wrap">
          {/* Left: Quick Scan Preset Selector, Engine Toggles & 1-Click Target Switcher */}
          <div className="flex items-center gap-2.5 flex-wrap">
            {/* Active Application Verification Button */}
            <div className="flex items-center gap-1 bg-zinc-950 border border-zinc-800 rounded-lg p-0.5">
              <button
                type="button"
                disabled={isScanning}
                onClick={() => {
                  triggerScan();
                }}
                title="Run SAST + SCA + IaC Code Property Graph verification on the active application"
                className="px-2.5 py-0.5 rounded-md text-[10px] font-mono font-bold transition-all flex items-center gap-1 bg-emerald-950 text-emerald-300 border border-emerald-700/80 hover:bg-emerald-900"
              >
                <ShieldCheck className="w-3 h-3 text-emerald-400" />
                <span>
                  🛡️ Verify Active Application (
                  {(projectPath || "cpg-sast-platform")
                    .replace(/[\\/]+$/, "")
                    .split(/[\\/]/)
                    .pop() || "cpg-sast-platform"}
                  )
                </span>
              </button>
            </div>

            <span className="text-zinc-800">|</span>

            <div className="flex items-center gap-1.5">
              <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-1">
                <Sliders className="w-3 h-3 text-cyan-400" />
                Preset:
              </span>
              <select
                value={activePresetId}
                onChange={(e) => handlePresetChange(e.target.value)}
                className="bg-zinc-950 border border-zinc-700 rounded px-2 py-0.5 text-[11px] text-cyan-300 font-medium focus:outline-none focus:border-cyan-500"
              >
                {presets.length > 0 ? (
                  presets.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))
                ) : (
                  <option value="preset-optimized">
                    Checkmarx / ALASTOR Optimized (Default)
                  </option>
                )}
              </select>
            </div>

            <span className="text-zinc-800">|</span>

            {/* Live Engine Toggles */}
            <div className="flex items-center gap-1">
              <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 mr-0.5">
                Engines:
              </span>
              {(["SAST", "SCA", "IaC"] as const).map((eng) => {
                const isOn = enabledEngines.includes(eng);
                return (
                  <button
                    key={eng}
                    type="button"
                    onClick={() => handleToggleEngine(eng)}
                    title={`Click to toggle ${eng} scan engine on/off`}
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border transition-all ${
                      isOn
                        ? "bg-emerald-950/80 text-emerald-300 border-emerald-700/80"
                        : "bg-zinc-950 text-zinc-500 border-zinc-800"
                    }`}
                  >
                    {eng}: {isOn ? "ON" : "OFF"}
                  </button>
                );
              })}
            </div>

            <span className="text-zinc-800 hidden lg:inline">|</span>

            {/* SLA & Gate Policy Quick Indicator */}
            <button
              type="button"
              onClick={() => setSettingsModalOpen(true, "GLOBAL_PROJECT")}
              title="Click to customize SLA Remediation Deadlines & CI/CD Fail Gates"
              className="hidden lg:flex items-center gap-1.5 px-2 py-0.5 rounded bg-zinc-950 hover:bg-zinc-900 border border-zinc-800 text-[10px] font-mono text-zinc-300"
            >
              <span>
                Gate:{" "}
                <strong className="text-rose-400">
                  {platformSettings?.fail_on_severity || "CRITICAL"}
                </strong>
              </span>
              <span className="text-zinc-600">•</span>
              <span>
                SLA: Crit {platformSettings?.sla_days?.CRITICAL ?? 7}d / High{" "}
                {platformSettings?.sla_days?.HIGH ?? 14}d
              </span>
            </button>
          </div>

          {/* Right: RACI Health Pill, SBOM Count & Quick Navigation Pills */}
          <div className="flex items-center gap-2 flex-wrap">
            {/* RACI Governance Status Pill */}
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("RACI_GOVERNANCE")}
              title="Click to open the interactive RACI Governance & Accountability Matrix"
              className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border flex items-center gap-1 transition-all ${
                raciWarningsCount === 0
                  ? "bg-amber-950/60 hover:bg-amber-900/70 text-amber-300 border-amber-700/80"
                  : "bg-red-950/70 hover:bg-red-900/80 text-red-300 border-red-700"
              }`}
            >
              {raciWarningsCount === 0 ? (
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-3 h-3 text-red-400" />
              )}
              <span>RACI Governance: {raciHealth}% Valid</span>
            </button>

            {/* SAST++++++ ASPM Quick Pill */}
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("SAST_PLUS_SUITE")}
              title="Click to open SAST++++++ Hub (Plain-English Impact, Live SBOM, Attack Surface, Remediation Roadmap & Non-Coder Academy)"
              className="px-2.5 py-0.5 rounded-full bg-rose-950/60 hover:bg-rose-900/70 border border-rose-700/80 text-rose-200 text-[10px] font-mono font-bold flex items-center gap-1 transition-all"
            >
              <Sparkles className="w-3 h-3 text-rose-400" />
              <span>
                SAST++++++ Maturity:{" "}
                {sastPlusSuite?.overall_maturity_grade || "Grade A"}
              </span>
              {sastPlusSuite && (
                <span className="text-zinc-400">
                  ({sastPlusSuite.total_sbom_components} SBOM pkgs)
                </span>
              )}
            </button>
          </div>
        </div>
      )}

      {/* ROW 3: Interactive 4-Step Non-Coder & Management Guided Workflow Bar */}
      {audienceMode === "NON_CODER_MANAGEMENT" && (
        <div className="px-3 py-1 bg-zinc-950/90 border-b border-zinc-800/80 flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 text-[10px]">
            <span className="px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-700/80 font-bold flex items-center gap-1">
              <GraduationCap className="w-3 h-3 text-emerald-400" />
              Guided Student &amp; Management Journey:
            </span>
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("REMEDIATION_IDE")}
              className={`px-2 py-0.5 rounded border font-medium transition-all ${
                workspaceViewMode === "REMEDIATION_IDE"
                  ? "bg-cyan-950 text-cyan-300 border-cyan-700 font-bold"
                  : "bg-zinc-900 text-zinc-300 border-zinc-800 hover:border-zinc-700"
              }`}
            >
              1️⃣ Inspect Code &amp; Plain-English Fixes ({findings.length} findings)
            </button>
            <span className="text-zinc-600">→</span>
            <button
              type="button"
              onClick={() => {
                setWorkspaceViewMode("SAST_PLUS_SUITE");
                setSastPlusActiveTab("TRANSLATOR");
              }}
              className={`px-2 py-0.5 rounded border font-medium transition-all ${
                workspaceViewMode === "SAST_PLUS_SUITE"
                  ? "bg-rose-950 text-rose-200 border-rose-700 font-bold"
                  : "bg-zinc-900 text-zinc-300 border-zinc-800 hover:border-zinc-700"
              }`}
            >
              2️⃣ Business Impact, Attack Surface &amp; Live SBOM
            </button>
            <span className="text-zinc-600">→</span>
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("RACI_GOVERNANCE")}
              className={`px-2 py-0.5 rounded border font-medium transition-all ${
                workspaceViewMode === "RACI_GOVERNANCE"
                  ? "bg-amber-950 text-amber-200 border-amber-700 font-bold"
                  : "bg-zinc-900 text-zinc-300 border-zinc-800 hover:border-zinc-700"
              }`}
            >
              3️⃣ RACI Accountability Matrix (Who Does What)
            </button>
            <span className="text-zinc-600">→</span>
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("DEEP_DIVE")}
              className={`px-2 py-0.5 rounded border font-medium transition-all ${
                workspaceViewMode === "DEEP_DIVE"
                  ? "bg-indigo-950 text-indigo-200 border-indigo-700 font-bold"
                  : "bg-zinc-900 text-zinc-300 border-zinc-800 hover:border-zinc-700"
              }`}
            >
              4️⃣ Compliance &amp; Executive Export
            </button>
          </div>
          <div className="text-[10px] font-mono text-zinc-400 hidden 2xl:block">
            Active Target:{" "}
            <strong className="text-cyan-300">{projectPath}</strong>
          </div>
        </div>
      )}
    </div>
  );
}
