"use client";

import React, { useState, useEffect } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { BackdropIntensity, SecurityQueryRule } from "@/types/cpg";
import { ALASTOR_THEMES } from "./AlastorBranding";
import {
  Settings,
  Sliders,
  Code2,
  ShieldCheck,
  Plus,
  CheckCircle2,
  X,
  Save,
  Eye,
  Wrench,
  Globe,
  FolderGit2,
  Palette,
  Sun,
  Sparkles,
  KeyRound,
  Check,
  ArrowUpRight,
} from "lucide-react";

type ModalTabId =
  | "PRESETS"
  | "GLOBAL_VS_PROJECT"
  | "QUERY_VIEWER"
  | "CUSTOMIZATION_ENGINE"
  | "APPEARANCE_AI";

export function SettingsCustomizationModal() {
  const isOpen = useAuditStore((s) => s.isSettingsModalOpen);
  const settingsActiveTab = useAuditStore((s) => s.settingsActiveTab);
  const setOpen = useAuditStore((s) => s.setSettingsModalOpen);
  const platformSettings = useAuditStore((s) => s.platformSettings);
  const fetchPlatformSettings = useAuditStore((s) => s.fetchPlatformSettings);
  const updatePlatformSettings = useAuditStore((s) => s.updatePlatformSettings);
  const upsertQueryRule = useAuditStore((s) => s.upsertQueryRule);
  const toggleQueryRule = useAuditStore((s) => s.toggleQueryRule);
  const addCustomSanitizer = useAuditStore((s) => s.addCustomSanitizer);
  const toggleCustomSanitizer = useAuditStore((s) => s.toggleCustomSanitizer);
  const projects = useAuditStore((s) => s.projects);

  const appTheme = useAuditStore((s) => s.appTheme);
  const setAppTheme = useAuditStore((s) => s.setAppTheme);
  const backdropIntensity = useAuditStore((s) => s.backdropIntensity);
  const setBackdropIntensity = useAuditStore((s) => s.setBackdropIntensity);
  const aiConfig = useAuditStore((s) => s.aiConfig);
  const setAiDrawerOpen = useAuditStore((s) => s.setAiDrawerOpen);

  const [activeTab, setActiveTab] = useState<ModalTabId>("PRESETS");

  // Query Viewer / Editor state
  const [selectedRule, setSelectedRule] = useState<SecurityQueryRule | null>(
    null
  );
  const [editRuleId, setEditRuleId] = useState("");
  const [editRuleName, setEditRuleName] = useState("");
  const [editEngine, setEditEngine] = useState<"SAST" | "SCA" | "IaC">("SAST");
  const [editLanguage, setEditLanguage] = useState("Python");
  const [editSeverity, setEditSeverity] = useState<
    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  >("HIGH");
  const [editCweId, setEditCweId] = useState("CWE-78");
  const [editOwasp, setEditOwasp] = useState("A03:2021 - Injection");
  const [editDescription, setEditDescription] = useState("");
  const [editCypher, setEditCypher] = useState("");
  const [editRemediation, setEditRemediation] = useState("");

  // Custom Sanitizer form state
  const [sanName, setSanName] = useState("");
  const [sanLang, setSanLang] = useState("Python");
  const [sanCwe, setSanCwe] = useState("CWE-78");
  const [sanDesc, setSanDesc] = useState("");

  // Global vs Project override state
  const [selectedScopeProject, setSelectedScopeProject] =
    useState<string>("proj-argon-core");
  const [savedBanner, setSavedBanner] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    if (settingsActiveTab === "GLOBAL_PROJECT") {
      setActiveTab("GLOBAL_VS_PROJECT");
    } else if (settingsActiveTab === "QUERY_VIEWER") {
      setActiveTab("QUERY_VIEWER");
    } else if (settingsActiveTab === "CUSTOMIZATION") {
      setActiveTab("CUSTOMIZATION_ENGINE");
    } else {
      setActiveTab("PRESETS");
    }
  }, [isOpen, settingsActiveTab]);

  useEffect(() => {
    if (isOpen && !platformSettings) {
      fetchPlatformSettings();
    }
  }, [isOpen, platformSettings, fetchPlatformSettings]);

  useEffect(() => {
    if (projects.length > 0 && !selectedScopeProject) {
      const activeProj = projects.find((p) => p.is_active) || projects[0];
      setSelectedScopeProject(activeProj.id);
    }
  }, [projects, selectedScopeProject]);

  useEffect(() => {
    if (platformSettings?.queries?.length && !selectedRule) {
      const first = platformSettings.queries[0];
      setSelectedRule(first);
      populateEditorFromRule(first);
    }
  }, [platformSettings, selectedRule]);

  const populateEditorFromRule = (r: SecurityQueryRule) => {
    setEditRuleId(r.id);
    setEditRuleName(r.name);
    setEditEngine(r.engine);
    setEditLanguage(r.language);
    setEditSeverity(
      (r.severity === "INFO" ? "LOW" : r.severity) as
        | "CRITICAL"
        | "HIGH"
        | "MEDIUM"
        | "LOW"
    );
    setEditCweId(r.cwe_id);
    setEditOwasp(r.owasp_category);
    setEditDescription(r.description);
    setEditCypher(r.cypher);
    setEditRemediation(r.remediation);
  };

  if (!isOpen) return null;

  const presets = platformSettings?.presets || [];
  const queries = platformSettings?.queries || [];
  const sanitizers = platformSettings?.custom_sanitizers || [];

  const handleSaveQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editRuleName.trim() || !editCypher.trim()) return;
    await upsertQueryRule({
      id: editRuleId.trim() || undefined,
      name: editRuleName.trim(),
      engine: editEngine,
      language: editLanguage,
      severity: editSeverity,
      cwe_id: editCweId,
      owasp_category: editOwasp,
      description: editDescription,
      cypher: editCypher,
      remediation: editRemediation,
      enabled: true,
    });
    setSavedBanner(`Saved & compiled security query: ${editRuleName}`);
    setTimeout(() => setSavedBanner(null), 3500);
  };

  const handleAddSanitizer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sanName.trim()) return;
    await addCustomSanitizer({
      function_name: sanName.trim(),
      language: sanLang,
      target_cwe: sanCwe,
      description:
        sanDesc.trim() ||
        `Custom codebase sanitizer neutralizing tainted data flows for ${sanCwe}`,
    });
    setSanName("");
    setSanDesc("");
    setSavedBanner(
      `Registered Custom Sanitizer '${sanName}' into CPG Taint Engine & Neo4j Graph`
    );
    setTimeout(() => setSavedBanner(null), 3500);
  };

  return (
    <div
      className="fixed inset-0 z-[170] bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 select-none"
      onClick={() => setOpen(false)}
    >
      <div
        className="bg-white border border-slate-300 rounded-2xl shadow-2xl w-full max-w-6xl max-h-[88vh] flex flex-col overflow-hidden text-slate-900"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-sky-100 border border-sky-300 flex items-center justify-center shrink-0">
              <Settings className="w-4 h-4 text-sky-800" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                Settings, Presets, Queries &amp; Daylight Appearance
                <span className="px-2 py-0.5 rounded bg-sky-100 text-sky-900 border border-sky-300 text-[10px] font-mono font-bold">
                  ALASTOR v4 CONFIG
                </span>
              </h2>
              <p className="text-[11px] text-slate-600">
                Configure Scan Presets, Global vs. Project Overrides, Cypher
                Queries, Custom Sanitizers, Daylight Palettes &amp; Frontier AI
              </p>
            </div>
          </div>

          {/* 5 Sub-Module Tabs */}
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl border border-slate-200 text-xs flex-wrap">
            <button
              type="button"
              onClick={() => setActiveTab("PRESETS")}
              className={`px-2.5 py-1.5 rounded-lg font-semibold flex items-center gap-1.5 transition-all ${
                activeTab === "PRESETS"
                  ? "bg-sky-700 text-white shadow-sm"
                  : "text-slate-700 hover:bg-white hover:text-slate-900"
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>1. Presets</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("GLOBAL_VS_PROJECT")}
              className={`px-2.5 py-1.5 rounded-lg font-semibold flex items-center gap-1.5 transition-all ${
                activeTab === "GLOBAL_VS_PROJECT"
                  ? "bg-sky-700 text-white shadow-sm"
                  : "text-slate-700 hover:bg-white hover:text-slate-900"
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>2. Global vs. Project</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("QUERY_VIEWER")}
              className={`px-2.5 py-1.5 rounded-lg font-semibold flex items-center gap-1.5 transition-all ${
                activeTab === "QUERY_VIEWER"
                  ? "bg-sky-700 text-white shadow-sm"
                  : "text-slate-700 hover:bg-white hover:text-slate-900"
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>3. Queries ({queries.length})</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("CUSTOMIZATION_ENGINE")}
              className={`px-2.5 py-1.5 rounded-lg font-semibold flex items-center gap-1.5 transition-all ${
                activeTab === "CUSTOMIZATION_ENGINE"
                  ? "bg-sky-700 text-white shadow-sm"
                  : "text-slate-700 hover:bg-white hover:text-slate-900"
              }`}
            >
              <Wrench className="w-3.5 h-3.5" />
              <span>4. Sanitizers &amp; Cypher</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("APPEARANCE_AI")}
              className={`px-2.5 py-1.5 rounded-lg font-semibold flex items-center gap-1.5 transition-all ${
                activeTab === "APPEARANCE_AI"
                  ? "bg-indigo-700 text-white shadow-sm"
                  : "text-slate-700 hover:bg-white hover:text-slate-900"
              }`}
            >
              <Palette className="w-3.5 h-3.5" />
              <span>5. Appearance &amp; AI</span>
            </button>
          </div>

          <button
            type="button"
            onClick={() => setOpen(false)}
            className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-700 hover:text-slate-900"
            title="Close Settings"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {savedBanner && (
          <div className="px-5 py-2 bg-emerald-50 border-b border-emerald-300 text-emerald-900 text-xs font-mono font-semibold flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-700" />
            <span>{savedBanner}</span>
          </div>
        )}

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 text-xs bg-white">
          {/* TAB 1: SCAN PRESETS */}
          {activeTab === "PRESETS" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-slate-900">
                    Predefined Scanning Profiles (Scan Presets)
                  </h3>
                  <p className="text-slate-600 text-xs mt-0.5">
                    Select an out-of-the-box scanning profile. ALASTOR includes
                    the{" "}
                    <b className="text-sky-800">Optimized</b> preset by default
                    to balance high recall with minimal false positives.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {presets.map((preset) => {
                  const isSelected =
                    (platformSettings?.active_preset_id ||
                      "preset-optimized") === preset.id;
                  return (
                    <div
                      key={preset.id}
                      onClick={async () => {
                        await updatePlatformSettings({
                          scope: "GLOBAL",
                          active_preset_id: preset.id,
                        });
                        setSavedBanner(`Activated Scan Preset: ${preset.name}`);
                        setTimeout(() => setSavedBanner(null), 3000);
                      }}
                      className={`p-5 rounded-2xl border cursor-pointer transition-all flex flex-col justify-between ${
                        isSelected
                          ? "bg-sky-50/70 border-sky-600 ring-1 ring-sky-600/30 shadow-sm"
                          : "bg-slate-50 border-slate-200 hover:border-slate-300 hover:bg-white"
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <span className="px-2 py-0.5 rounded bg-sky-100 text-sky-900 border border-sky-300 text-[10px] font-mono font-bold">
                            {preset.badge}
                          </span>
                          {isSelected && (
                            <span className="flex items-center gap-1 text-emerald-800 font-mono text-[11px] font-bold">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700" />
                              ACTIVE PRESET
                            </span>
                          )}
                        </div>
                        <h4 className="text-sm font-bold text-slate-900">
                          {preset.name}
                        </h4>
                        <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                          {preset.description}
                        </p>
                      </div>

                      <div className="mt-4 pt-3 border-t border-slate-200 flex items-center justify-between text-[11px] font-mono">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-slate-500">Engines:</span>
                          {preset.enabled_engines.map((eng) => (
                            <span
                              key={eng}
                              className="px-1.5 py-0.5 rounded bg-white border border-slate-300 text-sky-800 font-bold"
                            >
                              {eng}
                            </span>
                          ))}
                        </div>
                        <span className="text-slate-700 font-semibold">
                          {preset.enabled_rule_ids.length} Active Queries
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 2: GLOBAL VS. PROJECT SETTINGS */}
          {activeTab === "GLOBAL_VS_PROJECT" && platformSettings && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Left Column: Global Baseline Configuration */}
              <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                      <Globe className="w-4 h-4 text-sky-700" />
                      Global Organization Settings
                    </h3>
                    <p className="text-[11px] text-slate-600">
                      Default baseline inherited by all projects unless
                      overridden
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-sky-100 text-sky-900 border border-sky-300 font-mono text-[10px] font-bold">
                    GLOBAL SCOPE
                  </span>
                </div>

                <div className="space-y-3">
                  <div>
                    <label className="block text-[11px] font-mono font-semibold text-slate-700 mb-1">
                      Global Default Scan Preset
                    </label>
                    <select
                      value={platformSettings.active_preset_id}
                      onChange={(e) =>
                        updatePlatformSettings({
                          scope: "GLOBAL",
                          active_preset_id: e.target.value,
                        })
                      }
                      className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 font-medium"
                    >
                      {presets.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono font-semibold text-slate-700 mb-1">
                      Max Data-Flow &amp; Call Graph Depth (
                      {platformSettings.max_dfg_depth} hops)
                    </label>
                    <input
                      type="range"
                      min={5}
                      max={40}
                      value={platformSettings.max_dfg_depth}
                      onChange={(e) =>
                        updatePlatformSettings({
                          scope: "GLOBAL",
                          max_dfg_depth: Number(e.target.value),
                        })
                      }
                      className="w-full accent-sky-700"
                    />
                  </div>

                  <label className="flex items-center justify-between p-3 rounded-xl bg-white border border-slate-200 cursor-pointer">
                    <div>
                      <div className="font-semibold text-slate-900">
                        Auto-Suppress Low Severity Informational Findings
                      </div>
                      <div className="text-[11px] text-slate-600">
                        Focus remediation queues on Critical, High, and Medium
                        flaws
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={platformSettings.auto_suppress_low}
                      onChange={(e) =>
                        updatePlatformSettings({
                          scope: "GLOBAL",
                          auto_suppress_low: e.target.checked,
                        })
                      }
                      className="accent-sky-700 w-4 h-4"
                    />
                  </label>
                </div>
              </div>

              {/* Right Column: Project-Specific Override Settings */}
              <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                      <FolderGit2 className="w-4 h-4 text-indigo-700" />
                      Project-Level Configuration Override
                    </h3>
                    <p className="text-[11px] text-slate-600">
                      Override global scan presets, depth, or excluded paths for
                      a specific repository
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-indigo-100 text-indigo-900 border border-indigo-300 font-mono text-[10px] font-bold">
                    PROJECT OVERRIDE
                  </span>
                </div>

                <div>
                  <label className="block text-[11px] font-mono font-semibold text-slate-700 mb-1">
                    Select Target Project
                  </label>
                  <select
                    value={selectedScopeProject}
                    onChange={(e) => setSelectedScopeProject(e.target.value)}
                    className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-sky-900 font-mono font-semibold"
                  >
                    {projects.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} ({p.id})
                      </option>
                    ))}
                  </select>
                </div>

                {(() => {
                  const projOverride =
                    platformSettings.project_overrides?.[
                      selectedScopeProject
                    ] || {
                      active_preset_id: platformSettings.active_preset_id,
                      max_dfg_depth: platformSettings.max_dfg_depth,
                      excluded_paths: platformSettings.excluded_paths,
                    };

                  return (
                    <div className="space-y-3">
                      <div>
                        <label className="block text-[11px] font-mono font-semibold text-slate-700 mb-1">
                          Project Scan Preset Override
                        </label>
                        <select
                          value={
                            projOverride.active_preset_id ||
                            platformSettings.active_preset_id
                          }
                          onChange={(e) =>
                            updatePlatformSettings({
                              scope: "PROJECT",
                              project_id: selectedScopeProject,
                              active_preset_id: e.target.value,
                            })
                          }
                          className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 font-medium"
                        >
                          {presets.map((p) => (
                            <option key={p.id} value={p.id}>
                              {p.name}
                            </option>
                          ))}
                        </select>
                      </div>

                      <div className="p-3 rounded-xl bg-white border border-slate-200">
                        <div className="text-[11px] font-mono font-semibold text-slate-600 mb-1.5">
                          Active Excluded Directories for {selectedScopeProject}:
                        </div>
                        <div className="flex items-center gap-1.5 flex-wrap font-mono text-[10px]">
                          {(platformSettings.excluded_paths || []).map((ep) => (
                            <span
                              key={ep}
                              className="px-2 py-0.5 rounded bg-slate-100 border border-slate-300 text-slate-800 font-medium"
                            >
                              {ep}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  );
                })()}
              </div>
            </div>
          )}

          {/* TAB 3: QUERY VIEWER */}
          {activeTab === "QUERY_VIEWER" && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* Left Query List */}
              <div className="lg:col-span-5 space-y-2 max-h-[540px] overflow-y-auto pr-1">
                <div className="text-[11px] font-mono font-bold uppercase text-slate-600 mb-2">
                  Underlying Security Queries ({queries.length})
                </div>
                {queries.map((q) => {
                  const isSel = selectedRule?.id === q.id;
                  return (
                    <div
                      key={q.id}
                      onClick={() => {
                        setSelectedRule(q);
                        populateEditorFromRule(q);
                      }}
                      className={`p-3 rounded-xl border cursor-pointer transition-all ${
                        isSel
                          ? "bg-sky-50 border-sky-600 shadow-sm"
                          : "bg-slate-50 border-slate-200 hover:border-slate-300 hover:bg-white"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <div className="flex items-center gap-1.5">
                          <span className="px-1.5 py-0.5 rounded bg-sky-100 text-sky-900 border border-sky-300 font-mono text-[10px] font-bold">
                            {q.engine}
                          </span>
                          <span className="font-mono text-[10px] text-slate-600">
                            {q.id}
                          </span>
                          {q.is_custom && (
                            <span className="px-1.5 py-0.5 rounded bg-amber-100 text-amber-900 border border-amber-300 font-mono text-[9px] font-bold">
                              CUSTOM
                            </span>
                          )}
                        </div>
                        <input
                          type="checkbox"
                          checked={q.enabled}
                          onChange={(e) => {
                            e.stopPropagation();
                            toggleQueryRule(q.id);
                          }}
                          title="Enable or disable this query rule"
                          className="accent-sky-700 cursor-pointer w-4 h-4"
                        />
                      </div>
                      <div className="font-bold text-slate-900 text-xs">
                        {q.name}
                      </div>
                      <div className="text-[10px] font-mono text-slate-600 mt-1 flex items-center justify-between">
                        <span>
                          {q.cwe_id} • {q.language}
                        </span>
                        <span className="text-rose-800 font-bold">
                          {q.severity}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Right Query Inspector */}
              <div className="lg:col-span-7">
                {selectedRule ? (
                  <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-4">
                    <div className="flex items-center justify-between border-b border-slate-200 pb-3 gap-3 flex-wrap">
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="px-2 py-0.5 rounded bg-sky-100 text-sky-900 border border-sky-300 font-mono text-[10px] font-bold">
                            {selectedRule.id}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-indigo-100 text-indigo-900 border border-indigo-300 font-mono text-[10px] font-bold">
                            {selectedRule.cwe_id}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-white text-slate-700 border border-slate-300 font-mono text-[10px]">
                            {selectedRule.owasp_category}
                          </span>
                        </div>
                        <h3 className="text-base font-bold text-slate-900 mt-1.5">
                          {selectedRule.name}
                        </h3>
                      </div>

                      <button
                        type="button"
                        onClick={() => {
                          populateEditorFromRule(selectedRule);
                          setActiveTab("CUSTOMIZATION_ENGINE");
                        }}
                        className="px-3 py-1.5 rounded-lg bg-sky-700 hover:bg-sky-800 text-white font-semibold text-xs flex items-center gap-1.5 shadow-sm"
                      >
                        <Wrench className="w-3.5 h-3.5" />
                        <span>Customize This Query</span>
                      </button>
                    </div>

                    <p className="text-xs text-slate-700 leading-relaxed">
                      {selectedRule.description}
                    </p>

                    <div className="space-y-1.5">
                      <div className="text-[10px] font-mono uppercase text-sky-800 font-bold">
                        Underlying Neo4j Cypher / CPG Execution Query
                      </div>
                      <pre className="p-3.5 rounded-xl bg-white border border-slate-300 font-mono text-xs text-emerald-900 overflow-x-auto leading-relaxed">
                        {selectedRule.cypher}
                      </pre>
                    </div>

                    <div className="p-3 rounded-xl bg-amber-50/70 border border-amber-200">
                      <div className="text-[10px] font-mono uppercase text-amber-900 font-bold mb-1">
                        Default Remediation Guidance
                      </div>
                      <p className="text-xs text-slate-800">
                        {selectedRule.remediation}
                      </p>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          )}

          {/* TAB 4: CUSTOMIZATION ENGINE (QUERY EDITOR & CUSTOM SANITIZERS) */}
          {activeTab === "CUSTOMIZATION_ENGINE" && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Left: Modify / Author Custom Security Query */}
              <form
                onSubmit={handleSaveQuery}
                className="p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-3"
              >
                <div className="flex items-center justify-between border-b border-slate-200 pb-2.5">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                      <Code2 className="w-4 h-4 text-sky-700" />
                      Query Customization Engine
                    </h3>
                    <p className="text-[11px] text-slate-600">
                      Modify an existing rule or create a custom Cypher security
                      rule
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setEditRuleId(
                        `CUSTOM-${Math.floor(100 + Math.random() * 900)}`
                      );
                      setEditRuleName("Custom Taint Sanitizer Bypass Check");
                      setEditCypher(
                        "MATCH path = (src:CPGNode {is_source: true})-[:FLOWS_TO*1..10]->(sink:CPGNode {is_sink: true})\nWHERE NONE(n IN nodes(path) WHERE n.is_sanitizer = true)\nRETURN path"
                      );
                    }}
                    className="px-2.5 py-1 rounded bg-white hover:bg-slate-100 border border-slate-300 text-sky-800 font-mono font-bold text-[10px]"
                  >
                    + New Rule Template
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-2.5">
                  <div>
                    <label className="block text-[10px] font-mono font-semibold text-slate-600 mb-1">
                      Rule ID
                    </label>
                    <input
                      type="text"
                      value={editRuleId}
                      onChange={(e) => setEditRuleId(e.target.value)}
                      className="w-full bg-white border border-slate-300 rounded px-2.5 py-1.5 text-xs font-mono font-semibold text-sky-900"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono font-semibold text-slate-600 mb-1">
                      Engine &amp; Severity
                    </label>
                    <div className="grid grid-cols-2 gap-1.5">
                      <select
                        value={editEngine}
                        onChange={(e) =>
                          setEditEngine(
                            e.target.value as "SAST" | "SCA" | "IaC"
                          )
                        }
                        className="bg-white border border-slate-300 rounded px-2 py-1.5 text-xs font-mono text-slate-900"
                      >
                        <option value="SAST">SAST</option>
                        <option value="SCA">SCA</option>
                        <option value="IaC">IaC</option>
                      </select>
                      <select
                        value={editSeverity}
                        onChange={(e) =>
                          setEditSeverity(
                            e.target.value as
                              | "CRITICAL"
                              | "HIGH"
                              | "MEDIUM"
                              | "LOW"
                          )
                        }
                        className="bg-white border border-slate-300 rounded px-2 py-1.5 text-xs font-mono text-slate-900"
                      >
                        <option value="CRITICAL">CRITICAL</option>
                        <option value="HIGH">HIGH</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="LOW">LOW</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2.5">
                  <div>
                    <label className="block text-[10px] font-mono font-semibold text-slate-600 mb-1">
                      Rule Name
                    </label>
                    <input
                      type="text"
                      value={editRuleName}
                      onChange={(e) => setEditRuleName(e.target.value)}
                      className="w-full bg-white border border-slate-300 rounded px-2.5 py-1.5 text-xs text-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono font-semibold text-slate-600 mb-1">
                      CWE ID
                    </label>
                    <input
                      type="text"
                      value={editCweId}
                      onChange={(e) => setEditCweId(e.target.value)}
                      className="w-full bg-white border border-slate-300 rounded px-2.5 py-1.5 text-xs font-mono font-semibold text-indigo-900"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-mono font-semibold text-slate-600 mb-1">
                    Cypher / AST Pattern Logic
                  </label>
                  <textarea
                    rows={5}
                    value={editCypher}
                    onChange={(e) => setEditCypher(e.target.value)}
                    className="w-full bg-white border border-slate-300 rounded-lg p-2.5 text-xs font-mono text-emerald-900 focus:outline-none focus:border-sky-600"
                  />
                </div>

                <button
                  type="submit"
                  className="w-full py-2 rounded-xl bg-sky-700 hover:bg-sky-800 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>Save &amp; Compile Security Query</span>
                </button>
              </form>

              {/* Right: Custom Sanitizers Manager (Eliminate False Positives) */}
              <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 flex flex-col justify-between space-y-4">
                <div className="space-y-3">
                  <div className="border-b border-slate-200 pb-2.5">
                    <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-700" />
                      Custom Sanitizers (False-Positive Suppression)
                    </h3>
                    <p className="text-[11px] text-slate-600">
                      Register internal sanitizer helpers so the CPG engine
                      marks matching AST/DFG nodes with{" "}
                      <code className="text-emerald-800 font-semibold">
                        is_sanitizer = true
                      </code>{" "}
                      and prunes false-positive taint paths.
                    </p>
                  </div>

                  {/* Add Sanitizer Form */}
                  <form
                    onSubmit={handleAddSanitizer}
                    className="space-y-2.5 bg-white p-3.5 rounded-xl border border-slate-200"
                  >
                    <div className="grid grid-cols-2 gap-2">
                      <input
                        type="text"
                        required
                        value={sanName}
                        onChange={(e) => setSanName(e.target.value)}
                        placeholder="Function name (e.g. clean_cmd_arg)"
                        className="bg-slate-50 border border-slate-300 rounded px-2.5 py-1.5 text-xs font-mono text-slate-900"
                      />
                      <input
                        type="text"
                        value={sanDesc}
                        onChange={(e) => setSanDesc(e.target.value)}
                        placeholder="Purpose / rationale..."
                        className="bg-slate-50 border border-slate-300 rounded px-2.5 py-1.5 text-xs text-slate-800"
                      />
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      <input
                        type="text"
                        value={sanLang}
                        onChange={(e) => setSanLang(e.target.value)}
                        placeholder="Language"
                        className="bg-slate-50 border border-slate-300 rounded px-2.5 py-1.5 text-xs font-mono text-slate-800"
                      />
                      <input
                        type="text"
                        value={sanCwe}
                        onChange={(e) => setSanCwe(e.target.value)}
                        placeholder="CWE-78"
                        className="bg-slate-50 border border-slate-300 rounded px-2.5 py-1.5 text-xs font-mono font-semibold text-indigo-900"
                      />
                      <button
                        type="submit"
                        className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold rounded px-3 py-1.5 text-xs flex items-center justify-center gap-1 shadow-sm"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        <span>Add Sanitizer</span>
                      </button>
                    </div>
                  </form>

                  {/* Active Sanitizers List */}
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {sanitizers.map((san) => (
                      <div
                        key={san.id}
                        className="p-2.5 rounded-xl bg-white border border-slate-200 flex items-center justify-between gap-2"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-emerald-900 text-xs">
                              {san.function_name}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-300 font-mono text-[10px] text-slate-800 font-semibold">
                              {san.target_cwe}
                            </span>
                            <span className="text-[10px] font-mono text-slate-500">
                              {san.language}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-600 mt-0.5">
                            {san.description}
                          </div>
                        </div>

                        <input
                          type="checkbox"
                          checked={san.active}
                          onChange={() => toggleCustomSanitizer(san.id)}
                          className="accent-emerald-700 cursor-pointer w-4 h-4"
                        />
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: DAYLIGHT APPEARANCE PALETTES & FRONTIER AI BYOK VAULT */}
          {activeTab === "APPEARANCE_AI" && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Left: 3 Crisp Light Daylight Palettes + Watermark Control */}
              <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                      <Sun className="w-4 h-4 text-amber-700" />
                      High-Contrast Daylight Palettes
                    </h3>
                    <p className="text-[11px] text-slate-600">
                      ALASTOR v4 enforces WCAG AA (&ge; 4.5:1) crisp light
                      contrast across Monaco, CPG graphs, and tables
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-amber-100 text-amber-900 border border-amber-300 font-mono text-[10px] font-bold">
                    3 LIGHT THEMES
                  </span>
                </div>

                <div className="space-y-2.5">
                  {ALASTOR_THEMES.map((t) => {
                    const isCurrent = appTheme === t.id;
                    return (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => setAppTheme(t.id)}
                        className={`w-full p-3.5 rounded-xl border text-left transition-all flex items-center justify-between gap-3 ${
                          isCurrent
                            ? "bg-white border-sky-600 ring-1 ring-sky-600/30 shadow-sm"
                            : "bg-white/80 border-slate-200 hover:border-slate-300"
                        }`}
                      >
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-slate-900">
                              {t.name}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-300 font-mono text-[9px] font-bold text-slate-700">
                              {t.badge}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600 mt-0.5">
                            {t.subtitle}
                          </p>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <div className="flex items-center -space-x-1">
                            {t.swatches.map((hex, idx) => (
                              <span
                                key={idx}
                                className="w-4 h-4 rounded-full border border-slate-300 shadow-sm"
                                style={{ backgroundColor: hex }}
                              />
                            ))}
                          </div>
                          {isCurrent && (
                            <span className="px-2 py-0.5 rounded bg-emerald-100 text-emerald-900 border border-emerald-300 font-mono text-[10px] font-bold flex items-center gap-1">
                              <Check className="w-3 h-3" />
                              Active
                            </span>
                          )}
                        </div>
                      </button>
                    );
                  })}
                </div>

                <div className="pt-3 border-t border-slate-200 space-y-2">
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="font-bold text-slate-800 flex items-center gap-1.5">
                      <Eye className="w-3.5 h-3.5 text-amber-700" />
                      Mythological Sigil Watermark Intensity
                    </span>
                    <span className="text-slate-600 font-semibold">
                      {backdropIntensity}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-1.5 bg-slate-200/70 p-1 rounded-xl border border-slate-300">
                    {(["VIVID", "SUBTLE", "MINIMAL"] as BackdropIntensity[]).map(
                      (lvl) => (
                        <button
                          key={lvl}
                          type="button"
                          onClick={() => setBackdropIntensity(lvl)}
                          className={`py-1.5 rounded-lg text-[11px] font-mono font-bold transition-all ${
                            backdropIntensity === lvl
                              ? "bg-sky-700 text-white shadow-sm"
                              : "text-slate-700 hover:bg-white hover:text-slate-900"
                          }`}
                        >
                          {lvl === "VIVID"
                            ? "Vivid Art"
                            : lvl === "SUBTLE"
                            ? "Subtle (Default)"
                            : "Minimal / Off"}
                        </button>
                      )
                    )}
                  </div>
                </div>
              </div>

              {/* Right: Frontier AI BYOK Vault & Token-Slicing Telemetry */}
              <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 flex flex-col justify-between space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                    <div>
                      <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                        <Sparkles className="w-4 h-4 text-indigo-700" />
                        Frontier AI Copilot (BYOK Vault)
                      </h3>
                      <p className="text-[11px] text-slate-600">
                        Connect Gemini, OpenAI, Anthropic, or OpenAI-compatible
                        endpoints using CPG micro-slicing (75–92% fewer tokens)
                      </p>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${
                        aiConfig?.has_api_key
                          ? "bg-emerald-100 text-emerald-900 border-emerald-300"
                          : "bg-amber-100 text-amber-900 border-amber-300"
                      }`}
                    >
                      {aiConfig?.has_api_key ? "KEY CONFIGURED" : "BYOK READY"}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3 rounded-xl bg-white border border-slate-200">
                      <div className="text-[10px] font-mono text-slate-500 uppercase">
                        Active Provider &amp; Model
                      </div>
                      <div className="text-xs font-bold text-slate-900 mt-1 font-mono truncate">
                        {aiConfig?.provider || "gemini"} •{" "}
                        {aiConfig?.model || "gemini-2.5-flash"}
                      </div>
                    </div>
                    <div className="p-3 rounded-xl bg-white border border-slate-200">
                      <div className="text-[10px] font-mono text-slate-500 uppercase">
                        API Key Status
                      </div>
                      <div className="text-xs font-bold text-slate-900 mt-1 font-mono flex items-center gap-1.5">
                        <KeyRound className="w-3.5 h-3.5 text-indigo-700 shrink-0" />
                        <span className="truncate">
                          {aiConfig?.has_api_key
                            ? aiConfig.masked_api_key || "••••••••"
                            : "Not set yet"}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-indigo-50/70 border border-indigo-200 space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] font-mono font-bold text-indigo-950">
                      <span>CPG Micro-Slicing Token Efficiency</span>
                      <span className="text-emerald-800">
                        {aiConfig?.token_telemetry?.overall_savings_pct
                          ? `${Math.round(
                              aiConfig.token_telemetry.overall_savings_pct
                            )}% Saved`
                          : "Up to 90% Saved"}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-700 leading-relaxed">
                      Instead of sending whole repositories or full files,
                      ALASTOR extracts +/-5-line CPG source/sanitizer/sink hops
                      and compact AST/DFG digests—keeping prompt budgets minimal
                      and SHA-256 cached.
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => {
                    setOpen(false);
                    setAiDrawerOpen(true, "SETTINGS");
                  }}
                  className="w-full py-2.5 px-4 rounded-xl bg-indigo-700 hover:bg-indigo-800 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-sm transition-colors"
                >
                  <Sparkles className="w-4 h-4" />
                  <span>Open Frontier AI BYOK Vault &amp; Copilot Drawer</span>
                  <ArrowUpRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
