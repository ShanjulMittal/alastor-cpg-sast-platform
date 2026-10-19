"use client";

import React, { useState, useEffect } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { SecurityQueryRule } from "@/types/cpg";
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
} from "lucide-react";

export function SettingsCustomizationModal() {
  const isOpen = useAuditStore((s) => s.isSettingsModalOpen);
  const setOpen = useAuditStore((s) => s.setSettingsModalOpen);
  const platformSettings = useAuditStore((s) => s.platformSettings);
  const fetchPlatformSettings = useAuditStore((s) => s.fetchPlatformSettings);
  const updatePlatformSettings = useAuditStore((s) => s.updatePlatformSettings);
  const upsertQueryRule = useAuditStore((s) => s.upsertQueryRule);
  const toggleQueryRule = useAuditStore((s) => s.toggleQueryRule);
  const addCustomSanitizer = useAuditStore((s) => s.addCustomSanitizer);
  const toggleCustomSanitizer = useAuditStore((s) => s.toggleCustomSanitizer);
  const projects = useAuditStore((s) => s.projects);

  const [activeTab, setActiveTab] = useState<
    "PRESETS" | "GLOBAL_VS_PROJECT" | "QUERY_VIEWER" | "CUSTOMIZATION_ENGINE"
  >("PRESETS");

  // Query Viewer / Editor state
  const [selectedRule, setSelectedRule] = useState<SecurityQueryRule | null>(null);
  const [editRuleId, setEditRuleId] = useState("");
  const [editRuleName, setEditRuleName] = useState("");
  const [editEngine, setEditEngine] = useState<"SAST" | "SCA" | "IaC">("SAST");
  const [editLanguage, setEditLanguage] = useState("Python");
  const [editSeverity, setEditSeverity] = useState<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW">("HIGH");
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
  const [selectedScopeProject, setSelectedScopeProject] = useState<string>("proj-argon-core");
  const [savedBanner, setSavedBanner] = useState<string | null>(null);

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
    setEditSeverity((r.severity === "INFO" ? "LOW" : r.severity) as any);
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
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 select-none">
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl shadow-2xl w-full max-w-6xl max-h-[88vh] flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="px-5 py-3.5 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-700 flex items-center justify-center">
              <Settings className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                Settings, Scan Presets &amp; Query Customization Engine
                <span className="px-2 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px] font-mono">
                  ENTERPRISE CONFIG
                </span>
              </h2>
              <p className="text-[11px] text-zinc-400">
                Configure Checkmarx-style Scan Presets, Global vs. Project Overrides, Underlying Cypher Queries, and Custom Sanitizers
              </p>
            </div>
          </div>

          {/* 4 Sub-Module Tabs */}
          <div className="flex items-center gap-1 bg-zinc-950 p-1 rounded-xl border border-zinc-800 text-xs">
            <button
              type="button"
              onClick={() => setActiveTab("PRESETS")}
              className={`px-3 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === "PRESETS"
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-700"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>1. Scan Presets</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("GLOBAL_VS_PROJECT")}
              className={`px-3 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === "GLOBAL_VS_PROJECT"
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-700"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>2. Global vs. Project</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("QUERY_VIEWER")}
              className={`px-3 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === "QUERY_VIEWER"
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-700"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>3. Query Viewer ({queries.length})</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("CUSTOMIZATION_ENGINE")}
              className={`px-3 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === "CUSTOMIZATION_ENGINE"
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-700"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Wrench className="w-3.5 h-3.5" />
              <span>4. Customization &amp; Sanitizers</span>
            </button>
          </div>

          <button
            type="button"
            onClick={() => setOpen(false)}
            className="p-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {savedBanner && (
          <div className="px-5 py-2 bg-emerald-950/80 border-b border-emerald-700 text-emerald-200 text-xs font-mono flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{savedBanner}</span>
          </div>
        )}

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 text-xs">
          {/* TAB 1: SCAN PRESETS */}
          {activeTab === "PRESETS" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white">
                    Predefined Scanning Profiles (Scan Presets)
                  </h3>
                  <p className="text-zinc-400 text-xs">
                    Select an out-of-the-box scanning profile. ARGON includes the Checkmarx-style{" "}
                    <b className="text-cyan-300">Optimized</b> preset by default to balance high recall with near-zero false positives.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {presets.map((preset) => {
                  const isSelected =
                    (platformSettings?.active_preset_id || "preset-optimized") === preset.id;
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
                          ? "bg-zinc-900 border-cyan-500 ring-1 ring-cyan-500/40 shadow-lg"
                          : "bg-zinc-900/40 border-zinc-800 hover:border-zinc-700"
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px] font-mono font-bold">
                            {preset.badge}
                          </span>
                          {isSelected && (
                            <span className="flex items-center gap-1 text-emerald-400 font-mono text-[11px] font-bold">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              ACTIVE PRESET
                            </span>
                          )}
                        </div>
                        <h4 className="text-sm font-bold text-white">{preset.name}</h4>
                        <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                          {preset.description}
                        </p>
                      </div>

                      <div className="mt-4 pt-3 border-t border-zinc-800 flex items-center justify-between text-[11px] font-mono">
                        <div className="flex items-center gap-1.5">
                          <span className="text-zinc-500">Engines:</span>
                          {preset.enabled_engines.map((eng) => (
                            <span
                              key={eng}
                              className="px-1.5 py-0.2 rounded bg-zinc-950 border border-zinc-700 text-cyan-300"
                            >
                              {eng}
                            </span>
                          ))}
                        </div>
                        <span className="text-zinc-400">
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
              <div className="p-5 rounded-2xl bg-zinc-900/60 border border-zinc-800 space-y-4">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Globe className="w-4 h-4 text-cyan-400" />
                      Global Organization Settings
                    </h3>
                    <p className="text-[11px] text-zinc-400">
                      Default baseline inherited by all projects unless overridden
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono text-[10px]">
                    GLOBAL SCOPE
                  </span>
                </div>

                <div className="space-y-3">
                  <div>
                    <label className="block text-[11px] font-mono text-zinc-300 mb-1">
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
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white"
                    >
                      {presets.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono text-zinc-300 mb-1">
                      Max Data-Flow &amp; Call Graph Depth ({platformSettings.max_dfg_depth} hops)
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
                      className="w-full accent-cyan-500"
                    />
                  </div>

                  <label className="flex items-center justify-between p-3 rounded-xl bg-zinc-950 border border-zinc-800 cursor-pointer">
                    <div>
                      <div className="font-semibold text-zinc-200">
                        Auto-Suppress Low Severity Informational Findings
                      </div>
                      <div className="text-[11px] text-zinc-400">
                        Focus remediation queues on Critical, High, and Medium flaws
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
                      className="accent-cyan-500"
                    />
                  </label>
                </div>
              </div>

              {/* Right Column: Project-Specific Override Settings */}
              <div className="p-5 rounded-2xl bg-zinc-900/60 border border-zinc-800 space-y-4">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <FolderGit2 className="w-4 h-4 text-indigo-400" />
                      Project-Level Configuration Override
                    </h3>
                    <p className="text-[11px] text-zinc-400">
                      Override global scan presets, depth, or excluded paths for a specific repository
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 font-mono text-[10px]">
                    PROJECT OVERRIDE
                  </span>
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-zinc-300 mb-1">
                    Select Target Project
                  </label>
                  <select
                    value={selectedScopeProject}
                    onChange={(e) => setSelectedScopeProject(e.target.value)}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-cyan-300 font-mono"
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
                    platformSettings.project_overrides?.[selectedScopeProject] || {
                      active_preset_id: platformSettings.active_preset_id,
                      max_dfg_depth: platformSettings.max_dfg_depth,
                      excluded_paths: platformSettings.excluded_paths,
                    };

                  return (
                    <div className="space-y-3">
                      <div>
                        <label className="block text-[11px] font-mono text-zinc-300 mb-1">
                          Project Scan Preset Override
                        </label>
                        <select
                          value={projOverride.active_preset_id || platformSettings.active_preset_id}
                          onChange={(e) =>
                            updatePlatformSettings({
                              scope: "PROJECT",
                              project_id: selectedScopeProject,
                              active_preset_id: e.target.value,
                            })
                          }
                          className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white"
                        >
                          {presets.map((p) => (
                            <option key={p.id} value={p.id}>
                              {p.name}
                            </option>
                          ))}
                        </select>
                      </div>

                      <div className="p-3 rounded-xl bg-zinc-950 border border-zinc-800">
                        <div className="text-[11px] font-mono text-zinc-400 mb-1">
                          Active Excluded Directories for {selectedScopeProject}:
                        </div>
                        <div className="flex items-center gap-1.5 flex-wrap font-mono text-[10px]">
                          {(platformSettings.excluded_paths || []).map((ep) => (
                            <span
                              key={ep}
                              className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-300"
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
                <div className="text-[11px] font-mono uppercase text-zinc-400 mb-2">
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
                          ? "bg-zinc-900 border-cyan-500"
                          : "bg-zinc-900/40 border-zinc-800 hover:border-zinc-700"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <div className="flex items-center gap-1.5">
                          <span className="px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono text-[10px] font-bold">
                            {q.engine}
                          </span>
                          <span className="font-mono text-[10px] text-zinc-400">{q.id}</span>
                          {q.is_custom && (
                            <span className="px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-700 font-mono text-[9px]">
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
                          className="accent-cyan-500 cursor-pointer"
                        />
                      </div>
                      <div className="font-bold text-zinc-100 text-xs">{q.name}</div>
                      <div className="text-[10px] font-mono text-zinc-400 mt-1 flex items-center justify-between">
                        <span>
                          {q.cwe_id} • {q.language}
                        </span>
                        <span className="text-cyan-400">{q.severity}</span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Right Query Inspector */}
              <div className="lg:col-span-7">
                {selectedRule ? (
                  <div className="p-5 rounded-2xl bg-zinc-900/70 border border-zinc-800 space-y-4">
                    <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono text-[10px] font-bold">
                            {selectedRule.id}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 font-mono text-[10px]">
                            {selectedRule.cwe_id}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-zinc-950 text-zinc-300 border border-zinc-700 font-mono text-[10px]">
                            {selectedRule.owasp_category}
                          </span>
                        </div>
                        <h3 className="text-base font-bold text-white mt-1.5">
                          {selectedRule.name}
                        </h3>
                      </div>

                      <button
                        type="button"
                        onClick={() => {
                          populateEditorFromRule(selectedRule);
                          setActiveTab("CUSTOMIZATION_ENGINE");
                        }}
                        className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-1.5"
                      >
                        <Wrench className="w-3.5 h-3.5" />
                        <span>Customize This Query</span>
                      </button>
                    </div>

                    <p className="text-xs text-zinc-300 leading-relaxed">
                      {selectedRule.description}
                    </p>

                    <div className="space-y-1.5">
                      <div className="text-[10px] font-mono uppercase text-cyan-400 font-bold">
                        Underlying Neo4j Cypher / CPG Execution Query
                      </div>
                      <pre className="p-3.5 rounded-xl bg-zinc-950 border border-zinc-800 font-mono text-xs text-emerald-300 overflow-x-auto leading-relaxed">
                        {selectedRule.cypher}
                      </pre>
                    </div>

                    <div className="p-3 rounded-xl bg-zinc-950 border border-zinc-800">
                      <div className="text-[10px] font-mono uppercase text-amber-400 font-bold mb-1">
                        Default Remediation Guidance
                      </div>
                      <p className="text-xs text-zinc-300">{selectedRule.remediation}</p>
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
                className="p-5 rounded-2xl bg-zinc-900/60 border border-zinc-800 space-y-3"
              >
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2.5">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Code2 className="w-4 h-4 text-cyan-400" />
                      Query Customization Engine
                    </h3>
                    <p className="text-[11px] text-zinc-400">
                      Modify an existing rule or create a custom Cypher security rule
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setEditRuleId(`CUSTOM-${Math.floor(100 + Math.random() * 900)}`);
                      setEditRuleName("Custom Taint Sanitizer Bypass Check");
                      setEditCypher(
                        "MATCH path = (src:CPGNode {is_source: true})-[:FLOWS_TO*1..10]->(sink:CPGNode {is_sink: true})\nWHERE NONE(n IN nodes(path) WHERE n.is_sanitizer = true)\nRETURN path"
                      );
                    }}
                    className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-cyan-300 font-mono text-[10px]"
                  >
                    + New Rule Template
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-2.5">
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Rule ID
                    </label>
                    <input
                      type="text"
                      value={editRuleId}
                      onChange={(e) => setEditRuleId(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-cyan-300"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Engine &amp; Severity
                    </label>
                    <div className="grid grid-cols-2 gap-1.5">
                      <select
                        value={editEngine}
                        onChange={(e) => setEditEngine(e.target.value as any)}
                        className="bg-zinc-950 border border-zinc-800 rounded px-2 py-1.5 text-xs font-mono text-white"
                      >
                        <option value="SAST">SAST</option>
                        <option value="SCA">SCA</option>
                        <option value="IaC">IaC</option>
                      </select>
                      <select
                        value={editSeverity}
                        onChange={(e) => setEditSeverity(e.target.value as any)}
                        className="bg-zinc-950 border border-zinc-800 rounded px-2 py-1.5 text-xs font-mono text-white"
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
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Rule Name
                    </label>
                    <input
                      type="text"
                      value={editRuleName}
                      onChange={(e) => setEditRuleName(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      CWE ID
                    </label>
                    <input
                      type="text"
                      value={editCweId}
                      onChange={(e) => setEditCweId(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-indigo-300"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                    Cypher / AST Pattern Logic
                  </label>
                  <textarea
                    rows={5}
                    value={editCypher}
                    onChange={(e) => setEditCypher(e.target.value)}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-2.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <button
                  type="submit"
                  className="w-full py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs flex items-center justify-center gap-1.5"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>Save &amp; Compile Security Query</span>
                </button>
              </form>

              {/* Right: Custom Sanitizers Manager (Eliminate False Positives) */}
              <div className="p-5 rounded-2xl bg-zinc-900/60 border border-zinc-800 flex flex-col justify-between space-y-4">
                <div className="space-y-3">
                  <div className="border-b border-zinc-800 pb-2.5">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      Custom Sanitizers (False-Positive Suppression)
                    </h3>
                    <p className="text-[11px] text-zinc-400">
                      Register internal sanitizer helpers so the CPG engine marks matching AST/DFG nodes with{" "}
                      <code className="text-emerald-300">is_sanitizer = true</code> and prunes false-positive taint paths.
                    </p>
                  </div>

                  {/* Add Sanitizer Form */}
                  <form
                    onSubmit={handleAddSanitizer}
                    className="space-y-2.5 bg-zinc-950 p-3.5 rounded-xl border border-zinc-800"
                  >
                    <div className="grid grid-cols-2 gap-2">
                      <input
                        type="text"
                        required
                        value={sanName}
                        onChange={(e) => setSanName(e.target.value)}
                        placeholder="Function name (e.g. clean_cmd_arg)"
                        className="bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-white"
                      />
                      <input
                        type="text"
                        value={sanDesc}
                        onChange={(e) => setSanDesc(e.target.value)}
                        placeholder="Purpose / rationale..."
                        className="bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1.5 text-xs text-zinc-200"
                      />
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      <input
                        type="text"
                        value={sanLang}
                        onChange={(e) => setSanLang(e.target.value)}
                        placeholder="Language"
                        className="bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200"
                      />
                      <input
                        type="text"
                        value={sanCwe}
                        onChange={(e) => setSanCwe(e.target.value)}
                        placeholder="CWE-78"
                        className="bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-indigo-300"
                      />
                      <button
                        type="submit"
                        className="bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded px-3 py-1.5 text-xs flex items-center justify-center gap-1"
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
                        className="p-2.5 rounded-xl bg-zinc-950 border border-zinc-800 flex items-center justify-between gap-2"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-emerald-300 text-xs">
                              {san.function_name}
                            </span>
                            <span className="px-1.5 py-0.2 rounded bg-zinc-900 border border-zinc-700 font-mono text-[10px] text-zinc-300">
                              {san.target_cwe}
                            </span>
                            <span className="text-[10px] font-mono text-zinc-500">
                              {san.language}
                            </span>
                          </div>
                          <div className="text-[11px] text-zinc-400 mt-0.5">
                            {san.description}
                          </div>
                        </div>

                        <input
                          type="checkbox"
                          checked={san.active}
                          onChange={() => toggleCustomSanitizer(san.id)}
                          className="accent-emerald-500 cursor-pointer"
                        />
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
