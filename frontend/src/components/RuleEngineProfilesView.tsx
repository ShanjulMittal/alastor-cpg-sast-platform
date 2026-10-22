"use client";

import React, { useEffect, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  Sliders,
  CheckSquare,
  Square,
  Play,
  Plus,
  Search,
  ShieldCheck,
  Code2,
  KeyRound,
  Sparkles,
  CheckCircle2,
  XCircle,
  Filter,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

export const RuleEngineProfilesView: React.FC = () => {
  const {
    platformSettings,
    fetchPlatformSettings,
    updatePlatformSettings,
    toggleQueryRule,
    batchUpdateRules,
    createTestProfile,
    triggerScan,
    isScanning,
    projectPath,
  } = useAuditStore();

  const [engineFilter, setEngineFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [searchText, setSearchText] = useState<string>("");
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);

  // New Custom Test Profile Modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newProfileName, setNewProfileName] = useState("");
  const [newProfileBadge, setNewProfileBadge] = useState("CUSTOM");
  const [newProfileDesc, setNewProfileDesc] = useState("");

  useEffect(() => {
    if (!platformSettings) {
      fetchPlatformSettings();
    }
  }, [platformSettings, fetchPlatformSettings]);

  const presets = platformSettings?.presets || [];
  const queries = platformSettings?.queries || [];
  const activePresetId =
    platformSettings?.active_preset_id || "preset-optimized";
  const enabledEngines = platformSettings?.enabled_engines || [
    "SAST",
    "SCA",
    "IaC",
  ];

  const enabledRules = queries.filter((q) => q.enabled);

  const filteredRules = queries.filter((q) => {
    if (engineFilter !== "ALL" && q.engine !== engineFilter) return false;
    if (severityFilter !== "ALL" && q.severity !== severityFilter) return false;
    if (searchText.trim()) {
      const s = searchText.toLowerCase();
      return (
        q.id.toLowerCase().includes(s) ||
        q.name.toLowerCase().includes(s) ||
        q.cwe_id.toLowerCase().includes(s) ||
        q.description.toLowerCase().includes(s)
      );
    }
    return true;
  });

  const handleSelectPreset = async (presetId: string) => {
    await updatePlatformSettings({ active_preset_id: presetId });
  };

  const handleToggleEngine = async (eng: string) => {
    const exists = enabledEngines.includes(eng);
    const nextEngines = exists
      ? enabledEngines.filter((e) => e !== eng)
      : [...enabledEngines, eng];
    if (nextEngines.length === 0) return;
    await updatePlatformSettings({ enabled_engines: nextEngines });
  };

  const handleBulkSelectVisible = async (enable: boolean) => {
    const visibleIds = filteredRules.map((r) => r.id);
    if (enable) {
      const merged = Array.from(
        new Set([...enabledRules.map((r) => r.id), ...visibleIds])
      );
      await batchUpdateRules({ enabled_rule_ids: merged });
    } else {
      const remaining = enabledRules
        .map((r) => r.id)
        .filter((id) => !visibleIds.includes(id));
      await batchUpdateRules({
        enabled_rule_ids: remaining,
        disabled_rule_ids: visibleIds,
      });
    }
  };

  const handleSelectByCriteria = async (
    mode: "CRITICAL_HIGH" | "SECRETS_ONLY" | "TAINT_INJECTION"
  ) => {
    let selectedIds: string[] = [];
    if (mode === "CRITICAL_HIGH") {
      selectedIds = queries
        .filter((q) => q.severity === "CRITICAL" || q.severity === "HIGH")
        .map((q) => q.id);
    } else if (mode === "SECRETS_ONLY") {
      selectedIds = queries
        .filter(
          (q) =>
            q.id.toUpperCase().includes("SECRET") ||
            q.cwe_id === "CWE-798" ||
            q.name.toLowerCase().includes("secret") ||
            q.name.toLowerCase().includes("credential")
        )
        .map((q) => q.id);
    } else if (mode === "TAINT_INJECTION") {
      selectedIds = queries
        .filter((q) => q.engine === "SAST")
        .map((q) => q.id);
    }
    await batchUpdateRules({ enabled_rule_ids: selectedIds });
  };

  const handleSaveCustomProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newProfileName.trim()) return;
    await createTestProfile({
      name: newProfileName.trim(),
      badge: newProfileBadge.trim().toUpperCase() || "CUSTOM",
      description:
        newProfileDesc.trim() ||
        `Custom test profile with ${enabledRules.length} selected rules.`,
      enabled_engines: enabledEngines,
      enabled_rule_ids: enabledRules.map((r) => r.id),
    });
    setNewProfileName("");
    setNewProfileDesc("");
    setShowCreateModal(false);
  };

  return (
    <div className="flex-1 h-full overflow-y-auto bg-slate-950/95 text-slate-100 p-6 space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-start gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
            <Sliders className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-lg font-extrabold tracking-tight text-slate-100">
                Rule Engine & Test Profiles Governance Center
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                {enabledRules.length} of {queries.length} Rules Selected
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Define and switch between Test Profiles, toggle SAST / SCA / IaC engines, and granularly select which security rules to execute or exclude.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-3.5 py-2 rounded-lg text-xs font-bold bg-slate-800 hover:bg-slate-700 text-amber-300 border border-amber-500/40 flex items-center gap-1.5 transition-all"
          >
            <Plus className="w-3.5 h-3.5" />
            Save Current Selection as Test Profile
          </button>

          <button
            onClick={() => triggerScan(projectPath)}
            disabled={isScanning}
            className="px-4 py-2 rounded-lg text-xs font-extrabold bg-amber-500 hover:bg-amber-400 text-slate-950 flex items-center gap-1.5 shadow-lg transition-all disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            {isScanning
              ? "Scanning with Active Profile..."
              : "Run Scan with Active Profile"}
          </button>
        </div>
      </div>

      {/* SECTION 1: Test Profiles Selector Cards */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-extrabold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-amber-400" />
            1. Select Active Test Profile (Preset Configuration)
          </h2>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-semibold">
              Active Scan Engines:
            </span>
            {(["SAST", "SCA", "IaC"] as const).map((eng) => {
              const isOn = enabledEngines.includes(eng);
              return (
                <button
                  key={eng}
                  onClick={() => handleToggleEngine(eng)}
                  className={`px-2.5 py-1 rounded text-xs font-mono font-bold border transition-all flex items-center gap-1.5 ${
                    isOn
                      ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/50"
                      : "bg-slate-900 text-slate-500 border-slate-800"
                  }`}
                >
                  {isOn ? (
                    <CheckSquare className="w-3.5 h-3.5" />
                  ) : (
                    <Square className="w-3.5 h-3.5" />
                  )}
                  {eng}
                </button>
              );
            })}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {presets.map((preset) => {
            const isSelected = activePresetId === preset.id;
            return (
              <button
                key={preset.id}
                onClick={() => handleSelectPreset(preset.id)}
                className={`text-left p-4 rounded-xl border transition-all flex flex-col justify-between gap-3 ${
                  isSelected
                    ? "bg-amber-500/15 border-amber-400 shadow-lg shadow-amber-950/30"
                    : "bg-slate-900/80 border-slate-800 hover:border-slate-700"
                }`}
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-1">
                    <span
                      className={`px-2 py-0.5 text-[9px] font-mono font-extrabold rounded border ${
                        isSelected
                          ? "bg-amber-400 text-slate-950 border-amber-300"
                          : "bg-slate-800 text-slate-300 border-slate-700"
                      }`}
                    >
                      {preset.badge}
                    </span>
                    {isSelected && (
                      <span className="text-[10px] font-bold text-amber-300 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Active
                      </span>
                    )}
                  </div>
                  <div className="text-xs font-bold text-slate-100 leading-snug">
                    {preset.name}
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">
                    {preset.description}
                  </p>
                </div>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-300">
                  <span>{preset.enabled_rule_ids.length} Rules</span>
                  <span>{preset.enabled_engines.join("+")}</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* SECTION 2: Granular Rule Selection Matrix */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-extrabold text-slate-100 flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              2. Granular Security Rule Selection Matrix (Check Which Rules to Execute or Exclude)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Unchecking a rule immediately excludes its findings from active triage and future scans until re-enabled.
            </p>
          </div>

          {/* Quick Selection Presets */}
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              onClick={() => handleBulkSelectVisible(true)}
              className="px-2.5 py-1.5 rounded-lg text-[11px] font-bold bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/40 flex items-center gap-1"
            >
              <CheckCircle2 className="w-3.5 h-3.5" /> Select All Visible ({filteredRules.length})
            </button>
            <button
              onClick={() => handleBulkSelectVisible(false)}
              className="px-2.5 py-1.5 rounded-lg text-[11px] font-bold bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/40 flex items-center gap-1"
            >
              <XCircle className="w-3.5 h-3.5" /> Deselect Visible
            </button>
            <button
              onClick={() => handleSelectByCriteria("CRITICAL_HIGH")}
              className="px-2.5 py-1.5 rounded-lg text-[11px] font-bold bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700"
            >
              Critical & High Only
            </button>
            <button
              onClick={() => handleSelectByCriteria("SECRETS_ONLY")}
              className="px-2.5 py-1.5 rounded-lg text-[11px] font-bold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center gap-1"
            >
              <KeyRound className="w-3 h-3" /> Secret Key Rules Only
            </button>
            <button
              onClick={() => handleSelectByCriteria("TAINT_INJECTION")}
              className="px-2.5 py-1.5 rounded-lg text-[11px] font-bold bg-slate-800 hover:bg-slate-700 text-purple-300 border border-slate-700"
            >
              SAST Taint Rules Only
            </button>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-400 flex items-center gap-1">
              <Filter className="w-3.5 h-3.5" /> Engine:
            </span>
            {["ALL", "SAST", "SCA", "IaC"].map((eng) => (
              <button
                key={eng}
                onClick={() => setEngineFilter(eng)}
                className={`px-2.5 py-1 rounded text-xs font-bold border ${
                  engineFilter === eng
                    ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/50"
                    : "bg-slate-950 text-slate-400 border-slate-800"
                }`}
              >
                {eng}
              </button>
            ))}

            <span className="text-xs text-slate-400 ml-2">Severity:</span>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded text-xs font-bold border ${
                  severityFilter === sev
                    ? "bg-amber-500/20 text-amber-300 border-amber-500/50"
                    : "bg-slate-950 text-slate-400 border-slate-800"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="relative min-w-[260px]">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              placeholder="Search rule ID, CWE, secret, injection..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Rule List */}
        <div className="space-y-2.5">
          {filteredRules.map((rule) => {
            const isExpanded = expandedRuleId === rule.id;
            return (
              <div
                key={rule.id}
                className={`rounded-xl border transition-all p-4 ${
                  rule.enabled
                    ? "bg-slate-950/90 border-slate-800 hover:border-slate-700"
                    : "bg-slate-950/40 border-slate-900 opacity-65"
                }`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <button
                      onClick={() => toggleQueryRule(rule.id)}
                      className={`mt-0.5 px-2.5 py-1.5 rounded-lg border flex items-center gap-1.5 text-xs font-bold transition-all shrink-0 ${
                        rule.enabled
                          ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/50"
                          : "bg-slate-900 text-slate-500 border-slate-800 hover:text-slate-300"
                      }`}
                    >
                      {rule.enabled ? (
                        <>
                          <CheckSquare className="w-4 h-4 text-emerald-400" />
                          <span>ENABLED</span>
                        </>
                      ) : (
                        <>
                          <Square className="w-4 h-4" />
                          <span>EXCLUDED</span>
                        </>
                      )}
                    </button>

                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-extrabold text-amber-300">
                          {rule.id}
                        </span>
                        <span
                          className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded border ${
                            rule.severity === "CRITICAL"
                              ? "bg-red-500/20 text-red-300 border-red-500/40"
                              : rule.severity === "HIGH"
                              ? "bg-orange-500/20 text-orange-300 border-orange-500/40"
                              : "bg-amber-500/20 text-amber-300 border-amber-500/40"
                          }`}
                        >
                          {rule.severity} (CVSS {rule.cvss_score})
                        </span>
                        <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                          {rule.engine}
                        </span>
                        <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {rule.cwe_id}
                        </span>
                        <span className="text-[11px] text-slate-400">
                          {rule.owasp_category}
                        </span>
                      </div>

                      <h3 className="text-sm font-bold text-slate-100">
                        {rule.name}
                      </h3>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {rule.description}
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={() =>
                      setExpandedRuleId(isExpanded ? null : rule.id)
                    }
                    className="px-2.5 py-1 rounded text-xs font-mono text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 flex items-center gap-1 shrink-0"
                  >
                    {isExpanded ? (
                      <>
                        Hide Logic <ChevronUp className="w-3.5 h-3.5" />
                      </>
                    ) : (
                      <>
                        Inspect Query <ChevronDown className="w-3.5 h-3.5" />
                      </>
                    )}
                  </button>
                </div>

                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-slate-800/80 grid grid-cols-1 lg:grid-cols-2 gap-3">
                    <div className="bg-slate-900 rounded-lg p-3 border border-slate-800">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-cyan-300 mb-1">
                        CPG Cypher / AST Pattern Query
                      </div>
                      <pre className="text-[11px] font-mono text-slate-300 whitespace-pre-wrap overflow-x-auto">
                        {rule.cypher}
                      </pre>
                    </div>
                    <div className="bg-slate-900 rounded-lg p-3 border border-slate-800">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-300 mb-1">
                        Standard Remediation Guidance
                      </div>
                      <p className="text-xs text-slate-300">
                        {rule.remediation}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Create Custom Test Profile Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <form
            onSubmit={handleSaveCustomProfile}
            className="bg-slate-900 border border-slate-700 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl"
          >
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-extrabold text-slate-100 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-amber-400" />
                Create Custom Test Profile
              </h3>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="text-xs text-slate-400 hover:text-slate-200"
              >
                Close
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Saves your currently enabled{" "}
              <span className="text-amber-300 font-bold">
                {enabledRules.length} rules
              </span>{" "}
              and{" "}
              <span className="text-cyan-300 font-bold">
                {enabledEngines.join(" + ")}
              </span>{" "}
              engines as a reusable Test Profile.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-[11px] font-bold text-slate-300 mb-1">
                  Profile Name
                </label>
                <input
                  type="text"
                  required
                  value={newProfileName}
                  onChange={(e) => setNewProfileName(e.target.value)}
                  placeholder="e.g., Production API Release Gate"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                />
              </div>

              <div>
                <label className="block text-[11px] font-bold text-slate-300 mb-1">
                  Short Badge Code
                </label>
                <input
                  type="text"
                  value={newProfileBadge}
                  onChange={(e) => setNewProfileBadge(e.target.value)}
                  placeholder="e.g., PROD-GATE"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-100"
                />
              </div>

              <div>
                <label className="block text-[11px] font-bold text-slate-300 mb-1">
                  Profile Description
                </label>
                <textarea
                  rows={2}
                  value={newProfileDesc}
                  onChange={(e) => setNewProfileDesc(e.target.value)}
                  placeholder="Describe which rules and compliance scopes this profile enforces..."
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 text-slate-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg text-xs font-bold bg-amber-500 hover:bg-amber-400 text-slate-950"
              >
                Save & Activate Profile
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
