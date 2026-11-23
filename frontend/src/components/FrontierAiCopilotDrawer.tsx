"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  AiDrawerTab,
  AiFindingVerdict,
  AiProviderInfo,
  AiProviderType,
  TestFrameworkType,
} from "@/types/cpg";
import {
  Sparkles,
  X,
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  FileCode2,
  Wrench,
  Network,
  Settings,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Eye,
  EyeOff,
  Copy,
  Check,
  Zap,
  Database,
  Trash2,
  GitCompare,
  Play,
  ArrowUpRight,
  XCircle,
  Users,
  FlaskConical,
  Save,
  Terminal,
} from "lucide-react";

const FALLBACK_PROVIDERS: AiProviderInfo[] = [
  {
    id: "gemini",
    label: "Google Gemini",
    default_model: "gemini-2.5-flash",
    models: ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
    default_base_url: "https://generativelanguage.googleapis.com",
    requires_api_key: true,
  },
  {
    id: "openai",
    label: "OpenAI",
    default_model: "gpt-4o-mini",
    models: ["gpt-4o-mini", "gpt-4o", "o3-mini"],
    default_base_url: "https://api.openai.com/v1",
    requires_api_key: true,
  },
  {
    id: "anthropic",
    label: "Anthropic Claude",
    default_model: "claude-3-5-haiku-latest",
    models: [
      "claude-3-5-haiku-latest",
      "claude-3-7-sonnet-latest",
      "claude-3-5-sonnet-latest",
    ],
    default_base_url: "https://api.anthropic.com/v1",
    requires_api_key: true,
  },
  {
    id: "openai_compatible",
    label: "OpenAI-Compatible / Local Ollama",
    default_model: "llama3.2",
    models: ["llama3.2", "qwen2.5-coder:7b", "deepseek-r1"],
    default_base_url: "http://localhost:11434/v1",
    requires_api_key: false,
    requires_base_url: true,
  },
];

function formatConfidencePct(raw: number): number {
  if (typeof raw !== "number" || Number.isNaN(raw)) return 0;
  return raw <= 1 ? Math.round(raw * 100) : Math.round(raw);
}

export function FrontierAiCopilotDrawer() {
  const isAiDrawerOpen = useAuditStore((s) => s.isAiDrawerOpen);
  const aiDrawerActiveTab = useAuditStore((s) => s.aiDrawerActiveTab);
  const setAiDrawerOpen = useAuditStore((s) => s.setAiDrawerOpen);
  const aiConfig = useAuditStore((s) => s.aiConfig);
  const aiConnectionStatus = useAuditStore((s) => s.aiConnectionStatus);
  const aiVerdictsByFinding = useAuditStore((s) => s.aiVerdictsByFinding);
  const aiLastAudit = useAuditStore((s) => s.aiLastAudit);
  const aiLastSynthesizedPatch = useAuditStore((s) => s.aiLastSynthesizedPatch);
  const aiLastGraphExplanation = useAuditStore((s) => s.aiLastGraphExplanation);
  const aiErrorBanner = useAuditStore((s) => s.aiErrorBanner);
  const aiIsBusy = useAuditStore((s) => s.aiIsBusy);

  const fetchAiConfigState = useAuditStore((s) => s.fetchAiConfigState);
  const saveAiConfigState = useAuditStore((s) => s.saveAiConfigState);
  const runAiConnectionTest = useAuditStore((s) => s.runAiConnectionTest);
  const validateFindingsAi = useAuditStore((s) => s.validateFindingsAi);
  const auditCodeSelectionAi = useAuditStore((s) => s.auditCodeSelectionAi);
  const synthesizeFindingPatchAi = useAuditStore(
    (s) => s.synthesizeFindingPatchAi
  );
  const explainCurrentGraphWithAi = useAuditStore(
    (s) => s.explainCurrentGraphWithAi
  );
  const loadAiPatchIntoDiffEditor = useAuditStore(
    (s) => s.loadAiPatchIntoDiffEditor
  );
  const remediationPreview = useAuditStore((s) => s.remediationPreview);
  const patchPanelResult = useAuditStore((s) => s.patchPanelResult);
  const isValidatingPatchPanel = useAuditStore((s) => s.isValidatingPatchPanel);
  const patchPanelError = useAuditStore((s) => s.patchPanelError);
  const runPatchPanelValidation = useAuditStore(
    (s) => s.runPatchPanelValidation
  );
  const generatedSecurityTest = useAuditStore((s) => s.generatedSecurityTest);
  const isGeneratingSecurityTest = useAuditStore(
    (s) => s.isGeneratingSecurityTest
  );
  const drawerSecurityTestError = useAuditStore(
    (s) => s.drawerSecurityTestError
  );
  const generateSecurityTestAction = useAuditStore(
    (s) => s.generateSecurityTestAction
  );
  const clearGeneratedSecurityTest = useAuditStore(
    (s) => s.clearGeneratedSecurityTest
  );

  const findings = useAuditStore((s) => s.findings);
  const selectedFinding = useAuditStore((s) => s.selectedFinding);
  const selectFinding = useAuditStore((s) => s.selectFinding);
  const updateFindingTriage = useAuditStore((s) => s.updateFindingTriage);
  const activeFilepath = useAuditStore((s) => s.activeFilepath);
  const activeStartLine = useAuditStore((s) => s.activeStartLine);
  const activeEndLine = useAuditStore((s) => s.activeEndLine);
  const graphViewMode = useAuditStore((s) => s.graphViewMode);

  // Local BYOK Vault Form State
  const [provider, setProvider] = useState<AiProviderType>("gemini");
  const [model, setModel] = useState<string>("gemini-2.5-flash");
  const [baseUrl, setBaseUrl] = useState<string>(
    "https://generativelanguage.googleapis.com"
  );
  const [apiKeyInput, setApiKeyInput] = useState<string>("");
  const [showApiKey, setShowApiKey] = useState<boolean>(false);
  const [persistKey, setPersistKey] = useState<boolean>(true);
  const [savedToast, setSavedToast] = useState<string | null>(null);

  // Code Audit Form State
  const [auditFilepath, setAuditFilepath] = useState<string>("");
  const [auditStartLine, setAuditStartLine] = useState<number>(1);
  const [auditEndLine, setAuditEndLine] = useState<number>(45);
  const [focusQuestion, setFocusQuestion] = useState<string>("");

  // Copy feedback state
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [appliedTriageIds, setAppliedTriageIds] = useState<
    Record<string, boolean>
  >({});
  const [useAiPatchPersonas, setUseAiPatchPersonas] = useState<boolean>(false);
  const [testGenFramework, setTestGenFramework] =
    useState<TestFrameworkType>("auto");
  const [allowTestOverwrite, setAllowTestOverwrite] = useState<boolean>(false);

  useEffect(() => {
    setAllowTestOverwrite(false);
    const st = useAuditStore.getState();
    if (
      st.generatedSecurityTest &&
      st.generatedSecurityTest.finding_id !== selectedFinding?.id
    ) {
      clearGeneratedSecurityTest();
    } else if (!selectedFinding && st.drawerSecurityTestError) {
      clearGeneratedSecurityTest();
    }
  }, [selectedFinding?.id, selectedFinding, clearGeneratedSecurityTest]);

  useEffect(() => {
    void fetchAiConfigState();
  }, [fetchAiConfigState]);

  useEffect(() => {
    if (!aiConfig) return;
    setProvider(aiConfig.provider);
    setModel(aiConfig.model);
    setBaseUrl(aiConfig.base_url || "");
    setPersistKey(Boolean(aiConfig.persist_key));
  }, [aiConfig]);

  useEffect(() => {
    const fallbackNode =
      selectedFinding?.path_nodes && selectedFinding.path_nodes.length > 0
        ? selectedFinding.path_nodes[selectedFinding.path_nodes.length - 1]
        : null;
    const fp =
      activeFilepath ||
      selectedFinding?.best_fix_location?.filepath ||
      fallbackNode?.filepath ||
      "";
    const sLine =
      activeStartLine ||
      selectedFinding?.best_fix_location?.line ||
      fallbackNode?.start_line ||
      1;
    const eLine =
      activeEndLine && activeEndLine >= sLine
        ? Math.max(activeEndLine, Math.min(sLine + 25, activeEndLine + 12))
        : sLine + 25;

    if (fp) setAuditFilepath(fp);
    setAuditStartLine(Math.max(1, sLine));
    setAuditEndLine(Math.max(sLine, eLine));
  }, [activeFilepath, activeStartLine, activeEndLine, selectedFinding]);

  useEffect(() => {
    if (!isAiDrawerOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !useAuditStore.getState().isQuickCommandOpen) {
        setAiDrawerOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isAiDrawerOpen, setAiDrawerOpen]);

  const providersList = useMemo(() => {
    return aiConfig?.available_providers && aiConfig.available_providers.length > 0
      ? aiConfig.available_providers
      : FALLBACK_PROVIDERS;
  }, [aiConfig?.available_providers]);

  const activeProviderSpec = useMemo(() => {
    return (
      providersList.find((p) => p.id === provider) || providersList[0]
    );
  }, [providersList, provider]);

  const orderedVerdicts = useMemo(() => {
    const entries = Object.values(aiVerdictsByFinding);
    if (!selectedFinding) return entries;
    return [...entries].sort((a, b) => {
      if (a.finding_id === selectedFinding.id) return -1;
      if (b.finding_id === selectedFinding.id) return 1;
      return 0;
    });
  }, [aiVerdictsByFinding, selectedFinding]);

  if (!isAiDrawerOpen) return null;

  const telemetry = aiConfig?.token_telemetry;
  const promptTokens =
    telemetry?.total_prompt_tokens ?? telemetry?.prompt_tokens ?? 0;
  const fullFileEst =
    telemetry?.total_full_file_tokens_est ??
    telemetry?.full_file_tokens_est ??
    0;
  const tokensSaved =
    telemetry?.total_tokens_saved ?? telemetry?.tokens_saved ?? 0;
  const savingsPct =
    telemetry?.overall_savings_pct ?? telemetry?.savings_pct ?? 0;
  const cacheHits =
    telemetry?.total_cache_hits ?? telemetry?.cache_hits ?? 0;
  const totalRequests = telemetry?.total_requests ?? 0;

  const isProviderReady =
    Boolean(aiConfig?.has_api_key) ||
    aiConfig?.provider === "openai_compatible";

  const copyText = (key: string, value: string) => {
    navigator.clipboard?.writeText(value);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleSelectProvider = (nextProvider: AiProviderType) => {
    const spec =
      providersList.find((p) => p.id === nextProvider) || FALLBACK_PROVIDERS[0];
    setProvider(nextProvider);
    setModel(spec.default_model);
    setBaseUrl(spec.default_base_url || "");
  };

  const handleSaveConfig = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanModel = model.trim() || activeProviderSpec.default_model;
    const updated = await saveAiConfigState({
      provider,
      model: cleanModel,
      base_url: baseUrl.trim() || null,
      ...(apiKeyInput.trim() ? { api_key: apiKeyInput.trim() } : {}),
      persist_key: persistKey,
    });
    if (updated) {
      setApiKeyInput("");
      setSavedToast(
        `Saved ${activeProviderSpec.label} (${updated.model}) configuration.`
      );
      setTimeout(() => setSavedToast(null), 3200);
    }
  };

  const handleClearStoredKey = async () => {
    const cleanModel = model.trim() || activeProviderSpec.default_model;
    const updated = await saveAiConfigState({
      provider,
      model: cleanModel,
      base_url: baseUrl.trim() || null,
      clear_api_key: true,
      persist_key: persistKey,
    });
    setApiKeyInput("");
    if (updated) {
      setSavedToast("Cleared stored API key from memory and local vault.");
      setTimeout(() => setSavedToast(null), 3200);
    }
  };

  const handleTestConnection = async () => {
    const cleanModel = model.trim() || activeProviderSpec.default_model;
    const hasUnsavedDiff =
      Boolean(apiKeyInput.trim()) ||
      provider !== aiConfig?.provider ||
      cleanModel !== aiConfig?.model ||
      baseUrl.trim() !== (aiConfig?.base_url || "");

    if (hasUnsavedDiff) {
      const saved = await saveAiConfigState({
        provider,
        model: cleanModel,
        base_url: baseUrl.trim() || null,
        ...(apiKeyInput.trim() ? { api_key: apiKeyInput.trim() } : {}),
        persist_key: persistKey,
      });
      if (!saved) return;
      setApiKeyInput("");
    }
    await runAiConnectionTest();
  };

  const handleApplyVerdictTriage = async (verdict: AiFindingVerdict) => {
    await updateFindingTriage(
      verdict.finding_id,
      verdict.suggested_triage_status,
      `Frontier AI Verdict: ${verdict.verdict} (${formatConfidencePct(
        verdict.confidence
      )}%)`,
      verdict.exploitability_summary
    );
    setAppliedTriageIds((prev) => ({ ...prev, [verdict.finding_id]: true }));
  };

  const tabs: Array<{
    id: AiDrawerTab;
    label: string;
    icon: React.ReactNode;
    badge?: string | number;
  }> = [
    {
      id: "SETTINGS",
      label: "Settings / BYOK",
      icon: <Settings className="w-3.5 h-3.5" />,
    },
    {
      id: "VALIDATE",
      label: "Validate TP/FP",
      icon: <ShieldCheck className="w-3.5 h-3.5" />,
      badge:
        orderedVerdicts.length > 0 ? orderedVerdicts.length : undefined,
    },
    {
      id: "CODE_AUDIT",
      label: "Code Audit",
      icon: <FileCode2 className="w-3.5 h-3.5" />,
    },
    {
      id: "PATCH",
      label: "AI Patch",
      icon: <Wrench className="w-3.5 h-3.5" />,
    },
    {
      id: "GRAPH",
      label: "Graph Story",
      icon: <Network className="w-3.5 h-3.5" />,
    },
  ];

  return (
    <aside
      aria-label="Frontier AI Copilot Drawer"
      className="fixed top-11 bottom-[26px] right-0 z-[145] w-[465px] max-w-[96vw] bg-[var(--surface-panel)] border-l border-[var(--border-hairline)] shadow-2xl flex flex-col text-[var(--ink-primary)] select-text"
    >
      {/* Top Drawer Header */}
      <div className="px-4 py-2.5 bg-[var(--surface-elevated)] border-b border-[var(--border-hairline)] flex items-center justify-between gap-2 shrink-0 select-none">
        <div className="flex items-center gap-2 min-w-0">
          <div className="w-7 h-7 rounded-lg bg-indigo-700 text-white flex items-center justify-center shadow-sm shrink-0">
            <Sparkles className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <h2 className="text-xs font-extrabold tracking-tight text-[var(--ink-primary)] truncate">
                Frontier AI Copilot
              </h2>
              <span className="px-1.5 py-0.5 rounded bg-indigo-700 text-white font-mono text-[9px] font-bold shrink-0">
                BYOK • MICRO-SLICE
              </span>
            </div>
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-[var(--ink-muted)] truncate">
              <span>
                {aiConfig?.provider || provider} • {aiConfig?.model || model}
              </span>
              <span>•</span>
              {isProviderReady ? (
                <span className="text-emerald-800 font-bold">Key Ready</span>
              ) : (
                <button
                  type="button"
                  onClick={() => setAiDrawerOpen(true, "SETTINGS")}
                  className="text-amber-800 underline font-bold hover:text-amber-950"
                >
                  Configure Key
                </button>
              )}
            </div>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setAiDrawerOpen(false)}
          title="Close Frontier AI Copilot (Esc)"
          className="p-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 hover:text-slate-950 transition-colors shrink-0"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Live Token Efficiency Meter Banner */}
      <div className="px-3.5 py-2.5 bg-slate-50 border-b border-slate-200 space-y-1.5 shrink-0 select-none">
        <div className="flex items-center justify-between gap-2 text-[10px] font-mono">
          <span className="font-bold text-slate-800 flex items-center gap-1">
            <Zap className="w-3.5 h-3.5 text-emerald-700" />
            CPG Micro-Slice Token Efficiency Meter
          </span>
          <span className="px-1.5 py-0.5 rounded bg-emerald-700 text-white font-bold">
            {savingsPct.toFixed(1)}% Tokens Saved
          </span>
        </div>

        {/* Visual Savings Progress Bar */}
        <div className="w-full h-2 rounded-full bg-slate-200 overflow-hidden border border-slate-300">
          <div
            className="h-full bg-emerald-600 transition-all duration-300"
            style={{
              width: `${Math.min(100, Math.max(totalRequests > 0 ? 6 : 0, savingsPct))}%`,
            }}
          />
        </div>

        <div className="grid grid-cols-3 gap-1.5 text-[10px] font-mono">
          <div className="px-2 py-1 rounded bg-white border border-slate-200">
            <div className="text-[9px] text-slate-600">Prompt vs Full-File</div>
            <div className="font-bold text-slate-900 truncate">
              {promptTokens.toLocaleString()} / {fullFileEst.toLocaleString()}
            </div>
          </div>
          <div className="px-2 py-1 rounded bg-white border border-slate-200">
            <div className="text-[9px] text-slate-600">Tokens Saved</div>
            <div className="font-bold text-emerald-800 truncate">
              {tokensSaved.toLocaleString()} tok
            </div>
          </div>
          <div
            className="px-2 py-1 rounded bg-emerald-50 border border-emerald-300"
            title="0 tokens spent on SHA-256 cached code slices"
          >
            <div className="text-[9px] text-emerald-900 font-semibold">
              SHA-256 Cache Hits
            </div>
            <div className="font-bold text-emerald-800 truncate">
              {cacheHits} hits (0 tok)
            </div>
          </div>
        </div>
      </div>

      {/* 5 Clean Workflow Tabs */}
      <div
        role="tablist"
        aria-label="Frontier AI Copilot Modes"
        className="px-2 py-1.5 bg-[var(--surface-elevated)] border-b border-[var(--border-hairline)] flex items-center gap-1 overflow-x-auto shrink-0 select-none"
      >
        {tabs.map((tab) => {
          const active = aiDrawerActiveTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setAiDrawerOpen(true, tab.id)}
              className={`px-2 py-1 rounded-md text-[11px] font-semibold flex items-center gap-1 whitespace-nowrap border transition-colors ${
                active
                  ? "bg-indigo-700 text-white border-indigo-800 shadow-sm"
                  : "bg-white hover:bg-slate-100 text-slate-700 border-slate-200"
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <span
                  className={`px-1 rounded text-[9px] font-mono font-bold ${
                    active
                      ? "bg-indigo-800 text-white"
                      : "bg-slate-100 text-slate-800"
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Error / Busy Status Strip */}
      {aiErrorBanner && (
        <div className="mx-3 mt-2.5 p-2.5 rounded-lg bg-rose-50 border border-rose-300 text-rose-900 text-xs flex items-start justify-between gap-2 shrink-0">
          <div className="flex items-start gap-2 min-w-0">
            <AlertTriangle className="w-4 h-4 text-rose-700 shrink-0 mt-0.5" />
            <div className="leading-snug break-words">{aiErrorBanner}</div>
          </div>
          {aiDrawerActiveTab !== "SETTINGS" && (
            <button
              type="button"
              onClick={() => setAiDrawerOpen(true, "SETTINGS")}
              className="px-2 py-1 rounded bg-rose-700 hover:bg-rose-800 text-white text-[10px] font-mono font-bold shrink-0"
            >
              BYOK Vault
            </button>
          )}
        </div>
      )}

      {aiIsBusy && (
        <div className="mx-3 mt-2 px-3 py-1.5 rounded-lg bg-indigo-50 border border-indigo-300 text-indigo-900 text-[11px] font-mono font-semibold flex items-center gap-2 shrink-0">
          <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-700 shrink-0" />
          <span>
            Dispatching compact CPG micro-slice to {aiConfig?.provider || provider}...
          </span>
        </div>
      )}

      {/* Scrollable Active Tab Body */}
      <div className="flex-1 overflow-y-auto p-3.5 space-y-3.5 text-xs">
        {/* TAB 1: SETTINGS / BYOK VAULT */}
        {aiDrawerActiveTab === "SETTINGS" && (
          <form onSubmit={handleSaveConfig} className="space-y-3.5">
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
              <div className="font-bold text-slate-900 flex items-center gap-1.5">
                <KeyRound className="w-4 h-4 text-indigo-700" />
                <span>Bring-Your-Own-Key (BYOK) Multi-Provider Vault</span>
              </div>
              <p className="text-[11px] text-slate-600 leading-relaxed">
                ALASTOR compresses files into minimal AST/DFG micro-slices (&le; 40
                lines) and caches verdicts by SHA-256 (`0` tokens on repeat
                slices). Keys are stored with strict `0o600` local permissions and
                never returned in plaintext.
              </p>
            </div>

            {savedToast && (
              <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-300 text-emerald-900 text-[11px] font-mono font-semibold flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                <span>{savedToast}</span>
              </div>
            )}

            {/* Provider Selector */}
            <div className="space-y-1.5">
              <label className="block text-[11px] font-mono font-bold text-slate-800 uppercase">
                1. Select Frontier AI Provider
              </label>
              <div className="grid grid-cols-2 gap-1.5">
                {(
                  [
                    { id: "gemini", short: "Google Gemini", sub: "Gemini 2.5 Flash/Pro" },
                    { id: "openai", short: "OpenAI", sub: "GPT-4o / o3-mini" },
                    { id: "anthropic", short: "Anthropic Claude", sub: "Claude 3.7 / 3.5" },
                    {
                      id: "openai_compatible",
                      short: "OpenAI-Compatible / Ollama",
                      sub: "Local Ollama / vLLM / OpenRouter",
                    },
                  ] as const
                ).map((item) => {
                  const selected = provider === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => handleSelectProvider(item.id)}
                      className={`p-2.5 rounded-xl border text-left transition-all ${
                        selected
                          ? "bg-indigo-50 border-indigo-600 ring-1 ring-indigo-600/30"
                          : "bg-white hover:bg-slate-50 border-slate-200"
                      }`}
                    >
                      <div className="font-bold text-slate-900 text-xs flex items-center justify-between gap-1">
                        <span className="truncate">{item.short}</span>
                        {selected && (
                          <CheckCircle2 className="w-3.5 h-3.5 text-indigo-700 shrink-0" />
                        )}
                      </div>
                      <div className="text-[10px] font-mono text-slate-600 truncate mt-0.5">
                        {item.sub}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Model Dropdown + Custom Model Input */}
            <div className="space-y-1.5">
              <label className="block text-[11px] font-mono font-bold text-slate-800 uppercase">
                2. Model Selection (Preset or Custom Model ID)
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <select
                  aria-label="Preset AI models"
                  value={
                    activeProviderSpec.models.includes(model)
                      ? model
                      : "__custom__"
                  }
                  onChange={(e) => {
                    if (e.target.value !== "__custom__") {
                      setModel(e.target.value);
                    }
                  }}
                  className="w-full bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-900 focus:outline-none focus:border-indigo-600"
                >
                  {activeProviderSpec.models.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                  <option value="__custom__">Custom model ID...</option>
                </select>

                <input
                  type="text"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  placeholder="Or type custom model ID..."
                  className="w-full bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-indigo-600"
                />
              </div>
            </div>

            {/* Base URL Input */}
            <div className="space-y-1">
              <label className="block text-[11px] font-mono font-bold text-slate-800 uppercase">
                {provider === "openai_compatible"
                  ? "3. OpenAI-Compatible / Ollama Base URL *"
                  : "3. Endpoint Base URL (Optional Override)"}
              </label>
              <input
                type="text"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder={activeProviderSpec.default_base_url}
                className={`w-full bg-white border rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-indigo-600 ${
                  provider === "openai_compatible"
                    ? "border-indigo-400"
                    : "border-slate-300"
                }`}
              />
              {provider === "openai_compatible" && (
                <p className="text-[10px] font-mono text-slate-600">
                  Local Ollama default: <code>http://localhost:11434/v1</code> (no
                  API key required for local models).
                </p>
              )}
            </div>

            {/* Masked API Key Input + Stored Status Badge + Clear Stored Key */}
            <div className="space-y-1.5 p-3 rounded-xl bg-white border border-slate-200">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <label className="text-[11px] font-mono font-bold text-slate-800 uppercase">
                  4. API Key Credential
                </label>
                <div className="flex items-center gap-1.5">
                  {aiConfig?.has_api_key ? (
                    <>
                      <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-800 font-mono text-[10px] font-bold">
                        Stored: {aiConfig.masked_api_key || "••••••••"}
                      </span>
                      <button
                        type="button"
                        disabled={aiIsBusy}
                        onClick={handleClearStoredKey}
                        className="px-2 py-0.5 rounded bg-rose-50 hover:bg-rose-100 border border-rose-300 text-rose-800 font-mono text-[10px] font-bold flex items-center gap-1"
                      >
                        <Trash2 className="w-3 h-3" />
                        <span>Clear Stored Key</span>
                      </button>
                    </>
                  ) : (
                    <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-300 text-amber-900 font-mono text-[10px] font-semibold">
                      {provider === "openai_compatible"
                        ? "Optional for Local Ollama"
                        : "No Key Stored"}
                    </span>
                  )}
                </div>
              </div>

              <div className="relative flex items-center">
                <input
                  type={showApiKey ? "text" : "password"}
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  autoComplete="off"
                  placeholder={
                    aiConfig?.has_api_key
                      ? "Leave blank to keep stored key, or paste a new key to rotate..."
                      : provider === "openai_compatible"
                      ? "Optional Bearer key (leave empty for local Ollama)"
                      : "Paste provider API key (AIza..., sk-..., sk-ant-...)"
                  }
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg pl-3 pr-9 py-2 text-xs font-mono text-slate-900 placeholder-slate-500 focus:outline-none focus:border-indigo-600"
                />
                <button
                  type="button"
                  onClick={() => setShowApiKey((v) => !v)}
                  title={showApiKey ? "Mask key" : "Show key"}
                  className="absolute right-2.5 text-slate-500 hover:text-slate-900"
                >
                  {showApiKey ? (
                    <EyeOff className="w-3.5 h-3.5" />
                  ) : (
                    <Eye className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>

              <label className="flex items-start gap-2 pt-1 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={persistKey}
                  onChange={(e) => setPersistKey(e.target.checked)}
                  className="mt-0.5 accent-indigo-700"
                />
                <span className="text-[11px] text-slate-700 leading-snug">
                  <strong>Remember key in local `0o600` vault</strong> (
                  <code>.alastor_vault/ai_config.json</code>). Uncheck to keep in
                  ephemeral server memory for this session only.
                </span>
              </label>
            </div>

            {/* Save & Test Connection Buttons */}
            <div className="grid grid-cols-2 gap-2">
              <button
                type="submit"
                disabled={aiIsBusy}
                className="py-2 px-3 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Save Configuration</span>
              </button>

              <button
                type="button"
                disabled={aiIsBusy}
                onClick={handleTestConnection}
                className="py-2 px-3 rounded-xl bg-sky-700 hover:bg-sky-800 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm"
              >
                <Database className="w-4 h-4" />
                <span>Test Connection</span>
              </button>
            </div>

            {/* Connection Test Feedback */}
            {aiConnectionStatus && (
              <div
                className={`p-3 rounded-xl border text-xs space-y-1 ${
                  aiConnectionStatus.ok
                    ? "bg-emerald-50 border-emerald-300 text-emerald-950"
                    : "bg-rose-50 border-rose-300 text-rose-950"
                }`}
              >
                <div className="flex items-center justify-between gap-2 font-mono font-bold">
                  <span className="flex items-center gap-1.5">
                    {aiConnectionStatus.ok ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-rose-700" />
                    )}
                    <span>
                      {aiConnectionStatus.ok
                        ? "CONNECTION VERIFIED"
                        : "CONNECTION FAILED"}
                    </span>
                  </span>
                  <span className="px-2 py-0.5 rounded bg-white border border-slate-300 text-slate-800 text-[10px]">
                    {aiConnectionStatus.latency_ms} ms •{" "}
                    {aiConnectionStatus.model}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed">
                  {aiConnectionStatus.message}
                </p>
              </div>
            )}
          </form>
        )}

        {/* TAB 2: VALIDATE TP/FP */}
        {aiDrawerActiveTab === "VALIDATE" && (
          <div className="space-y-3">
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <div className="font-bold text-slate-900">
                  Micro-Slice TP / FP Triage Validator
                </div>
                <span className="px-2 py-0.5 rounded bg-white border border-slate-300 font-mono text-[10px] text-slate-700">
                  {findings.length} Active Flaws
                </span>
              </div>

              {selectedFinding ? (
                <div className="p-2 rounded-lg bg-white border border-slate-200 text-[11px]">
                  <div className="font-mono text-[10px] text-slate-500">
                    Selected Finding:
                  </div>
                  <div className="font-bold text-slate-900 truncate">
                    [{selectedFinding.severity}] {selectedFinding.title}
                  </div>
                </div>
              ) : (
                <div className="text-[11px] text-slate-600">
                  Select a finding in Triage &amp; Fix or run Batch Digest
                  Validation across top findings in a single prompt.
                </div>
              )}

              <div className="grid grid-cols-1 gap-2">
                <button
                  type="button"
                  disabled={!selectedFinding || aiIsBusy}
                  onClick={() =>
                    selectedFinding && validateFindingsAi([selectedFinding.id])
                  }
                  className="w-full py-2 px-3 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm"
                >
                  <ShieldCheck className="w-4 h-4" />
                  <span>Validate Selected Finding</span>
                </button>

                <button
                  type="button"
                  disabled={findings.length === 0 || aiIsBusy}
                  onClick={() =>
                    validateFindingsAi(
                      findings.slice(0, 10).map((f) => f.id)
                    )
                  }
                  className="w-full py-2 px-3 rounded-xl bg-sky-700 hover:bg-sky-800 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm"
                >
                  <Sparkles className="w-4 h-4" />
                  <span>
                    Batch Digest Validate (Up to 10 Findings in 1 Call)
                  </span>
                </button>
              </div>
            </div>

            {/* Rendered Verdict Cards */}
            {orderedVerdicts.length === 0 ? (
              <div className="py-8 px-4 text-center rounded-xl border border-dashed border-slate-300 bg-white text-slate-600 space-y-1">
                <ShieldCheck className="w-7 h-7 mx-auto text-slate-400" />
                <div className="font-semibold text-slate-800">
                  No AI Verdicts Generated Yet
                </div>
                <p className="text-[11px]">
                  Click <b>Validate Selected Finding</b> or{" "}
                  <b>Batch Digest Validate</b> above to verify exploitability
                  using compact AST/DFG micro-slices.
                </p>
              </div>
            ) : (
              <div className="space-y-2.5">
                {orderedVerdicts.map((v) => {
                  const matched = findings.find((f) => f.id === v.finding_id);
                  const confPct = formatConfidencePct(v.confidence);
                  const alreadyApplied =
                    appliedTriageIds[v.finding_id] ||
                    matched?.triage_status === v.suggested_triage_status;

                  const verdictPillClass =
                    v.verdict === "TRUE_POSITIVE"
                      ? "bg-rose-700 text-white"
                      : v.verdict === "FALSE_POSITIVE"
                      ? "bg-emerald-700 text-white"
                      : "bg-amber-700 text-white";

                  return (
                    <div
                      key={v.finding_id}
                      className={`p-3 rounded-xl border bg-white space-y-2 shadow-sm ${
                        selectedFinding?.id === v.finding_id
                          ? "border-indigo-500 ring-1 ring-indigo-500/25"
                          : "border-slate-200"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1.5 flex-wrap">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${verdictPillClass}`}
                          >
                            {v.verdict.replace(/_/g, " ")} • {confPct}%
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-300 text-slate-800 font-mono text-[10px]">
                            Micro-Slice: {v.slice_lines_count} lines
                          </span>
                          {v.cache_hit && (
                            <span className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-800 font-mono text-[10px] font-bold">
                              Cache Hit • 0 tok
                            </span>
                          )}
                        </div>

                        {matched && (
                          <button
                            type="button"
                            onClick={() => selectFinding(matched)}
                            className="text-[10px] font-mono font-bold text-sky-800 hover:underline flex items-center gap-0.5"
                          >
                            <span>Inspect</span>
                            <ArrowUpRight className="w-3 h-3" />
                          </button>
                        )}
                      </div>

                      <div className="font-bold text-slate-900">
                        {matched ? matched.title : `Finding ${v.finding_id}`}
                      </div>

                      <div className="p-2 rounded-lg bg-slate-50 border border-slate-200 space-y-1 text-[11px]">
                        <div>
                          <strong className="text-slate-900">
                            Exploitability:{" "}
                          </strong>
                          <span className="text-slate-700">
                            {v.exploitability_summary}
                          </span>
                        </div>
                        <div>
                          <strong className="text-emerald-800">
                            Recommended Action:{" "}
                          </strong>
                          <span className="text-slate-700">
                            {v.recommended_action}
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center justify-between gap-2 pt-0.5">
                        <span className="text-[10px] font-mono text-slate-600">
                          Suggested:{" "}
                          <strong className="text-slate-900">
                            {v.suggested_triage_status}
                          </strong>
                        </span>

                        <button
                          type="button"
                          onClick={() => handleApplyVerdictTriage(v)}
                          className={`px-2.5 py-1 rounded-lg font-mono text-[10px] font-bold flex items-center gap-1 transition-colors ${
                            alreadyApplied
                              ? "bg-emerald-50 border border-emerald-300 text-emerald-800"
                              : "bg-emerald-700 hover:bg-emerald-800 text-white"
                          }`}
                        >
                          <CheckCircle2 className="w-3 h-3" />
                          <span>
                            {alreadyApplied
                              ? "Triage Status Applied"
                              : "Apply Triage Status"}
                          </span>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* TAB 3: CODE AUDIT */}
        {aiDrawerActiveTab === "CODE_AUDIT" && (
          <div className="space-y-3">
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
              <div className="font-bold text-slate-900">
                Surgical Code Selection Security Audit
              </div>

              <div className="space-y-2">
                <div>
                  <label className="block text-[10px] font-mono font-bold text-slate-700 mb-0.5">
                    Target Filepath
                  </label>
                  <input
                    type="text"
                    value={auditFilepath}
                    onChange={(e) => setAuditFilepath(e.target.value)}
                    placeholder="Select a file in Monaco or enter relative filepath..."
                    className="w-full bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-900"
                  />
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[10px] font-mono font-bold text-slate-700 mb-0.5">
                      Start Line
                    </label>
                    <input
                      type="number"
                      min={1}
                      value={auditStartLine}
                      onChange={(e) =>
                        setAuditStartLine(Math.max(1, Number(e.target.value) || 1))
                      }
                      className="w-full bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono font-bold text-slate-700 mb-0.5">
                      End Line
                    </label>
                    <input
                      type="number"
                      min={1}
                      value={auditEndLine}
                      onChange={(e) =>
                        setAuditEndLine(Math.max(1, Number(e.target.value) || 1))
                      }
                      className="w-full bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-900"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-mono font-bold text-slate-700 mb-0.5">
                    Optional Focus Question
                  </label>
                  <input
                    type="text"
                    value={focusQuestion}
                    onChange={(e) => setFocusQuestion(e.target.value)}
                    placeholder="e.g., Check for command injection, SSRF, or auth bypass..."
                    className="w-full bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs text-slate-900 placeholder-slate-400"
                  />
                </div>

                <button
                  type="button"
                  disabled={!auditFilepath.trim() || aiIsBusy}
                  onClick={() =>
                    auditCodeSelectionAi(
                      auditFilepath.trim(),
                      auditStartLine,
                      Math.max(auditStartLine, auditEndLine),
                      focusQuestion.trim() || undefined
                    )
                  }
                  className="w-full py-2 px-3 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Audit Code Slice with Frontier AI</span>
                </button>
              </div>
            </div>

            {aiLastAudit && (
              <div className="p-3 rounded-xl bg-white border border-slate-200 space-y-3 shadow-sm">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span
                    className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                      ["CRITICAL", "HIGH"].includes(
                        (aiLastAudit.risk_level || "").toUpperCase()
                      )
                        ? "bg-rose-700 text-white"
                        : (aiLastAudit.risk_level || "").toUpperCase() ===
                          "MEDIUM"
                        ? "bg-amber-700 text-white"
                        : "bg-emerald-700 text-white"
                    }`}
                  >
                    RISK: {aiLastAudit.risk_level || "ASSESSED"}
                  </span>
                  {aiLastAudit.token_telemetry && (
                    <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-800 font-mono text-[10px] font-bold">
                      {aiLastAudit.token_telemetry.prompt_tokens} prompt tok •{" "}
                      {aiLastAudit.token_telemetry.savings_pct.toFixed(0)}% saved
                    </span>
                  )}
                </div>

                <p className="text-xs text-slate-800 leading-relaxed">
                  {aiLastAudit.summary}
                </p>

                {aiLastAudit.observations &&
                  aiLastAudit.observations.length > 0 && (
                    <div className="space-y-2">
                      <div className="text-[10px] font-mono font-bold uppercase text-slate-700">
                        Line-Level Security Observations (
                        {aiLastAudit.observations.length})
                      </div>
                      {aiLastAudit.observations.map((obs, idx) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1"
                        >
                          <div className="flex items-center justify-between gap-2 font-mono text-[10px]">
                            <span className="font-bold text-indigo-800">
                              Lines {obs.line_range}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-white border border-slate-300 font-bold text-slate-800">
                              {obs.severity}
                            </span>
                          </div>
                          <div className="font-bold text-slate-900">
                            {obs.title}
                          </div>
                          <p className="text-[11px] text-slate-700">
                            {obs.explanation}
                          </p>
                          {obs.remediation && (
                            <p className="text-[11px] text-emerald-800 font-medium">
                              Fix: {obs.remediation}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                {aiLastAudit.secure_snippet && (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono font-bold uppercase text-emerald-800">
                        Recommended Hardened Snippet
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          copyText("audit-snippet", aiLastAudit.secure_snippet)
                        }
                        className="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-800 font-mono text-[10px] font-bold flex items-center gap-1"
                      >
                        {copiedKey === "audit-snippet" ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-700" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy</span>
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="p-2.5 rounded-lg bg-emerald-50/70 border border-emerald-300 font-mono text-[11px] text-slate-900 overflow-x-auto whitespace-pre-wrap">
                      {aiLastAudit.secure_snippet}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* TAB 4: AI PATCH SYNTHESIS */}
        {aiDrawerActiveTab === "PATCH" && (
          <div className="space-y-3">
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
              <div className="font-bold text-slate-900">
                Surgical BFL Chokepoint Patch Synthesizer
              </div>
              <p className="text-[11px] text-slate-600">
                Synthesizes a minimal, drop-in remediation patch from the
                finding&apos;s CPG micro-slice and loads it straight into the
                Monaco side-by-side DiffEditor for SHA-256 verified application.
              </p>

              <button
                type="button"
                disabled={!selectedFinding || aiIsBusy}
                onClick={() =>
                  selectedFinding &&
                  synthesizeFindingPatchAi(selectedFinding.id)
                }
                className="w-full py-2 px-3 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm"
              >
                <Wrench className="w-4 h-4" />
                <span>
                  {selectedFinding
                    ? "Synthesize AI Patch for Selected Finding"
                    : "Select a Finding First"}
                </span>
              </button>
            </div>

            {aiLastSynthesizedPatch && (
              <div className="p-3 rounded-xl bg-white border border-slate-200 space-y-3 shadow-sm">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-300 text-indigo-900 font-mono text-[10px] font-bold truncate max-w-[240px]">
                    {aiLastSynthesizedPatch.filepath || "Target Slice"}
                  </span>
                  {aiLastSynthesizedPatch.token_telemetry && (
                    <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-800 font-mono text-[10px] font-bold">
                      {aiLastSynthesizedPatch.token_telemetry.savings_pct.toFixed(
                        0
                      )}
                      % tokens saved
                    </span>
                  )}
                </div>

                <p className="text-xs text-slate-800 leading-relaxed">
                  {aiLastSynthesizedPatch.explanation}
                </p>

                {aiLastSynthesizedPatch.before_snippet && (
                  <div className="space-y-1">
                    <div className="text-[10px] font-mono font-bold uppercase text-rose-800">
                      Vulnerable Slice (Before)
                    </div>
                    <pre className="p-2.5 rounded-lg bg-rose-50 border border-rose-200 font-mono text-[11px] text-rose-950 overflow-x-auto whitespace-pre-wrap">
                      {aiLastSynthesizedPatch.before_snippet}
                    </pre>
                  </div>
                )}

                {aiLastSynthesizedPatch.after_snippet && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono font-bold uppercase text-emerald-800">
                        Hardened Slice (After)
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          copyText(
                            "patch-after",
                            aiLastSynthesizedPatch.after_snippet
                          )
                        }
                        className="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-800 font-mono text-[10px] font-bold flex items-center gap-1"
                      >
                        {copiedKey === "patch-after" ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-700" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy</span>
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-300 font-mono text-[11px] text-emerald-950 overflow-x-auto whitespace-pre-wrap">
                      {aiLastSynthesizedPatch.after_snippet}
                    </pre>
                  </div>
                )}

                <button
                  type="button"
                  onClick={() =>
                    void loadAiPatchIntoDiffEditor(aiLastSynthesizedPatch)
                  }
                  className="w-full py-2.5 px-3 rounded-xl bg-emerald-700 hover:bg-emerald-800 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-sm"
                >
                  <GitCompare className="w-4 h-4" />
                  <span>Load into Diff Editor</span>
                </button>
              </div>
            )}

            {/* S11 Dual-Verified 3-Persona + AST/CPG Patch Validation Panel */}
            {(() => {
              const normFp = (fp?: string | null) =>
                (fp || "").replace(/\\/g, "/").trim().toLowerCase();
              const activeAiPatch =
                selectedFinding &&
                aiLastSynthesizedPatch?.finding_id === selectedFinding.id
                  ? aiLastSynthesizedPatch
                  : null;
              const activePreview =
                selectedFinding &&
                remediationPreview?.finding_id === selectedFinding.id
                  ? remediationPreview
                  : null;
              const fallbackNode =
                selectedFinding?.path_nodes &&
                selectedFinding.path_nodes.length > 0
                  ? selectedFinding.path_nodes[
                      selectedFinding.path_nodes.length - 1
                    ]
                  : null;

              let candidateFilepath = "";
              let candidateOriginal = "";
              let candidateProposed = "";

              // 1. Full-file + full-file (same filepath)
              const fullOriginal = activePreview?.original_content || "";
              const fullProposedFromAi = activeAiPatch?.patched_full_content || "";
              const fullProposedFromPreview = activePreview?.patched_content || "";
              const sameFileForAiFull =
                Boolean(fullProposedFromAi.trim()) &&
                Boolean(activePreview?.filepath) &&
                (!activeAiPatch?.filepath ||
                  normFp(activeAiPatch.filepath) ===
                    normFp(activePreview?.filepath));

              if (fullOriginal.trim() && sameFileForAiFull) {
                candidateFilepath =
                  activeAiPatch?.filepath || activePreview?.filepath || "";
                candidateOriginal = fullOriginal;
                candidateProposed = fullProposedFromAi;
              } else if (
                fullOriginal.trim() &&
                fullProposedFromPreview.trim() &&
                activePreview?.filepath
              ) {
                candidateFilepath = activePreview.filepath;
                candidateOriginal = fullOriginal;
                candidateProposed = fullProposedFromPreview;
              } else if (
                // 2. Snippet + snippet from AI synthesized patch
                activeAiPatch?.before_snippet?.trim() &&
                activeAiPatch?.after_snippet?.trim()
              ) {
                candidateFilepath =
                  activeAiPatch.filepath ||
                  selectedFinding?.best_fix_location?.filepath ||
                  fallbackNode?.filepath ||
                  "";
                candidateOriginal = activeAiPatch.before_snippet;
                candidateProposed = activeAiPatch.after_snippet;
              } else if (
                // 3. BFL code block + code block (never prose recommended_fix)
                selectedFinding?.best_fix_location?.before_code_block?.trim() &&
                selectedFinding?.best_fix_location?.after_code_block?.trim()
              ) {
                candidateFilepath =
                  selectedFinding.best_fix_location.filepath ||
                  fallbackNode?.filepath ||
                  "";
                candidateOriginal =
                  selectedFinding.best_fix_location.before_code_block;
                candidateProposed =
                  selectedFinding.best_fix_location.after_code_block;
              }

              const canRunPanel = Boolean(
                selectedFinding &&
                  candidateFilepath.trim() &&
                  candidateOriginal.trim() &&
                  candidateProposed.trim()
              );

              const handleRunS11Validation = () => {
                if (!canRunPanel || !selectedFinding) return;
                void runPatchPanelValidation({
                  finding_id: selectedFinding.id,
                  filepath: candidateFilepath.trim(),
                  original_code: candidateOriginal,
                  proposed_code: candidateProposed,
                  cwe_id: selectedFinding.cwe_id || null,
                  use_ai: isProviderReady && useAiPatchPersonas,
                });
              };

              return (
                <div className="p-3 rounded-xl bg-white border border-slate-200 space-y-3 shadow-sm">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="font-extrabold text-slate-900 text-xs flex items-center gap-1.5">
                        <Users className="w-4 h-4 text-indigo-700 shrink-0" />
                        <span>S11 Dual-Verified 3-Persona Patch Panel</span>
                      </div>
                      <p className="text-[11px] text-slate-600 mt-0.5 leading-snug">
                        Fail-closed deterministic AST syntax, hostile-patch
                        post-gate &amp; CPG taint-severance verification plus
                        3-persona review.
                      </p>
                    </div>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 font-mono text-[9px] font-extrabold shrink-0">
                      $0 / BYOK
                    </span>
                  </div>

                  {isProviderReady && (
                    <label className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-indigo-50 border border-indigo-200 text-indigo-950 text-[11px] font-semibold cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={useAiPatchPersonas}
                        onChange={(e) =>
                          setUseAiPatchPersonas(e.target.checked)
                        }
                        className="accent-indigo-700"
                      />
                      <span>Use BYOK AI Personas</span>
                    </label>
                  )}

                  <button
                    type="button"
                    disabled={!canRunPanel || isValidatingPatchPanel}
                    onClick={handleRunS11Validation}
                    className="w-full py-2 px-3 rounded-xl bg-sky-700 hover:bg-sky-800 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm transition-colors"
                  >
                    {isValidatingPatchPanel ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <ShieldCheck className="w-4 h-4" />
                    )}
                    <span>
                      {isValidatingPatchPanel
                        ? "Running S11 Gates & 3 Personas..."
                        : "Run S11 3-Persona + AST/CPG Validation"}
                    </span>
                  </button>

                  {!canRunPanel && (
                    <p className="text-[10px] font-mono text-slate-600">
                      Synthesize an AI patch or open a remediation diff preview
                      for the selected finding (paired before/after code) to
                      enable S11 validation.
                    </p>
                  )}

                  {patchPanelError && (
                    <div
                      role="alert"
                      className="p-2.5 rounded-lg bg-rose-50 border border-rose-300 text-rose-950 text-[11px] font-semibold flex items-start gap-1.5"
                    >
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-700 shrink-0 mt-0.5" />
                      <span className="break-words">{patchPanelError}</span>
                    </div>
                  )}

                  {patchPanelResult && (
                    <div className="space-y-3 pt-1">
                      {/* Overall Verdict Banner */}
                      <div
                        className={`p-2.5 rounded-xl border space-y-1 ${
                          patchPanelResult.overall_verdict === "APPROVED"
                            ? "bg-emerald-50 border-emerald-300 text-emerald-950"
                            : patchPanelResult.overall_verdict ===
                              "REVISIONS_REQUIRED"
                            ? "bg-amber-50 border-amber-300 text-amber-950"
                            : "bg-rose-50 border-rose-300 text-rose-950"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <span className="font-mono text-[11px] font-extrabold flex items-center gap-1.5">
                            {patchPanelResult.overall_verdict === "APPROVED" ? (
                              <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                            ) : patchPanelResult.overall_verdict ===
                              "REVISIONS_REQUIRED" ? (
                              <AlertTriangle className="w-4 h-4 text-amber-700" />
                            ) : (
                              <XCircle className="w-4 h-4 text-rose-700" />
                            )}
                            <span>
                              VERDICT:{" "}
                              {patchPanelResult.overall_verdict.replace(
                                /_/g,
                                " "
                              )}
                            </span>
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-white border border-slate-300 text-slate-900 font-mono text-[9px] font-bold">
                            {patchPanelResult.execution_mode}
                          </span>
                        </div>
                        {patchPanelResult.summary && (
                          <p className="text-[11px] leading-snug">
                            {patchPanelResult.summary}
                          </p>
                        )}
                      </div>

                      {/* 3 Deterministic Safety Gates */}
                      <div className="space-y-1.5">
                        <div className="text-[10px] font-mono font-extrabold uppercase text-slate-700">
                          3 Deterministic Safety Gates (Fail-Closed)
                        </div>
                        <div className="grid grid-cols-1 gap-1.5">
                          <div
                            className={`p-2 rounded-lg border flex items-start justify-between gap-2 text-[11px] ${
                              patchPanelResult.syntax_ok
                                ? "bg-emerald-50 border-emerald-300 text-emerald-950"
                                : "bg-rose-50 border-rose-300 text-rose-950"
                            }`}
                          >
                            <div className="space-y-0.5 min-w-0">
                              <div className="font-bold flex items-center gap-1.5">
                                {patchPanelResult.syntax_ok ? (
                                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                                ) : (
                                  <XCircle className="w-3.5 h-3.5 text-rose-700 shrink-0" />
                                )}
                                <span>AST Syntax</span>
                              </div>
                              {patchPanelResult.syntax_error && (
                                <div className="font-mono text-[10px] text-rose-900 break-words">
                                  {patchPanelResult.syntax_error}
                                </div>
                              )}
                            </div>
                            <span className="font-mono text-[10px] font-extrabold shrink-0">
                              {patchPanelResult.syntax_ok ? "PASS" : "FAIL"}
                            </span>
                          </div>

                          <div
                            className={`p-2 rounded-lg border flex items-start justify-between gap-2 text-[11px] ${
                              !patchPanelResult.hostile_patch_blocked
                                ? "bg-emerald-50 border-emerald-300 text-emerald-950"
                                : "bg-rose-50 border-rose-300 text-rose-950"
                            }`}
                          >
                            <div className="space-y-1 min-w-0">
                              <div className="font-bold flex items-center gap-1.5">
                                {!patchPanelResult.hostile_patch_blocked ? (
                                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                                ) : (
                                  <XCircle className="w-3.5 h-3.5 text-rose-700 shrink-0" />
                                )}
                                <span>Hostile-Patch Post-Gate</span>
                              </div>
                              {patchPanelResult.hostile_patch_reasons.length >
                                0 && (
                                <ul className="list-disc pl-4 space-y-0.5 text-[10px] font-mono text-rose-950">
                                  {patchPanelResult.hostile_patch_reasons.map(
                                    (reason, idx) => (
                                      <li key={idx}>{reason}</li>
                                    )
                                  )}
                                </ul>
                              )}
                            </div>
                            <span className="font-mono text-[10px] font-extrabold shrink-0">
                              {!patchPanelResult.hostile_patch_blocked
                                ? "CLEAN"
                                : "BLOCKED"}
                            </span>
                          </div>

                          <div
                            className={`p-2 rounded-lg border flex items-center justify-between gap-2 text-[11px] ${
                              patchPanelResult.cpg_sink_severed
                                ? "bg-emerald-50 border-emerald-300 text-emerald-950"
                                : "bg-amber-50 border-amber-300 text-amber-950"
                            }`}
                          >
                            <div className="font-bold flex items-center gap-1.5">
                              {patchPanelResult.cpg_sink_severed ? (
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                              ) : (
                                <AlertTriangle className="w-3.5 h-3.5 text-amber-700 shrink-0" />
                              )}
                              <span>CPG Taint Severance</span>
                            </div>
                            <span className="font-mono text-[10px] font-extrabold shrink-0">
                              {patchPanelResult.cpg_sink_severed
                                ? "SEVERED"
                                : "UNVERIFIED"}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* 3 Persona Scorecards */}
                      {patchPanelResult.personas.length > 0 && (
                        <div className="space-y-1.5">
                          <div className="text-[10px] font-mono font-extrabold uppercase text-slate-700">
                            3-Persona Review Scorecards
                          </div>
                          <div className="space-y-2">
                            {patchPanelResult.personas.map((persona) => {
                              const pPillClass =
                                persona.verdict === "APPROVE"
                                  ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                                  : persona.verdict === "CONCERN"
                                  ? "bg-amber-50 text-amber-950 border-amber-300"
                                  : "bg-rose-50 text-rose-950 border-rose-300";
                              return (
                                <div
                                  key={persona.persona_id}
                                  className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5"
                                >
                                  <div className="flex items-center justify-between gap-2 flex-wrap">
                                    <span className="text-xs font-extrabold text-slate-900">
                                      {persona.persona_label}
                                    </span>
                                    <div className="flex items-center gap-1.5 font-mono text-[10px]">
                                      <span
                                        className={`px-1.5 py-0.5 rounded border font-extrabold ${pPillClass}`}
                                      >
                                        {persona.verdict}
                                      </span>
                                      <span className="px-1.5 py-0.5 rounded bg-white border border-slate-300 text-slate-900 font-extrabold">
                                        {persona.score}/100
                                      </span>
                                    </div>
                                  </div>

                                  {persona.summary && (
                                    <p className="text-[11px] text-slate-800 leading-snug">
                                      {persona.summary}
                                    </p>
                                  )}

                                  {persona.findings.length > 0 && (
                                    <ul className="list-disc pl-4 space-y-0.5 text-[11px] text-slate-700">
                                      {persona.findings.map((note, idx) => (
                                        <li key={idx}>{note}</li>
                                      ))}
                                    </ul>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Pillar 5: 1-Click Security Regression Unit-Test Generator */}
            <div className="p-3 rounded-xl bg-white border border-slate-200 space-y-3 shadow-sm">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="font-extrabold text-slate-900 text-xs flex items-center gap-1.5">
                    <FlaskConical className="w-4 h-4 text-emerald-700 shrink-0" />
                    <span>1-Click Security Regression Unit-Test Generator</span>
                  </div>
                  <p className="text-[11px] text-slate-600 mt-0.5 leading-snug">
                    Generates deterministic, zero-raw-secret regression tests
                    tailored to the finding&apos;s CWE for{" "}
                    <code>pytest</code>, <code>jest</code>, <code>vitest</code>,
                    or <code>go test</code>.
                  </p>
                </div>
                <span className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 font-mono text-[9px] font-extrabold shrink-0">
                  $0 AST
                </span>
              </div>

              {selectedFinding ? (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 items-end">
                    <div>
                      <label className="block text-[10px] font-mono font-bold text-slate-700 mb-1">
                        Test Framework
                      </label>
                      <select
                        aria-label="Security regression test framework"
                        value={testGenFramework}
                        onChange={(e) =>
                          setTestGenFramework(
                            e.target.value as TestFrameworkType
                          )
                        }
                        className="w-full bg-slate-50 border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-900 focus:outline-none focus:border-indigo-600"
                      >
                        <option value="auto">Auto (Detect from File/Repo)</option>
                        <option value="pytest">pytest (Python)</option>
                        <option value="jest">jest (JS/TS)</option>
                        <option value="vitest">vitest (JS/TS)</option>
                        <option value="go_test">go_test (Go)</option>
                      </select>
                    </div>

                    <label className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-[11px] font-semibold text-slate-800 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={allowTestOverwrite}
                        onChange={(e) =>
                          setAllowTestOverwrite(e.target.checked)
                        }
                        className="accent-indigo-700"
                      />
                      <span>Allow Overwrite</span>
                    </label>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <button
                      type="button"
                      disabled={isGeneratingSecurityTest}
                      onClick={() =>
                        void generateSecurityTestAction({
                          finding_id: selectedFinding.id,
                          framework: testGenFramework,
                          write_to_workspace: false,
                          overwrite: false,
                        })
                      }
                      className="py-2 px-3 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm transition-colors"
                    >
                      {isGeneratingSecurityTest ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <FlaskConical className="w-3.5 h-3.5" />
                      )}
                      <span>Generate Regression Test</span>
                    </button>

                    <button
                      type="button"
                      disabled={isGeneratingSecurityTest}
                      onClick={() =>
                        void generateSecurityTestAction({
                          finding_id: selectedFinding.id,
                          framework: testGenFramework,
                          write_to_workspace: true,
                          overwrite: allowTestOverwrite,
                        })
                      }
                      className="py-2 px-3 rounded-xl bg-emerald-700 hover:bg-emerald-800 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm transition-colors"
                    >
                      {isGeneratingSecurityTest ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Save className="w-3.5 h-3.5" />
                      )}
                      <span>Write to tests/security/</span>
                    </button>
                  </div>

                  {drawerSecurityTestError && (
                    <div
                      role="alert"
                      className="p-2.5 rounded-lg bg-rose-50 border border-rose-300 text-rose-950 text-[11px] font-semibold flex items-start gap-1.5"
                    >
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-700 shrink-0 mt-0.5" />
                      <span className="break-words">
                        {drawerSecurityTestError}
                      </span>
                    </div>
                  )}

                  {generatedSecurityTest && (
                    <div className="space-y-2.5 pt-2 border-t border-slate-200">
                      <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                        <span className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-900 font-extrabold">
                          {generatedSecurityTest.framework}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded border font-extrabold flex items-center gap-1 ${
                            generatedSecurityTest.syntax_valid
                              ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                              : "bg-amber-50 text-amber-950 border-amber-300"
                          }`}
                        >
                          {generatedSecurityTest.syntax_valid ? (
                            <CheckCircle2 className="w-3 h-3 text-emerald-700" />
                          ) : (
                            <AlertTriangle className="w-3 h-3 text-amber-700" />
                          )}
                          <span>
                            {generatedSecurityTest.syntax_valid
                              ? "AST Verified"
                              : "Syntax Check Warning"}
                          </span>
                        </span>
                        {generatedSecurityTest.written_to_disk && (
                          <span className="px-2 py-0.5 rounded bg-emerald-700 text-white font-bold">
                            Written to Disk
                          </span>
                        )}
                      </div>

                      <div className="p-2 rounded-lg bg-slate-50 border border-slate-200 text-[11px] font-mono text-slate-800 space-y-1">
                        <div className="truncate">
                          <span className="text-slate-600 font-semibold">
                            Path:{" "}
                          </span>
                          <span className="font-bold text-slate-900">
                            {generatedSecurityTest.suggested_relative_path}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5 text-slate-700 truncate">
                          <Terminal className="w-3 h-3 text-indigo-700 shrink-0" />
                          <code className="truncate">
                            {generatedSecurityTest.run_command_hint}
                          </code>
                        </div>
                      </div>

                      {generatedSecurityTest.warnings.length > 0 && (
                        <div className="p-2 rounded-lg bg-amber-50 border border-amber-300 text-amber-950 text-[10.5px] space-y-0.5">
                          {generatedSecurityTest.warnings.map((w, idx) => (
                            <div key={idx}>{w}</div>
                          ))}
                        </div>
                      )}

                      <div className="space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[10px] font-mono font-bold uppercase text-slate-700">
                            Generated Regression Test ({generatedSecurityTest.cwe_id})
                          </span>
                          <button
                            type="button"
                            onClick={() =>
                              copyText(
                                "security-test-code",
                                generatedSecurityTest.test_code
                              )
                            }
                            className="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-800 font-mono text-[10px] font-bold flex items-center gap-1"
                          >
                            {copiedKey === "security-test-code" ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-700" />
                                <span>Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy Test Code</span>
                              </>
                            )}
                          </button>
                        </div>

                        <pre className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 font-mono text-[10.5px] text-slate-900 overflow-x-auto whitespace-pre-wrap break-words max-h-64">
                          {generatedSecurityTest.test_code}
                        </pre>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <p className="text-[11px] font-mono text-slate-600">
                  Select a finding in Triage &amp; Fix to generate a CWE-tailored
                  security regression unit test.
                </p>
              )}
            </div>
          </div>
        )}

        {/* TAB 5: GRAPH STORY */}
        {aiDrawerActiveTab === "GRAPH" && (
          <div className="space-y-3">
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-bold text-slate-900">
                  Plain-English Graph Storyteller
                </span>
                <span className="px-2 py-0.5 rounded bg-white border border-slate-300 font-mono text-[10px] text-slate-700">
                  {graphViewMode}
                </span>
              </div>
              <p className="text-[11px] text-slate-600">
                Translates the active CPG / 360° Architecture / Trust Boundary
                node-and-edge digest into a clear step-by-step narrative for
                engineers and executives.
              </p>

              <button
                type="button"
                disabled={aiIsBusy}
                onClick={() => void explainCurrentGraphWithAi()}
                className="w-full py-2 px-3 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm"
              >
                <Network className="w-4 h-4" />
                <span>Explain Current Graph with AI</span>
              </button>
            </div>

            {aiLastGraphExplanation && (
              <div className="p-3.5 rounded-xl bg-white border border-slate-200 space-y-3 shadow-sm">
                <h3 className="text-sm font-extrabold text-slate-900 leading-snug">
                  {aiLastGraphExplanation.headline}
                </h3>

                <p className="text-xs text-slate-700 leading-relaxed">
                  {aiLastGraphExplanation.plain_english_story}
                </p>

                {aiLastGraphExplanation.step_walkthrough &&
                  aiLastGraphExplanation.step_walkthrough.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-[10px] font-mono font-bold uppercase text-indigo-800">
                        Step-by-Step Flow Walkthrough
                      </div>
                      <ol className="space-y-1.5">
                        {aiLastGraphExplanation.step_walkthrough.map(
                          (step, idx) => (
                            <li
                              key={idx}
                              className="p-2 rounded-lg bg-slate-50 border border-slate-200 flex items-start gap-2 text-[11px] text-slate-800"
                            >
                              <span className="w-5 h-5 rounded-full bg-indigo-700 text-white font-mono text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                                {idx + 1}
                              </span>
                              <span className="leading-relaxed">{step}</span>
                            </li>
                          )
                        )}
                      </ol>
                    </div>
                  )}

                {aiLastGraphExplanation.security_takeaway && (
                  <div className="p-2.5 rounded-lg bg-amber-50 border border-amber-300 text-amber-950 text-[11px] leading-relaxed">
                    <strong className="font-bold uppercase font-mono text-[10px] block mb-0.5 text-amber-900">
                      Key Security Takeaway
                    </strong>
                    {aiLastGraphExplanation.security_takeaway}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </aside>
  );
}

export default FrontierAiCopilotDrawer;
