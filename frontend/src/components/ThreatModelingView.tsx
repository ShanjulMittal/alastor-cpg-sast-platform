"use client";

import React, { useEffect, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  ShieldAlert,
  KeyRound,
  Eye,
  EyeOff,
  Compass,
  PhoneCall,
  Code2,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Globe,
  Server,
  Database,
  ArrowRight,
  Layers,
  Filter,
  Sparkles,
  Copy,
  Check,
} from "lucide-react";

const STRIDE_META: Record<
  string,
  {
    letter: string;
    label: string;
    securityProperty: string;
    color: string;
    badgeBg: string;
  }
> = {
  SPOOFING: {
    letter: "S",
    label: "Spoofing Identity",
    securityProperty: "Authentication",
    color: "text-rose-400",
    badgeBg: "bg-rose-500/15 border-rose-500/40 text-rose-300",
  },
  TAMPERING: {
    letter: "T",
    label: "Tampering with Data",
    securityProperty: "Integrity",
    color: "text-amber-400",
    badgeBg: "bg-amber-500/15 border-amber-500/40 text-amber-300",
  },
  REPUDIATION: {
    letter: "R",
    label: "Repudiation",
    securityProperty: "Non-Repudiation & Auditability",
    color: "text-purple-400",
    badgeBg: "bg-purple-500/15 border-purple-500/40 text-purple-300",
  },
  INFORMATION_DISCLOSURE: {
    letter: "I",
    label: "Information Disclosure",
    securityProperty: "Confidentiality & Secret Hygiene",
    color: "text-cyan-400",
    badgeBg: "bg-cyan-500/15 border-cyan-500/40 text-cyan-300",
  },
  DENIAL_OF_SERVICE: {
    letter: "D",
    label: "Denial of Service",
    securityProperty: "Availability & Resilience",
    color: "text-orange-400",
    badgeBg: "bg-orange-500/15 border-orange-500/40 text-orange-300",
  },
  ELEVATION_OF_PRIVILEGE: {
    letter: "E",
    label: "Elevation of Privilege",
    securityProperty: "Authorization & Sandboxing",
    color: "text-red-400",
    badgeBg: "bg-red-500/15 border-red-500/40 text-red-300",
  },
};

export const ThreatModelingView: React.FC = () => {
  const {
    sastPlusSuite,
    fetchSastPlusSuite,
    findings,
    projectPath,
    selectFinding,
    setWorkspaceViewMode,
    setGraphViewMode,
    setIdeLayoutMode,
    userAccountsState,
  } = useAuditStore();

  const [activeSubTab, setActiveSubTab] = useState<
    "STRIDE_BOARD" | "SECRET_KEYS_VAULT" | "TRUST_BOUNDARIES" | "ENTRYPOINTS_PBOM"
  >("STRIDE_BOARD");
  const [selectedStrideCategory, setSelectedStrideCategory] =
    useState<string>("ALL");
  const [revealedSecretIds, setRevealedSecretIds] = useState<
    Record<string, boolean>
  >({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    if (!sastPlusSuite) {
      fetchSastPlusSuite();
    }
  }, [sastPlusSuite, fetchSastPlusSuite]);

  const activeUser = userAccountsState?.users?.find(
    (u) => u.id === userAccountsState.active_user_id
  );
  const canRevealSecrets = activeUser ? activeUser.can_reveal_secrets : true;

  const secretFindings = findings.filter(
    (f) =>
      f.is_secret_finding ||
      (f.rule_id || "").toUpperCase().includes("SECRET") ||
      f.cwe_id === "CWE-798"
  );

  const strideThreats = sastPlusSuite?.stride_threats || [];
  const endpoints = sastPlusSuite?.endpoints || [];
  const pipelineChecks = sastPlusSuite?.pipeline_checks || [];

  const filteredStride =
    selectedStrideCategory === "ALL"
      ? strideThreats
      : strideThreats.filter(
          (t) => t.stride_category === selectedStrideCategory
        );

  const toggleRevealSecret = (id: string) => {
    if (!canRevealSecrets) return;
    setRevealedSecretIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopySecret = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const handleInspectFindingInIde = (findingId: string) => {
    const target = findings.find((f) => f.id === findingId);
    if (target) {
      selectFinding(target);
      setWorkspaceViewMode("REMEDIATION_IDE");
    }
  };

  return (
    <div className="flex-1 h-full overflow-y-auto bg-slate-950/95 text-slate-100 p-6 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-start gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-rose-500/15 border border-rose-500/40 flex items-center justify-center text-rose-400 shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-lg font-extrabold tracking-tight text-slate-100">
                Architectural Threat Modeling & Secret Key Intelligence
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                STRIDE + Secret Hunter + Entrypoints
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Live architectural threat synthesis derived directly from the Code Property Graph (AST/CFG/DFG/Call Graph), Attack Surface Entrypoints, and Deep Secret Key Scanner for{" "}
              <span className="font-mono text-amber-300 font-semibold">
                {projectPath || "Active Application"}
              </span>
              .
            </p>
          </div>
        </div>

        {/* Direct Graph Launch Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setWorkspaceViewMode("REMEDIATION_IDE");
              setGraphViewMode("ENTRYPOINT_GRAPH");
              setIdeLayoutMode("SPLIT_BOTH");
            }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-bold bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/40 transition-all"
          >
            <Compass className="w-3.5 h-3.5" />
            View Entry Points Graph
          </button>
          <button
            onClick={() => {
              setWorkspaceViewMode("REMEDIATION_IDE");
              setGraphViewMode("CALL_GRAPH");
              setIdeLayoutMode("SPLIT_BOTH");
            }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-bold bg-purple-500/15 hover:bg-purple-500/25 text-purple-300 border border-purple-500/40 transition-all"
          >
            <PhoneCall className="w-3.5 h-3.5" />
            View Call Graph
          </button>
        </div>
      </div>

      {/* KPI Summary Strip */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
            STRIDE Threat Vectors
          </div>
          <div className="text-2xl font-extrabold text-rose-400 mt-1">
            {strideThreats.length}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            {
              strideThreats.filter((t) => t.status === "ACTION_REQUIRED").length
            }{" "}
            require immediate mitigation
          </div>
        </div>

        <div className="bg-slate-900/80 border border-amber-500/30 rounded-xl p-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-amber-300 flex items-center gap-1">
            <KeyRound className="w-3 h-3" /> Discovered Secret Keys
          </div>
          <div className="text-2xl font-extrabold text-amber-300 mt-1">
            {secretFindings.length}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            Hardcoded API keys, tokens & credentials
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-300">
            Attack Entrypoints
          </div>
          <div className="text-2xl font-extrabold text-emerald-400 mt-1">
            {endpoints.length}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            Routes, CLI & untrusted input handlers
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-cyan-300">
            PBOM Pipeline Controls
          </div>
          <div className="text-2xl font-extrabold text-cyan-400 mt-1">
            {pipelineChecks.filter((c) => c.status === "PASS").length}/
            {pipelineChecks.length || 6}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            CI/CD & supply-chain integrity checks
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-purple-300">
            Architecture Posture Grade
          </div>
          <div className="text-2xl font-extrabold text-purple-300 mt-1">
            {sastPlusSuite?.overall_maturity_grade || "B+"} (
            {sastPlusSuite?.maturity_score ?? 82}/100)
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            Automated CPG threat resilience score
          </div>
        </div>
      </div>

      {/* Sub-navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveSubTab("STRIDE_BOARD")}
            className={`px-3.5 py-2 rounded-lg text-xs font-bold flex items-center gap-2 transition-all border ${
              activeSubTab === "STRIDE_BOARD"
                ? "bg-rose-500/20 text-rose-200 border-rose-500/50"
                : "bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800"
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            STRIDE Threat Matrix ({strideThreats.length})
          </button>

          <button
            onClick={() => setActiveSubTab("SECRET_KEYS_VAULT")}
            className={`px-3.5 py-2 rounded-lg text-xs font-bold flex items-center gap-2 transition-all border ${
              activeSubTab === "SECRET_KEYS_VAULT"
                ? "bg-amber-500/20 text-amber-200 border-amber-500/50"
                : "bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800"
            }`}
          >
            <KeyRound className="w-3.5 h-3.5 text-amber-400" />
            Secret Keys & Credentials Vault ({secretFindings.length})
          </button>

          <button
            onClick={() => setActiveSubTab("TRUST_BOUNDARIES")}
            className={`px-3.5 py-2 rounded-lg text-xs font-bold flex items-center gap-2 transition-all border ${
              activeSubTab === "TRUST_BOUNDARIES"
                ? "bg-cyan-500/20 text-cyan-200 border-cyan-500/50"
                : "bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800"
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            Trust Boundary Architecture Map
          </button>

          <button
            onClick={() => setActiveSubTab("ENTRYPOINTS_PBOM")}
            className={`px-3.5 py-2 rounded-lg text-xs font-bold flex items-center gap-2 transition-all border ${
              activeSubTab === "ENTRYPOINTS_PBOM"
                ? "bg-emerald-500/20 text-emerald-200 border-emerald-500/50"
                : "bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800"
            }`}
          >
            <Compass className="w-3.5 h-3.5 text-emerald-400" />
            Attack Surface Entrypoints & PBOM ({endpoints.length})
          </button>
        </div>
      </div>

      {/* TAB 1: STRIDE THREAT MATRIX */}
      {activeSubTab === "STRIDE_BOARD" && (
        <div className="space-y-4">
          {/* Category Filter Pills */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-slate-400 flex items-center gap-1 mr-1">
              <Filter className="w-3.5 h-3.5" /> Filter STRIDE Category:
            </span>
            <button
              onClick={() => setSelectedStrideCategory("ALL")}
              className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-all ${
                selectedStrideCategory === "ALL"
                  ? "bg-amber-500/20 text-amber-300 border-amber-500/50"
                  : "bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200"
              }`}
            >
              All Categories ({strideThreats.length})
            </button>
            {Object.entries(STRIDE_META).map(([catKey, meta]) => {
              const count = strideThreats.filter(
                (t) => t.stride_category === catKey
              ).length;
              return (
                <button
                  key={catKey}
                  onClick={() => setSelectedStrideCategory(catKey)}
                  className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-all flex items-center gap-1.5 ${
                    selectedStrideCategory === catKey
                      ? meta.badgeBg
                      : "bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200"
                  }`}
                >
                  <span className="font-mono font-extrabold">
                    [{meta.letter}]
                  </span>
                  <span>{meta.label}</span>
                  <span className="text-[10px] opacity-80">({count})</span>
                </button>
              );
            })}
          </div>

          {/* STRIDE Threat Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {filteredStride.map((threat) => {
              const meta = STRIDE_META[threat.stride_category] || {
                letter: threat.stride_letter || "T",
                label: threat.stride_category,
                securityProperty: "Security Control",
                color: "text-amber-400",
                badgeBg: "bg-amber-500/15 border-amber-500/40 text-amber-300",
              };
              return (
                <div
                  key={threat.id}
                  className="bg-slate-900/90 border border-slate-800 hover:border-slate-700 rounded-xl p-5 flex flex-col justify-between gap-4 shadow-lg"
                >
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2.5">
                        <span
                          className={`w-8 h-8 rounded-lg border flex items-center justify-center font-mono text-sm font-black ${meta.badgeBg}`}
                        >
                          {meta.letter}
                        </span>
                        <div>
                          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                            {meta.label} • Violates {meta.securityProperty}
                          </div>
                          <h3 className="text-sm font-bold text-slate-100">
                            {threat.title}
                          </h3>
                        </div>
                      </div>

                      <div className="flex items-center gap-1.5 shrink-0">
                        <span
                          className={`px-2 py-0.5 text-[10px] font-bold rounded border ${
                            threat.status === "ACTION_REQUIRED"
                              ? "bg-red-500/20 text-red-300 border-red-500/40"
                              : threat.status === "MITIGATED"
                              ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                              : "bg-amber-500/20 text-amber-300 border-amber-500/40"
                          }`}
                        >
                          {threat.status.replace("_", " ")}
                        </span>
                        <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {threat.severity}
                        </span>
                      </div>
                    </div>

                    <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3 space-y-1.5">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-rose-300">
                        Attack Scenario & Exploit Vector
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {threat.threat_scenario}
                      </p>
                    </div>

                    <div className="bg-emerald-950/20 border border-emerald-500/25 rounded-lg p-3 space-y-1.5">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-300">
                        Architectural Mitigation Control
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {threat.mitigation_control}
                      </p>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] text-slate-400 font-semibold">
                        Affected Components:
                      </span>
                      {threat.affected_components.slice(0, 3).map((comp, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-amber-300 border border-slate-700"
                        >
                          {comp}
                        </span>
                      ))}
                    </div>

                    {threat.linked_finding_ids.length > 0 && (
                      <button
                        onClick={() =>
                          handleInspectFindingInIde(threat.linked_finding_ids[0])
                        }
                        className="px-2.5 py-1 rounded-lg text-[11px] font-bold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 flex items-center gap-1 transition-all"
                      >
                        <Code2 className="w-3 h-3" />
                        Inspect Linked Code Flaw ({threat.linked_finding_ids.length})
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 2: SECRET KEYS & CREDENTIALS VAULT */}
      {activeSubTab === "SECRET_KEYS_VAULT" && (
        <div className="space-y-4">
          <div className="bg-amber-950/20 border border-amber-500/40 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <KeyRound className="w-6 h-6 text-amber-400 shrink-0" />
              <div>
                <h2 className="text-sm font-bold text-amber-200">
                  Deep Secret Keys, API Tokens & Cryptographic Credentials Inspector
                </h2>
                <p className="text-xs text-slate-300 mt-0.5">
                  Instead of generic runtime reachability badges, ALASTOR extracts the exact hardcoded secret key identifier, credential classification, Shannon entropy score, and masked/revealable value.
                </p>
              </div>
            </div>
            <div className="text-xs font-mono px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300">
              RBAC Secret Reveal Permission:{" "}
              <span
                className={
                  canRevealSecrets
                    ? "text-emerald-400 font-bold"
                    : "text-red-400 font-bold"
                }
              >
                {canRevealSecrets ? "AUTHORIZED" : "RESTRICTED (MASKED ONLY)"}
              </span>
            </div>
          </div>

          {secretFindings.length === 0 ? (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-8 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <div className="text-sm font-bold text-slate-200">
                No Hardcoded Secret Keys Detected in Active Scan
              </div>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                All scanned source files, environment templates, and manifests passed hardcoded credential and high-entropy secret key checks.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {secretFindings.map((sf) => {
                const node = sf.path_nodes?.[0];
                const isRevealed = !!revealedSecretIds[sf.id];
                const keyName = sf.secret_key_name || node?.name || "SECRET_KEY";
                const maskedVal =
                  sf.secret_value_masked || "REDACTED_SECRET_VALUE";
                const rawVal = sf.secret_value_raw || maskedVal;
                const displayVal = isRevealed ? rawVal : maskedVal;

                return (
                  <div
                    key={sf.id}
                    className="bg-slate-900/90 border border-amber-500/35 hover:border-amber-400/60 rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-md"
                  >
                    <div className="space-y-2 flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="px-2 py-0.5 text-[10px] font-mono font-extrabold rounded bg-red-500/20 text-red-300 border border-red-500/40">
                          {sf.severity}
                        </span>
                        <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 flex items-center gap-1">
                          <KeyRound className="w-3 h-3" />
                          {sf.secret_type || "Hardcoded Secret Key"}
                        </span>
                        {sf.secret_entropy && (
                          <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-cyan-300 border border-slate-700">
                            Entropy: {sf.secret_entropy} bits/char
                          </span>
                        )}
                        <span className="text-xs font-mono text-slate-400 truncate">
                          {node?.filepath}:{node?.start_line}
                        </span>
                      </div>

                      <div className="text-sm font-bold text-slate-100">
                        {sf.title}
                      </div>

                      {/* Key Name + Value Box */}
                      <div className="flex flex-wrap items-center gap-2 bg-slate-950 border border-amber-500/30 rounded-lg px-3 py-2 font-mono text-xs">
                        <span className="text-amber-400 font-bold">
                          🔑 {keyName}
                        </span>
                        <span className="text-slate-500">=</span>
                        <span
                          className={`px-2 py-0.5 rounded ${
                            isRevealed
                              ? "bg-red-950/60 text-red-200 border border-red-500/40"
                              : "bg-slate-900 text-amber-200"
                          } break-all`}
                        >
                          {displayVal}
                        </span>

                        {canRevealSecrets && (
                          <button
                            onClick={() => toggleRevealSecret(sf.id)}
                            className="ml-auto px-2 py-1 rounded text-[10px] font-sans font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1"
                            title={
                              isRevealed
                                ? "Mask Secret Key Value"
                                : "Reveal Raw Secret Key Value"
                            }
                          >
                            {isRevealed ? (
                              <>
                                <EyeOff className="w-3 h-3 text-amber-400" /> Mask
                              </>
                            ) : (
                              <>
                                <Eye className="w-3 h-3 text-amber-400" /> Reveal Key
                              </>
                            )}
                          </button>
                        )}

                        <button
                          onClick={() =>
                            handleCopySecret(
                              sf.id,
                              `${keyName}=${displayVal}`
                            )
                          }
                          className="px-2 py-1 rounded text-[10px] font-sans font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1"
                        >
                          {copiedId === sf.id ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" /> Copied
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" /> Copy
                            </>
                          )}
                        </button>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => {
                          selectFinding(sf);
                          setWorkspaceViewMode("REMEDIATION_IDE");
                        }}
                        className="px-3 py-2 rounded-lg text-xs font-bold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 flex items-center gap-1.5 transition-all"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        Locate Key in Code
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: TRUST BOUNDARY ARCHITECTURE MAP */}
      {activeSubTab === "TRUST_BOUNDARIES" && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-slate-100">
                Four-Tier Trust Boundary & Taint Propagation Architecture
              </h2>
              <p className="text-xs text-slate-400">
                Visualizes how untrusted external inputs cross trust boundaries into application entrypoints, call graph logic, and sensitive sinks/secrets.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-stretch">
            {/* Zone 1 */}
            <div className="rounded-xl border-2 border-dashed border-rose-500/40 bg-rose-950/10 p-4 flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                    TRUST ZONE 0 • UNTRUSTED
                  </span>
                  <Globe className="w-4 h-4 text-rose-400" />
                </div>
                <h3 className="text-sm font-bold text-slate-100">
                  External Actors & Untrusted Inputs
                </h3>
                <p className="text-xs text-slate-400">
                  HTTP requests, CLI flags, webhook payloads, BGP/network packets, and third-party registries.
                </p>
              </div>
              <div className="space-y-1.5 text-xs font-mono text-rose-300 bg-slate-950/80 p-2.5 rounded-lg border border-slate-800">
                <div>• HTTP Query / Body Params</div>
                <div>• CLI argv / Env Overrides</div>
                <div>• External Package Tarballs</div>
              </div>
            </div>

            {/* Zone 2 */}
            <div className="rounded-xl border-2 border-emerald-500/40 bg-emerald-950/10 p-4 flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                    TRUST BOUNDARY 1 • INGRESS
                  </span>
                  <Compass className="w-4 h-4 text-emerald-400" />
                </div>
                <h3 className="text-sm font-bold text-slate-100">
                  Attack Surface Entrypoints ({endpoints.length})
                </h3>
                <p className="text-xs text-slate-400">
                  API routes, controller handlers, and daemon command parsers discovered in the codebase.
                </p>
              </div>
              <button
                onClick={() => {
                  setWorkspaceViewMode("REMEDIATION_IDE");
                  setGraphViewMode("ENTRYPOINT_GRAPH");
                  setIdeLayoutMode("SPLIT_BOTH");
                }}
                className="w-full py-2 px-3 rounded-lg text-xs font-bold bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 flex items-center justify-center gap-1.5"
              >
                Open Entry Points Graph <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Zone 3 */}
            <div className="rounded-xl border-2 border-purple-500/40 bg-purple-950/10 p-4 flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                    TRUST ZONE 2 • CORE LOGIC
                  </span>
                  <Server className="w-4 h-4 text-purple-400" />
                </div>
                <h3 className="text-sm font-bold text-slate-100">
                  Inter-Procedural Call Graph
                </h3>
                <p className="text-xs text-slate-400">
                  Internal function invocations (`:CALLS`), business logic, and sanitizer checkpoints.
                </p>
              </div>
              <button
                onClick={() => {
                  setWorkspaceViewMode("REMEDIATION_IDE");
                  setGraphViewMode("CALL_GRAPH");
                  setIdeLayoutMode("SPLIT_BOTH");
                }}
                className="w-full py-2 px-3 rounded-lg text-xs font-bold bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40 flex items-center justify-center gap-1.5"
              >
                Open Call Graph <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Zone 4 */}
            <div className="rounded-xl border-2 border-amber-500/40 bg-amber-950/10 p-4 flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                    TRUST ZONE 3 • CROWN JEWELS
                  </span>
                  <Database className="w-4 h-4 text-amber-400" />
                </div>
                <h3 className="text-sm font-bold text-slate-100">
                  High-Privilege Sinks & Secret Keys
                </h3>
                <p className="text-xs text-slate-400">
                  OS shell execution, SQL stores, filesystem writes, and {secretFindings.length} discovered secret keys.
                </p>
              </div>
              <button
                onClick={() => setActiveSubTab("SECRET_KEYS_VAULT")}
                className="w-full py-2 px-3 rounded-lg text-xs font-bold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 flex items-center justify-center gap-1.5"
              >
                Inspect {secretFindings.length} Secret Keys <KeyRound className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: ATTACK SURFACE ENTRYPOINTS & PBOM */}
      {activeSubTab === "ENTRYPOINTS_PBOM" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Entrypoints Table */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Compass className="w-4 h-4 text-emerald-400" />
                Discovered Attack Surface Entrypoints ({endpoints.length})
              </h3>
              <button
                onClick={() => {
                  setWorkspaceViewMode("REMEDIATION_IDE");
                  setGraphViewMode("ENTRYPOINT_GRAPH");
                }}
                className="text-xs font-bold text-emerald-400 hover:underline"
              >
                Visualize in Graph →
              </button>
            </div>
            <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
              {endpoints.map((ep) => (
                <div
                  key={ep.id}
                  className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 flex items-center justify-between gap-3"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                        {ep.method}
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-100 truncate">
                        {ep.route_path}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1 truncate">
                      Handler: <span className="font-mono text-slate-300">{ep.handler_name}</span> • {ep.filepath}:{ep.line_number}
                    </div>
                  </div>
                  <span
                    className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded shrink-0 ${
                      ep.exposure_level === "HIGH_EXPOSURE"
                        ? "bg-red-500/20 text-red-300 border border-red-500/40"
                        : "bg-slate-800 text-slate-300 border border-slate-700"
                    }`}
                  >
                    {ep.auth_posture}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* PBOM Checks */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              Pipeline Bill of Materials (PBOM) & Supply-Chain Posture
            </h3>
            <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
              {pipelineChecks.map((chk) => (
                <div
                  key={chk.id}
                  className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-100">
                      {chk.title}
                    </span>
                    <span
                      className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
                        chk.status === "PASS"
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                          : chk.status === "WARNING"
                          ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                          : "bg-red-500/20 text-red-300 border border-red-500/40"
                      }`}
                    >
                      {chk.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{chk.details}</p>
                  <div className="text-[11px] text-cyan-300/90 font-mono">
                    Remediation: {chk.remediation}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
