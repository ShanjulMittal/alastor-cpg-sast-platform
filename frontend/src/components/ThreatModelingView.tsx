"use client";

import React, { useEffect, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { StrideThreatItem } from "@/types/cpg";
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
  Copy,
  Check,
  XCircle,
  Wrench,
  FileCode,
  ExternalLink,
} from "lucide-react";

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

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
    openCodeLocationInIde,
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
  const [statusFilter, setStatusFilter] = useState<"ALL" | "FAIL_ONLY" | "PASS_ONLY">("ALL");
  const [revealedSecretIds, setRevealedSecretIds] = useState<
    Record<string, boolean>
  >({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [inlinePreviewThreatId, setInlinePreviewThreatId] = useState<string | null>(null);
  const [inlineCodeLines, setInlineCodeLines] = useState<string[]>([]);
  const [inlineCodeMeta, setInlineCodeMeta] = useState<{ filepath: string; line: number }>({
    filepath: "",
    line: 1,
  });
  const [loadingPreview, setLoadingPreview] = useState<boolean>(false);

  // Always keep Threat Model synchronized with the active project and findings list
  useEffect(() => {
    fetchSastPlusSuite();
  }, [projectPath, findings.length, fetchSastPlusSuite]);

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

  const filteredStride = strideThreats.filter((t) => {
    if (selectedStrideCategory !== "ALL" && t.stride_category !== selectedStrideCategory) {
      return false;
    }
    if (statusFilter === "FAIL_ONLY" && t.status === "MITIGATED") {
      return false;
    }
    if (statusFilter === "PASS_ONLY" && t.status !== "MITIGATED") {
      return false;
    }
    return true;
  });

  const passedStrideCount = strideThreats.filter((t) => t.status === "MITIGATED").length;
  const actionStrideCount = strideThreats.filter((t) => t.status !== "MITIGATED").length;
  const totalChecksSum = strideThreats.reduce(
    (acc, t) => acc + (t.total_checks_count ?? (t.ok_count || 1) + (t.issue_count || 0)),
    0
  );
  const totalOkSum = strideThreats.reduce(
    (acc, t) => acc + (t.ok_count ?? (t.what_passed?.length || 1)),
    0
  );
  const totalIssueSum = strideThreats.reduce(
    (acc, t) => acc + (t.issue_count ?? (t.status === "MITIGATED" ? 0 : t.linked_finding_ids?.length || 1)),
    0
  );
  const totalObsSum = strideThreats.reduce(
    (acc, t) => acc + (t.observations?.length ?? t.observations_count ?? 0),
    0
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

  const handleInspectThreatCode = (threat: StrideThreatItem) => {
    const firstFindingId =
      threat.linked_finding_ids && threat.linked_finding_ids.length > 0
        ? threat.linked_finding_ids[0]
        : undefined;
    const primaryFp =
      threat.primary_filepath ||
      (threat.affected_components && threat.affected_components.length > 0
        ? threat.affected_components[0]
        : undefined);
    const primaryLn = threat.primary_line || 1;
    openCodeLocationInIde(primaryFp, primaryLn, firstFindingId);
  };

  const handleToggleInlinePreview = async (threat: StrideThreatItem) => {
    if (inlinePreviewThreatId === threat.id) {
      setInlinePreviewThreatId(null);
      return;
    }
    setInlinePreviewThreatId(threat.id);
    const rawFp =
      threat.primary_filepath ||
      (threat.affected_components && threat.affected_components[0]) ||
      "";
    const cleanFp = rawFp.replace(/\s*\(.*\)$/, "").split(":")[0].trim();
    const targetLn = threat.primary_line || 1;
    setInlineCodeMeta({ filepath: cleanFp || "workspace", line: targetLn });

    if (!cleanFp) {
      setInlineCodeLines([threat.code_snippet || "// No source file linked"]);
      return;
    }

    setLoadingPreview(true);
    try {
      const res = await fetch(
        `${BACKEND_URL}/api/file?path=${encodeURIComponent(cleanFp)}`
      );
      if (res.ok) {
        const data = await res.json();
        const allLines = (data.content || "").split(/\r?\n/);
        const startIdx = Math.max(0, targetLn - 6);
        const endIdx = Math.min(allLines.length, targetLn + 8);
        const slice = allLines.slice(startIdx, endIdx).map((l: string, i: number) => {
          const lnNum = startIdx + i + 1;
          const marker = lnNum === targetLn ? ">> " : "   ";
          return `${marker}${String(lnNum).padStart(4, " ")} | ${l}`;
        });
        setInlineCodeLines(
          slice.length > 0
            ? slice
            : [threat.code_snippet || "// File is empty"]
        );
      } else {
        setInlineCodeLines([
          threat.code_snippet || `// Source snippet at ${cleanFp}:${targetLn}`,
        ]);
      }
    } catch {
      setInlineCodeLines([
        threat.code_snippet || `// Source snippet at ${cleanFp}:${targetLn}`,
      ]);
    } finally {
      setLoadingPreview(false);
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
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-lg font-extrabold tracking-tight text-slate-100">
                Architectural Threat Modeling, Pass/Fail Verdict & Corrective Action Dossier
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                STRIDE + Pass/Fail Rationale + Risk + Corrective Actions
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Complete architectural threat breakdown explaining{" "}
              <span className="text-emerald-300 font-semibold">what passed</span>,{" "}
              <span className="text-rose-300 font-semibold">what failed</span>,{" "}
              <span className="text-amber-300 font-semibold">why it is or is not an issue</span>,{" "}
              <span className="text-cyan-300 font-semibold">business/technical risk</span>, and{" "}
              <span className="text-purple-300 font-semibold">step-by-step corrective actions</span>{" "}
              for{" "}
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
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <div className="bg-slate-900/80 border border-emerald-500/30 rounded-xl p-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-300 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> What is OK (Total Count)
          </div>
          <div className="text-2xl font-extrabold text-emerald-400 mt-1">
            {totalOkSum}{" "}
            <span className="text-xs font-mono text-emerald-300/80">
              / {totalChecksSum} Checks
            </span>
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            {passedStrideCount}/6 STRIDE Categories 100% OK
          </div>
        </div>

        <div className="bg-slate-900/80 border border-rose-500/30 rounded-xl p-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-rose-300 flex items-center gap-1">
            <XCircle className="w-3 h-3" /> What is the Issue (Count)
          </div>
          <div className="text-2xl font-extrabold text-rose-400 mt-1">
            {totalIssueSum}{" "}
            <span className="text-xs font-mono text-rose-300/80">
              Issues
            </span>
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            Across {actionStrideCount}/6 STRIDE Categories
          </div>
        </div>

        <div className="bg-slate-900/80 border border-cyan-500/30 rounded-xl p-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-1">
            <FileCode className="w-3 h-3" /> Recorded Observations
          </div>
          <div className="text-2xl font-extrabold text-cyan-400 mt-1">
            {totalObsSum}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            File:line OK &amp; Issue evidence items
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
            Hardcoded keys &amp; tokens ({endpoints.length} entrypoints)
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-cyan-300">
            PBOM Pipeline Controls
          </div>
          <div className="text-2xl font-extrabold text-cyan-400 mt-1">
            {pipelineChecks.filter((c) => c.status === "PASS").length}/
            {pipelineChecks.length || 5}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            Supply-chain checks passed
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-purple-300">
            Architecture Posture Grade
          </div>
          <div className="text-xl font-extrabold text-purple-300 mt-1 truncate">
            {sastPlusSuite?.overall_maturity_grade || "B+"} (
            {sastPlusSuite?.maturity_score ?? 82}%)
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            Resilience score
          </div>
        </div>
      </div>

      {/* Sub-navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setActiveSubTab("STRIDE_BOARD")}
            className={`px-3.5 py-2 rounded-lg text-xs font-bold flex items-center gap-2 transition-all border ${
              activeSubTab === "STRIDE_BOARD"
                ? "bg-rose-500/20 text-rose-200 border-rose-500/50"
                : "bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800"
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Detailed STRIDE Threat Dossier ({strideThreats.length})
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

      {/* TAB 1: DETAILED STRIDE THREAT MATRIX */}
      {activeSubTab === "STRIDE_BOARD" && (
        <div className="space-y-5">
          {/* STRIDE Framework Executive Summary & Count Matrix Table (What is OK vs What is the Issue) */}
          <div className="bg-slate-900/95 border border-slate-800 rounded-xl p-4 space-y-3 shadow-xl">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-extrabold text-slate-100 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>
                    STRIDE Framework Executive Count &amp; Verdict Matrix — What is OK vs. What is the Issue
                  </span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Per-category STRIDE breakdown showing exact inspected check counts,{" "}
                  <span className="text-emerald-300 font-semibold">✔ What is OK (Passed Count)</span>,{" "}
                  <span className="text-rose-300 font-semibold">✖ What is the Issue (Failed Count)</span>, and{" "}
                  <span className="text-cyan-300 font-semibold">Recorded Observations</span>.
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="px-2.5 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 font-bold">
                  ✔ Total OK: {totalOkSum}
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-rose-500/15 border border-rose-500/40 text-rose-300 font-bold">
                  ✖ Total Issues: {totalIssueSum}
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 font-bold">
                  Observations: {totalObsSum}
                </span>
              </div>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-950 text-slate-300 border-b border-slate-800 text-[10px] uppercase tracking-wider font-extrabold">
                    <th className="py-2.5 px-3">STRIDE Category &amp; Property</th>
                    <th className="py-2.5 px-3 text-center">Total Checks</th>
                    <th className="py-2.5 px-3 text-center text-emerald-300">✔ OK Count</th>
                    <th className="py-2.5 px-3 text-center text-rose-300">✖ Issue Count</th>
                    <th className="py-2.5 px-3 text-center text-cyan-300">Observations</th>
                    <th className="py-2.5 px-3">✔ What is OK (Verified Safe)</th>
                    <th className="py-2.5 px-3">✖ What is the Issue (Detected Flaws)</th>
                    <th className="py-2.5 px-3 text-center">STRIDE Verdict</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {strideThreats.map((st) => {
                    const m = STRIDE_META[st.stride_category] || {
                      letter: st.stride_letter || "T",
                      label: st.stride_category,
                      securityProperty: st.security_property || "Security Control",
                      color: "text-amber-400",
                      badgeBg: "bg-amber-500/15 border-amber-500/40 text-amber-300",
                    };
                    const okC = st.ok_count ?? (st.what_passed?.length || 1);
                    const issC = st.issue_count ?? (st.status === "MITIGATED" ? 0 : st.linked_finding_ids?.length || 1);
                    const totC = st.total_checks_count ?? okC + issC;
                    const obsC = st.observations?.length ?? st.observations_count ?? 0;
                    const isOk = issC === 0 && st.status === "MITIGATED";
                    return (
                      <tr
                        key={st.id}
                        className={`transition-colors ${
                          isOk ? "bg-slate-900/40 hover:bg-slate-900/80" : "bg-rose-950/10 hover:bg-rose-950/20"
                        }`}
                      >
                        <td className="py-2.5 px-3">
                          <div className="flex items-center gap-2">
                            <span className={`w-7 h-7 rounded-lg border flex items-center justify-center font-mono font-black text-xs shrink-0 ${m.badgeBg}`}>
                              {m.letter}
                            </span>
                            <div>
                              <div className="font-bold text-slate-100">{m.label}</div>
                              <div className="text-[10px] text-slate-400">{st.security_property || m.securityProperty}</div>
                            </div>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 text-center font-mono font-bold text-slate-200">
                          {totC}
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-mono font-extrabold">
                            ✔ {okC} OK
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span
                            className={`px-2 py-0.5 rounded font-mono font-extrabold border ${
                              issC > 0
                                ? "bg-rose-500/20 text-rose-300 border-rose-500/50"
                                : "bg-slate-800/80 text-emerald-400 border-slate-700"
                            }`}
                          >
                            {issC > 0 ? `✖ ${issC} Issue${issC > 1 ? "s" : ""}` : "0 Issues"}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 font-mono font-bold">
                            {obsC} Obs
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-emerald-200/90 max-w-xs">
                          {st.ok_summary || st.what_passed?.[0] || "Controls verified OK."}
                        </td>
                        <td className={`py-2.5 px-3 max-w-xs ${issC > 0 ? "text-rose-200 font-medium" : "text-slate-400"}`}>
                          {st.issue_summary || (issC > 0 ? st.what_failed?.[0] : "0 Issues — All checks OK.")}
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span
                            className={`px-2 py-1 rounded-md text-[10px] font-mono font-extrabold border inline-flex items-center gap-1 ${
                              isOk
                                ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/50"
                                : "bg-rose-500/20 text-rose-300 border-rose-500/50"
                            }`}
                          >
                            {isOk ? "✔ OK (PASS)" : `✖ ISSUE (${st.severity})`}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              type="button"
                              onClick={() => setSelectedStrideCategory(st.stride_category)}
                              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[10px] font-bold"
                            >
                              Focus [{m.letter}]
                            </button>
                            <button
                              type="button"
                              onClick={() => handleInspectThreatCode(st)}
                              className="px-2 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-[10px] font-bold flex items-center gap-1"
                            >
                              <Code2 className="w-3 h-3" />
                              Inspect
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
                <tfoot>
                  <tr className="bg-slate-950 border-t-2 border-slate-700 font-mono text-xs font-extrabold text-slate-100">
                    <td className="py-2.5 px-3">TOTAL ACROSS ALL 6 STRIDE DOMAINS</td>
                    <td className="py-2.5 px-3 text-center">{totalChecksSum} Checks</td>
                    <td className="py-2.5 px-3 text-center text-emerald-400">✔ {totalOkSum} OK</td>
                    <td className="py-2.5 px-3 text-center text-rose-400">✖ {totalIssueSum} Issues</td>
                    <td className="py-2.5 px-3 text-center text-cyan-300">{totalObsSum} Observations</td>
                    <td className="py-2.5 px-3 text-emerald-300 font-sans text-[11px]">
                      {passedStrideCount} of 6 STRIDE categories 100% OK
                    </td>
                    <td className="py-2.5 px-3 text-rose-300 font-sans text-[11px]">
                      {actionStrideCount} of 6 STRIDE categories have active issues
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      {actionStrideCount === 0 ? "✔ ALL OK" : `${actionStrideCount} ACTION REQ`}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedStrideCategory("ALL");
                          setStatusFilter("ALL");
                        }}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[10px]"
                      >
                        Show All 6
                      </button>
                    </td>
                  </tr>
                </tfoot>
              </table>
            </div>
          </div>

          {/* Category & Verdict Filter Pills */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/60 border border-slate-800/80 rounded-xl p-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs font-semibold text-slate-400 flex items-center gap-1 mr-1">
                <Filter className="w-3.5 h-3.5" /> STRIDE Vector:
              </span>
              <button
                onClick={() => setSelectedStrideCategory("ALL")}
                className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-all ${
                  selectedStrideCategory === "ALL"
                    ? "bg-amber-500/20 text-amber-300 border-amber-500/50"
                    : "bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200"
                }`}
              >
                All 6 STRIDE ({totalOkSum} OK / {totalIssueSum} Issues)
              </button>
              {Object.entries(STRIDE_META).map(([catKey, meta]) => {
                const matchThreat = strideThreats.find(
                  (t) => t.stride_category === catKey
                );
                const okC = matchThreat?.ok_count ?? 1;
                const issC = matchThreat?.issue_count ?? 0;
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
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-950/80 text-emerald-300">
                      ✔{okC}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        issC > 0
                          ? "bg-rose-500/30 text-rose-200 font-extrabold"
                          : "bg-slate-950/60 text-slate-400"
                      }`}
                    >
                      ✖{issC}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Pass vs Fail Verdict Filter */}
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setStatusFilter("ALL")}
                className={`px-2.5 py-1 rounded-md text-xs font-bold border ${
                  statusFilter === "ALL"
                    ? "bg-slate-800 text-white border-slate-600"
                    : "bg-slate-950 text-slate-400 border-slate-800"
                }`}
              >
                All Verdicts (6)
              </button>
              <button
                onClick={() => setStatusFilter("FAIL_ONLY")}
                className={`px-2.5 py-1 rounded-md text-xs font-bold border flex items-center gap-1 ${
                  statusFilter === "FAIL_ONLY"
                    ? "bg-rose-500/20 text-rose-300 border-rose-500/50"
                    : "bg-slate-950 text-slate-400 border-slate-800"
                }`}
              >
                <XCircle className="w-3 h-3 text-rose-400" />
                Has Issues ({actionStrideCount})
              </button>
              <button
                onClick={() => setStatusFilter("PASS_ONLY")}
                className={`px-2.5 py-1 rounded-md text-xs font-bold border flex items-center gap-1 ${
                  statusFilter === "PASS_ONLY"
                    ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/50"
                    : "bg-slate-950 text-slate-400 border-slate-800"
                }`}
              >
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                100% OK ({passedStrideCount})
              </button>
            </div>
          </div>

          {/* Detailed STRIDE Threat Dossier Cards */}
          <div className="grid grid-cols-1 gap-5">
            {filteredStride.map((threat) => {
              const meta = STRIDE_META[threat.stride_category] || {
                letter: threat.stride_letter || "T",
                label: threat.stride_category,
                securityProperty: "Security Control",
                color: "text-amber-400",
                badgeBg: "bg-amber-500/15 border-amber-500/40 text-amber-300",
              };
              const isPassed = threat.status === "MITIGATED";
              const primaryFp =
                threat.primary_filepath ||
                threat.affected_components?.[0] ||
                "workspace";
              const primaryLn = threat.primary_line || 1;
              const okCount = threat.ok_count ?? (threat.what_passed?.length || 1);
              const issueCount =
                threat.issue_count ??
                (isPassed ? 0 : threat.linked_finding_ids?.length || 1);
              const totalCount = threat.total_checks_count ?? okCount + issueCount;
              const obsList = threat.observations || [];
              const issueObsCount = obsList.filter((o) => o.verdict === "ISSUE").length;
              const okObsCount = obsList.filter((o) => o.verdict === "OK").length;

              const whatPassedList =
                threat.what_passed && threat.what_passed.length > 0
                  ? threat.what_passed
                  : [
                      "Automated CPG AST, CFG, and DFG inspection completed for this category.",
                    ];
              const whatFailedList =
                threat.what_failed && threat.what_failed.length > 0
                  ? threat.what_failed
                  : isPassed
                  ? [
                      "0 Issues Detected — All inspected components passed verification (100% OK).",
                    ]
                  : [threat.threat_scenario];
              const whyText =
                threat.why_issue_or_not ||
                (isPassed
                  ? `PASS RATIONALE: ${threat.threat_scenario}`
                  : `ISSUE RATIONALE: ${threat.threat_scenario}`);
              const riskText =
                threat.risk_impact ||
                `Violates ${meta.securityProperty}. ${threat.threat_scenario}`;
              const correctiveSteps =
                threat.corrective_actions &&
                threat.corrective_actions.length > 0
                  ? threat.corrective_actions
                  : [threat.mitigation_control];

              return (
                <div
                  key={threat.id}
                  className={`bg-slate-900/95 border rounded-xl p-5 space-y-4 shadow-lg transition-all ${
                    isPassed
                      ? "border-emerald-500/30 hover:border-emerald-500/50"
                      : "border-rose-500/40 hover:border-rose-500/60"
                  }`}
                >
                  {/* Top Row: STRIDE Badge, Title, Count Pills, Verdict Status & Severity */}
                  <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800/90 pb-3.5">
                    <div className="flex items-start gap-3">
                      <span
                        className={`w-10 h-10 rounded-xl border flex items-center justify-center font-mono text-base font-black shrink-0 ${meta.badgeBg}`}
                      >
                        {meta.letter}
                      </span>
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                            STRIDE [{meta.letter}] • {meta.label} • Security Property:{" "}
                            <span className="text-slate-200">
                              {threat.security_property || meta.securityProperty}
                            </span>
                          </span>
                          {threat.compliance_mapping && (
                            <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800/90 text-cyan-300 border border-slate-700">
                              {threat.compliance_mapping}
                            </span>
                          )}
                        </div>
                        <h3 className="text-base font-extrabold text-slate-100 mt-1">
                          {threat.title}
                        </h3>
                      </div>
                    </div>

                    {/* Explicit Count Details & Verdict Pills */}
                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      <span className="px-2.5 py-1 text-xs font-mono font-bold rounded-lg bg-slate-950 text-slate-200 border border-slate-700">
                        Total Inspected: {totalCount}
                      </span>
                      <span className="px-2.5 py-1 text-xs font-mono font-extrabold rounded-lg bg-emerald-500/20 text-emerald-300 border border-emerald-500/50">
                        ✔ OK Count: {okCount}
                      </span>
                      <span
                        className={`px-2.5 py-1 text-xs font-mono font-extrabold rounded-lg border ${
                          issueCount > 0
                            ? "bg-rose-500/20 text-rose-300 border-rose-500/50"
                            : "bg-slate-800 text-emerald-300 border-slate-700"
                        }`}
                      >
                        ✖ Issue Count: {issueCount}
                      </span>
                      <span className="px-2.5 py-1 text-xs font-mono font-bold rounded-lg bg-cyan-500/15 text-cyan-300 border border-cyan-500/40">
                        Observations: {obsList.length}
                      </span>

                      {/* Pass / Fail Verdict Pill */}
                      <span
                        className={`px-2.5 py-1 text-xs font-extrabold rounded-lg border flex items-center gap-1.5 ${
                          isPassed
                            ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/50"
                            : "bg-red-500/20 text-red-300 border-red-500/50"
                        }`}
                      >
                        {isPassed ? (
                          <>
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                            {threat.verdict_label || `OK • ALL ${okCount} PASSED`}
                          </>
                        ) : (
                          <>
                            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                            {threat.verdict_label || `ISSUE • ${issueCount} FAILED`}
                          </>
                        )}
                      </span>
                    </div>
                  </div>

                  {/* Section 1: What is OK vs. What is the Issue (2-Column Comparison with Counts) */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                    {/* What is OK */}
                    <div className="bg-emerald-950/15 border border-emerald-500/30 rounded-xl p-3.5 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <div className="text-xs font-extrabold uppercase tracking-wider text-emerald-300 flex items-center gap-1.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                          ✔ What is OK as per STRIDE [{meta.letter}] (Verified Safe Controls)
                        </div>
                        <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[11px] font-bold">
                          {okCount} OK / Passed
                        </span>
                      </div>
                      <ul className="space-y-1.5 text-xs text-slate-200">
                        {whatPassedList.map((item, i) => (
                          <li key={i} className="flex items-start gap-2 leading-relaxed">
                            <span className="text-emerald-400 font-bold shrink-0">✔</span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* What is the Issue */}
                    <div
                      className={`rounded-xl p-3.5 space-y-2 border ${
                        isPassed
                          ? "bg-slate-950/60 border-slate-800"
                          : "bg-rose-950/20 border-rose-500/40"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div
                          className={`text-xs font-extrabold uppercase tracking-wider flex items-center gap-1.5 ${
                            isPassed ? "text-emerald-300" : "text-rose-300"
                          }`}
                        >
                          {isPassed ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                          ) : (
                            <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                          )}
                          ✖ What is the Issue as per STRIDE [{meta.letter}] (Detected Flaws &amp; Gaps)
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold ${
                            issueCount > 0
                              ? "bg-rose-500/25 text-rose-200 border border-rose-500/40"
                              : "bg-emerald-500/15 text-emerald-300"
                          }`}
                        >
                          {issueCount} Issue{issueCount === 1 ? "" : "s"}
                        </span>
                      </div>
                      <ul className="space-y-1.5 text-xs text-slate-200">
                        {whatFailedList.map((item, i) => (
                          <li key={i} className="flex items-start gap-2 leading-relaxed">
                            <span
                              className={`font-bold shrink-0 ${
                                isPassed ? "text-emerald-400" : "text-rose-400"
                              }`}
                            >
                              {isPassed ? "✔" : "✖"}
                            </span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* Section 2: Detailed STRIDE Observations Breakdown (Issues & Verified-OK Evidence) */}
                  {obsList.length > 0 && (
                    <div className="bg-slate-950/90 border border-slate-800 rounded-xl p-4 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="text-xs font-extrabold uppercase tracking-wider text-cyan-300 flex items-center gap-2">
                          <FileCode className="w-4 h-4 text-cyan-400" />
                          <span>
                            Detailed STRIDE [{meta.letter}] Observations Breakdown ({obsList.length} Observations:{" "}
                            <span className="text-rose-300">{issueObsCount} Issue(s)</span> •{" "}
                            <span className="text-emerald-300">{okObsCount} Verified OK</span>)
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-400">
                          Click <strong className="text-amber-300">Inspect Code</strong> on any observation to jump to its exact file &amp; line in the IDE
                        </span>
                      </div>

                      <div className="space-y-2.5">
                        {obsList.map((obs, oIdx) => {
                          const isObsIssue = obs.verdict === "ISSUE";
                          return (
                            <div
                              key={obs.id || oIdx}
                              className={`rounded-xl p-3.5 border space-y-2 ${
                                isObsIssue
                                  ? "bg-rose-950/20 border-rose-500/40"
                                  : "bg-emerald-950/10 border-emerald-500/30"
                              }`}
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px] font-mono text-slate-300">
                                    Obs #{oIdx + 1}
                                  </span>
                                  <span
                                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-extrabold border ${
                                      isObsIssue
                                        ? "bg-rose-500/25 text-rose-200 border-rose-500/50"
                                        : "bg-emerald-500/20 text-emerald-300 border-emerald-500/50"
                                    }`}
                                  >
                                    {isObsIssue
                                      ? `✖ ISSUE DETECTED • ${obs.severity}`
                                      : "✔ OK • CONTROL VERIFIED"}
                                  </span>
                                  <span className="px-2 py-0.5 rounded bg-slate-900 text-cyan-300 border border-slate-800 text-[10px] font-mono">
                                    {obs.control_domain}
                                  </span>
                                  {obs.cwe_or_standard && (
                                    <span className="px-2 py-0.5 rounded bg-slate-900 text-purple-300 border border-slate-800 text-[10px] font-mono">
                                      {obs.cwe_or_standard}
                                    </span>
                                  )}
                                  <span className="text-xs font-mono font-bold text-amber-300">
                                    {obs.filepath}:{obs.line}
                                  </span>
                                </div>

                                <button
                                  type="button"
                                  onClick={() =>
                                    openCodeLocationInIde(
                                      obs.filepath,
                                      obs.line || 1,
                                      obs.linked_finding_id || undefined
                                    )
                                  }
                                  className="px-2.5 py-1 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-[11px] font-bold flex items-center gap-1 cursor-pointer shrink-0"
                                >
                                  <Code2 className="w-3 h-3" />
                                  Inspect Code ({obs.filepath}:{obs.line})
                                </button>
                              </div>

                              <div className="text-xs font-bold text-slate-100">
                                {obs.title}
                              </div>

                              {obs.code_snippet && (
                                <pre className="text-[11px] font-mono text-amber-200 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 overflow-x-auto">
                                  {obs.filepath}:{obs.line} → {obs.code_snippet}
                                </pre>
                              )}

                              <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
                                <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-2.5">
                                  <span
                                    className={`font-bold ${
                                      isObsIssue ? "text-rose-300" : "text-emerald-300"
                                    }`}
                                  >
                                    {isObsIssue ? "Why This is an Issue: " : "Why This is OK: "}
                                  </span>
                                  <span className="text-slate-200">{obs.why_ok_or_issue}</span>
                                </div>
                                <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-2.5">
                                  <span className="font-bold text-amber-300">Risk &amp; Impact: </span>
                                  <span className="text-slate-200">{obs.risk_impact}</span>
                                </div>
                                <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-2.5">
                                  <span className="font-bold text-cyan-300">Corrective Action: </span>
                                  <span className="text-slate-200">{obs.corrective_action}</span>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Section 3: Why It Is / Is Not an Issue + Business & Technical Risk */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                    <div className="bg-slate-950/80 border border-amber-500/30 rounded-xl p-3.5 space-y-1.5">
                      <div className="text-xs font-extrabold uppercase tracking-wider text-amber-300">
                        Why This Is / Is Not a Security Issue (Root-Cause Analysis)
                      </div>
                      <p className="text-xs text-slate-200 leading-relaxed">
                        {whyText}
                      </p>
                    </div>

                    <div className="bg-slate-950/80 border border-rose-500/30 rounded-xl p-3.5 space-y-1.5">
                      <div className="text-xs font-extrabold uppercase tracking-wider text-rose-300">
                        Technical &amp; Business Risk Analysis (Blast Radius)
                      </div>
                      <p className="text-xs text-slate-200 leading-relaxed">
                        {riskText}
                      </p>
                    </div>
                  </div>

                  {/* Section 4: Step-by-Step Corrective Actions & Mitigation Plan */}
                  <div className="bg-cyan-950/15 border border-cyan-500/30 rounded-xl p-4 space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-xs font-extrabold uppercase tracking-wider text-cyan-300 flex items-center gap-1.5">
                        <Wrench className="w-4 h-4 text-cyan-400" />
                        Corrective Actions &amp; Architectural Remediation Plan
                      </div>
                      <span className="text-[11px] text-slate-400">
                        Target Location:{" "}
                        <span className="font-mono text-amber-300">
                          {primaryFp}:{primaryLn}
                        </span>
                      </span>
                    </div>
                    <div className="space-y-1.5">
                      {correctiveSteps.map((step, idx) => (
                        <div
                          key={idx}
                          className="text-xs text-slate-200 bg-slate-950/70 border border-slate-800/80 rounded-lg px-3 py-2 leading-relaxed font-medium"
                        >
                          {step}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Inline Live Code Preview (When Toggled Open) */}
                  {inlinePreviewThreatId === threat.id && (
                    <div className="bg-slate-950 border border-amber-500/40 rounded-xl p-3.5 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-bold text-amber-300 flex items-center gap-1.5">
                          <FileCode className="w-3.5 h-3.5" />
                          Live Source Code Preview — {inlineCodeMeta.filepath}:L
                          {inlineCodeMeta.line}
                        </span>
                        <button
                          onClick={() => handleInspectThreatCode(threat)}
                          className="text-xs font-bold text-cyan-300 hover:underline flex items-center gap-1"
                        >
                          Open Full File in Split Monaco IDE{" "}
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      </div>
                      <pre className="text-[11px] font-mono text-slate-200 bg-slate-900/95 border border-slate-800 rounded-lg p-3 overflow-x-auto leading-relaxed">
                        {loadingPreview
                          ? "Loading source file lines..."
                          : inlineCodeLines.join("\n")}
                      </pre>
                    </div>
                  )}

                  {/* Footer Row: Clickable Affected Components + Inspect Linked Code Buttons */}
                  <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[11px] text-slate-400 font-semibold">
                        Click Component to Inspect Code:
                      </span>
                      {(threat.affected_components || []).slice(0, 4).map((comp, idx) => (
                        <button
                          key={idx}
                          type="button"
                          onClick={() => openCodeLocationInIde(comp, primaryLn)}
                          title={`Open ${comp} in Split Code + Graph IDE`}
                          className="px-2.5 py-1 text-[11px] font-mono rounded-md bg-slate-800 hover:bg-amber-500/20 text-amber-300 hover:text-amber-200 border border-slate-700 hover:border-amber-500/50 flex items-center gap-1 transition-all cursor-pointer"
                        >
                          <FileCode className="w-3 h-3 shrink-0" />
                          {comp}
                        </button>
                      ))}
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => handleToggleInlinePreview(threat)}
                        className="px-3 py-1.5 rounded-lg text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-all"
                      >
                        <Eye className="w-3.5 h-3.5 text-cyan-400" />
                        {inlinePreviewThreatId === threat.id
                          ? "Hide Inline Code"
                          : "Preview Code Here"}
                      </button>

                      <button
                        type="button"
                        onClick={() => handleInspectThreatCode(threat)}
                        className="px-3.5 py-1.5 rounded-lg text-xs font-bold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/50 flex items-center gap-1.5 transition-all shadow-sm"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        Inspect Linked Code in IDE (
                        {threat.linked_finding_ids?.length
                          ? `${threat.linked_finding_ids.length} Flaw${
                              threat.linked_finding_ids.length > 1 ? "s" : ""
                            }`
                          : `${primaryFp}:${primaryLn}`}
                        )
                      </button>
                    </div>
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
                  Extracts exact hardcoded secret key identifiers, credential classifications, Shannon entropy scores, and masked/revealable values with corrective rotation actions.
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
            <div className="bg-slate-900/80 border border-emerald-500/30 rounded-xl p-8 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <div className="text-sm font-bold text-emerald-300">
                PASS • No Hardcoded Secret Keys Detected in Active Scan
              </div>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                All scanned source files, environment templates, and manifests passed hardcoded credential (`CWE-798`) and high-entropy secret key checks.
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
                const fp = sf.best_fix_location?.filepath || node?.filepath || "config";
                const ln = sf.best_fix_location?.line || node?.start_line || 1;

                return (
                  <div
                    key={sf.id}
                    className="bg-slate-900/90 border border-amber-500/35 hover:border-amber-400/60 rounded-xl p-4 flex flex-col gap-3 shadow-md"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="px-2 py-0.5 text-[10px] font-mono font-extrabold rounded bg-red-500/20 text-red-300 border border-red-500/40">
                          FAIL • {sf.severity}
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
                        <span className="text-xs font-mono text-amber-300">
                          {fp}:{ln}
                        </span>
                      </div>

                      <button
                        type="button"
                        onClick={() => openCodeLocationInIde(fp, ln, sf.id)}
                        className="px-3 py-1.5 rounded-lg text-xs font-bold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 flex items-center gap-1.5 transition-all"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        Locate Key in Code ({fp}:{ln})
                      </button>
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
                          type="button"
                          onClick={() => toggleRevealSecret(sf.id)}
                          className="ml-auto px-2 py-1 rounded text-[10px] font-sans font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1"
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
                        type="button"
                        onClick={() =>
                          handleCopySecret(sf.id, `${keyName}=${displayVal}`)
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

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
                      <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-2.5 text-slate-300">
                        <span className="text-rose-300 font-bold">Why Issue & Risk: </span>
                        {sf.description}
                      </div>
                      <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-2.5 text-slate-300">
                        <span className="text-emerald-300 font-bold">Corrective Action: </span>
                        {sf.remediation}
                      </div>
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
          <div>
            <h2 className="text-sm font-bold text-slate-100">
              Four-Tier Trust Boundary & Taint Propagation Architecture
            </h2>
            <p className="text-xs text-slate-400">
              Visualizes how untrusted external inputs cross trust boundaries into application entrypoints, call graph logic, and sensitive sinks/secrets.
            </p>
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
                type="button"
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
                type="button"
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
                type="button"
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
                type="button"
                onClick={() => {
                  setWorkspaceViewMode("REMEDIATION_IDE");
                  setGraphViewMode("ENTRYPOINT_GRAPH");
                  setIdeLayoutMode("SPLIT_BOTH");
                }}
                className="text-xs font-bold text-emerald-400 hover:underline"
              >
                Visualize in Graph →
              </button>
            </div>
            <div className="space-y-2.5 max-h-[540px] overflow-y-auto pr-1">
              {endpoints.map((ep) => (
                <div
                  key={ep.id}
                  className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                        {ep.method}
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-100 truncate">
                        {ep.route_path}
                      </span>
                    </div>
                    <span
                      className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded shrink-0 ${
                        ep.exposure_level === "HIGH_EXPOSURE"
                          ? "bg-red-500/20 text-red-300 border border-red-500/40"
                          : "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                      }`}
                    >
                      {ep.exposure_level === "HIGH_EXPOSURE"
                        ? `ACTION REQUIRED • ${ep.auth_posture}`
                        : `PASS • ${ep.auth_posture}`}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400">
                    {ep.plain_english_purpose}
                  </div>
                  <div className="flex items-center justify-between pt-1">
                    <span className="text-[11px] font-mono text-slate-400">
                      Handler: <span className="text-slate-200">{ep.handler_name}</span> • {ep.filepath}:{ep.line_number}
                    </span>
                    <button
                      type="button"
                      onClick={() => openCodeLocationInIde(ep.filepath, ep.line_number)}
                      className="px-2.5 py-1 rounded text-[11px] font-bold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 flex items-center gap-1"
                    >
                      <Code2 className="w-3 h-3" />
                      Inspect Code
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* PBOM Checks with Pass/Fail Rationale, Risk & Corrective Actions */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              Pipeline Bill of Materials (PBOM) & Pass/Fail Controls
            </h3>
            <div className="space-y-3 max-h-[540px] overflow-y-auto pr-1">
              {pipelineChecks.map((chk) => (
                <div
                  key={chk.id}
                  className="bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <div className="text-[10px] font-mono uppercase text-slate-400">
                        {chk.category}
                      </div>
                      <span className="text-xs font-bold text-slate-100">
                        {chk.title}
                      </span>
                    </div>
                    <span
                      className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded shrink-0 ${
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

                  <p className="text-xs text-slate-300">{chk.details}</p>

                  {chk.why_issue_or_not && (
                    <div className="text-[11px] text-amber-200/90 bg-slate-900/90 border border-slate-800 rounded p-2">
                      {chk.why_issue_or_not}
                    </div>
                  )}

                  {chk.risk_impact && (
                    <div className="text-[11px] text-rose-300/90">
                      <span className="font-bold">Risk:</span> {chk.risk_impact}
                    </div>
                  )}

                  <div className="flex items-center justify-between gap-2 pt-1 border-t border-slate-800/80">
                    <span className="text-[11px] text-cyan-300/90 font-mono truncate">
                      Corrective Action: {chk.remediation}
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        openCodeLocationInIde(
                          chk.primary_filepath || chk.evidence_path,
                          chk.primary_line || 1
                        )
                      }
                      className="px-2.5 py-1 rounded text-[11px] font-bold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 flex items-center gap-1 shrink-0"
                    >
                      <Code2 className="w-3 h-3" />
                      Inspect File
                    </button>
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
