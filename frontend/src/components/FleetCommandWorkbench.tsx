"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  Finding,
  FleetAppGroupRollup,
  FleetRepoResult,
  FleetRunResponse,
  ScanRunCheckpointSummary,
  ScannerFormatType,
} from "@/types/cpg";
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Code2,
  Copy,
  Cpu,
  Database,
  FileCode,
  FileJson,
  FileSpreadsheet,
  GitBranch,
  GitCommit,
  HardDrive,
  Layers,
  Loader2,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  Upload,
  Wrench,
  X,
} from "lucide-react";

type WorkbenchSectionTab = "ALL" | "FUSION" | "FLEET" | "CHECKPOINTS_GC";

const SCANNER_FORMAT_OPTIONS: Array<{
  value: "" | ScannerFormatType;
  label: string;
}> = [
  { value: "", label: "Auto-Detect (Recommended)" },
  { value: "SARIF_2_1", label: "SARIF 2.1.0" },
  { value: "CODEQL_SARIF", label: "CodeQL SARIF" },
  { value: "SEMGREP_JSON", label: "Semgrep JSON" },
  { value: "TRIVY_JSON", label: "Trivy JSON" },
  { value: "GITLEAKS_JSON", label: "Gitleaks JSON" },
  { value: "CHECKOV_JSON", label: "Checkov JSON" },
];

const CLI_SNIPPETS: Array<{ id: string; label: string; command: string }> = [
  { id: "doctor", label: "Readiness Doctor", command: "alastor doctor" },
  {
    id: "estimate",
    label: "$0 Scope Estimate",
    command: "alastor estimate --repo .",
  },
  {
    id: "fusion",
    label: "Scan + Resume + Fusion",
    command: "alastor scan --repo . --resume --fusion-report semgrep.json",
  },
  {
    id: "fleet",
    label: "Fleet CSV Batch",
    command: "alastor scan --repo-file fleet.csv --group-by-app",
  },
  {
    id: "replay",
    label: "EV Post-Fix Replay",
    command: "alastor ev-replay --repo .",
  },
  {
    id: "gc",
    label: "Vault GC Dry Run",
    command: "alastor gc --dry-run",
  },
];

const CORE_STAGE_ORDER = [
  "S0_CPG",
  "S1_RULES",
  "S2_SECRETS_SCA",
  "S3_FUSION",
  "S4_COGNITIVE",
  "S6_VERIFY",
  "S8_CHAINS",
  "S9_REPORTS",
];

function getDoctorStatusBadge(status?: string): string {
  switch (status) {
    case "READY":
      return "bg-emerald-700 text-white border-emerald-800";
    case "DEGRADED":
      return "bg-amber-100 text-amber-950 border-amber-400";
    default:
      return "bg-rose-700 text-white border-rose-800";
  }
}

function getCheckStatusBadge(status: "OK" | "WARN" | "FAIL"): string {
  switch (status) {
    case "OK":
      return "bg-emerald-50 text-emerald-900 border-emerald-300";
    case "WARN":
      return "bg-amber-50 text-amber-950 border-amber-300";
    case "FAIL":
    default:
      return "bg-rose-50 text-rose-950 border-rose-300";
  }
}

function getGoLiveBadgeClass(decision: string): string {
  switch (decision) {
    case "GO_LIVE_APPROVED":
      return "bg-emerald-700 text-white border-emerald-800";
    case "NO_GO_HOLD_RELEASE":
      return "bg-rose-700 text-white border-rose-800";
    case "CONDITIONAL_GO_LIVE":
    default:
      return "bg-amber-100 text-amber-950 border-amber-400";
  }
}

function getRunStatusBadgeClass(status: string): string {
  switch (status) {
    case "COMPLETED":
    case "RESUMED_COMPLETED":
      return "bg-emerald-50 text-emerald-900 border-emerald-300";
    case "PARTIAL":
    case "RUNNING":
      return "bg-indigo-50 text-indigo-950 border-indigo-300";
    case "FAILED":
    default:
      return "bg-rose-50 text-rose-950 border-rose-300";
  }
}

function getStagePillClass(status: string): string {
  switch (status) {
    case "COMPLETED":
      return "bg-emerald-50 text-emerald-900 border-emerald-300";
    case "RUNNING":
      return "bg-indigo-700 text-white border-indigo-800";
    case "FAILED":
      return "bg-rose-700 text-white border-rose-800";
    case "SKIPPED":
      return "bg-slate-100 text-slate-700 border-slate-300";
    case "PENDING":
    default:
      return "bg-[#f8fafc] text-slate-600 border-slate-200";
  }
}

function getSeverityBadgeClass(severity: string): string {
  switch (severity) {
    case "CRITICAL":
      return "bg-rose-700 text-white border-rose-800";
    case "HIGH":
      return "bg-amber-100 text-amber-950 border-amber-400";
    case "MEDIUM":
      return "bg-yellow-50 text-amber-950 border-amber-300";
    case "LOW":
      return "bg-sky-50 text-sky-950 border-sky-300";
    default:
      return "bg-slate-100 text-slate-800 border-slate-300";
  }
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatCsvField(raw: string): string {
  if (/[",\r\n]/.test(raw)) {
    return `"${raw.replace(/"/g, '""')}"`;
  }
  return raw;
}

function getFindingLocation(f: Finding): { filepath: string; line: number } {
  const bfl = f.best_fix_location;
  if (bfl?.filepath) {
    return { filepath: bfl.filepath, line: bfl.line || 1 };
  }
  const firstNode = f.path_nodes?.[0];
  if (firstNode?.filepath) {
    return { filepath: firstNode.filepath, line: firstNode.start_line || 1 };
  }
  return { filepath: "(workspace)", line: 1 };
}

export const FleetCommandWorkbench: React.FC = () => {
  const projectPath = useAuditStore((s) => s.projectPath);
  const findings = useAuditStore((s) => s.findings);
  const openCodeLocationInIde = useAuditStore((s) => s.openCodeLocationInIde);

  const fleetDoctor = useAuditStore((s) => s.fleetDoctor);
  const fleetEstimate = useAuditStore((s) => s.fleetEstimate);
  const fusionResult = useAuditStore((s) => s.fusionResult);
  const fleetRunResult = useAuditStore((s) => s.fleetRunResult);
  const fleetRuns = useAuditStore((s) => s.fleetRuns);
  const fleetCheckpoints = useAuditStore((s) => s.fleetCheckpoints);
  const fleetGcReport = useAuditStore((s) => s.fleetGcReport);

  const isLoadingDoctor = useAuditStore((s) => s.isLoadingDoctor);
  const isEstimatingFleet = useAuditStore((s) => s.isEstimatingFleet);
  const isImportingFusion = useAuditStore((s) => s.isImportingFusion);
  const isRunningFleet = useAuditStore((s) => s.isRunningFleet);
  const isLoadingFleetRuns = useAuditStore((s) => s.isLoadingFleetRuns);
  const isLoadingCheckpoints = useAuditStore((s) => s.isLoadingCheckpoints);
  const isResumingCheckpoint = useAuditStore((s) => s.isResumingCheckpoint);
  const isRunningGc = useAuditStore((s) => s.isRunningGc);
  const fleetError = useAuditStore((s) => s.fleetError);

  const fetchFleetDoctorAction = useAuditStore(
    (s) => s.fetchFleetDoctorAction
  );
  const estimateFleetRepoAction = useAuditStore(
    (s) => s.estimateFleetRepoAction
  );
  const importScannerFusionAction = useAuditStore(
    (s) => s.importScannerFusionAction
  );
  const runFleetBatchAction = useAuditStore((s) => s.runFleetBatchAction);
  const loadFleetRunsAction = useAuditStore((s) => s.loadFleetRunsAction);
  const loadFleetCheckpointsAction = useAuditStore(
    (s) => s.loadFleetCheckpointsAction
  );
  const resumeFleetCheckpointAction = useAuditStore(
    (s) => s.resumeFleetCheckpointAction
  );
  const runFleetGcAction = useAuditStore((s) => s.runFleetGcAction);
  const clearFleetError = useAuditStore((s) => s.clearFleetError);

  // Internal workbench section switcher
  const [sectionTab, setSectionTab] = useState<WorkbenchSectionTab>("ALL");

  // Doctor UI state
  const [checkNeo4j, setCheckNeo4j] = useState<boolean>(false);
  const [doctorChecksOpen, setDoctorChecksOpen] = useState<boolean>(false);

  // Clipboard state
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const copyTimerRef = useRef<number | null>(null);

  // Universal 6-Format Scanner Fusion state (project-scoped)
  const [sourceFormat, setSourceFormat] = useState<"" | ScannerFormatType>("");
  const [correlateCpg, setCorrelateCpg] = useState<boolean>(true);
  const [runS6Verify, setRunS6Verify] = useState<boolean>(false);
  const [reportJson, setReportJson] = useState<string>("");
  const [reportFilename, setReportFilename] = useState<string>("");
  const [showAllFusionFindings, setShowAllFusionFindings] =
    useState<boolean>(false);
  const fusionFileInputRef = useRef<HTMLInputElement | null>(null);

  // CSV Multi-Repo Fleet Batch Runner state
  const [manifestName, setManifestName] = useState<string>("fleet-manifest");
  const [groupByApp, setGroupByApp] = useState<boolean>(true);
  const [resumeCheckpoints, setResumeCheckpoints] = useState<boolean>(true);
  const [maxWorkers, setMaxWorkers] = useState<number>(2);
  const [csvContent, setCsvContent] = useState<string>("");
  const [csvFilename, setCsvFilename] = useState<string>("");
  const [selectedHistoryRunId, setSelectedHistoryRunId] = useState<
    string | null
  >(null);
  const csvFileInputRef = useRef<HTMLInputElement | null>(null);

  // Checkpoints & Vault GC state
  const [workspaceOnlyCheckpoints, setWorkspaceOnlyCheckpoints] =
    useState<boolean>(false);
  const [resumingRunId, setResumingRunId] = useState<string | null>(null);
  const [resumedNotice, setResumedNotice] = useState<FleetRepoResult | null>(
    null
  );
  const [olderThanDays, setOlderThanDays] = useState<number>(30);
  const [keepLast, setKeepLast] = useState<number>(20);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  // Load runtime Doctor and persisted Fleet Runs on mount
  useEffect(() => {
    void fetchFleetDoctorAction(false);
    void loadFleetRunsAction();
  }, [fetchFleetDoctorAction, loadFleetRunsAction]);

  // Reset project-scoped local inputs when switching workspaces
  useEffect(() => {
    setSourceFormat("");
    setCorrelateCpg(true);
    setRunS6Verify(false);
    setReportJson("");
    setReportFilename("");
    setShowAllFusionFindings(false);
    setResumedNotice(null);
  }, [projectPath]);

  // Reload SQLite stage checkpoints whenever workspace or filter changes
  useEffect(() => {
    void loadFleetCheckpointsAction(
      workspaceOnlyCheckpoints ? projectPath : undefined
    );
  }, [projectPath, workspaceOnlyCheckpoints, loadFleetCheckpointsAction]);

  const activeFindingIds = useMemo(
    () => new Set(findings.map((f) => f.id)),
    [findings]
  );

  const handleCopyText = useCallback(async (key: string, value: string) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopiedKey(null);
        copyTimerRef.current = null;
      }, 1800);
    } catch (err) {
      console.error("Clipboard copy failed:", err);
    }
  }, []);

  const handleFusionFileUpload = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setReportJson(text);
      setReportFilename(file.name);
    } catch (err) {
      console.error("Failed to read scanner report file:", err);
    } finally {
      e.target.value = "";
    }
  };

  const handleCsvFileUpload = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setCsvContent(text);
      setCsvFilename(file.name);
    } catch (err) {
      console.error("Failed to read CSV manifest file:", err);
    } finally {
      e.target.value = "";
    }
  };

  const handleInsertSampleCsv = () => {
    const sampleRepo =
      (projectPath || "").trim() ||
      fleetEstimate?.project_path ||
      ".";
    const sampleCsv = [
      "repo,app_group,branch,fusion_reports,profile",
      `${formatCsvField(sampleRepo)},core-platform,main,,deterministic`,
    ].join("\n");
    setCsvContent(sampleCsv);
    setCsvFilename("sample-local-fleet.csv");
  };

  const handleRunFusion = async () => {
    if (!reportJson.trim()) return;
    await importScannerFusionAction({
      project_path: projectPath,
      report_json: reportJson,
      source_format: sourceFormat || null,
      correlate_cpg: correlateCpg,
      run_s6_verify: runS6Verify,
    });
  };

  const handleLaunchFleetBatch = async () => {
    if (!csvContent.trim()) return;
    setSelectedHistoryRunId(null);
    await runFleetBatchAction({
      manifest_name: manifestName.trim() || "fleet-manifest",
      csv_content: csvContent,
      group_by_app: groupByApp,
      resume: resumeCheckpoints,
      max_workers: maxWorkers,
    });
    if (workspaceOnlyCheckpoints) {
      await loadFleetCheckpointsAction(projectPath);
    }
  };

  const handleResumeCheckpoint = async (cp: ScanRunCheckpointSummary) => {
    setResumingRunId(cp.run_id);
    try {
      const res = await resumeFleetCheckpointAction(cp.run_id);
      if (res) {
        setResumedNotice(res);
      }
      if (workspaceOnlyCheckpoints) {
        await loadFleetCheckpointsAction(projectPath);
      }
    } finally {
      setResumingRunId(null);
    }
  };

  const handleRunGc = async (dryRun: boolean) => {
    const safeDays = Math.max(0, Math.min(3650, Math.floor(olderThanDays || 0)));
    const safeKeep = Math.max(0, Math.min(1000, Math.floor(keepLast || 0)));
    await runFleetGcAction({
      older_than_days: safeDays,
      keep_last: safeKeep,
      dry_run: dryRun,
    });
    if (!dryRun && workspaceOnlyCheckpoints) {
      await loadFleetCheckpointsAction(projectPath);
    }
  };

  const displayedFusionFindings = useMemo(() => {
    if (!fusionResult?.findings) return [];
    const prioritized = [...fusionResult.findings].sort((a, b) => {
      const aCorr = (a.corroborated_by?.length || 0) > 0 ? 2 : a.source_engine ? 1 : 0;
      const bCorr = (b.corroborated_by?.length || 0) > 0 ? 2 : b.source_engine ? 1 : 0;
      return bCorr - aCorr;
    });
    if (showAllFusionFindings) {
      return prioritized;
    }
    const fusedOnly = prioritized.filter(
      (f) => (f.corroborated_by && f.corroborated_by.length > 0) || Boolean(f.source_engine)
    );
    return fusedOnly.length > 0 ? fusedOnly : prioritized;
  }, [fusionResult, showAllFusionFindings]);

  const activeFleetRunDisplay: FleetRunResponse | null = useMemo(() => {
    if (selectedHistoryRunId) {
      const match = fleetRuns.find((r) => r.fleet_run_id === selectedHistoryRunId);
      if (match) return match;
    }
    return fleetRunResult || fleetRuns[0] || null;
  }, [selectedHistoryRunId, fleetRuns, fleetRunResult]);

  return (
    <div className="space-y-5 text-slate-900 select-text">
      {/* 1. Top Readiness & CLI Posture Strip (Doctor + $0 Scope Estimator + CLI Quick-Reference) */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        {/* Doctor Readiness Card */}
        <div className="xl:col-span-7 bg-white border border-slate-300 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-indigo-50 border border-indigo-300 flex items-center justify-center text-indigo-800 shrink-0">
                <Activity className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-sm font-extrabold text-slate-900">
                    ALASTOR Runtime Readiness (<span className="font-mono">doctor</span>)
                  </h2>
                  {fleetDoctor && (
                    <span
                      className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${getDoctorStatusBadge(
                        fleetDoctor.overall_status
                      )}`}
                    >
                      {fleetDoctor.overall_status}
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-600 mt-0.5">
                  Verifies Tree-sitter parsers, GraphStore backend, Git hardening,
                  Docker sandbox, and SQLite checkpoint vault writability.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <label className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={checkNeo4j}
                  onChange={(e) => setCheckNeo4j(e.target.checked)}
                  className="accent-indigo-700 w-3.5 h-3.5"
                />
                <span>Probe Neo4j</span>
              </label>
              <button
                type="button"
                disabled={isLoadingDoctor}
                onClick={() => void fetchFleetDoctorAction(checkNeo4j)}
                className="px-3 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 disabled:opacity-50 border border-slate-300 text-slate-900 text-xs font-extrabold flex items-center gap-1.5"
              >
                <RefreshCw
                  className={`w-3.5 h-3.5 text-indigo-700 ${
                    isLoadingDoctor ? "animate-spin" : ""
                  }`}
                />
                <span>Refresh Doctor</span>
              </button>
            </div>
          </div>

          {isLoadingDoctor && !fleetDoctor ? (
            <div className="py-6 flex items-center justify-center gap-2 text-xs font-mono text-slate-700">
              <Loader2 className="w-4 h-4 animate-spin text-indigo-700" />
              <span>Running runtime diagnostics...</span>
            </div>
          ) : fleetDoctor ? (
            <>
              <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
                <span className="px-2.5 py-1 rounded-lg bg-emerald-50 border border-emerald-300 text-emerald-900 font-extrabold flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-emerald-800" />
                  {fleetDoctor.parsers_ready}/{fleetDoctor.parsers_total} Tree-sitter Parsers
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-indigo-50 border border-indigo-300 text-indigo-950 font-extrabold flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5 text-indigo-800" />
                  {fleetDoctor.graph_backend}
                </span>
                <span
                  className={`px-2.5 py-1 rounded-lg border font-extrabold flex items-center gap-1.5 ${
                    fleetDoctor.git_available
                      ? "bg-emerald-50 border-emerald-300 text-emerald-900"
                      : "bg-amber-50 border-amber-300 text-amber-950"
                  }`}
                >
                  <GitBranch className="w-3.5 h-3.5" />
                  {fleetDoctor.git_available ? "Git Hardening Ready" : "Git Missing"}
                </span>
                <span
                  className={`px-2.5 py-1 rounded-lg border font-bold ${
                    fleetDoctor.docker_available
                      ? "bg-emerald-50 border-emerald-300 text-emerald-900"
                      : "bg-slate-50 border-slate-300 text-slate-700"
                  }`}
                >
                  Docker Sandbox:{" "}
                  {fleetDoctor.docker_available ? "Ready" : "Optional (Off)"}
                </span>
                <span
                  className={`px-2.5 py-1 rounded-lg border font-extrabold flex items-center gap-1 ${
                    fleetDoctor.vault_writable
                      ? "bg-emerald-50 border-emerald-300 text-emerald-900"
                      : "bg-rose-50 border-rose-300 text-rose-950"
                  }`}
                >
                  <HardDrive className="w-3.5 h-3.5" />
                  Vault {fleetDoctor.vault_writable ? "Writable" : "Read-Only"}
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-300 text-slate-800 font-bold">
                  Python {fleetDoctor.python_version}
                </span>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-200 text-[11px]">
                <span
                  className="font-mono text-slate-600 truncate max-w-md"
                  title={fleetDoctor.vault_path}
                >
                  Vault: {fleetDoctor.vault_path}
                </span>
                <button
                  type="button"
                  onClick={() => setDoctorChecksOpen((prev) => !prev)}
                  className="font-mono font-bold text-indigo-800 hover:underline flex items-center gap-1"
                >
                  <span>
                    {doctorChecksOpen
                      ? "Hide Detailed Checks"
                      : `Inspect ${fleetDoctor.checks.length} Checks`}
                  </span>
                  {doctorChecksOpen ? (
                    <ChevronUp className="w-3.5 h-3.5" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>

              {doctorChecksOpen && fleetDoctor.checks.length > 0 && (
                <div className="overflow-x-auto rounded-lg border border-slate-200">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-mono uppercase text-slate-700">
                        <th className="py-2 px-3">Check</th>
                        <th className="py-2 px-3">Status</th>
                        <th className="py-2 px-3">Detail</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200">
                      {fleetDoctor.checks.map((chk) => (
                        <tr key={chk.name} className="bg-white">
                          <td className="py-2 px-3 font-mono font-bold text-slate-900">
                            {chk.name}
                          </td>
                          <td className="py-2 px-3">
                            <span
                              className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${getCheckStatusBadge(
                                chk.status
                              )}`}
                            >
                              {chk.status}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-slate-700">
                            {chk.detail}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          ) : (
            <div className="rounded-lg bg-[#f8fafc] border border-slate-200 p-3 text-xs text-slate-700">
              Click <span className="font-bold">Refresh Doctor</span> to inspect
              runtime readiness.
            </div>
          )}
        </div>

        {/* $0 Scope & Cost Estimator Card */}
        <div className="xl:col-span-5 bg-white border border-slate-300 rounded-xl p-5 shadow-sm flex flex-col justify-between space-y-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-sm font-extrabold text-slate-900">
                  <span className="font-mono">$0</span> Scope &amp; Cost Estimator
                </h2>
                <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 text-[10px] font-mono font-extrabold">
                  ZERO AI SPEND
                </span>
              </div>
              <p
                className="text-[11px] font-mono text-slate-600 mt-1 truncate max-w-xs"
                title={projectPath || "Active Backend Workspace"}
              >
                Workspace: {projectPath || "(Active Backend Workspace)"}
              </p>
            </div>

            <button
              type="button"
              disabled={isEstimatingFleet}
              onClick={() => void estimateFleetRepoAction(projectPath)}
              className="px-3 py-1.5 rounded-lg bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white border border-indigo-800 text-xs font-extrabold flex items-center gap-1.5 shrink-0 shadow-sm"
            >
              {isEstimatingFleet ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Wrench className="w-3.5 h-3.5" />
              )}
              <span>Run $0 Estimate</span>
            </button>
          </div>

          {fleetEstimate ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div className="rounded-lg bg-[#f8fafc] border border-slate-200 p-2.5">
                  <div className="text-[10px] font-mono uppercase text-slate-600 font-bold">
                    Files
                  </div>
                  <div className="text-base font-extrabold text-slate-900">
                    {fleetEstimate.total_files.toLocaleString()}
                  </div>
                  <div className="text-[10px] text-slate-600">
                    {fleetEstimate.skipped_files} skipped
                  </div>
                </div>
                <div className="rounded-lg bg-[#f8fafc] border border-slate-200 p-2.5">
                  <div className="text-[10px] font-mono uppercase text-slate-600 font-bold">
                    Total LOC
                  </div>
                  <div className="text-base font-extrabold text-slate-900">
                    {fleetEstimate.total_loc.toLocaleString()}
                  </div>
                  <div className="text-[10px] text-slate-600">
                    {fleetEstimate.recommended_profile}
                  </div>
                </div>
                <div className="rounded-lg bg-[#f8fafc] border border-slate-200 p-2.5">
                  <div className="text-[10px] font-mono uppercase text-slate-600 font-bold">
                    Det. Time
                  </div>
                  <div className="text-base font-extrabold text-indigo-900">
                    {fleetEstimate.estimated_deterministic_seconds.toFixed(2)}s
                  </div>
                  <div className="text-[10px] text-slate-600">0 AI calls</div>
                </div>
                <div className="rounded-lg bg-[#f8fafc] border border-slate-200 p-2.5">
                  <div className="text-[10px] font-mono uppercase text-slate-600 font-bold">
                    Est. AI Cost
                  </div>
                  <div className="text-base font-extrabold text-emerald-900">
                    ${fleetEstimate.estimated_ai_cost_usd.toFixed(4)}
                  </div>
                  <div className="text-[10px] text-slate-600">
                    {fleetEstimate.estimated_ai_tokens.toLocaleString()} tok
                  </div>
                </div>
              </div>

              {Object.keys(fleetEstimate.languages || {}).length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[10px] font-mono font-extrabold uppercase text-slate-600 mr-1">
                    Languages:
                  </span>
                  {Object.entries(fleetEstimate.languages).map(([lang, cnt]) => (
                    <span
                      key={lang}
                      className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-950 text-[10px] font-mono font-bold"
                    >
                      {lang}: {cnt}
                    </span>
                  ))}
                </div>
              )}

              {fleetEstimate.repo_kind_hints.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[10px] font-mono font-extrabold uppercase text-slate-600 mr-1">
                    Repo Hints:
                  </span>
                  {fleetEstimate.repo_kind_hints.map((hint) => (
                    <span
                      key={hint}
                      className="px-2 py-0.5 rounded bg-amber-50 border border-amber-300 text-amber-950 text-[10px] font-mono font-bold"
                    >
                      {hint}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-xl border border-dashed border-slate-300 bg-[#f8fafc] p-4 text-xs text-slate-700">
              Click <span className="font-bold">Run $0 Estimate</span> to count
              scannable files, LOC, language mix, deterministic scan duration,
              and projected BYOK AI token cost with zero LLM spend.
            </div>
          )}
        </div>
      </div>

      {/* Compact CLI & SDK Quick-Reference Strip */}
      <div className="bg-white border border-slate-300 rounded-xl p-4 shadow-sm space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-indigo-700" />
            <h3 className="text-xs font-extrabold uppercase tracking-wider text-slate-900">
              Headless CLI &amp; Python SDK Quick-Reference
            </h3>
          </div>
          <button
            type="button"
            onClick={() =>
              void handleCopyText(
                "sdk-import",
                "from alastor_sdk import doctor, estimate, scan, fuse_scanner_report, ev_replay, gc"
              )
            }
            className="px-2.5 py-1 rounded-lg bg-[#f8fafc] hover:bg-slate-100 border border-slate-300 text-[11px] font-mono font-bold text-slate-800 flex items-center gap-1.5"
          >
            {copiedKey === "sdk-import" ? (
              <>
                <Check className="w-3 h-3 text-emerald-700" />
                <span className="text-emerald-800">Copied SDK Import!</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3 text-indigo-700" />
                <span>Copy Python SDK Import</span>
              </>
            )}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
          {CLI_SNIPPETS.map((item) => {
            const cKey = `cli-${item.id}`;
            return (
              <div
                key={item.id}
                className="rounded-lg bg-[#f8fafc] border border-slate-200 px-3 py-2 flex items-center justify-between gap-2"
              >
                <div className="min-w-0">
                  <div className="text-[10px] font-bold uppercase text-slate-600">
                    {item.label}
                  </div>
                  <div className="text-[11px] font-mono font-bold text-slate-900 truncate">
                    {item.command}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => void handleCopyText(cKey, item.command)}
                  aria-label={`Copy ${item.command}`}
                  className="px-2 py-1 rounded bg-white hover:bg-slate-100 border border-slate-300 text-[10px] font-mono font-bold text-slate-800 flex items-center gap-1 shrink-0"
                >
                  {copiedKey === cKey ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-700" />
                      <span className="text-emerald-800">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3 text-slate-700" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* Accessible Daylight Error Banner */}
      {fleetError && (
        <div
          role="alert"
          className="px-4 py-3 rounded-xl bg-rose-50 border border-rose-300 text-rose-950 text-xs font-bold flex items-center justify-between gap-3 shadow-sm"
        >
          <div className="flex items-center gap-2 min-w-0">
            <AlertTriangle className="w-4 h-4 text-rose-700 shrink-0" />
            <span className="break-words">{fleetError}</span>
          </div>
          <button
            type="button"
            onClick={clearFleetError}
            aria-label="Dismiss Fleet error"
            className="p-1 rounded-lg hover:bg-rose-100 text-rose-900 shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Internal Workbench Section Tabs */}
      <div className="bg-white border border-slate-200 rounded-xl p-2 shadow-sm flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => setSectionTab("ALL")}
          className={`px-3 py-1.5 rounded-lg text-xs font-extrabold border flex items-center gap-1.5 transition-colors ${
            sectionTab === "ALL"
              ? "bg-indigo-700 text-white border-indigo-800 shadow-sm"
              : "bg-white text-slate-700 hover:bg-slate-100 border-slate-300"
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>All Workbench Panels</span>
        </button>

        <button
          type="button"
          onClick={() => setSectionTab("FUSION")}
          className={`px-3 py-1.5 rounded-lg text-xs font-extrabold border flex items-center gap-1.5 transition-colors ${
            sectionTab === "FUSION"
              ? "bg-indigo-700 text-white border-indigo-800 shadow-sm"
              : "bg-white text-slate-700 hover:bg-slate-100 border-slate-300"
          }`}
        >
          <FileJson className="w-3.5 h-3.5" />
          <span>Scanner Fusion (6 Formats)</span>
          {fusionResult && (
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-extrabold ${
                sectionTab === "FUSION"
                  ? "bg-white text-indigo-950"
                  : "bg-indigo-50 text-indigo-950 border border-indigo-200"
              }`}
            >
              {fusionResult.corroborated_count} Corroborated
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setSectionTab("FLEET")}
          className={`px-3 py-1.5 rounded-lg text-xs font-extrabold border flex items-center gap-1.5 transition-colors ${
            sectionTab === "FLEET"
              ? "bg-indigo-700 text-white border-indigo-800 shadow-sm"
              : "bg-white text-slate-700 hover:bg-slate-100 border-slate-300"
          }`}
        >
          <FileSpreadsheet className="w-3.5 h-3.5" />
          <span>CSV Fleet Batch Runner</span>
          <span
            className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-extrabold ${
              sectionTab === "FLEET"
                ? "bg-white text-indigo-950"
                : "bg-slate-100 text-slate-800 border border-slate-300"
            }`}
          >
            {fleetRuns.length} Runs
          </span>
        </button>

        <button
          type="button"
          onClick={() => setSectionTab("CHECKPOINTS_GC")}
          className={`px-3 py-1.5 rounded-lg text-xs font-extrabold border flex items-center gap-1.5 transition-colors ${
            sectionTab === "CHECKPOINTS_GC"
              ? "bg-indigo-700 text-white border-indigo-800 shadow-sm"
              : "bg-white text-slate-700 hover:bg-slate-100 border-slate-300"
          }`}
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>SQLite Checkpoints &amp; Vault GC</span>
          <span
            className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-extrabold ${
              sectionTab === "CHECKPOINTS_GC"
                ? "bg-white text-indigo-950"
                : "bg-slate-100 text-slate-800 border border-slate-300"
            }`}
          >
            {fleetCheckpoints.length}
          </span>
        </button>
      </div>

      {/* 2. Universal 6-Format Scanner Fusion Panel */}
      {(sectionTab === "ALL" || sectionTab === "FUSION") && (
        <div className="bg-white border border-slate-300 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-200 pb-3">
            <div>
              <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                <FileJson className="w-4 h-4 text-indigo-700" />
                <span>
                  Universal 6-Format Scanner Fusion &amp; CPG Corroboration
                </span>
              </h3>
              <p className="text-xs text-slate-600 mt-0.5">
                Import SARIF 2.1.0, CodeQL, Semgrep, Trivy, Gitleaks, or Checkov
                JSON reports, scrub raw secrets, and corroborate findings onto
                the ALASTOR CPG.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <label className="px-3 py-1.5 rounded-lg bg-[#f8fafc] border border-slate-300 text-xs font-bold text-slate-800 flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={correlateCpg}
                  onChange={(e) => setCorrelateCpg(e.target.checked)}
                  className="accent-indigo-700 w-3.5 h-3.5"
                />
                <span>Correlate onto ALASTOR CPG</span>
              </label>

              <label className="px-3 py-1.5 rounded-lg bg-[#f8fafc] border border-slate-300 text-xs font-bold text-slate-800 flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={runS6Verify}
                  onChange={(e) => setRunS6Verify(e.target.checked)}
                  className="accent-indigo-700 w-3.5 h-3.5"
                />
                <span>Run S6 Adversarial Verifier ($0)</span>
              </label>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
            <div className="md:col-span-4 space-y-1">
              <label
                htmlFor="fusion-format-select"
                className="block text-xs font-extrabold text-slate-900"
              >
                Scanner Report Format
              </label>
              <select
                id="fusion-format-select"
                value={sourceFormat}
                onChange={(e) =>
                  setSourceFormat(e.target.value as "" | ScannerFormatType)
                }
                className="w-full h-9 px-3 rounded-lg bg-[#f8fafc] border border-slate-300 focus:border-indigo-600 focus:bg-white focus:outline-none text-xs font-semibold text-slate-900"
              >
                {SCANNER_FORMAT_OPTIONS.map((opt) => (
                  <option key={opt.value || "AUTO"} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-8 flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <input
                  ref={fusionFileInputRef}
                  type="file"
                  accept=".json,.sarif"
                  onChange={(e) => void handleFusionFileUpload(e)}
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => fusionFileInputRef.current?.click()}
                  className="h-9 px-3 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-900 text-xs font-bold flex items-center gap-1.5"
                >
                  <Upload className="w-3.5 h-3.5 text-indigo-700" />
                  <span>Upload .json / .sarif</span>
                </button>
                {reportFilename && (
                  <span className="px-2.5 py-1 rounded bg-indigo-50 border border-indigo-200 text-indigo-950 text-[11px] font-mono font-bold">
                    {reportFilename}
                  </span>
                )}
                {reportJson.trim() && (
                  <button
                    type="button"
                    onClick={() => {
                      setReportJson("");
                      setReportFilename("");
                    }}
                    className="h-9 px-3 rounded-lg bg-white hover:bg-rose-50 border border-slate-300 text-rose-800 text-xs font-bold"
                  >
                    Clear
                  </button>
                )}
              </div>

              <button
                type="button"
                disabled={isImportingFusion || !reportJson.trim()}
                onClick={() => void handleRunFusion()}
                className="h-9 px-4 rounded-lg bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white border border-indigo-800 text-xs font-extrabold flex items-center gap-2 shadow-sm"
              >
                {isImportingFusion ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5 fill-current" />
                )}
                <span>Fuse into ALASTOR CPG</span>
              </button>
            </div>
          </div>

          <textarea
            rows={5}
            value={reportJson}
            onChange={(e) => setReportJson(e.target.value)}
            aria-label="External scanner JSON or SARIF payload"
            placeholder='Paste SARIF 2.1.0, CodeQL SARIF, Semgrep, Trivy, Gitleaks, or Checkov JSON here...'
            className="w-full p-3 rounded-lg bg-[#f8fafc] border border-slate-300 focus:border-indigo-600 focus:bg-white focus:outline-none text-xs font-mono text-slate-900 placeholder-slate-500"
          />

          {fusionResult && (
            <div className="space-y-3 pt-2 border-t border-slate-200">
              <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono font-extrabold">
                <span className="px-2.5 py-1 rounded-md bg-indigo-700 text-white border border-indigo-800">
                  Detected Format: {fusionResult.detected_format}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-slate-100 text-slate-900 border border-slate-300">
                  Imported: {fusionResult.imported_raw_count}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-emerald-50 text-emerald-900 border border-emerald-300">
                  Corroborated Multi-Engine: {fusionResult.corroborated_count}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-sky-50 text-sky-950 border border-sky-300">
                  New Unique: {fusionResult.new_unique_count}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-indigo-50 text-indigo-950 border border-indigo-300">
                  CPG Enriched: {fusionResult.cpg_enriched_count}
                </span>
                <span className="px-2.5 py-1 rounded-md bg-amber-50 text-amber-950 border border-amber-300">
                  S6 Verified: {fusionResult.s6_verified_count}
                </span>
              </div>

              {fusionResult.warnings.length > 0 && (
                <div className="rounded-lg bg-amber-50 border border-amber-300 p-2.5 text-xs text-amber-950 space-y-1">
                  {fusionResult.warnings.map((warn, idx) => (
                    <div key={idx} className="font-mono text-[11px]">
                      • {warn}
                    </div>
                  ))}
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-extrabold text-slate-900">
                  Fused &amp; Corroborated Findings (
                  {displayedFusionFindings.length} shown of{" "}
                  {fusionResult.findings.length})
                </span>
                <button
                  type="button"
                  onClick={() => setShowAllFusionFindings((prev) => !prev)}
                  className="text-[11px] font-mono font-bold text-indigo-800 hover:underline"
                >
                  {showAllFusionFindings
                    ? "Prioritize External / Corroborated Only"
                    : `Show All Workspace Findings (${fusionResult.findings.length})`}
                </button>
              </div>

              {displayedFusionFindings.length > 0 && (
                <div className="overflow-x-auto max-h-80 rounded-lg border border-slate-200">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead className="sticky top-0 bg-slate-50 border-b border-slate-200 text-[10px] font-mono uppercase text-slate-700">
                      <tr>
                        <th className="py-2 px-3">Severity</th>
                        <th className="py-2 px-3">Rule &amp; Title</th>
                        <th className="py-2 px-3">Engine &amp; Corroboration</th>
                        <th className="py-2 px-3">Location</th>
                        <th className="py-2 px-3">Reachability / Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 bg-white">
                      {displayedFusionFindings.map((f) => {
                        const loc = getFindingLocation(f);
                        const canOpen = activeFindingIds.has(f.id);
                        return (
                          <tr
                            key={f.id}
                            className="hover:bg-slate-50 transition-colors"
                          >
                            <td className="py-2 px-3 align-top whitespace-nowrap">
                              <span
                                className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${getSeverityBadgeClass(
                                  f.severity
                                )}`}
                              >
                                {f.severity}
                              </span>
                            </td>
                            <td className="py-2 px-3 align-top">
                              <div className="font-bold text-slate-900">
                                {f.title}
                              </div>
                              <div className="text-[10px] font-mono text-slate-600 mt-0.5 flex flex-wrap items-center gap-1.5">
                                <span>{f.rule_id}</span>
                                {f.cwe_id && (
                                  <span className="px-1.5 py-0.5 rounded bg-amber-50 border border-amber-300 text-amber-950 font-bold">
                                    {f.cwe_id}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="py-2 px-3 align-top">
                              <div className="flex flex-wrap items-center gap-1 font-mono text-[10px]">
                                <span className="px-1.5 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-950 font-bold">
                                  {f.source_engine || f.scan_engine || "ALASTOR"}
                                </span>
                                {(f.corroborated_by || []).map((eng) => (
                                  <span
                                    key={eng}
                                    className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 font-extrabold"
                                  >
                                    +{eng}
                                  </span>
                                ))}
                              </div>
                            </td>
                            <td className="py-2 px-3 align-top font-mono text-[11px]">
                              {canOpen ? (
                                <button
                                  type="button"
                                  onClick={() =>
                                    openCodeLocationInIde(
                                      loc.filepath,
                                      loc.line,
                                      f.id
                                    )
                                  }
                                  className="text-indigo-800 hover:underline font-bold flex items-center gap-1 text-left"
                                >
                                  <Code2 className="w-3 h-3 shrink-0" />
                                  <span className="truncate max-w-xs">
                                    {loc.filepath}:{loc.line}
                                  </span>
                                </button>
                              ) : (
                                <span className="text-slate-700 truncate block max-w-xs">
                                  {loc.filepath}:{loc.line}
                                </span>
                              )}
                            </td>
                            <td className="py-2 px-3 align-top whitespace-nowrap font-mono text-[10px]">
                              <div className="font-bold text-slate-800">
                                {f.reachability_status || "REACHABLE"}
                              </div>
                              <div className="text-slate-600">
                                {f.triage_status || "TO_VERIFY"}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 3. CSV Multi-Repo Fleet Batch Runner (--repo-file & --group-by-app) */}
      {(sectionTab === "ALL" || sectionTab === "FLEET") && (
        <div className="bg-white border border-slate-300 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-200 pb-3">
            <div>
              <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                <FileSpreadsheet className="w-4 h-4 text-indigo-700" />
                <span>
                  CSV Multi-Repo Fleet Batch Runner (
                  <span className="font-mono">--repo-file</span> &amp;{" "}
                  <span className="font-mono">--group-by-app</span>)
                </span>
              </h3>
              <p className="text-xs text-slate-600 mt-0.5">
                Execute deterministic or checkpoint-resumed scans across a CSV
                manifest of confined local paths or validated Git URLs and roll
                up App-Group Go-Live decisions.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <label className="px-3 py-1.5 rounded-lg bg-[#f8fafc] border border-slate-300 text-xs font-bold text-slate-800 flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={groupByApp}
                  onChange={(e) => setGroupByApp(e.target.checked)}
                  className="accent-indigo-700 w-3.5 h-3.5"
                />
                <span>Group by App</span>
              </label>

              <label className="px-3 py-1.5 rounded-lg bg-[#f8fafc] border border-slate-300 text-xs font-bold text-slate-800 flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={resumeCheckpoints}
                  onChange={(e) => setResumeCheckpoints(e.target.checked)}
                  className="accent-indigo-700 w-3.5 h-3.5"
                />
                <span>Resume SQLite Checkpoints</span>
              </label>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
            <div className="md:col-span-4 space-y-1">
              <label
                htmlFor="fleet-manifest-name"
                className="block text-xs font-extrabold text-slate-900"
              >
                Manifest Name
              </label>
              <input
                id="fleet-manifest-name"
                type="text"
                value={manifestName}
                onChange={(e) => setManifestName(e.target.value)}
                placeholder="fleet-manifest"
                className="w-full h-9 px-3 rounded-lg bg-[#f8fafc] border border-slate-300 focus:border-indigo-600 focus:bg-white focus:outline-none text-xs font-mono text-slate-900"
              />
            </div>

            <div className="md:col-span-2 space-y-1">
              <label
                htmlFor="fleet-max-workers"
                className="block text-xs font-extrabold text-slate-900"
              >
                Max Workers
              </label>
              <select
                id="fleet-max-workers"
                value={maxWorkers}
                onChange={(e) => setMaxWorkers(Number(e.target.value))}
                className="w-full h-9 px-3 rounded-lg bg-[#f8fafc] border border-slate-300 focus:border-indigo-600 focus:bg-white focus:outline-none text-xs font-mono font-bold text-slate-900"
              >
                {[1, 2, 3, 4, 6, 8].map((w) => (
                  <option key={w} value={w}>
                    {w} worker{w > 1 ? "s" : ""}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-6 flex flex-wrap items-center justify-end gap-2">
              <input
                ref={csvFileInputRef}
                type="file"
                accept=".csv,.txt"
                onChange={(e) => void handleCsvFileUpload(e)}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => csvFileInputRef.current?.click()}
                className="h-9 px-3 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-900 text-xs font-bold flex items-center gap-1.5"
              >
                <Upload className="w-3.5 h-3.5 text-indigo-700" />
                <span>Upload .csv</span>
              </button>

              <button
                type="button"
                onClick={handleInsertSampleCsv}
                className="h-9 px-3 rounded-lg bg-indigo-50 hover:bg-indigo-100 border border-indigo-300 text-indigo-950 text-xs font-extrabold flex items-center gap-1.5"
              >
                <FileCode className="w-3.5 h-3.5 text-indigo-700" />
                <span>Insert Sample Local CSV</span>
              </button>

              <button
                type="button"
                disabled={isRunningFleet || !csvContent.trim()}
                onClick={() => void handleLaunchFleetBatch()}
                className="h-9 px-4 rounded-lg bg-emerald-700 hover:bg-emerald-800 disabled:opacity-50 text-white border border-emerald-800 text-xs font-extrabold flex items-center gap-2 shadow-sm"
              >
                {isRunningFleet ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5 fill-current" />
                )}
                <span>Launch Fleet Batch Scan</span>
              </button>
            </div>
          </div>

          <div className="space-y-1">
            <div className="flex items-center justify-between text-[11px] text-slate-600">
              <span>
                Columns:{" "}
                <span className="font-mono font-bold text-slate-800">
                  repo,app_group,branch,fusion_reports,profile
                </span>
              </span>
              {csvFilename && (
                <span className="font-mono font-bold text-indigo-800">
                  Loaded: {csvFilename}
                </span>
              )}
            </div>
            <textarea
              rows={4}
              value={csvContent}
              onChange={(e) => setCsvContent(e.target.value)}
              aria-label="Fleet CSV manifest content"
              placeholder={
                "repo,app_group,branch,fusion_reports,profile\nC:\\Projects\\service-a,payments,main,,deterministic"
              }
              className="w-full p-3 rounded-lg bg-[#f8fafc] border border-slate-300 focus:border-indigo-600 focus:bg-white focus:outline-none text-xs font-mono text-slate-900 placeholder-slate-500"
            />
          </div>

          {/* Active or Selected Fleet Run Rollup Matrix + Repo Results */}
          {activeFleetRunDisplay && (
            <div className="space-y-4 pt-3 border-t border-slate-200">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-extrabold text-slate-900">
                    Fleet Run: {activeFleetRunDisplay.manifest_name}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-300 text-[10px] font-mono font-bold text-slate-800">
                    {activeFleetRunDisplay.fleet_run_id}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${getRunStatusBadgeClass(
                      activeFleetRunDisplay.status
                    )}`}
                  >
                    {activeFleetRunDisplay.status}
                  </span>
                </div>
                <span className="text-[11px] font-mono text-slate-700">
                  Repos: {activeFleetRunDisplay.completed_repos}/
                  {activeFleetRunDisplay.total_repos} completed (
                  {activeFleetRunDisplay.failed_repos} failed) •{" "}
                  {activeFleetRunDisplay.created_at}
                </span>
              </div>

              {/* App-Group Go-Live Rollup Matrix */}
              {activeFleetRunDisplay.app_rollups.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-extrabold text-slate-900">
                    App-Group Go-Live Rollup Matrix
                  </h4>
                  <div className="overflow-x-auto rounded-lg border border-slate-200">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-mono uppercase text-slate-700">
                          <th className="py-2 px-3">App Group</th>
                          <th className="py-2 px-3">Repos</th>
                          <th className="py-2 px-3">Completed / Failed</th>
                          <th className="py-2 px-3">Critical / High / Total</th>
                          <th className="py-2 px-3">Corroborated</th>
                          <th className="py-2 px-3">EV Confirmed</th>
                          <th className="py-2 px-3">Go-Live Decision</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 bg-white">
                        {activeFleetRunDisplay.app_rollups.map(
                          (rollup: FleetAppGroupRollup) => (
                            <tr key={rollup.app_group}>
                              <td className="py-2 px-3 font-mono font-extrabold text-slate-900">
                                {rollup.app_group}
                              </td>
                              <td className="py-2 px-3 font-mono">
                                {rollup.repo_count}
                              </td>
                              <td className="py-2 px-3 font-mono">
                                <span className="text-emerald-900 font-bold">
                                  {rollup.completed_repos}
                                </span>{" "}
                                /{" "}
                                <span
                                  className={
                                    rollup.failed_repos > 0
                                      ? "text-rose-800 font-bold"
                                      : "text-slate-600"
                                  }
                                >
                                  {rollup.failed_repos}
                                </span>
                              </td>
                              <td className="py-2 px-3 font-mono">
                                <span className="text-rose-800 font-bold">
                                  {rollup.critical_count}
                                </span>{" "}
                                /{" "}
                                <span className="text-amber-900 font-bold">
                                  {rollup.high_count}
                                </span>{" "}
                                /{" "}
                                <span className="text-slate-900 font-extrabold">
                                  {rollup.total_findings}
                                </span>
                              </td>
                              <td className="py-2 px-3 font-mono font-bold text-indigo-900">
                                {rollup.corroborated_count}
                              </td>
                              <td className="py-2 px-3 font-mono font-bold text-rose-900">
                                {rollup.ev_confirmed_count}
                              </td>
                              <td className="py-2 px-3 whitespace-nowrap">
                                <span
                                  className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${getGoLiveBadgeClass(
                                    rollup.go_live_decision
                                  )}`}
                                >
                                  {rollup.go_live_decision}
                                </span>
                              </td>
                            </tr>
                          )
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Per-Repo Results Table */}
              {activeFleetRunDisplay.repo_results.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-extrabold text-slate-900">
                    Per-Repository Execution Results
                  </h4>
                  <div className="overflow-x-auto rounded-lg border border-slate-200">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-mono uppercase text-slate-700">
                          <th className="py-2 px-3">Repository</th>
                          <th className="py-2 px-3">App Group</th>
                          <th className="py-2 px-3">Status</th>
                          <th className="py-2 px-3">Findings (C/H/M/L)</th>
                          <th className="py-2 px-3">Corroborated / EV</th>
                          <th className="py-2 px-3">Go-Live</th>
                          <th className="py-2 px-3">Resumed Stages / Notes</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 bg-white">
                        {activeFleetRunDisplay.repo_results.map((repoRes) => (
                          <tr key={repoRes.run_id || repoRes.repo}>
                            <td className="py-2 px-3 font-mono text-[11px] font-bold text-slate-900">
                              <div className="truncate max-w-xs" title={repoRes.repo}>
                                {repoRes.repo}
                              </div>
                              <div className="text-[10px] text-slate-600 font-normal">
                                {repoRes.run_id} • {repoRes.duration_ms.toFixed(0)} ms
                              </div>
                            </td>
                            <td className="py-2 px-3 font-mono text-slate-800">
                              {repoRes.app_group}
                            </td>
                            <td className="py-2 px-3 whitespace-nowrap">
                              <span
                                className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${getRunStatusBadgeClass(
                                  repoRes.status
                                )}`}
                              >
                                {repoRes.status}
                              </span>
                            </td>
                            <td className="py-2 px-3 font-mono whitespace-nowrap">
                              <span className="font-extrabold text-slate-900">
                                {repoRes.total_findings}
                              </span>{" "}
                              <span className="text-[10px] text-slate-600">
                                ({repoRes.critical_count}/{repoRes.high_count}/
                                {repoRes.medium_count}/{repoRes.low_count})
                              </span>
                            </td>
                            <td className="py-2 px-3 font-mono whitespace-nowrap">
                              {repoRes.corroborated_count} /{" "}
                              {repoRes.ev_confirmed_count}
                            </td>
                            <td className="py-2 px-3 whitespace-nowrap">
                              <span
                                className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${getGoLiveBadgeClass(
                                  repoRes.go_live_decision
                                )}`}
                              >
                                {repoRes.go_live_decision}
                              </span>
                            </td>
                            <td className="py-2 px-3">
                              {repoRes.error ? (
                                <span className="text-[11px] font-mono font-bold text-rose-800">
                                  {repoRes.error}
                                </span>
                              ) : repoRes.resumed_stages.length > 0 ? (
                                <div className="flex flex-wrap gap-1">
                                  {repoRes.resumed_stages.map((st) => (
                                    <span
                                      key={st}
                                      className="px-1.5 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-950 text-[9px] font-mono font-bold"
                                    >
                                      {st}
                                    </span>
                                  ))}
                                </div>
                              ) : (
                                <span className="text-[10px] font-mono text-slate-600">
                                  Fresh Run
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Persisted Fleet Run History List */}
          <div className="pt-3 border-t border-slate-200 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <h4 className="text-xs font-extrabold text-slate-900">
                Persisted Fleet Batch Run History ({fleetRuns.length})
              </h4>
              <button
                type="button"
                disabled={isLoadingFleetRuns}
                onClick={() => void loadFleetRunsAction()}
                className="px-2.5 py-1 rounded-lg bg-[#f8fafc] hover:bg-slate-100 disabled:opacity-50 border border-slate-300 text-slate-800 text-[11px] font-bold flex items-center gap-1"
              >
                <RefreshCw
                  className={`w-3 h-3 text-indigo-700 ${
                    isLoadingFleetRuns ? "animate-spin" : ""
                  }`}
                />
                <span>Refresh History</span>
              </button>
            </div>

            {fleetRuns.length === 0 ? (
              <div className="rounded-lg bg-[#f8fafc] border border-dashed border-slate-300 p-4 text-center text-xs text-slate-600">
                No persisted fleet batch runs yet. Paste or insert a sample CSV
                above and click <span className="font-bold">Launch Fleet Batch Scan</span>.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
                {fleetRuns.map((run) => {
                  const isSelected =
                    activeFleetRunDisplay?.fleet_run_id === run.fleet_run_id;
                  return (
                    <button
                      key={run.fleet_run_id}
                      type="button"
                      onClick={() => setSelectedHistoryRunId(run.fleet_run_id)}
                      className={`text-left p-3 rounded-xl border transition-colors space-y-1 ${
                        isSelected
                          ? "bg-indigo-50/70 border-indigo-400"
                          : "bg-[#f8fafc] border-slate-200 hover:border-slate-300"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-extrabold text-slate-900 truncate">
                          {run.manifest_name}
                        </span>
                        <span
                          className={`px-1.5 py-0.5 rounded border text-[9px] font-mono font-extrabold ${getRunStatusBadgeClass(
                            run.status
                          )}`}
                        >
                          {run.status}
                        </span>
                      </div>
                      <div className="text-[10px] font-mono text-slate-700 flex items-center justify-between gap-2">
                        <span>{run.fleet_run_id}</span>
                        <span>
                          {run.completed_repos}/{run.total_repos} repos
                        </span>
                      </div>
                      <div className="text-[10px] font-mono text-slate-600">
                        {run.created_at}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 4. SQLite Stage Checkpoints (--resume) & Vault Garbage Collection (gc) */}
      {(sectionTab === "ALL" || sectionTab === "CHECKPOINTS_GC") && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
          {/* SQLite Stage Checkpoints */}
          <div className="xl:col-span-8 bg-white border border-slate-300 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-200 pb-3">
              <div>
                <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                  <RotateCcw className="w-4 h-4 text-indigo-700" />
                  <span>
                    SQLite Stage Checkpoints (
                    <span className="font-mono">--resume</span>)
                  </span>
                </h3>
                <p className="text-xs text-slate-600 mt-0.5">
                  Tracks SHA-256 stage payloads and host provenance across{" "}
                  <span className="font-mono">S0_CPG</span>..
                  <span className="font-mono">S9_REPORTS</span> for safe 1-click
                  resumption.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <label className="px-2.5 py-1.5 rounded-lg bg-[#f8fafc] border border-slate-300 text-[11px] font-bold text-slate-800 flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={workspaceOnlyCheckpoints}
                    onChange={(e) =>
                      setWorkspaceOnlyCheckpoints(e.target.checked)
                    }
                    className="accent-indigo-700 w-3.5 h-3.5"
                  />
                  <span>Active Workspace Only</span>
                </label>

                <button
                  type="button"
                  disabled={isLoadingCheckpoints}
                  onClick={() =>
                    void loadFleetCheckpointsAction(
                      workspaceOnlyCheckpoints ? projectPath : undefined
                    )
                  }
                  className="px-3 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 disabled:opacity-50 border border-slate-300 text-slate-900 text-xs font-extrabold flex items-center gap-1.5"
                >
                  <RefreshCw
                    className={`w-3.5 h-3.5 text-indigo-700 ${
                      isLoadingCheckpoints ? "animate-spin" : ""
                    }`}
                  />
                  <span>Refresh Checkpoints</span>
                </button>
              </div>
            </div>

            {resumedNotice && (
              <div className="rounded-xl bg-emerald-50 border border-emerald-300 p-3 text-xs text-emerald-950 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <CheckCircle2 className="w-4 h-4 text-emerald-800 shrink-0" />
                  <span className="font-extrabold">
                    Resumed {resumedNotice.run_id}:
                  </span>
                  <span className="font-mono font-bold">
                    {resumedNotice.status}
                  </span>
                  <span>• {resumedNotice.total_findings} findings</span>
                  {resumedNotice.resumed_stages.length > 0 && (
                    <span className="font-mono text-[11px]">
                      (Skipped/Cached: {resumedNotice.resumed_stages.join(", ")})
                    </span>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => setResumedNotice(null)}
                  aria-label="Dismiss resumed checkpoint notice"
                  className="p-1 rounded hover:bg-emerald-100 text-emerald-900"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            {isLoadingCheckpoints && fleetCheckpoints.length === 0 ? (
              <div className="py-8 flex items-center justify-center gap-2 text-xs font-mono text-slate-700">
                <Loader2 className="w-4 h-4 animate-spin text-indigo-700" />
                <span>Loading SQLite stage checkpoints...</span>
              </div>
            ) : fleetCheckpoints.length === 0 ? (
              <div className="py-8 px-4 text-center rounded-xl border border-dashed border-slate-300 bg-[#f8fafc] text-xs text-slate-700">
                No SQLite stage checkpoints recorded for this view yet. Run a
                fleet batch scan or CLI scan to persist checkpoints.
              </div>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-slate-200">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-mono uppercase text-slate-700">
                      <th className="py-2 px-3">Run / Commit / App</th>
                      <th className="py-2 px-3">Repo Path</th>
                      <th className="py-2 px-3">Status &amp; Provenance</th>
                      <th className="py-2 px-3">Stages</th>
                      <th className="py-2 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 bg-white">
                    {fleetCheckpoints.map((cp) => {
                      const stageMap = new Map(
                        (cp.stages || []).map((st) => [st.stage_name, st])
                      );
                      const orderedStageNames = Array.from(
                        new Set([
                          ...CORE_STAGE_ORDER.filter((s) => stageMap.has(s)),
                          ...(cp.stages || []).map((s) => s.stage_name),
                        ])
                      );
                      const isRowResuming =
                        isResumingCheckpoint && resumingRunId === cp.run_id;

                      return (
                        <tr
                          key={cp.run_id}
                          className="hover:bg-slate-50 transition-colors"
                        >
                          <td className="py-2.5 px-3 align-top font-mono">
                            <div className="text-[11px] font-extrabold text-slate-900">
                              {cp.run_id}
                            </div>
                            <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[10px] text-slate-700">
                              <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-slate-100 border border-slate-300">
                                <GitCommit className="w-2.5 h-2.5" />
                                {cp.commit_sha
                                  ? cp.commit_sha.slice(0, 8)
                                  : "no-sha"}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-950 font-bold">
                                {cp.app_group || "default"}
                              </span>
                            </div>
                          </td>

                          <td className="py-2.5 px-3 align-top font-mono text-[11px] text-slate-800">
                            <div
                              className="truncate max-w-[200px]"
                              title={cp.repo_path}
                            >
                              {cp.repo_path}
                            </div>
                            <div className="text-[10px] text-slate-600 mt-0.5">
                              {cp.updated_at}
                            </div>
                          </td>

                          <td className="py-2.5 px-3 align-top whitespace-nowrap space-y-1">
                            <div>
                              <span
                                className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${getRunStatusBadgeClass(
                                  cp.status
                                )}`}
                              >
                                {cp.status}
                              </span>
                            </div>
                            <div>
                              {cp.host_provenance_valid ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 text-[10px] font-mono font-extrabold">
                                  <ShieldCheck className="w-3 h-3" />
                                  Host Verified
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-50 border border-rose-300 text-rose-950 text-[10px] font-mono font-extrabold">
                                  <ShieldAlert className="w-3 h-3" />
                                  Foreign/Unverified
                                </span>
                              )}
                            </div>
                          </td>

                          <td className="py-2.5 px-3 align-top">
                            <div className="flex flex-wrap gap-1">
                              {orderedStageNames.length > 0 ? (
                                orderedStageNames.map((stName) => {
                                  const st = stageMap.get(stName);
                                  const stStatus = st?.status || "PENDING";
                                  return (
                                    <span
                                      key={stName}
                                      title={`${stName}: ${stStatus} (${(
                                        st?.duration_ms ?? 0
                                      ).toFixed(0)} ms)`}
                                      className={`px-1.5 py-0.5 rounded border text-[9px] font-mono font-extrabold ${getStagePillClass(
                                        stStatus
                                      )}`}
                                    >
                                      {stName}
                                    </span>
                                  );
                                })
                              ) : (
                                <span className="text-[10px] font-mono text-slate-600">
                                  No stage payloads yet
                                </span>
                              )}
                            </div>
                          </td>

                          <td className="py-2.5 px-3 align-top text-right whitespace-nowrap">
                            <button
                              type="button"
                              disabled={isResumingCheckpoint}
                              onClick={() => void handleResumeCheckpoint(cp)}
                              className="px-3 py-1.5 rounded-lg bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white border border-indigo-800 text-[11px] font-extrabold inline-flex items-center gap-1 shadow-sm"
                            >
                              {isRowResuming ? (
                                <Loader2 className="w-3 h-3 animate-spin" />
                              ) : (
                                <RotateCcw className="w-3 h-3" />
                              )}
                              <span>Resume</span>
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Vault Garbage Collection (gc) Panel */}
          <div className="xl:col-span-4 bg-white border border-slate-300 rounded-xl p-5 shadow-sm space-y-4">
            <div className="border-b border-slate-200 pb-3">
              <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                <Trash2 className="w-4 h-4 text-amber-800" />
                <span>
                  Vault Garbage Collection (<span className="font-mono">gc</span>)
                </span>
              </h3>
              <p className="text-xs text-slate-600 mt-0.5">
                Prunes expired SQLite checkpoint runs and orphaned temp CPG
                directories beyond retention limits.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label
                  htmlFor="gc-older-than-days"
                  className="block text-xs font-extrabold text-slate-900"
                >
                  Older Than (Days)
                </label>
                <input
                  id="gc-older-than-days"
                  type="number"
                  min={0}
                  max={3650}
                  value={olderThanDays}
                  onChange={(e) => {
                    const v = Number(e.target.value);
                    setOlderThanDays(Number.isFinite(v) ? v : 0);
                  }}
                  className="w-full h-9 px-3 rounded-lg bg-[#f8fafc] border border-slate-300 focus:border-indigo-600 focus:bg-white focus:outline-none text-xs font-mono font-bold text-slate-900"
                />
              </div>

              <div className="space-y-1">
                <label
                  htmlFor="gc-keep-last"
                  className="block text-xs font-extrabold text-slate-900"
                >
                  Keep Last Runs
                </label>
                <input
                  id="gc-keep-last"
                  type="number"
                  min={0}
                  max={1000}
                  value={keepLast}
                  onChange={(e) => {
                    const v = Number(e.target.value);
                    setKeepLast(Number.isFinite(v) ? v : 0);
                  }}
                  className="w-full h-9 px-3 rounded-lg bg-[#f8fafc] border border-slate-300 focus:border-indigo-600 focus:bg-white focus:outline-none text-xs font-mono font-bold text-slate-900"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={isRunningGc}
                onClick={() => void handleRunGc(true)}
                className="flex-1 h-9 px-3 rounded-lg bg-white hover:bg-slate-100 disabled:opacity-50 text-slate-900 border border-slate-300 text-xs font-extrabold flex items-center justify-center gap-1.5"
              >
                {isRunningGc ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-700" />
                ) : (
                  <Activity className="w-3.5 h-3.5 text-indigo-700" />
                )}
                <span>Dry Run Preview</span>
              </button>

              <button
                type="button"
                disabled={isRunningGc}
                onClick={() => void handleRunGc(false)}
                className="flex-1 h-9 px-3 rounded-lg bg-rose-700 hover:bg-rose-800 disabled:opacity-50 text-white border border-rose-800 text-xs font-extrabold flex items-center justify-center gap-1.5 shadow-sm"
              >
                {isRunningGc ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Trash2 className="w-3.5 h-3.5" />
                )}
                <span>Execute GC</span>
              </button>
            </div>

            {fleetGcReport ? (
              <div className="rounded-xl bg-[#f8fafc] border border-slate-200 p-3.5 space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-extrabold text-slate-900">
                    Retention Report
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded border text-[10px] font-mono font-extrabold ${
                      fleetGcReport.dry_run
                        ? "bg-indigo-50 text-indigo-950 border-indigo-300"
                        : "bg-emerald-700 text-white border-emerald-800"
                    }`}
                  >
                    {fleetGcReport.dry_run ? "DRY RUN PREVIEW" : "GC EXECUTED"}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded-lg bg-white border border-slate-200 p-2">
                    <div className="text-[10px] font-mono uppercase text-slate-600">
                      Pruned Runs
                    </div>
                    <div className="text-sm font-extrabold text-slate-900 font-mono">
                      {fleetGcReport.pruned_runs}
                    </div>
                  </div>
                  <div className="rounded-lg bg-white border border-slate-200 p-2">
                    <div className="text-[10px] font-mono uppercase text-slate-600">
                      Pruned Checkpoints
                    </div>
                    <div className="text-sm font-extrabold text-slate-900 font-mono">
                      {fleetGcReport.pruned_checkpoints}
                    </div>
                  </div>
                  <div className="rounded-lg bg-white border border-slate-200 p-2">
                    <div className="text-[10px] font-mono uppercase text-slate-600">
                      Reclaimed Bytes
                    </div>
                    <div className="text-sm font-extrabold text-emerald-900 font-mono">
                      {formatBytes(fleetGcReport.reclaimed_bytes)}
                    </div>
                  </div>
                  <div className="rounded-lg bg-white border border-slate-200 p-2">
                    <div className="text-[10px] font-mono uppercase text-slate-600">
                      Kept Runs
                    </div>
                    <div className="text-sm font-extrabold text-indigo-900 font-mono">
                      {fleetGcReport.kept_runs}
                    </div>
                  </div>
                </div>

                {fleetGcReport.pruned_temp_dirs > 0 && (
                  <div className="text-[11px] font-mono text-slate-700">
                    Pruned temp CPG dirs: {fleetGcReport.pruned_temp_dirs}
                  </div>
                )}

                {fleetGcReport.warnings.length > 0 && (
                  <div className="text-[11px] font-mono text-amber-950 bg-amber-50 border border-amber-300 rounded p-2 space-y-0.5">
                    {fleetGcReport.warnings.map((w, i) => (
                      <div key={i}>• {w}</div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="rounded-xl border border-dashed border-slate-300 bg-[#f8fafc] p-3.5 text-xs text-slate-700">
                Run <span className="font-bold">Dry Run Preview</span> first to
                inspect candidate checkpoint pruning without modifying disk
                state.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default FleetCommandWorkbench;
