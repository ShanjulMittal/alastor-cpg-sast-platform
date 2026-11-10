"use client";

import React, { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import { StudioCommandHeader } from "@/components/StudioCommandHeader";
import { StudioStatusBar } from "@/components/StudioStatusBar";
import { FrontierAiCopilotDrawer } from "@/components/FrontierAiCopilotDrawer";
import { ActiveApplicationBanner } from "@/components/ActiveApplicationBanner";
import { ResizableSplitPane } from "@/components/ResizableSplitPane";
import { FlawExplorerSidebar } from "@/components/FlawExplorerSidebar";
import { ProjectsHubView } from "@/components/ProjectsHubView";
import { ThreatModelingView } from "@/components/ThreatModelingView";
import { DeepDiveDashboard } from "@/components/DeepDiveDashboard";
import { SastPlusSuiteView } from "@/components/SastPlusSuiteView";
import { RaciGovernanceView } from "@/components/RaciGovernanceView";
import { EngineAccessWorkspace } from "@/components/EngineAccessWorkspace";
import { SettingsCustomizationModal } from "@/components/SettingsCustomizationModal";
import { IntegrationHubModal } from "@/components/IntegrationHubModal";
import { AlastorMythicBackground } from "@/components/AlastorBranding";
import { AlastorPortalGate } from "@/components/AlastorPortalGate";
import QuickCommandModal from "@/components/QuickCommandModal";
import { useKeyboardNavigation } from "@/hooks/useKeyboardNavigation";
import { useAuditStore } from "@/store/useAuditStore";
import { BACKEND_URL } from "@/lib/api";
import {
  AspmSubSection,
  ExtractedAdvisory,
  Finding,
  WorkspaceViewMode,
} from "@/types/cpg";
import {
  Loader2,
  FolderOpen,
  FileText,
  FolderGit2,
  Upload,
  Play,
  GitCompare,
  Network,
  ShieldAlert,
  Sparkles,
  Maximize2,
  BarChart3,
  Package,
  Sliders,
  Users,
  Download,
  FileCode2,
  FileSpreadsheet,
  Globe,
  Ticket,
  Settings,
  CheckCircle2,
  Zap,
  ExternalLink,
} from "lucide-react";

// Dynamically import Monaco Editor and ReactFlow Canvas with SSR disabled
// to guarantee zero hydration mismatches and prevent DOM measurement failures.
const MonacoCodePane = dynamic(
  () => import("@/components/MonacoCodePane").then((mod) => mod.MonacoCodePane),
  {
    ssr: false,
    loading: () => (
      <div className="flex flex-col items-center justify-center h-full bg-[var(--surface-void)] text-[var(--ink-muted)] font-mono text-xs gap-2">
        <Loader2 className="w-5 h-5 animate-spin text-rose-700" />
        <span>Summoning ALASTOR Source &amp; BFL Inspector...</span>
      </div>
    ),
  }
);

const ReactFlowGraphPane = dynamic(
  () =>
    import("@/components/ReactFlowGraphPane").then(
      (mod) => mod.ReactFlowGraphPane
    ),
  {
    ssr: false,
    loading: () => (
      <div className="flex flex-col items-center justify-center h-full bg-[var(--surface-void)] text-[var(--ink-muted)] font-mono text-xs gap-2">
        <Loader2 className="w-5 h-5 animate-spin text-sky-700" />
        <span>Summoning ALASTOR CPG Sigil Canvas...</span>
      </div>
    ),
  }
);

function escapeHtml(val: unknown): string {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeCsvCell(val: unknown): string {
  const s = String(val ?? "").replace(/\r?\n/g, " ");
  if (s.includes(",") || s.includes('"') || s.includes("\n")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function triggerBrowserDownload(
  content: BlobPart,
  mimeType: string,
  filename: string
) {
  const blob = new Blob([content], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export default function AuditPage() {
  useKeyboardNavigation();

  const primaryStage = useAuditStore((s) => s.primaryStage);
  const setPrimaryStage = useAuditStore((s) => s.setPrimaryStage);
  const mapSubTab = useAuditStore((s) => s.mapSubTab);
  const setMapSubTab = useAuditStore((s) => s.setMapSubTab);
  const aspmSubSection = useAuditStore((s) => s.aspmSubSection);
  const setAspmSubSection = useAuditStore((s) => s.setAspmSubSection);

  const workspaceViewMode = useAuditStore((s) => s.workspaceViewMode);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);
  const executiveAspmTab = useAuditStore((s) => s.executiveAspmTab);
  const setExecutiveAspmTab = useAuditStore((s) => s.setExecutiveAspmTab);
  const engineAccessTab = useAuditStore((s) => s.engineAccessTab);
  const setEngineAccessTab = useAuditStore((s) => s.setEngineAccessTab);

  const showPortalGate = useAuditStore((s) => s.showPortalGate);
  const setShowPortalGate = useAuditStore((s) => s.setShowPortalGate);
  const ideLayoutMode = useAuditStore((s) => s.ideLayoutMode);
  const isSidebarCollapsed = useAuditStore((s) => s.isSidebarCollapsed);
  const explorerWidth = useAuditStore((s) => s.explorerWidth);
  const setExplorerWidth = useAuditStore((s) => s.setExplorerWidth);
  const codeGraphRatio = useAuditStore((s) => s.codeGraphRatio);
  const setCodeGraphRatio = useAuditStore((s) => s.setCodeGraphRatio);
  const hydrateUiPreferences = useAuditStore((s) => s.hydrateUiPreferences);

  const projectPath = useAuditStore((s) => s.projectPath);
  const setProjectPath = useAuditStore((s) => s.setProjectPath);
  const triggerScan = useAuditStore((s) => s.triggerScan);
  const isScanning = useAuditStore((s) => s.isScanning);
  const openTargetPicker = useAuditStore((s) => s.openTargetPicker);
  const setTrackChangesPanelOpen = useAuditStore(
    (s) => s.setTrackChangesPanelOpen
  );
  const setGraphFullscreen = useAuditStore((s) => s.setGraphFullscreen);
  const setAiDrawerOpen = useAuditStore((s) => s.setAiDrawerOpen);
  const explainCurrentGraphWithAi = useAuditStore(
    (s) => s.explainCurrentGraphWithAi
  );

  const findings = useAuditStore((s) => s.findings);
  const selectFinding = useAuditStore((s) => s.selectFinding);
  const metrics = useAuditStore((s) => s.metrics);
  const appTree = useAuditStore((s) => s.appTree);
  const sastPlusSuite = useAuditStore((s) => s.sastPlusSuite);
  const raciGovernance = useAuditStore((s) => s.raciGovernance);
  const exportAuditReport = useAuditStore((s) => s.exportAuditReport);
  const setSettingsModalOpen = useAuditStore((s) => s.setSettingsModalOpen);
  const setIntegrationModalOpen = useAuditStore(
    (s) => s.setIntegrationModalOpen
  );

  const lastBatchFixResult = useAuditStore((s) => s.lastBatchFixResult);
  const isBatchFixing = useAuditStore((s) => s.isBatchFixing);
  const batchApplyAllSafeFixes = useAuditStore((s) => s.batchApplyAllSafeFixes);
  const aiVerdictsByFinding = useAuditStore((s) => s.aiVerdictsByFinding);

  const extractedAdvisories = useAuditStore((s) => s.extractedAdvisories);
  const isExtractingIntel = useAuditStore((s) => s.isExtractingIntel);
  const intelStatusMessage = useAuditStore((s) => s.intelStatusMessage);
  const extractAndScanFromSites = useAuditStore(
    (s) => s.extractAndScanFromSites
  );

  const fetchFindings = useAuditStore((s) => s.fetchFindings);
  const fetchMetrics = useAuditStore((s) => s.fetchMetrics);
  const fetchAppTree = useAuditStore((s) => s.fetchAppTree);
  const fetchProjects = useAuditStore((s) => s.fetchProjects);
  const fetchDeepDiveAnalytics = useAuditStore((s) => s.fetchDeepDiveAnalytics);
  const fetchPlatformSettings = useAuditStore((s) => s.fetchPlatformSettings);
  const fetchIntegrations = useAuditStore((s) => s.fetchIntegrations);
  const fetchRaciGovernance = useAuditStore((s) => s.fetchRaciGovernance);
  const fetchSastPlusSuite = useAuditStore((s) => s.fetchSastPlusSuite);
  const fetchTrackChanges = useAuditStore((s) => s.fetchTrackChanges);
  const fetchUserAccounts = useAuditStore((s) => s.fetchUserAccounts);
  const fetchAiConfigState = useAuditStore((s) => s.fetchAiConfigState);

  // Local UI state for Stage 1 Quick Scan bar, Stage 4 Rules/CVE sub-mode, and Export Center feedback
  const [quickScanTarget, setQuickScanTarget] = useState(projectPath);
  const [rulesSubMode, setRulesSubMode] = useState<"ENGINE" | "CVE_INTEL">(
    "ENGINE"
  );
  const [cveCustomUrl, setCveCustomUrl] = useState("");
  const [cveKeyword, setCveKeyword] = useState("");
  const [exportToast, setExportToast] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState<string | null>(null);

  useEffect(() => {
    setQuickScanTarget(projectPath);
  }, [projectPath]);

  useEffect(() => {
    if (
      engineAccessTab === "RULE_PROFILES" ||
      engineAccessTab === "CYPHER_SANITIZERS"
    ) {
      setRulesSubMode("ENGINE");
    }
  }, [engineAccessTab]);

  useEffect(() => {
    hydrateUiPreferences();
    fetchFindings();
    fetchMetrics();
    fetchAppTree();
    fetchProjects();
    fetchDeepDiveAnalytics();
    fetchPlatformSettings();
    fetchIntegrations();
    fetchRaciGovernance();
    fetchSastPlusSuite();
    fetchTrackChanges();
    fetchUserAccounts();
    void fetchAiConfigState();
  }, [
    hydrateUiPreferences,
    fetchFindings,
    fetchMetrics,
    fetchAppTree,
    fetchProjects,
    fetchDeepDiveAnalytics,
    fetchPlatformSettings,
    fetchIntegrations,
    fetchRaciGovernance,
    fetchSastPlusSuite,
    fetchTrackChanges,
    fetchUserAccounts,
    fetchAiConfigState,
  ]);

  const handleEnterApp = (
    mode: WorkspaceViewMode = "REMEDIATION_IDE",
    operator?: { name: string; role: string; email: string }
  ) => {
    setWorkspaceViewMode(mode);
    setShowPortalGate(false, operator);
  };

  if (showPortalGate) {
    return <AlastorPortalGate onEnterApp={handleEnterApp} />;
  }

  const showExportFeedback = (msg: string) => {
    setExportToast(msg);
    setTimeout(() => setExportToast(null), 3500);
  };

  const fetchExportJsonBundle = async (): Promise<{
    project: string;
    metrics: any;
    findings: Finding[];
  }> => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/export/report?format=json`);
      if (res.ok) {
        const data = await res.json();
        return {
          project: data.project || projectPath || "alastor-target",
          metrics: data.metrics || metrics || {},
          findings: Array.isArray(data.findings) ? data.findings : findings,
        };
      }
    } catch {}
    return {
      project: projectPath || "alastor-target",
      metrics: metrics || {},
      findings,
    };
  };

  const handleDownloadHtmlDossier = async () => {
    setIsExporting("html");
    try {
      const bundle = await fetchExportJsonBundle();
      const generatedAt = new Date().toISOString();
      const rowsHtml = bundle.findings
        .map((f) => {
          const sink =
            f.path_nodes && f.path_nodes.length > 0
              ? f.path_nodes[f.path_nodes.length - 1]
              : null;
          const loc = `${f.best_fix_location?.filepath || sink?.filepath || "source"}:L${
            f.best_fix_location?.line || sink?.start_line || 1
          }`;
          const aiV = aiVerdictsByFinding[f.id];
          return `<tr>
            <td><strong>${escapeHtml(f.severity)}</strong></td>
            <td><code>${escapeHtml(f.cwe_id || f.rule_id)}</code></td>
            <td>${escapeHtml(f.scan_engine || "SAST")}</td>
            <td><strong>${escapeHtml(f.title)}</strong><div class="muted">${escapeHtml(
              f.description || ""
            )}</div></td>
            <td><code>${escapeHtml(loc)}</code></td>
            <td>${escapeHtml(
              aiV ? `${aiV.verdict} (${Math.round(aiV.confidence <= 1 ? aiV.confidence * 100 : aiV.confidence)}%)` : f.triage_status || "TO_VERIFY"
            )}</td>
            <td>${escapeHtml(f.remediation || "")}</td>
          </tr>`;
        })
        .join("\n");

      const htmlDoc = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>ALASTOR Executive &amp; Technical Security Audit Dossier</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 32px; line-height: 1.5; }
    .container { max-width: 1180px; margin: 0 auto; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 16px; padding: 32px; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06); }
    h1 { margin: 0 0 6px; font-size: 24px; color: #0f172a; }
    .sub { color: #475569; font-size: 13px; margin-bottom: 24px; }
    .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .kpi { padding: 14px; border-radius: 12px; background: #f8fafc; border: 1px solid #cbd5e1; }
    .kpi .lbl { font-size: 11px; text-transform: uppercase; color: #475569; font-weight: 700; }
    .kpi .val { font-size: 22px; font-weight: 800; color: #0f172a; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { background: #f1f5f9; color: #0f172a; text-align: left; padding: 10px; border-bottom: 2px solid #cbd5e1; }
    td { padding: 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 11px; }
    .muted { color: #475569; font-size: 11px; margin-top: 4px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>ALASTOR • Deterministic CPG-SAST &amp; ASPM Audit Dossier</h1>
    <div class="sub">Target: <code>${escapeHtml(bundle.project)}</code> • Generated: ${escapeHtml(
        generatedAt
      )}</div>
    <div class="kpis">
      <div class="kpi"><div class="lbl">Total Active Findings</div><div class="val">${
        bundle.findings.length
      }</div></div>
      <div class="kpi"><div class="lbl">Critical / High</div><div class="val">${
        bundle.metrics.critical_count ?? 0
      } / ${bundle.metrics.high_count ?? 0}</div></div>
      <div class="kpi"><div class="lbl">CPG Nodes / Edges</div><div class="val">${
        bundle.metrics.total_nodes ?? 0
      } / ${bundle.metrics.total_edges ?? 0}</div></div>
      <div class="kpi"><div class="lbl">SBOM Components</div><div class="val">${
        sastPlusSuite?.total_sbom_components ?? 0
      }</div></div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>CWE / Rule</th>
          <th>Engine</th>
          <th>Finding &amp; Impact</th>
          <th>Chokepoint (BFL)</th>
          <th>Triage / AI Verdict</th>
          <th>Remediation Guidance</th>
        </tr>
      </thead>
      <tbody>
        ${
          rowsHtml ||
          `<tr><td colspan="7">Zero active security findings detected. 100% clean posture verified.</td></tr>`
        }
      </tbody>
    </table>
  </div>
</body>
</html>`;

      triggerBrowserDownload(
        htmlDoc,
        "text/html;charset=utf-8",
        "alastor-executive-audit-dossier.html"
      );
      showExportFeedback("Downloaded Executive HTML Audit Dossier (.html)");
    } finally {
      setIsExporting(null);
    }
  };

  const handleDownloadCsvReport = async () => {
    setIsExporting("csv");
    try {
      const bundle = await fetchExportJsonBundle();
      const headers = [
        "Finding ID",
        "Severity",
        "Engine",
        "Language",
        "Rule ID",
        "CWE ID",
        "CVSS",
        "Title",
        "Filepath",
        "BFL Line",
        "Triage Status",
        "AI Verdict",
        "Remediation",
      ];
      const rows = bundle.findings.map((f) => {
        const sink =
          f.path_nodes && f.path_nodes.length > 0
            ? f.path_nodes[f.path_nodes.length - 1]
            : null;
        const aiV = aiVerdictsByFinding[f.id];
        return [
          f.id,
          f.severity,
          f.scan_engine || "SAST",
          f.language || "",
          f.rule_id,
          f.cwe_id || "",
          f.cvss_score ?? "",
          f.title,
          f.best_fix_location?.filepath || sink?.filepath || "",
          f.best_fix_location?.line || sink?.start_line || 1,
          f.triage_status || "TO_VERIFY",
          aiV ? `${aiV.verdict}` : "",
          f.remediation || "",
        ]
          .map(escapeCsvCell)
          .join(",");
      });

      const csvText = [headers.join(","), ...rows].join("\n");
      triggerBrowserDownload(
        csvText,
        "text/csv;charset=utf-8",
        "alastor-findings-report.csv"
      );
      showExportFeedback("Downloaded Findings Spreadsheet (.csv)");
    } finally {
      setIsExporting(null);
    }
  };

  const handleDownloadSbomJson = async () => {
    setIsExporting("sbom");
    try {
      let cdx = sastPlusSuite?.cyclonedx_json;
      if (!cdx) {
        const res = await fetch(`${BACKEND_URL}/api/sast-plus/suite`);
        if (res.ok) {
          const data = await res.json();
          cdx = data?.cyclonedx_json;
        }
      }
      const payload = cdx || {
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        components: [],
      };
      triggerBrowserDownload(
        JSON.stringify(payload, null, 2),
        "application/json",
        "alastor-sbom-cyclonedx.cdx.json"
      );
      showExportFeedback("Downloaded CycloneDX v1.5 SBOM (.cdx.json)");
    } finally {
      setIsExporting(null);
    }
  };

  const handleDownloadRaciJson = () => {
    const payload = raciGovernance || { activities: [], roles: [] };
    triggerBrowserDownload(
      JSON.stringify(payload, null, 2),
      "application/json",
      "alastor-raci-governance-matrix.json"
    );
    showExportFeedback("Downloaded RACI Governance Matrix (.json)");
  };

  const handleDownloadUnifiedPatch = () => {
    if (!lastBatchFixResult?.unified_diff) return;
    triggerBrowserDownload(
      lastBatchFixResult.unified_diff,
      "text/x-patch;charset=utf-8",
      "alastor-batch-remediation.patch"
    );
    showExportFeedback("Downloaded Unified Remediation Diff (.patch)");
  };

  const aspmPills: Array<{
    id: AspmSubSection;
    label: string;
    icon: React.ReactNode;
    badge?: string | number;
  }> = [
    {
      id: "POSTURE",
      label: "1. Executive Posture & Analytics",
      icon: <BarChart3 className="w-3.5 h-3.5" />,
    },
    {
      id: "SAST_PLUS",
      label: "2. SAST+ Suite, SBOM & Academy",
      icon: <Package className="w-3.5 h-3.5" />,
      badge: sastPlusSuite?.total_sbom_components ?? undefined,
    },
    {
      id: "RULES_ENGINE",
      label: "3. Rules, Cypher & Web CVE Intel",
      icon: <Sliders className="w-3.5 h-3.5" />,
    },
    {
      id: "GOVERNANCE",
      label: "4. Governance, RBAC & Connectors",
      icon: <Users className="w-3.5 h-3.5" />,
    },
    {
      id: "EXPORTS",
      label: "5. Export Center",
      icon: <Download className="w-3.5 h-3.5" />,
      badge: "SARIF / HTML / CSV",
    },
  ];

  const activeRulesEngineTab: "RULE_PROFILES" | "CYPHER_SANITIZERS" =
    engineAccessTab === "CYPHER_SANITIZERS"
      ? "CYPHER_SANITIZERS"
      : "RULE_PROFILES";

  const activeGovernanceTab =
    workspaceViewMode === "ENGINE_ACCESS" &&
    (engineAccessTab === "ACCOUNTS_RBAC" ||
      engineAccessTab === "ISSUE_CONNECTORS")
      ? engineAccessTab
      : "RACI";

  return (
    <div className="relative flex flex-col h-screen w-screen overflow-hidden bg-[var(--surface-void)] text-[var(--ink-primary)] select-none">
      {/* Mythological Sanctuary & Subtle Arcane CPG Watermark */}
      <AlastorMythicBackground />

      {/* 44px Guided 4-Stage Workflow Command Header */}
      <StudioCommandHeader />

      {/* Main 4-Stage Studio Workspace Router (Zero Left Icon Rail Clutter) */}
      <div className="relative z-10 flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
        {/* ================================================================ */}
        {/* STAGE 1: 1. SCAN & REPOS                                         */}
        {/* ================================================================ */}
        {primaryStage === "SCAN_REPOS" && (
          <main className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
            {/* Prominent Quick Target Launcher & Direct Path/GitHub Scan Bar */}
            <div className="px-4 py-2.5 bg-[var(--surface-panel)] border-b border-[var(--border-hairline)] flex items-center justify-between gap-3 flex-wrap shrink-0">
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const clean = quickScanTarget.trim();
                  if (!clean) return;
                  setProjectPath(clean);
                  void triggerScan(clean);
                }}
                className="flex items-center gap-2 flex-1 min-w-[280px] max-w-2xl"
              >
                <input
                  type="text"
                  value={quickScanTarget}
                  onChange={(e) => setQuickScanTarget(e.target.value)}
                  placeholder="Paste local directory path or GitHub repo URL (https://github.com/owner/repo)..."
                  className="flex-1 h-8 bg-white border border-slate-300 rounded-lg px-3 text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-sky-600"
                />
                <button
                  type="submit"
                  disabled={isScanning || !quickScanTarget.trim()}
                  className="h-8 px-3.5 rounded-lg bg-sky-700 hover:bg-sky-800 disabled:opacity-50 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm shrink-0"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Scanning...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Scan Target</span>
                    </>
                  )}
                </button>
              </form>

              <div className="flex items-center gap-1.5 flex-wrap">
                <button
                  type="button"
                  onClick={() => openTargetPicker("FOLDER")}
                  className="h-8 px-2.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-semibold flex items-center gap-1.5"
                >
                  <FolderOpen className="w-3.5 h-3.5 text-sky-700" />
                  <span>Browse Folder</span>
                </button>
                <button
                  type="button"
                  onClick={() => openTargetPicker("FILE")}
                  className="h-8 px-2.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-semibold flex items-center gap-1.5"
                >
                  <FileText className="w-3.5 h-3.5 text-emerald-700" />
                  <span>Single File</span>
                </button>
                <button
                  type="button"
                  onClick={() => openTargetPicker("URL")}
                  className="h-8 px-2.5 rounded-lg bg-indigo-50 hover:bg-indigo-100 border border-indigo-300 text-indigo-900 text-xs font-bold flex items-center gap-1.5"
                >
                  <FolderGit2 className="w-3.5 h-3.5 text-indigo-700" />
                  <span>GitHub Repo (Public / PAT)</span>
                </button>
                <button
                  type="button"
                  onClick={() => openTargetPicker("UPLOAD")}
                  className="h-8 px-2.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-semibold flex items-center gap-1.5"
                >
                  <Upload className="w-3.5 h-3.5 text-amber-700" />
                  <span>Upload / Snippet</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTrackChangesPanelOpen(true)}
                  className="h-8 px-2.5 rounded-lg bg-amber-50 hover:bg-amber-100 border border-amber-300 text-amber-900 text-xs font-bold flex items-center gap-1.5"
                >
                  <GitCompare className="w-3.5 h-3.5 text-amber-700" />
                  <span>Scan History &amp; Δ</span>
                </button>
              </div>
            </div>

            <div className="flex-1 flex min-w-0 min-h-0 overflow-hidden">
              <ProjectsHubView />
            </div>
          </main>
        )}

        {/* ================================================================ */}
        {/* STAGE 2: 2. TRIAGE & FIX                                         */}
        {/* ================================================================ */}
        {primaryStage === "TRIAGE_FIX" && (
          <main className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
            <ActiveApplicationBanner />
            <div className="flex-1 flex min-w-0 min-h-0 overflow-hidden">
              <ResizableSplitPane
                mode="fixed-left"
                leftPx={explorerWidth}
                onChangeLeftPx={setExplorerWidth}
                collapsed={isSidebarCollapsed}
                ariaLabel="Resize Flaw Explorer Sidebar"
                left={<FlawExplorerSidebar />}
                right={
                  ideLayoutMode === "CODE_FOCUS" ? (
                    <MonacoCodePane />
                  ) : ideLayoutMode === "GRAPH_FOCUS" ? (
                    <ReactFlowGraphPane />
                  ) : (
                    <ResizableSplitPane
                      mode="ratio"
                      ratio={codeGraphRatio}
                      onChangeRatio={setCodeGraphRatio}
                      ariaLabel="Resize Code Editor and CPG Graph Split"
                      left={<MonacoCodePane />}
                      right={<ReactFlowGraphPane />}
                    />
                  )
                }
              />
            </div>
          </main>
        )}

        {/* ================================================================ */}
        {/* STAGE 3: 3. 360° MAP & THREATS                                   */}
        {/* ================================================================ */}
        {primaryStage === "MAP_360_THREATS" && (
          <main className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
            {/* Clean 2-Pill Sub-Navigation Bar */}
            <div className="px-4 py-2 bg-[var(--surface-panel)] border-b border-[var(--border-hairline)] flex items-center justify-between gap-2 flex-wrap shrink-0">
              <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded-xl border border-slate-300">
                <button
                  type="button"
                  onClick={() => setMapSubTab("SPIDER_360")}
                  className={`px-3 py-1 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all ${
                    mapSubTab === "SPIDER_360"
                      ? "bg-sky-700 text-white shadow-sm"
                      : "text-slate-700 hover:bg-white hover:text-slate-950"
                  }`}
                >
                  <Network className="w-3.5 h-3.5" />
                  <span>360° Architecture &amp; Call Flows</span>
                </button>

                <button
                  type="button"
                  onClick={() => setMapSubTab("THREAT_BOUNDARIES")}
                  className={`px-3 py-1 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all ${
                    mapSubTab === "THREAT_BOUNDARIES"
                      ? "bg-rose-700 text-white shadow-sm"
                      : "text-slate-700 hover:bg-white hover:text-slate-950"
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Trust Boundaries, STRIDE &amp; PBOM</span>
                </button>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setAiDrawerOpen(true, "GRAPH");
                    void explainCurrentGraphWithAi();
                  }}
                  className="px-3 py-1.5 rounded-lg bg-indigo-700 hover:bg-indigo-800 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Explain Graph / Threat Flow with AI</span>
                </button>

                {mapSubTab === "SPIDER_360" && (
                  <button
                    type="button"
                    onClick={() => setGraphFullscreen(true)}
                    className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-semibold flex items-center gap-1.5"
                  >
                    <Maximize2 className="w-3.5 h-3.5 text-sky-700" />
                    <span>Fullscreen</span>
                  </button>
                )}
              </div>
            </div>

            <div className="flex-1 flex min-w-0 min-h-0 overflow-hidden">
              {mapSubTab === "THREAT_BOUNDARIES" ? (
                <ThreatModelingView />
              ) : (
                <ReactFlowGraphPane />
              )}
            </div>
          </main>
        )}

        {/* ================================================================ */}
        {/* STAGE 4: 4. ASPM, RULES & REPORTS                                */}
        {/* ================================================================ */}
        {primaryStage === "ASPM_GOVERNANCE" && (
          <main className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
            {/* Clean Horizontal 5-Pill ASPM & Governance Sub-Bar */}
            <div className="px-4 py-2 bg-[var(--surface-panel)] border-b border-[var(--border-hairline)] flex items-center justify-between gap-2 flex-wrap shrink-0">
              <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl border border-slate-300 overflow-x-auto max-w-full">
                {aspmPills.map((pill) => {
                  const active = aspmSubSection === pill.id;
                  return (
                    <button
                      key={pill.id}
                      type="button"
                      onClick={() => setAspmSubSection(pill.id)}
                      className={`px-3 py-1 rounded-lg text-xs font-bold flex items-center gap-1.5 whitespace-nowrap transition-all ${
                        active
                          ? "bg-sky-700 text-white shadow-sm"
                          : "text-slate-700 hover:bg-white hover:text-slate-950"
                      }`}
                    >
                      {pill.icon}
                      <span>{pill.label}</span>
                      {pill.badge !== undefined && (
                        <span
                          className={`px-1.5 py-0.1 rounded text-[9px] font-mono font-extrabold ${
                            active
                              ? "bg-sky-800 text-white"
                              : "bg-white text-slate-800 border border-slate-300"
                          }`}
                        >
                          {pill.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setIntegrationModalOpen(true)}
                  className="px-2.5 py-1 rounded-lg bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-semibold flex items-center gap-1.5"
                >
                  <Ticket className="w-3.5 h-3.5 text-amber-700" />
                  <span className="hidden sm:inline">Jira / GitHub Hub</span>
                </button>
                <button
                  type="button"
                  onClick={() => setSettingsModalOpen(true, "PRESETS")}
                  className="px-2.5 py-1 rounded-lg bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-semibold flex items-center gap-1.5"
                >
                  <Settings className="w-3.5 h-3.5 text-sky-700" />
                  <span className="hidden sm:inline">Query Studio</span>
                </button>
              </div>
            </div>

            {/* Active Sub-Section Content */}
            <div className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
              {aspmSubSection === "POSTURE" && (
                <div className="flex-1 overflow-y-auto">
                  <DeepDiveDashboard />
                </div>
              )}

              {aspmSubSection === "SAST_PLUS" && (
                <div className="flex-1 overflow-y-auto">
                  <SastPlusSuiteView />
                </div>
              )}

              {aspmSubSection === "RULES_ENGINE" && (
                <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
                  <div className="px-4 py-1.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap shrink-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <button
                        type="button"
                        onClick={() => {
                          setRulesSubMode("ENGINE");
                          setEngineAccessTab("RULE_PROFILES");
                        }}
                        className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-colors ${
                          rulesSubMode === "ENGINE" &&
                          activeRulesEngineTab === "RULE_PROFILES"
                            ? "bg-sky-700 text-white border-sky-800"
                            : "bg-white text-slate-700 border-slate-300 hover:bg-slate-100"
                        }`}
                      >
                        1. Rule Profiles &amp; 21-Rule Matrix
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setRulesSubMode("ENGINE");
                          setEngineAccessTab("CYPHER_SANITIZERS");
                        }}
                        className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-colors ${
                          rulesSubMode === "ENGINE" &&
                          activeRulesEngineTab === "CYPHER_SANITIZERS"
                            ? "bg-sky-700 text-white border-sky-800"
                            : "bg-white text-slate-700 border-slate-300 hover:bg-slate-100"
                        }`}
                      >
                        2. Sanitizer &amp; Cypher Studio
                      </button>
                      <button
                        type="button"
                        onClick={() => setRulesSubMode("CVE_INTEL")}
                        className={`px-2.5 py-1 rounded-md text-xs font-bold border flex items-center gap-1.5 transition-colors ${
                          rulesSubMode === "CVE_INTEL"
                            ? "bg-indigo-700 text-white border-indigo-800"
                            : "bg-white text-slate-700 border-slate-300 hover:bg-slate-100"
                        }`}
                      >
                        <Globe className="w-3.5 h-3.5" />
                        <span>
                          3. Live Web CVE &amp; Advisory Extractor (
                          {extractedAdvisories.length})
                        </span>
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() =>
                        setSettingsModalOpen(true, "QUERY_VIEWER")
                      }
                      className="px-2.5 py-1 rounded-md bg-white hover:bg-slate-100 border border-slate-300 text-sky-800 text-xs font-bold"
                    >
                      Open Full Cypher Rule Editor Modal
                    </button>
                  </div>

                  {rulesSubMode === "ENGINE" ? (
                    <div className="flex-1 flex min-h-0 overflow-hidden">
                      <EngineAccessWorkspace
                        hideInternalNav
                        activeTabOverride={activeRulesEngineTab}
                      />
                    </div>
                  ) : (
                    <div className="flex-1 overflow-y-auto p-5 space-y-4 select-text">
                      <div className="max-w-5xl mx-auto space-y-4">
                        <form
                          onSubmit={(e) => {
                            e.preventDefault();
                            const urls = cveCustomUrl
                              .split(",")
                              .map((u) => u.trim())
                              .filter(Boolean);
                            void extractAndScanFromSites({
                              sources: ["osv", "nvd", "cisa_owasp"],
                              customUrls: urls,
                              searchQuery: cveKeyword,
                            });
                          }}
                          className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-3"
                        >
                          <div className="flex items-center justify-between gap-2 flex-wrap">
                            <div>
                              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                                <Globe className="w-4 h-4 text-indigo-700" />
                                Live OSV.dev, NIST NVD &amp; MITRE CWE Threat
                                Intelligence Extractor
                              </h3>
                              <p className="text-xs text-slate-600 mt-0.5">
                                Pull live package &amp; CWE advisories from
                                authoritative feeds and match vulnerable
                                patterns directly against your active CPG.
                              </p>
                            </div>
                            <button
                              type="submit"
                              disabled={isExtractingIntel}
                              className="px-4 py-2 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm"
                            >
                              {isExtractingIntel ? (
                                <>
                                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                  <span>Extracting &amp; Matching...</span>
                                </>
                              ) : (
                                <>
                                  <Sparkles className="w-3.5 h-3.5" />
                                  <span>Pull Live CVE Advisories Now</span>
                                </>
                              )}
                            </button>
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <input
                              type="text"
                              value={cveCustomUrl}
                              onChange={(e) => setCveCustomUrl(e.target.value)}
                              placeholder="Optional advisory URL (e.g. https://nvd.nist.gov/vuln/detail/CVE-...)"
                              className="bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono text-slate-900"
                            />
                            <input
                              type="text"
                              value={cveKeyword}
                              onChange={(e) => setCveKeyword(e.target.value)}
                              placeholder="Optional keyword or CWE filter (e.g. CWE-78, SQL injection)"
                              className="bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono text-slate-900"
                            />
                          </div>

                          {intelStatusMessage && (
                            <div className="p-2.5 rounded-lg bg-sky-50 border border-sky-300 text-sky-900 text-xs font-mono">
                              {intelStatusMessage}
                            </div>
                          )}
                        </form>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {extractedAdvisories.map((adv: ExtractedAdvisory) => (
                            <div
                              key={adv.id}
                              className={`p-4 rounded-xl border bg-white space-y-2 ${
                                adv.matched_in_code
                                  ? "border-rose-400 shadow-sm"
                                  : "border-slate-200"
                              }`}
                            >
                              <div className="flex items-center justify-between gap-2">
                                <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-800 border border-rose-300 font-mono text-[10px] font-bold">
                                  {adv.severity} {adv.cwe_id ? `• ${adv.cwe_id}` : ""}
                                </span>
                                <a
                                  href={adv.reference_url}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="text-xs font-mono text-sky-800 hover:underline flex items-center gap-1 font-semibold"
                                >
                                  <span>{adv.source_site}</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </div>
                              <div className="font-bold text-xs text-slate-900">
                                {adv.title}
                              </div>
                              <p className="text-xs text-slate-600 leading-relaxed">
                                {adv.summary}
                              </p>
                              {adv.matched_in_code && (
                                <button
                                  type="button"
                                  onClick={() => {
                                    const match = findings.find(
                                      (f) =>
                                        (adv.cwe_id && f.cwe_id === adv.cwe_id) ||
                                        (adv.matched_files.length > 0 &&
                                          f.path_nodes.some(
                                            (n) =>
                                              n.filepath === adv.matched_files[0]
                                          ))
                                    );
                                    if (match) {
                                      selectFinding(match);
                                    } else {
                                      setPrimaryStage("TRIAGE_FIX");
                                    }
                                  }}
                                  className="px-2.5 py-1 rounded bg-rose-700 hover:bg-rose-800 text-white text-[11px] font-bold"
                                >
                                  Matched in Code ({adv.match_count}) — Inspect in
                                  Triage &amp; Fix
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {aspmSubSection === "GOVERNANCE" && (
                <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
                  <div className="px-4 py-1.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap shrink-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <button
                        type="button"
                        onClick={() => setExecutiveAspmTab("RACI")}
                        className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-colors ${
                          activeGovernanceTab === "RACI"
                            ? "bg-sky-700 text-white border-sky-800"
                            : "bg-white text-slate-700 border-slate-300 hover:bg-slate-100"
                        }`}
                      >
                        1. RACI Accountability Matrix
                      </button>
                      <button
                        type="button"
                        onClick={() => setEngineAccessTab("ACCOUNTS_RBAC")}
                        className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-colors ${
                          activeGovernanceTab === "ACCOUNTS_RBAC"
                            ? "bg-sky-700 text-white border-sky-800"
                            : "bg-white text-slate-700 border-slate-300 hover:bg-slate-100"
                        }`}
                      >
                        2. Multi-Tenant Accounts &amp; RBAC
                      </button>
                      <button
                        type="button"
                        onClick={() => setEngineAccessTab("ISSUE_CONNECTORS")}
                        className={`px-2.5 py-1 rounded-md text-xs font-bold border transition-colors ${
                          activeGovernanceTab === "ISSUE_CONNECTORS"
                            ? "bg-sky-700 text-white border-sky-800"
                            : "bg-white text-slate-700 border-slate-300 hover:bg-slate-100"
                        }`}
                      >
                        3. Jira &amp; GitHub Issue Sync
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() => setIntegrationModalOpen(true)}
                      className="px-2.5 py-1 rounded-md bg-amber-50 hover:bg-amber-100 border border-amber-300 text-amber-900 text-xs font-bold flex items-center gap-1"
                    >
                      <Ticket className="w-3.5 h-3.5 text-amber-700" />
                      <span>Configure Jira / GitHub Connectors</span>
                    </button>
                  </div>

                  {activeGovernanceTab === "RACI" ? (
                    <div className="flex-1 overflow-y-auto">
                      <RaciGovernanceView />
                    </div>
                  ) : (
                    <div className="flex-1 flex min-h-0 overflow-hidden">
                      <EngineAccessWorkspace
                        hideInternalNav
                        activeTabOverride={activeGovernanceTab}
                      />
                    </div>
                  )}
                </div>
              )}

              {aspmSubSection === "EXPORTS" && (
                <div className="flex-1 overflow-y-auto p-6 select-text">
                  <div className="max-w-6xl mx-auto space-y-5">
                    <div className="flex items-center justify-between gap-3 flex-wrap">
                      <div>
                        <h2 className="text-base font-extrabold text-slate-900 flex items-center gap-2">
                          <Download className="w-5 h-5 text-sky-700" />
                          Enterprise Audit &amp; Compliance Export Center
                        </h2>
                        <p className="text-xs text-slate-600 mt-0.5">
                          One-click deliverables for CI/CD SARIF gates, CISO
                          executive briefings, CycloneDX v1.5 SBOM supply-chain
                          attestations, spreadsheets, and unified `.patch`
                          bundles.
                        </p>
                      </div>

                      {exportToast && (
                        <div className="px-3 py-1.5 rounded-xl bg-emerald-50 border border-emerald-300 text-emerald-900 text-xs font-mono font-bold flex items-center gap-1.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                          <span>{exportToast}</span>
                        </div>
                      )}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {/* 1. SARIF v2.1.0 */}
                      <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between space-y-4">
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-300 font-mono text-[10px] font-bold">
                              OASIS STANDARD • CI/CD
                            </span>
                            <FileCode2 className="w-4 h-4 text-emerald-700" />
                          </div>
                          <h3 className="text-sm font-bold text-slate-900">
                            SARIF v2.1.0 Report (`.sarif.json`)
                          </h3>
                          <p className="text-xs text-slate-600 leading-relaxed">
                            GitHub Advanced Security, GitLab SAST, and VS Code
                            SARIF Viewer compatible static analysis output with
                            full CPG codeFlows.
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            void exportAuditReport("sarif");
                            showExportFeedback(
                              "Downloaded OASIS SARIF v2.1.0 Report (.sarif.json)"
                            );
                          }}
                          className="w-full py-2 px-3 rounded-xl bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold flex items-center justify-center gap-1.5 shadow-sm"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Download SARIF v2.1.0</span>
                        </button>
                      </div>

                      {/* 2. Executive HTML Dossier */}
                      <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between space-y-4">
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="px-2 py-0.5 rounded bg-sky-50 text-sky-800 border border-sky-300 font-mono text-[10px] font-bold">
                              PRINTABLE BRIEFING • HTML
                            </span>
                            <Globe className="w-4 h-4 text-sky-700" />
                          </div>
                          <h3 className="text-sm font-bold text-slate-900">
                            Executive HTML Audit Dossier (`.html`)
                          </h3>
                          <p className="text-xs text-slate-600 leading-relaxed">
                            Standalone high-contrast light-mode HTML executive
                            security report with KPI summary cards, BFL
                            chokepoints, and Frontier AI verdicts.
                          </p>
                        </div>
                        <button
                          type="button"
                          disabled={isExporting === "html"}
                          onClick={() => void handleDownloadHtmlDossier()}
                          className="w-full py-2 px-3 rounded-xl bg-sky-700 hover:bg-sky-800 disabled:opacity-50 text-white text-xs font-bold flex items-center justify-center gap-1.5 shadow-sm"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>
                            {isExporting === "html"
                              ? "Generating HTML..."
                              : "Download Executive HTML"}
                          </span>
                        </button>
                      </div>

                      {/* 3. Markdown Audit Report */}
                      <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between space-y-4">
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-800 border border-indigo-300 font-mono text-[10px] font-bold">
                              ENGINEERING • MARKDOWN
                            </span>
                            <FileText className="w-4 h-4 text-indigo-700" />
                          </div>
                          <h3 className="text-sm font-bold text-slate-900">
                            Technical Audit Report (`.md`)
                          </h3>
                          <p className="text-xs text-slate-600 leading-relaxed">
                            PR-ready Markdown security audit report detailing
                            every taint path, affected file/line, CWE mapping,
                            and remediation snippet.
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            void exportAuditReport("markdown");
                            showExportFeedback(
                              "Downloaded Markdown Audit Report (.md)"
                            );
                          }}
                          className="w-full py-2 px-3 rounded-xl bg-indigo-700 hover:bg-indigo-800 text-white text-xs font-bold flex items-center justify-center gap-1.5 shadow-sm"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Download Markdown (.md)</span>
                        </button>
                      </div>

                      {/* 4. CSV Spreadsheet */}
                      <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between space-y-4">
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="px-2 py-0.5 rounded bg-amber-50 text-amber-900 border border-amber-300 font-mono text-[10px] font-bold">
                              GRC &amp; ANALYTICS • CSV
                            </span>
                            <FileSpreadsheet className="w-4 h-4 text-amber-700" />
                          </div>
                          <h3 className="text-sm font-bold text-slate-900">
                            Findings &amp; Triage Spreadsheet (`.csv`)
                          </h3>
                          <p className="text-xs text-slate-600 leading-relaxed">
                            RFC-4180 escaped spreadsheet export of all active
                            findings, CVSS scores, BFL locations, triage states,
                            and AI TP/FP verdicts.
                          </p>
                        </div>
                        <button
                          type="button"
                          disabled={isExporting === "csv"}
                          onClick={() => void handleDownloadCsvReport()}
                          className="w-full py-2 px-3 rounded-xl bg-amber-700 hover:bg-amber-800 disabled:opacity-50 text-white text-xs font-bold flex items-center justify-center gap-1.5 shadow-sm"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Download CSV Spreadsheet</span>
                        </button>
                      </div>

                      {/* 5. CycloneDX v1.5 SBOM */}
                      <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between space-y-4">
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="px-2 py-0.5 rounded bg-sky-50 text-sky-800 border border-sky-300 font-mono text-[10px] font-bold">
                              EO 14028 • SUPPLY CHAIN
                            </span>
                            <Package className="w-4 h-4 text-sky-700" />
                          </div>
                          <h3 className="text-sm font-bold text-slate-900">
                            CycloneDX v1.5 SBOM (`.cdx.json`)
                          </h3>
                          <p className="text-xs text-slate-600 leading-relaxed">
                            Machine-readable Software Bill of Materials listing
                            discovered Python, npm/Node, Go, Rust, and container
                            dependencies.
                          </p>
                        </div>
                        <button
                          type="button"
                          disabled={isExporting === "sbom"}
                          onClick={() => void handleDownloadSbomJson()}
                          className="w-full py-2 px-3 rounded-xl bg-sky-700 hover:bg-sky-800 disabled:opacity-50 text-white text-xs font-bold flex items-center justify-center gap-1.5 shadow-sm"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Download CycloneDX SBOM</span>
                        </button>
                      </div>

                      {/* 6. Unified Batch Remediation .patch */}
                      <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between space-y-4">
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-800 border border-rose-300 font-mono text-[10px] font-bold">
                              GIT APPLY • UNIFIED DIFF
                            </span>
                            <Zap className="w-4 h-4 text-rose-700" />
                          </div>
                          <h3 className="text-sm font-bold text-slate-900">
                            Unified Remediation Patch (`.patch`)
                          </h3>
                          <p className="text-xs text-slate-600 leading-relaxed">
                            {lastBatchFixResult?.unified_diff
                              ? `Ready: ${lastBatchFixResult.applied_count} verified AST fixes (${lastBatchFixResult.verified_severed_count} severed). Compatible with git apply.`
                              : "Run Batch Auto-Fix to generate a syntax-verified multi-file unified diff (.patch) ready for git apply."}
                          </p>
                        </div>
                        {lastBatchFixResult?.unified_diff ? (
                          <button
                            type="button"
                            onClick={handleDownloadUnifiedPatch}
                            className="w-full py-2 px-3 rounded-xl bg-rose-700 hover:bg-rose-800 text-white text-xs font-bold flex items-center justify-center gap-1.5 shadow-sm"
                          >
                            <Download className="w-3.5 h-3.5" />
                            <span>Download Unified .patch</span>
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled={isBatchFixing || findings.length === 0}
                            onClick={() => void batchApplyAllSafeFixes()}
                            className="w-full py-2 px-3 rounded-xl bg-emerald-700 hover:bg-emerald-800 disabled:opacity-50 text-white text-xs font-bold flex items-center justify-center gap-1.5 shadow-sm"
                          >
                            {isBatchFixing ? (
                              <>
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                <span>Generating Safe Fixes...</span>
                              </>
                            ) : (
                              <>
                                <Zap className="w-3.5 h-3.5" />
                                <span>Run Batch Auto-Fix First</span>
                              </>
                            )}
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Secondary JSON Machine Deliverables Strip */}
                    <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-3 flex-wrap">
                      <div className="text-xs text-slate-700">
                        <strong className="text-slate-900">
                          Additional Machine-Readable JSON Bundles:
                        </strong>{" "}
                        Export raw CPG metrics + findings JSON or PMI/COBIT RACI
                        governance assignments.
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            void exportAuditReport("json");
                            showExportFeedback(
                              "Downloaded Full Audit Bundle (.json)"
                            );
                          }}
                          className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 text-xs font-bold flex items-center gap-1.5"
                        >
                          <Download className="w-3.5 h-3.5 text-sky-700" />
                          <span>Full Findings &amp; CPG JSON</span>
                        </button>
                        <button
                          type="button"
                          onClick={handleDownloadRaciJson}
                          className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 text-xs font-bold flex items-center gap-1.5"
                        >
                          <Download className="w-3.5 h-3.5 text-amber-700" />
                          <span>RACI Matrix JSON</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </main>
        )}
      </div>

      {/* 26px Precision Bottom Studio Status Bar */}
      <StudioStatusBar />

      {/* Collapsible Right Frontier AI Copilot BYOK Drawer */}
      <FrontierAiCopilotDrawer />

      {/* Global Studio Modals (Ctrl+K Omnibar, Query/Appearance Modal & Issue Connector Modal) */}
      <QuickCommandModal />
      <SettingsCustomizationModal />
      <IntegrationHubModal />
    </div>
  );
}
