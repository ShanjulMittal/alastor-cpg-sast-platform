"use client";

import React, { useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { GitHubRepoVerifyResponse, ProjectConfig } from "@/types/cpg";
import {
  FolderGit2,
  GitBranch,
  ShieldAlert,
  Flame,
  Plus,
  Settings,
  Webhook,
  CheckCircle2,
  Layers,
  ArrowUpRight,
  Sliders,
  X,
  Clock,
  Eye,
  EyeOff,
  RefreshCw,
  GitCompare,
  Lock,
  Unlock,
  KeyRound,
  Loader2,
  ExternalLink,
  Trash2,
} from "lucide-react";

export function ProjectsHubView() {
  const projects = useAuditStore((s) => s.projects);
  const activateProject = useAuditStore((s) => s.activateProject);
  const createProject = useAuditStore((s) => s.createProject);
  const deleteProject = useAuditStore((s) => s.deleteProject);
  const verifyGitHubRepo = useAuditStore((s) => s.verifyGitHubRepo);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);
  const setSettingsModalOpen = useAuditStore((s) => s.setSettingsModalOpen);
  const setIntegrationModalOpen = useAuditStore((s) => s.setIntegrationModalOpen);
  const isScanning = useAuditStore((s) => s.isScanning);
  const scanProgress = useAuditStore((s) => s.scanProgress);

  const [busyCard, setBusyCard] = useState<{
    id: string;
    action: "VIEW" | "RESCAN" | "OPEN_IDE" | "DELETE";
  } | null>(null);
  const [recentScanNotice, setRecentScanNotice] = useState<{
    projectId: string;
    message: string;
  } | null>(null);

  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [scmProvider, setScmProvider] = useState<"GITHUB" | "GITLAB" | "BITBUCKET" | "LOCAL">("GITHUB");
  const [projName, setProjName] = useState("");
  const [projDescription, setProjDescription] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [defaultBranch, setDefaultBranch] = useState("main");
  const [targetPath, setTargetPath] = useState("");
  const [presetId, setPresetId] = useState("preset-optimized");

  // GitHub Public / Private Import Auth State
  const [isPrivateRepo, setIsPrivateRepo] = useState(false);
  const [authToken, setAuthToken] = useState("");
  const [authUsername, setAuthUsername] = useState("");
  const [saveToken, setSaveToken] = useState(true);
  const [showAuthToken, setShowAuthToken] = useState(false);
  const [runScanImmediately, setRunScanImmediately] = useState(true);
  const [isSubmittingImport, setIsSubmittingImport] = useState(false);
  const [isVerifyingImportRepo, setIsVerifyingImportRepo] = useState(false);
  const [importVerifyResult, setImportVerifyResult] = useState<GitHubRepoVerifyResponse | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  const deriveRepoDisplayName = (rawUrl: string): string => {
    const clean = rawUrl.trim().replace(/\.git$/i, "").replace(/\/+$/, "");
    const parts = clean.split("/").filter(Boolean);
    if (parts.length >= 2) {
      return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
    }
    return parts[parts.length - 1] || "";
  };

  const handleVerifyImportRepo = async () => {
    if (!repoUrl.trim()) {
      setImportError("Paste a repository URL first (e.g. https://github.com/owner/repo).");
      return;
    }
    setImportError(null);
    setIsVerifyingImportRepo(true);
    try {
      const res = await verifyGitHubRepo({
        repo_url: repoUrl.trim(),
        branch: defaultBranch.trim() || undefined,
        auth_token: authToken.trim() || undefined,
        auth_username: authUsername.trim() || undefined,
      });
      setImportVerifyResult(res);
      if (res) {
        if (res.full_name && !projName.trim()) {
          setProjName(res.full_name);
        }
        if (res.default_branch) {
          setDefaultBranch(res.default_branch);
        }
        if (res.is_private === true || (res.requires_auth && !res.accessible)) {
          setIsPrivateRepo(true);
        } else if (res.is_private === false) {
          setIsPrivateRepo(false);
        }
      }
    } finally {
      setIsVerifyingImportRepo(false);
    }
  };

  const handleImportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setImportError(null);

    if (scmProvider === "LOCAL") {
      if (!projName.trim() || !targetPath.trim()) {
        setImportError("Project Display Name and Local Filesystem Path are required.");
        return;
      }
      setIsSubmittingImport(true);
      try {
        const res = await createProject({
          name: projName.trim(),
          description: projDescription.trim() || `Local project directory at ${targetPath.trim()}`,
          scm_provider: "LOCAL",
          repo_url: "",
          branch: defaultBranch || "main",
          target_path: targetPath.trim(),
          preset_id: presetId,
          auto_scan_on_push: false,
          auto_scan_on_pr: false,
          run_scan_immediately: runScanImmediately,
        });
        if (!res.ok) {
          setImportError(res.error || "Failed to register local project.");
          return;
        }
        setProjName("");
        setProjDescription("");
        setTargetPath("");
        setIsImportModalOpen(false);
      } finally {
        setIsSubmittingImport(false);
      }
      return;
    }

    // Remote GitHub / GitLab / Bitbucket Repository Import
    const cleanUrl = repoUrl.trim();
    if (!cleanUrl) {
      setImportError("Please paste the GitHub / Git repository URL.");
      return;
    }
    if (isPrivateRepo && !authToken.trim() && !importVerifyResult?.has_saved_token) {
      setImportError(
        "Private repository selected: please provide a Personal Access Token (ghp_... or github_pat_...)."
      );
      return;
    }

    const effectiveName = projName.trim() || deriveRepoDisplayName(cleanUrl) || "Remote Git Repository";
    setIsSubmittingImport(true);
    try {
      const res = await createProject({
        name: effectiveName,
        description:
          projDescription.trim() ||
          `${isPrivateRepo ? "Private" : "Public"} ${scmProvider} repository (${cleanUrl})`,
        scm_provider: scmProvider,
        repo_url: cleanUrl,
        branch: defaultBranch.trim() || "main",
        target_path: "",
        preset_id: presetId,
        auto_scan_on_push: false,
        auto_scan_on_pr: false,
        is_private_repo: isPrivateRepo,
        auth_token: isPrivateRepo ? authToken.trim() || undefined : undefined,
        auth_username: isPrivateRepo ? authUsername.trim() || undefined : undefined,
        save_token: isPrivateRepo ? saveToken : false,
        run_scan_immediately: runScanImmediately,
      });

      if (!res.ok) {
        if (res.authRequired) {
          setIsPrivateRepo(true);
        }
        setImportError(res.error || "Failed to clone or import remote repository.");
        return;
      }

      setProjName("");
      setProjDescription("");
      setRepoUrl("");
      setAuthToken("");
      setImportVerifyResult(null);
      setIsImportModalOpen(false);
      if (runScanImmediately) {
        setWorkspaceViewMode("DEEP_DIVE");
      }
    } finally {
      setIsSubmittingImport(false);
    }
  };

  const getRiskBadge = (proj: ProjectConfig) => {
    if (!proj.last_scan_at && proj.total_findings === 0) {
      return {
        bg: "bg-[var(--surface-void)] border-[var(--border-subtle)] text-[var(--ink-muted)]",
        bar: "bg-[var(--border-strong)]",
        label: "NOT SCANNED YET",
      };
    }
    switch (proj.risk_level) {
      case "CRITICAL":
        return {
          bg: "bg-red-500/15 border-red-500/40 text-[var(--sev-critical)]",
          bar: "bg-gradient-to-r from-red-600 to-rose-500",
          label: "CRITICAL RISK",
        };
      case "HIGH":
        return {
          bg: "bg-amber-500/15 border-amber-500/40 text-[var(--sev-high)]",
          bar: "bg-gradient-to-r from-amber-500 to-orange-500",
          label: "HIGH RISK",
        };
      case "MEDIUM":
        return {
          bg: "bg-yellow-500/15 border-yellow-500/40 text-[var(--sev-medium)]",
          bar: "bg-gradient-to-r from-yellow-500 to-amber-400",
          label: "MEDIUM RISK",
        };
      case "LOW":
        return {
          bg: "bg-blue-500/15 border-blue-500/40 text-[var(--sev-low)]",
          bar: "bg-gradient-to-r from-blue-500 to-cyan-400",
          label: "LOW RISK",
        };
      default:
        return {
          bg: "bg-emerald-500/15 border-emerald-500/40 text-[var(--sev-safe)]",
          bar: "bg-gradient-to-r from-emerald-500 to-teal-400",
          label: "SECURE (0 FLAWS)",
        };
    }
  };

  const scannedProjects = projects.filter((p) => Boolean(p.last_scan_at) || (p.total_findings || 0) > 0);
  const totalCriticalAcrossPortfolio = projects.reduce((acc, p) => acc + (p.critical_count || 0), 0);
  const totalFindingsAcrossPortfolio = projects.reduce((acc, p) => acc + (p.total_findings || 0), 0);
  const avgPortfolioRisk =
    scannedProjects.length > 0
      ? Math.round(scannedProjects.reduce((acc, p) => acc + (p.risk_score || 0), 0) / scannedProjects.length)
      : 0;

  return (
    <div className="flex-1 h-full overflow-y-auto bg-[var(--surface-void)] p-6 text-[var(--ink-primary)] select-none">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Top Hub Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[var(--surface-panel)] border border-[var(--border-subtle)] rounded-2xl p-5 shadow-lg">
          <div className="flex items-center gap-4">
            <img
              src="/alastor-demon-logo.png"
              alt="Alastor Demon Crest"
              className="w-16 h-16 rounded-2xl border border-amber-500/50 shadow-lg shadow-rose-600/20 object-cover hidden sm:block shrink-0"
            />
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2 py-0.5 rounded-full bg-[var(--sig-crimson)]/15 text-[var(--sig-crimson)] border border-[var(--sig-crimson)]/40 text-[10px] font-mono font-bold uppercase tracking-wider">
                  ALASTOR • GitHub &amp; Local Project Registry
                </span>
                <span className="text-xs text-[var(--ink-muted)] font-mono">
                  • Public URL Paste • Private PAT Auth • On-Disk SAST / SCA / IaC
                </span>
              </div>
              <h1 className="text-xl font-bold tracking-tight text-[var(--ink-primary)] flex items-center gap-2">
                <FolderGit2 className="w-5 h-5 text-[var(--sig-gold)]" />
                Project Management &amp; Security Posture Hub
              </h1>
              <p className="text-xs text-[var(--ink-secondary)] max-w-2xl">
                Import <b className="text-[var(--sev-safe)]">Open / Public GitHub repositories</b> by simply pasting the URL, connect{" "}
                <b className="text-[var(--sig-gold)]">Private repositories</b> with a Personal Access Token, or register local directories on disk.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
            <button
              type="button"
              onClick={() => setSettingsModalOpen(true)}
              className="px-3.5 py-2 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-subtle)] text-[var(--ink-primary)] text-xs font-semibold flex items-center gap-2 transition-colors cursor-pointer"
            >
              <Settings className="w-4 h-4 text-[var(--sig-cyan)]" />
              <span>Scan Presets &amp; Queries</span>
            </button>
            <button
              type="button"
              onClick={() => setIntegrationModalOpen(true)}
              className="px-3.5 py-2 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-subtle)] text-[var(--ink-primary)] text-xs font-semibold flex items-center gap-2 transition-colors cursor-pointer"
            >
              <Sliders className="w-4 h-4 text-[var(--sig-crimson)]" />
              <span>Integration Hub (Jira / GitHub)</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setImportError(null);
                setImportVerifyResult(null);
                setScmProvider("GITHUB");
                setIsImportModalOpen(true);
              }}
              className="px-4 py-2 rounded-xl bg-gradient-to-r from-indigo-600 via-cyan-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white text-xs font-bold flex items-center gap-2 shadow-md transition-all cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>Import GitHub / Local Project</span>
            </button>
          </div>
        </div>

        {/* Portfolio Summary Strip (Strictly Real Scanned Data) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-subtle)] flex items-center justify-between">
            <div>
              <div className="text-[11px] font-mono uppercase text-[var(--ink-muted)]">Registered Directories</div>
              <div className="text-2xl font-bold text-[var(--ink-primary)] mt-1">{projects.length}</div>
              <div className="text-[11px] text-[var(--sev-safe)] mt-0.5 flex items-center gap-1 font-medium">
                <CheckCircle2 className="w-3 h-3" />
                <span>{scannedProjects.length} scanned in session</span>
              </div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center">
              <FolderGit2 className="w-5 h-5 text-[var(--sig-cyan)]" />
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-subtle)] flex items-center justify-between">
            <div>
              <div className="text-[11px] font-mono uppercase text-[var(--ink-muted)]">Scanned Risk Score</div>
              <div className="text-2xl font-bold text-[var(--sev-high)] mt-1">{avgPortfolioRisk} / 100</div>
              <div className="text-[11px] text-[var(--ink-secondary)] mt-0.5">
                {scannedProjects.length > 0 ? "From real scanned projects" : "Run a scan to compute"}
              </div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/40 flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-[var(--sev-high)]" />
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-subtle)] flex items-center justify-between">
            <div>
              <div className="text-[11px] font-mono uppercase text-[var(--ink-muted)]">Critical Flaws</div>
              <div className="text-2xl font-bold text-[var(--sev-critical)] mt-1">
                {totalCriticalAcrossPortfolio}
              </div>
              <div className="text-[11px] text-[var(--ink-secondary)] mt-0.5">
                Across {totalFindingsAcrossPortfolio} real findings
              </div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-red-500/15 border border-red-500/40 flex items-center justify-center">
              <Flame className="w-5 h-5 text-[var(--sev-critical)]" />
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-subtle)] flex items-center justify-between">
            <div>
              <div className="text-[11px] font-mono uppercase text-[var(--ink-muted)]">Active Scan Engines</div>
              <div className="text-lg font-bold text-[var(--sig-cyan)] mt-1 font-mono">
                SAST • SCA • IaC
              </div>
              <div className="text-[11px] text-[var(--ink-secondary)] mt-0.5">
                Tree-Sitter CPG + Manifests + Docker
              </div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-indigo-500/15 border border-indigo-500/40 flex items-center justify-center">
              <Layers className="w-5 h-5 text-indigo-400" />
            </div>
          </div>
        </div>

        {/* Project Cards Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {projects.map((proj) => {
            const isActive = Boolean(proj.is_active);
            const hasScannedBefore =
              Boolean(proj.last_scan_at) ||
              Boolean(proj.has_cached_scan) ||
              (proj.total_findings || 0) > 0;
            const isCardBusy = busyCard?.id === proj.id;
            const isCardScanning =
              (isCardBusy && busyCard?.action === "RESCAN") ||
              (isScanning && isActive);
            const risk = getRiskBadge(proj);

            return (
              <div
                key={proj.id}
                className={`rounded-2xl border p-5 flex flex-col justify-between transition-all ${
                  isActive
                    ? "bg-[var(--surface-panel)] border-[var(--sig-cyan)] shadow-lg ring-1 ring-[var(--sig-cyan)]/40"
                    : "bg-[var(--surface-panel)]/85 border-[var(--border-subtle)] hover:border-[var(--border-strong)]"
                }`}
              >
                <div>
                  {/* Top Row: SCM Badge + Visibility + Risk Enumeration Badge */}
                  <div className="flex items-center justify-between gap-2 mb-3 flex-wrap">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-subtle)] text-[10px] font-mono font-bold text-[var(--sig-cyan)]">
                        {proj.scm_provider}
                      </span>
                      {proj.scm_provider !== "LOCAL" && (
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border flex items-center gap-1 ${
                            proj.is_private_repo
                              ? "bg-amber-500/15 border-amber-500/40 text-[var(--sev-high)]"
                              : "bg-emerald-500/15 border-emerald-500/40 text-[var(--sev-safe)]"
                          }`}
                        >
                          {proj.is_private_repo ? (
                            <>
                              <Lock className="w-2.5 h-2.5" />
                              <span>PRIVATE</span>
                            </>
                          ) : (
                            <>
                              <Unlock className="w-2.5 h-2.5" />
                              <span>PUBLIC</span>
                            </>
                          )}
                        </span>
                      )}
                      {proj.is_private_repo && proj.has_saved_auth && (
                        <span
                          title="Personal Access Token stored in git-ignored local vault for 1-click Re-Scan"
                          className="px-1.5 py-0.5 rounded bg-indigo-500/15 border border-indigo-500/40 text-indigo-400 text-[9px] font-mono font-bold"
                        >
                          AUTH SAVED
                        </span>
                      )}
                      <span className="flex items-center gap-1 text-[11px] font-mono text-[var(--ink-secondary)] bg-[var(--surface-void)] px-2 py-0.5 rounded border border-[var(--border-subtle)]">
                        <GitBranch className="w-3 h-3 text-indigo-400" />
                        {proj.branch}
                      </span>
                      {isActive && (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-[var(--sev-safe)] border border-emerald-500/40 text-[10px] font-mono font-bold">
                          ACTIVE
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-1.5">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${risk.bg}`}
                      >
                        {risk.label} ({proj.risk_score}/100)
                      </span>
                      {proj.id !== "proj-alastor-enterprise" && (
                        <button
                          type="button"
                          disabled={isScanning || Boolean(busyCard)}
                          onClick={async () => {
                            setBusyCard({ id: proj.id, action: "DELETE" });
                            try {
                              await deleteProject(proj.id);
                            } finally {
                              setBusyCard(null);
                            }
                          }}
                          title={`Remove ${proj.name} from project registry`}
                          className="p-1 rounded-lg bg-[var(--surface-void)] hover:bg-red-500/15 text-[var(--ink-muted)] hover:text-[var(--sev-critical)] border border-[var(--border-subtle)] hover:border-red-500/40 transition-colors cursor-pointer disabled:opacity-40"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Project Title, Remote Repo URL & Local Path */}
                  <h2 className="text-base font-bold text-[var(--ink-primary)] flex items-center justify-between">
                    <span className="truncate">{proj.name}</span>
                  </h2>
                  {proj.repo_url && (
                    <a
                      href={proj.repo_url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[11px] font-mono text-indigo-400 hover:text-indigo-300 truncate mt-0.5 flex items-center gap-1"
                      title={proj.repo_url}
                    >
                      <ExternalLink className="w-3 h-3 shrink-0" />
                      <span className="truncate">{proj.repo_url}</span>
                    </a>
                  )}
                  <p className="text-[11px] font-mono text-[var(--ink-muted)] truncate mt-0.5" title={proj.target_path}>
                    {proj.target_path}
                  </p>

                  {/* Live Scan Progress Banner (Shown on Active Scanning Card) */}
                  {isCardScanning && (
                    <div className="mt-2.5 p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/40 space-y-1.5 font-mono">
                      <div className="flex items-center justify-between text-[10px] text-[var(--sig-cyan)] font-bold">
                        <span className="flex items-center gap-1.5 truncate">
                          <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" />
                          <span className="truncate">
                            {scanProgress?.phase || "Compiling 7-Pass CPG + SCA + IaC..."}
                          </span>
                        </span>
                        <span className="shrink-0">{scanProgress?.percent ?? 15}%</span>
                      </div>
                      <div className="w-full h-1.5 rounded-full bg-[var(--surface-void)] overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-cyan-500 to-indigo-500 transition-all duration-300"
                          style={{ width: `${Math.max(10, scanProgress?.percent ?? 20)}%` }}
                        />
                      </div>
                    </div>
                  )}

                  {/* Recent Scan Completion Notice */}
                  {!isCardScanning && recentScanNotice?.projectId === proj.id && (
                    <div className="mt-2.5 p-2 rounded-xl bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-between gap-2 text-[10px] font-mono text-[var(--sev-safe)]">
                      <span className="flex items-center gap-1.5 font-bold truncate">
                        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                        <span className="truncate">{recentScanNotice.message}</span>
                      </span>
                      <button
                        type="button"
                        onClick={() => setWorkspaceViewMode("REMEDIATION_IDE")}
                        className="px-2 py-0.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold shrink-0 cursor-pointer"
                      >
                        Open IDE →
                      </button>
                    </div>
                  )}

                  {/* Last Scanned & Continuous Track Changes Snapshot Card */}
                  <div className="mt-2.5 p-2.5 rounded-xl bg-[var(--surface-void)] border border-amber-500/30 space-y-1.5 font-mono">
                    <div className="flex items-center justify-between gap-2 text-[10px]">
                      <span className="flex items-center gap-1.5 text-[var(--sig-gold)] font-bold">
                        <Clock className="w-3.5 h-3.5 text-[var(--sig-gold)] shrink-0" />
                        {proj.last_scan_at
                          ? `Last Scanned: ${proj.last_scan_at}`
                          : "Status: Not Scanned Yet"}
                      </span>
                      {proj.last_scan_at && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/40 text-[9px] text-[var(--sig-gold)] font-bold">
                          Scan #{proj.scan_count || 1} (Saved)
                        </span>
                      )}
                    </div>

                    {proj.previous_scan_at && (
                      <div className="text-[9px] text-[var(--ink-muted)]">
                        Previous Baseline: <span className="text-[var(--ink-secondary)]">{proj.previous_scan_at}</span>
                      </div>
                    )}

                    {/* Continuous Track Changes Delta Pills */}
                    <div className="flex items-center justify-between gap-1.5 pt-1 border-t border-[var(--border-subtle)] text-[10px]">
                      <span className="flex items-center gap-1 text-indigo-400 font-bold">
                        <GitCompare className="w-3 h-3 text-indigo-400" />
                        Track Changes:
                      </span>
                      <div className="flex items-center gap-1.5">
                        <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/40 text-[var(--sev-safe)] font-bold">
                          ✅ {proj.fixed_since_last_scan ?? 0} Fixed
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/40 text-[var(--sev-high)] font-bold">
                          🆕 {proj.new_since_last_scan ?? 0} New
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-[var(--surface-panel)] border border-[var(--border-subtle)] text-[var(--ink-secondary)]">
                          ⏳ {proj.unchanged_since_last_scan ?? 0} Same
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Risk Meter Progress Bar */}
                  <div className="mt-3 space-y-1">
                    <div className="flex items-center justify-between text-[10px] font-mono">
                      <span className="text-[var(--ink-muted)]">Risk Enumeration Index</span>
                      <span className="text-[var(--ink-primary)] font-bold">{proj.risk_score}%</span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-[var(--surface-void)] overflow-hidden border border-[var(--border-subtle)]">
                      <div
                        className={`h-full rounded-full ${risk.bar}`}
                        style={{ width: `${Math.max(0, Math.min(100, proj.risk_score))}%` }}
                      />
                    </div>
                  </div>

                  {/* Severity Pill Matrix */}
                  <div className="grid grid-cols-4 gap-1.5 mt-3.5 pt-3 border-t border-[var(--border-subtle)] text-center font-mono">
                    <div className="p-1.5 rounded-lg bg-red-500/10 border border-red-500/30">
                      <div className="text-xs font-bold text-[var(--sev-critical)]">{proj.critical_count}</div>
                      <div className="text-[9px] text-[var(--ink-secondary)] uppercase">Critical</div>
                    </div>
                    <div className="p-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30">
                      <div className="text-xs font-bold text-[var(--sev-high)]">{proj.high_count}</div>
                      <div className="text-[9px] text-[var(--ink-secondary)] uppercase">High</div>
                    </div>
                    <div className="p-1.5 rounded-lg bg-yellow-500/10 border border-yellow-500/30">
                      <div className="text-xs font-bold text-[var(--sev-medium)]">{proj.medium_count}</div>
                      <div className="text-[9px] text-[var(--ink-secondary)] uppercase">Medium</div>
                    </div>
                    <div className="p-1.5 rounded-lg bg-blue-500/10 border border-blue-500/30">
                      <div className="text-xs font-bold text-[var(--sev-low)]">{proj.low_count}</div>
                      <div className="text-[9px] text-[var(--ink-secondary)] uppercase">Low</div>
                    </div>
                  </div>

                  {/* Engine Breakdown & Preset Tags */}
                  <div className="mt-3 flex items-center justify-between text-[10px] font-mono text-[var(--ink-secondary)] bg-[var(--surface-void)] px-2.5 py-1.5 rounded-lg border border-[var(--border-subtle)]">
                    <span>
                      SAST: <b className="text-[var(--sig-cyan)]">{proj.sast_count}</b> • SCA:{" "}
                      <b className="text-purple-400">{proj.sca_count}</b> • IaC:{" "}
                      <b className="text-[var(--sig-gold)]">{proj.iac_count}</b>
                    </span>
                    <span>
                      Preset: <b className="text-[var(--sev-safe)]">{proj.preset_id}</b>
                    </span>
                  </div>

                  {/* Cloud SCM Webhook Status Notice (Compact 1-Line Status) */}
                  <div className="mt-2.5 pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between gap-2">
                    <span
                      className="text-[10px] font-mono text-[var(--ink-muted)] flex items-center gap-1 truncate"
                      title="Automatic GitHub/GitLab push & pull_request webhooks require a public ingress tunnel; use Re-Scan & Track on localhost."
                    >
                      <Webhook className="w-3 h-3 text-[var(--sig-gold)] shrink-0" />
                      <span className="truncate">SCM Webhooks (push/PR): Localhost manual trigger</span>
                    </span>
                    <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-[var(--sig-gold)] border border-amber-500/40 text-[9px] font-mono font-bold shrink-0">
                      MANUAL SYNC
                    </span>
                  </div>
                </div>

                {/* Card Footer Actions: View Saved Scan Details (Instant) vs Re-Scan & Track Changes */}
                <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <button
                      type="button"
                      disabled={isScanning || Boolean(busyCard)}
                      onClick={async () => {
                        setRecentScanNotice(null);
                        setBusyCard({ id: proj.id, action: "VIEW" });
                        try {
                          await activateProject(proj.id, !hasScannedBefore);
                          setWorkspaceViewMode("EXECUTIVE_ASPM");
                        } finally {
                          setBusyCard(null);
                        }
                      }}
                      title={
                        hasScannedBefore
                          ? "Open saved scan details & findings immediately in Executive Posture"
                          : "Run initial scan on this repository and open Executive Posture"
                      }
                      className="flex-1 py-2 px-3 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/50 disabled:opacity-50 text-[var(--sig-gold)] font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm transition-colors cursor-pointer"
                    >
                      {isCardBusy && busyCard?.action === "VIEW" ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--sig-gold)]" />
                      ) : (
                        <Eye className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
                      )}
                      <span>
                        {isCardBusy && busyCard?.action === "VIEW"
                          ? hasScannedBefore
                            ? "Opening Posture..."
                            : `Scanning (${scanProgress?.percent ?? 15}%)...`
                          : hasScannedBefore
                          ? "View Last Scan Details"
                          : "Scan & View Details"}
                      </span>
                    </button>

                    <button
                      type="button"
                      disabled={isScanning || Boolean(busyCard)}
                      onClick={async () => {
                        setRecentScanNotice(null);
                        setBusyCard({ id: proj.id, action: "RESCAN" });
                        try {
                          await activateProject(proj.id, true);
                          const refreshed = useAuditStore
                            .getState()
                            .projects.find((p) => p.id === proj.id);
                          setRecentScanNotice({
                            projectId: proj.id,
                            message: `Scan #${refreshed?.scan_count ?? 1} saved (${refreshed?.total_findings ?? useAuditStore.getState().findings.length} findings)`,
                          });
                        } finally {
                          setBusyCard(null);
                        }
                      }}
                      title="Run a fresh compiler scan and compare Fixed vs New findings against the last scan"
                      className="flex-1 py-2 px-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs flex items-center justify-center gap-1.5 shadow-sm transition-colors cursor-pointer"
                    >
                      <RefreshCw
                        className={`w-3.5 h-3.5 ${
                          isCardScanning ? "animate-spin" : ""
                        }`}
                      />
                      <span>
                        {isCardScanning
                          ? `Re-Scanning (${scanProgress?.percent ?? 15}%)...`
                          : "Re-Scan & Track"}
                      </span>
                    </button>
                  </div>

                  <button
                    type="button"
                    disabled={isScanning || Boolean(busyCard)}
                    onClick={async () => {
                      setRecentScanNotice(null);
                      setBusyCard({ id: proj.id, action: "OPEN_IDE" });
                      try {
                        await activateProject(proj.id, !hasScannedBefore);
                        setWorkspaceViewMode("REMEDIATION_IDE");
                      } finally {
                        setBusyCard(null);
                      }
                    }}
                    className="w-full py-2 px-3 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] disabled:opacity-50 text-[var(--ink-primary)] font-semibold text-xs flex items-center justify-center gap-1.5 border border-[var(--border-subtle)] hover:border-[var(--sig-cyan)] transition-colors cursor-pointer"
                  >
                    {isCardBusy && busyCard?.action === "OPEN_IDE" ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--sig-cyan)]" />
                        <span>
                          {hasScannedBefore
                            ? "Loading Saved Scan into Workbench..."
                            : `Scanning & Opening Workbench (${scanProgress?.percent ?? 15}%)...`}
                        </span>
                      </>
                    ) : (
                      <>
                        <span>
                          {hasScannedBefore
                            ? "Open Saved Scan in Remediation IDE"
                            : "Scan & Open in Remediation IDE"}
                        </span>
                        <ArrowUpRight className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Import GitHub (Public URL / Private Token) or Local Project Modal */}
      {isImportModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-zinc-950 border border-zinc-800 rounded-2xl shadow-2xl w-full max-w-2xl overflow-hidden my-auto">
            <div className="px-5 py-4 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FolderGit2 className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-bold text-white">
                  Import GitHub Repository or Local Project
                </span>
              </div>
              <button
                type="button"
                onClick={() => setIsImportModalOpen(false)}
                className="p-1 text-zinc-400 hover:text-white rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleImportSubmit} className="p-5 space-y-4 text-xs max-h-[82vh] overflow-y-auto">
              <div>
                <label className="block text-[11px] font-mono uppercase text-zinc-400 mb-1.5">
                  1. Source Provider
                </label>
                <div className="grid grid-cols-4 gap-2">
                  {(["GITHUB", "GITLAB", "BITBUCKET", "LOCAL"] as const).map((scm) => (
                    <button
                      type="button"
                      key={scm}
                      onClick={() => {
                        setScmProvider(scm);
                        setImportError(null);
                      }}
                      className={`py-2 px-3 rounded-lg border font-mono text-xs font-bold transition-all ${
                        scmProvider === scm
                          ? "bg-cyan-950 border-cyan-500 text-cyan-300"
                          : "bg-zinc-900 border-zinc-800 text-zinc-400 hover:text-zinc-200"
                      }`}
                    >
                      {scm}
                    </button>
                  ))}
                </div>
              </div>

              {importError && (
                <div className="p-3 rounded-xl bg-rose-950/60 border border-rose-700/80 flex items-start gap-2 text-rose-200">
                  <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div className="leading-relaxed">
                    <div className="font-bold text-rose-300">Repository Import / Auth Notice</div>
                    <div className="text-[11px] mt-0.5">{importError}</div>
                  </div>
                </div>
              )}

              {scmProvider !== "LOCAL" ? (
                <>
                  {/* Public vs Private Toggle */}
                  <div>
                    <label className="block text-[11px] font-mono uppercase text-zinc-400 mb-1.5">
                      2. Repository Visibility &amp; Authentication
                    </label>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                      <button
                        type="button"
                        onClick={() => {
                          setIsPrivateRepo(false);
                          setImportError(null);
                        }}
                        className={`p-3 rounded-xl border text-left transition-all flex items-start gap-2.5 ${
                          !isPrivateRepo
                            ? "bg-emerald-950/35 border-emerald-500/80"
                            : "bg-zinc-900/50 border-zinc-800 hover:border-zinc-700"
                        }`}
                      >
                        <Unlock className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                        <div>
                          <div className="font-bold text-zinc-100 flex items-center gap-1.5">
                            <span>Open / Public Repo</span>
                            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700">
                              PASTE URL ONLY
                            </span>
                          </div>
                          <p className="text-[11px] text-zinc-400 mt-0.5">
                            No token required — just paste the URL and clone &amp; scan.
                          </p>
                        </div>
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          setIsPrivateRepo(true);
                          setImportError(null);
                        }}
                        className={`p-3 rounded-xl border text-left transition-all flex items-start gap-2.5 ${
                          isPrivateRepo
                            ? "bg-amber-950/35 border-amber-500/80"
                            : "bg-zinc-900/50 border-zinc-800 hover:border-zinc-700"
                        }`}
                      >
                        <Lock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                        <div>
                          <div className="font-bold text-zinc-100 flex items-center gap-1.5">
                            <span>Private Repo</span>
                            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700">
                              TOKEN REQUIRED
                            </span>
                          </div>
                          <p className="text-[11px] text-zinc-400 mt-0.5">
                            Authenticate securely with a GitHub / GitLab Personal Access Token.
                          </p>
                        </div>
                      </button>
                    </div>
                  </div>

                  {/* Repository URL + Verify Button */}
                  <div>
                    <label className="block text-[11px] font-mono text-zinc-300 mb-1">
                      {scmProvider} Repository URL *
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        required
                        value={repoUrl}
                        onChange={(e) => {
                          const val = e.target.value;
                          setRepoUrl(val);
                          setImportVerifyResult(null);
                          setImportError(null);
                          if (!projName.trim() && val.includes("/")) {
                            const guessed = deriveRepoDisplayName(val);
                            if (guessed) setProjName(guessed);
                          }
                        }}
                        placeholder="https://github.com/owner/repository"
                        className="flex-1 bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 font-mono focus:outline-none focus:border-cyan-500"
                      />
                      <button
                        type="button"
                        disabled={isVerifyingImportRepo || !repoUrl.trim()}
                        onClick={handleVerifyImportRepo}
                        className="px-3 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 border border-zinc-700 text-zinc-200 font-semibold flex items-center gap-1.5 shrink-0"
                      >
                        {isVerifyingImportRepo ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                        ) : (
                          <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                        )}
                        <span>Verify</span>
                      </button>
                    </div>
                  </div>

                  {importVerifyResult && (
                    <div
                      className={`p-2.5 rounded-xl border text-[11px] ${
                        importVerifyResult.accessible
                          ? "bg-emerald-950/30 border-emerald-700/70 text-emerald-200"
                          : "bg-amber-950/40 border-amber-700/80 text-amber-200"
                      }`}
                    >
                      <span className="font-bold font-mono mr-2">
                        {importVerifyResult.is_private === true
                          ? "[PRIVATE 🔒]"
                          : importVerifyResult.is_private === false
                          ? "[PUBLIC 🌐]"
                          : "[REMOTE]"}
                      </span>
                      {importVerifyResult.message}
                    </div>
                  )}

                  {/* Private Repo Token Inputs */}
                  {isPrivateRepo && (
                    <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-700/50 space-y-3">
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                        <div className="sm:col-span-2">
                          <label className="block text-[11px] font-mono text-amber-300 mb-1 flex items-center gap-1.5">
                            <KeyRound className="w-3.5 h-3.5 text-amber-400" />
                            <span>Personal Access Token (PAT) *</span>
                          </label>
                          <div className="relative flex items-center">
                            <input
                              type={showAuthToken ? "text" : "password"}
                              value={authToken}
                              onChange={(e) => {
                                setAuthToken(e.target.value);
                                setImportError(null);
                              }}
                              placeholder={
                                importVerifyResult?.has_saved_token
                                  ? "Saved token found in local vault (leave blank to reuse)"
                                  : "ghp_... or github_pat_... (Contents: Read-only)"
                              }
                              autoComplete="off"
                              className="w-full bg-zinc-950 border border-amber-600/60 rounded-lg pl-3 pr-9 py-2 text-xs text-white font-mono focus:outline-none focus:border-amber-400"
                            />
                            <button
                              type="button"
                              onClick={() => setShowAuthToken((v) => !v)}
                              className="absolute right-2.5 text-zinc-400 hover:text-zinc-200"
                            >
                              {showAuthToken ? (
                                <EyeOff className="w-3.5 h-3.5" />
                              ) : (
                                <Eye className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>

                        <div>
                          <label className="block text-[11px] font-mono text-zinc-300 mb-1">
                            Username (Optional)
                          </label>
                          <input
                            type="text"
                            value={authUsername}
                            onChange={(e) => setAuthUsername(e.target.value)}
                            placeholder="x-access-token"
                            autoComplete="off"
                            className="w-full bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-amber-400"
                          />
                        </div>
                      </div>

                      <label className="flex items-center gap-2 text-xs text-zinc-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={saveToken}
                          onChange={(e) => setSaveToken(e.target.checked)}
                          className="rounded border-zinc-700 bg-zinc-950 text-amber-500"
                        />
                        <span>
                          Save token locally in git-ignored <code>.alastor_vault</code> so <b>Re-Scan &amp; Track</b> works with 1 click
                        </span>
                      </label>
                    </div>
                  )}
                </>
              ) : (
                <div>
                  <label className="block text-[11px] font-mono text-zinc-300 mb-1">
                    Local Filesystem Directory Path *
                  </label>
                  <input
                    type="text"
                    required
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                    placeholder="e.g. C:\Projects\MyService"
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-200 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-mono text-zinc-300 mb-1">
                    Project Display Name {scmProvider === "LOCAL" ? "*" : "(Auto-detected from URL)"}
                  </label>
                  <input
                    type="text"
                    required={scmProvider === "LOCAL"}
                    value={projName}
                    onChange={(e) => setProjName(e.target.value)}
                    placeholder={scmProvider === "LOCAL" ? "Enter project name" : "owner/repository"}
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-mono text-zinc-300 mb-1">
                    Branch / Tag
                  </label>
                  <input
                    type="text"
                    value={defaultBranch}
                    onChange={(e) => setDefaultBranch(e.target.value)}
                    placeholder="main"
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-zinc-300 mb-1">
                  Scan Preset Profile
                </label>
                <select
                  value={presetId}
                  onChange={(e) => setPresetId(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="preset-optimized">
                    ALASTOR Optimized (Default) — SAST + SCA + IaC
                  </option>
                  <option value="preset-high-security">
                    Zero-Trust Comprehensive Audit (All Rules Enabled)
                  </option>
                  <option value="preset-fast-ci">
                    Fast CI/CD Gate (Critical Blockers Only)
                  </option>
                  <option value="preset-owasp-compliance">
                    OWASP Top 10 &amp; PCI-DSS Compliance Benchmark
                  </option>
                </select>
              </div>

              <label className="flex items-center gap-2 text-xs text-cyan-200 cursor-pointer bg-cyan-950/25 border border-cyan-800/60 p-3 rounded-xl">
                <input
                  type="checkbox"
                  checked={runScanImmediately}
                  onChange={(e) => setRunScanImmediately(e.target.checked)}
                  className="rounded border-zinc-700 bg-zinc-900 text-cyan-500"
                />
                <span>
                  <b>{scmProvider === "LOCAL" ? "Run Full CPG Scan Immediately" : "Clone Repository & Run Full CPG + SBOM + STRIDE Scan Immediately"}</b>
                </span>
              </label>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  disabled={isSubmittingImport}
                  onClick={() => setIsImportModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingImport}
                  className={`px-4 py-2 rounded-lg text-white font-bold flex items-center gap-2 ${
                    scmProvider !== "LOCAL" && isPrivateRepo
                      ? "bg-amber-600 hover:bg-amber-500"
                      : "bg-cyan-600 hover:bg-cyan-500"
                  } disabled:opacity-50`}
                >
                  {isSubmittingImport ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>{scmProvider === "LOCAL" ? "Registering..." : "Cloning & Scanning..."}</span>
                    </>
                  ) : (
                    <span>
                      {scmProvider === "LOCAL"
                        ? "Register Local Project"
                        : isPrivateRepo
                        ? "Authenticate, Clone & Import"
                        : "Clone & Import Public Repo"}
                    </span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
