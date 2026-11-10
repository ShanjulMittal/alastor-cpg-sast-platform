"use client";

import React, { useState, useEffect, useRef, useMemo } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  GitHubRepoVerifyResponse,
  PrimaryWorkflowStage,
} from "@/types/cpg";
import { AlastorThemeSwitcher } from "./AlastorBranding";
import { BACKEND_URL } from "@/lib/api";
import {
  ShieldAlert,
  Play,
  Loader2,
  FileCode2,
  FolderOpen,
  FileText,
  Upload,
  ChevronDown,
  CornerLeftUp,
  HardDrive,
  Folder,
  X,
  Sparkles,
  CheckCircle2,
  Settings,
  FolderGit2,
  Code2,
  Search,
  Lock,
  Unlock,
  KeyRound,
  Eye,
  EyeOff,
  GitBranch,
  GitCompare,
  Network,
  BarChart3,
} from "lucide-react";

interface FsEntry {
  name: string;
  path: string;
  is_dir: boolean;
  size_bytes: number;
  extension: string;
  is_code: boolean;
}

interface QuickRoot {
  label: string;
  path: string;
  kind: string;
}

interface FsBrowseData {
  current_path: string;
  parent_path: string | null;
  quick_roots: QuickRoot[];
  directories: FsEntry[];
  files: FsEntry[];
}

export function StudioCommandHeader() {
  const metrics = useAuditStore((s) => s.metrics);
  const appTree = useAuditStore((s) => s.appTree);
  const findings = useAuditStore((s) => s.findings);
  const isScanning = useAuditStore((s) => s.isScanning);
  const scanStatusMessage = useAuditStore((s) => s.scanStatusMessage);
  const scanProgress = useAuditStore((s) => s.scanProgress);
  const projectPath = useAuditStore((s) => s.projectPath);
  const setProjectPath = useAuditStore((s) => s.setProjectPath);
  const projects = useAuditStore((s) => s.projects);
  const activateProject = useAuditStore((s) => s.activateProject);
  const triggerScan = useAuditStore((s) => s.triggerScan);
  const extractAndScanFromSites = useAuditStore(
    (s) => s.extractAndScanFromSites
  );

  // v4 Guided 4-Stage Workflow + Frontier AI Copilot Store Slices
  const primaryStage = useAuditStore((s) => s.primaryStage);
  const setPrimaryStage = useAuditStore((s) => s.setPrimaryStage);
  const isAiDrawerOpen = useAuditStore((s) => s.isAiDrawerOpen);
  const setAiDrawerOpen = useAuditStore((s) => s.setAiDrawerOpen);
  const aiConfig = useAuditStore((s) => s.aiConfig);
  const aiIsBusy = useAuditStore((s) => s.aiIsBusy);

  const trackChanges = useAuditStore((s) => s.trackChanges);
  const isTrackChangesPanelOpen = useAuditStore(
    (s) => s.isTrackChangesPanelOpen
  );
  const setTrackChangesPanelOpen = useAuditStore(
    (s) => s.setTrackChangesPanelOpen
  );

  const platformSettings = useAuditStore((s) => s.platformSettings);
  const fetchPlatformSettings = useAuditStore((s) => s.fetchPlatformSettings);
  const userAccountsState = useAuditStore((s) => s.userAccountsState);
  const fetchUserAccounts = useAuditStore((s) => s.fetchUserAccounts);
  const setSettingsModalOpen = useAuditStore((s) => s.setSettingsModalOpen);
  const setShowPortalGate = useAuditStore((s) => s.setShowPortalGate);
  const setQuickCommandOpen = useAuditStore((s) => s.setQuickCommandOpen);

  const isTargetPickerOpen = useAuditStore((s) => s.isTargetPickerOpen);
  const targetPickerTab = useAuditStore((s) => s.targetPickerTab);
  const gitScanPrefillUrl = useAuditStore((s) => s.gitScanPrefillUrl);
  const gitScanForcePrivateAuth = useAuditStore(
    (s) => s.gitScanForcePrivateAuth
  );
  const gitScanErrorBanner = useAuditStore((s) => s.gitScanErrorBanner);
  const openTargetPicker = useAuditStore((s) => s.openTargetPicker);
  const closeTargetPicker = useAuditStore((s) => s.closeTargetPicker);
  const verifyGitHubRepo = useAuditStore((s) => s.verifyGitHubRepo);

  const [inputPath, setInputPath] = useState(projectPath);

  // Visual Filesystem Browser State
  const [browseData, setBrowseData] = useState<FsBrowseData | null>(null);
  const [isLoadingFs, setIsLoadingFs] = useState(false);
  const [fsFilter, setFsFilter] = useState("");
  const [isNativeDialogOpen, setIsNativeDialogOpen] = useState(false);

  // GitHub Repository & Remote URL Scanner State
  const [urlInput, setUrlInput] = useState("");
  const [repoVisibilityMode, setRepoVisibilityMode] = useState<
    "PUBLIC" | "PRIVATE"
  >("PUBLIC");
  const [repoBranch, setRepoBranch] = useState("");
  const [repoAuthToken, setRepoAuthToken] = useState("");
  const [repoAuthUsername, setRepoAuthUsername] = useState("");
  const [saveRepoToken, setSaveRepoToken] = useState(false);
  const [showRepoToken, setShowRepoToken] = useState(false);
  const [isVerifyingRepo, setIsVerifyingRepo] = useState(false);
  const [verifyResult, setVerifyResult] =
    useState<GitHubRepoVerifyResponse | null>(null);
  const [localGitError, setLocalGitError] = useState<string | null>(null);
  const [autoExtractUrlVulns, setAutoExtractUrlVulns] = useState(false);
  const tokenInputRef = useRef<HTMLInputElement | null>(null);

  // Upload / Snippet State
  const [snippetFilename, setSnippetFilename] = useState("snippet.py");
  const [snippetContent, setSnippetContent] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const fileUploadInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!platformSettings) fetchPlatformSettings();
    if (!userAccountsState) fetchUserAccounts();
  }, [
    platformSettings,
    userAccountsState,
    fetchPlatformSettings,
    fetchUserAccounts,
  ]);

  useEffect(() => {
    setInputPath(projectPath);
  }, [projectPath]);

  useEffect(() => {
    if (gitScanPrefillUrl) {
      setUrlInput(gitScanPrefillUrl);
    }
    if (gitScanForcePrivateAuth) {
      setRepoVisibilityMode("PRIVATE");
      setTimeout(() => {
        tokenInputRef.current?.focus();
      }, 120);
    }
  }, [gitScanPrefillUrl, gitScanForcePrivateAuth]);

  // Auto-load filesystem browser whenever target picker opens on FOLDER or FILE
  useEffect(() => {
    if (
      isTargetPickerOpen &&
      (targetPickerTab === "FOLDER" || targetPickerTab === "FILE") &&
      !browseData &&
      !isLoadingFs
    ) {
      void fetchFsDirectory();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isTargetPickerOpen, targetPickerTab]);

  const resolvedPath = useMemo(() => {
    if (appTree?.root_path) return appTree.root_path;
    if (projectPath) return projectPath;
    const activeProj = projects.find((p) => p.is_active) || projects[0];
    return activeProj?.target_path || "";
  }, [appTree, projectPath, projects]);

  const activeProjectObj = useMemo(() => {
    const normResolved = resolvedPath.replace(/\\/g, "/").toLowerCase();
    return (
      projects.find((p) => p.is_active) ||
      projects.find(
        (p) => p.target_path.replace(/\\/g, "/").toLowerCase() === normResolved
      ) ||
      null
    );
  }, [projects, resolvedPath]);

  const applicationName = useMemo(() => {
    if (resolvedPath) {
      const cleaned = resolvedPath.replace(/[\\/]+$/, "");
      const parts = cleaned.split(/[\\/]/);
      const folderName = parts[parts.length - 1];
      if (folderName && folderName !== ".") {
        return folderName;
      }
    }
    if (activeProjectObj?.name) {
      return activeProjectObj.name;
    }
    return "cpg-sast-platform";
  }, [resolvedPath, activeProjectObj]);

  const fetchFsDirectory = async (dirPath?: string) => {
    setIsLoadingFs(true);
    try {
      const q = dirPath ? `?path=${encodeURIComponent(dirPath)}` : "";
      const res = await fetch(`${BACKEND_URL}/api/fs/browse${q}`);
      if (res.ok) {
        const data: FsBrowseData = await res.json();
        setBrowseData(data);
      }
    } catch (err) {
      console.error("Failed to browse filesystem:", err);
    } finally {
      setIsLoadingFs(false);
    }
  };

  const openPickerModal = (tab: "FOLDER" | "FILE" | "URL" | "UPLOAD") => {
    openTargetPicker(tab);
    if (tab === "FOLDER" || tab === "FILE") {
      void fetchFsDirectory(browseData?.current_path);
    }
  };

  const handleVerifyGitHubRepo = async () => {
    const clean = urlInput.trim();
    if (!clean) {
      setLocalGitError(
        "Paste a GitHub repository URL first (e.g. https://github.com/owner/repo)."
      );
      return;
    }
    setLocalGitError(null);
    setIsVerifyingRepo(true);
    try {
      const vRes = await verifyGitHubRepo({
        repo_url: clean,
        branch: repoBranch.trim() || undefined,
        auth_token: repoAuthToken.trim() || undefined,
        auth_username: repoAuthUsername.trim() || undefined,
      });
      setVerifyResult(vRes);
      if (vRes) {
        if (vRes.requires_auth && !vRes.accessible) {
          setRepoVisibilityMode("PRIVATE");
          setTimeout(() => tokenInputRef.current?.focus(), 100);
        } else if (
          vRes.is_private === false &&
          repoVisibilityMode !== "PRIVATE"
        ) {
          setRepoVisibilityMode("PUBLIC");
        }
        if (vRes.default_branch && !repoBranch.trim()) {
          setRepoBranch(vRes.default_branch);
        }
      }
    } finally {
      setIsVerifyingRepo(false);
    }
  };

  const handleScanGitHubRepo = async (
    overrideUrl?: string,
    forcePublicSample = false
  ) => {
    const rawTarget = (overrideUrl ?? urlInput).trim();
    if (!rawTarget) {
      setLocalGitError("Please paste a GitHub repository URL to scan.");
      return;
    }
    setLocalGitError(null);

    const effectiveMode = forcePublicSample
      ? "AUTO"
      : repoVisibilityMode === "PRIVATE"
      ? "PRIVATE"
      : "AUTO";
    const trimmedTok = forcePublicSample ? "" : repoAuthToken.trim();
    const hasSavedForThisRepo = Boolean(
      verifyResult?.has_saved_token && verifyResult?.normalized_url
    );

    if (effectiveMode === "PRIVATE" && !trimmedTok && !hasSavedForThisRepo) {
      setLocalGitError(
        "Private repository selected: please enter your GitHub Personal Access Token (ghp_... or github_pat_... with Contents: Read-only)."
      );
      tokenInputRef.current?.focus();
      return;
    }

    setInputPath(rawTarget);
    closeTargetPicker();

    const scanOutcome = await triggerScan(rawTarget, {
      branch: forcePublicSample ? undefined : repoBranch.trim() || undefined,
      repo_visibility: effectiveMode,
      auth_token: trimmedTok || undefined,
      auth_username: forcePublicSample
        ? undefined
        : repoAuthUsername.trim() || undefined,
      save_token: forcePublicSample ? false : saveRepoToken,
    });

    if (scanOutcome.ok && autoExtractUrlVulns && rawTarget.startsWith("http")) {
      await extractAndScanFromSites({
        sources: ["osv", "nvd", "cisa_owasp"],
        customUrls: [rawTarget],
      });
    } else if (!scanOutcome.ok && scanOutcome.authRequired) {
      setRepoVisibilityMode("PRIVATE");
      setLocalGitError(
        scanOutcome.error ||
          "Authentication required for this private repository."
      );
    }
  };

  const handleSelectAndScan = async (
    target: string,
    alsoExtractSiteUrl?: string
  ) => {
    const clean = target.trim();
    if (!clean) return;
    setInputPath(clean);
    setProjectPath(clean);
    closeTargetPicker();
    const outcome = await triggerScan(clean);
    if (
      outcome.ok &&
      alsoExtractSiteUrl &&
      alsoExtractSiteUrl.startsWith("http")
    ) {
      await extractAndScanFromSites({
        sources: ["osv", "nvd", "cisa_owasp"],
        customUrls: [alsoExtractSiteUrl],
      });
    }
  };

  const handleNativeOsDialog = async (
    mode: "folder" | "file",
    autoScanAfterPick = false
  ) => {
    setIsNativeDialogOpen(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/fs/native-dialog`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode,
          initial_dir: browseData?.current_path || undefined,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (!data.cancelled && data.selected_path) {
          setInputPath(data.selected_path);
          setProjectPath(data.selected_path);
          if (autoScanAfterPick) {
            closeTargetPicker();
            await triggerScan(data.selected_path);
          }
        }
      }
    } catch (err) {
      console.error("Native OS dialog error:", err);
    } finally {
      setIsNativeDialogOpen(false);
    }
  };

  const handleBrowserFileUpload = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;
    setIsUploading(true);
    try {
      const payloadFiles: { filepath: string; content: string }[] = [];
      for (let i = 0; i < Math.min(fileList.length, 60); i++) {
        const f = fileList[i];
        if (f.size > 1024 * 1024) continue;
        const text = await f.text();
        const relPath = (f as any).webkitRelativePath || f.name;
        payloadFiles.push({ filepath: relPath, content: text });
      }
      if (payloadFiles.length === 0) return;

      const batchName =
        fileList.length === 1
          ? fileList[0].name.replace(/[^a-zA-Z0-9._-]/g, "_")
          : "uploaded_project";
      const res = await fetch(`${BACKEND_URL}/api/scan/upload`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_name: batchName,
          files: payloadFiles,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.target_path) {
          await handleSelectAndScan(data.target_path);
        }
      }
    } catch (err) {
      console.error("Failed to upload files for scan:", err);
    } finally {
      setIsUploading(false);
      if (fileUploadInputRef.current) fileUploadInputRef.current.value = "";
    }
  };

  const handleScanSnippet = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!snippetContent.trim()) return;
    setIsUploading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/scan/upload`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_name: "live_snippet_workspace",
          files: [
            {
              filepath: snippetFilename.trim() || "snippet.py",
              content: snippetContent,
            },
          ],
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.target_path) {
          await handleSelectAndScan(data.target_path);
        }
      }
    } catch (err) {
      console.error("Snippet scan error:", err);
    } finally {
      setIsUploading(false);
    }
  };

  const showProgress =
    isScanning || Boolean(scanProgress && scanProgress.is_scanning);
  const percent = scanProgress?.percent ?? (isScanning ? 10 : 0);
  const currentPass =
    scanProgress?.current_pass || (isScanning ? "Pass 1/7 • CPG Scan" : "");
  const filesDone = scanProgress?.files_done ?? 0;
  const totalScanFiles = scanProgress?.total_files ?? 0;
  const progressMessage = scanProgress?.message || scanStatusMessage || "";

  const fixedCount =
    trackChanges?.fixed_count ?? activeProjectObj?.fixed_since_last_scan ?? 0;
  const newCount =
    trackChanges?.new_count ??
    activeProjectObj?.new_since_last_scan ??
    findings.filter(
      (f) => f.change_status === "NEW" || f.change_status === "REOPENED"
    ).length;

  const aiTelemetry = aiConfig?.token_telemetry;
  const aiRequests = aiTelemetry?.total_requests ?? 0;
  const aiSavingsPct =
    aiTelemetry?.overall_savings_pct ?? aiTelemetry?.savings_pct ?? 0;
  const isAiReady =
    Boolean(aiConfig?.has_api_key) ||
    aiConfig?.provider === "openai_compatible";

  const filteredDirs = (browseData?.directories || []).filter(
    (d) =>
      !fsFilter.trim() ||
      d.name.toLowerCase().includes(fsFilter.toLowerCase())
  );
  const filteredFiles = (browseData?.files || []).filter(
    (f) =>
      !fsFilter.trim() ||
      f.name.toLowerCase().includes(fsFilter.toLowerCase())
  );

  const workflowStages: Array<{
    id: PrimaryWorkflowStage;
    label: string;
    shortLabel: string;
    icon: React.ReactNode;
    badge?: string | number;
    hint: string;
  }> = [
    {
      id: "SCAN_REPOS",
      label: "1. Scan & Repos",
      shortLabel: "1. Scan",
      icon: <FolderGit2 className="w-3.5 h-3.5 shrink-0" />,
      badge: projects.length || undefined,
      hint: "Target Acquisition, Projects Hub, GitHub Clone & Scan Snapshots",
    },
    {
      id: "TRIAGE_FIX",
      label: "2. Triage & Fix",
      shortLabel: "2. Triage",
      icon: <Code2 className="w-3.5 h-3.5 shrink-0" />,
      badge: findings.length,
      hint: "Flaw Explorer, Batch Auto-Fix, Monaco BFL DiffEditor & CPG Path",
    },
    {
      id: "MAP_360_THREATS",
      label: "3. 360° Map & Threats",
      shortLabel: "3. 360° Map",
      icon: <Network className="w-3.5 h-3.5 shrink-0" />,
      hint: "Full-Screen 360° Architecture & Call Flows + STRIDE Trust Boundaries",
    },
    {
      id: "ASPM_GOVERNANCE",
      label: "4. ASPM, Rules & Reports",
      shortLabel: "4. ASPM & Export",
      icon: <BarChart3 className="w-3.5 h-3.5 shrink-0" />,
      hint: "Executive Posture, SBOM, Rule Engine, RBAC/Jira & Export Center",
    },
  ];

  return (
    <>
      <header
        aria-label="ALASTOR Guided 4-Stage Workflow Header"
        className="h-11 px-3 bg-[var(--surface-panel)] border-b border-[var(--border-hairline)] text-[var(--ink-primary)] flex items-center justify-between gap-2 select-none relative z-50 shrink-0"
      >
        {/* LEFT CLUSTER: [Ἀ] Crest + Active Repo Selector */}
        <div className="flex items-center gap-2 min-w-0 shrink-0">
          <button
            type="button"
            onClick={() => setShowPortalGate(true)}
            title="Return to Launch Hub (Ἀλάστωρ Portal Gate)"
            className="group flex items-center gap-2 pr-1.5 py-1 rounded-lg hover:bg-[var(--surface-elevated)] transition-colors"
          >
            <span className="w-7 h-7 rounded-lg bg-rose-700 text-white border border-rose-800 flex items-center justify-center shadow-sm">
              <span className="font-display font-bold text-xs leading-none">
                Ἀ
              </span>
            </span>
            <span className="font-display font-extrabold text-xs tracking-[0.14em] text-[var(--ink-primary)] hidden sm:inline">
              ALASTOR
            </span>
          </button>

          <div className="h-4 w-px bg-[var(--border-hairline)] hidden md:block" />

          {/* Active Repository Selector Pill + Saved Snapshot Quick Switcher */}
          <div className="hidden md:flex items-center gap-1 min-w-0">
            <button
              type="button"
              onClick={() => openPickerModal("FOLDER")}
              title={`Active Target: ${
                resolvedPath || applicationName
              } — Click to browse local folders, single files, GitHub repos, or upload code`}
              className="h-7 px-2.5 rounded-md bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] text-xs font-semibold text-[var(--ink-primary)] flex items-center gap-1.5 transition-colors max-w-[175px]"
            >
              <FolderOpen className="w-3.5 h-3.5 text-sky-700 shrink-0" />
              <span className="font-mono text-[11px] truncate">
                {applicationName}
              </span>
              <ChevronDown className="w-3 h-3 text-[var(--ink-muted)] shrink-0" />
            </button>

            {projects.length > 1 && (
              <select
                aria-label="Quick switch saved project snapshot"
                value={activeProjectObj?.id || ""}
                onChange={(e) => {
                  if (e.target.value) {
                    void activateProject(e.target.value, false);
                  }
                }}
                disabled={isScanning}
                title="Switch active repository using cached scan snapshot (no re-scan required)"
                className="hidden 2xl:block h-7 bg-white border border-[var(--border-hairline)] hover:border-sky-600 rounded-md px-1.5 text-[10px] font-mono text-[var(--ink-primary)] focus:outline-none cursor-pointer max-w-[125px]"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    Repo: {p.name}
                  </option>
                ))}
              </select>
            )}
          </div>
        </div>

        {/* CENTER CLUSTER: Guided 4-Stage Workflow Bar */}
        <nav
          aria-label="Guided 4-Stage Security Workflow"
          className="flex items-center bg-slate-100 border border-slate-300 rounded-xl p-0.5 gap-0.5 overflow-x-auto min-w-0"
        >
          {workflowStages.map((st) => {
            const active = primaryStage === st.id;
            return (
              <button
                key={st.id}
                type="button"
                onClick={() => setPrimaryStage(st.id)}
                title={st.hint}
                className={`h-7 px-2.5 rounded-lg text-[11px] font-bold flex items-center gap-1.5 whitespace-nowrap transition-all ${
                  active
                    ? "bg-sky-700 text-white shadow-sm"
                    : "text-slate-700 hover:bg-white hover:text-slate-950"
                }`}
              >
                {st.icon}
                <span className="hidden xl:inline">{st.label}</span>
                <span className="xl:hidden">{st.shortLabel}</span>
                {st.badge !== undefined && (
                  <span
                    className={`px-1.5 py-0.1 rounded text-[9px] font-mono font-extrabold ${
                      active
                        ? "bg-sky-800 text-white"
                        : st.id === "TRIAGE_FIX" && Number(st.badge) > 0
                        ? "bg-rose-100 text-rose-800 border border-rose-300"
                        : "bg-slate-200 text-slate-800"
                    }`}
                  >
                    {st.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* RIGHT CLUSTER: Scan Progress / Quick Scan + Δ Track + ⌘K + Settings + Theme + ✨ Frontier AI Copilot */}
        <div className="flex items-center gap-1.5 shrink-0">
          {/* Active 7-Pass Scan Progress Pill OR Compact Scan Trigger */}
          {showProgress ? (
            <div
              title={progressMessage || currentPass}
              className="relative h-7 px-2.5 rounded-md bg-sky-50 border border-sky-400 text-[10px] font-mono text-sky-950 flex items-center gap-1.5 overflow-hidden min-w-[148px]"
            >
              <Loader2 className="w-3.5 h-3.5 animate-spin text-sky-700 shrink-0" />
              <span className="truncate font-bold max-w-[110px]">
                {currentPass}
              </span>
              {totalScanFiles > 0 && (
                <span className="text-sky-800 hidden 2xl:inline">
                  {filesDone}/{totalScanFiles}
                </span>
              )}
              <span className="font-extrabold text-sky-800 ml-auto">
                {percent}%
              </span>
              <div
                className="absolute bottom-0 left-0 h-[2px] bg-sky-700 transition-all duration-200"
                style={{ width: `${Math.max(4, Math.min(100, percent))}%` }}
              />
            </div>
          ) : (
            <button
              type="button"
              onClick={() =>
                void handleSelectAndScan(
                  inputPath || resolvedPath || projectPath
                )
              }
              title="Run 7-Pass Deterministic CPG Scan on active target"
              className="h-7 px-2.5 rounded-md bg-emerald-700 hover:bg-emerald-800 text-white text-[11px] font-bold flex items-center gap-1.5 transition-colors shadow-sm shrink-0"
            >
              <Play className="w-3 h-3 fill-current" />
              <span className="hidden sm:inline">Scan</span>
            </button>
          )}

          {/* Track Changes Delta Badge */}
          <button
            type="button"
            onClick={() => setTrackChangesPanelOpen(!isTrackChangesPanelOpen)}
            title="Toggle Saved Scan Snapshot & Track Changes Comparison"
            className={`hidden 2xl:flex items-center gap-1 h-7 px-2 rounded-md border text-[10px] font-mono font-bold transition-colors ${
              isTrackChangesPanelOpen
                ? "bg-amber-700 text-white border-amber-800"
                : "bg-white hover:bg-slate-50 border-[var(--border-hairline)] text-slate-800"
            }`}
          >
            <GitCompare className="w-3 h-3" />
            <span>
              +{fixedCount}F / +{newCount}N
            </span>
          </button>

          {/* Ctrl+K Quick Command Trigger */}
          <button
            type="button"
            onClick={() => setQuickCommandOpen(true)}
            title="Open Command Palette & Fuzzy Search (Ctrl+K)"
            className="h-7 px-2 rounded-md bg-white hover:bg-slate-50 border border-[var(--border-hairline)] text-[11px] font-mono font-bold text-slate-700 hover:text-slate-950 flex items-center gap-1 transition-colors"
          >
            <Search className="w-3.5 h-3.5 text-sky-700" />
            <span className="hidden lg:inline">⌘K</span>
          </button>

          {/* Settings & Customization Modal Trigger */}
          <button
            type="button"
            onClick={() => setSettingsModalOpen(true, "PRESETS")}
            title="Open Scan Presets, Cypher Studio, Sanitizers & Appearance Settings"
            className="h-7 px-2 rounded-md bg-white hover:bg-slate-50 border border-[var(--border-hairline)] text-slate-700 hover:text-slate-950 flex items-center justify-center transition-colors"
          >
            <Settings className="w-3.5 h-3.5 text-slate-700" />
          </button>

          {/* Light Daylight Theme Switcher */}
          <AlastorThemeSwitcher />

          {/* Prominent ✨ Frontier AI Copilot Button */}
          <button
            type="button"
            onClick={() =>
              setAiDrawerOpen(
                !isAiDrawerOpen,
                isAiReady ? "VALIDATE" : "SETTINGS"
              )
            }
            title="Open Frontier AI BYOK Copilot Drawer (Validate TP/FP, Code Audit, AI Patch & Graph Story)"
            className={`h-7 px-2.5 rounded-md text-white text-[11px] font-bold flex items-center gap-1.5 shadow-sm transition-colors shrink-0 ${
              isAiDrawerOpen
                ? "bg-indigo-800 ring-2 ring-indigo-300"
                : "bg-indigo-700 hover:bg-indigo-800"
            }`}
          >
            {aiIsBusy ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Sparkles className="w-3.5 h-3.5" />
            )}
            <span>Frontier AI</span>
            <span className="hidden sm:inline px-1.5 py-0.1 rounded bg-indigo-800 text-white font-mono text-[9px] font-extrabold">
              {aiRequests > 0
                ? `${Math.round(aiSavingsPct)}% Saved`
                : isAiReady
                ? "READY"
                : "BYOK"}
            </span>
          </button>
        </div>
      </header>

      {/* INTERACTIVE TARGET PICKER & GITHUB REPOSITORY SCANNER MODAL */}
      {isTargetPickerOpen && (
        <div className="fixed inset-0 z-[200] bg-slate-900/45 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
          <div className="bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[var(--ink-primary)] rounded-2xl shadow-2xl w-full max-w-4xl overflow-hidden flex flex-col h-[620px] max-h-[88vh] my-auto">
            {/* Modal Header & Mode Tabs */}
            <div className="px-4 py-3 bg-[var(--surface-elevated)] border-b border-[var(--border-hairline)] flex items-center justify-between flex-wrap gap-2 shrink-0">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-amber-700" />
                <span className="text-xs font-bold uppercase tracking-wider text-[var(--ink-primary)]">
                  Select Scan Target (Folder, File, GitHub Public/Private Repo,
                  or Snippet)
                </span>
              </div>

              <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-300 flex-wrap">
                <button
                  type="button"
                  onClick={() => {
                    openTargetPicker("FOLDER");
                    if (!browseData) void fetchFsDirectory();
                  }}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition-colors ${
                    targetPickerTab === "FOLDER"
                      ? "bg-sky-700 text-white shadow-sm"
                      : "text-slate-700 hover:text-slate-950"
                  }`}
                >
                  <FolderOpen className="w-3.5 h-3.5" />
                  <span>1. Folder Browser</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    openTargetPicker("FILE");
                    if (!browseData) void fetchFsDirectory();
                  }}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition-colors ${
                    targetPickerTab === "FILE"
                      ? "bg-emerald-700 text-white shadow-sm"
                      : "text-slate-700 hover:text-slate-950"
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>2. Single File</span>
                </button>
                <button
                  type="button"
                  onClick={() => openTargetPicker("URL")}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition-colors ${
                    targetPickerTab === "URL"
                      ? "bg-indigo-700 text-white shadow-sm"
                      : "text-slate-700 hover:text-slate-950"
                  }`}
                >
                  <FolderGit2 className="w-3.5 h-3.5" />
                  <span>3. GitHub Repo / URL</span>
                </button>
                <button
                  type="button"
                  onClick={() => openTargetPicker("UPLOAD")}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold transition-colors ${
                    targetPickerTab === "UPLOAD"
                      ? "bg-amber-700 text-white shadow-sm"
                      : "text-slate-700 hover:text-slate-950"
                  }`}
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>4. Upload / Paste Code</span>
                </button>
              </div>

              <button
                type="button"
                onClick={closeTargetPicker}
                className="p-1.5 text-slate-700 hover:text-slate-950 rounded-md bg-white hover:bg-slate-100 border border-slate-300"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* TAB 1 & TAB 2: VISUAL FOLDER & FILE EXPLORER */}
            {(targetPickerTab === "FOLDER" || targetPickerTab === "FILE") && (
              <div className="flex flex-1 min-h-0 overflow-hidden">
                {/* Left Sidebar: Quick-Access Discovered Projects & Drives */}
                <div className="w-64 border-r border-[var(--border-hairline)] bg-[var(--surface-void)] p-3 flex flex-col gap-2 overflow-y-auto">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--ink-muted)] font-semibold px-1">
                    Quick-Select Projects &amp; Drives
                  </div>

                  <button
                    type="button"
                    disabled={isNativeDialogOpen}
                    onClick={() =>
                      void handleNativeOsDialog(
                        targetPickerTab === "FILE" ? "file" : "folder",
                        true
                      )
                    }
                    className="w-full py-2 px-2.5 rounded-lg bg-sky-700 hover:bg-sky-800 disabled:opacity-50 text-white text-xs font-bold flex items-center justify-center gap-1.5 shadow-sm transition-all"
                  >
                    {isNativeDialogOpen ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>Opening OS Dialog...</span>
                      </>
                    ) : (
                      <>
                        <FolderOpen className="w-3.5 h-3.5" />
                        <span>
                          Open Windows{" "}
                          {targetPickerTab === "FILE" ? "File" : "Folder"}{" "}
                          Dialog
                        </span>
                      </>
                    )}
                  </button>

                  <div className="border-t border-[var(--border-hairline)] my-1" />

                  {(browseData?.quick_roots || []).map((qr) => (
                    <div
                      key={qr.path}
                      className="group flex items-center justify-between gap-1 rounded-md px-2 py-1.5 hover:bg-white text-xs transition-colors"
                    >
                      <button
                        type="button"
                        onClick={() => void fetchFsDirectory(qr.path)}
                        className="flex items-center gap-2 text-left truncate flex-1 text-[var(--ink-primary)] font-medium"
                        title={qr.path}
                      >
                        {qr.kind === "drive" ? (
                          <HardDrive className="w-3.5 h-3.5 text-amber-700 shrink-0" />
                        ) : qr.kind === "project" ? (
                          <FolderOpen className="w-3.5 h-3.5 text-sky-700 shrink-0" />
                        ) : (
                          <Folder className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                        )}
                        <span className="truncate">{qr.label}</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleSelectAndScan(qr.path)}
                        className="opacity-0 group-hover:opacity-100 px-2 py-0.5 rounded bg-sky-700 hover:bg-sky-800 text-white text-[10px] font-bold shrink-0 transition-opacity"
                      >
                        Scan
                      </button>
                    </div>
                  ))}
                </div>

                {/* Right Pane: Interactive Directory & File Navigator */}
                <div className="flex-1 flex flex-col overflow-hidden bg-[var(--surface-panel)]">
                  <div className="p-3 border-b border-[var(--border-hairline)] bg-[var(--surface-elevated)] flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0 flex-1">
                      <button
                        type="button"
                        disabled={!browseData?.parent_path || isLoadingFs}
                        onClick={() =>
                          browseData?.parent_path &&
                          void fetchFsDirectory(browseData.parent_path)
                        }
                        title="Up One Directory"
                        className="p-1.5 rounded bg-white hover:bg-slate-100 border border-slate-300 disabled:opacity-40 text-slate-800 shrink-0"
                      >
                        <CornerLeftUp className="w-3.5 h-3.5" />
                      </button>
                      <div className="px-2.5 py-1 rounded bg-white border border-slate-300 font-mono text-xs text-sky-800 font-semibold truncate flex-1">
                        {browseData?.current_path || "Loading..."}
                      </div>
                    </div>

                    <input
                      type="text"
                      value={fsFilter}
                      onChange={(e) => setFsFilter(e.target.value)}
                      placeholder="Filter folders/files..."
                      className="w-40 bg-white border border-slate-300 rounded px-2.5 py-1 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-sky-600"
                    />

                    {targetPickerTab === "FOLDER" &&
                      browseData?.current_path && (
                        <button
                          type="button"
                          onClick={() =>
                            void handleSelectAndScan(browseData.current_path)
                          }
                          className="px-3 py-1.5 rounded-md bg-sky-700 hover:bg-sky-800 text-white text-xs font-bold flex items-center gap-1.5 shrink-0 shadow-sm"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Scan Current Folder</span>
                        </button>
                      )}
                  </div>

                  {/* Directory & File Listing */}
                  <div className="flex-1 overflow-y-auto p-3 space-y-1">
                    {isLoadingFs ? (
                      <div className="flex items-center justify-center h-48 text-[var(--ink-muted)] text-xs gap-2">
                        <Loader2 className="w-4 h-4 animate-spin text-sky-700" />
                        <span>Loading directory contents...</span>
                      </div>
                    ) : (
                      <>
                        {filteredDirs.length > 0 && (
                          <div className="mb-3">
                            <div className="text-[10px] font-mono uppercase text-[var(--ink-muted)] mb-1 px-2">
                              Folders ({filteredDirs.length}) — Click folder
                              name to open, or click &quot;Scan&quot;
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                              {filteredDirs.map((dir) => (
                                <div
                                  key={dir.path}
                                  className="flex items-center justify-between p-2 rounded-lg border border-[var(--border-hairline)] bg-white hover:border-sky-500 transition-all group"
                                >
                                  <button
                                    type="button"
                                    onClick={() =>
                                      void fetchFsDirectory(dir.path)
                                    }
                                    className="flex items-center gap-2 min-w-0 flex-1 text-left"
                                  >
                                    <Folder className="w-4 h-4 text-sky-700 shrink-0" />
                                    <span className="text-xs font-mono text-[var(--ink-primary)] font-medium truncate">
                                      {dir.name}
                                    </span>
                                  </button>
                                  <div className="flex items-center gap-1 shrink-0">
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setInputPath(dir.path);
                                        setProjectPath(dir.path);
                                        closeTargetPicker();
                                      }}
                                      className="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-800 text-[10px] font-semibold"
                                    >
                                      Select
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        void handleSelectAndScan(dir.path)
                                      }
                                      className="px-2 py-0.5 rounded bg-sky-700 hover:bg-sky-800 text-white text-[10px] font-bold flex items-center gap-1"
                                    >
                                      <Play className="w-2.5 h-2.5 fill-current" />
                                      <span>Scan</span>
                                    </button>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        <div>
                          <div className="text-[10px] font-mono uppercase text-[var(--ink-muted)] mb-1 px-2">
                            Files in Folder ({filteredFiles.length}) — Select
                            any single file to scan directly
                          </div>
                          {filteredFiles.length === 0 ? (
                            <div className="text-xs text-[var(--ink-muted)] px-2 py-4 font-mono">
                              No files in this directory. Navigate into a
                              subfolder above.
                            </div>
                          ) : (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                              {filteredFiles.map((file) => (
                                <div
                                  key={file.path}
                                  className={`flex items-center justify-between p-2 rounded-lg border transition-all ${
                                    file.is_code
                                      ? "border-emerald-300 bg-emerald-50/40 hover:border-emerald-500"
                                      : "border-[var(--border-hairline)] bg-white"
                                  }`}
                                >
                                  <div className="flex items-center gap-2 min-w-0 flex-1">
                                    <FileCode2
                                      className={`w-4 h-4 shrink-0 ${
                                        file.is_code
                                          ? "text-emerald-700"
                                          : "text-slate-500"
                                      }`}
                                    />
                                    <div className="min-w-0">
                                      <div className="text-xs font-mono text-[var(--ink-primary)] font-medium truncate">
                                        {file.name}
                                      </div>
                                      <div className="text-[10px] font-mono text-[var(--ink-muted)]">
                                        {(file.size_bytes / 1024).toFixed(1)} KB{" "}
                                        {file.is_code && (
                                          <span className="text-emerald-800 font-semibold ml-1">
                                            • CPG Supported
                                          </span>
                                        )}
                                      </div>
                                    </div>
                                  </div>

                                  <div className="flex items-center gap-1 shrink-0">
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setInputPath(file.path);
                                        setProjectPath(file.path);
                                        closeTargetPicker();
                                      }}
                                      className="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-800 text-[10px] font-semibold"
                                    >
                                      Select
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        void handleSelectAndScan(file.path)
                                      }
                                      className="px-2 py-0.5 rounded bg-emerald-700 hover:bg-emerald-800 text-white text-[10px] font-bold flex items-center gap-1"
                                    >
                                      <Play className="w-2.5 h-2.5 fill-current" />
                                      <span>Scan File</span>
                                    </button>
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 3: GITHUB REPOSITORY (OPEN/PUBLIC OR PRIVATE AUTH) & REMOTE URL SCANNER */}
            {targetPickerTab === "URL" && (
              <div className="p-5 space-y-4 bg-[var(--surface-panel)] flex-1 overflow-y-auto">
                <div>
                  <h3 className="text-sm font-bold text-[var(--ink-primary)] flex items-center gap-2">
                    <FolderGit2 className="w-4 h-4 text-indigo-700" />
                    GitHub Repository &amp; Remote Source Scanner
                  </h3>
                  <p className="text-xs text-[var(--ink-muted)] mt-0.5">
                    For <b className="text-emerald-800">Open / Public</b>{" "}
                    repositories, simply paste the GitHub URL and click{" "}
                    <b>Clone &amp; Scan</b>. For{" "}
                    <b className="text-amber-800">Private</b> repositories,
                    provide a GitHub Personal Access Token (
                    <code>Contents: Read-only</code>).
                  </p>
                </div>

                {/* Visibility Mode Selector */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <button
                    type="button"
                    onClick={() => {
                      setRepoVisibilityMode("PUBLIC");
                      setLocalGitError(null);
                    }}
                    className={`p-3 rounded-xl border text-left transition-all flex items-start gap-2.5 ${
                      repoVisibilityMode === "PUBLIC"
                        ? "bg-emerald-50/70 border-emerald-500 shadow-sm"
                        : "bg-white border-slate-200 hover:bg-slate-50"
                    }`}
                  >
                    <div className="p-1.5 rounded-lg border border-emerald-400 text-emerald-700 shrink-0 bg-white">
                      <Unlock className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                        <span>Open / Public Repository</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-900 border border-emerald-300 font-bold">
                          NO TOKEN
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-600 mt-0.5">
                        Paste any public GitHub / GitLab repo, branch tree, or
                        raw file URL and scan immediately.
                      </p>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setRepoVisibilityMode("PRIVATE");
                      setLocalGitError(null);
                      setTimeout(() => tokenInputRef.current?.focus(), 80);
                    }}
                    className={`p-3 rounded-xl border text-left transition-all flex items-start gap-2.5 ${
                      repoVisibilityMode === "PRIVATE"
                        ? "bg-amber-50/70 border-amber-500 shadow-sm"
                        : "bg-white border-slate-200 hover:bg-slate-50"
                    }`}
                  >
                    <div className="p-1.5 rounded-lg border border-amber-400 text-amber-800 shrink-0 bg-white">
                      <Lock className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                        <span>Private Repository</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-100 text-amber-900 border border-amber-300 font-bold">
                          AUTH REQUIRED
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-600 mt-0.5">
                        Authenticate securely with a GitHub Fine-Grained or
                        Classic Personal Access Token.
                      </p>
                    </div>
                  </button>
                </div>

                {/* Error Banner */}
                {(localGitError || gitScanErrorBanner) && (
                  <div className="p-3 rounded-xl bg-rose-50 border border-rose-300 flex items-start gap-2.5 text-xs text-rose-950">
                    <ShieldAlert className="w-4 h-4 text-rose-700 shrink-0 mt-0.5" />
                    <div className="flex-1 leading-relaxed">
                      <div className="font-bold text-rose-800">
                        Repository Access / Authentication Required
                      </div>
                      <div className="text-[11px] text-rose-900 mt-0.5">
                        {localGitError || gitScanErrorBanner}
                      </div>
                    </div>
                  </div>
                )}

                {/* Repo URL + Branch + Verify + Scan Controls */}
                <div className="space-y-2.5 bg-slate-50 border border-slate-200 rounded-xl p-3.5">
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
                    <div className="md:col-span-8">
                      <label className="block text-[11px] font-mono font-bold text-slate-800 mb-1">
                        GitHub Repository or Source URL *
                      </label>
                      <input
                        type="text"
                        value={urlInput}
                        onChange={(e) => {
                          setUrlInput(e.target.value);
                          setVerifyResult(null);
                          setLocalGitError(null);
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            void handleScanGitHubRepo();
                          }
                        }}
                        placeholder="https://github.com/owner/repository (or /tree/branch)"
                        className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono text-slate-900 focus:outline-none focus:border-indigo-600"
                      />
                    </div>
                    <div className="md:col-span-4">
                      <label className="block text-[11px] font-mono font-bold text-slate-800 mb-1 flex items-center gap-1">
                        <GitBranch className="w-3 h-3 text-indigo-700" />
                        <span>Branch / Tag (Optional)</span>
                      </label>
                      <input
                        type="text"
                        value={repoBranch}
                        onChange={(e) => setRepoBranch(e.target.value)}
                        placeholder="default (e.g. main)"
                        className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono text-slate-900 focus:outline-none focus:border-indigo-600"
                      />
                    </div>
                  </div>

                  {/* Private Repository Auth Panel */}
                  {repoVisibilityMode === "PRIVATE" && (
                    <div className="pt-2 mt-2 border-t border-slate-200 space-y-2.5">
                      <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
                        <div className="md:col-span-8">
                          <label className="block text-[11px] font-mono font-bold text-amber-900 mb-1 flex items-center justify-between">
                            <span className="flex items-center gap-1.5">
                              <KeyRound className="w-3.5 h-3.5 text-amber-700" />
                              <span>Personal Access Token (PAT) *</span>
                            </span>
                            <span className="text-[10px] text-slate-600 font-normal">
                              Scope: Contents (Read-only) or repo
                            </span>
                          </label>
                          <div className="relative flex items-center">
                            <input
                              ref={tokenInputRef}
                              type={showRepoToken ? "text" : "password"}
                              value={repoAuthToken}
                              onChange={(e) => {
                                setRepoAuthToken(e.target.value);
                                setLocalGitError(null);
                              }}
                              placeholder={
                                verifyResult?.has_saved_token
                                  ? "Saved token detected in local vault (leave blank to reuse)"
                                  : "ghp_... or github_pat_... (Required for private repos)"
                              }
                              autoComplete="off"
                              className="w-full bg-white border border-amber-400 rounded-lg pl-3 pr-9 py-2 text-xs font-mono text-slate-900 focus:outline-none focus:border-amber-600"
                            />
                            <button
                              type="button"
                              onClick={() => setShowRepoToken((v) => !v)}
                              title={
                                showRepoToken ? "Hide token" : "Show token"
                              }
                              className="absolute right-2.5 text-slate-500 hover:text-slate-900"
                            >
                              {showRepoToken ? (
                                <EyeOff className="w-3.5 h-3.5" />
                              ) : (
                                <Eye className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>

                        <div className="md:col-span-4">
                          <label className="block text-[11px] font-mono font-bold text-slate-800 mb-1">
                            Auth Username (Optional)
                          </label>
                          <input
                            type="text"
                            value={repoAuthUsername}
                            onChange={(e) =>
                              setRepoAuthUsername(e.target.value)
                            }
                            placeholder="x-access-token (auto)"
                            autoComplete="off"
                            className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono text-slate-900 focus:outline-none focus:border-amber-600"
                          />
                        </div>
                      </div>

                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <label className="flex items-center gap-2 text-xs text-slate-800 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={saveRepoToken}
                            onChange={(e) => setSaveRepoToken(e.target.checked)}
                            className="accent-amber-700"
                          />
                          <span>
                            Save token in local git-ignored vault (
                            <code>.alastor_vault</code>) for 1-click{" "}
                            <b>Re-Scan &amp; Track Changes</b>
                          </span>
                        </label>
                        <span className="text-[10px] font-mono text-emerald-800 font-semibold">
                          Passed via ephemeral Git HTTP header — never stored in
                          clone URL
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Action Buttons Row */}
                  <div className="flex items-center justify-between flex-wrap gap-2 pt-1">
                    <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={autoExtractUrlVulns}
                        onChange={(e) =>
                          setAutoExtractUrlVulns(e.target.checked)
                        }
                        className="accent-indigo-700"
                      />
                      <span>
                        Also correlate live OSV/NVD advisories after scan
                      </span>
                    </label>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={isVerifyingRepo || !urlInput.trim()}
                        onClick={() => void handleVerifyGitHubRepo()}
                        className="px-3 py-2 rounded-lg bg-white hover:bg-slate-100 disabled:opacity-50 border border-slate-300 text-slate-800 text-xs font-bold flex items-center gap-1.5 transition-colors"
                      >
                        {isVerifyingRepo ? (
                          <>
                            <Loader2 className="w-3.5 h-3.5 animate-spin text-sky-700" />
                            <span>Verifying...</span>
                          </>
                        ) : (
                          <>
                            <CheckCircle2 className="w-3.5 h-3.5 text-sky-700" />
                            <span>Verify Repo Access</span>
                          </>
                        )}
                      </button>

                      <button
                        type="button"
                        disabled={isScanning || !urlInput.trim()}
                        onClick={() => void handleScanGitHubRepo()}
                        className={`px-4 py-2 rounded-lg text-white text-xs font-bold flex items-center gap-1.5 shadow-sm transition-colors disabled:opacity-50 ${
                          repoVisibilityMode === "PRIVATE"
                            ? "bg-amber-700 hover:bg-amber-800"
                            : "bg-indigo-700 hover:bg-indigo-800"
                        }`}
                      >
                        {repoVisibilityMode === "PRIVATE" ? (
                          <Lock className="w-3.5 h-3.5" />
                        ) : (
                          <Play className="w-3.5 h-3.5 fill-current" />
                        )}
                        <span>
                          {repoVisibilityMode === "PRIVATE"
                            ? "Authenticate, Clone & Scan"
                            : "Clone & Scan Repo"}
                        </span>
                      </button>
                    </div>
                  </div>
                </div>

                {/* Live Pre-Flight Verification Result Card */}
                {verifyResult && (
                  <div
                    className={`p-3 rounded-xl border text-xs flex items-start justify-between gap-3 flex-wrap ${
                      verifyResult.accessible
                        ? "bg-emerald-50 border-emerald-300"
                        : "bg-amber-50 border-amber-300"
                    }`}
                  >
                    <div className="space-y-1 min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold font-mono text-slate-900">
                          {verifyResult.full_name ||
                            verifyResult.normalized_url}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            verifyResult.is_private
                              ? "bg-amber-100 text-amber-900 border-amber-400"
                              : "bg-emerald-100 text-emerald-900 border-emerald-400"
                          }`}
                        >
                          {verifyResult.is_private === true
                            ? "PRIVATE REPO 🔒"
                            : verifyResult.is_private === false
                            ? "OPEN / PUBLIC 🌐"
                            : "REMOTE TARGET"}
                        </span>
                        {verifyResult.default_branch && (
                          <span className="px-2 py-0.5 rounded bg-white border border-slate-300 text-slate-800 text-[10px] font-mono">
                            branch: {verifyResult.default_branch}
                          </span>
                        )}
                        {verifyResult.primary_language && (
                          <span className="px-2 py-0.5 rounded bg-white border border-slate-300 text-sky-800 text-[10px] font-mono font-semibold">
                            {verifyResult.primary_language}
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-700">
                        {verifyResult.message}
                      </div>
                    </div>
                  </div>
                )}

                {/* 1-Click Open / Public GitHub Repository Samples */}
                <div className="space-y-2 pt-2 border-t border-[var(--border-hairline)]">
                  <div className="text-[11px] font-mono uppercase text-[var(--ink-muted)] font-semibold">
                    1-Click Open / Public GitHub Targets (No Token Required)
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {[
                      {
                        title: "ALASTOR Public GitHub Repo (Full CPG Clone)",
                        url: "https://github.com/ShanjulMittal/alastor-cpg-sast-platform",
                        desc: "Clones public GitHub repository with zero auth & runs full SAST + SBOM",
                      },
                      {
                        title: "Flask Core App Module (Direct GitHub Raw File)",
                        url: "https://raw.githubusercontent.com/pallets/flask/main/src/flask/app.py",
                        desc: "Fetches single remote Python file & builds CPG + Spider App Tree",
                      },
                    ].map((preset) => (
                      <div
                        key={preset.url}
                        className="p-2.5 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-slate-900 truncate">
                            {preset.title}
                          </div>
                          <div className="text-[10px] font-mono text-sky-800 truncate">
                            {preset.url}
                          </div>
                          <div className="text-[10px] text-slate-600">
                            {preset.desc}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            setRepoVisibilityMode("PUBLIC");
                            setUrlInput(preset.url);
                            void handleScanGitHubRepo(preset.url, true);
                          }}
                          className="px-2.5 py-1 rounded bg-sky-700 hover:bg-sky-800 text-white text-[11px] font-bold shrink-0"
                        >
                          Paste &amp; Scan
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 4: UPLOAD FILES OR PASTE CODE SNIPPET */}
            {targetPickerTab === "UPLOAD" && (
              <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6 bg-[var(--surface-panel)] overflow-y-auto flex-1">
                <div className="space-y-4 border border-slate-200 rounded-xl p-4 bg-slate-50 flex flex-col justify-between">
                  <div className="space-y-2">
                    <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                      <Upload className="w-4 h-4 text-amber-700" />
                      Pick Local File(s) from Computer
                    </h3>
                    <p className="text-xs text-slate-600">
                      Select one or more source files (`.py`, `.js`, `.ts`,
                      `.tsx`, `.json`, `.yaml`) directly from your computer.
                    </p>
                  </div>

                  <div className="border-2 border-dashed border-slate-300 hover:border-amber-600 rounded-xl p-6 text-center transition-colors bg-white">
                    <input
                      ref={fileUploadInputRef}
                      type="file"
                      multiple
                      onChange={handleBrowserFileUpload}
                      className="hidden"
                      id="studio-target-file-input"
                    />
                    <label
                      htmlFor="studio-target-file-input"
                      className="cursor-pointer flex flex-col items-center gap-2"
                    >
                      <div className="w-10 h-10 rounded-full bg-amber-50 border border-amber-400 flex items-center justify-center text-amber-800">
                        {isUploading ? (
                          <Loader2 className="w-5 h-5 animate-spin" />
                        ) : (
                          <Upload className="w-5 h-5" />
                        )}
                      </div>
                      <span className="text-xs font-bold text-slate-900">
                        Click to Choose File(s) to Scan
                      </span>
                      <span className="text-[11px] text-slate-600 font-mono">
                        Supports .py, .js, .jsx, .ts, .tsx, .json, .yaml
                      </span>
                    </label>
                  </div>
                </div>

                <form
                  onSubmit={handleScanSnippet}
                  className="space-y-3 border border-slate-200 rounded-xl p-4 bg-slate-50 flex flex-col"
                >
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                      <FileCode2 className="w-4 h-4 text-sky-700" />
                      Paste Code Snippet to Scan
                    </h3>
                    <input
                      type="text"
                      value={snippetFilename}
                      onChange={(e) => setSnippetFilename(e.target.value)}
                      placeholder="snippet.py"
                      className="w-36 bg-white border border-slate-300 rounded px-2 py-1 text-xs font-mono text-sky-800 font-semibold"
                    />
                  </div>
                  <textarea
                    rows={7}
                    value={snippetContent}
                    onChange={(e) => setSnippetContent(e.target.value)}
                    placeholder="Paste Python, JavaScript, or TypeScript code here..."
                    className="w-full flex-1 bg-white border border-slate-300 rounded-lg p-2.5 text-xs font-mono text-slate-900 focus:outline-none focus:border-sky-600"
                  />
                  <button
                    type="submit"
                    disabled={isUploading}
                    className="w-full py-2 rounded-lg bg-sky-700 hover:bg-sky-800 disabled:opacity-50 text-white text-xs font-bold flex items-center justify-center gap-1.5 shadow-sm"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Build CPG &amp; Scan Snippet Now</span>
                  </button>
                </form>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export default StudioCommandHeader;
