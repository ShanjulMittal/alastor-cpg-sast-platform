"use client";

import React, { useState, useEffect, useRef, useMemo } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { GitHubRepoVerifyResponse } from "@/types/cpg";
import {
  AlastorDemonCrestSvg,
  AlastorThemeSwitcher,
} from "./AlastorBranding";
import {
  ShieldAlert,
  ShieldCheck,
  Flame,
  Network,
  Play,
  Loader2,
  FileCode2,
  Globe,
  Download,
  FolderOpen,
  FileText,
  Upload,
  ChevronDown,
  ChevronRight,
  CornerLeftUp,
  HardDrive,
  Folder,
  X,
  Sparkles,
  CheckCircle2,
  Settings,
  Ticket,
  PieChart,
  FolderGit2,
  Code2,
  Users,
  Search,
  Menu,
  Sliders,
  Lock,
  Unlock,
  KeyRound,
  Eye,
  EyeOff,
  GitBranch,
  GitCompare,
  GraduationCap,
  Terminal,
  Compass,
  PhoneCall,
  Building2,
  Layers,
  Command,
  Columns,
} from "lucide-react";

const BACKEND_URL =
  process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

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

type MenuCategoryId =
  | "FILE"
  | "WORKSPACE"
  | "GRAPHS"
  | "THREATS"
  | "RULES"
  | "ACCOUNTS"
  | "REPORTS";

export function StudioCommandHeader() {
  const metrics = useAuditStore((s) => s.metrics);
  const appTree = useAuditStore((s) => s.appTree);
  const findings = useAuditStore((s) => s.findings);
  const selectedFinding = useAuditStore((s) => s.selectedFinding);
  const isScanning = useAuditStore((s) => s.isScanning);
  const scanStatusMessage = useAuditStore((s) => s.scanStatusMessage);
  const scanProgress = useAuditStore((s) => s.scanProgress);
  const projectPath = useAuditStore((s) => s.projectPath);
  const setProjectPath = useAuditStore((s) => s.setProjectPath);
  const projects = useAuditStore((s) => s.projects);
  const activateProject = useAuditStore((s) => s.activateProject);
  const triggerScan = useAuditStore((s) => s.triggerScan);
  const setActiveSidebarTab = useAuditStore((s) => s.setActiveSidebarTab);
  const extractAndScanFromSites = useAuditStore(
    (s) => s.extractAndScanFromSites
  );
  const exportAuditReport = useAuditStore((s) => s.exportAuditReport);
  const setGraphFullscreen = useAuditStore((s) => s.setGraphFullscreen);
  const workspaceViewMode = useAuditStore((s) => s.workspaceViewMode);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);
  const graphViewMode = useAuditStore((s) => s.graphViewMode);
  const setGraphViewMode = useAuditStore((s) => s.setGraphViewMode);
  const ideLayoutMode = useAuditStore((s) => s.ideLayoutMode);
  const setIdeLayoutMode = useAuditStore((s) => s.setIdeLayoutMode);
  const isDiffEditorOpen = useAuditStore((s) => s.isDiffEditorOpen);
  const setDiffEditorOpen = useAuditStore((s) => s.setDiffEditorOpen);
  const audienceMode = useAuditStore((s) => s.audienceMode);
  const setAudienceMode = useAuditStore((s) => s.setAudienceMode);
  const platformSettings = useAuditStore((s) => s.platformSettings);
  const fetchPlatformSettings = useAuditStore((s) => s.fetchPlatformSettings);
  const updatePlatformSettings = useAuditStore((s) => s.updatePlatformSettings);
  const userAccountsState = useAuditStore((s) => s.userAccountsState);
  const fetchUserAccounts = useAuditStore((s) => s.fetchUserAccounts);
  const switchUserOrAccount = useAuditStore((s) => s.switchUserOrAccount);
  const setSettingsModalOpen = useAuditStore((s) => s.setSettingsModalOpen);
  const setIntegrationModalOpen = useAuditStore(
    (s) => s.setIntegrationModalOpen
  );
  const raciGovernance = useAuditStore((s) => s.raciGovernance);
  const sastPlusSuite = useAuditStore((s) => s.sastPlusSuite);
  const filterSecretsOnly = useAuditStore((s) => s.filterSecretsOnly);
  const setFilterSecretsOnly = useAuditStore((s) => s.setFilterSecretsOnly);
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
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [activeMenuCategory, setActiveMenuCategory] =
    useState<MenuCategoryId>("FILE");
  const menuContainerRef = useRef<HTMLDivElement | null>(null);

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

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (
        menuContainerRef.current &&
        !menuContainerRef.current.contains(e.target as Node)
      ) {
        setIsMenuOpen(false);
      }
    };
    if (isMenuOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [isMenuOpen]);

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
      fetchFsDirectory(browseData?.current_path);
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

  const enabledEngines = platformSettings?.enabled_engines || [
    "SAST",
    "SCA",
    "IaC",
  ];
  const activePresetId =
    platformSettings?.active_preset_id || "preset-optimized";
  const presets = platformSettings?.presets || [];

  const accounts = userAccountsState?.accounts || [];
  const users = userAccountsState?.users || [];
  const activeAccount =
    accounts.find((a) => a.id === userAccountsState?.active_account_id) ||
    accounts[0];
  const activeUser =
    users.find((u) => u.id === userAccountsState?.active_user_id) || users[0];

  const secretCount = findings.filter(
    (f) =>
      f.is_secret_finding ||
      (f.rule_id || "").toUpperCase().includes("SECRET") ||
      f.cwe_id === "CWE-798"
  ).length;

  const handleToggleEngine = async (eng: string) => {
    const exists = enabledEngines.includes(eng);
    const next = exists
      ? enabledEngines.filter((e) => e !== eng)
      : [...enabledEngines, eng];
    if (next.length === 0) return;
    await updatePlatformSettings({
      scope: platformSettings?.active_scope || "GLOBAL",
      enabled_engines: next,
    });
  };

  const handlePresetChange = async (presetId: string) => {
    await updatePlatformSettings({
      scope: platformSettings?.active_scope || "GLOBAL",
      active_preset_id: presetId,
    });
    setIsMenuOpen(false);
  };

  const handleDownloadCycloneDxSbom = () => {
    setIsMenuOpen(false);
    const cdx = sastPlusSuite?.cyclonedx_json || {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [],
    };
    const blob = new Blob([JSON.stringify(cdx, null, 2)], {
      type: "application/json",
    });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "alastor-sbom.cdx.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const handleDownloadRaciJson = () => {
    setIsMenuOpen(false);
    if (!raciGovernance) return;
    const blob = new Blob([JSON.stringify(raciGovernance, null, 2)], {
      type: "application/json",
    });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "alastor-raci-governance-matrix.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const showProgress =
    isScanning || Boolean(scanProgress && scanProgress.is_scanning);
  const percent = scanProgress?.percent ?? (isScanning ? 10 : 0);
  const currentPass =
    scanProgress?.current_pass || (isScanning ? "Pass 1/7 • CPG Scan" : "");
  const filesDone = scanProgress?.files_done ?? 0;
  const totalScanFiles = scanProgress?.total_files ?? 0;
  const progressMessage = scanProgress?.message || scanStatusMessage || "";

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

  const menuCategories: Array<{
    id: MenuCategoryId;
    label: string;
    icon: React.ReactNode;
  }> = [
    {
      id: "FILE",
      label: "1. File & Scan",
      icon: <Play className="w-3.5 h-3.5 text-[var(--sig-gold)]" />,
    },
    {
      id: "WORKSPACE",
      label: "2. Workspace",
      icon: <Columns className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />,
    },
    {
      id: "GRAPHS",
      label: "3. CPG & Graphs",
      icon: <Network className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />,
    },
    {
      id: "THREATS",
      label: "4. Threat Model & Secrets",
      icon: <ShieldAlert className="w-3.5 h-3.5 text-[var(--sig-crimson)]" />,
    },
    {
      id: "RULES",
      label: "5. Rule Engine",
      icon: <Sliders className="w-3.5 h-3.5 text-[var(--sig-gold)]" />,
    },
    {
      id: "ACCOUNTS",
      label: "6. Accounts",
      icon: <Users className="w-3.5 h-3.5 text-[var(--sig-emerald)]" />,
    },
    {
      id: "REPORTS",
      label: "7. Reports & Exports",
      icon: <Download className="w-3.5 h-3.5 text-[var(--sig-emerald)]" />,
    },
  ];

  return (
    <>
      <header
        aria-label="ALASTOR Studio Command Header"
        className="h-11 px-3 bg-[var(--surface-panel)] border-b border-[var(--border-hairline)] text-[var(--ink-primary)] flex items-center justify-between gap-2 select-none relative z-50 shrink-0"
      >
        {/* LEFT CLUSTER: [Ἀ] Crest + ALASTOR Wordmark + Menu ▾ + Active Repo Selector + GitHub Scan */}
        <div className="flex items-center gap-2 min-w-0 shrink-0">
          {/* [Ἀ] Launch Hub Crest Button */}
          <button
            type="button"
            onClick={() => setShowPortalGate(true)}
            title="Return to Launch Hub (Ἀλάστωρ Portal Gate)"
            className="group flex items-center gap-2 pr-2 py-1 rounded-lg hover:bg-[var(--surface-elevated)] transition-colors"
          >
            <span className="w-7 h-7 rounded-lg bg-[var(--surface-elevated)] border border-[var(--sig-gold)]/50 group-hover:border-[var(--sig-gold)] flex items-center justify-center shadow-sm">
              <span className="font-display font-bold text-xs text-[var(--sig-gold)] leading-none">
                Ἀ
              </span>
            </span>
            <span className="font-display font-bold text-xs tracking-[0.14em] text-[var(--ink-primary)] hidden sm:inline">
              ALASTOR
            </span>
          </button>

          {/* Compact 7-Category Application Menu Popover */}
          <div ref={menuContainerRef} className="relative">
            <button
              type="button"
              onClick={() => setIsMenuOpen((v) => !v)}
              title="Open 7-Category Studio Command Menu (File, Workspace, Graphs, Threat Model, Rules, Accounts, Reports)"
              className={`h-7 px-2.5 rounded-md border text-[11px] font-semibold flex items-center gap-1 transition-colors ${
                isMenuOpen
                  ? "bg-[var(--surface-elevated)] border-[var(--sig-gold)] text-[var(--sig-gold)]"
                  : "bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border-[var(--border-hairline)] text-[var(--ink-primary)]"
              }`}
            >
              <Menu className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
              <span>Menu</span>
              <ChevronDown className="w-3 h-3 text-[var(--ink-muted)]" />
            </button>

            {isMenuOpen && (
              <div className="absolute left-0 top-9 w-[560px] max-w-[92vw] rounded-xl bg-[var(--surface-elevated)] border border-[var(--border-hairline)] shadow-2xl z-[160] flex overflow-hidden text-xs">
                {/* Left Column: 7 Categories */}
                <div className="w-48 bg-[var(--surface-panel)] border-r border-[var(--border-hairline)] p-1.5 space-y-0.5 shrink-0">
                  <div className="px-2 py-1 text-[9px] font-mono font-bold uppercase tracking-wider text-[var(--ink-muted)]">
                    Studio Menu (7 Groups)
                  </div>
                  {menuCategories.map((cat) => {
                    const active = activeMenuCategory === cat.id;
                    return (
                      <button
                        key={cat.id}
                        type="button"
                        onMouseEnter={() => setActiveMenuCategory(cat.id)}
                        onClick={() => setActiveMenuCategory(cat.id)}
                        className={`w-full px-2.5 py-1.5 rounded-lg text-left text-[11px] font-semibold flex items-center justify-between gap-1.5 transition-colors ${
                          active
                            ? "bg-[var(--surface-elevated)] text-[var(--ink-primary)] border border-[var(--sig-gold)]/50"
                            : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)] hover:bg-[var(--surface-void)]"
                        }`}
                      >
                        <span className="flex items-center gap-2 truncate">
                          {cat.icon}
                          <span className="truncate">{cat.label}</span>
                        </span>
                        <ChevronRight className="w-3 h-3 opacity-60 shrink-0" />
                      </button>
                    );
                  })}
                </div>

                {/* Right Column: Category Actions */}
                <div className="flex-1 p-2.5 space-y-1 max-h-[420px] overflow-y-auto bg-[var(--surface-elevated)]">
                  {activeMenuCategory === "FILE" && (
                    <>
                      <div className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-[var(--ink-muted)]">
                        Target Acquisition &amp; 7-Pass CPG Scan
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setIsMenuOpen(false);
                          triggerScan(resolvedPath || projectPath);
                        }}
                        className="w-full px-2.5 py-2 rounded-lg bg-[var(--surface-panel)] hover:bg-[var(--surface-void)] border border-[var(--sig-gold)]/50 flex items-center gap-2 text-[var(--ink-primary)] font-bold text-left"
                      >
                        <Play className="w-3.5 h-3.5 text-[var(--sig-gold)] fill-current" />
                        <span>Run Full 7-Pass CPG + Secret Scan Now</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setIsMenuOpen(false);
                          openPickerModal("URL");
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center gap-2 text-[var(--ink-primary)] font-semibold text-left"
                      >
                        <FolderGit2 className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
                        <span>
                          Scan GitHub Repo (Public NO TOKEN / Private PAT)
                        </span>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setIsMenuOpen(false);
                          openPickerModal("FOLDER");
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center gap-2 text-[var(--ink-primary)] text-left"
                      >
                        <FolderOpen className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
                        <span>Browse Local Folder or Single File...</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setIsMenuOpen(false);
                          openPickerModal("UPLOAD");
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center gap-2 text-[var(--ink-primary)] text-left"
                      >
                        <Upload className="w-3.5 h-3.5 text-[var(--sig-emerald)]" />
                        <span>Upload Files or Paste Live Code Snippet...</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setIsMenuOpen(false);
                          setWorkspaceViewMode("REMEDIATION_IDE");
                          setActiveSidebarTab("SITE_EXTRACTOR");
                          extractAndScanFromSites({
                            sources: ["osv", "nvd", "cisa_owasp"],
                            customUrls: [],
                          });
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center gap-2 text-[var(--ink-primary)] text-left"
                      >
                        <Globe className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
                        <span>Pull Live Web CVE Advisories (OSV / NVD)</span>
                      </button>
                      <div className="border-t border-[var(--border-hairline)] my-1" />
                      <button
                        type="button"
                        onClick={() => {
                          setQuickCommandOpen(true);
                          setIsMenuOpen(false);
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center justify-between text-[var(--ink-primary)] text-left"
                      >
                        <span className="flex items-center gap-2">
                          <Command className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
                          <span>Command Palette</span>
                        </span>
                        <kbd className="text-[9px] font-mono bg-[var(--surface-void)] px-1.5 py-0.5 rounded border border-[var(--border-hairline)]">
                          Ctrl+K
                        </kbd>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setShowPortalGate(true);
                          setIsMenuOpen(false);
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center gap-2 text-[var(--sig-crimson)] text-left font-medium"
                      >
                        <Flame className="w-3.5 h-3.5" />
                        <span>Return to Alastor Launch Hub</span>
                      </button>
                    </>
                  )}

                  {activeMenuCategory === "WORKSPACE" && (
                    <>
                      <div className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-[var(--ink-muted)]">
                        5 Focused Studio Workspaces
                      </div>
                      {(
                        [
                          {
                            id: "REMEDIATION_IDE",
                            label: "1. Workbench (Code, BFL Diff & 7 CPG Graphs)",
                            icon: (
                              <Code2 className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
                            ),
                          },
                          {
                            id: "THREAT_MODELING",
                            label: "2. Threats (STRIDE Matrix & Secret Vault)",
                            icon: (
                              <ShieldAlert className="w-3.5 h-3.5 text-[var(--sig-crimson)]" />
                            ),
                          },
                          {
                            id: "EXECUTIVE_ASPM",
                            label:
                              "3. ASPM (Translator, SBOM, Analytics & RACI)",
                            icon: (
                              <Layers className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
                            ),
                          },
                          {
                            id: "PROJECTS_HUB",
                            label: "4. Repos (Projects Hub, GitHub & Webhooks)",
                            icon: (
                              <FolderGit2 className="w-3.5 h-3.5 text-[var(--sig-emerald)]" />
                            ),
                          },
                          {
                            id: "ENGINE_ACCESS",
                            label:
                              "5. Engine (Rule Profiles, Sanitizers & RBAC)",
                            icon: (
                              <Sliders className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
                            ),
                          },
                        ] as const
                      ).map((item) => (
                        <button
                          key={item.id}
                          type="button"
                          onClick={() => {
                            setWorkspaceViewMode(item.id);
                            setIsMenuOpen(false);
                          }}
                          className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center justify-between text-left"
                        >
                          <span className="flex items-center gap-2 text-[var(--ink-primary)] font-medium">
                            {item.icon}
                            <span>{item.label}</span>
                          </span>
                          {workspaceViewMode === item.id && (
                            <span className="text-[9px] font-mono text-[var(--sig-gold)] font-bold">
                              ACTIVE
                            </span>
                          )}
                        </button>
                      ))}

                      <div className="border-t border-[var(--border-hairline)] my-1" />
                      <div className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-[var(--ink-muted)]">
                        Direct Sub-View Jump
                      </div>
                      <div className="grid grid-cols-2 gap-1 px-1">
                        <button
                          type="button"
                          onClick={() => {
                            setWorkspaceViewMode("DEEP_DIVE");
                            setIsMenuOpen(false);
                          }}
                          className="px-2 py-1.5 rounded bg-[var(--surface-panel)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[10px] font-medium text-left flex items-center gap-1.5"
                        >
                          <PieChart className="w-3 h-3 text-[var(--sig-cyan)]" />
                          <span>Compliance &amp; SLA</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setWorkspaceViewMode("RACI_GOVERNANCE");
                            setIsMenuOpen(false);
                          }}
                          className="px-2 py-1.5 rounded bg-[var(--surface-panel)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[10px] font-medium text-left flex items-center gap-1.5"
                        >
                          <ShieldCheck className="w-3 h-3 text-[var(--sig-gold)]" />
                          <span>RACI Governance</span>
                        </button>
                      </div>

                      <div className="border-t border-[var(--border-hairline)] my-1" />
                      <div className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-[var(--ink-muted)]">
                        Workbench Panel Layout
                      </div>
                      <div className="grid grid-cols-3 gap-1 px-1 pb-1">
                        {(
                          [
                            { id: "CODE_FOCUS", label: "1. Code Only" },
                            { id: "SPLIT_BOTH", label: "2. Split Both" },
                            { id: "GRAPH_FOCUS", label: "3. Graph Only" },
                          ] as const
                        ).map((l) => (
                          <button
                            key={l.id}
                            type="button"
                            onClick={() => {
                              setWorkspaceViewMode("REMEDIATION_IDE");
                              setIdeLayoutMode(l.id);
                              setIsMenuOpen(false);
                            }}
                            className={`px-2 py-1 rounded text-[10px] font-bold border ${
                              ideLayoutMode === l.id
                                ? "bg-[var(--surface-panel)] text-[var(--sig-gold)] border-[var(--sig-gold)]"
                                : "bg-[var(--surface-void)] text-[var(--ink-muted)] border-[var(--border-hairline)]"
                            }`}
                          >
                            {l.label}
                          </button>
                        ))}
                      </div>
                    </>
                  )}

                  {activeMenuCategory === "GRAPHS" && (
                    <>
                      <div className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-[var(--ink-muted)]">
                        7 Interactive CPG Graph Visualizations
                      </div>
                      {(
                        [
                          {
                            id: "FINDING_PATH",
                            label:
                              "1. Vulnerability Attack Path (Source → BFL → Sink)",
                            badge: "TAINT",
                          },
                          {
                            id: "APP_TREE",
                            label: "2. 360° Application Spider Map",
                            badge: "360° MAP",
                          },
                          {
                            id: "CALL_GRAPH",
                            label: "3. Inter-Procedural Call Graph (:CALLS)",
                            badge: "CALLS",
                          },
                          {
                            id: "ENTRYPOINT_GRAPH",
                            label: "4. Attack Surface Entry Points Graph",
                            badge: "INGRESS",
                          },
                          {
                            id: "DFG_ONLY",
                            label: "5. Data-Flow Slice (DFG_FLOWS_TO)",
                            badge: "DFG",
                          },
                          {
                            id: "CFG_ONLY",
                            label: "6. Control-Flow Slice (CFG_NEXT)",
                            badge: "CFG",
                          },
                          {
                            id: "FULL_CPG",
                            label:
                              "7. Unified Code Property Graph (AST+CFG+DFG)",
                            badge: "FULL CPG",
                          },
                        ] as const
                      ).map((g) => (
                        <button
                          key={g.id}
                          type="button"
                          onClick={() => {
                            setWorkspaceViewMode("REMEDIATION_IDE");
                            setGraphViewMode(g.id);
                            if (ideLayoutMode === "CODE_FOCUS") {
                              setIdeLayoutMode("SPLIT_BOTH");
                            }
                            setIsMenuOpen(false);
                          }}
                          className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center justify-between text-left"
                        >
                          <span className="text-[var(--ink-primary)] font-medium">
                            {g.label}
                          </span>
                          <span
                            className={`px-1.5 py-0.5 text-[9px] font-mono font-bold rounded border ${
                              graphViewMode === g.id
                                ? "bg-[var(--surface-panel)] text-[var(--sig-cyan)] border-[var(--sig-cyan)]"
                                : "bg-[var(--surface-void)] text-[var(--ink-muted)] border-[var(--border-hairline)]"
                            }`}
                          >
                            {g.badge}
                          </span>
                        </button>
                      ))}
                      <div className="border-t border-[var(--border-hairline)] my-1" />
                      <button
                        type="button"
                        onClick={() => {
                          setGraphFullscreen(true);
                          setIsMenuOpen(false);
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center gap-2 text-[var(--sig-cyan)] font-semibold text-left"
                      >
                        <Layers className="w-3.5 h-3.5" />
                        <span>Launch Fullscreen 360° Graph Presentation</span>
                      </button>
                    </>
                  )}

                  {activeMenuCategory === "THREATS" && (
                    <>
                      <button
                        type="button"
                        onClick={() => {
                          setWorkspaceViewMode("THREAT_MODELING");
                          setIsMenuOpen(false);
                        }}
                        className="w-full p-2.5 rounded-lg bg-[var(--surface-panel)] hover:bg-[var(--surface-void)] border border-[var(--sig-crimson)]/40 flex flex-col gap-0.5 text-left"
                      >
                        <span className="text-xs font-bold text-[var(--ink-primary)] flex items-center gap-1.5">
                          <ShieldAlert className="w-3.5 h-3.5 text-[var(--sig-crimson)]" />
                          Open STRIDE Threat Modeling Workspace
                        </span>
                        <span className="text-[10px] text-[var(--ink-muted)]">
                          Interactive STRIDE verdict matrix, trust boundaries,
                          attack entrypoints &amp; Secret Keys Vault
                        </span>
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          setFilterSecretsOnly(!filterSecretsOnly);
                          setWorkspaceViewMode("REMEDIATION_IDE");
                          setIsMenuOpen(false);
                        }}
                        className="w-full px-2.5 py-2 rounded-lg hover:bg-[var(--surface-panel)] flex items-center justify-between text-left"
                      >
                        <span className="flex items-center gap-2 text-[var(--sig-gold)] font-semibold">
                          <KeyRound className="w-3.5 h-3.5" />
                          <span>
                            Filter Detected Secret Keys ({secretCount})
                          </span>
                        </span>
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[var(--surface-void)] text-[var(--sig-gold)] border border-[var(--border-hairline)]">
                          {filterSecretsOnly ? "FILTER ON" : "SHOW KEYS"}
                        </span>
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          setWorkspaceViewMode("REMEDIATION_IDE");
                          setGraphViewMode("ENTRYPOINT_GRAPH");
                          setIsMenuOpen(false);
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center gap-2 text-[var(--ink-primary)] text-left"
                      >
                        <Compass className="w-3.5 h-3.5 text-[var(--sig-emerald)]" />
                        <span>Inspect Attack Surface Entry Points Graph</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          setWorkspaceViewMode("REMEDIATION_IDE");
                          setGraphViewMode("CALL_GRAPH");
                          setIsMenuOpen(false);
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center gap-2 text-[var(--ink-primary)] text-left"
                      >
                        <PhoneCall className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
                        <span>Inspect Inter-Procedural Call Graph</span>
                      </button>
                    </>
                  )}

                  {activeMenuCategory === "RULES" && (
                    <>
                      <button
                        type="button"
                        onClick={() => {
                          setWorkspaceViewMode("RULE_ENGINE_PROFILES");
                          setIsMenuOpen(false);
                        }}
                        className="w-full p-2.5 rounded-lg bg-[var(--surface-panel)] hover:bg-[var(--surface-void)] border border-[var(--sig-cyan)]/40 flex flex-col gap-0.5 text-left"
                      >
                        <span className="text-xs font-bold text-[var(--ink-primary)] flex items-center gap-1.5">
                          <Sliders className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
                          Open Rule Engine &amp; 18-Rule Matrix
                        </span>
                        <span className="text-[10px] text-[var(--ink-muted)]">
                          Configure test profiles, AST sanitizers, and toggle
                          individual security rules
                        </span>
                      </button>

                      <div className="px-2 pt-1 text-[9px] font-mono uppercase tracking-wider text-[var(--ink-muted)]">
                        Quick-Switch Active Test Profile
                      </div>
                      {presets.map((p) => (
                        <button
                          key={p.id}
                          type="button"
                          onClick={() => handlePresetChange(p.id)}
                          className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center justify-between text-left"
                        >
                          <span className="text-[var(--ink-primary)] font-medium truncate pr-2">
                            {p.name}
                          </span>
                          <span
                            className={`px-1.5 py-0.5 text-[9px] font-mono font-bold rounded shrink-0 border ${
                              activePresetId === p.id
                                ? "bg-[var(--surface-panel)] text-[var(--sig-gold)] border-[var(--sig-gold)]"
                                : "bg-[var(--surface-void)] text-[var(--ink-muted)] border-[var(--border-hairline)]"
                            }`}
                          >
                            {activePresetId === p.id ? "ACTIVE" : p.badge}
                          </span>
                        </button>
                      ))}

                      <div className="border-t border-[var(--border-hairline)] my-1" />
                      <div className="px-2 py-1 flex items-center justify-between">
                        <span className="text-[10px] text-[var(--ink-muted)] font-semibold">
                          Engines:
                        </span>
                        <div className="flex items-center gap-1">
                          {(["SAST", "SCA", "IaC"] as const).map((eng) => {
                            const isOn = enabledEngines.includes(eng);
                            return (
                              <button
                                key={eng}
                                type="button"
                                onClick={() => handleToggleEngine(eng)}
                                className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border ${
                                  isOn
                                    ? "bg-[var(--surface-panel)] text-[var(--sig-emerald)] border-[var(--sig-emerald)]"
                                    : "bg-[var(--surface-void)] text-[var(--ink-muted)] border-[var(--border-hairline)]"
                                }`}
                              >
                                {eng}: {isOn ? "ON" : "OFF"}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </>
                  )}

                  {activeMenuCategory === "ACCOUNTS" && (
                    <>
                      <button
                        type="button"
                        onClick={() => {
                          setWorkspaceViewMode("USER_PROFILES");
                          setIsMenuOpen(false);
                        }}
                        className="w-full p-2.5 rounded-lg bg-[var(--surface-panel)] hover:bg-[var(--surface-void)] border border-[var(--sig-gold)]/40 flex flex-col gap-0.5 text-left"
                      >
                        <span className="text-xs font-bold text-[var(--ink-primary)] flex items-center gap-1.5">
                          <Users className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
                          Open Multi-Tenant Accounts &amp; RBAC
                        </span>
                        <span className="text-[10px] text-[var(--ink-muted)]">
                          Manage isolated tenant accounts, RBAC operator
                          profiles &amp; secret reveal clearance
                        </span>
                      </button>

                      <div className="px-2 pt-1 text-[9px] font-mono uppercase tracking-wider text-[var(--ink-muted)]">
                        Switch Isolated Tenant Account
                      </div>
                      {accounts.map((acct) => (
                        <button
                          key={acct.id}
                          type="button"
                          onClick={() => {
                            switchUserOrAccount({ account_id: acct.id });
                            setIsMenuOpen(false);
                          }}
                          className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center justify-between text-left"
                        >
                          <span className="flex items-center gap-1.5 text-[var(--ink-primary)] font-medium truncate">
                            <Building2 className="w-3.5 h-3.5 text-[var(--sig-cyan)] shrink-0" />
                            <span className="truncate">{acct.name}</span>
                          </span>
                          {activeAccount?.id === acct.id && (
                            <span className="text-[9px] font-mono text-[var(--sig-cyan)] font-bold shrink-0">
                              ACTIVE
                            </span>
                          )}
                        </button>
                      ))}

                      <div className="px-2 pt-1 text-[9px] font-mono uppercase tracking-wider text-[var(--ink-muted)]">
                        Assume RBAC Operator Profile
                      </div>
                      {users.map((u) => (
                        <button
                          key={u.id}
                          type="button"
                          onClick={() => {
                            switchUserOrAccount({ user_id: u.id });
                            setIsMenuOpen(false);
                          }}
                          className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center justify-between text-left"
                        >
                          <span className="text-[var(--ink-primary)] font-medium truncate">
                            {u.name}{" "}
                            <span className="text-[10px] text-[var(--ink-muted)]">
                              ({u.role})
                            </span>
                          </span>
                          {activeUser?.id === u.id && (
                            <CheckCircle2 className="w-3.5 h-3.5 text-[var(--sig-emerald)] shrink-0" />
                          )}
                        </button>
                      ))}
                    </>
                  )}

                  {activeMenuCategory === "REPORTS" && (
                    <>
                      <div className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-[var(--ink-muted)]">
                        Audit Deliverables &amp; Compliance Exports
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setIsMenuOpen(false);
                          exportAuditReport("markdown");
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] text-left text-[var(--ink-primary)] font-medium"
                      >
                        Executive Audit Dossier (.md)
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setIsMenuOpen(false);
                          exportAuditReport("json");
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] text-left text-[var(--ink-primary)] font-medium"
                      >
                        Full Findings &amp; CPG Metrics (.json)
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setIsMenuOpen(false);
                          exportAuditReport("sarif");
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] text-left text-[var(--sig-emerald)] font-semibold"
                      >
                        CI/CD SARIF v2.1.0 Report (.sarif.json)
                      </button>
                      <button
                        type="button"
                        onClick={handleDownloadCycloneDxSbom}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] text-left text-[var(--sig-cyan)] font-medium"
                      >
                        CycloneDX v1.5 SBOM (.cdx.json)
                      </button>
                      <button
                        type="button"
                        onClick={handleDownloadRaciJson}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] text-left text-[var(--sig-gold)] font-medium"
                      >
                        RACI Governance Matrix (.json)
                      </button>
                      <div className="border-t border-[var(--border-hairline)] my-1" />
                      <button
                        type="button"
                        onClick={() => {
                          setIntegrationModalOpen(true);
                          setIsMenuOpen(false);
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center gap-2 text-[var(--ink-primary)] font-semibold text-left"
                      >
                        <Ticket className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
                        <span>Jira &amp; GitHub Issues Connectors</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setSettingsModalOpen(true, "GLOBAL_PROJECT");
                          setIsMenuOpen(false);
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg hover:bg-[var(--surface-panel)] flex items-center gap-2 text-[var(--ink-primary)] text-left"
                      >
                        <Settings className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
                        <span>Advanced Engine &amp; Sanitizer Settings</span>
                      </button>
                    </>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="h-4 w-px bg-[var(--border-hairline)] hidden sm:block" />

          {/* Active Repository Selector Pill + Saved Snapshot Quick Switcher */}
          <div className="flex items-center gap-1 min-w-0">
            <button
              type="button"
              onClick={() => openPickerModal("FOLDER")}
              title={`Active Target: ${
                resolvedPath || applicationName
              } — Click to browse local folders, single files, or upload code`}
              className="h-7 px-2.5 rounded-md bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] text-xs font-medium text-[var(--ink-primary)] flex items-center gap-1.5 transition-colors max-w-[200px]"
            >
              <FolderOpen className="w-3.5 h-3.5 text-[var(--sig-cyan)] shrink-0" />
              <span className="font-mono text-[11px] font-semibold truncate">
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
                    activateProject(e.target.value, false);
                  }
                }}
                disabled={isScanning}
                title="Switch active repository using cached scan snapshot (no re-scan required)"
                className="hidden 2xl:block h-7 bg-[var(--surface-elevated)] border border-[var(--border-hairline)] hover:border-[var(--sig-cyan)] rounded-md px-1.5 text-[10px] font-mono text-[var(--ink-muted)] hover:text-[var(--ink-primary)] focus:outline-none cursor-pointer max-w-[130px]"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    Repo: {p.name}
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* GitHub Scan Trigger Button */}
          <button
            type="button"
            onClick={() => openPickerModal("URL")}
            title="Scan any Open/Public GitHub Repo (NO TOKEN) or Private Repo (with Personal Access Token)"
            className="h-7 px-2.5 rounded-md bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--sig-cyan)]/40 hover:border-[var(--sig-cyan)] text-[var(--ink-primary)] text-[11px] font-semibold flex items-center gap-1.5 transition-colors shrink-0"
          >
            <FolderGit2 className="w-3.5 h-3.5 text-[var(--sig-cyan)] shrink-0" />
            <span className="hidden md:inline">GitHub Scan</span>
          </button>
        </div>

        {/* CENTER CLUSTER: Ctrl+K Omnibar Search Trigger */}
        <div className="flex-1 max-w-[200px] xl:max-w-[240px] 2xl:max-w-md mx-1.5 hidden lg:flex justify-center min-w-[140px]">
          <button
            type="button"
            onClick={() => setQuickCommandOpen(true)}
            title="Open Command Palette & Fuzzy Search (Ctrl+K)"
            className="w-full h-7 px-2.5 rounded-md bg-[var(--surface-void)] hover:bg-[var(--surface-elevated)] border border-[var(--border-hairline)] hover:border-[var(--sig-gold)]/50 text-[11px] text-[var(--ink-muted)] hover:text-[var(--ink-primary)] flex items-center justify-between gap-2 transition-colors"
          >
            <span className="flex items-center gap-1.5 truncate">
              <Search className="w-3.5 h-3.5 text-[var(--sig-cyan)] shrink-0" />
              <span className="truncate">
                Search findings, files, graphs, SARIF...
              </span>
            </span>
            <kbd className="px-1.5 py-0.5 rounded bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[9px] font-mono text-[var(--ink-muted)] shrink-0">
              Ctrl+K
            </kbd>
          </button>
        </div>

        {/* RIGHT CLUSTER: [Code | Split | Graph] + [Preview Diff (d)] + [Scan / 7-Pass Stage Pill] + [Engineer/Executive] + Theme */}
        <div className="flex items-center gap-1.5 shrink-0">
          {/* Segmented Code | Split | Graph Layout Switch (when in Workbench) */}
          {workspaceViewMode === "REMEDIATION_IDE" && (
            <div
              role="group"
              aria-label="Workbench Panel Layout"
              className="hidden lg:flex items-center h-7 bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-md p-0.5 text-[10px] font-mono font-semibold"
            >
              {(
                [
                  { id: "CODE_FOCUS", label: "Code", keyHint: "1" },
                  { id: "SPLIT_BOTH", label: "Split", keyHint: "2" },
                  { id: "GRAPH_FOCUS", label: "Graph", keyHint: "3" },
                ] as const
              ).map((mode) => {
                const active = ideLayoutMode === mode.id;
                return (
                  <button
                    key={mode.id}
                    type="button"
                    onClick={() => setIdeLayoutMode(mode.id)}
                    title={`Switch to ${mode.label} layout (Shortcut: ${mode.keyHint})`}
                    className={`px-2 py-0.5 rounded transition-colors ${
                      active
                        ? "bg-[var(--surface-elevated)] text-[var(--sig-gold)] border border-[var(--sig-gold)]/50 font-bold"
                        : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                    }`}
                  >
                    {mode.label}
                  </button>
                );
              })}
            </div>
          )}

          {/* Quick BFL Diff Preview Toggle when a finding is active */}
          {workspaceViewMode === "REMEDIATION_IDE" && selectedFinding && (
            <button
              type="button"
              onClick={() => setDiffEditorOpen(!isDiffEditorOpen)}
              title="Toggle live Monaco Chokepoint BFL DiffEditor (Shortcut: d)"
              className={`hidden 2xl:flex items-center gap-1 h-7 px-2 rounded-md border text-[10px] font-mono font-bold transition-colors ${
                isDiffEditorOpen
                  ? "bg-[var(--surface-elevated)] border-[var(--sig-gold)] text-[var(--sig-gold)]"
                  : "bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border-[var(--border-hairline)] text-[var(--ink-primary)]"
              }`}
            >
              <GitCompare className="w-3 h-3 text-[var(--sig-gold)]" />
              <span>{isDiffEditorOpen ? "Exit Diff" : "Preview Diff (d)"}</span>
            </button>
          )}

          {/* Primary Scan CTA or Live 7-Pass Compiler Stage Pill */}
          {showProgress ? (
            <div
              title={progressMessage || currentPass}
              className="relative h-7 px-2.5 rounded-md bg-[var(--surface-elevated)] border border-[var(--sig-cyan)] text-[10px] font-mono text-[var(--ink-primary)] flex items-center gap-2 overflow-hidden min-w-[165px]"
            >
              <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--sig-cyan)] shrink-0" />
              <span className="truncate font-semibold max-w-[130px]">
                {currentPass}
              </span>
              {totalScanFiles > 0 && (
                <span className="text-[var(--ink-muted)] hidden sm:inline">
                  {filesDone}/{totalScanFiles}
                </span>
              )}
              <span className="font-bold text-[var(--sig-cyan)] ml-auto">
                {percent}%
              </span>
              <div
                className="absolute bottom-0 left-0 h-[2px] bg-[var(--sig-cyan)] transition-all duration-200"
                style={{ width: `${Math.max(4, Math.min(100, percent))}%` }}
              />
            </div>
          ) : (
            <button
              type="button"
              onClick={() =>
                handleSelectAndScan(
                  inputPath || resolvedPath || projectPath
                )
              }
              title="Execute 7-Pass Deterministic CPG Scan (AST + CFG + DFG + :CALLS + OSV + STRIDE)"
              className="h-7 px-2.5 rounded-md bg-[var(--sig-cyan)] hover:opacity-90 text-white text-[11px] font-semibold flex items-center gap-1.5 transition-opacity shadow-sm shrink-0"
            >
              <Play className="w-3 h-3 fill-current" />
              <span>Scan Target</span>
            </button>
          )}

          {/* Compact Findings Verdict Pill */}
          {(metrics?.total_findings ?? 0) === 0 ? (
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("EXECUTIVE_ASPM")}
              title="0 Active Vulnerabilities — View ASPM & Compliance Proof"
              className="hidden sm:flex items-center gap-1 h-7 px-2 rounded-md bg-[var(--surface-elevated)] border border-[var(--sig-emerald)]/50 text-[var(--sig-emerald)] text-[10px] font-mono font-bold"
            >
              <CheckCircle2 className="w-3 h-3" />
              <span>0 Flaws</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("REMEDIATION_IDE")}
              title="Jump to Flaw Explorer in Workbench"
              className="hidden sm:flex items-center gap-1.5 h-7 px-2 rounded-md bg-[var(--surface-elevated)] border border-[var(--sig-crimson)]/50 text-[10px] font-mono"
            >
              <span className="text-[var(--sig-crimson)] font-bold flex items-center gap-0.5">
                <Flame className="w-3 h-3" />
                {metrics?.critical_count ?? 0}C
              </span>
              <span className="text-[var(--ink-muted)]">·</span>
              <span className="text-[var(--sig-gold)] font-bold">
                {metrics?.high_count ?? 0}H
              </span>
              <span className="text-[var(--ink-muted)]">·</span>
              <span className="text-[var(--ink-primary)] font-bold">
                {metrics?.total_findings ?? 0}
              </span>
            </button>
          )}

          {/* Engineer / Executive Lens Toggle */}
          <button
            type="button"
            onClick={() =>
              setAudienceMode(
                audienceMode === "NON_CODER_MANAGEMENT"
                  ? "TECHNICAL_ENGINEER"
                  : "NON_CODER_MANAGEMENT"
              )
            }
            title="Switch between Technical Engineer Lens and Executive Plain-English Lens"
            className="hidden md:flex items-center gap-1 h-7 px-2 rounded-md bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[10px] font-semibold text-[var(--ink-primary)] transition-colors"
          >
            {audienceMode === "NON_CODER_MANAGEMENT" ? (
              <>
                <GraduationCap className="w-3 h-3 text-[var(--sig-emerald)]" />
                <span>Executive</span>
              </>
            ) : (
              <>
                <Terminal className="w-3 h-3 text-[var(--sig-cyan)]" />
                <span>Engineer</span>
              </>
            )}
          </button>

          {/* Theme & Light/Dark Switcher */}
          <AlastorThemeSwitcher />
        </div>
      </header>

      {/* INTERACTIVE TARGET PICKER & GITHUB REPOSITORY SCANNER MODAL */}
      {isTargetPickerOpen && (
        <div className="fixed inset-0 z-[200] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
          <div className="bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[var(--ink-primary)] rounded-2xl shadow-2xl w-full max-w-4xl overflow-hidden flex flex-col h-[620px] max-h-[88vh] my-auto">
            {/* Modal Header & Mode Tabs */}
            <div className="px-4 py-3 bg-[var(--surface-elevated)] border-b border-[var(--border-hairline)] flex items-center justify-between flex-wrap gap-2 shrink-0">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-[var(--sig-gold)]" />
                <span className="text-xs font-bold uppercase tracking-wider text-[var(--ink-primary)]">
                  Select Scan Target (Folder, File, GitHub Public/Private Repo,
                  or Snippet)
                </span>
              </div>

              <div className="flex items-center gap-1 bg-[var(--surface-void)] p-1 rounded-lg border border-[var(--border-hairline)] flex-wrap">
                <button
                  type="button"
                  onClick={() => {
                    openTargetPicker("FOLDER");
                    if (!browseData) fetchFsDirectory();
                  }}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    targetPickerTab === "FOLDER"
                      ? "bg-[var(--surface-elevated)] text-[var(--sig-cyan)] border border-[var(--sig-cyan)]/60 font-bold"
                      : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <FolderOpen className="w-3.5 h-3.5" />
                  <span>1. Folder Browser</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    openTargetPicker("FILE");
                    if (!browseData) fetchFsDirectory();
                  }}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    targetPickerTab === "FILE"
                      ? "bg-[var(--surface-elevated)] text-[var(--sig-emerald)] border border-[var(--sig-emerald)]/60 font-bold"
                      : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>2. Single File</span>
                </button>
                <button
                  type="button"
                  onClick={() => openTargetPicker("URL")}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    targetPickerTab === "URL"
                      ? "bg-[var(--surface-elevated)] text-[var(--sig-gold)] border border-[var(--sig-gold)]/60 font-bold"
                      : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <FolderGit2 className="w-3.5 h-3.5" />
                  <span>3. GitHub Repo / URL</span>
                </button>
                <button
                  type="button"
                  onClick={() => openTargetPicker("UPLOAD")}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    targetPickerTab === "UPLOAD"
                      ? "bg-[var(--surface-elevated)] text-[var(--sig-gold)] border border-[var(--sig-gold)]/60 font-bold"
                      : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>4. Upload / Paste Code</span>
                </button>
              </div>

              <button
                type="button"
                onClick={closeTargetPicker}
                className="p-1 text-[var(--ink-muted)] hover:text-[var(--ink-primary)] rounded-md hover:bg-[var(--surface-void)]"
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
                      handleNativeOsDialog(
                        targetPickerTab === "FILE" ? "file" : "folder",
                        true
                      )
                    }
                    className="w-full py-2 px-2.5 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-panel)] border border-[var(--sig-cyan)]/60 text-[var(--ink-primary)] text-xs font-semibold flex items-center justify-center gap-1.5 shadow-sm transition-all"
                  >
                    {isNativeDialogOpen ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--sig-cyan)]" />
                        <span>Opening OS Dialog...</span>
                      </>
                    ) : (
                      <>
                        <FolderOpen className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
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
                      className="group flex items-center justify-between gap-1 rounded-md px-2 py-1.5 hover:bg-[var(--surface-elevated)] text-xs transition-colors"
                    >
                      <button
                        type="button"
                        onClick={() => fetchFsDirectory(qr.path)}
                        className="flex items-center gap-2 text-left truncate flex-1 text-[var(--ink-primary)]"
                        title={qr.path}
                      >
                        {qr.kind === "drive" ? (
                          <HardDrive className="w-3.5 h-3.5 text-[var(--sig-gold)] shrink-0" />
                        ) : qr.kind === "project" ? (
                          <FolderOpen className="w-3.5 h-3.5 text-[var(--sig-cyan)] shrink-0" />
                        ) : (
                          <Folder className="w-3.5 h-3.5 text-[var(--ink-muted)] shrink-0" />
                        )}
                        <span className="truncate">{qr.label}</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => handleSelectAndScan(qr.path)}
                        className="opacity-0 group-hover:opacity-100 px-1.5 py-0.5 rounded bg-[var(--sig-cyan)] text-white text-[10px] font-semibold shrink-0 transition-opacity"
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
                          fetchFsDirectory(browseData.parent_path)
                        }
                        title="Up One Directory"
                        className="p-1.5 rounded bg-[var(--surface-panel)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] disabled:opacity-40 text-[var(--ink-primary)] shrink-0"
                      >
                        <CornerLeftUp className="w-3.5 h-3.5" />
                      </button>
                      <div className="px-2.5 py-1 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] font-mono text-xs text-[var(--sig-cyan)] truncate flex-1">
                        {browseData?.current_path || "Loading..."}
                      </div>
                    </div>

                    <input
                      type="text"
                      value={fsFilter}
                      onChange={(e) => setFsFilter(e.target.value)}
                      placeholder="Filter folders/files..."
                      className="w-40 bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded px-2.5 py-1 text-xs text-[var(--ink-primary)] placeholder-[var(--ink-muted)] focus:outline-none focus:border-[var(--sig-cyan)]"
                    />

                    {targetPickerTab === "FOLDER" &&
                      browseData?.current_path && (
                        <button
                          type="button"
                          onClick={() =>
                            handleSelectAndScan(browseData.current_path)
                          }
                          className="px-3 py-1.5 rounded-md bg-[var(--sig-cyan)] hover:opacity-90 text-white text-xs font-semibold flex items-center gap-1.5 shrink-0 shadow-sm"
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
                        <Loader2 className="w-4 h-4 animate-spin text-[var(--sig-cyan)]" />
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
                                  className="flex items-center justify-between p-2 rounded-lg border border-[var(--border-hairline)] bg-[var(--surface-elevated)] hover:border-[var(--sig-cyan)]/60 transition-all group"
                                >
                                  <button
                                    type="button"
                                    onClick={() => fetchFsDirectory(dir.path)}
                                    className="flex items-center gap-2 min-w-0 flex-1 text-left"
                                  >
                                    <Folder className="w-4 h-4 text-[var(--sig-cyan)] shrink-0" />
                                    <span className="text-xs font-mono text-[var(--ink-primary)] truncate">
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
                                      className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-primary)] text-[10px] font-medium"
                                    >
                                      Select
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        handleSelectAndScan(dir.path)
                                      }
                                      className="px-2 py-0.5 rounded bg-[var(--sig-cyan)] text-white text-[10px] font-semibold flex items-center gap-1"
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
                                      ? "border-[var(--sig-emerald)]/40 bg-[var(--surface-elevated)] hover:border-[var(--sig-emerald)]"
                                      : "border-[var(--border-hairline)] bg-[var(--surface-void)]"
                                  }`}
                                >
                                  <div className="flex items-center gap-2 min-w-0 flex-1">
                                    <FileCode2
                                      className={`w-4 h-4 shrink-0 ${
                                        file.is_code
                                          ? "text-[var(--sig-emerald)]"
                                          : "text-[var(--ink-muted)]"
                                      }`}
                                    />
                                    <div className="min-w-0">
                                      <div className="text-xs font-mono text-[var(--ink-primary)] truncate">
                                        {file.name}
                                      </div>
                                      <div className="text-[10px] font-mono text-[var(--ink-muted)]">
                                        {(file.size_bytes / 1024).toFixed(1)} KB{" "}
                                        {file.is_code && (
                                          <span className="text-[var(--sig-emerald)] ml-1">
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
                                      className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-primary)] text-[10px] font-medium"
                                    >
                                      Select
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        handleSelectAndScan(file.path)
                                      }
                                      className="px-2 py-0.5 rounded bg-[var(--sig-emerald)] text-white text-[10px] font-semibold flex items-center gap-1"
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
                    <FolderGit2 className="w-4 h-4 text-[var(--sig-cyan)]" />
                    GitHub Repository &amp; Remote Source Scanner
                  </h3>
                  <p className="text-xs text-[var(--ink-muted)] mt-0.5">
                    For <b className="text-[var(--sig-emerald)]">Open / Public</b>{" "}
                    repositories, simply paste the GitHub URL and click{" "}
                    <b>Clone &amp; Scan</b>. For{" "}
                    <b className="text-[var(--sig-gold)]">Private</b>{" "}
                    repositories, provide a GitHub Personal Access Token (
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
                        ? "bg-[var(--surface-elevated)] border-[var(--sig-emerald)] shadow-sm"
                        : "bg-[var(--surface-void)] border-[var(--border-hairline)]"
                    }`}
                  >
                    <div className="p-1.5 rounded-lg border border-[var(--sig-emerald)]/50 text-[var(--sig-emerald)] shrink-0">
                      <Unlock className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-[var(--ink-primary)] flex items-center gap-1.5">
                        <span>Open / Public Repository</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--surface-void)] text-[var(--sig-emerald)] border border-[var(--sig-emerald)]/50">
                          NO TOKEN
                        </span>
                      </div>
                      <p className="text-[11px] text-[var(--ink-muted)] mt-0.5">
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
                        ? "bg-[var(--surface-elevated)] border-[var(--sig-gold)] shadow-sm"
                        : "bg-[var(--surface-void)] border-[var(--border-hairline)]"
                    }`}
                  >
                    <div className="p-1.5 rounded-lg border border-[var(--sig-gold)]/50 text-[var(--sig-gold)] shrink-0">
                      <Lock className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-[var(--ink-primary)] flex items-center gap-1.5">
                        <span>Private Repository</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--surface-void)] text-[var(--sig-gold)] border border-[var(--sig-gold)]/50">
                          AUTH REQUIRED
                        </span>
                      </div>
                      <p className="text-[11px] text-[var(--ink-muted)] mt-0.5">
                        Authenticate securely with a GitHub Fine-Grained or
                        Classic Personal Access Token.
                      </p>
                    </div>
                  </button>
                </div>

                {/* Error Banner */}
                {(localGitError || gitScanErrorBanner) && (
                  <div className="p-3 rounded-xl bg-[var(--surface-elevated)] border border-[var(--sig-crimson)] flex items-start gap-2.5 text-xs text-[var(--ink-primary)]">
                    <ShieldAlert className="w-4 h-4 text-[var(--sig-crimson)] shrink-0 mt-0.5" />
                    <div className="flex-1 leading-relaxed">
                      <div className="font-bold text-[var(--sig-crimson)]">
                        Repository Access / Authentication Required
                      </div>
                      <div className="text-[11px] text-[var(--ink-muted)] mt-0.5">
                        {localGitError || gitScanErrorBanner}
                      </div>
                    </div>
                  </div>
                )}

                {/* Repo URL + Branch + Verify + Scan Controls */}
                <div className="space-y-2.5 bg-[var(--surface-elevated)] border border-[var(--border-hairline)] rounded-xl p-3.5">
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
                    <div className="md:col-span-8">
                      <label className="block text-[11px] font-mono text-[var(--ink-primary)] mb-1">
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
                            handleScanGitHubRepo();
                          }
                        }}
                        placeholder="https://github.com/owner/repository (or /tree/branch)"
                        className="w-full bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--ink-primary)] focus:outline-none focus:border-[var(--sig-cyan)]"
                      />
                    </div>
                    <div className="md:col-span-4">
                      <label className="block text-[11px] font-mono text-[var(--ink-primary)] mb-1 flex items-center gap-1">
                        <GitBranch className="w-3 h-3 text-[var(--sig-cyan)]" />
                        <span>Branch / Tag (Optional)</span>
                      </label>
                      <input
                        type="text"
                        value={repoBranch}
                        onChange={(e) => setRepoBranch(e.target.value)}
                        placeholder="default (e.g. main)"
                        className="w-full bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--ink-primary)] focus:outline-none focus:border-[var(--sig-cyan)]"
                      />
                    </div>
                  </div>

                  {/* Private Repository Auth Panel */}
                  {repoVisibilityMode === "PRIVATE" && (
                    <div className="pt-2 mt-2 border-t border-[var(--border-hairline)] space-y-2.5">
                      <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
                        <div className="md:col-span-8">
                          <label className="block text-[11px] font-mono text-[var(--sig-gold)] mb-1 flex items-center justify-between">
                            <span className="flex items-center gap-1.5">
                              <KeyRound className="w-3.5 h-3.5" />
                              <span>Personal Access Token (PAT) *</span>
                            </span>
                            <span className="text-[10px] text-[var(--ink-muted)]">
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
                              className="w-full bg-[var(--surface-void)] border border-[var(--sig-gold)]/60 rounded-lg pl-3 pr-9 py-2 text-xs font-mono text-[var(--ink-primary)] focus:outline-none focus:border-[var(--sig-gold)]"
                            />
                            <button
                              type="button"
                              onClick={() => setShowRepoToken((v) => !v)}
                              title={
                                showRepoToken ? "Hide token" : "Show token"
                              }
                              className="absolute right-2.5 text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
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
                          <label className="block text-[11px] font-mono text-[var(--ink-primary)] mb-1">
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
                            className="w-full bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--ink-primary)] focus:outline-none focus:border-[var(--sig-gold)]"
                          />
                        </div>
                      </div>

                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <label className="flex items-center gap-2 text-xs text-[var(--ink-primary)] cursor-pointer">
                          <input
                            type="checkbox"
                            checked={saveRepoToken}
                            onChange={(e) => setSaveRepoToken(e.target.checked)}
                            className="rounded border-[var(--border-hairline)] bg-[var(--surface-void)]"
                          />
                          <span>
                            Save token in local git-ignored vault (
                            <code>.alastor_vault</code>) for 1-click{" "}
                            <b>Re-Scan &amp; Track Changes</b>
                          </span>
                        </label>
                        <span className="text-[10px] font-mono text-[var(--sig-emerald)]">
                          Passed via ephemeral Git HTTP header — never stored in
                          clone URL
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Action Buttons Row */}
                  <div className="flex items-center justify-between flex-wrap gap-2 pt-1">
                    <label className="flex items-center gap-2 text-xs text-[var(--ink-muted)] cursor-pointer">
                      <input
                        type="checkbox"
                        checked={autoExtractUrlVulns}
                        onChange={(e) =>
                          setAutoExtractUrlVulns(e.target.checked)
                        }
                        className="rounded border-[var(--border-hairline)] bg-[var(--surface-void)]"
                      />
                      <span>
                        Also correlate live OSV/NVD advisories after scan
                      </span>
                    </label>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={isVerifyingRepo || !urlInput.trim()}
                        onClick={handleVerifyGitHubRepo}
                        className="px-3 py-2 rounded-lg bg-[var(--surface-panel)] hover:bg-[var(--surface-void)] disabled:opacity-50 border border-[var(--border-hairline)] text-[var(--ink-primary)] text-xs font-semibold flex items-center gap-1.5 transition-colors"
                      >
                        {isVerifyingRepo ? (
                          <>
                            <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--sig-cyan)]" />
                            <span>Verifying...</span>
                          </>
                        ) : (
                          <>
                            <CheckCircle2 className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />
                            <span>Verify Repo Access</span>
                          </>
                        )}
                      </button>

                      <button
                        type="button"
                        disabled={isScanning || !urlInput.trim()}
                        onClick={() => handleScanGitHubRepo()}
                        className={`px-4 py-2 rounded-lg text-white text-xs font-bold flex items-center gap-1.5 shadow-md transition-opacity disabled:opacity-50 ${
                          repoVisibilityMode === "PRIVATE"
                            ? "bg-[var(--sig-gold)] hover:opacity-90"
                            : "bg-[var(--sig-cyan)] hover:opacity-90"
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
                    className={`p-3 rounded-xl border text-xs flex items-start justify-between gap-3 flex-wrap bg-[var(--surface-elevated)] ${
                      verifyResult.accessible
                        ? "border-[var(--sig-emerald)]"
                        : "border-[var(--sig-gold)]"
                    }`}
                  >
                    <div className="space-y-1 min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold font-mono text-[var(--ink-primary)]">
                          {verifyResult.full_name ||
                            verifyResult.normalized_url}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            verifyResult.is_private
                              ? "text-[var(--sig-gold)] border-[var(--sig-gold)]"
                              : "text-[var(--sig-emerald)] border-[var(--sig-emerald)]"
                          }`}
                        >
                          {verifyResult.is_private === true
                            ? "PRIVATE REPO 🔒"
                            : verifyResult.is_private === false
                            ? "OPEN / PUBLIC 🌐"
                            : "REMOTE TARGET"}
                        </span>
                        {verifyResult.default_branch && (
                          <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-primary)] text-[10px] font-mono">
                            branch: {verifyResult.default_branch}
                          </span>
                        )}
                        {verifyResult.primary_language && (
                          <span className="px-2 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--sig-cyan)] text-[10px] font-mono">
                            {verifyResult.primary_language}
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-[var(--ink-muted)]">
                        {verifyResult.message}
                      </div>
                    </div>
                  </div>
                )}

                {/* 1-Click Open / Public GitHub Repository Samples */}
                <div className="space-y-2 pt-2 border-t border-[var(--border-hairline)]">
                  <div className="text-[11px] font-mono uppercase text-[var(--ink-muted)]">
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
                        className="p-2.5 rounded-lg border border-[var(--border-hairline)] bg-[var(--surface-elevated)] flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-xs font-semibold text-[var(--ink-primary)] truncate">
                            {preset.title}
                          </div>
                          <div className="text-[10px] font-mono text-[var(--sig-cyan)] truncate">
                            {preset.url}
                          </div>
                          <div className="text-[10px] text-[var(--ink-muted)]">
                            {preset.desc}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            setRepoVisibilityMode("PUBLIC");
                            setUrlInput(preset.url);
                            handleScanGitHubRepo(preset.url, true);
                          }}
                          className="px-2.5 py-1 rounded bg-[var(--surface-panel)] hover:bg-[var(--surface-void)] border border-[var(--sig-cyan)]/50 text-[var(--sig-cyan)] text-[11px] font-semibold shrink-0"
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
                <div className="space-y-4 border border-[var(--border-hairline)] rounded-xl p-4 bg-[var(--surface-elevated)] flex flex-col justify-between">
                  <div className="space-y-2">
                    <h3 className="text-sm font-bold text-[var(--ink-primary)] flex items-center gap-2">
                      <Upload className="w-4 h-4 text-[var(--sig-gold)]" />
                      Pick Local File(s) from Computer
                    </h3>
                    <p className="text-xs text-[var(--ink-muted)]">
                      Select one or more source files (`.py`, `.js`, `.ts`,
                      `.tsx`, `.json`, `.yaml`) directly from your computer.
                    </p>
                  </div>

                  <div className="border-2 border-dashed border-[var(--border-hairline)] hover:border-[var(--sig-gold)] rounded-xl p-6 text-center transition-colors">
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
                      <div className="w-10 h-10 rounded-full bg-[var(--surface-void)] border border-[var(--sig-gold)] flex items-center justify-center text-[var(--sig-gold)]">
                        {isUploading ? (
                          <Loader2 className="w-5 h-5 animate-spin" />
                        ) : (
                          <Upload className="w-5 h-5" />
                        )}
                      </div>
                      <span className="text-xs font-semibold text-[var(--ink-primary)]">
                        Click to Choose File(s) to Scan
                      </span>
                      <span className="text-[11px] text-[var(--ink-muted)] font-mono">
                        Supports .py, .js, .jsx, .ts, .tsx, .json, .yaml
                      </span>
                    </label>
                  </div>
                </div>

                <form
                  onSubmit={handleScanSnippet}
                  className="space-y-3 border border-[var(--border-hairline)] rounded-xl p-4 bg-[var(--surface-elevated)] flex flex-col"
                >
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-[var(--ink-primary)] flex items-center gap-2">
                      <FileCode2 className="w-4 h-4 text-[var(--sig-cyan)]" />
                      Paste Code Snippet to Scan
                    </h3>
                    <input
                      type="text"
                      value={snippetFilename}
                      onChange={(e) => setSnippetFilename(e.target.value)}
                      placeholder="snippet.py"
                      className="w-36 bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded px-2 py-1 text-xs font-mono text-[var(--sig-cyan)]"
                    />
                  </div>
                  <textarea
                    rows={7}
                    value={snippetContent}
                    onChange={(e) => setSnippetContent(e.target.value)}
                    placeholder="Paste Python, JavaScript, or TypeScript code here..."
                    className="w-full flex-1 bg-[var(--surface-void)] border border-[var(--border-hairline)] rounded-lg p-2.5 text-xs font-mono text-[var(--ink-primary)] focus:outline-none focus:border-[var(--sig-cyan)]"
                  />
                  <button
                    type="submit"
                    disabled={isUploading}
                    className="w-full py-2 rounded-lg bg-[var(--sig-cyan)] hover:opacity-90 text-white text-xs font-semibold flex items-center justify-center gap-1.5 shadow"
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
