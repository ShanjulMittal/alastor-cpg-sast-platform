"use client";

import React, { useState, useEffect, useRef } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  ShieldAlert,
  Flame,
  Info,
  Network,
  GitCommit,
  Play,
  Loader2,
  Database,
  Layers,
  FileCode2,
  Globe,
  Download,
  FolderOpen,
  FileText,
  Link2,
  Upload,
  ChevronDown,
  ChevronRight,
  CornerLeftUp,
  HardDrive,
  Folder,
  X,
  Sparkles,
  CheckCircle2,
  ExternalLink,
  Maximize2,
  Settings,
  Ticket,
  PieChart,
  FolderGit2,
  Code2,
  Users,
  Search,
  Menu,
  SlidersHorizontal,
} from "lucide-react";
import {
  AlastorBrandHeader,
  AlastorThemeSwitcher,
} from "./AlastorBranding";

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

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

export function TopMetricsBar() {
  const metrics = useAuditStore((s) => s.metrics);
  const appTree = useAuditStore((s) => s.appTree);
  const isScanning = useAuditStore((s) => s.isScanning);
  const scanStatusMessage = useAuditStore((s) => s.scanStatusMessage);
  const scanProgress = useAuditStore((s) => s.scanProgress);
  const projectPath = useAuditStore((s) => s.projectPath);
  const setProjectPath = useAuditStore((s) => s.setProjectPath);
  const triggerScan = useAuditStore((s) => s.triggerScan);
  const setActiveSidebarTab = useAuditStore((s) => s.setActiveSidebarTab);
  const extractAndScanFromSites = useAuditStore((s) => s.extractAndScanFromSites);
  const isExtractingIntel = useAuditStore((s) => s.isExtractingIntel);
  const exportAuditReport = useAuditStore((s) => s.exportAuditReport);
  const setGraphFullscreen = useAuditStore((s) => s.setGraphFullscreen);
  const workspaceViewMode = useAuditStore((s) => s.workspaceViewMode);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);
  const setSettingsModalOpen = useAuditStore((s) => s.setSettingsModalOpen);
  const setIntegrationModalOpen = useAuditStore((s) => s.setIntegrationModalOpen);
  const integrationState = useAuditStore((s) => s.integrationState);
  const setShowPortalGate = useAuditStore((s) => s.setShowPortalGate);
  const activeOperator = useAuditStore((s) => s.activeOperator);
  const uiDensityMode = useAuditStore((s) => s.uiDensityMode);
  const setUiDensityMode = useAuditStore((s) => s.setUiDensityMode);
  const isMenuBarExpanded = useAuditStore((s) => s.isMenuBarExpanded);
  const setMenuBarExpanded = useAuditStore((s) => s.setMenuBarExpanded);
  const setQuickCommandOpen = useAuditStore((s) => s.setQuickCommandOpen);

  const [inputPath, setInputPath] = useState(projectPath);
  const [isPickerOpen, setIsPickerOpen] = useState(false);
  const [pickerTab, setPickerTab] = useState<"FOLDER" | "FILE" | "URL" | "UPLOAD">("FOLDER");

  // Visual Filesystem Browser State
  const [browseData, setBrowseData] = useState<FsBrowseData | null>(null);
  const [isLoadingFs, setIsLoadingFs] = useState(false);
  const [fsFilter, setFsFilter] = useState("");
  const [isNativeDialogOpen, setIsNativeDialogOpen] = useState(false);

  // URL Target State
  const [urlInput, setUrlInput] = useState("");
  const [autoExtractUrlVulns, setAutoExtractUrlVulns] = useState(true);

  // Upload / Snippet State
  const [snippetFilename, setSnippetFilename] = useState("snippet.py");
  const [snippetContent, setSnippetContent] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const fileUploadInputRef = useRef<HTMLInputElement | null>(null);

  // Recent targets history (strictly real local directories, zero synthetic demo paths)
  const [recentTargets, setRecentTargets] = useState<string[]>([
    "C:\\Projects\\Securecodereview\\cpg-sast-platform",
    "C:\\Projects\\MISP",
    "C:\\Projects\\NewsLetter",
    "C:\\Projects\\Securecodereview",
  ]);

  useEffect(() => {
    setInputPath(projectPath);
  }, [projectPath]);

  const addRecentTarget = (target: string) => {
    if (!target.trim()) return;
    setRecentTargets((prev) => [target, ...prev.filter((item) => item !== target)].slice(0, 8));
  };

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
    setPickerTab(tab);
    setIsPickerOpen(true);
    if (tab === "FOLDER" || tab === "FILE") {
      fetchFsDirectory(browseData?.current_path);
    }
  };

  const handleSelectAndScan = async (target: string, alsoExtractSiteUrl?: string) => {
    const clean = target.trim();
    if (!clean) return;
    setInputPath(clean);
    setProjectPath(clean);
    addRecentTarget(clean);
    setIsPickerOpen(false);
    await triggerScan(clean);
    if (alsoExtractSiteUrl && alsoExtractSiteUrl.startsWith("http")) {
      await extractAndScanFromSites({
        sources: ["osv", "nvd", "cisa_owasp"],
        customUrls: [alsoExtractSiteUrl],
      });
    }
  };

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    handleSelectAndScan(inputPath, inputPath.startsWith("http") ? inputPath : undefined);
  };

  const handleNativeOsDialog = async (mode: "folder" | "file", autoScanAfterPick = false) => {
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
          addRecentTarget(data.selected_path);
          if (autoScanAfterPick) {
            setIsPickerOpen(false);
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

  const handleBrowserFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
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

      const batchName = fileList.length === 1 ? fileList[0].name.replace(/[^a-zA-Z0-9._-]/g, "_") : "uploaded_project";
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
          files: [{ filepath: snippetFilename.trim() || "snippet.py", content: snippetContent }],
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

  // Detect target badge type
  const targetBadge = (() => {
    const v = inputPath.trim();
    if (v.startsWith("http://") || v.startsWith("https://") || v.startsWith("git@")) {
      return { label: "URL", color: "bg-indigo-950 text-indigo-300 border-indigo-700" };
    }
    if (/\.(py|js|jsx|ts|tsx|json|yaml|yml|html)$/i.test(v)) {
      return { label: "FILE", color: "bg-emerald-950 text-emerald-300 border-emerald-700" };
    }
    return { label: "FOLDER", color: "bg-cyan-950 text-cyan-300 border-cyan-800" };
  })();

  const detectedTech = appTree?.detected_tech_stack || metrics?.tech_stack || [];
  const totalFiles = appTree?.total_files || metrics?.total_app_files || 0;

  const showProgress = isScanning || (scanProgress && scanProgress.is_scanning);
  const percent = scanProgress?.percent ?? (isScanning ? 10 : 0);
  const currentPass = scanProgress?.current_pass || (isScanning ? "Scanning Target..." : "");
  const currentFile = scanProgress?.current_file || "";
  const filesDone = scanProgress?.files_done ?? 0;
  const totalScanFiles = scanProgress?.total_files ?? 0;
  const progressMessage = scanProgress?.message || scanStatusMessage || "";

  const filteredDirs = (browseData?.directories || []).filter(
    (d) => !fsFilter.trim() || d.name.toLowerCase().includes(fsFilter.toLowerCase())
  );
  const filteredFiles = (browseData?.files || []).filter(
    (f) => !fsFilter.trim() || f.name.toLowerCase().includes(fsFilter.toLowerCase())
  );

  const [showQuickGuide, setShowQuickGuide] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);

  return (
    <div className="flex flex-col border-b border-zinc-800 bg-zinc-950/95 select-none relative z-40">
      {/* Primary Top Bar */}
      <header className="h-14 px-4 flex items-center justify-between gap-3">
        {/* Left: Brand & Clean 5-Tab Workspace Navigation */}
        <div className="flex items-center gap-3 shrink-0">
          <AlastorBrandHeader />

          {/* 5-Module Workspace Switcher */}
          <div className="flex items-center bg-zinc-900/90 border border-zinc-800 rounded-xl p-1 text-xs font-medium gap-0.5">
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("PROJECTS_HUB")}
              title="1. Projects & Saved Scans Hub (Switch apps, view saved scan snapshots, or add repository)"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all ${
                workspaceViewMode === "PROJECTS_HUB"
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-700/80 font-bold shadow-sm"
                  : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60"
              }`}
            >
              <FolderGit2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>Projects</span>
            </button>
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("DEEP_DIVE")}
              title="2. Overview & Deep-Dive Analytics (Security Posture, OWASP/SANS Compliance, Fix First List)"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all ${
                workspaceViewMode === "DEEP_DIVE"
                  ? "bg-indigo-950 text-indigo-300 border border-indigo-700/80 font-bold shadow-sm"
                  : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60"
              }`}
            >
              <PieChart className="w-3.5 h-3.5 text-indigo-400" />
              <span>Overview</span>
            </button>
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("REMEDIATION_IDE")}
              title="3. Code & Graph Review Workspace (Findings, Source Code, Plain-English Fixes & CPG Graph)"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all ${
                workspaceViewMode === "REMEDIATION_IDE"
                  ? "bg-emerald-950 text-emerald-300 border border-emerald-700/80 font-bold shadow-sm"
                  : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60"
              }`}
            >
              <Code2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>Code &amp; Graph</span>
            </button>
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("RACI_GOVERNANCE")}
              title="4. RACI Governance & Role Accountability Matrix (Responsible, Accountable, Consulted, Informed)"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all ${
                workspaceViewMode === "RACI_GOVERNANCE"
                  ? "bg-amber-950 text-amber-300 border border-amber-700/80 font-bold shadow-sm"
                  : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60"
              }`}
            >
              <Users className="w-3.5 h-3.5 text-amber-400" />
              <span>RACI</span>
            </button>
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("SAST_PLUS_SUITE")}
              title="5. SAST++++++ Suite (Plain-English Risk Translator, Live SBOM, Attack Surface, Roadmap & Academy)"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all ${
                workspaceViewMode === "SAST_PLUS_SUITE"
                  ? "bg-rose-950 text-rose-300 border border-rose-700/80 font-bold shadow-sm"
                  : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60"
              }`}
            >
              <Sparkles className="w-3.5 h-3.5 text-rose-400" />
              <span>SAST++++++</span>
            </button>
          </div>
        </div>

        {/* Center: Target Picker, Scan & Global Quick Find (Streamlined in Simple Mode, Expanded in Pro Mode) */}
        {uiDensityMode === "SIMPLE_CLEAN" ? (
          <div className="flex items-center gap-2 flex-1 max-w-xl justify-center">
            {/* Clean 1-Click Target Browser Button */}
            <button
              type="button"
              onClick={() => openPickerModal("FOLDER")}
              title="Browse and select any Folder, Single File, URL/Git Repo, or Upload Code to scan"
              className="px-3 py-1.5 rounded-xl bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-xs font-medium text-zinc-200 flex items-center gap-2 transition-colors shrink-0"
            >
              <FolderOpen className="w-3.5 h-3.5 text-cyan-400" />
              <span>Select Target...</span>
            </button>

            {/* Primary Scan Action */}
            <button
              type="button"
              disabled={isScanning}
              onClick={() => handleSelectAndScan(inputPath || projectPath)}
              title="Run CPG SAST + SCA + Secrets Scan on the active target"
              className="bg-cyan-600 hover:bg-cyan-500 disabled:bg-zinc-800 text-white font-semibold text-xs px-3.5 py-1.5 rounded-xl flex items-center gap-1.5 transition-colors shadow-sm shadow-cyan-900/50 shrink-0"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-200" />
                  <span>Scanning {percent}%</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Scan</span>
                </>
              )}
            </button>

            {/* Global Quick Find & Command Palette Trigger (Ctrl+K) */}
            <button
              type="button"
              onClick={() => setQuickCommandOpen(true)}
              title="Search any feature, page, scan action, export, finding, or file (Ctrl+K)"
              className="flex-1 max-w-xs px-3 py-1.5 rounded-xl bg-zinc-900/90 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-xs text-zinc-400 hover:text-zinc-200 flex items-center justify-between gap-2 transition-colors"
            >
              <span className="flex items-center gap-2 truncate">
                <Search className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="truncate">Quick Find / All Actions...</span>
              </span>
              <kbd className="px-1.5 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-[10px] font-mono text-zinc-400 shrink-0">
                Ctrl+K
              </kbd>
            </button>
          </div>
        ) : (
          <form onSubmit={handleScan} className="flex items-center gap-1.5 flex-1 max-w-2xl">
            <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-md p-0.5 shrink-0">
              <button
                type="button"
                onClick={() => openPickerModal("FOLDER")}
                title="Browse & Select a Local Project Folder"
                className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium text-cyan-300 hover:bg-zinc-800 transition-colors"
              >
                <FolderOpen className="w-3.5 h-3.5 text-cyan-400" />
                <span>Folder</span>
              </button>
              <button
                type="button"
                onClick={() => openPickerModal("FILE")}
                title="Browse & Select a Single Source File"
                className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium text-emerald-300 hover:bg-zinc-800 transition-colors"
              >
                <FileText className="w-3.5 h-3.5 text-emerald-400" />
                <span>File</span>
              </button>
              <button
                type="button"
                onClick={() => openPickerModal("URL")}
                title="Scan a Remote URL, GitHub Repo, or Webpage"
                className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium text-indigo-300 hover:bg-zinc-800 transition-colors"
              >
                <Link2 className="w-3.5 h-3.5 text-indigo-400" />
                <span>URL</span>
              </button>
              <button
                type="button"
                onClick={() => openPickerModal("UPLOAD")}
                title="Upload Local File(s) or Paste Code Snippet"
                className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium text-amber-300 hover:bg-zinc-800 transition-colors"
              >
                <Upload className="w-3.5 h-3.5 text-amber-400" />
                <span className="hidden xl:inline">Upload</span>
              </button>
            </div>

            <div className="relative flex-1 min-w-[160px]">
              <span
                className={`absolute left-2 top-1/2 -translate-y-1/2 text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${targetBadge.color}`}
              >
                {targetBadge.label}
              </span>
              <input
                type="text"
                list="common-scan-targets"
                value={inputPath}
                onChange={(e) => setInputPath(e.target.value)}
                placeholder="Select Folder, File, or URL (https://...)..."
                className="w-full bg-zinc-900 border border-zinc-800 rounded-md pl-16 pr-7 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
              />
              <button
                type="button"
                onClick={() => openPickerModal("FOLDER")}
                title="Open Visual Target Browser"
                className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1 text-zinc-400 hover:text-cyan-300 rounded"
              >
                <ChevronDown className="w-3.5 h-3.5" />
              </button>
              <datalist id="common-scan-targets">
                {recentTargets.map((rt) => (
                  <option key={rt} value={rt} />
                ))}
              </datalist>
            </div>

            <button
              type="submit"
              disabled={isScanning}
              className="bg-cyan-600 hover:bg-cyan-500 disabled:bg-zinc-800 text-white font-semibold text-xs px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-colors shadow-sm shadow-cyan-900/50 shrink-0"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                  <span>{percent}%</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Scan</span>
                </>
              )}
            </button>

            <button
              type="button"
              disabled={isExtractingIntel}
              onClick={() => {
                setActiveSidebarTab("SITE_EXTRACTOR");
                extractAndScanFromSites({
                  sources: ["osv", "nvd", "cisa_owasp"],
                  customUrls: inputPath.startsWith("http") ? [inputPath] : [],
                });
              }}
              title="Pull live advisories from OSV.dev, NIST NVD, MITRE CWE & OWASP"
              className="bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700/80 text-indigo-200 font-medium text-xs px-2.5 py-1.5 rounded-md flex items-center gap-1.5 transition-colors shrink-0"
            >
              {isExtractingIntel ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-400" />
              ) : (
                <Globe className="w-3.5 h-3.5 text-indigo-400" />
              )}
              <span className="hidden lg:inline">Web Vulns</span>
            </button>

            <button
              type="button"
              onClick={() => setGraphFullscreen(true)}
              title="Open Full-Screen Graph Presentation View"
              className="bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/80 text-cyan-200 font-medium text-xs px-2.5 py-1.5 rounded-md flex items-center gap-1.5 transition-colors shrink-0"
            >
              <Maximize2 className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden xl:inline">Present</span>
            </button>
          </form>
        )}

        {/* Right: Clean Posture Summary, Simple/Pro Mode Switch, Menus Toggle, Export & Settings */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Unified Findings Posture Pill */}
          {(metrics?.total_findings ?? 0) === 0 ? (
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("DEEP_DIVE")}
              title="0 Active Vulnerabilities — Click to view full Executive Posture Summary"
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-emerald-950/70 border border-emerald-700/70 text-emerald-300 text-xs font-semibold"
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>0 Flaws</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setWorkspaceViewMode("REMEDIATION_IDE")}
              title="Click to inspect findings in Code & Graph Review"
              className="flex items-center gap-2 px-2.5 py-1 rounded-xl bg-rose-950/60 border border-rose-800/80 text-xs font-mono"
            >
              <span className="text-red-300 font-bold flex items-center gap-1">
                <Flame className="w-3.5 h-3.5 text-red-500" />
                {metrics?.critical_count ?? 0} Crit
              </span>
              <span className="text-zinc-600">•</span>
              <span className="text-amber-300 font-bold">
                {metrics?.high_count ?? 0} High
              </span>
              <span className="text-zinc-600">•</span>
              <span className="text-zinc-200 font-bold">
                {metrics?.total_findings ?? 0} Total
              </span>
            </button>
          )}

          {/* Simple Clean vs Pro Detailed View Mode Switcher */}
          <button
            type="button"
            onClick={() =>
              setUiDensityMode(
                uiDensityMode === "SIMPLE_CLEAN" ? "PRO_DETAILED" : "SIMPLE_CLEAN"
              )
            }
            title="Switch between Simple Clean View (streamlined layout) and Pro Detailed View (all toolbars & ribbons expanded)"
            className={`px-2.5 py-1.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all ${
              uiDensityMode === "SIMPLE_CLEAN"
                ? "bg-emerald-950/70 hover:bg-emerald-900/80 border-emerald-700/70 text-emerald-300"
                : "bg-amber-950/70 hover:bg-amber-900/80 border-amber-700/70 text-amber-300"
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            <span>{uiDensityMode === "SIMPLE_CLEAN" ? "✨ Simple View" : "🎛️ Pro View"}</span>
          </button>

          {/* Toggle Full Desktop Menu & Quick Settings Ribbon */}
          <button
            type="button"
            onClick={() => setMenuBarExpanded(!isMenuBarExpanded)}
            title="Show or hide the full SAST++++++ Desktop Menu Bar & Quick Settings Ribbon"
            className={`px-2.5 py-1.5 rounded-xl border text-xs font-medium flex items-center gap-1.5 transition-colors ${
              isMenuBarExpanded
                ? "bg-cyan-950 text-cyan-300 border-cyan-700"
                : "bg-zinc-900 hover:bg-zinc-800 border-zinc-700 text-zinc-300"
            }`}
          >
            <Menu className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden xl:inline">Menus</span>
          </button>

          {/* Export Report Dropdown */}
          <div className="relative shrink-0">
            <button
              type="button"
              onClick={() => setShowExportMenu((v) => !v)}
              title="Download Security Audit Report (Markdown, JSON, or SARIF)"
              className="bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-200 font-medium text-xs px-2.5 py-1.5 rounded-xl flex items-center gap-1 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden lg:inline">Export</span>
              <ChevronDown className="w-3 h-3 text-zinc-400" />
            </button>

            {showExportMenu && (
              <div className="absolute right-0 mt-1.5 w-60 rounded-xl bg-zinc-950 border border-zinc-700 shadow-2xl p-1.5 z-50 space-y-1 text-left">
                <button
                  type="button"
                  onClick={() => {
                    setShowExportMenu(false);
                    exportAuditReport("markdown");
                  }}
                  className="w-full p-2 rounded-lg hover:bg-zinc-900 flex flex-col gap-0.5 text-left"
                >
                  <span className="text-xs font-semibold text-zinc-100">
                    Markdown Audit Report (.md)
                  </span>
                  <span className="text-[10px] text-zinc-400">
                    Human-readable executive summary, stories &amp; fixes
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowExportMenu(false);
                    exportAuditReport("json");
                  }}
                  className="w-full p-2 rounded-lg hover:bg-zinc-900 flex flex-col gap-0.5 text-left"
                >
                  <span className="text-xs font-semibold text-zinc-100">
                    JSON Full Data (.json)
                  </span>
                  <span className="text-[10px] text-zinc-400">
                    Machine-readable findings, metrics &amp; advisories
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowExportMenu(false);
                    exportAuditReport("sarif");
                  }}
                  className="w-full p-2 rounded-lg hover:bg-zinc-900 flex flex-col gap-0.5 text-left"
                >
                  <span className="text-xs font-semibold text-zinc-100">
                    GitHub / IDE SARIF (.sarif.json)
                  </span>
                  <span className="text-[10px] text-zinc-400">
                    Standard static analysis format for CI/CD pipelines
                  </span>
                </button>
              </div>
            )}
          </div>

          {/* Integration Hub (Jira / GitHub Issues) Button */}
          <button
            type="button"
            onClick={() => setIntegrationModalOpen(true)}
            title="Integration Hub: Connect Jira & GitHub Issues"
            className="px-2.5 py-1.5 rounded-xl border bg-indigo-950/80 hover:bg-indigo-900 border-indigo-700/80 text-indigo-200 text-xs font-medium flex items-center gap-1 transition-colors"
          >
            <Ticket className="w-3.5 h-3.5 text-indigo-400" />
            <span className="hidden 2xl:inline">Tickets</span>
            {integrationState?.tickets && integrationState.tickets.length > 0 && (
              <span className="px-1 py-0.1 rounded bg-indigo-900 text-[9px] font-mono font-bold text-white">
                {integrationState.tickets.length}
              </span>
            )}
          </button>

          {/* Theme & Light Mode Switcher */}
          <AlastorThemeSwitcher />

          {/* Gear Icon: Settings, Presets, Query Viewer & Customization Engine */}
          <button
            type="button"
            onClick={() => setSettingsModalOpen(true)}
            title="Settings & Customization (Scan Presets, Global vs Project Overrides, Query Viewer, Custom Sanitizers)"
            className="p-1.5 rounded-xl border bg-zinc-900 hover:bg-zinc-800 border-zinc-700 text-zinc-200 hover:text-cyan-300 flex items-center gap-1 transition-colors"
          >
            <Settings className="w-4 h-4 text-cyan-400" />
          </button>

          {/* Interactive How-It-Works Guide Button */}
          <button
            type="button"
            onClick={() => setShowQuickGuide((v) => !v)}
            title="Show/Hide Quick 4-Step Guide"
            className={`p-1.5 rounded-xl border text-xs font-medium flex items-center gap-1 transition-colors ${
              showQuickGuide
                ? "bg-cyan-950 text-cyan-300 border-cyan-700"
                : "bg-zinc-900 text-zinc-300 border-zinc-700 hover:bg-zinc-800"
            }`}
          >
            <Info className="w-4 h-4 text-cyan-400" />
          </button>
        </div>
      </header>

      {/* Self-Explanatory Quick Guide Banner */}
      {showQuickGuide && (
        <div className="bg-zinc-900/95 border-t border-cyan-900/60 px-4 py-3 text-xs">
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-cyan-300 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5" />
              How to Use ALASTOR • Daimon CPG-SAST (4 Simple Steps)
            </span>
            <button
              type="button"
              onClick={() => setShowQuickGuide(false)}
              className="text-zinc-400 hover:text-zinc-200 text-[11px] font-mono flex items-center gap-1"
            >
              <span>Close Guide</span>
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5">
            <div className="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800">
              <div className="font-bold text-cyan-400 mb-0.5">
                1. Pick Any Target (Top Bar)
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                Click <b>Folder</b>, <b>File</b>, <b>URL</b>, or <b>Upload</b> to select a local folder, single file, GitHub repo, or paste code—no copy-pasting needed.
              </p>
            </div>
            <div className="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800">
              <div className="font-bold text-red-400 mb-0.5">
                2. Select a Finding (Left Panel)
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                Browse <b>1. Findings</b> for code-flow vulnerabilities or <b>2. Web Intel</b> to extract live CVEs/CWEs from security sites and match them in code.
              </p>
            </div>
            <div className="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800">
              <div className="font-bold text-emerald-400 mb-0.5">
                3. Read the Story &amp; Fix (Center Panel)
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                The <b>Attack Storyboard</b> below the code editor explains what happened, why it matters, lets you step through <b>Prev/Next Step</b>, and shows a <b>How to Fix</b> example.
              </p>
            </div>
            <div className="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800">
              <div className="font-bold text-indigo-400 mb-0.5">
                4. Explore Spider Map (Right Panel)
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                Switch between <b>1. Attack Path</b> (traces input to sink) and <b>2. 360° Spider Map</b> (interactive radial web of all folders, files, and symbol references).
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Interactive Target Selector Modal (Folder / Single File / URL / Upload) */}
      {isPickerOpen && (
        <div className="fixed inset-0 z-[200] bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
          <div className="bg-zinc-950 border border-zinc-700 rounded-2xl shadow-2xl w-full max-w-4xl overflow-hidden flex flex-col h-[540px] max-h-[86vh] my-auto">
            {/* Modal Header & Mode Tabs */}
            <div className="px-4 py-3 bg-zinc-900/90 border-b border-zinc-800 flex items-center justify-between flex-wrap gap-2 shrink-0">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-zinc-200 flex items-center gap-1.5">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  Select Scan Target (No Copy-Paste Needed)
                </span>
              </div>

              <div className="flex items-center gap-1 bg-zinc-950 p-1 rounded-lg border border-zinc-800 flex-wrap">
                <button
                  type="button"
                  onClick={() => {
                    setPickerTab("FOLDER");
                    if (!browseData) fetchFsDirectory();
                  }}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    pickerTab === "FOLDER"
                      ? "bg-cyan-950 text-cyan-300 border border-cyan-700/80"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <FolderOpen className="w-3.5 h-3.5" />
                  <span>1. Folder Browser</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setPickerTab("FILE");
                    if (!browseData) fetchFsDirectory();
                  }}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    pickerTab === "FILE"
                      ? "bg-emerald-950 text-emerald-300 border border-emerald-700/80"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>2. Single File</span>
                </button>
                <button
                  type="button"
                  onClick={() => setPickerTab("URL")}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    pickerTab === "URL"
                      ? "bg-indigo-950 text-indigo-300 border border-indigo-700/80"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Link2 className="w-3.5 h-3.5" />
                  <span>3. URL / Git Repo</span>
                </button>
                <button
                  type="button"
                  onClick={() => setPickerTab("UPLOAD")}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    pickerTab === "UPLOAD"
                      ? "bg-amber-950 text-amber-300 border border-amber-700/80"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>4. Upload / Paste Code</span>
                </button>
              </div>

              <button
                type="button"
                onClick={() => setIsPickerOpen(false)}
                className="p-1 text-zinc-400 hover:text-zinc-100 rounded-md hover:bg-zinc-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* TAB 1 & TAB 2: VISUAL FOLDER & FILE EXPLORER */}
            {(pickerTab === "FOLDER" || pickerTab === "FILE") && (
              <div className="flex flex-1 min-h-0 overflow-hidden">
                {/* Left Sidebar: Quick-Access Discovered Projects & Drives */}
                <div className="w-64 border-r border-zinc-800 bg-zinc-900/40 p-3 flex flex-col gap-2 overflow-y-auto">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 font-semibold px-1">
                    Quick-Select Projects & Drives
                  </div>

                  {/* Native Windows Explorer Dialog Trigger */}
                  <button
                    type="button"
                    disabled={isNativeDialogOpen}
                    onClick={() =>
                      handleNativeOsDialog(pickerTab === "FILE" ? "file" : "folder", true)
                    }
                    className="w-full py-2 px-2.5 rounded-lg bg-gradient-to-r from-cyan-950 to-blue-950 hover:from-cyan-900 hover:to-blue-900 border border-cyan-700/80 text-cyan-200 text-xs font-medium flex items-center justify-center gap-1.5 shadow-sm transition-all"
                  >
                    {isNativeDialogOpen ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                        <span>Opening OS Dialog...</span>
                      </>
                    ) : (
                      <>
                        <FolderOpen className="w-3.5 h-3.5 text-cyan-400" />
                        <span>
                          Open Windows {pickerTab === "FILE" ? "File" : "Folder"} Dialog
                        </span>
                      </>
                    )}
                  </button>

                  <div className="border-t border-zinc-800/80 my-1" />

                  {(browseData?.quick_roots || []).map((qr) => (
                    <div
                      key={qr.path}
                      className="group flex items-center justify-between gap-1 rounded-md px-2 py-1.5 hover:bg-zinc-800/80 text-xs transition-colors"
                    >
                      <button
                        type="button"
                        onClick={() => fetchFsDirectory(qr.path)}
                        className="flex items-center gap-2 text-left truncate flex-1 text-zinc-300 group-hover:text-white"
                        title={qr.path}
                      >
                        {qr.kind === "drive" ? (
                          <HardDrive className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                        ) : qr.kind === "project" ? (
                          <FolderOpen className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        ) : (
                          <Folder className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                        )}
                        <span className="truncate">{qr.label}</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => handleSelectAndScan(qr.path)}
                        className="opacity-0 group-hover:opacity-100 px-1.5 py-0.5 rounded bg-cyan-600 hover:bg-cyan-500 text-[10px] font-semibold text-white shrink-0 transition-opacity"
                      >
                        Scan
                      </button>
                    </div>
                  ))}
                </div>

                {/* Right Pane: Interactive Directory & File Navigator */}
                <div className="flex-1 flex flex-col overflow-hidden bg-zinc-950">
                  {/* Current Path Bar & Controls */}
                  <div className="p-3 border-b border-zinc-800 bg-zinc-900/50 flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0 flex-1">
                      <button
                        type="button"
                        disabled={!browseData?.parent_path || isLoadingFs}
                        onClick={() =>
                          browseData?.parent_path && fetchFsDirectory(browseData.parent_path)
                        }
                        title="Up One Directory"
                        className="p-1.5 rounded bg-zinc-800 hover:bg-zinc-700 disabled:opacity-40 text-zinc-200 shrink-0"
                      >
                        <CornerLeftUp className="w-3.5 h-3.5" />
                      </button>
                      <div className="px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 font-mono text-xs text-cyan-300 truncate flex-1">
                        {browseData?.current_path || "Loading..."}
                      </div>
                    </div>

                    <input
                      type="text"
                      value={fsFilter}
                      onChange={(e) => setFsFilter(e.target.value)}
                      placeholder="Filter folders/files..."
                      className="w-40 bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500"
                    />

                    {pickerTab === "FOLDER" && browseData?.current_path && (
                      <button
                        type="button"
                        onClick={() => handleSelectAndScan(browseData.current_path)}
                        className="px-3 py-1.5 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 shrink-0 shadow-sm"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Scan Current Folder</span>
                      </button>
                    )}
                  </div>

                  {/* Directory & File Listing */}
                  <div className="flex-1 overflow-y-auto p-3 space-y-1">
                    {isLoadingFs ? (
                      <div className="flex items-center justify-center h-48 text-zinc-400 text-xs gap-2">
                        <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                        <span>Loading directory contents...</span>
                      </div>
                    ) : (
                      <>
                        {/* Subdirectories */}
                        {filteredDirs.length > 0 && (
                          <div className="mb-3">
                            <div className="text-[10px] font-mono uppercase text-zinc-500 mb-1 px-2">
                              Folders ({filteredDirs.length}) — Click folder name to open, or click &quot;Select &amp; Scan&quot;
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                              {filteredDirs.map((dir) => (
                                <div
                                  key={dir.path}
                                  className="flex items-center justify-between p-2 rounded-lg border border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900 hover:border-cyan-800/60 transition-all group"
                                >
                                  <button
                                    type="button"
                                    onClick={() => fetchFsDirectory(dir.path)}
                                    className="flex items-center gap-2 min-w-0 flex-1 text-left"
                                  >
                                    <Folder className="w-4 h-4 text-cyan-400 shrink-0" />
                                    <span className="text-xs font-mono text-zinc-200 truncate group-hover:text-cyan-300">
                                      {dir.name}
                                    </span>
                                  </button>
                                  <div className="flex items-center gap-1 shrink-0">
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setInputPath(dir.path);
                                        setProjectPath(dir.path);
                                        setIsPickerOpen(false);
                                      }}
                                      className="px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] font-medium"
                                    >
                                      Select
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => handleSelectAndScan(dir.path)}
                                      className="px-2 py-0.5 rounded bg-cyan-600/90 hover:bg-cyan-500 text-white text-[10px] font-semibold flex items-center gap-1"
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

                        {/* Files */}
                        <div>
                          <div className="text-[10px] font-mono uppercase text-zinc-500 mb-1 px-2">
                            Files in Folder ({filteredFiles.length}) — Select any single file to scan directly
                          </div>
                          {filteredFiles.length === 0 ? (
                            <div className="text-xs text-zinc-500 px-2 py-4 font-mono">
                              No files in this directory. Navigate into a subfolder above.
                            </div>
                          ) : (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                              {filteredFiles.map((file) => (
                                <div
                                  key={file.path}
                                  className={`flex items-center justify-between p-2 rounded-lg border transition-all ${
                                    file.is_code
                                      ? "border-emerald-900/50 bg-emerald-950/15 hover:bg-emerald-950/30 hover:border-emerald-700/70"
                                      : "border-zinc-800/70 bg-zinc-900/30 hover:bg-zinc-900"
                                  }`}
                                >
                                  <div className="flex items-center gap-2 min-w-0 flex-1">
                                    <FileCode2
                                      className={`w-4 h-4 shrink-0 ${
                                        file.is_code ? "text-emerald-400" : "text-zinc-500"
                                      }`}
                                    />
                                    <div className="min-w-0">
                                      <div className="text-xs font-mono text-zinc-200 truncate">
                                        {file.name}
                                      </div>
                                      <div className="text-[10px] font-mono text-zinc-500">
                                        {(file.size_bytes / 1024).toFixed(1)} KB{" "}
                                        {file.is_code && (
                                          <span className="text-emerald-400 ml-1">• CPG Supported</span>
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
                                        setIsPickerOpen(false);
                                      }}
                                      className="px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] font-medium"
                                    >
                                      Select
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => handleSelectAndScan(file.path)}
                                      className="px-2 py-0.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] font-semibold flex items-center gap-1"
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

            {/* TAB 3: REMOTE URL / GITHUB REPO / LIVE WEBPAGE SCANNER */}
            {pickerTab === "URL" && (
              <div className="p-6 space-y-5 bg-zinc-950">
                <div>
                  <h3 className="text-sm font-bold text-zinc-100 flex items-center gap-2">
                    <Globe className="w-4 h-4 text-indigo-400" />
                    Scan Remote URL, GitHub Repository, or Live Webpage
                  </h3>
                  <p className="text-xs text-zinc-400 mt-1">
                    Enter any GitHub/GitLab repository URL, a direct GitHub file URL, a raw source code link, or a live webpage URL. ARGON will fetch the target, build its Code Property Graph &amp; Spider App Tree, and scan for vulnerabilities.
                  </p>
                </div>

                <div className="space-y-3">
                  <label className="block text-xs font-mono text-zinc-300">
                    Target URL (Git Repo, File URL, or Webpage)
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="https://github.com/owner/repo or https://example.com/app.py"
                      className="flex-1 bg-zinc-900 border border-zinc-700 rounded-lg px-3.5 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-indigo-500"
                    />
                    <button
                      type="button"
                      onClick={() =>
                        handleSelectAndScan(
                          urlInput,
                          autoExtractUrlVulns ? urlInput : undefined
                        )
                      }
                      className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-md"
                    >
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Fetch &amp; Scan URL</span>
                    </button>
                  </div>

                  <label className="flex items-center gap-2 text-xs text-zinc-300 cursor-pointer pt-1">
                    <input
                      type="checkbox"
                      checked={autoExtractUrlVulns}
                      onChange={(e) => setAutoExtractUrlVulns(e.target.checked)}
                      className="rounded border-zinc-700 bg-zinc-900 text-indigo-500"
                    />
                    <span>
                      Also extract CVE/CWE security advisories from this URL and correlate against code
                    </span>
                  </label>
                </div>

                {/* 1-Click Preset URL Targets */}
                <div className="space-y-2 pt-2 border-t border-zinc-800">
                  <div className="text-[11px] font-mono uppercase text-zinc-400">
                    1-Click Sample URLs &amp; Advisories
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {[
                      {
                        title: "GitHub Python Source File (Flask App Routing)",
                        url: "https://raw.githubusercontent.com/pallets/flask/main/src/flask/app.py",
                        desc: "Fetches single remote Python file & builds CPG + Spider App Tree",
                      },
                      {
                        title: "MITRE CWE-89 SQL Injection Specification",
                        url: "https://cwe.mitre.org/data/definitions/89.html",
                        desc: "Extracts webpage scripts & CWE-89 vulnerability rules",
                      },
                      {
                        title: "MITRE CWE-78 OS Command Injection",
                        url: "https://cwe.mitre.org/data/definitions/78.html",
                        desc: "Extracts CWE-78 advisories & scans workspace",
                      },
                      {
                        title: "OWASP Top 10 Injection Advisory Page",
                        url: "https://owasp.org/Top10/A03_2021-Injection/",
                        desc: "Scrapes OWASP injection patterns & maps target",
                      },
                    ].map((preset) => (
                      <div
                        key={preset.url}
                        className="p-2.5 rounded-lg border border-zinc-800 bg-zinc-900/50 hover:border-indigo-700/70 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-xs font-semibold text-zinc-200 truncate">
                            {preset.title}
                          </div>
                          <div className="text-[10px] font-mono text-indigo-400 truncate">
                            {preset.url}
                          </div>
                          <div className="text-[10px] text-zinc-500">{preset.desc}</div>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            setUrlInput(preset.url);
                            handleSelectAndScan(
                              preset.url,
                              autoExtractUrlVulns ? preset.url : undefined
                            );
                          }}
                          className="px-2.5 py-1 rounded bg-indigo-950 hover:bg-indigo-900 border border-indigo-700 text-indigo-200 text-[11px] font-medium shrink-0"
                        >
                          Use &amp; Scan
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 4: UPLOAD FILES FROM BROWSER OR PASTE CODE SNIPPET */}
            {pickerTab === "UPLOAD" && (
              <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6 bg-zinc-950 overflow-y-auto">
                {/* Left: Browser FilePicker Upload */}
                <div className="space-y-4 border border-zinc-800 rounded-xl p-4 bg-zinc-900/30 flex flex-col justify-between">
                  <div className="space-y-2">
                    <h3 className="text-sm font-bold text-zinc-100 flex items-center gap-2">
                      <Upload className="w-4 h-4 text-amber-400" />
                      Pick Local File(s) from Computer
                    </h3>
                    <p className="text-xs text-zinc-400">
                      Select one or more source files (`.py`, `.js`, `.ts`, `.tsx`, `.json`, `.yaml`) directly from your computer using your browser&apos;s file selector.
                    </p>
                  </div>

                  <div className="border-2 border-dashed border-zinc-700 hover:border-amber-500/80 rounded-xl p-6 text-center transition-colors">
                    <input
                      ref={fileUploadInputRef}
                      type="file"
                      multiple
                      onChange={handleBrowserFileUpload}
                      className="hidden"
                      id="browser-target-file-input"
                    />
                    <label
                      htmlFor="browser-target-file-input"
                      className="cursor-pointer flex flex-col items-center gap-2"
                    >
                      <div className="w-10 h-10 rounded-full bg-amber-950/80 border border-amber-700 flex items-center justify-center text-amber-400">
                        {isUploading ? (
                          <Loader2 className="w-5 h-5 animate-spin" />
                        ) : (
                          <Upload className="w-5 h-5" />
                        )}
                      </div>
                      <span className="text-xs font-semibold text-zinc-200">
                        Click to Choose File(s) to Scan
                      </span>
                      <span className="text-[11px] text-zinc-500 font-mono">
                        Supports .py, .js, .jsx, .ts, .tsx, .json, .yaml
                      </span>
                    </label>
                  </div>
                </div>

                {/* Right: Direct Code Snippet Paste & Scan */}
                <form
                  onSubmit={handleScanSnippet}
                  className="space-y-3 border border-zinc-800 rounded-xl p-4 bg-zinc-900/30 flex flex-col"
                >
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-zinc-100 flex items-center gap-2">
                      <FileCode2 className="w-4 h-4 text-cyan-400" />
                      Paste Code Snippet to Scan
                    </h3>
                    <input
                      type="text"
                      value={snippetFilename}
                      onChange={(e) => setSnippetFilename(e.target.value)}
                      placeholder="snippet.py"
                      className="w-36 bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs font-mono text-cyan-300"
                    />
                  </div>
                  <textarea
                    rows={7}
                    value={snippetContent}
                    onChange={(e) => setSnippetContent(e.target.value)}
                    placeholder="Paste Python, JavaScript, or TypeScript code here..."
                    className="w-full flex-1 bg-zinc-950 border border-zinc-800 rounded-lg p-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500"
                  />
                  <button
                    type="submit"
                    disabled={isUploading}
                    className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center justify-center gap-1.5 shadow"
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

      {/* Live Scan Telemetry Progress Banner */}
      {showProgress && (
        <div className="bg-zinc-900/95 border-t border-cyan-900/40 px-4 py-2 flex flex-col gap-1.5 transition-all">
          <div className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2.5 min-w-0">
              <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700 text-[11px] font-semibold flex items-center gap-1.5 shrink-0 shadow-sm shadow-cyan-950">
                <Loader2 className="w-3 h-3 animate-spin text-cyan-400" />
                {currentPass}
              </span>

              {totalScanFiles > 0 && (
                <span className="text-zinc-400 text-xs shrink-0">
                  <span className="text-zinc-100 font-bold">{filesDone}</span> / {totalScanFiles} files
                </span>
              )}

              {currentFile && (
                <span className="text-zinc-400 truncate text-[11px] max-w-[450px]" title={currentFile}>
                  <FileCode2 className="w-3 h-3 inline mr-1 text-zinc-500" />
                  {currentFile}
                </span>
              )}

              <span className="text-zinc-500 hidden md:inline text-[11px] truncate">
                {progressMessage}
              </span>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <span className="text-sm font-bold font-mono text-cyan-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.6)]">
                {percent}%
              </span>
            </div>
          </div>

          <div className="w-full h-1.5 bg-zinc-800/80 rounded-full overflow-hidden relative border border-zinc-700/50">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 rounded-full transition-all duration-300 ease-out shadow-[0_0_12px_rgba(6,182,212,0.8)] relative"
              style={{ width: `${Math.max(2, Math.min(100, percent))}%` }}
            >
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-pulse" />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
