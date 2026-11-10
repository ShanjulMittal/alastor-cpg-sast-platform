"use client";

import React, { useState, useEffect, useMemo } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  Search,
  X,
  FolderGit2,
  BarChart3,
  Shield,
  Users,
  Sparkles,
  RefreshCw,
  GitCompare,
  Settings,
  Ticket,
  Download,
  Code2,
  Network,
  Columns,
  GraduationCap,
  Cpu,
  AlertTriangle,
  FileCode2,
  Layers,
  BookOpen,
  ShieldAlert,
  Sliders,
  Compass,
  GitPullRequest,
  KeyRound,
  Zap,
  Bot,
  Wand2,
  CheckCircle2,
  FileSpreadsheet,
} from "lucide-react";

type CommandCategory =
  | "4-Stage Guided Workflow"
  | "Frontier AI & Batch Auto-Fix"
  | "ASPM & Engine Sub-Tabs"
  | "Scan & Track Changes"
  | "Layout, Themes & Exports";

interface QuickCommandItem {
  id: string;
  category: CommandCategory;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  badge?: string;
  action: () => void;
}

export function QuickCommandModal() {
  const {
    isQuickCommandOpen,
    setQuickCommandOpen,
    primaryStage,
    setPrimaryStage,
    setMapSubTab,
    setAspmSubSection,
    setExecutiveAspmTab,
    setEngineAccessTab,
    setAiDrawerOpen,
    batchApplyAllSafeFixes,
    explainCurrentGraphWithAi,
    validateFindingsAi,
    selectedFinding,
    synthesizeFindingPatchAi,
    triggerScan,
    projectPath,
    openTargetPicker,
    isDiffEditorOpen,
    setDiffEditorOpen,
    setTrackChangesPanelOpen,
    isTrackChangesMode,
    setTrackChangesMode,
    ideLayoutMode,
    setIdeLayoutMode,
    audienceMode,
    setAudienceMode,
    setSettingsModalOpen,
    setIntegrationModalOpen,
    exportAuditReport,
    findings,
    selectFinding,
    appTree,
    selectTreeFile,
    setShowPortalGate,
    setFilterSecretsOnly,
    setActiveSidebarTab,
  } = useAuditStore();

  const [query, setQuery] = useState("");

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setQuickCommandOpen(!isQuickCommandOpen);
      } else if (e.key === "Escape" && isQuickCommandOpen) {
        setQuickCommandOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isQuickCommandOpen, setQuickCommandOpen]);

  const activeOpenCount = useMemo(
    () =>
      findings.filter(
        (f) =>
          f.triage_status !== "NOT_EXPLOITABLE" &&
          f.triage_status !== "PROPOSED_NOT_EXPLOITABLE" &&
          f.triage_status !== "RESOLVED"
      ).length,
    [findings]
  );

  const commands: QuickCommandItem[] = useMemo(
    () => [
      // 1. 4-Stage Guided Workflow
      {
        id: "stage-1-scan-repos",
        category: "4-Stage Guided Workflow",
        title: "Stage 1: Scan & Repos (Target Picker, GitHub Clone & Projects)",
        subtitle:
          "Scan local folders, single files, public/private GitHub URLs, or ZIP uploads and manage repositories",
        icon: <FolderGit2 className="w-4 h-4 text-sky-700" />,
        badge: primaryStage === "SCAN_REPOS" ? "Active • Stage 1" : "Stage 1",
        action: () => setPrimaryStage("SCAN_REPOS"),
      },
      {
        id: "stage-2-triage-fix",
        category: "4-Stage Guided Workflow",
        title: "Stage 2: Triage & Fix (Code, BFL DiffEditor & CPG Paths)",
        subtitle:
          "Inspect vulnerabilities, preview surgical BFL patches, batch auto-fix issues, and step through CPG hops",
        icon: <Code2 className="w-4 h-4 text-emerald-700" />,
        badge: primaryStage === "TRIAGE_FIX" ? "Active • Stage 2" : "Stage 2",
        action: () => setPrimaryStage("TRIAGE_FIX"),
      },
      {
        id: "stage-3-map-360",
        category: "4-Stage Guided Workflow",
        title: "Stage 3: 360° Map & Threats — Architecture & Call Flows",
        subtitle:
          "Interactive 360° Application Spider Map, AST/CFG/DFG, Attack Surface & Inter-Procedural Call Graphs",
        icon: <Network className="w-4 h-4 text-sky-700" />,
        badge:
          primaryStage === "MAP_360_THREATS" ? "Active • Stage 3" : "Stage 3A",
        action: () => {
          setPrimaryStage("MAP_360_THREATS");
          setMapSubTab("SPIDER_360");
        },
      },
      {
        id: "stage-3-stride-threats",
        category: "4-Stage Guided Workflow",
        title: "Stage 3: 360° Map & Threats — Trust Boundaries, STRIDE & PBOM",
        subtitle:
          "STRIDE Verdict Matrix (OK vs Issue), Trust Boundary Zones, CI/CD PBOM & Cryptographic Secret Vault",
        icon: <ShieldAlert className="w-4 h-4 text-rose-700" />,
        badge: "Stage 3B",
        action: () => {
          setPrimaryStage("MAP_360_THREATS");
          setMapSubTab("THREAT_BOUNDARIES");
        },
      },
      {
        id: "stage-4-aspm-governance",
        category: "4-Stage Guided Workflow",
        title: "Stage 4: ASPM, Rules & Reports (Posture, SBOM, Rules & Exports)",
        subtitle:
          "Executive posture analytics, CycloneDX SBOM, 21-Rule Matrix, RACI/RBAC governance, and Export Center",
        icon: <BarChart3 className="w-4 h-4 text-amber-700" />,
        badge:
          primaryStage === "ASPM_GOVERNANCE" ? "Active • Stage 4" : "Stage 4",
        action: () => setPrimaryStage("ASPM_GOVERNANCE"),
      },

      // 2. Frontier AI Copilot & Batch Auto-Fix
      {
        id: "ai-batch-autofix",
        category: "Frontier AI & Batch Auto-Fix",
        title: `⚡ Fix All Safe Issues (${activeOpenCount} Open Candidates)`,
        subtitle:
          "Run atomic bottom-up BFL auto-remediation across open findings with unified .patch rollback & CPG re-scan",
        icon: <Zap className="w-4 h-4 text-emerald-700" />,
        badge: "1-Click Batch Fix",
        action: () => {
          setPrimaryStage("TRIAGE_FIX");
          void batchApplyAllSafeFixes();
        },
      },
      {
        id: "ai-settings-byok",
        category: "Frontier AI & Batch Auto-Fix",
        title: "Frontier AI Copilot — BYOK Vault & Provider Settings",
        subtitle:
          "Connect Gemini, OpenAI, Anthropic, or OpenAI-compatible endpoints with CPG micro-slicing token telemetry",
        icon: <Bot className="w-4 h-4 text-indigo-700" />,
        badge: "BYOK AI",
        action: () => setAiDrawerOpen(true, "SETTINGS"),
      },
      {
        id: "ai-validate-tpfp",
        category: "Frontier AI & Batch Auto-Fix",
        title: "Validate Findings (TP / FP) with Frontier AI",
        subtitle:
          "Evaluate CPG micro-slices to classify True Positives vs False Positives with confidence scores",
        icon: <CheckCircle2 className="w-4 h-4 text-indigo-700" />,
        badge: "AI Triage",
        action: () => {
          setAiDrawerOpen(true, "VALIDATE");
          if (findings.length > 0) {
            void validateFindingsAi(
              selectedFinding
                ? [selectedFinding.id]
                : findings.slice(0, 8).map((f) => f.id)
            );
          }
        },
      },
      {
        id: "ai-code-audit",
        category: "Frontier AI & Batch Auto-Fix",
        title: "Deep Code Selection Audit with Frontier AI",
        subtitle:
          "Audit a targeted line range with CPG taint context and receive secure code recommendations",
        icon: <Sparkles className="w-4 h-4 text-indigo-700" />,
        badge: "AI Audit",
        action: () => setAiDrawerOpen(true, "CODE_AUDIT"),
      },
      {
        id: "ai-patch-synthesis",
        category: "Frontier AI & Batch Auto-Fix",
        title: "Synthesize Context-Aware AI Patch for Selected Finding",
        subtitle:
          "Generate surgical remediation code and load directly into the Monaco Side-by-Side DiffEditor",
        icon: <Wand2 className="w-4 h-4 text-indigo-700" />,
        badge: "AI Patch",
        action: () => {
          setAiDrawerOpen(true, "PATCH");
          if (selectedFinding) {
            void synthesizeFindingPatchAi(selectedFinding.id);
          }
        },
      },
      {
        id: "ai-explain-graph",
        category: "Frontier AI & Batch Auto-Fix",
        title: "Explain Current CPG / 360° Architecture Graph with AI",
        subtitle:
          "Translate the active graph topology into a plain-English security walkthrough",
        icon: <Network className="w-4 h-4 text-indigo-700" />,
        badge: "Graph Story",
        action: () => {
          setAiDrawerOpen(true, "GRAPH");
          void explainCurrentGraphWithAi();
        },
      },

      // 3. ASPM & Engine Sub-Tabs
      {
        id: "sub-aspm-posture",
        category: "ASPM & Engine Sub-Tabs",
        title: "Compliance & Posture Analytics (OWASP / PCI-DSS / SOC2)",
        subtitle:
          "Executive posture score, SLA aging buckets, CWE heatmaps, and regulatory scorecards",
        icon: <BarChart3 className="w-4 h-4 text-sky-700" />,
        badge: "ASPM • Posture",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("POSTURE");
          setExecutiveAspmTab("ANALYTICS");
        },
      },
      {
        id: "sub-aspm-translator",
        category: "ASPM & Engine Sub-Tabs",
        title: "Plain-English Impact Translator",
        subtitle:
          "Business impact stories, non-coder analogies, and 3-step management action plans",
        icon: <GraduationCap className="w-4 h-4 text-emerald-700" />,
        badge: "SAST+ • Translator",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("SAST_PLUS");
          setExecutiveAspmTab("TRANSLATOR");
        },
      },
      {
        id: "sub-aspm-sbom",
        category: "ASPM & Engine Sub-Tabs",
        title: "CycloneDX SBOM & Supply-Chain Inspector",
        subtitle:
          "Inspect live package manifests (requirements.txt, package.json) and export .cdx.json",
        icon: <Layers className="w-4 h-4 text-sky-700" />,
        badge: "SAST+ • SBOM",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("SAST_PLUS");
          setExecutiveAspmTab("SBOM");
        },
      },
      {
        id: "sub-aspm-attack-surface",
        category: "ASPM & Engine Sub-Tabs",
        title: "API Attack Surface & Entrypoints",
        subtitle:
          "Inspect discovered HTTP routes, callable entrypoints, and adjacent vulnerabilities",
        icon: <Compass className="w-4 h-4 text-amber-700" />,
        badge: "SAST+ • Surface",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("SAST_PLUS");
          setExecutiveAspmTab("ATTACK_SURFACE");
        },
      },
      {
        id: "sub-aspm-roadmap",
        category: "ASPM & Engine Sub-Tabs",
        title: "Remediation Roadmap (Phased Sprint Plan)",
        subtitle:
          "Prioritized Phase 1 (24-72h), Phase 2 (Sprint), and Phase 3 (Hardening) fix plan",
        icon: <Sparkles className="w-4 h-4 text-emerald-700" />,
        badge: "SAST+ • Roadmap",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("SAST_PLUS");
          setExecutiveAspmTab("ROADMAP");
        },
      },
      {
        id: "sub-aspm-academy",
        category: "ASPM & Engine Sub-Tabs",
        title: "Security Academy & Non-Coder Glossary",
        subtitle:
          "Learn CPG, AST/CFG/DFG, BFL Chokepoints, CWE/CVE/CVSS, and SBOM fundamentals",
        icon: <BookOpen className="w-4 h-4 text-rose-700" />,
        badge: "SAST+ • Academy",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("SAST_PLUS");
          setExecutiveAspmTab("ACADEMY");
        },
      },
      {
        id: "sub-engine-rules",
        category: "ASPM & Engine Sub-Tabs",
        title: "Rule Profiles & 21-Rule Security Matrix",
        subtitle:
          "Toggle SAST, SCA, IaC, and Secret rules or switch between Optimized and Zero-Trust profiles",
        icon: <Sliders className="w-4 h-4 text-amber-700" />,
        badge: "Rules Engine",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("RULES_ENGINE");
          setEngineAccessTab("RULE_PROFILES");
        },
      },
      {
        id: "sub-engine-cypher",
        category: "ASPM & Engine Sub-Tabs",
        title: "Cypher & Sanitizer Studio",
        subtitle:
          "Inspect Neo4j Cypher taint queries, tune DFG hop depth, and register custom AST sanitizers",
        icon: <Code2 className="w-4 h-4 text-sky-700" />,
        badge: "Rules • Cypher",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("RULES_ENGINE");
          setEngineAccessTab("CYPHER_SANITIZERS");
        },
      },
      {
        id: "sub-aspm-raci",
        category: "ASPM & Engine Sub-Tabs",
        title: "RACI Matrix & Governance Accountability",
        subtitle:
          "Assign Responsible, Accountable, Consulted, and Informed owners with PMI/COBIT validation",
        icon: <Users className="w-4 h-4 text-amber-700" />,
        badge: "Governance • RACI",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("GOVERNANCE");
          setExecutiveAspmTab("RACI");
        },
      },
      {
        id: "sub-engine-accounts",
        category: "ASPM & Engine Sub-Tabs",
        title: "Multi-Tenant Accounts & RBAC",
        subtitle:
          "Manage isolated tenant accounts, operator roles, and granular RBAC permissions",
        icon: <Users className="w-4 h-4 text-emerald-700" />,
        badge: "Governance • RBAC",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("GOVERNANCE");
          setEngineAccessTab("ACCOUNTS_RBAC");
        },
      },
      {
        id: "sub-engine-connectors",
        category: "ASPM & Engine Sub-Tabs",
        title: "Jira & GitHub Sync (Issue Connectors)",
        subtitle:
          "Manage remediation tickets, bi-directional triage sync, and Jira/GitHub connectors",
        icon: <Ticket className="w-4 h-4 text-amber-700" />,
        badge: "Governance • Sync",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("GOVERNANCE");
          setEngineAccessTab("ISSUE_CONNECTORS");
        },
      },
      {
        id: "sub-cve-extractor",
        category: "ASPM & Engine Sub-Tabs",
        title: "Live Web CVE & Advisory Extractor (NVD / CISA KEV / GitHub)",
        subtitle:
          "Extract live CVE advisories from web feeds and correlate against your codebase",
        icon: <Shield className="w-4 h-4 text-sky-700" />,
        badge: "Threat Intel",
        action: () => {
          setPrimaryStage("TRIAGE_FIX");
          setActiveSidebarTab("SITE_EXTRACTOR");
        },
      },

      // 4. Scan & Track Changes
      {
        id: "act-toggle-bfl-diff",
        category: "Scan & Track Changes",
        title: "Toggle BFL Patch Diff Preview (d)",
        subtitle:
          "Switch Monaco between source inspection and side-by-side Best Fix Location (BFL) DiffEditor",
        icon: <GitPullRequest className="w-4 h-4 text-amber-700" />,
        badge: isDiffEditorOpen ? "Diff Active" : "Shortcut: d",
        action: () => {
          setPrimaryStage("TRIAGE_FIX");
          setDiffEditorOpen(!isDiffEditorOpen);
        },
      },
      {
        id: "act-scan-github-repo",
        category: "Scan & Track Changes",
        title: "Scan GitHub Repository (Public URL / Private Token)",
        subtitle:
          "Open the GitHub Repository Scanner modal for public zero-token or private PAT clones",
        icon: <FolderGit2 className="w-4 h-4 text-sky-700" />,
        badge: "GitHub Clone",
        action: () => openTargetPicker("URL"),
      },
      {
        id: "act-filter-secrets",
        category: "Scan & Track Changes",
        title: "Secret Vault & Hardcoded Key Filter",
        subtitle:
          "Filter Triage Flaw Explorer to show detected API keys, tokens, and credentials",
        icon: <KeyRound className="w-4 h-4 text-amber-700" />,
        badge: "Secrets",
        action: () => {
          setFilterSecretsOnly(true);
          setPrimaryStage("TRIAGE_FIX");
        },
      },
      {
        id: "scan-rescan",
        category: "Scan & Track Changes",
        title: "Re-Scan Active Application Now",
        subtitle: projectPath
          ? `Run fresh 7-pass CPG SAST + SCA + Secrets scan on ${projectPath}`
          : "Run fresh 7-pass CPG scan on the active target application",
        icon: <RefreshCw className="w-4 h-4 text-emerald-700" />,
        badge: "7-Pass Scan",
        action: () => {
          void triggerScan(projectPath || undefined);
        },
      },
      {
        id: "scan-track-changes-panel",
        category: "Scan & Track Changes",
        title: "Open Saved Scan Details & Track Changes Comparison",
        subtitle:
          "Compare current scan vs previous scan (Fixed, New, and Unchanged delta)",
        icon: <GitCompare className="w-4 h-4 text-sky-700" />,
        badge: "Delta Tracker",
        action: () => setTrackChangesPanelOpen(true),
      },
      {
        id: "scan-toggle-track-mode",
        category: "Scan & Track Changes",
        title: isTrackChangesMode
          ? "Disable Continuous Track Changes Badges"
          : "Enable Continuous Track Changes Badges",
        subtitle:
          "Toggle Fixed / New / Unchanged badges across all review views",
        icon: <GitCompare className="w-4 h-4 text-amber-700" />,
        badge: isTrackChangesMode ? "Currently ON" : "Currently OFF",
        action: () => setTrackChangesMode(!isTrackChangesMode),
      },
      {
        id: "scan-portal-gate",
        category: "Scan & Track Changes",
        title: "Open Launch Hub (Ἀλάστωρ Portal Gate)",
        subtitle:
          "Return to the Launch Hub with Instant GitHub Quick-Scan and Saved Scan overview",
        icon: <Shield className="w-4 h-4 text-rose-700" />,
        action: () => setShowPortalGate(true),
      },

      // 5. Layout, Themes & Exports
      {
        id: "layout-code-focus",
        category: "Layout, Themes & Exports",
        title: "Code & Fix Focus Layout (1)",
        subtitle: "Maximize the Monaco Code & BFL DiffEditor pane",
        icon: <Code2 className="w-4 h-4 text-emerald-700" />,
        badge: ideLayoutMode === "CODE_FOCUS" ? "Active" : "Key: 1",
        action: () => {
          setPrimaryStage("TRIAGE_FIX");
          setIdeLayoutMode("CODE_FOCUS");
        },
      },
      {
        id: "layout-split-both",
        category: "Layout, Themes & Exports",
        title: "Split Code + Graph Layout (2)",
        subtitle: "Show Monaco Editor and Interactive CPG Graph side-by-side",
        icon: <Columns className="w-4 h-4 text-amber-700" />,
        badge: ideLayoutMode === "SPLIT_BOTH" ? "Active" : "Key: 2",
        action: () => {
          setPrimaryStage("TRIAGE_FIX");
          setIdeLayoutMode("SPLIT_BOTH");
        },
      },
      {
        id: "layout-graph-focus",
        category: "Layout, Themes & Exports",
        title: "Visual Graph Focus Layout (3)",
        subtitle:
          "Maximize the interactive ReactFlow CPG & 360° Architecture Canvas",
        icon: <Network className="w-4 h-4 text-sky-700" />,
        badge: ideLayoutMode === "GRAPH_FOCUS" ? "Active" : "Key: 3",
        action: () => {
          setPrimaryStage("TRIAGE_FIX");
          setIdeLayoutMode("GRAPH_FOCUS");
        },
      },
      {
        id: "layout-audience-toggle",
        category: "Layout, Themes & Exports",
        title:
          audienceMode === "NON_CODER_MANAGEMENT"
            ? "Switch to Technical Engineer Lens"
            : "Switch to Executive / Non-Coder Lens",
        subtitle:
          "Tailor terminology and explanations for security engineers or executive leaders",
        icon:
          audienceMode === "NON_CODER_MANAGEMENT" ? (
            <Cpu className="w-4 h-4 text-sky-700" />
          ) : (
            <GraduationCap className="w-4 h-4 text-amber-700" />
          ),
        badge:
          audienceMode === "NON_CODER_MANAGEMENT" ? "Executive" : "Engineer",
        action: () =>
          setAudienceMode(
            audienceMode === "NON_CODER_MANAGEMENT"
              ? "TECHNICAL_ENGINEER"
              : "NON_CODER_MANAGEMENT"
          ),
      },
      {
        id: "settings-presets",
        category: "Layout, Themes & Exports",
        title: "Open Settings, Cypher Queries & Daylight Palettes",
        subtitle:
          "Configure Scan Presets, Neo4j Cypher rules, Custom Sanitizers, and the 3 Daylight Themes",
        icon: <Settings className="w-4 h-4 text-sky-700" />,
        action: () => setSettingsModalOpen(true, "PRESETS"),
      },
      {
        id: "settings-integrations",
        category: "Layout, Themes & Exports",
        title: "Open Jira & GitHub Issues Connector Modal",
        subtitle:
          "Configure live REST connectors, test connection, and manage issue tickets",
        icon: <Ticket className="w-4 h-4 text-amber-700" />,
        action: () => setIntegrationModalOpen(true),
      },
      {
        id: "export-center-hub",
        category: "Layout, Themes & Exports",
        title: "Open Unified Export Center (SARIF, HTML Dossier, CSV, SBOM, .patch)",
        subtitle:
          "One-click downloads for SARIF v2.1.0, Executive HTML, Markdown, CSV, CycloneDX SBOM, and Git Patches",
        icon: <FileSpreadsheet className="w-4 h-4 text-emerald-700" />,
        badge: "8 Formats",
        action: () => {
          setPrimaryStage("ASPM_GOVERNANCE");
          setAspmSubSection("EXPORTS");
        },
      },
      {
        id: "export-md",
        category: "Layout, Themes & Exports",
        title: "Export Executive & Technical Audit Report (.md)",
        subtitle:
          "Download full Markdown security audit report for the active application",
        icon: <Download className="w-4 h-4 text-emerald-700" />,
        badge: "Markdown",
        action: () => {
          void exportAuditReport("markdown");
        },
      },
      {
        id: "export-json",
        category: "Layout, Themes & Exports",
        title: "Export Machine-Readable Audit Data (.json)",
        subtitle:
          "Download structured JSON payload with all findings and metrics",
        icon: <Download className="w-4 h-4 text-sky-700" />,
        badge: "JSON",
        action: () => {
          void exportAuditReport("json");
        },
      },
      {
        id: "export-sarif",
        category: "Layout, Themes & Exports",
        title: "Export OASIS SARIF v2.1.0 Report (.sarif.json)",
        subtitle:
          "Download GitHub Advanced Security / IDE compatible SARIF v2.1.0 report",
        icon: <Download className="w-4 h-4 text-amber-700" />,
        badge: "SARIF",
        action: () => {
          void exportAuditReport("sarif");
        },
      },
    ],
    [
      primaryStage,
      activeOpenCount,
      findings,
      selectedFinding,
      projectPath,
      isDiffEditorOpen,
      isTrackChangesMode,
      ideLayoutMode,
      audienceMode,
      setPrimaryStage,
      setMapSubTab,
      setAspmSubSection,
      setExecutiveAspmTab,
      setEngineAccessTab,
      setAiDrawerOpen,
      batchApplyAllSafeFixes,
      explainCurrentGraphWithAi,
      validateFindingsAi,
      synthesizeFindingPatchAi,
      openTargetPicker,
      setDiffEditorOpen,
      setFilterSecretsOnly,
      setActiveSidebarTab,
      triggerScan,
      setTrackChangesPanelOpen,
      setTrackChangesMode,
      setShowPortalGate,
      setIdeLayoutMode,
      setAudienceMode,
      setSettingsModalOpen,
      setIntegrationModalOpen,
      exportAuditReport,
    ]
  );

  const q = query.trim().toLowerCase();

  const filteredCommands = useMemo(() => {
    if (!q) return commands;
    return commands.filter(
      (c) =>
        c.title.toLowerCase().includes(q) ||
        c.subtitle.toLowerCase().includes(q) ||
        c.category.toLowerCase().includes(q) ||
        (c.badge && c.badge.toLowerCase().includes(q))
    );
  }, [commands, q]);

  const matchingFindings = useMemo(() => {
    if (!q) return findings.slice(0, 5);
    return findings
      .filter((f) => {
        const sinkNode = f.path_nodes?.[f.path_nodes.length - 1];
        const fp = sinkNode?.filepath || "";
        return (
          f.title.toLowerCase().includes(q) ||
          fp.toLowerCase().includes(q) ||
          (f.cwe_id || "").toLowerCase().includes(q) ||
          f.severity.toLowerCase().includes(q)
        );
      })
      .slice(0, 6);
  }, [findings, q]);

  const matchingFiles = useMemo(() => {
    if (!q || !appTree?.flat_files) return [];
    return appTree.flat_files
      .filter(
        (f) =>
          f.filepath.toLowerCase().includes(q) ||
          f.purpose.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q)
      )
      .slice(0, 5);
  }, [appTree, q]);

  if (!isQuickCommandOpen) return null;

  return (
    <div
      className="fixed inset-0 z-[180] bg-slate-900/50 backdrop-blur-sm flex items-start justify-center pt-14 p-4"
      onClick={() => setQuickCommandOpen(false)}
    >
      <div
        className="w-full max-w-2xl bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[var(--ink-primary)] rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[82vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Header */}
        <div className="px-4 py-3 border-b border-[var(--border-hairline)] flex items-center gap-3 bg-[var(--surface-void)]">
          <Search className="w-4 h-4 text-sky-700 shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Jump to Stage 1–4, Frontier AI Copilot, Fix All Safe Issues, SBOM, RACI, finding, or file..."
            className="w-full bg-transparent text-xs font-sans text-[var(--ink-primary)] placeholder:text-[var(--ink-muted)] focus:outline-none"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              className="text-[11px] font-mono text-[var(--ink-secondary)] hover:text-[var(--ink-primary)] px-2 py-0.5 rounded bg-[var(--surface-panel)] border border-[var(--border-hairline)]"
            >
              Clear
            </button>
          )}
          <button
            type="button"
            onClick={() => setQuickCommandOpen(false)}
            className="p-1 rounded-lg text-[var(--ink-muted)] hover:text-[var(--ink-primary)] hover:bg-[var(--surface-elevated)]"
            title="Close (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results Body */}
        <div className="flex-1 overflow-y-auto p-3 space-y-4">
          {/* Matching Findings */}
          {matchingFindings.length > 0 && (
            <div>
              <div className="px-2 pb-1.5 text-[10px] font-mono font-bold uppercase tracking-wider text-rose-800 flex items-center justify-between">
                <span>Active Application Findings ({findings.length} total)</span>
                <span className="font-normal text-[var(--ink-muted)]">
                  Click to inspect in Stage 2: Triage &amp; Fix
                </span>
              </div>
              <div className="space-y-1">
                {matchingFindings.map((f) => {
                  const sinkNode = f.path_nodes?.[f.path_nodes.length - 1];
                  return (
                    <button
                      key={f.id}
                      type="button"
                      onClick={() => {
                        setPrimaryStage("TRIAGE_FIX");
                        selectFinding(f);
                        setQuickCommandOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-xl hover:bg-[var(--surface-elevated)] border border-transparent hover:border-[var(--border-hairline)] flex items-center justify-between gap-3 transition-colors"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <AlertTriangle className="w-4 h-4 text-rose-700 shrink-0" />
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-[var(--ink-primary)] truncate">
                            {f.title}
                          </div>
                          <div className="text-[11px] text-[var(--ink-muted)] font-mono truncate">
                            {sinkNode?.filepath || f.rule_id}:
                            {sinkNode?.start_line || 1} • {f.cwe_id || "CWE"}
                          </div>
                        </div>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-800 border border-rose-300 shrink-0">
                        {f.severity}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Matching Files */}
          {matchingFiles.length > 0 && (
            <div>
              <div className="px-2 pb-1.5 text-[10px] font-mono font-bold uppercase tracking-wider text-sky-800">
                Matching Source Files
              </div>
              <div className="space-y-1">
                {matchingFiles.map((file) => (
                  <button
                    key={file.filepath}
                    type="button"
                    onClick={() => {
                      setPrimaryStage("TRIAGE_FIX");
                      selectTreeFile(file);
                      setQuickCommandOpen(false);
                    }}
                    className="w-full text-left px-3 py-2 rounded-xl hover:bg-[var(--surface-elevated)] border border-transparent hover:border-[var(--border-hairline)] flex items-center justify-between gap-3 transition-colors"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <FileCode2 className="w-4 h-4 text-sky-700 shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-mono font-bold text-[var(--ink-primary)] truncate">
                          {file.filepath}
                        </div>
                        <div className="text-[11px] text-[var(--ink-muted)] truncate">
                          {file.purpose}
                        </div>
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[var(--surface-void)] text-[var(--ink-secondary)] border border-[var(--border-hairline)] shrink-0">
                      {file.language}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Grouped Platform Commands */}
          {(
            [
              "4-Stage Guided Workflow",
              "Frontier AI & Batch Auto-Fix",
              "ASPM & Engine Sub-Tabs",
              "Scan & Track Changes",
              "Layout, Themes & Exports",
            ] as const
          ).map((category) => {
            const catItems = filteredCommands.filter(
              (c) => c.category === category
            );
            if (catItems.length === 0) return null;
            return (
              <div key={category}>
                <div className="px-2 pb-1.5 text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--ink-muted)]">
                  {category}
                </div>
                <div className="space-y-1">
                  {catItems.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        item.action();
                        setQuickCommandOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-xl hover:bg-[var(--surface-elevated)] border border-transparent hover:border-[var(--border-hairline)] flex items-center justify-between gap-3 transition-colors group"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="p-2 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)] shrink-0">
                          {item.icon}
                        </div>
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-[var(--ink-primary)] group-hover:text-sky-800 transition-colors truncate">
                            {item.title}
                          </div>
                          <div className="text-[11px] text-[var(--ink-muted)] truncate">
                            {item.subtitle}
                          </div>
                        </div>
                      </div>
                      {item.badge && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[var(--surface-void)] text-slate-800 border border-[var(--border-hairline)] shrink-0">
                          {item.badge}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            );
          })}

          {filteredCommands.length === 0 &&
            matchingFindings.length === 0 &&
            matchingFiles.length === 0 && (
              <div className="py-10 text-center text-[var(--ink-muted)] text-xs font-mono">
                No matching features, findings, or files found for &ldquo;{query}
                &rdquo;.
              </div>
            )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 bg-[var(--surface-void)] border-t border-[var(--border-hairline)] flex items-center justify-between text-[10px] font-mono text-[var(--ink-muted)]">
          <span>
            Press{" "}
            <kbd className="px-1.5 py-0.5 rounded bg-[var(--surface-panel)] text-[var(--ink-primary)] border border-[var(--border-hairline)] font-semibold">
              Ctrl+K
            </kbd>{" "}
            anytime •{" "}
            <kbd className="px-1.5 py-0.5 rounded bg-[var(--surface-panel)] text-[var(--ink-primary)] border border-[var(--border-hairline)] font-semibold">
              d
            </kbd>{" "}
            BFL Diff
          </span>
          <span className="font-semibold text-[var(--ink-secondary)]">
            ALASTOR v4 Command Omnibar
          </span>
        </div>
      </div>
    </div>
  );
}

export default QuickCommandModal;
