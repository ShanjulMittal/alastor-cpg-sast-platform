import { create } from "zustand";
import {
  Finding,
  CPGNode,
  MetricsResponse,
  GraphViewMode,
  WorkspaceViewMode,
  ExecutiveAspmTab,
  EngineAccessTab,
  RemediatePreviewResponse,
  RemediateApplyResponse,
  RemediateUndoResponse,
  AudiencePersonaMode,
  AppTreeSummary,
  FilePurposeInfo,
  ScanProgress,
  ExtractedAdvisory,
  SiteExtractResponse,
  ProjectConfig,
  DeepDiveAnalyticsResponse,
  PlatformSettingsResponse,
  IntegrationHubStateResponse,
  BugTrackerConnectorConfig,
  IssueTicket,
  TestConnectionResponse,
  TriageStatus,
  ScanEngineType,
  AppThemeId,
  BackdropIntensity,
  RaciValue,
  RaciGovernanceResponse,
  SastPlusSuiteResponse,
  TrackChangesSummary,
  UserAccountsStateResponse,
  GitHubRepoVerifyResponse,
  GitRepoScanOptions,
  ScanResponse,
  PrimaryWorkflowStage,
  MapSubTab,
  AspmSubSection,
  AiDrawerTab,
  BatchRemediateResponse,
  AiPublicConfig,
  AiConfigUpdatePayload,
  AiConnectionTestResponse,
  AiFindingVerdict,
  AiValidateFindingsResponse,
  AiCodeAuditResponse,
  AiPatchSynthesisResponse,
  AiGraphExplainPayload,
  AiGraphExplainResponse,
} from "@/types/cpg";
import {
  BACKEND_URL,
  fetchAiConfig,
  updateAiConfig,
  testAiConnection,
  validateFindingsWithAi,
  auditCodeSelectionWithAi,
  synthesizePatchWithAi,
  explainGraphWithAi,
  batchApplyRemediations,
} from "@/lib/api";

export const UI_PREFS_STORAGE_KEY = "alastor_ui_prefs_v4";

const VALID_APP_THEMES: AppThemeId[] = [
  "olympian-light",
  "athena-parchment",
  "hyperborean-light",
];

function normalizeLightTheme(theme?: string | null): AppThemeId {
  if (theme && (VALID_APP_THEMES as string[]).includes(theme)) {
    return theme as AppThemeId;
  }
  return "olympian-light";
}

function applyDocumentTheme(theme: AppThemeId): void {
  if (typeof document === "undefined") return;
  const safeTheme = normalizeLightTheme(theme);
  const htmlEl = document.documentElement;
  htmlEl.setAttribute("data-theme", safeTheme);
  htmlEl.setAttribute("data-theme-mode", "light");
  htmlEl.classList.remove("dark");
  htmlEl.classList.add("light");
}

function persistUiPrefs(getState: () => AuditState): void {
  if (typeof window === "undefined") return;
  try {
    const s = getState();
    const payload = {
      hasEnteredWorkspace: !s.showPortalGate,
      showPortalGate: s.showPortalGate,
      appTheme: normalizeLightTheme(s.appTheme),
      backdropIntensity: s.backdropIntensity,
      primaryStage: s.primaryStage,
      mapSubTab: s.mapSubTab,
      aspmSubSection: s.aspmSubSection,
      workspaceViewMode: s.workspaceViewMode,
      executiveAspmTab: s.executiveAspmTab,
      engineAccessTab: s.engineAccessTab,
      ideLayoutMode: s.ideLayoutMode,
      explorerWidth: s.explorerWidth,
      codeGraphRatio: s.codeGraphRatio,
    };
    localStorage.setItem(UI_PREFS_STORAGE_KEY, JSON.stringify(payload));
  } catch {}
}

interface AuditState {
  projectPath: string;
  findings: Finding[];
  selectedFinding: Finding | null;
  activeFilepath: string | null;
  activeStartLine: number | null;
  activeEndLine: number | null;
  selectedGraphNodeId: string | null;
  graphViewMode: GraphViewMode;
  primaryStage: PrimaryWorkflowStage;
  mapSubTab: MapSubTab;
  aspmSubSection: AspmSubSection;
  workspaceViewMode: WorkspaceViewMode;
  executiveAspmTab: ExecutiveAspmTab;
  engineAccessTab: EngineAccessTab;
  explorerWidth: number;
  codeGraphRatio: number;
  isDiffEditorOpen: boolean;
  activePathStepIndex: number;
  remediationPreview: RemediatePreviewResponse | null;
  remediationError: string | null;
  isApplyingPatch: boolean;
  isBatchFixing: boolean;
  lastBatchFixResult: BatchRemediateResponse | null;
  lastAppliedPatch: {
    patchId: string;
    findingId: string;
    filepath: string;
    verifiedSevered: boolean;
  } | null;

  // Frontier AI BYOK Copilot Drawer & Micro-Slice State
  isAiDrawerOpen: boolean;
  aiDrawerActiveTab: AiDrawerTab;
  aiConfig: AiPublicConfig | null;
  aiConnectionStatus: AiConnectionTestResponse | null;
  aiVerdictsByFinding: Record<string, AiFindingVerdict>;
  aiLastAudit: AiCodeAuditResponse | null;
  aiLastSynthesizedPatch: AiPatchSynthesisResponse | null;
  aiLastGraphExplanation: AiGraphExplainResponse | null;
  aiErrorBanner: string | null;
  aiIsBusy: boolean;
  audienceMode: AudiencePersonaMode;
  isSettingsBarVisible: boolean;
  metrics: MetricsResponse | null;
  isScanning: boolean;
  scanStatusMessage: string | null;
  scanProgress: ScanProgress | null;
  reactFlowInstance: any | null;
  isGraphFullscreen: boolean;

  // Theme & Mythological Backdrop state
  appTheme: AppThemeId;
  backdropIntensity: BackdropIntensity;
  showPortalGate: boolean;
  activeOperator: { name: string; role: string; email: string };

  // Application Architecture Tree & Purpose state
  appTree: AppTreeSummary | null;
  selectedTreeFile: FilePurposeInfo | null;
  activeSidebarTab: "FLAWS" | "APP_TREE" | "SITE_EXTRACTOR";

  // Unified Engine & Grouping Filter state
  activeEngineFilter: "ALL" | ScanEngineType;
  primaryGrouping: "NONE" | "LANGUAGE" | "SEVERITY" | "ENGINE";
  filterSecretsOnly: boolean;

  // User Accounts & Multi-Tenant Separation state
  userAccountsState: UserAccountsStateResponse | null;

  // External Site Vulnerability Intelligence state
  extractedAdvisories: ExtractedAdvisory[];
  isExtractingIntel: boolean;
  intelStatusMessage: string | null;

  // Enterprise Modals & Views State
  isSettingsModalOpen: boolean;
  settingsActiveTab: "PRESETS" | "GLOBAL_PROJECT" | "QUERY_VIEWER" | "CUSTOMIZATION";
  isIntegrationModalOpen: boolean;
  projects: ProjectConfig[];
  deepDiveAnalytics: DeepDiveAnalyticsResponse | null;
  platformSettings: PlatformSettingsResponse | null;
  integrationState: IntegrationHubStateResponse | null;
  raciGovernance: RaciGovernanceResponse | null;
  sastPlusSuite: SastPlusSuiteResponse | null;
  sastPlusActiveTab: "TRANSLATOR" | "SBOM" | "ATTACK_SURFACE" | "ROADMAP" | "THREAT_MODEL" | "ACADEMY";

  // Continuous Track Changes & Saved Scan Details State
  trackChanges: TrackChangesSummary | null;
  isTrackChangesMode: boolean;
  isTrackChangesPanelOpen: boolean;

  // UI Simplicity, Layout & Command Palette State
  uiDensityMode: "SIMPLE_CLEAN" | "PRO_DETAILED";
  ideLayoutMode: "SPLIT_BOTH" | "CODE_FOCUS" | "GRAPH_FOCUS";
  isSidebarCollapsed: boolean;
  isQuickCommandOpen: boolean;
  isMenuBarExpanded: boolean;

  // Target Picker & GitHub Repository Scanner Modal State
  isTargetPickerOpen: boolean;
  targetPickerTab: "FOLDER" | "FILE" | "URL" | "UPLOAD";
  gitScanPrefillUrl: string;
  gitScanForcePrivateAuth: boolean;
  gitScanErrorBanner: string | null;
  openTargetPicker: (
    tab?: "FOLDER" | "FILE" | "URL" | "UPLOAD",
    prefillUrl?: string,
    forcePrivate?: boolean,
    errorBanner?: string | null
  ) => void;
  closeTargetPicker: () => void;
  verifyGitHubRepo: (payload: {
    repo_url: string;
    branch?: string;
    auth_token?: string;
    auth_username?: string;
  }) => Promise<GitHubRepoVerifyResponse | null>;

  setAppTheme: (theme: AppThemeId) => void;
  setBackdropIntensity: (intensity: BackdropIntensity) => void;
  setPrimaryStage: (stage: PrimaryWorkflowStage) => void;
  setMapSubTab: (subTab: MapSubTab) => void;
  setAspmSubSection: (section: AspmSubSection) => void;
  setAiDrawerOpen: (open: boolean, tab?: AiDrawerTab) => void;
  fetchAiConfigState: () => Promise<AiPublicConfig | null>;
  saveAiConfigState: (payload: AiConfigUpdatePayload) => Promise<AiPublicConfig | null>;
  runAiConnectionTest: () => Promise<AiConnectionTestResponse | null>;
  validateFindingsAi: (findingIds?: string[]) => Promise<AiValidateFindingsResponse | null>;
  auditCodeSelectionAi: (
    filepath: string,
    startLine: number,
    endLine: number,
    focusQuestion?: string
  ) => Promise<AiCodeAuditResponse | null>;
  synthesizeFindingPatchAi: (findingId: string) => Promise<AiPatchSynthesisResponse | null>;
  explainGraphAi: (payload: AiGraphExplainPayload) => Promise<AiGraphExplainResponse | null>;
  batchApplyAllSafeFixes: (findingIds?: string[]) => Promise<BatchRemediateResponse | null>;
  setAudienceMode: (mode: AudiencePersonaMode) => void;
  setSettingsBarVisible: (visible: boolean) => void;
  setUiDensityMode: (mode: "SIMPLE_CLEAN" | "PRO_DETAILED") => void;
  setIdeLayoutMode: (mode: "SPLIT_BOTH" | "CODE_FOCUS" | "GRAPH_FOCUS") => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setQuickCommandOpen: (open: boolean) => void;
  setMenuBarExpanded: (expanded: boolean) => void;
  setSastPlusActiveTab: (tab: "TRANSLATOR" | "SBOM" | "ATTACK_SURFACE" | "ROADMAP" | "THREAT_MODEL" | "ACADEMY") => void;
  setExecutiveAspmTab: (tab: ExecutiveAspmTab) => void;
  setEngineAccessTab: (tab: EngineAccessTab) => void;
  setExplorerWidth: (px: number) => void;
  setCodeGraphRatio: (ratio: number) => void;
  setDiffEditorOpen: (open: boolean) => void;
  stepFindingPath: (delta: 1 | -1) => void;
  fetchRemediationPreview: (finding: Finding) => Promise<void>;
  applyRemediationPatch: (patchedContent: string) => Promise<RemediateApplyResponse | null>;
  undoLastRemediationPatch: () => Promise<boolean>;
  hydrateUiPreferences: () => void;
  setShowPortalGate: (
    show: boolean,
    operator?: { name: string; role: string; email: string }
  ) => void;
  setProjectPath: (path: string) => void;
  setGraphViewMode: (mode: GraphViewMode) => void;
  setWorkspaceViewMode: (mode: WorkspaceViewMode) => void;
  setActiveSidebarTab: (tab: "FLAWS" | "APP_TREE" | "SITE_EXTRACTOR") => void;
  setActiveEngineFilter: (eng: "ALL" | ScanEngineType) => void;
  setPrimaryGrouping: (grp: "NONE" | "LANGUAGE" | "SEVERITY" | "ENGINE") => void;
  setFilterSecretsOnly: (val: boolean) => void;
  setSettingsModalOpen: (open: boolean, tab?: "PRESETS" | "GLOBAL_PROJECT" | "QUERY_VIEWER" | "CUSTOMIZATION") => void;
  setIntegrationModalOpen: (open: boolean) => void;
  setReactFlowInstance: (instance: any) => void;
  setGraphFullscreen: (val: boolean) => void;
  selectFinding: (finding: Finding) => void;
  jumpToBestFixLocation: (finding: Finding) => void;
  openCodeLocationInIde: (filepath?: string, line?: number, findingId?: string) => void;
  selectTreeFile: (file: FilePurposeInfo) => void;
  selectGraphNode: (node: CPGNode) => void;
  selectCodeLine: (filepath: string, line: number) => Promise<void>;
  fetchFindings: () => Promise<void>;
  fetchMetrics: () => Promise<void>;
  fetchAppTree: () => Promise<void>;
  fetchAdvisories: (autoInit?: boolean) => Promise<void>;
  fetchProjects: () => Promise<void>;
  createProject: (payload: {
    name: string;
    description: string;
    scm_provider: "GITHUB" | "GITLAB" | "BITBUCKET" | "LOCAL";
    repo_url: string;
    branch: string;
    target_path: string;
    preset_id: string;
    auto_scan_on_push: boolean;
    auto_scan_on_pr: boolean;
    is_private_repo?: boolean;
    auth_token?: string;
    auth_username?: string;
    save_token?: boolean;
    run_scan_immediately?: boolean;
  }) => Promise<{ ok: boolean; project: ProjectConfig | null; error?: string; authRequired?: boolean }>;
  updateProjectAutomation: (projectId: string, payload: Record<string, any>) => Promise<void>;
  activateProject: (projectId: string, runScan?: boolean) => Promise<void>;
  deleteProject: (projectId: string) => Promise<boolean>;
  triggerProjectWebhook: (projectId: string, eventType: "push" | "pull_request", branch?: string) => Promise<void>;
  fetchDeepDiveAnalytics: () => Promise<void>;
  updateFindingTriage: (
    findingId: string,
    status: TriageStatus,
    reason?: string,
    comment?: string
  ) => Promise<void>;
  fetchPlatformSettings: () => Promise<void>;
  updatePlatformSettings: (payload: Record<string, any>) => Promise<void>;
  upsertQueryRule: (payload: Record<string, any>) => Promise<void>;
  toggleQueryRule: (ruleId: string) => Promise<void>;
  createTestProfile: (payload: {
    name: string;
    badge: string;
    description: string;
    enabled_engines: string[];
    enabled_rule_ids: string[];
  }) => Promise<void>;
  batchUpdateRules: (payload: {
    enabled_rule_ids: string[];
    disabled_rule_ids?: string[];
    preset_id?: string;
  }) => Promise<void>;
  fetchUserAccounts: () => Promise<void>;
  createAccount: (payload: {
    name: string;
    organization_unit: string;
    environment_tier?: string;
    isolation_mode?: string;
    compliance_mandate?: string;
    assigned_project_ids?: string[];
  }) => Promise<void>;
  createUserProfile: (payload: {
    name: string;
    email: string;
    role: string;
    title: string;
    department: string;
    account_id: string;
    default_test_profile_id?: string;
  }) => Promise<void>;
  switchUserOrAccount: (payload: {
    account_id?: string;
    user_id?: string;
    assign_project_id?: string;
    target_account_id?: string;
    toggle_permission_user_id?: string;
    toggle_permission_field?: string;
  }) => Promise<void>;
  addCustomSanitizer: (payload: {
    function_name: string;
    language: string;
    target_cwe: string;
    description: string;
  }) => Promise<void>;
  toggleCustomSanitizer: (sanId: string) => Promise<void>;
  fetchIntegrations: () => Promise<void>;
  updateIntegrationConfig: (cfg: Partial<BugTrackerConnectorConfig>) => Promise<void>;
  testIntegrationConnection: (payload: {
    provider: "JIRA" | "GITHUB_ISSUES";
    jira_url?: string;
    jira_project_key?: string;
    jira_email?: string;
    jira_api_token?: string;
    github_repo?: string;
    github_token?: string;
  }) => Promise<TestConnectionResponse | null>;
  createTicketForFinding: (
    findingId: string,
    provider?: "JIRA" | "GITHUB_ISSUES",
    options?: {
      assignee?: string;
      priority?: "HIGHEST" | "HIGH" | "MEDIUM" | "LOW";
      labels?: string[];
      custom_notes?: string;
    }
  ) => Promise<IssueTicket | null>;
  updateTicket: (
    ticketId: string,
    payload: {
      status?: "OPEN" | "IN_PROGRESS" | "RESOLVED";
      assignee?: string;
      priority?: "HIGHEST" | "HIGH" | "MEDIUM" | "LOW";
      comment?: string;
      comment_author?: string;
    }
  ) => Promise<IssueTicket | null>;
  deleteTicket: (ticketId: string) => Promise<boolean>;
  autoSyncTickets: () => Promise<void>;
  fetchRaciGovernance: () => Promise<void>;
  updateRaciCell: (activityId: string, roleId: string, value: RaciValue) => Promise<void>;
  updateFindingRaciOwner: (payload: {
    finding_id: string;
    assigned_person?: string;
    target_sprint?: string;
    responsible_role?: string;
    accountable_role?: string;
  }) => Promise<void>;
  resetRaciGovernance: () => Promise<void>;
  fetchSastPlusSuite: () => Promise<void>;
  setTrackChangesMode: (enabled: boolean) => void;
  setTrackChangesPanelOpen: (open: boolean) => void;
  fetchTrackChanges: (projectPath?: string) => Promise<void>;
  extractAndScanFromSites: (params: {
    sources: string[];
    customUrls: string[];
    searchQuery?: string;
  }) => Promise<SiteExtractResponse | null>;
  exportAuditReport: (format: "markdown" | "json" | "sarif") => Promise<void>;
  triggerScan: (
    targetPath?: string,
    options?: GitRepoScanOptions
  ) => Promise<{ ok: boolean; authRequired?: boolean; error?: string; response?: ScanResponse }>;
}

export const useAuditStore = create<AuditState>((set, get) => ({
  projectPath: "",
  findings: [],
  selectedFinding: null,
  activeFilepath: null,
  activeStartLine: null,
  activeEndLine: null,
  selectedGraphNodeId: null,
  graphViewMode: "FINDING_PATH",
  primaryStage: "TRIAGE_FIX",
  mapSubTab: "SPIDER_360",
  aspmSubSection: "POSTURE",
  workspaceViewMode: "REMEDIATION_IDE",
  executiveAspmTab: "TRANSLATOR",
  engineAccessTab: "RULE_PROFILES",
  explorerWidth: 310,
  codeGraphRatio: 0.52,
  isDiffEditorOpen: false,
  activePathStepIndex: 0,
  remediationPreview: null,
  remediationError: null,
  isApplyingPatch: false,
  isBatchFixing: false,
  lastBatchFixResult: null,
  lastAppliedPatch: null,
  isAiDrawerOpen: false,
  aiDrawerActiveTab: "VALIDATE",
  aiConfig: null,
  aiConnectionStatus: null,
  aiVerdictsByFinding: {},
  aiLastAudit: null,
  aiLastSynthesizedPatch: null,
  aiLastGraphExplanation: null,
  aiErrorBanner: null,
  aiIsBusy: false,
  audienceMode: "NON_CODER_MANAGEMENT",
  isSettingsBarVisible: false,
  metrics: null,
  isScanning: false,
  scanStatusMessage: null,
  scanProgress: null,
  reactFlowInstance: null,
  isGraphFullscreen: false,

  appTheme: "olympian-light",
  backdropIntensity: "SUBTLE",
  showPortalGate: false,
  activeOperator: {
    name: "Local Operator",
    role: "Standalone Mode",
    email: "",
  },

  appTree: null,
  selectedTreeFile: null,
  activeSidebarTab: "FLAWS",

  activeEngineFilter: "ALL",
  primaryGrouping: "NONE",
  filterSecretsOnly: false,
  userAccountsState: null,

  extractedAdvisories: [],
  isExtractingIntel: false,
  intelStatusMessage: null,

  isSettingsModalOpen: false,
  settingsActiveTab: "PRESETS",
  isIntegrationModalOpen: false,
  projects: [],
  deepDiveAnalytics: null,
  platformSettings: null,
  integrationState: null,
  raciGovernance: null,
  sastPlusSuite: null,
  sastPlusActiveTab: "TRANSLATOR",

  trackChanges: null,
  isTrackChangesMode: true,
  isTrackChangesPanelOpen: false,

  uiDensityMode: "SIMPLE_CLEAN",
  ideLayoutMode: "SPLIT_BOTH",
  isSidebarCollapsed: false,
  isQuickCommandOpen: false,
  isMenuBarExpanded: true,

  isTargetPickerOpen: false,
  targetPickerTab: "FOLDER",
  gitScanPrefillUrl: "",
  gitScanForcePrivateAuth: false,
  gitScanErrorBanner: null,

  openTargetPicker: (
    tab = "FOLDER",
    prefillUrl = "",
    forcePrivate = false,
    errorBanner = null
  ) => {
    set({
      isTargetPickerOpen: true,
      targetPickerTab: tab,
      ...(prefillUrl ? { gitScanPrefillUrl: prefillUrl } : {}),
      gitScanForcePrivateAuth: forcePrivate,
      gitScanErrorBanner: errorBanner,
    });
  },

  closeTargetPicker: () => {
    set({
      isTargetPickerOpen: false,
      gitScanErrorBanner: null,
    });
  },

  verifyGitHubRepo: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/github/verify-repo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        return (await res.json()) as GitHubRepoVerifyResponse;
      }
    } catch (err) {
      console.error("Failed to verify GitHub repo:", err);
    }
    return null;
  },

  setAppTheme: (theme: AppThemeId) => {
    const safeTheme = normalizeLightTheme(theme);
    set({ appTheme: safeTheme });
    applyDocumentTheme(safeTheme);
    if (typeof window !== "undefined") {
      try {
        localStorage.setItem("alastor_app_theme_v4", safeTheme);
      } catch {}
    }
    persistUiPrefs(get);
  },

  setPrimaryStage: (stage: PrimaryWorkflowStage) => {
    if (stage === "SCAN_REPOS") {
      set({
        primaryStage: "SCAN_REPOS",
        workspaceViewMode: "PROJECTS_HUB",
      });
      persistUiPrefs(get);
      get().fetchProjects();
      get().fetchTrackChanges();
      return;
    }

    if (stage === "TRIAGE_FIX") {
      const currentGraphMode = get().graphViewMode;
      const currentLayout = get().ideLayoutMode;
      set({
        primaryStage: "TRIAGE_FIX",
        workspaceViewMode: "REMEDIATION_IDE",
        ...(currentGraphMode === "APP_TREE"
          ? { graphViewMode: "FINDING_PATH" as GraphViewMode }
          : {}),
        ...(currentLayout === "GRAPH_FOCUS" && currentGraphMode === "APP_TREE"
          ? { ideLayoutMode: "SPLIT_BOTH" as const }
          : {}),
      });
      persistUiPrefs(get);
      get().fetchTrackChanges();
      return;
    }

    if (stage === "MAP_360_THREATS") {
      const sub = get().mapSubTab;
      if (sub === "THREAT_BOUNDARIES") {
        set({
          primaryStage: "MAP_360_THREATS",
          workspaceViewMode: "THREAT_MODELING",
        });
        persistUiPrefs(get);
        get().fetchSastPlusSuite();
        get().fetchTrackChanges();
      } else {
        set({
          primaryStage: "MAP_360_THREATS",
          workspaceViewMode: "REMEDIATION_IDE",
          graphViewMode: "APP_TREE",
          ideLayoutMode: "GRAPH_FOCUS",
        });
        persistUiPrefs(get);
        get().fetchAppTree();
        get().fetchSastPlusSuite();
        get().fetchTrackChanges();
      }
      return;
    }

    // stage === "ASPM_GOVERNANCE"
    const sec = get().aspmSubSection;
    if (sec === "RULES_ENGINE") {
      set({
        primaryStage: "ASPM_GOVERNANCE",
        workspaceViewMode: "ENGINE_ACCESS",
        engineAccessTab: "RULE_PROFILES",
      });
      persistUiPrefs(get);
      get().fetchPlatformSettings();
      get().fetchUserAccounts();
      get().fetchIntegrations();
      get().fetchProjects();
      return;
    }

    const mappedExecTab: ExecutiveAspmTab =
      sec === "GOVERNANCE"
        ? "RACI"
        : sec === "SAST_PLUS"
        ? "SBOM"
        : "ANALYTICS";
    set({
      primaryStage: "ASPM_GOVERNANCE",
      workspaceViewMode: "EXECUTIVE_ASPM",
      executiveAspmTab: mappedExecTab,
    });
    persistUiPrefs(get);
    get().fetchSastPlusSuite();
    get().fetchDeepDiveAnalytics();
    get().fetchRaciGovernance();
    get().fetchTrackChanges();
  },

  setMapSubTab: (subTab: MapSubTab) => {
    if (subTab === "THREAT_BOUNDARIES") {
      set({
        mapSubTab: "THREAT_BOUNDARIES",
        primaryStage: "MAP_360_THREATS",
        workspaceViewMode: "THREAT_MODELING",
      });
      persistUiPrefs(get);
      get().fetchSastPlusSuite();
    } else {
      set({
        mapSubTab: "SPIDER_360",
        primaryStage: "MAP_360_THREATS",
        workspaceViewMode: "REMEDIATION_IDE",
        graphViewMode: "APP_TREE",
        ideLayoutMode: "GRAPH_FOCUS",
      });
      persistUiPrefs(get);
      get().fetchAppTree();
      get().fetchSastPlusSuite();
    }
  },

  setAspmSubSection: (section: AspmSubSection) => {
    if (section === "RULES_ENGINE") {
      set({
        aspmSubSection: section,
        primaryStage: "ASPM_GOVERNANCE",
        workspaceViewMode: "ENGINE_ACCESS",
        engineAccessTab: "RULE_PROFILES",
      });
      persistUiPrefs(get);
      get().fetchPlatformSettings();
      get().fetchUserAccounts();
      get().fetchIntegrations();
      return;
    }
    if (section === "GOVERNANCE") {
      set({
        aspmSubSection: section,
        primaryStage: "ASPM_GOVERNANCE",
        workspaceViewMode: "EXECUTIVE_ASPM",
        executiveAspmTab: "RACI",
      });
      persistUiPrefs(get);
      get().fetchRaciGovernance();
      get().fetchUserAccounts();
      get().fetchIntegrations();
      return;
    }
    if (section === "SAST_PLUS") {
      set({
        aspmSubSection: section,
        primaryStage: "ASPM_GOVERNANCE",
        workspaceViewMode: "EXECUTIVE_ASPM",
        executiveAspmTab: "SBOM",
        sastPlusActiveTab: "SBOM",
      });
      persistUiPrefs(get);
      get().fetchSastPlusSuite();
      return;
    }
    set({
      aspmSubSection: section,
      primaryStage: "ASPM_GOVERNANCE",
      workspaceViewMode: "EXECUTIVE_ASPM",
      executiveAspmTab: "ANALYTICS",
    });
    persistUiPrefs(get);
    get().fetchDeepDiveAnalytics();
    get().fetchSastPlusSuite();
    get().fetchRaciGovernance();
  },

  setAiDrawerOpen: (open: boolean, tab?: AiDrawerTab) => {
    set((state) => ({
      isAiDrawerOpen: open,
      ...(tab ? { aiDrawerActiveTab: tab } : { aiDrawerActiveTab: state.aiDrawerActiveTab }),
    }));
    if (open && !get().aiConfig) {
      void get().fetchAiConfigState();
    }
  },

  fetchAiConfigState: async () => {
    try {
      const cfg = await fetchAiConfig();
      set({ aiConfig: cfg });
      return cfg;
    } catch (err: any) {
      console.error("Failed to fetch AI config:", err);
      return null;
    }
  },

  saveAiConfigState: async (payload: AiConfigUpdatePayload) => {
    set({ aiIsBusy: true, aiErrorBanner: null });
    try {
      const cfg = await updateAiConfig(payload);
      set({
        aiConfig: cfg,
        aiIsBusy: false,
        aiConnectionStatus: null,
        aiErrorBanner: null,
      });
      return cfg;
    } catch (err: any) {
      const msg = err?.detail || err?.message || "Failed to update AI configuration.";
      set({ aiIsBusy: false, aiErrorBanner: msg });
      return null;
    }
  },

  runAiConnectionTest: async () => {
    set({ aiIsBusy: true, aiErrorBanner: null });
    try {
      const res = await testAiConnection();
      set({
        aiConnectionStatus: res,
        aiIsBusy: false,
        aiErrorBanner: res.ok ? null : res.message,
      });
      void get().fetchAiConfigState();
      return res;
    } catch (err: any) {
      const msg = err?.detail || err?.message || "Failed to test AI connection.";
      set({ aiIsBusy: false, aiErrorBanner: msg });
      return null;
    }
  },

  validateFindingsAi: async (findingIds?: string[]) => {
    set({ aiIsBusy: true, aiErrorBanner: null });
    try {
      const res = await validateFindingsWithAi({
        finding_ids: findingIds ?? [],
      });
      const nextMap = { ...get().aiVerdictsByFinding };
      for (const v of res.verdicts || []) {
        if (v && v.finding_id) {
          nextMap[v.finding_id] = v;
        }
      }
      set({
        aiVerdictsByFinding: nextMap,
        aiIsBusy: false,
        aiErrorBanner: res.ok ? null : res.user_message || "AI finding validation did not complete.",
      });
      void get().fetchAiConfigState();
      return res;
    } catch (err: any) {
      const msg = err?.detail || err?.message || "Failed to validate findings with AI.";
      set({ aiIsBusy: false, aiErrorBanner: msg });
      return null;
    }
  },

  auditCodeSelectionAi: async (filepath, startLine, endLine, focusQuestion) => {
    set({ aiIsBusy: true, aiErrorBanner: null });
    try {
      const res = await auditCodeSelectionWithAi({
        filepath,
        start_line: startLine,
        end_line: endLine,
        ...(focusQuestion ? { focus_question: focusQuestion } : {}),
      });
      set({
        aiLastAudit: res,
        aiIsBusy: false,
        aiErrorBanner: res.ok ? null : res.user_message || "AI code selection audit failed.",
      });
      void get().fetchAiConfigState();
      return res;
    } catch (err: any) {
      const msg = err?.detail || err?.message || "Failed to audit code selection with AI.";
      set({ aiIsBusy: false, aiErrorBanner: msg });
      return null;
    }
  },

  synthesizeFindingPatchAi: async (findingId: string) => {
    set({ aiIsBusy: true, aiErrorBanner: null });
    try {
      const res = await synthesizePatchWithAi({ finding_id: findingId });
      set({
        aiLastSynthesizedPatch: res,
        aiIsBusy: false,
        aiErrorBanner: res.ok ? null : res.user_message || "AI patch synthesis failed.",
      });
      void get().fetchAiConfigState();
      return res;
    } catch (err: any) {
      const msg = err?.detail || err?.message || "Failed to synthesize patch with AI.";
      set({ aiIsBusy: false, aiErrorBanner: msg });
      return null;
    }
  },

  explainGraphAi: async (payload: AiGraphExplainPayload) => {
    set({ aiIsBusy: true, aiErrorBanner: null });
    try {
      const res = await explainGraphWithAi(payload);
      set({
        aiLastGraphExplanation: res,
        aiIsBusy: false,
        aiErrorBanner: res.ok ? null : res.user_message || "AI graph walkthrough failed.",
      });
      void get().fetchAiConfigState();
      return res;
    } catch (err: any) {
      const msg = err?.detail || err?.message || "Failed to explain graph with AI.";
      set({ aiIsBusy: false, aiErrorBanner: msg });
      return null;
    }
  },

  setBackdropIntensity: (intensity: BackdropIntensity) => {
    set({ backdropIntensity: intensity });
    if (typeof window !== "undefined") {
      try {
        localStorage.setItem("alastor_backdrop_intensity", intensity);
      } catch {}
    }
    persistUiPrefs(get);
  },

  setAudienceMode: (mode: AudiencePersonaMode) => {
    set({ audienceMode: mode });
  },

  setSettingsBarVisible: (visible: boolean) => {
    set({ isSettingsBarVisible: visible });
  },

  setUiDensityMode: (mode: "SIMPLE_CLEAN" | "PRO_DETAILED") => {
    set({
      uiDensityMode: mode,
      isMenuBarExpanded: mode === "PRO_DETAILED",
      isSettingsBarVisible: mode === "PRO_DETAILED",
    });
  },

  setIdeLayoutMode: (mode: "SPLIT_BOTH" | "CODE_FOCUS" | "GRAPH_FOCUS") => {
    set({ ideLayoutMode: mode });
    persistUiPrefs(get);
  },

  setSidebarCollapsed: (collapsed: boolean) => {
    set({ isSidebarCollapsed: collapsed });
  },

  setQuickCommandOpen: (open: boolean) => {
    set({ isQuickCommandOpen: open });
  },

  setMenuBarExpanded: (expanded: boolean) => {
    set({ isMenuBarExpanded: expanded });
  },

  setTrackChangesMode: (enabled: boolean) => {
    set({ isTrackChangesMode: enabled });
  },

  setTrackChangesPanelOpen: (open: boolean) => {
    set({ isTrackChangesPanelOpen: open });
    if (open) {
      get().fetchTrackChanges();
    }
  },

  setSastPlusActiveTab: (tab) => {
    const mappedExecTab: ExecutiveAspmTab =
      tab === "THREAT_MODEL" ? "ATTACK_SURFACE" : tab;
    set({
      sastPlusActiveTab: tab,
      primaryStage: "ASPM_GOVERNANCE",
      aspmSubSection: "SAST_PLUS",
      workspaceViewMode: "EXECUTIVE_ASPM",
      executiveAspmTab: mappedExecTab,
    });
    persistUiPrefs(get);
    get().fetchSastPlusSuite();
  },

  setExecutiveAspmTab: (tab: ExecutiveAspmTab) => {
    const mappedSubSection: AspmSubSection =
      tab === "ANALYTICS"
        ? "POSTURE"
        : tab === "RACI"
        ? "GOVERNANCE"
        : "SAST_PLUS";
    set((state) => ({
      executiveAspmTab: tab,
      primaryStage: "ASPM_GOVERNANCE",
      aspmSubSection: mappedSubSection,
      workspaceViewMode: "EXECUTIVE_ASPM",
      ...(tab === "TRANSLATOR" ||
      tab === "SBOM" ||
      tab === "ATTACK_SURFACE" ||
      tab === "ROADMAP" ||
      tab === "ACADEMY"
        ? { sastPlusActiveTab: tab }
        : { sastPlusActiveTab: state.sastPlusActiveTab }),
    }));
    persistUiPrefs(get);
    if (tab === "ANALYTICS") {
      get().fetchDeepDiveAnalytics();
    } else if (tab === "RACI") {
      get().fetchRaciGovernance();
    } else {
      get().fetchSastPlusSuite();
    }
  },

  setEngineAccessTab: (tab: EngineAccessTab) => {
    const mappedSubSection: AspmSubSection =
      tab === "RULE_PROFILES" || tab === "CYPHER_SANITIZERS"
        ? "RULES_ENGINE"
        : "GOVERNANCE";
    set({
      engineAccessTab: tab,
      primaryStage: "ASPM_GOVERNANCE",
      aspmSubSection: mappedSubSection,
      workspaceViewMode: "ENGINE_ACCESS",
    });
    persistUiPrefs(get);
    if (tab === "RULE_PROFILES" || tab === "CYPHER_SANITIZERS") {
      get().fetchPlatformSettings();
    } else if (tab === "ACCOUNTS_RBAC") {
      get().fetchUserAccounts();
      get().fetchProjects();
    } else if (tab === "ISSUE_CONNECTORS") {
      get().fetchIntegrations();
    }
  },

  setExplorerWidth: (px: number) => {
    const clamped = Math.max(240, Math.min(480, Math.round(px)));
    set({ explorerWidth: clamped });
    persistUiPrefs(get);
  },

  setCodeGraphRatio: (ratio: number) => {
    const clamped = Math.max(0.25, Math.min(0.75, Number(ratio.toFixed(3))));
    set({ codeGraphRatio: clamped });
    persistUiPrefs(get);
  },

  setDiffEditorOpen: (open: boolean) => {
    set({ isDiffEditorOpen: open });
    if (open) {
      const finding = get().selectedFinding;
      if (finding) {
        get().fetchRemediationPreview(finding);
      }
    }
  },

  stepFindingPath: (delta: 1 | -1) => {
    const finding = get().selectedFinding;
    if (!finding || !finding.path_nodes || finding.path_nodes.length === 0) {
      return;
    }
    const len = finding.path_nodes.length;
    const nextIdx = Math.max(0, Math.min(len - 1, get().activePathStepIndex + delta));
    const node = finding.path_nodes[nextIdx];
    set({
      activePathStepIndex: nextIdx,
      selectedGraphNodeId: node.id,
      activeFilepath: node.filepath,
      activeStartLine: node.start_line,
      activeEndLine: node.end_line,
    });
    const rf = get().reactFlowInstance;
    if (rf && rf.getNode && node.id) {
      const flowNode = rf.getNode(node.id);
      if (flowNode) {
        rf.setCenter(flowNode.position.x + 110, flowNode.position.y + 45, {
          zoom: 1.4,
          duration: 320,
        });
      }
    }
  },

  fetchRemediationPreview: async (finding: Finding) => {
    const bfl = finding.best_fix_location;
    const sinkNode =
      finding.path_nodes && finding.path_nodes.length > 0
        ? finding.path_nodes[finding.path_nodes.length - 1]
        : null;
    const filepath = bfl?.filepath || sinkNode?.filepath || get().activeFilepath || "";
    const targetLine = bfl?.line || sinkNode?.start_line || get().activeStartLine || 1;
    const recommendedFix =
      bfl?.after_code_block || bfl?.recommended_fix || finding.remediation || null;

    if (!filepath) return;

    try {
      const res = await fetch(`${BACKEND_URL}/api/remediate/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_id: finding.id,
          filepath,
          target_line: targetLine,
          rule_id: finding.rule_id || "",
          recommended_fix: recommendedFix,
        }),
      });
      if (res.ok) {
        const data: RemediatePreviewResponse = await res.json();
        set({ remediationPreview: data, remediationError: null });
      }
    } catch (err) {
      console.error("Failed to fetch remediation preview:", err);
    }
  },

  applyRemediationPatch: async (patchedContent: string) => {
    const finding = get().selectedFinding;
    const preview = get().remediationPreview;
    if (!finding || !preview) return null;

    set({ isApplyingPatch: true, remediationError: null });
    try {
      const res = await fetch(`${BACKEND_URL}/api/remediate/apply`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_id: finding.id,
          filepath: preview.filepath,
          rule_id: finding.rule_id || "",
          expected_sha256: preview.expected_sha256,
          patched_content: patchedContent,
        }),
      });
      if (res.ok) {
        const data: RemediateApplyResponse = await res.json();
        set({
          lastAppliedPatch: {
            patchId: data.patch_id,
            findingId: finding.id,
            filepath: data.filepath,
            verifiedSevered: data.verified_severed,
          },
          remediationError: null,
          isApplyingPatch: false,
          isDiffEditorOpen: false,
        });
        await Promise.all([
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchProjects(),
          get().fetchTrackChanges(),
        ]);
        void Promise.all([
          get().fetchDeepDiveAnalytics(),
          get().fetchRaciGovernance(),
          get().fetchSastPlusSuite(),
        ]);
        return data;
      }
      if (res.status === 409) {
        let detail = "Target file was modified externally (SHA256 mismatch). Refresh Diff to reload.";
        try {
          const errBody = await res.json();
          if (errBody?.detail) detail = String(errBody.detail);
        } catch {}
        set({ isApplyingPatch: false, remediationError: detail });
        return null;
      }
      set({ isApplyingPatch: false, remediationError: `Failed to apply patch (HTTP ${res.status})` });
      return null;
    } catch (err) {
      console.error("Failed to apply remediation patch:", err);
      set({ isApplyingPatch: false, remediationError: "Network error while applying remediation patch." });
      return null;
    }
  },

  undoLastRemediationPatch: async () => {
    const lastPatch = get().lastAppliedPatch;
    if (!lastPatch) return false;

    set({ isApplyingPatch: true, remediationError: null });
    try {
      const res = await fetch(`${BACKEND_URL}/api/remediate/undo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          patch_id: lastPatch.patchId,
        }),
      });
      if (res.ok) {
        set({
          lastAppliedPatch: null,
          remediationError: null,
          isApplyingPatch: false,
        });
        await Promise.all([
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchProjects(),
          get().fetchTrackChanges(),
        ]);
        void Promise.all([
          get().fetchDeepDiveAnalytics(),
          get().fetchRaciGovernance(),
          get().fetchSastPlusSuite(),
        ]);
        const currentSelected = get().selectedFinding;
        if (currentSelected) {
          await get().fetchRemediationPreview(currentSelected);
        }
        return true;
      }
      set({ isApplyingPatch: false });
      return false;
    } catch (err) {
      console.error("Failed to undo remediation patch:", err);
      set({ isApplyingPatch: false });
      return false;
    }
  },

  batchApplyAllSafeFixes: async (findingIds?: string[]) => {
    set({ isBatchFixing: true, remediationError: null });
    try {
      const res = await batchApplyRemediations({
        finding_ids: findingIds ?? [],
      });
      const latestPatchId =
        res.applied_patch_ids && res.applied_patch_ids.length > 0
          ? res.applied_patch_ids[res.applied_patch_ids.length - 1]
          : null;
      const latestFilepath =
        res.patched_files && res.patched_files.length > 0
          ? res.patched_files[res.patched_files.length - 1]
          : null;
      const latestFindingId =
        res.applied_finding_ids && res.applied_finding_ids.length > 0
          ? res.applied_finding_ids[res.applied_finding_ids.length - 1]
          : null;

      set((state) => ({
        isBatchFixing: false,
        lastBatchFixResult: res,
        isDiffEditorOpen: false,
        remediationPreview: null,
        remediationError: null,
        lastAppliedPatch:
          res.applied_count > 0 && latestPatchId
            ? {
                patchId: latestPatchId,
                findingId: latestFindingId || state.selectedFinding?.id || "batch",
                filepath: latestFilepath || state.activeFilepath || "batch",
                verifiedSevered: res.verified_severed_count > 0,
              }
            : state.lastAppliedPatch,
      }));

      await Promise.all([
        get().fetchFindings(),
        get().fetchMetrics(),
        get().fetchAppTree(),
        get().fetchProjects(),
        get().fetchTrackChanges(),
      ]);
      void Promise.all([
        get().fetchDeepDiveAnalytics(),
        get().fetchRaciGovernance(),
        get().fetchSastPlusSuite(),
      ]);
      return res;
    } catch (err: any) {
      const msg = err?.detail || err?.message || "Failed to batch-apply safe remediations.";
      set({ isBatchFixing: false, remediationError: msg });
      return null;
    }
  },

  hydrateUiPreferences: () => {
    if (typeof window === "undefined") return;
    try {
      const raw = localStorage.getItem(UI_PREFS_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        const updates: Partial<AuditState> = {};

        if (typeof parsed.showPortalGate === "boolean") {
          updates.showPortalGate = parsed.showPortalGate;
        } else {
          updates.showPortalGate = false;
        }

        const safeTheme = normalizeLightTheme(parsed.appTheme);
        updates.appTheme = safeTheme;
        applyDocumentTheme(safeTheme);

        if (
          parsed.backdropIntensity &&
          ["VIVID", "SUBTLE", "MINIMAL"].includes(parsed.backdropIntensity)
        ) {
          updates.backdropIntensity = parsed.backdropIntensity;
        }

        if (
          parsed.ideLayoutMode &&
          ["SPLIT_BOTH", "CODE_FOCUS", "GRAPH_FOCUS"].includes(parsed.ideLayoutMode)
        ) {
          updates.ideLayoutMode = parsed.ideLayoutMode;
        }

        if (typeof parsed.explorerWidth === "number" && !Number.isNaN(parsed.explorerWidth)) {
          updates.explorerWidth = Math.max(240, Math.min(480, Math.round(parsed.explorerWidth)));
        }

        if (typeof parsed.codeGraphRatio === "number" && !Number.isNaN(parsed.codeGraphRatio)) {
          updates.codeGraphRatio = Math.max(
            0.25,
            Math.min(0.75, Number(parsed.codeGraphRatio.toFixed(3)))
          );
        }

        if (
          parsed.mapSubTab &&
          ["SPIDER_360", "THREAT_BOUNDARIES"].includes(parsed.mapSubTab)
        ) {
          updates.mapSubTab = parsed.mapSubTab;
        }

        if (
          parsed.aspmSubSection &&
          ["POSTURE", "SAST_PLUS", "RULES_ENGINE", "GOVERNANCE", "EXPORTS"].includes(
            parsed.aspmSubSection
          )
        ) {
          updates.aspmSubSection = parsed.aspmSubSection;
        }

        if (
          parsed.executiveAspmTab &&
          [
            "TRANSLATOR",
            "SBOM",
            "ATTACK_SURFACE",
            "ROADMAP",
            "ACADEMY",
            "ANALYTICS",
            "RACI",
          ].includes(parsed.executiveAspmTab)
        ) {
          updates.executiveAspmTab = parsed.executiveAspmTab;
        }

        if (
          parsed.engineAccessTab &&
          [
            "RULE_PROFILES",
            "CYPHER_SANITIZERS",
            "ACCOUNTS_RBAC",
            "ISSUE_CONNECTORS",
          ].includes(parsed.engineAccessTab)
        ) {
          updates.engineAccessTab = parsed.engineAccessTab;
        }

        set(updates);

        if (
          parsed.primaryStage &&
          ["SCAN_REPOS", "TRIAGE_FIX", "MAP_360_THREATS", "ASPM_GOVERNANCE"].includes(
            parsed.primaryStage
          )
        ) {
          get().setPrimaryStage(parsed.primaryStage);
        } else if (
          parsed.workspaceViewMode &&
          [
            "REMEDIATION_IDE",
            "AUDIT_STUDIO",
            "THREAT_MODELING",
            "EXECUTIVE_ASPM",
            "PROJECTS_HUB",
            "ENGINE_ACCESS",
            "DEEP_DIVE",
            "RACI_GOVERNANCE",
            "SAST_PLUS_SUITE",
            "RULE_ENGINE_PROFILES",
            "USER_PROFILES",
          ].includes(parsed.workspaceViewMode)
        ) {
          get().setWorkspaceViewMode(parsed.workspaceViewMode);
        }
        return;
      }

      // Migrate from any legacy v3 storage keys — force light-only theme & direct workspace entry
      let legacyRawTheme =
        localStorage.getItem("alastor_app_theme_v4") ||
        localStorage.getItem("alastor_app_theme_v3");
      try {
        const legacyPrefsRaw = localStorage.getItem("alastor_ui_prefs_v3");
        if (!legacyRawTheme && legacyPrefsRaw) {
          const legacyParsed = JSON.parse(legacyPrefsRaw);
          if (legacyParsed?.appTheme) {
            legacyRawTheme = String(legacyParsed.appTheme);
          }
        }
      } catch {}

      const migratedTheme = normalizeLightTheme(legacyRawTheme);
      set({
        appTheme: migratedTheme,
        showPortalGate: false,
      });
      applyDocumentTheme(migratedTheme);

      const legacyBackdrop = localStorage.getItem(
        "alastor_backdrop_intensity"
      ) as BackdropIntensity | null;
      if (legacyBackdrop && ["VIVID", "SUBTLE", "MINIMAL"].includes(legacyBackdrop)) {
        set({ backdropIntensity: legacyBackdrop });
      }
      persistUiPrefs(get);
    } catch {}
  },

  setShowPortalGate: (show, operator) => {
    set((state) => ({
      showPortalGate: show,
      ...(operator ? { activeOperator: operator } : {}),
    }));
    persistUiPrefs(get);
  },

  setProjectPath: (path: string) => set({ projectPath: path }),

  setGraphViewMode: (mode: GraphViewMode) => set({ graphViewMode: mode }),

  setWorkspaceViewMode: (mode: WorkspaceViewMode) => {
    if (mode === "DEEP_DIVE") {
      set({
        primaryStage: "ASPM_GOVERNANCE",
        aspmSubSection: "POSTURE",
        workspaceViewMode: "EXECUTIVE_ASPM",
        executiveAspmTab: "ANALYTICS",
      });
      persistUiPrefs(get);
      get().fetchTrackChanges();
      get().fetchDeepDiveAnalytics();
      get().fetchSastPlusSuite();
      return;
    }
    if (mode === "RACI_GOVERNANCE") {
      set({
        primaryStage: "ASPM_GOVERNANCE",
        aspmSubSection: "GOVERNANCE",
        workspaceViewMode: "EXECUTIVE_ASPM",
        executiveAspmTab: "RACI",
      });
      persistUiPrefs(get);
      get().fetchTrackChanges();
      get().fetchRaciGovernance();
      get().fetchSastPlusSuite();
      return;
    }
    if (mode === "SAST_PLUS_SUITE") {
      const currentSastTab = get().sastPlusActiveTab;
      const mappedExecTab: ExecutiveAspmTab =
        currentSastTab === "THREAT_MODEL" ? "ATTACK_SURFACE" : currentSastTab;
      set({
        primaryStage: "ASPM_GOVERNANCE",
        aspmSubSection: "SAST_PLUS",
        workspaceViewMode: "EXECUTIVE_ASPM",
        executiveAspmTab: mappedExecTab,
      });
      persistUiPrefs(get);
      get().fetchTrackChanges();
      get().fetchSastPlusSuite();
      get().fetchDeepDiveAnalytics();
      get().fetchRaciGovernance();
      return;
    }
    if (mode === "RULE_ENGINE_PROFILES") {
      set({
        primaryStage: "ASPM_GOVERNANCE",
        aspmSubSection: "RULES_ENGINE",
        workspaceViewMode: "ENGINE_ACCESS",
        engineAccessTab: "RULE_PROFILES",
      });
      persistUiPrefs(get);
      get().fetchTrackChanges();
      get().fetchPlatformSettings();
      return;
    }
    if (mode === "USER_PROFILES") {
      set({
        primaryStage: "ASPM_GOVERNANCE",
        aspmSubSection: "GOVERNANCE",
        workspaceViewMode: "ENGINE_ACCESS",
        engineAccessTab: "ACCOUNTS_RBAC",
      });
      persistUiPrefs(get);
      get().fetchTrackChanges();
      get().fetchUserAccounts();
      get().fetchProjects();
      return;
    }

    const normalizedMode: WorkspaceViewMode =
      mode === "AUDIT_STUDIO" ? "REMEDIATION_IDE" : mode;
    const syncedStage: PrimaryWorkflowStage =
      normalizedMode === "PROJECTS_HUB"
        ? "SCAN_REPOS"
        : normalizedMode === "THREAT_MODELING"
        ? "MAP_360_THREATS"
        : normalizedMode === "EXECUTIVE_ASPM" || normalizedMode === "ENGINE_ACCESS"
        ? "ASPM_GOVERNANCE"
        : "TRIAGE_FIX";

    set((state) => ({
      workspaceViewMode: normalizedMode,
      primaryStage: syncedStage,
      ...(normalizedMode === "THREAT_MODELING"
        ? { mapSubTab: "THREAT_BOUNDARIES" as MapSubTab }
        : {}),
      ...(normalizedMode === "REMEDIATION_IDE" && state.graphViewMode === "APP_TREE"
        ? { graphViewMode: "FINDING_PATH" as GraphViewMode, ideLayoutMode: "SPLIT_BOTH" as const }
        : {}),
    }));
    persistUiPrefs(get);
    get().fetchTrackChanges();
    if (normalizedMode === "PROJECTS_HUB") {
      get().fetchProjects();
    } else if (normalizedMode === "EXECUTIVE_ASPM") {
      get().fetchSastPlusSuite();
      get().fetchDeepDiveAnalytics();
      get().fetchRaciGovernance();
    } else if (normalizedMode === "THREAT_MODELING") {
      get().fetchSastPlusSuite();
    } else if (normalizedMode === "ENGINE_ACCESS") {
      get().fetchPlatformSettings();
      get().fetchUserAccounts();
      get().fetchIntegrations();
      get().fetchProjects();
    }
  },


  setActiveSidebarTab: (tab: "FLAWS" | "APP_TREE" | "SITE_EXTRACTOR") => set({ activeSidebarTab: tab }),

  setActiveEngineFilter: (eng: "ALL" | ScanEngineType) => set({ activeEngineFilter: eng }),

  setPrimaryGrouping: (grp: "NONE" | "LANGUAGE" | "SEVERITY" | "ENGINE") => set({ primaryGrouping: grp }),

  setFilterSecretsOnly: (val: boolean) => set({ filterSecretsOnly: val }),

  setSettingsModalOpen: (open: boolean, tab?: "PRESETS" | "GLOBAL_PROJECT" | "QUERY_VIEWER" | "CUSTOMIZATION") => {
    set({
      isSettingsModalOpen: open,
      ...(tab ? { settingsActiveTab: tab } : {}),
    });
    if (open) {
      get().fetchPlatformSettings();
    }
  },

  setIntegrationModalOpen: (open: boolean) => {
    set({ isIntegrationModalOpen: open });
    if (open) {
      get().fetchIntegrations();
    }
  },

  setReactFlowInstance: (instance: any) => set({ reactFlowInstance: instance }),

  setGraphFullscreen: (val: boolean) => set({ isGraphFullscreen: val }),

  selectFinding: (finding: Finding) => {
    const firstNode = finding.path_nodes && finding.path_nodes.length > 0 ? finding.path_nodes[0] : null;
    set((state) => ({
      selectedFinding: finding,
      activePathStepIndex: 0,
      remediationPreview: null,
      selectedGraphNodeId: firstNode ? firstNode.id : null,
      activeFilepath: firstNode ? firstNode.filepath : null,
      activeStartLine: firstNode ? firstNode.start_line : null,
      activeEndLine: firstNode ? firstNode.end_line : null,
      primaryStage: "TRIAGE_FIX",
      workspaceViewMode: "REMEDIATION_IDE",
      ...(state.graphViewMode === "APP_TREE"
        ? { graphViewMode: "FINDING_PATH" as GraphViewMode, ideLayoutMode: "SPLIT_BOTH" as const }
        : {}),
    }));
    if (get().isDiffEditorOpen) {
      get().fetchRemediationPreview(finding);
    }
  },

  jumpToBestFixLocation: (finding: Finding) => {
    const bfl = finding.best_fix_location;
    if (!bfl) {
      get().selectFinding(finding);
      set({
        primaryStage: "TRIAGE_FIX",
        workspaceViewMode: "REMEDIATION_IDE",
        ideLayoutMode: "SPLIT_BOTH",
        isSidebarCollapsed: false,
      });
      return;
    }
    set((state) => ({
      selectedFinding: finding,
      selectedGraphNodeId: bfl.node_id || null,
      activeFilepath: bfl.filepath,
      activeStartLine: bfl.line,
      activeEndLine: bfl.line,
      primaryStage: "TRIAGE_FIX",
      workspaceViewMode: "REMEDIATION_IDE",
      ideLayoutMode: "SPLIT_BOTH",
      isSidebarCollapsed: false,
      ...(state.graphViewMode === "APP_TREE"
        ? { graphViewMode: "FINDING_PATH" as GraphViewMode }
        : {}),
    }));
    const rf = get().reactFlowInstance;
    if (rf && rf.getNode && bfl.node_id) {
      const flowNode = rf.getNode(bfl.node_id);
      if (flowNode) {
        rf.setCenter(flowNode.position.x + 110, flowNode.position.y + 45, {
          zoom: 1.45,
          duration: 450,
        });
      }
    }
  },

  openCodeLocationInIde: (filepath?: string, line?: number, findingId?: string) => {
    const allFindings = get().findings || [];
    const treeFiles = get().appTree?.flat_files || [];

    // 1. Try direct finding match by ID
    if (findingId) {
      const byId = allFindings.find((f) => f.id === findingId);
      if (byId) {
        get().jumpToBestFixLocation(byId);
        return;
      }
    }

    // 2. Parse clean filepath and line from string like "ciso/next.config.ts:1 (GET /)" or "app.py:42"
    let rawPath = (filepath || "").trim();
    rawPath = rawPath.replace(/\s*\(.*\)$/, "").trim();
    let parsedLine = line && line > 0 ? line : 1;

    const colonMatch = rawPath.match(/^(.+?):L?(\d+)$/i);
    if (colonMatch) {
      rawPath = colonMatch[1].trim();
      if (!line) {
        parsedLine = parseInt(colonMatch[2], 10) || 1;
      }
    }

    // 3. Try matching a finding in the active findings list by filepath
    if (rawPath) {
      const normRaw = rawPath.replace(/\\/g, "/").toLowerCase();
      const byPathFinding = allFindings.find((f) => {
        const bflFp = (f.best_fix_location?.filepath || "").replace(/\\/g, "/").toLowerCase();
        const nodeFp = (f.path_nodes?.[f.path_nodes.length - 1]?.filepath || "").replace(/\\/g, "/").toLowerCase();
        return (
          bflFp === normRaw ||
          nodeFp === normRaw ||
          (bflFp && normRaw.endsWith(bflFp)) ||
          (nodeFp && normRaw.endsWith(nodeFp))
        );
      });
      if (byPathFinding) {
        set((state) => ({
          selectedFinding: byPathFinding,
          activeFilepath: byPathFinding.best_fix_location?.filepath || rawPath,
          activeStartLine: parsedLine || byPathFinding.best_fix_location?.line || 1,
          activeEndLine: parsedLine || byPathFinding.best_fix_location?.line || 1,
          primaryStage: "TRIAGE_FIX",
          workspaceViewMode: "REMEDIATION_IDE",
          ideLayoutMode: "SPLIT_BOTH",
          isSidebarCollapsed: false,
          ...(state.graphViewMode === "APP_TREE"
            ? { graphViewMode: "FINDING_PATH" as GraphViewMode }
            : {}),
        }));
        return;
      }
    }

    // 4. Otherwise resolve against appTree flat_files or fallback to first available file/finding
    let resolvedFile = rawPath;
    if (!resolvedFile || resolvedFile === "application root" || resolvedFile === "workspace manifest") {
      if (allFindings.length > 0) {
        get().jumpToBestFixLocation(allFindings[0]);
        return;
      }
      resolvedFile = treeFiles[0]?.filepath || get().activeFilepath || "";
    } else if (treeFiles.length > 0) {
      const normReq = resolvedFile.replace(/\\/g, "/").toLowerCase();
      const matchedTree = treeFiles.find((tf) => {
        const tfNorm = tf.filepath.replace(/\\/g, "/").toLowerCase();
        return tfNorm === normReq || tfNorm.endsWith(normReq) || normReq.endsWith(tfNorm);
      });
      if (matchedTree) {
        resolvedFile = matchedTree.filepath;
      }
    }

    set((state) => ({
      activeFilepath: resolvedFile,
      activeStartLine: parsedLine,
      activeEndLine: parsedLine,
      primaryStage: "TRIAGE_FIX",
      workspaceViewMode: "REMEDIATION_IDE",
      ideLayoutMode: "SPLIT_BOTH",
      isSidebarCollapsed: false,
      ...(state.graphViewMode === "APP_TREE"
        ? { graphViewMode: "FINDING_PATH" as GraphViewMode }
        : {}),
    }));
  },

  selectTreeFile: (file: FilePurposeInfo) => {
    set({
      selectedTreeFile: file,
      activeFilepath: file.filepath,
      activeStartLine: 1,
      activeEndLine: Math.min(file.line_count, 1),
    });
  },

  selectGraphNode: (node: CPGNode) => {
    set({
      selectedGraphNodeId: node.id,
      activeFilepath: node.filepath,
      activeStartLine: node.start_line,
      activeEndLine: node.end_line,
    });
  },

  selectCodeLine: async (filepath: string, line: number) => {
    try {
      const res = await fetch(
        `${BACKEND_URL}/api/node-at-location?filepath=${encodeURIComponent(filepath)}&line=${line}`
      );
      if (!res.ok) return;
      const data = await res.json();
      if (data && data.node) {
        const node: CPGNode = data.node;
        set({
          selectedGraphNodeId: node.id,
          activeFilepath: node.filepath,
          activeStartLine: node.start_line,
          activeEndLine: node.end_line,
        });

        const rf = get().reactFlowInstance;
        if (rf && rf.getNode) {
          const flowNode = rf.getNode(node.id);
          if (flowNode) {
            rf.setCenter(flowNode.position.x + 100, flowNode.position.y + 40, {
              zoom: 1.4,
              duration: 500,
            });
          }
        }
      }
    } catch (err) {
      console.error("Error finding node at location:", err);
    }
  },

  fetchFindings: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/findings`);
      if (res.ok) {
        const data: Finding[] = await res.json();
        const curSel = get().selectedFinding;
        const updatedSel = curSel ? data.find((f) => f.id === curSel.id) || data[0] || null : data[0] || null;
        set({ findings: data });
        if (data.length === 0) {
          set({ selectedFinding: null, selectedGraphNodeId: null });
        } else if (updatedSel && (!curSel || curSel.id !== updatedSel.id)) {
          const firstNode =
            updatedSel.path_nodes && updatedSel.path_nodes.length > 0
              ? updatedSel.path_nodes[0]
              : null;
          set({
            selectedFinding: updatedSel,
            activePathStepIndex: 0,
            remediationPreview: null,
            selectedGraphNodeId: firstNode ? firstNode.id : null,
            activeFilepath: firstNode ? firstNode.filepath : null,
            activeStartLine: firstNode ? firstNode.start_line : null,
            activeEndLine: firstNode ? firstNode.end_line : null,
          });
          if (get().isDiffEditorOpen) {
            void get().fetchRemediationPreview(updatedSel);
          }
        } else if (updatedSel && curSel) {
          set({ selectedFinding: updatedSel });
        }
      }
    } catch (err) {
      console.error("Failed to fetch findings:", err);
    }
  },

  fetchAppTree: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/app-tree`);
      if (res.ok) {
        const data: AppTreeSummary = await res.json();
        set((state) => ({
          appTree: data,
          projectPath: data.root_path || state.projectPath,
        }));
        if (data.flat_files.length > 0 && !get().selectedTreeFile) {
          set({ selectedTreeFile: data.flat_files[0] });
          if (!get().activeFilepath) {
            set({ activeFilepath: data.flat_files[0].filepath, activeStartLine: 1 });
          }
        }
      }
    } catch (err) {
      console.error("Failed to fetch app tree:", err);
    }
  },

  fetchMetrics: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/metrics`);
      if (res.ok) {
        const data: MetricsResponse = await res.json();
        set({ metrics: data });
      }
    } catch (err) {
      console.error("Failed to fetch metrics:", err);
    }
  },

  fetchAdvisories: async (autoInit = false) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/vuln-intel/advisories?auto_init=${autoInit}`);
      if (res.ok) {
        const data: ExtractedAdvisory[] = await res.json();
        set({ extractedAdvisories: data });
      }
    } catch (err) {
      console.error("Failed to fetch advisories:", err);
    }
  },

  fetchProjects: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/projects`);
      if (res.ok) {
        const data: ProjectConfig[] = await res.json();
        const activeProj = data.find((p) => p.is_active) || data[0];
        set((state) => ({
          projects: data,
          projectPath: state.projectPath || (activeProj ? activeProj.target_path : ""),
        }));
      }
    } catch (err) {
      console.error("Failed to fetch projects:", err);
    }
  },

  createProject: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/projects`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const proj: ProjectConfig = await res.json();
        await Promise.all([
          get().fetchProjects(),
          ...(payload.run_scan_immediately
            ? [
                get().fetchFindings(),
                get().fetchMetrics(),
                get().fetchAppTree(),
                get().fetchDeepDiveAnalytics(),
                get().fetchRaciGovernance(),
                get().fetchSastPlusSuite(),
                get().fetchTrackChanges(),
              ]
            : []),
        ]);
        return { ok: true, project: proj };
      } else {
        const errBody = await res.json().catch(() => ({}));
        const detail = String(errBody.detail || `HTTP ${res.status}`);
        const authRequired =
          res.status === 401 ||
          detail.includes("GITHUB_AUTH_REQUIRED") ||
          detail.includes("GITHUB_AUTH_FAILED");
        return { ok: false, project: null, error: detail, authRequired };
      }
    } catch (err: any) {
      console.error("Failed to create project:", err);
      return { ok: false, project: null, error: err?.message || "Network error" };
    }
  },

  updateProjectAutomation: async (projectId, payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/projects/${encodeURIComponent(projectId)}/automation`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        await get().fetchProjects();
      }
    } catch (err) {
      console.error("Failed to update project automation:", err);
    }
  },

  activateProject: async (projectId, runScan = false) => {
    const existingProj = get().projects.find((p) => p.id === projectId);
    const needsScan =
      runScan ||
      Boolean(existingProj && !existingProj.last_scan_at && !existingProj.has_cached_scan);

    // Optimistically mark the selected project as active on frame 1
    set((state) => ({
      projects: state.projects.map((p) => ({
        ...p,
        is_active: p.id === projectId,
      })),
      ...(existingProj?.target_path ? { projectPath: existingProj.target_path } : {}),
    }));

    try {
      const res = await fetch(
        `${BACKEND_URL}/api/projects/${encodeURIComponent(projectId)}/activate?skip_warmup=${
          needsScan ? "true" : "false"
        }`,
        {
          method: "POST",
        }
      );
      if (res.ok) {
        const proj: ProjectConfig = await res.json();
        set((state) => ({
          projectPath: proj.target_path,
          projects: state.projects.map((p) =>
            p.id === proj.id ? { ...proj, is_active: true } : { ...p, is_active: false }
          ),
          selectedFinding: null,
          selectedGraphNodeId: null,
          selectedTreeFile: null,
          activeFilepath: null,
          activeStartLine: null,
          activeEndLine: null,
        }));
        if (needsScan) {
          const hasLocalCheckout =
            Boolean(proj.target_path) &&
            !proj.target_path.startsWith("http://") &&
            !proj.target_path.startsWith("https://") &&
            !proj.target_path.startsWith("git@");
          if (proj.scm_provider !== "LOCAL" && proj.repo_url && !hasLocalCheckout) {
            if (proj.is_private_repo && !proj.has_saved_auth) {
              get().openTargetPicker(
                "URL",
                proj.repo_url,
                true,
                `Private repository '${proj.name}' requires your Personal Access Token to fetch & re-scan the latest commit.`
              );
              return;
            }
            await get().triggerScan(proj.repo_url, {
              branch: proj.branch || "main",
              repo_visibility: proj.is_private_repo ? "PRIVATE" : "AUTO",
            });
          } else {
            await get().triggerScan(proj.target_path);
          }
          return;
        }
        await Promise.all([
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchAppTree(),
          get().fetchProjects(),
        ]);
        void Promise.all([
          get().fetchDeepDiveAnalytics(),
          get().fetchRaciGovernance(),
          get().fetchSastPlusSuite(),
          get().fetchTrackChanges(),
        ]);
      }
    } catch (err) {
      console.error("Failed to activate project:", err);
    }
  },

  deleteProject: async (projectId) => {
    try {
      const res = await fetch(
        `${BACKEND_URL}/api/projects/${encodeURIComponent(projectId)}`,
        {
          method: "DELETE",
        }
      );
      if (res.ok) {
        set((state) => ({
          projects: state.projects.filter((p) => p.id !== projectId),
        }));
        await get().fetchProjects();
        return true;
      }
    } catch (err) {
      console.error("Failed to delete project:", err);
    }
    return false;
  },

  triggerProjectWebhook: async (projectId, eventType, branch = "main") => {
    set({
      isScanning: true,
      scanStatusMessage: `SCM Webhook (${eventType} on ${branch}) triggered automated scan...`,
    });
    try {
      const res = await fetch(`${BACKEND_URL}/api/projects/${encodeURIComponent(projectId)}/webhook`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_type: eventType,
          branch,
          commit_sha: Math.random().toString(16).slice(2, 9),
          actor: eventType === "push" ? "github-push-webhook" : "github-pr-gate",
        }),
      });
      if (res.ok) {
        await Promise.all([
          get().fetchProjects(),
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchAppTree(),
          get().fetchDeepDiveAnalytics(),
          get().fetchTrackChanges(),
        ]);
      }
    } catch (err) {
      console.error("Failed to trigger project webhook:", err);
    } finally {
      set({ isScanning: false, scanStatusMessage: null });
    }
  },

  fetchDeepDiveAnalytics: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/analytics/deep-dive`);
      if (res.ok) {
        const data: DeepDiveAnalyticsResponse = await res.json();
        set({ deepDiveAnalytics: data });
      }
    } catch (err) {
      console.error("Failed to fetch deep dive analytics:", err);
    }
  },

  updateFindingTriage: async (findingId, status, reason, comment) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/findings/${encodeURIComponent(findingId)}/triage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status,
          reason: reason || null,
          comment: comment || null,
          author: "Lead Security Auditor",
        }),
      });
      if (res.ok) {
        await Promise.all([
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchDeepDiveAnalytics(),
          get().fetchProjects(),
          get().fetchIntegrations(),
          get().fetchTrackChanges(),
        ]);
      }
    } catch (err) {
      console.error("Failed to update finding triage:", err);
    }
  },

  fetchPlatformSettings: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/settings`);
      if (res.ok) {
        const data: PlatformSettingsResponse = await res.json();
        set({ platformSettings: data });
      }
    } catch (err) {
      console.error("Failed to fetch platform settings:", err);
    }
  },

  updatePlatformSettings: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/settings`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data: PlatformSettingsResponse = await res.json();
        set({ platformSettings: data });
        await Promise.all([
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchDeepDiveAnalytics(),
        ]);
      }
    } catch (err) {
      console.error("Failed to update platform settings:", err);
    }
  },

  upsertQueryRule: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/settings/queries`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        await Promise.all([
          get().fetchPlatformSettings(),
          get().fetchFindings(),
          get().fetchDeepDiveAnalytics(),
        ]);
      }
    } catch (err) {
      console.error("Failed to upsert query rule:", err);
    }
  },

  toggleQueryRule: async (ruleId) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/settings/queries/${encodeURIComponent(ruleId)}/toggle`, {
        method: "POST",
      });
      if (res.ok) {
        await Promise.all([
          get().fetchPlatformSettings(),
          get().fetchFindings(),
          get().fetchDeepDiveAnalytics(),
        ]);
      }
    } catch (err) {
      console.error("Failed to toggle query rule:", err);
    }
  },

  createTestProfile: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/settings/presets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data: PlatformSettingsResponse = await res.json();
        set({ platformSettings: data });
        await Promise.all([
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchDeepDiveAnalytics(),
        ]);
      }
    } catch (err) {
      console.error("Failed to create test profile:", err);
    }
  },

  batchUpdateRules: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/settings/queries/batch-select`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data: PlatformSettingsResponse = await res.json();
        set({ platformSettings: data });
        await Promise.all([
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchDeepDiveAnalytics(),
        ]);
      }
    } catch (err) {
      console.error("Failed to batch update rules:", err);
    }
  },

  fetchUserAccounts: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/accounts`);
      if (res.ok) {
        const data: UserAccountsStateResponse = await res.json();
        const activeUser = data.users.find((u) => u.id === data.active_user_id) || data.users[0];
        set((state) => ({
          userAccountsState: data,
          activeOperator: activeUser
            ? {
                name: activeUser.name,
                role: `${activeUser.title} (${activeUser.account_name})`,
                email: activeUser.email,
              }
            : state.activeOperator,
        }));
      }
    } catch (err) {
      console.error("Failed to fetch user accounts state:", err);
    }
  },

  createAccount: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/accounts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data: UserAccountsStateResponse = await res.json();
        set({ userAccountsState: data });
        await get().fetchProjects();
      }
    } catch (err) {
      console.error("Failed to create tenant account:", err);
    }
  },

  createUserProfile: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/accounts/users`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data: UserAccountsStateResponse = await res.json();
        set({ userAccountsState: data });
      }
    } catch (err) {
      console.error("Failed to create user profile:", err);
    }
  },

  switchUserOrAccount: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/accounts/switch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data: UserAccountsStateResponse = await res.json();
        const activeUser = data.users.find((u) => u.id === data.active_user_id) || data.users[0];
        set((state) => ({
          userAccountsState: data,
          activeOperator: activeUser
            ? {
                name: activeUser.name,
                role: `${activeUser.title} (${activeUser.account_name})`,
                email: activeUser.email,
              }
            : state.activeOperator,
        }));
        await Promise.all([
          get().fetchPlatformSettings(),
          get().fetchProjects(),
          get().fetchFindings(),
        ]);
      }
    } catch (err) {
      console.error("Failed to switch user or account:", err);
    }
  },

  addCustomSanitizer: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/settings/sanitizers`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        await Promise.all([
          get().fetchPlatformSettings(),
          get().fetchFindings(),
          get().fetchDeepDiveAnalytics(),
        ]);
      }
    } catch (err) {
      console.error("Failed to add custom sanitizer:", err);
    }
  },

  toggleCustomSanitizer: async (sanId) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/settings/sanitizers/${encodeURIComponent(sanId)}/toggle`, {
        method: "POST",
      });
      if (res.ok) {
        await Promise.all([
          get().fetchPlatformSettings(),
          get().fetchFindings(),
          get().fetchDeepDiveAnalytics(),
        ]);
      }
    } catch (err) {
      console.error("Failed to toggle custom sanitizer:", err);
    }
  },

  fetchIntegrations: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/integrations`);
      if (res.ok) {
        const data: IntegrationHubStateResponse = await res.json();
        set({ integrationState: data });
      }
    } catch (err) {
      console.error("Failed to fetch integrations:", err);
    }
  },

  updateIntegrationConfig: async (cfg) => {
    try {
      const currentCfg = get().integrationState?.config || {};
      const merged = { ...currentCfg, ...cfg };
      const res = await fetch(`${BACKEND_URL}/api/integrations/config`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(merged),
      });
      if (res.ok) {
        await Promise.all([get().fetchIntegrations(), get().fetchFindings()]);
      }
    } catch (err) {
      console.error("Failed to update integration config:", err);
    }
  },

  testIntegrationConnection: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/integrations/test-connection`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data: TestConnectionResponse = await res.json();
        await get().fetchIntegrations();
        return data;
      }
    } catch (err) {
      console.error("Failed to test integration connection:", err);
    }
    return null;
  },

  createTicketForFinding: async (findingId, provider, options) => {
    try {
      const defaultProv = get().integrationState?.config?.default_provider;
      const resolvedProv =
        provider ||
        (defaultProv === "GITHUB_ISSUES" ? "GITHUB_ISSUES" : "JIRA");
      const res = await fetch(`${BACKEND_URL}/api/integrations/tickets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_id: findingId,
          provider: resolvedProv,
          assignee: options?.assignee || get().activeOperator?.email || "Unassigned",
          priority: options?.priority || null,
          labels: options?.labels || null,
          custom_notes: options?.custom_notes || null,
        }),
      });
      if (res.ok) {
        const ticket: IssueTicket = await res.json();
        await Promise.all([get().fetchIntegrations(), get().fetchFindings()]);
        return ticket;
      }
    } catch (err) {
      console.error("Failed to create ticket:", err);
    }
    return null;
  },

  updateTicket: async (ticketId, payload) => {
    try {
      const res = await fetch(
        `${BACKEND_URL}/api/integrations/tickets/${encodeURIComponent(ticketId)}`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );
      if (res.ok) {
        const updated: IssueTicket = await res.json();
        await Promise.all([
          get().fetchIntegrations(),
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchDeepDiveAnalytics(),
          get().fetchProjects(),
        ]);
        return updated;
      }
    } catch (err) {
      console.error("Failed to update ticket:", err);
    }
    return null;
  },

  deleteTicket: async (ticketId) => {
    try {
      const res = await fetch(
        `${BACKEND_URL}/api/integrations/tickets/${encodeURIComponent(ticketId)}`,
        {
          method: "DELETE",
        }
      );
      if (res.ok) {
        await Promise.all([get().fetchIntegrations(), get().fetchFindings()]);
        return true;
      }
    } catch (err) {
      console.error("Failed to delete ticket:", err);
    }
    return false;
  },

  autoSyncTickets: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/integrations/tickets/auto-sync`, {
        method: "POST",
      });
      if (res.ok) {
        await Promise.all([get().fetchIntegrations(), get().fetchFindings()]);
      }
    } catch (err) {
      console.error("Failed to auto-sync tickets:", err);
    }
  },

  fetchRaciGovernance: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/governance/raci`);
      if (res.ok) {
        const data: RaciGovernanceResponse = await res.json();
        set({ raciGovernance: data });
      }
    } catch (err) {
      console.error("Failed to fetch RACI governance matrix:", err);
    }
  },

  updateRaciCell: async (activityId, roleId, value) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/governance/raci/cell`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          activity_id: activityId,
          role_id: roleId,
          value,
        }),
      });
      if (res.ok) {
        const data: RaciGovernanceResponse = await res.json();
        set({ raciGovernance: data });
      }
    } catch (err) {
      console.error("Failed to update RACI cell:", err);
    }
  },

  updateFindingRaciOwner: async (payload) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/governance/raci/finding-owner`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data: RaciGovernanceResponse = await res.json();
        set({ raciGovernance: data });
        await get().fetchFindings();
      }
    } catch (err) {
      console.error("Failed to update finding RACI owner:", err);
    }
  },

  resetRaciGovernance: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/governance/raci/reset`, {
        method: "POST",
      });
      if (res.ok) {
        const data: RaciGovernanceResponse = await res.json();
        set({ raciGovernance: data });
        await get().fetchFindings();
      }
    } catch (err) {
      console.error("Failed to reset RACI governance:", err);
    }
  },

  fetchSastPlusSuite: async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/aspm/suite`);
      if (res.ok) {
        const data: SastPlusSuiteResponse = await res.json();
        set({ sastPlusSuite: data });
      }
    } catch (err) {
      console.error("Failed to fetch SAST++++++ ASPM suite:", err);
    }
  },

  fetchTrackChanges: async (projectPath?: string) => {
    try {
      const q = projectPath ? `?project_path=${encodeURIComponent(projectPath)}` : "";
      const res = await fetch(`${BACKEND_URL}/api/scan/track-changes${q}`);
      if (res.ok) {
        const data: TrackChangesSummary = await res.json();
        set({ trackChanges: data });
      }
    } catch (err) {
      console.error("Failed to fetch Track Changes summary:", err);
    }
  },

  extractAndScanFromSites: async ({ sources, customUrls, searchQuery }) => {
    set({
      isExtractingIntel: true,
      intelStatusMessage: "Extracting advisories from selected sites & scanning codebase CPG...",
    });
    try {
      const res = await fetch(`${BACKEND_URL}/api/vuln-intel/extract`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sources,
          custom_urls: customUrls,
          search_query: searchQuery || null,
          auto_scan_code: true,
        }),
      });
      if (res.ok) {
        const data: SiteExtractResponse = await res.json();
        set({
          extractedAdvisories: data.advisories,
          isExtractingIntel: false,
          intelStatusMessage: `Extracted ${data.extracted_count} advisories across ${data.sources_queried.length} site(s); identified ${data.code_findings_created} matches in code!`,
        });
        await Promise.all([
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchDeepDiveAnalytics(),
          get().fetchRaciGovernance(),
          get().fetchSastPlusSuite(),
          get().fetchTrackChanges(),
        ]);
        return data;
      } else {
        const err = await res.json();
        set({
          isExtractingIntel: false,
          intelStatusMessage: `Extraction error: ${err.detail || "Failed"}`,
        });
        return null;
      }
    } catch (err: any) {
      set({
        isExtractingIntel: false,
        intelStatusMessage: `Network error: ${err.message}`,
      });
      return null;
    }
  },

  exportAuditReport: async (format: "markdown" | "json" | "sarif") => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/export/report?format=${format}`);
      if (!res.ok) return;
      const blob = await res.blob();
      const ext = format === "markdown" ? "md" : format === "sarif" ? "sarif.json" : "json";
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `alastor-security-audit-report.${ext}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to export report:", err);
    }
  },

  triggerScan: async (targetPath?: string, options?: GitRepoScanOptions) => {
    const path = (targetPath || get().projectPath || "").trim();
    if (!path) {
      return { ok: false, error: "Please select or paste a target path or GitHub repository URL." };
    }
    set({
      isScanning: true,
      gitScanErrorBanner: null,
      scanStatusMessage: `Initiating analysis for: ${path}...`,
      scanProgress: {
        is_scanning: true,
        phase: "STARTING",
        current_pass: "Initializing Scan",
        current_file: path,
        files_done: 0,
        total_files: 0,
        percent: 2,
        message: `Connecting to compiler engine for: ${path}...`,
      },
    });

    let pollInterval: any = null;

    pollInterval = setInterval(async () => {
      try {
        const pRes = await fetch(`${BACKEND_URL}/api/scan/progress`);
        if (pRes.ok) {
          const prog: ScanProgress = await pRes.json();
          set({
            scanProgress: prog,
            scanStatusMessage: prog.message,
          });
        }
      } catch (err) {
        // Ignore transient poll errors
      }
    }, 250);

    try {
      const reqPayload: Record<string, any> = { target_path: path };
      if (options?.branch) reqPayload.branch = options.branch;
      if (options?.repo_visibility) reqPayload.repo_visibility = options.repo_visibility;
      if (options?.auth_token) reqPayload.auth_token = options.auth_token;
      if (options?.auth_username) reqPayload.auth_username = options.auth_username;
      if (typeof options?.save_token === "boolean") reqPayload.save_token = options.save_token;

      const res = await fetch(`${BACKEND_URL}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reqPayload),
      });

      if (res.ok) {
        const scanData: ScanResponse = await res.json();
        set({
          projectPath: scanData.project_path || path,
          isTargetPickerOpen: false,
          gitScanErrorBanner: null,
          scanStatusMessage: "Mapping complete. Updating application tree and rule hunters...",
          scanProgress: {
            is_scanning: false,
            phase: "COMPLETED",
            current_pass: "Completed",
            current_file: "",
            files_done: 1,
            total_files: 1,
            percent: 100,
            message: "Scan completed successfully!",
          },
        });
        await Promise.all([
          get().fetchFindings(),
          get().fetchProjects(),
          get().fetchMetrics(),
          get().fetchAppTree(),
        ]);
        set({ isScanning: false, scanStatusMessage: null });
        void Promise.all([
          get().fetchDeepDiveAnalytics(),
          get().fetchRaciGovernance(),
          get().fetchSastPlusSuite(),
          get().fetchTrackChanges(),
        ]);
        return { ok: true, response: scanData };
      } else {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        const rawDetail = String(err.detail || "Unknown error");
        const isAuthRequired =
          res.status === 401 ||
          rawDetail.includes("[GITHUB_AUTH_REQUIRED]") ||
          rawDetail.includes("[GITHUB_AUTH_FAILED]");
        const cleanDetail = rawDetail
          .replace("[GITHUB_AUTH_REQUIRED]", "")
          .replace("[GITHUB_AUTH_FAILED]", "")
          .trim();

        set({
          isScanning: false,
          scanStatusMessage: `Scan Failed: ${cleanDetail}`,
          gitScanErrorBanner: cleanDetail,
          ...(isAuthRequired
            ? {
                isTargetPickerOpen: true,
                targetPickerTab: "URL",
                gitScanPrefillUrl: path,
                gitScanForcePrivateAuth: true,
              }
            : {}),
          scanProgress: {
            is_scanning: false,
            phase: "ERROR",
            current_pass: isAuthRequired ? "Auth Required" : "Error",
            current_file: "",
            files_done: 0,
            total_files: 0,
            percent: 0,
            message: `Scan Failed: ${cleanDetail}`,
            error: cleanDetail,
          },
        });
        return { ok: false, authRequired: isAuthRequired, error: cleanDetail };
      }
    } catch (err: any) {
      const msg = err?.message || "Network connection failed";
      set({
        isScanning: false,
        scanStatusMessage: `Network Error: ${msg}`,
        scanProgress: {
          is_scanning: false,
          phase: "ERROR",
          current_pass: "Network Error",
          current_file: "",
          files_done: 0,
          total_files: 0,
          percent: 0,
          message: `Network Error: ${msg}`,
          error: msg,
        },
      });
      return { ok: false, error: msg };
    } finally {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    }
  },
}));

