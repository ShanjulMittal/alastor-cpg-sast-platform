import { create } from "zustand";
import {
  Finding,
  CPGNode,
  MetricsResponse,
  GraphViewMode,
  WorkspaceViewMode,
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
} from "@/types/cpg";

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

interface AuditState {
  projectPath: string;
  findings: Finding[];
  selectedFinding: Finding | null;
  activeFilepath: string | null;
  activeStartLine: number | null;
  activeEndLine: number | null;
  selectedGraphNodeId: string | null;
  graphViewMode: GraphViewMode;
  workspaceViewMode: WorkspaceViewMode;
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

  setAppTheme: (theme: AppThemeId) => void;
  setBackdropIntensity: (intensity: BackdropIntensity) => void;
  setAudienceMode: (mode: AudiencePersonaMode) => void;
  setSettingsBarVisible: (visible: boolean) => void;
  setUiDensityMode: (mode: "SIMPLE_CLEAN" | "PRO_DETAILED") => void;
  setIdeLayoutMode: (mode: "SPLIT_BOTH" | "CODE_FOCUS" | "GRAPH_FOCUS") => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setQuickCommandOpen: (open: boolean) => void;
  setMenuBarExpanded: (expanded: boolean) => void;
  setSastPlusActiveTab: (tab: "TRANSLATOR" | "SBOM" | "ATTACK_SURFACE" | "ROADMAP" | "THREAT_MODEL" | "ACADEMY") => void;
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
  setSettingsModalOpen: (open: boolean, tab?: "PRESETS" | "GLOBAL_PROJECT" | "QUERY_VIEWER" | "CUSTOMIZATION") => void;
  setIntegrationModalOpen: (open: boolean) => void;
  setReactFlowInstance: (instance: any) => void;
  setGraphFullscreen: (val: boolean) => void;
  selectFinding: (finding: Finding) => void;
  jumpToBestFixLocation: (finding: Finding) => void;
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
  }) => Promise<ProjectConfig | null>;
  updateProjectAutomation: (projectId: string, payload: Record<string, any>) => Promise<void>;
  activateProject: (projectId: string, runScan?: boolean) => Promise<void>;
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
  triggerScan: (targetPath?: string) => Promise<void>;
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
  workspaceViewMode: "REMEDIATION_IDE",
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
  isMenuBarExpanded: false,

  setAppTheme: (theme: AppThemeId) => {
    set({ appTheme: theme });
    if (typeof window !== "undefined") {
      try {
        localStorage.setItem("alastor_app_theme_v3", theme);
      } catch {}
    }
  },

  setBackdropIntensity: (intensity: BackdropIntensity) => {
    set({ backdropIntensity: intensity });
    if (typeof window !== "undefined") {
      try {
        localStorage.setItem("alastor_backdrop_intensity", intensity);
      } catch {}
    }
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
    set({ sastPlusActiveTab: tab, workspaceViewMode: "SAST_PLUS_SUITE" });
    get().fetchSastPlusSuite();
  },

  setShowPortalGate: (show, operator) => {
    set((state) => ({
      showPortalGate: show,
      ...(operator ? { activeOperator: operator } : {}),
    }));
  },

  setProjectPath: (path: string) => set({ projectPath: path }),

  setGraphViewMode: (mode: GraphViewMode) => set({ graphViewMode: mode }),

  setWorkspaceViewMode: (mode: WorkspaceViewMode) => {
    set({ workspaceViewMode: mode });
    get().fetchTrackChanges();
    if (mode === "PROJECTS_HUB") {
      get().fetchProjects();
    } else if (mode === "DEEP_DIVE") {
      get().fetchDeepDiveAnalytics();
    } else if (mode === "RACI_GOVERNANCE") {
      get().fetchRaciGovernance();
    } else if (mode === "SAST_PLUS_SUITE") {
      get().fetchSastPlusSuite();
    }
  },


  setActiveSidebarTab: (tab: "FLAWS" | "APP_TREE" | "SITE_EXTRACTOR") => set({ activeSidebarTab: tab }),

  setActiveEngineFilter: (eng: "ALL" | ScanEngineType) => set({ activeEngineFilter: eng }),

  setPrimaryGrouping: (grp: "NONE" | "LANGUAGE" | "SEVERITY" | "ENGINE") => set({ primaryGrouping: grp }),

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
    set({
      selectedFinding: finding,
      selectedGraphNodeId: firstNode ? firstNode.id : null,
      activeFilepath: firstNode ? firstNode.filepath : null,
      activeStartLine: firstNode ? firstNode.start_line : null,
      activeEndLine: firstNode ? firstNode.end_line : null,
    });
  },

  jumpToBestFixLocation: (finding: Finding) => {
    const bfl = finding.best_fix_location;
    if (!bfl) {
      get().selectFinding(finding);
      return;
    }
    set({
      selectedFinding: finding,
      selectedGraphNodeId: bfl.node_id || null,
      activeFilepath: bfl.filepath,
      activeStartLine: bfl.line,
      activeEndLine: bfl.line,
      workspaceViewMode: "REMEDIATION_IDE",
    });
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
          get().selectFinding(updatedSel);
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
        await get().fetchProjects();
        return proj;
      }
    } catch (err) {
      console.error("Failed to create project:", err);
    }
    return null;
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
    try {
      const res = await fetch(
        `${BACKEND_URL}/api/projects/${encodeURIComponent(projectId)}/activate`,
        {
          method: "POST",
        }
      );
      if (res.ok) {
        const proj: ProjectConfig = await res.json();
        set({
          projectPath: proj.target_path,
          selectedFinding: null,
          selectedGraphNodeId: null,
          selectedTreeFile: null,
          activeFilepath: null,
          activeStartLine: null,
          activeEndLine: null,
        });
        if (runScan) {
          await get().triggerScan(proj.target_path);
        }
        await Promise.all([
          get().fetchProjects(),
          get().fetchFindings(),
          get().fetchMetrics(),
          get().fetchAppTree(),
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

  triggerScan: async (targetPath?: string) => {
    const path = targetPath || get().projectPath;
    set({
      isScanning: true,
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
      const res = await fetch(`${BACKEND_URL}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_path: path }),
      });

      if (res.ok) {
        set({
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
          get().fetchMetrics(),
          get().fetchAppTree(),
          get().fetchProjects(),
          get().fetchDeepDiveAnalytics(),
          get().fetchRaciGovernance(),
          get().fetchSastPlusSuite(),
          get().fetchTrackChanges(),
        ]);
        setTimeout(() => {
          set({ isScanning: false, scanStatusMessage: null });
        }, 1500);
      } else {
        const err = await res.json();
        set({
          isScanning: false,
          scanStatusMessage: `Scan Failed: ${err.detail || "Unknown error"}`,
          scanProgress: {
            is_scanning: false,
            phase: "ERROR",
            current_pass: "Error",
            current_file: "",
            files_done: 0,
            total_files: 0,
            percent: 0,
            message: `Scan Failed: ${err.detail || "Unknown error"}`,
            error: err.detail,
          },
        });
      }
    } catch (err: any) {
      set({
        isScanning: false,
        scanStatusMessage: `Network Error: ${err.message}`,
        scanProgress: {
          is_scanning: false,
          phase: "ERROR",
          current_pass: "Network Error",
          current_file: "",
          files_done: 0,
          total_files: 0,
          percent: 0,
          message: `Network Error: ${err.message}`,
          error: err.message,
        },
      });
    } finally {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    }
  },
}));

