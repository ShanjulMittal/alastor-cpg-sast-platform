export type NodeLabel =
  | "File"
  | "AppFile"
  | "AppDirectory"
  | "AppElement"
  | "Directory"
  | "Module"
  | "Class"
  | "Function"
  | "Parameter"
  | "Variable"
  | "Assignment"
  | "Call"
  | "ControlBlock"
  | "LoopBlock"
  | "Return"
  | "Literal"
  | "Entry"
  | "Exit";

export type EdgeType =
  | "AST_CHILD"
  | "CFG_NEXT"
  | "CFG_TRUE"
  | "CFG_FALSE"
  | "CFG_LOOP_BACK"
  | "CFG_BREAK"
  | "DFG_FLOWS_TO"
  | "CALLS"
  | "DEFINES"
  | "IMPORTS"
  | "CONTAINS"
  | "DECLARES"
  | "CONFIGURES";

export interface CPGNode {
  id: string;
  label: NodeLabel;
  ast_type: string;
  name: string;
  code: string;
  filepath: string;
  start_line: number;
  end_line: number;
  start_col: number;
  end_col: number;
  scope_id: string;
  is_source: boolean;
  is_sink: boolean;
  is_sanitizer: boolean;
  is_bfl?: boolean;
  category?: string;
  purpose?: string;
  language?: string;
}

export interface CPGEdge {
  id: string;
  source_id: string;
  target_id: string;
  edge_type: EdgeType;
  var_name?: string | null;
}

export interface BestFixLocation {
  node_id: string;
  filepath: string;
  line: number;
  column: number;
  code_snippet: string;
  explanation: string;
  recommended_fix: string;
  rationale?: string;
  before_code_block?: string;
  after_code_block?: string;
}

export type TriageStatus =
  | "TO_VERIFY"
  | "CONFIRMED"
  | "NOT_EXPLOITABLE"
  | "PROPOSED_NOT_EXPLOITABLE"
  | "RESOLVED";

export type ScanEngineType = "SAST" | "SCA" | "IaC";

export interface Finding {
  id: string;
  rule_id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  cwe_id?: string | null;
  cve_id?: string | null;
  owasp_category?: string | null;
  cvss_score?: number | null;
  remediation?: string | null;
  source_site?: string | null;
  reference_url?: string | null;
  path_nodes: CPGNode[];
  path_edges: Array<{
    id: string;
    source: string;
    target: string;
    type: string;
    var_name?: string | null;
  }>;
  scan_engine?: ScanEngineType;
  language?: string;
  best_fix_location?: BestFixLocation | null;
  triage_status?: TriageStatus;
  triage_reason?: string | null;
  triage_comment?: string | null;
  triaged_by?: string | null;
  triaged_at?: string | null;
  first_seen_at?: string | null;
  age_days?: number;
  sla_status?: "WITHIN_SLA" | "APPROACHING_SLA" | "SLA_BREACHED" | string;
  linked_ticket_id?: string | null;
  linked_ticket_url?: string | null;
  plain_english_summary?: string;
  non_coder_analogy?: string;
  business_impact?: string;
  management_action_steps?: string[];
  effort_estimate?: string;
  financial_risk_tier?: string;
  raci_responsible?: string;
  raci_accountable?: string;
  raci_consulted?: string;
  raci_informed?: string;
  change_status?: "NEW" | "UNCHANGED" | "FIXED" | "REOPENED";
  fixed_at?: string | null;
  scan_number_introduced?: number;
  reachability_status?: "REACHABLE" | "CONDITIONALLY_REACHABLE" | "UNREACHABLE_DORMANT";
  reachability_reason?: string;
  epss_score?: number;
  epss_percentile?: number;
  cisa_kev_listed?: boolean;
  exploit_maturity?: string;
}

export interface ExtractedAdvisory {
  id: string;
  cve_id?: string | null;
  cwe_id?: string | null;
  title: string;
  summary: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss_score?: number | null;
  source_site: string;
  reference_url: string;
  affected_packages: string[];
  code_patterns: string[];
  remediation: string;
  matched_in_code: boolean;
  match_count: number;
  matched_files: string[];
}

export interface SiteExtractResponse {
  extracted_count: number;
  matched_in_code_count: number;
  code_findings_created: number;
  advisories: ExtractedAdvisory[];
  code_findings: Finding[];
  sources_queried: string[];
}

export interface DiscoveredElement {
  name: string;
  element_type: string;
  signature: string;
  line_number: number;
  details: string;
}

export interface FilePurposeInfo {
  filepath: string;
  filename: string;
  extension: string;
  category: string;
  purpose: string;
  language: string;
  line_count: number;
  size_bytes: number;
  sha256: string;
  elements: DiscoveredElement[];
  is_cpg_supported: boolean;
  security_tags: string[];
}

export interface DirectoryTreeNode {
  name: string;
  path: string;
  purpose: string;
  files: FilePurposeInfo[];
  subdirectories: DirectoryTreeNode[];
}

export interface AppTreeSummary {
  root_path: string;
  total_files: number;
  total_directories: number;
  total_lines: number;
  category_counts: Record<string, number>;
  detected_tech_stack: string[];
  tree: DirectoryTreeNode;
  flat_files: FilePurposeInfo[];
}

export interface ScanResponse {
  project_path: string;
  files_scanned: number;
  nodes_created: number;
  edges_created: number;
  status: string;
  categories?: Record<string, number>;
  tech_stack?: string[];
  total_app_files?: number;
}

export interface MetricsResponse {
  total_nodes: number;
  total_edges: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_app_files?: number;
  categories?: Record<string, number>;
  tech_stack?: string[];
}

export type GraphViewMode =
  | "FINDING_PATH"
  | "FULL_CPG"
  | "CALL_GRAPH"
  | "DFG_ONLY"
  | "CFG_ONLY"
  | "APP_TREE";

export type WorkspaceViewMode =
  | "REMEDIATION_IDE"
  | "PROJECTS_HUB"
  | "DEEP_DIVE"
  | "RACI_GOVERNANCE"
  | "SAST_PLUS_SUITE";

export type AudiencePersonaMode = "NON_CODER_MANAGEMENT" | "TECHNICAL_ENGINEER";

export interface ScanProgress {
  is_scanning: boolean;
  phase: string;
  current_pass: string;
  current_file: string;
  files_done: number;
  total_files: number;
  percent: number;
  message: string;
  error?: string | null;
}

// ---------------------------------------------------------------------------
// Enterprise Feature Interfaces
// ---------------------------------------------------------------------------
export interface ProjectAutomationConfig {
  auto_scan_on_push: boolean;
  auto_scan_on_pr: boolean;
  auto_scan_on_schedule: boolean;
  schedule_cron: string;
  target_branches: string[];
  webhook_url: string;
  webhook_secret_masked: string;
  last_triggered_at?: string | null;
  last_trigger_event?: string | null;
}

export interface ProjectConfig {
  id: string;
  name: string;
  description: string;
  scm_provider: "GITHUB" | "GITLAB" | "BITBUCKET" | "LOCAL";
  repo_url: string;
  branch: string;
  target_path: string;
  preset_id: string;
  override_global_settings: boolean;
  custom_engines: string[];
  automation: ProjectAutomationConfig;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SECURE";
  risk_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_findings: number;
  sast_count: number;
  sca_count: number;
  iac_count: number;
  languages: string[];
  last_scan_at?: string | null;
  previous_scan_at?: string | null;
  scan_count?: number;
  has_cached_scan?: boolean;
  fixed_since_last_scan?: number;
  new_since_last_scan?: number;
  unchanged_since_last_scan?: number;
  files_scanned_count?: number;
  cpg_nodes_count?: number;
  cpg_edges_count?: number;
  is_active: boolean;
}

export interface AgingBucket {
  bucket: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ComplianceControlItem {
  control_id: string;
  title: string;
  category: string;
  status: "PASS" | "FAIL" | "WARNING";
  findings_count: number;
  mapped_cwes: string[];
  description: string;
}

export interface ComplianceStandardReport {
  standard_id: string;
  name: string;
  version: string;
  compliance_score: number;
  passed_controls: number;
  failed_controls: number;
  total_controls: number;
  controls: ComplianceControlItem[];
}

export interface EngineSummaryItem {
  engine: ScanEngineType;
  label: string;
  description: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  status: string;
  rules_executed: number;
}

export interface DeepDiveAnalyticsResponse {
  project_id: string;
  project_name: string;
  risk_level: string;
  risk_score: number;
  severity_breakdown: Record<string, number>;
  language_breakdown: Record<string, number>;
  engine_breakdown: EngineSummaryItem[];
  aging_summary: AgingBucket[];
  mean_age_days: number;
  sla_breached_count: number;
  suppressed_count: number;
  confirmed_count: number;
  compliance_reports: ComplianceStandardReport[];
}

export interface ScanPreset {
  id: string;
  name: string;
  badge: string;
  description: string;
  is_default: boolean;
  enabled_engines: string[];
  enabled_rule_ids: string[];
}

export interface SecurityQueryRule {
  id: string;
  name: string;
  engine: ScanEngineType;
  language: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cwe_id: string;
  owasp_category: string;
  cvss_score: number;
  description: string;
  remediation: string;
  cypher: string;
  enabled: boolean;
  is_custom: boolean;
}

export interface CustomSanitizerRule {
  id: string;
  function_name: string;
  language: string;
  target_cwe: string;
  description: string;
  active: boolean;
}

export interface PlatformSettingsResponse {
  active_scope: "GLOBAL" | "PROJECT";
  active_preset_id: string;
  enabled_engines: string[];
  max_dfg_depth: number;
  auto_suppress_low: boolean;
  fail_on_severity: "CRITICAL" | "HIGH" | "MEDIUM" | "NONE";
  sla_days: Record<string, number>;
  excluded_paths: string[];
  presets: ScanPreset[];
  queries: SecurityQueryRule[];
  custom_sanitizers: CustomSanitizerRule[];
  project_overrides: Record<string, any>;
}

export interface BugTrackerConnectorConfig {
  jira_enabled: boolean;
  jira_url: string;
  jira_project_key: string;
  jira_issue_type: string;
  jira_email?: string;
  jira_api_token?: string;
  jira_api_token_masked: string;
  jira_connection_status?: string;
  jira_last_tested_at?: string | null;
  github_issues_enabled: boolean;
  github_repo: string;
  github_labels: string[];
  github_token?: string;
  github_token_masked: string;
  github_connection_status?: string;
  github_last_tested_at?: string | null;
  auto_create_tickets: boolean;
  auto_severity_threshold: "CRITICAL" | "HIGH" | "MEDIUM" | "ALL";
  auto_trigger_on: "SCAN_COMPLETE" | "ON_CONFIRMED" | "MANUAL";
  default_provider: "JIRA" | "GITHUB_ISSUES" | "BOTH";
  bidirectional_triage_sync?: boolean;
}

export interface TicketComment {
  id: string;
  author: string;
  body: string;
  created_at: string;
}

export interface IssueTicket {
  id: string;
  ticket_key: string;
  provider: "JIRA" | "GITHUB_ISSUES";
  finding_id: string;
  finding_title: string;
  severity: string;
  cwe_id?: string | null;
  filepath: string;
  line: number;
  bfl_summary: string;
  status: "OPEN" | "IN_PROGRESS" | "RESOLVED";
  priority?: "HIGHEST" | "HIGH" | "MEDIUM" | "LOW";
  labels?: string[];
  assignee: string;
  created_at: string;
  updated_at?: string | null;
  external_url: string;
  remote_issue_url?: string | null;
  sync_mode?: "LIVE_API" | "LOCAL_TRACKER";
  auto_generated: boolean;
  payload_preview: string;
  comments?: TicketComment[];
}

export interface TestConnectionResponse {
  provider: "JIRA" | "GITHUB_ISSUES";
  ok: boolean;
  mode: "LIVE_API" | "PUBLIC_READONLY" | "LOCAL_TRACKER" | "NOT_CONFIGURED" | "ERROR";
  http_status: number;
  latency_ms: number;
  message: string;
  details: Record<string, any>;
}

export interface IntegrationHubStateResponse {
  config: BugTrackerConnectorConfig;
  tickets: IssueTicket[];
}

export type AppThemeId =
  | "alastor-infernal"
  | "olympian-light"
  | "athena-parchment"
  | "hyperborean-light"
  | "hecate-arcane"
  | "stygian-abyss";

export type BackdropIntensity = "VIVID" | "SUBTLE" | "MINIMAL";

// ---------------------------------------------------------------------------
// 6. RACI Governance & Accountability Matrix Interfaces
// ---------------------------------------------------------------------------
export type RaciValue = "R" | "A" | "C" | "I" | "-";

export interface RaciRoleDefinition {
  role_id: string;
  title: string;
  short_code: string;
  department: string;
  plain_description: string;
  default_owner: string;
}

export interface RaciActivityRow {
  activity_id: string;
  phase: string;
  activity_name: string;
  plain_explanation: string;
  deliverable: string;
  assignments: Record<string, RaciValue>;
  validation_status:
    | "VALID"
    | "WARNING_MULTIPLE_A"
    | "ERROR_MISSING_A"
    | "ERROR_MISSING_R";
  validation_message: string;
}

export interface FindingRaciAssignment {
  finding_id: string;
  finding_title: string;
  severity: string;
  engine: string;
  filepath: string;
  line: number;
  responsible_role: string;
  accountable_role: string;
  consulted_role: string;
  informed_role: string;
  assigned_person: string;
  sla_status: string;
  target_sprint: string;
  plain_action_required: string;
}

export interface RaciGovernanceResponse {
  roles: RaciRoleDefinition[];
  activities: RaciActivityRow[];
  finding_assignments: FindingRaciAssignment[];
  governance_health_score: number;
  valid_rows_count: number;
  total_rows_count: number;
  validation_warnings: string[];
}

// ---------------------------------------------------------------------------
// 7. SAST ++++++ ASPM Suite (Live SBOM, Attack Surface & Roadmap)
// ---------------------------------------------------------------------------
export interface SbomComponentItem {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  manifest_path: string;
  line_number: number;
  is_pinned: boolean;
  license_type: string;
  risk_status:
    | "VERIFIED_PINNED"
    | "FLOATING_VERSION"
    | "UNPINNED_IMPORT"
    | "REVIEW_REQUIRED";
  plain_english_role: string;
}

export interface AttackSurfaceEndpoint {
  id: string;
  method: string;
  route_path: string;
  handler_name: string;
  filepath: string;
  line_number: number;
  auth_posture: string;
  linked_findings_count: number;
  exposure_level: "HIGH_EXPOSURE" | "INTERNAL_API" | "STANDARD";
  plain_english_purpose: string;
}

export interface RemediationRoadmapItem {
  finding_id: string;
  title: string;
  severity: string;
  engine: string;
  phase: "PHASE_1_IMMEDIATE" | "PHASE_2_SPRINT" | "PHASE_3_HARDENING";
  phase_label: string;
  effort_estimate: string;
  risk_reduction_points: number;
  responsible_role: string;
  plain_english_fix: string;
  filepath: string;
  line: number;
}

export interface StrideThreatItem {
  id: string;
  stride_category:
    | "SPOOFING"
    | "TAMPERING"
    | "REPUDIATION"
    | "INFORMATION_DISCLOSURE"
    | "DENIAL_OF_SERVICE"
    | "ELEVATION_OF_PRIVILEGE";
  stride_letter: string;
  title: string;
  status: "MITIGATED" | "ACTION_REQUIRED" | "MONITORED";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  affected_components: string[];
  threat_scenario: string;
  mitigation_control: string;
  linked_finding_ids: string[];
}

export interface PipelineSecurityCheck {
  id: string;
  category: string;
  title: string;
  status: "PASS" | "WARNING" | "FAIL";
  evidence_path: string;
  details: string;
  remediation: string;
}

export interface SastPlusSuiteResponse {
  project_path: string;
  total_sbom_components: number;
  pinned_components_count: number;
  unpinned_components_count: number;
  sbom_components: SbomComponentItem[];
  cyclonedx_json: Record<string, any>;
  discovered_endpoints_count: number;
  endpoints: AttackSurfaceEndpoint[];
  roadmap_items: RemediationRoadmapItem[];
  stride_threats?: StrideThreatItem[];
  pipeline_checks?: PipelineSecurityCheck[];
  reachable_findings_count?: number;
  dormant_findings_count?: number;
  executive_plain_summary: string;
  overall_maturity_grade: string;
  maturity_score: number;
}

// ---------------------------------------------------------------------------
// 8. Continuous Track Changes Mode & Saved Scan History Interfaces
// ---------------------------------------------------------------------------
export interface ScanSnapshotRecord {
  scan_id: string;
  scan_number: number;
  scanned_at: string;
  project_path: string;
  application_name: string;
  files_scanned: number;
  nodes_created: number;
  edges_created: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  new_count: number;
  fixed_count: number;
  unchanged_count: number;
  summary_note: string;
}

export interface TrackChangesSummary {
  application_name: string;
  project_path: string;
  has_been_scanned: boolean;
  scan_count: number;
  last_scanned_at?: string | null;
  previous_scanned_at?: string | null;
  comparison_mode: "BASELINE_FIRST_SCAN" | "DELTA_VS_PREVIOUS_SCAN";
  total_active_findings: number;
  new_count: number;
  fixed_count: number;
  unchanged_count: number;
  reopened_count: number;
  new_findings: Finding[];
  fixed_findings: Finding[];
  unchanged_findings: Finding[];
  scan_history: ScanSnapshotRecord[];
  status_headline: string;
}

