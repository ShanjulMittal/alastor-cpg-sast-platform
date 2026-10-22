"""
Strict Pydantic v2 Data Contracts for Deterministic Code Property Graph (CPG) & SAST.
"""
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field

NodeLabel = Literal[
    "File", "Directory", "AppElement", "Module", "Class", "Function", "Parameter", 
    "Variable", "Assignment", "Call", "ControlBlock", 
    "LoopBlock", "Return", "Literal", "Entry", "Exit"
]

EdgeType = Literal[
    "AST_CHILD",        # Syntactic hierarchy
    "CFG_NEXT",         # Sequential execution path
    "CFG_TRUE",         # Conditional true branch
    "CFG_FALSE",        # Conditional false branch
    "CFG_LOOP_BACK",    # Loop back-edge (critical for infinite loop math)
    "CFG_BREAK",        # Loop termination edge
    "DFG_FLOWS_TO",     # Variable def-use and assignment propagation
    "CALLS",            # Function/Method invocation across modules
    "DEFINES",          # Scope definition
    "IMPORTS",          # Cross-file dependency
    "CONTAINS",         # Directory -> File / Directory hierarchy
    "DECLARES",         # File -> AppElement declaration
    "CONFIGURES"        # Config/Manifest -> Component relationship
]


class CPGNode(BaseModel):
    id: str                             # Deterministic SHA256(filepath + node_type + start_byte + end_byte)
    label: NodeLabel
    ast_type: str                       # Raw tree-sitter type (e.g., 'function_definition', 'call')
    name: str                           # Identifier name or operator symbol
    code: str                           # Raw source text (truncated to 500 chars)
    filepath: str                       # Relative path from project root
    start_line: int                     # 1-indexed (tree-sitter row + 1)
    end_line: int                       # 1-indexed
    start_col: int                      # 0-indexed column
    end_col: int                        # 0-indexed column
    scope_id: str                       # Enclosing Function or Module ID
    is_source: bool = False             # True if matches known untrusted input signature
    is_sink: bool = False               # True if matches dangerous execution sink
    is_sanitizer: bool = False          # True if matches known validation/escaping function


class CPGEdge(BaseModel):
    id: str                             # SHA256(source_id + target_id + edge_type)
    source_id: str
    target_id: str
    edge_type: EdgeType
    var_name: Optional[str] = None      # Populated for DFG_FLOWS_TO edges


class BestFixLocation(BaseModel):
    node_id: str = ""
    filepath: str = ""
    line: int = 1
    column: int = 0
    code_snippet: str = ""
    explanation: str = ""
    recommended_fix: str = ""
    before_code_block: str = ""
    after_code_block: str = ""


class Finding(BaseModel):
    id: str
    rule_id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    title: str
    description: str = ""
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    source_site: Optional[str] = None
    reference_url: Optional[str] = None
    path_nodes: List[Dict[str, Any]] = Field(default_factory=list)
    path_edges: List[Dict[str, Any]] = Field(default_factory=list)
    scan_engine: Literal["SAST", "SCA", "IaC"] = "SAST"
    language: str = "Python"
    best_fix_location: Optional[BestFixLocation] = None
    triage_status: Literal[
        "TO_VERIFY",
        "CONFIRMED",
        "NOT_EXPLOITABLE",
        "PROPOSED_NOT_EXPLOITABLE",
        "RESOLVED"
    ] = "TO_VERIFY"
    triage_reason: Optional[str] = None
    triage_comment: Optional[str] = None
    triaged_by: Optional[str] = None
    triaged_at: Optional[str] = None
    first_seen_at: Optional[str] = None
    age_days: int = 0
    sla_status: Literal["WITHIN_SLA", "APPROACHING_SLA", "SLA_BREACHED"] = "WITHIN_SLA"
    linked_ticket_id: Optional[str] = None
    linked_ticket_url: Optional[str] = None
    # SAST++++++ Non-Coder / Management Translation & RACI Ownership Fields
    plain_english_summary: str = ""
    non_coder_analogy: str = ""
    business_impact: str = ""
    management_action_steps: List[str] = Field(default_factory=list)
    effort_estimate: str = ""
    financial_risk_tier: str = ""
    raci_responsible: str = ""
    raci_accountable: str = ""
    raci_consulted: str = ""
    raci_informed: str = ""
    # Continuous Track Changes & Scan Delta Fields
    change_status: Literal["NEW", "UNCHANGED", "FIXED", "REOPENED"] = "UNCHANGED"
    fixed_at: Optional[str] = None
    scan_number_introduced: int = 1
    # Enterprise Reachability, EPSS v4 & CISA KEV Exploitability Intelligence
    reachability_status: Literal["REACHABLE", "CONDITIONALLY_REACHABLE", "UNREACHABLE_DORMANT"] = "REACHABLE"
    reachability_reason: str = ""
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    cisa_kev_listed: bool = False
    exploit_maturity: Literal[
        "ACTIVE_IN_THE_WILD",
        "PROOF_OF_CONCEPT",
        "SUPPLY_CHAIN_EXPOSURE",
        "CONFIGURATION_EXPOSURE",
        "DORMANT_CODE_PATH"
    ] = "PROOF_OF_CONCEPT"
    # Secret Keys & Credentials Detection Metadata
    is_secret_finding: bool = False
    secret_key_name: Optional[str] = None
    secret_value_masked: Optional[str] = None
    secret_value_raw: Optional[str] = None
    secret_type: Optional[str] = None
    secret_entropy: Optional[float] = None



class ExtractedAdvisory(BaseModel):
    id: str
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    title: str
    summary: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "HIGH"
    cvss_score: Optional[float] = None
    source_site: str
    reference_url: str
    affected_packages: List[str] = Field(default_factory=list)
    code_patterns: List[str] = Field(default_factory=list)
    remediation: str = ""
    matched_in_code: bool = False
    match_count: int = 0
    matched_files: List[str] = Field(default_factory=list)


class SiteExtractRequest(BaseModel):
    sources: List[str] = Field(default_factory=lambda: ["osv", "nvd", "cisa_owasp"])
    custom_urls: List[str] = Field(default_factory=list)
    search_query: Optional[str] = None
    auto_scan_code: bool = True


class SiteExtractResponse(BaseModel):
    extracted_count: int
    matched_in_code_count: int
    code_findings_created: int
    advisories: List[ExtractedAdvisory]
    code_findings: List[Finding]
    sources_queried: List[str]



class ScanRequest(BaseModel):
    target_path: str


class DiscoveredElement(BaseModel):
    name: str
    element_type: str
    signature: str = ""
    line_number: int = 1
    details: str = ""


class FilePurposeInfo(BaseModel):
    filepath: str
    filename: str
    extension: str
    category: str
    purpose: str
    language: str
    line_count: int
    size_bytes: int
    sha256: str
    elements: List[DiscoveredElement] = Field(default_factory=list)
    is_cpg_supported: bool = False
    security_tags: List[str] = Field(default_factory=list)


class DirectoryTreeNode(BaseModel):
    name: str
    path: str
    purpose: str = ""
    files: List[FilePurposeInfo] = Field(default_factory=list)
    subdirectories: List["DirectoryTreeNode"] = Field(default_factory=list)


class AppTreeSummary(BaseModel):
    root_path: str
    total_files: int
    total_directories: int
    total_lines: int
    category_counts: Dict[str, int]
    detected_tech_stack: List[str]
    tree: DirectoryTreeNode
    flat_files: List[FilePurposeInfo]


class ScanResponse(BaseModel):
    project_path: str
    files_scanned: int
    nodes_created: int
    edges_created: int
    status: str
    categories: Optional[Dict[str, int]] = None
    tech_stack: Optional[List[str]] = None
    total_app_files: Optional[int] = None


class MetricsResponse(BaseModel):
    total_nodes: int
    total_edges: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_app_files: int = 0
    categories: Dict[str, int] = Field(default_factory=dict)
    tech_stack: List[str] = Field(default_factory=list)


class ScanProgress(BaseModel):
    is_scanning: bool = False
    phase: str = "IDLE"
    current_pass: str = ""
    current_file: str = ""
    files_done: int = 0
    total_files: int = 0
    percent: int = 0
    message: str = "Ready"
    error: Optional[str] = None


class FsEntry(BaseModel):
    name: str
    path: str
    is_dir: bool
    size_bytes: int = 0
    extension: str = ""
    is_code: bool = False


class FsBrowseResponse(BaseModel):
    current_path: str
    parent_path: Optional[str] = None
    quick_roots: List[Dict[str, str]] = Field(default_factory=list)
    directories: List[FsEntry] = Field(default_factory=list)
    files: List[FsEntry] = Field(default_factory=list)


class NativeDialogRequest(BaseModel):
    mode: Literal["folder", "file"] = "folder"
    initial_dir: Optional[str] = None


class NativeDialogResponse(BaseModel):
    selected_path: str = ""
    cancelled: bool = False
    error: Optional[str] = None


class UploadTargetFile(BaseModel):
    filepath: str
    content: str


class UploadTargetRequest(BaseModel):
    target_name: str = "uploaded_workspace"
    files: List[UploadTargetFile] = Field(default_factory=list)


class UploadTargetResponse(BaseModel):
    target_path: str
    files_saved: int


# ---------------------------------------------------------------------------
# 1. Project Management & Automation Models
# ---------------------------------------------------------------------------
class ProjectAutomationConfig(BaseModel):
    auto_scan_on_push: bool = False
    auto_scan_on_pr: bool = False
    auto_scan_on_schedule: bool = False
    schedule_cron: str = "0 2 * * *"
    target_branches: List[str] = Field(default_factory=lambda: ["main", "master", "develop"])
    webhook_url: str = ""
    webhook_secret_masked: str = ""
    last_triggered_at: Optional[str] = None
    last_trigger_event: Optional[str] = None


class ProjectConfig(BaseModel):
    id: str
    name: str
    description: str = ""
    scm_provider: Literal["GITHUB", "GITLAB", "BITBUCKET", "LOCAL"] = "LOCAL"
    repo_url: str = ""
    branch: str = "main"
    target_path: str
    preset_id: str = "preset-optimized"
    override_global_settings: bool = False
    custom_engines: List[str] = Field(default_factory=lambda: ["SAST", "SCA", "IaC"])
    automation: ProjectAutomationConfig = Field(default_factory=ProjectAutomationConfig)
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SECURE"] = "SECURE"
    risk_score: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_findings: int = 0
    sast_count: int = 0
    sca_count: int = 0
    iac_count: int = 0
    languages: List[str] = Field(default_factory=list)
    last_scan_at: Optional[str] = None
    previous_scan_at: Optional[str] = None
    scan_count: int = 0
    has_cached_scan: bool = False
    fixed_since_last_scan: int = 0
    new_since_last_scan: int = 0
    unchanged_since_last_scan: int = 0
    files_scanned_count: int = 0
    cpg_nodes_count: int = 0
    cpg_edges_count: int = 0
    is_active: bool = False
    account_id: str = "acct-enterprise-hq"
    account_name: str = "Enterprise Security HQ"


class CreateProjectRequest(BaseModel):
    name: str
    description: str = ""
    scm_provider: Literal["GITHUB", "GITLAB", "BITBUCKET", "LOCAL"] = "GITHUB"
    repo_url: str = ""
    branch: str = "main"
    target_path: str = ""
    preset_id: str = "preset-optimized"
    auto_scan_on_push: bool = True
    auto_scan_on_pr: bool = True


class UpdateProjectAutomationRequest(BaseModel):
    auto_scan_on_push: Optional[bool] = None
    auto_scan_on_pr: Optional[bool] = None
    auto_scan_on_schedule: Optional[bool] = None
    target_branches: Optional[List[str]] = None
    preset_id: Optional[str] = None
    override_global_settings: Optional[bool] = None
    custom_engines: Optional[List[str]] = None


class WebhookTriggerRequest(BaseModel):
    event_type: Literal["push", "pull_request", "manual"] = "push"
    branch: str = "main"
    commit_sha: str = "8f4a2c1"
    actor: str = "github-actions[bot]"


# ---------------------------------------------------------------------------
# 2. Deep Dive & Analysis Interface Models
# ---------------------------------------------------------------------------
class AgingBucket(BaseModel):
    bucket: str
    count: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ComplianceControlItem(BaseModel):
    control_id: str
    title: str
    category: str
    status: Literal["PASS", "FAIL", "WARNING"]
    findings_count: int = 0
    mapped_cwes: List[str] = Field(default_factory=list)
    description: str = ""


class ComplianceStandardReport(BaseModel):
    standard_id: str
    name: str
    version: str
    compliance_score: int
    passed_controls: int
    failed_controls: int
    total_controls: int
    controls: List[ComplianceControlItem] = Field(default_factory=list)


class EngineSummaryItem(BaseModel):
    engine: Literal["SAST", "SCA", "IaC"]
    label: str
    description: str
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    status: str = "ACTIVE"
    rules_executed: int = 0


class DeepDiveAnalyticsResponse(BaseModel):
    project_id: str
    project_name: str
    risk_level: str
    risk_score: int
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    language_breakdown: Dict[str, int] = Field(default_factory=dict)
    engine_breakdown: List[EngineSummaryItem] = Field(default_factory=list)
    aging_summary: List[AgingBucket] = Field(default_factory=list)
    mean_age_days: float = 0.0
    sla_breached_count: int = 0
    suppressed_count: int = 0
    confirmed_count: int = 0
    compliance_reports: List[ComplianceStandardReport] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 3. Vulnerability Remediation & Triage Models
# ---------------------------------------------------------------------------
class TriageUpdateRequest(BaseModel):
    status: Literal[
        "TO_VERIFY",
        "CONFIRMED",
        "NOT_EXPLOITABLE",
        "PROPOSED_NOT_EXPLOITABLE",
        "RESOLVED"
    ]
    reason: Optional[str] = None
    comment: Optional[str] = None
    author: str = "Security Lead"


# ---------------------------------------------------------------------------
# 4. Settings & Customization Engine Models
# ---------------------------------------------------------------------------
class ScanPreset(BaseModel):
    id: str
    name: str
    badge: str
    description: str
    is_default: bool = False
    enabled_engines: List[str] = Field(default_factory=lambda: ["SAST", "SCA", "IaC"])
    enabled_rule_ids: List[str] = Field(default_factory=list)


class SecurityQueryRule(BaseModel):
    id: str
    name: str
    engine: Literal["SAST", "SCA", "IaC"] = "SAST"
    language: str = "Python / JS / TS"
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "HIGH"
    cwe_id: str = "CWE-78"
    owasp_category: str = "A03:2021 - Injection"
    cvss_score: float = 7.5
    description: str = ""
    remediation: str = ""
    cypher: str = ""
    enabled: bool = True
    is_custom: bool = False


class CustomSanitizerRule(BaseModel):
    id: str
    function_name: str
    language: str = "All"
    target_cwe: str = "ALL"
    description: str = ""
    active: bool = True


class PlatformSettingsResponse(BaseModel):
    active_scope: Literal["GLOBAL", "PROJECT"] = "GLOBAL"
    active_preset_id: str = "preset-optimized"
    enabled_engines: List[str] = Field(default_factory=lambda: ["SAST", "SCA", "IaC"])
    max_dfg_depth: int = 25
    auto_suppress_low: bool = False
    fail_on_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "NONE"] = "CRITICAL"
    sla_days: Dict[str, int] = Field(default_factory=lambda: {"CRITICAL": 7, "HIGH": 14, "MEDIUM": 30, "LOW": 90})
    excluded_paths: List[str] = Field(default_factory=lambda: ["node_modules", ".git", ".next", "__pycache__", ".venv"])
    presets: List[ScanPreset] = Field(default_factory=list)
    queries: List[SecurityQueryRule] = Field(default_factory=list)
    custom_sanitizers: List[CustomSanitizerRule] = Field(default_factory=list)
    project_overrides: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


class UpdatePlatformSettingsRequest(BaseModel):
    scope: Literal["GLOBAL", "PROJECT"] = "GLOBAL"
    project_id: Optional[str] = None
    active_preset_id: Optional[str] = None
    enabled_engines: Optional[List[str]] = None
    max_dfg_depth: Optional[int] = None
    auto_suppress_low: Optional[bool] = None
    fail_on_severity: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "NONE"]] = None
    sla_days: Optional[Dict[str, int]] = None
    excluded_paths: Optional[List[str]] = None


class UpsertQueryRuleRequest(BaseModel):
    id: Optional[str] = None
    name: str
    engine: Literal["SAST", "SCA", "IaC"] = "SAST"
    language: str = "Python / JS / TS"
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "HIGH"
    cwe_id: str = "CWE-78"
    owasp_category: str = "A03:2021 - Injection"
    cvss_score: float = 7.5
    description: str = ""
    remediation: str = ""
    cypher: str = ""
    enabled: bool = True


class AddCustomSanitizerRequest(BaseModel):
    function_name: str
    language: str = "All"
    target_cwe: str = "ALL"
    description: str = "Custom codebase sanitizer function"


class CreateTestProfileRequest(BaseModel):
    name: str
    badge: str = "CUSTOM PROFILE"
    description: str = "Custom security test profile"
    enabled_engines: List[str] = Field(default_factory=lambda: ["SAST", "SCA", "IaC"])
    enabled_rule_ids: List[str] = Field(default_factory=list)


class BatchRuleSelectionRequest(BaseModel):
    enabled_rule_ids: List[str] = Field(default_factory=list)
    preset_id: Optional[str] = None


# ---------------------------------------------------------------------------
# 9. Enterprise User Profiling, RBAC & Multi-Tenant Account Separation
# ---------------------------------------------------------------------------
class TenantAccount(BaseModel):
    id: str
    name: str
    division: str = "Enterprise Security"
    compliance_tier: str = "SOC2 / ISO-27001 / PCI-DSS"
    owner_email: str = "secops@enterprise.local"
    isolation_mode: Literal["STRICT_TENANT", "SHARED_GOVERNANCE"] = "STRICT_TENANT"
    project_count: int = 0


class UserProfileRecord(BaseModel):
    id: str
    name: str
    email: str
    role: Literal["CISO_EXEC", "APPSEC_ARCHITECT", "SECURITY_AUDITOR", "DEVSECOPS_ENG", "DEVELOPER"] = "APPSEC_ARCHITECT"
    title: str
    account_id: str = "acct-enterprise-hq"
    account_name: str = "Enterprise Security HQ"
    avatar_color: str = "cyan"
    permissions: List[str] = Field(default_factory=list)
    is_active: bool = False


class CreateAccountRequest(BaseModel):
    name: str
    division: str = "Core Engineering"
    compliance_tier: str = "SOC2 Type II"
    owner_email: str = "lead@enterprise.local"
    isolation_mode: Literal["STRICT_TENANT", "SHARED_GOVERNANCE"] = "STRICT_TENANT"


class CreateUserProfileRequest(BaseModel):
    name: str
    email: str
    role: Literal["CISO_EXEC", "APPSEC_ARCHITECT", "SECURITY_AUDITOR", "DEVSECOPS_ENG", "DEVELOPER"] = "SECURITY_AUDITOR"
    title: str = "Security Engineer"
    account_id: str = "acct-enterprise-hq"


class SwitchUserOrAccountRequest(BaseModel):
    user_id: Optional[str] = None
    account_id: Optional[str] = None
    assign_project_id: Optional[str] = None
    target_account_id: Optional[str] = None


class UserAccountsStateResponse(BaseModel):
    active_account_id: str = "ALL"
    active_user_id: str = "usr-architect"
    accounts: List[TenantAccount] = Field(default_factory=list)
    users: List[UserProfileRecord] = Field(default_factory=list)
    audit_log: List[Dict[str, str]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 5. Integration Hub (Jira / GitHub Issues & Automated Ticket Creation)
# ---------------------------------------------------------------------------
class BugTrackerConnectorConfig(BaseModel):
    jira_enabled: bool = False
    jira_url: str = ""
    jira_project_key: str = "SEC"
    jira_issue_type: str = "Task"
    jira_email: str = ""
    jira_api_token: str = ""
    jira_api_token_masked: str = ""
    jira_connection_status: str = "NOT_CONFIGURED"
    jira_last_tested_at: Optional[str] = None
    github_issues_enabled: bool = False
    github_repo: str = ""
    github_labels: List[str] = Field(default_factory=lambda: ["security", "alastor-cpg", "automated-bfl"])
    github_token: str = ""
    github_token_masked: str = ""
    github_connection_status: str = "NOT_CONFIGURED"
    github_last_tested_at: Optional[str] = None
    auto_create_tickets: bool = False
    auto_severity_threshold: Literal["CRITICAL", "HIGH", "MEDIUM", "ALL"] = "HIGH"
    auto_trigger_on: Literal["SCAN_COMPLETE", "ON_CONFIRMED", "MANUAL"] = "MANUAL"
    default_provider: Literal["JIRA", "GITHUB_ISSUES", "BOTH"] = "JIRA"
    bidirectional_triage_sync: bool = True


class TicketComment(BaseModel):
    id: str
    author: str = "Security Auditor"
    body: str
    created_at: str


class IssueTicket(BaseModel):
    id: str
    ticket_key: str
    provider: Literal["JIRA", "GITHUB_ISSUES"]
    finding_id: str
    finding_title: str
    severity: str
    cwe_id: Optional[str] = None
    filepath: str
    line: int
    bfl_summary: str = ""
    status: Literal["OPEN", "IN_PROGRESS", "RESOLVED"] = "OPEN"
    priority: Literal["HIGHEST", "HIGH", "MEDIUM", "LOW"] = "HIGH"
    labels: List[str] = Field(default_factory=list)
    assignee: str = "Unassigned"
    created_at: str
    updated_at: Optional[str] = None
    external_url: str
    remote_issue_url: Optional[str] = None
    sync_mode: Literal["LIVE_API", "LOCAL_TRACKER"] = "LOCAL_TRACKER"
    auto_generated: bool = False
    payload_preview: str = ""
    comments: List[TicketComment] = Field(default_factory=list)


class CreateTicketRequest(BaseModel):
    finding_id: str
    provider: Literal["JIRA", "GITHUB_ISSUES"] = "JIRA"
    assignee: Optional[str] = "Unassigned"
    priority: Optional[Literal["HIGHEST", "HIGH", "MEDIUM", "LOW"]] = None
    labels: Optional[List[str]] = None
    custom_notes: Optional[str] = None


class UpdateTicketRequest(BaseModel):
    status: Optional[Literal["OPEN", "IN_PROGRESS", "RESOLVED"]] = None
    assignee: Optional[str] = None
    priority: Optional[Literal["HIGHEST", "HIGH", "MEDIUM", "LOW"]] = None
    comment: Optional[str] = None
    comment_author: str = "Security Auditor"


class TestConnectionRequest(BaseModel):
    provider: Literal["JIRA", "GITHUB_ISSUES"]
    jira_url: Optional[str] = None
    jira_project_key: Optional[str] = None
    jira_email: Optional[str] = None
    jira_api_token: Optional[str] = None
    github_repo: Optional[str] = None
    github_token: Optional[str] = None


class TestConnectionResponse(BaseModel):
    provider: Literal["JIRA", "GITHUB_ISSUES"]
    ok: bool
    mode: Literal["LIVE_API", "PUBLIC_READONLY", "LOCAL_TRACKER", "NOT_CONFIGURED", "ERROR"]
    http_status: int
    latency_ms: int
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)


class IntegrationHubStateResponse(BaseModel):
    config: BugTrackerConnectorConfig
    tickets: List[IssueTicket] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 6. RACI Governance & Accountability Matrix Models
# ---------------------------------------------------------------------------
RaciValue = Literal["R", "A", "C", "I", "-"]


class RaciRoleDefinition(BaseModel):
    role_id: str
    title: str
    short_code: str
    department: str
    plain_description: str
    default_owner: str


class RaciActivityRow(BaseModel):
    activity_id: str
    phase: str
    activity_name: str
    plain_explanation: str
    deliverable: str
    assignments: Dict[str, RaciValue] = Field(default_factory=dict)
    validation_status: Literal["VALID", "WARNING_MULTIPLE_A", "ERROR_MISSING_A", "ERROR_MISSING_R"] = "VALID"
    validation_message: str = "Valid PMI/COBIT RACI row (1 Accountable, >=1 Responsible)"


class FindingRaciAssignment(BaseModel):
    finding_id: str
    finding_title: str
    severity: str
    engine: str
    filepath: str
    line: int
    responsible_role: str
    accountable_role: str
    consulted_role: str
    informed_role: str
    assigned_person: str
    sla_status: str
    target_sprint: str
    plain_action_required: str


class RaciGovernanceResponse(BaseModel):
    roles: List[RaciRoleDefinition] = Field(default_factory=list)
    activities: List[RaciActivityRow] = Field(default_factory=list)
    finding_assignments: List[FindingRaciAssignment] = Field(default_factory=list)
    governance_health_score: int = 100
    valid_rows_count: int = 0
    total_rows_count: int = 0
    validation_warnings: List[str] = Field(default_factory=list)


class UpdateRaciCellRequest(BaseModel):
    activity_id: str
    role_id: str
    value: RaciValue


class UpdateFindingRaciOwnerRequest(BaseModel):
    finding_id: str
    assigned_person: Optional[str] = None
    target_sprint: Optional[str] = None
    responsible_role: Optional[str] = None
    accountable_role: Optional[str] = None


# ---------------------------------------------------------------------------
# 7. SAST ++++++ ASPM Suite (Live SBOM, API Attack Surface & Roadmap)
# ---------------------------------------------------------------------------
class SbomComponentItem(BaseModel):
    id: str
    name: str
    version: str
    ecosystem: str
    manifest_path: str
    line_number: int = 1
    is_pinned: bool = False
    license_type: str = "OSI-Approved / Standard"
    risk_status: Literal["VERIFIED_PINNED", "FLOATING_VERSION", "UNPINNED_IMPORT", "REVIEW_REQUIRED"] = "VERIFIED_PINNED"
    plain_english_role: str = ""


class AttackSurfaceEndpoint(BaseModel):
    id: str
    method: str
    route_path: str
    handler_name: str
    filepath: str
    line_number: int = 1
    auth_posture: str = "Local / Unauthenticated Endpoint"
    linked_findings_count: int = 0
    exposure_level: Literal["HIGH_EXPOSURE", "INTERNAL_API", "STANDARD"] = "STANDARD"
    plain_english_purpose: str = ""


class RemediationRoadmapItem(BaseModel):
    finding_id: str
    title: str
    severity: str
    engine: str
    phase: Literal["PHASE_1_IMMEDIATE", "PHASE_2_SPRINT", "PHASE_3_HARDENING"]
    phase_label: str
    effort_estimate: str
    risk_reduction_points: int
    responsible_role: str
    plain_english_fix: str
    filepath: str
    line: int


class StrideThreatItem(BaseModel):
    id: str
    stride_category: Literal[
        "SPOOFING",
        "TAMPERING",
        "REPUDIATION",
        "INFORMATION_DISCLOSURE",
        "DENIAL_OF_SERVICE",
        "ELEVATION_OF_PRIVILEGE"
    ]
    stride_letter: str = "T"
    title: str
    status: Literal["MITIGATED", "ACTION_REQUIRED", "MONITORED"] = "MONITORED"
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    affected_components: List[str] = Field(default_factory=list)
    threat_scenario: str = ""
    mitigation_control: str = ""
    linked_finding_ids: List[str] = Field(default_factory=list)
    primary_filepath: str = ""
    primary_line: int = 1
    code_snippet: str = ""
    what_passed: List[str] = Field(default_factory=list)
    what_failed: List[str] = Field(default_factory=list)
    why_issue_or_not: str = ""
    risk_impact: str = ""
    likelihood: str = "LOW (Mitigated)"
    compliance_mapping: str = "OWASP Top 10 / MITRE CWE"
    corrective_actions: List[str] = Field(default_factory=list)


class PipelineSecurityCheck(BaseModel):
    id: str
    category: str
    title: str
    status: Literal["PASS", "WARNING", "FAIL"] = "PASS"
    evidence_path: str = ""
    details: str = ""
    remediation: str = ""
    primary_filepath: str = ""
    primary_line: int = 1
    what_passed: List[str] = Field(default_factory=list)
    what_failed: List[str] = Field(default_factory=list)
    why_issue_or_not: str = ""
    risk_impact: str = ""
    corrective_actions: List[str] = Field(default_factory=list)


class SastPlusSuiteResponse(BaseModel):
    project_path: str
    total_sbom_components: int = 0
    pinned_components_count: int = 0
    unpinned_components_count: int = 0
    sbom_components: List[SbomComponentItem] = Field(default_factory=list)
    cyclonedx_json: Dict[str, Any] = Field(default_factory=dict)
    discovered_endpoints_count: int = 0
    endpoints: List[AttackSurfaceEndpoint] = Field(default_factory=list)
    roadmap_items: List[RemediationRoadmapItem] = Field(default_factory=list)
    stride_threats: List[StrideThreatItem] = Field(default_factory=list)
    pipeline_checks: List[PipelineSecurityCheck] = Field(default_factory=list)
    reachable_findings_count: int = 0
    dormant_findings_count: int = 0
    executive_plain_summary: str = ""
    overall_maturity_grade: str = "B+"
    maturity_score: int = 85


# ---------------------------------------------------------------------------
# 8. Continuous Track Changes Mode & Saved Scan History Models
# ---------------------------------------------------------------------------
class ScanSnapshotRecord(BaseModel):
    scan_id: str
    scan_number: int
    scanned_at: str
    project_path: str
    application_name: str
    files_scanned: int = 0
    nodes_created: int = 0
    edges_created: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    new_count: int = 0
    fixed_count: int = 0
    unchanged_count: int = 0
    summary_note: str = ""


class TrackChangesSummary(BaseModel):
    application_name: str
    project_path: str
    has_been_scanned: bool = False
    scan_count: int = 0
    last_scanned_at: Optional[str] = None
    previous_scanned_at: Optional[str] = None
    comparison_mode: Literal["BASELINE_FIRST_SCAN", "DELTA_VS_PREVIOUS_SCAN"] = "BASELINE_FIRST_SCAN"
    total_active_findings: int = 0
    new_count: int = 0
    fixed_count: int = 0
    unchanged_count: int = 0
    reopened_count: int = 0
    new_findings: List[Finding] = Field(default_factory=list)
    fixed_findings: List[Finding] = Field(default_factory=list)
    unchanged_findings: List[Finding] = Field(default_factory=list)
    scan_history: List[ScanSnapshotRecord] = Field(default_factory=list)
    status_headline: str = ""




