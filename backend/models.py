"""
Strict Pydantic v2 Data Contracts for Deterministic Code Property Graph (CPG) & SAST.
"""
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, field_validator

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


_CredentialValidationStatus = Literal[
    "VERIFIED_ACTIVE",
    "REVOKED_OR_INVALID",
    "OFFLINE_STRUCTURALLY_VALID",
    "TEST_OR_PLACEHOLDER",
    "VERIFICATION_ERROR",
]
SecretValidationStatus = _CredentialValidationStatus
_FindingLocationOrigin = Literal["WORKING_TREE", "GIT_HISTORY"]
_DEFAULT_ORIGIN: _FindingLocationOrigin = "WORKING_TREE"


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

    @field_validator("path_nodes", "path_edges", mode="before")
    @classmethod
    def _coerce_graph_items_to_dicts(cls, value: Any) -> Any:
        if not isinstance(value, list):
            return value
        return [item.model_dump() if isinstance(item, BaseModel) else item for item in value]
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
    secret_validation_status: Optional[SecretValidationStatus] = None
    secret_detector_id: Optional[str] = None
    secret_verified_identity: Optional[str] = None
    secret_validation_message: Optional[str] = None
    secret_verified_at: Optional[str] = None
    secret_source: Optional[_FindingLocationOrigin] = _DEFAULT_ORIGIN
    secret_commit_sha: Optional[str] = None
    secret_commit_author: Optional[str] = None



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
    branch: Optional[str] = None
    repo_visibility: Literal["AUTO", "PUBLIC", "PRIVATE"] = "AUTO"
    auth_token: Optional[str] = None
    auth_username: Optional[str] = None
    save_token: bool = False


class GitHubRepoVerifyRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = None
    auth_token: Optional[str] = None
    auth_username: Optional[str] = None


class GitHubRepoVerifyResponse(BaseModel):
    valid_url: bool = False
    provider: Literal["GITHUB", "GITLAB", "BITBUCKET", "RAW_FILE", "OTHER"] = "GITHUB"
    owner: str = ""
    repo: str = ""
    full_name: str = ""
    normalized_url: str = ""
    accessible: bool = False
    is_private: Optional[bool] = None
    requires_auth: bool = False
    authenticated: bool = False
    has_saved_token: bool = False
    default_branch: str = "main"
    selected_branch: str = "main"
    primary_language: Optional[str] = None
    stars: int = 0
    size_kb: int = 0
    description: str = ""
    message: str = ""


class DiscoveredElement(BaseModel):
    name: str
    element_type: str
    signature: str = ""
    line_number: int = 1
    details: str = ""


class CrossFileEdge(BaseModel):
    source_filepath: str
    target_filepath: str
    edge_type: str = "IMPORTS"
    symbols: List[str] = Field(default_factory=list)
    flow_label: str = "IMPORTS"


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
    imports_files: List[str] = Field(default_factory=list)


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
    cross_file_edges: List[CrossFileEdge] = Field(default_factory=list)


class ScanResponse(BaseModel):
    project_path: str
    files_scanned: int
    nodes_created: int
    edges_created: int
    status: str
    categories: Optional[Dict[str, int]] = None
    tech_stack: Optional[List[str]] = None
    total_app_files: Optional[int] = None
    scm_provider: Optional[str] = None
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    is_private_repo: Optional[bool] = None
    display_name: Optional[str] = None


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
    is_private_repo: bool = False
    has_saved_auth: bool = False
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
    is_private_repo: bool = False
    auth_token: Optional[str] = None
    auth_username: Optional[str] = None
    save_token: bool = False
    run_scan_immediately: bool = False


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


class RemediatePreviewRequest(BaseModel):
    finding_id: str
    filepath: str
    target_line: int = 1
    rule_id: str = ""
    recommended_fix: Optional[str] = None


class RemediatePreviewResponse(BaseModel):
    can_auto_patch: bool
    filepath: str
    expected_sha256: str
    original_content: str
    patched_content: str
    fix_summary: str
    target_line: int


class RemediateApplyRequest(BaseModel):
    finding_id: str
    filepath: str
    rule_id: str = ""
    expected_sha256: str
    patched_content: str


class RemediateApplyResponse(BaseModel):
    status: str
    patch_id: str
    filepath: str
    verified_severed: bool
    remaining_findings_count: int
    fixed_delta_count: int
    message: str


class RemediateUndoRequest(BaseModel):
    patch_id: str


class RemediateUndoResponse(BaseModel):
    status: str
    patch_id: str
    filepath: str
    restored_sha256: str
    active_findings_count: int
    message: str


class BatchRemediateRequest(BaseModel):
    finding_ids: List[str] = Field(default_factory=list)


class BatchRemediateResponse(BaseModel):
    status: str
    applied_count: int
    skipped_count: int
    applied_patch_ids: List[str] = Field(default_factory=list)
    patched_files: List[str] = Field(default_factory=list)
    applied_finding_ids: List[str] = Field(default_factory=list)
    verified_severed_count: int = 0
    remaining_findings_count: int = 0
    unified_diff: str = ""
    message: str = ""


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
    organization_unit: str = "Enterprise Security"
    environment_tier: str = "PRODUCTION"
    compliance_tier: str = "SOC2 Type II / ISO-27001 / PCI-DSS v4.0"
    compliance_mandate: str = "SOC2 Type II / ISO-27001 / PCI-DSS v4.0"
    owner_email: str = "secops@enterprise.local"
    isolation_mode: str = "STRICT"
    project_count: int = 0
    assigned_project_ids: List[str] = Field(default_factory=list)
    allowed_preset_ids: List[str] = Field(
        default_factory=lambda: [
            "preset-optimized",
            "preset-strict-enterprise",
            "preset-secret-hunter",
            "preset-fast-ci",
        ]
    )
    created_at: str = "2026-10-18"


class UserProfileRecord(BaseModel):
    id: str
    name: str
    email: str
    role: str = "APPSEC_ARCHITECT"
    title: str = "Principal AppSec Architect"
    department: str = "Application Security"
    account_id: str = "acct-enterprise-hq"
    account_name: str = "Enterprise Security HQ"
    avatar_color: str = "cyan"
    avatar_badge: str = "SM"
    clearance_level: str = "LEVEL-5 ARCHITECT CLEARANCE"
    permissions: List[str] = Field(default_factory=list)
    default_test_profile_id: str = "preset-optimized"
    can_reveal_secrets: bool = True
    can_edit_rules: bool = True
    can_triage_findings: bool = True
    can_manage_accounts: bool = True
    last_active_at: str = "Active Session"
    is_active: bool = False


class CreateAccountRequest(BaseModel):
    name: str
    division: Optional[str] = None
    organization_unit: Optional[str] = None
    environment_tier: Optional[str] = "PRODUCTION"
    compliance_tier: Optional[str] = None
    compliance_mandate: Optional[str] = None
    owner_email: Optional[str] = "lead@enterprise.local"
    isolation_mode: Optional[str] = "STRICT"
    assigned_project_ids: Optional[List[str]] = None


class CreateUserProfileRequest(BaseModel):
    name: str
    email: str
    role: str = "SECURITY_AUDITOR"
    title: Optional[str] = "Security Engineer"
    department: Optional[str] = "Application Security"
    account_id: str = "acct-enterprise-hq"
    default_test_profile_id: Optional[str] = "preset-optimized"
    can_reveal_secrets: Optional[bool] = None
    can_edit_rules: Optional[bool] = None
    can_triage_findings: Optional[bool] = None
    can_manage_accounts: Optional[bool] = None


class SwitchUserOrAccountRequest(BaseModel):
    user_id: Optional[str] = None
    account_id: Optional[str] = None
    assign_project_id: Optional[str] = None
    target_account_id: Optional[str] = None
    toggle_permission_user_id: Optional[str] = None
    toggle_permission_field: Optional[str] = None


class UserAccountsStateResponse(BaseModel):
    active_account_id: str = "acct-enterprise-hq"
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


class StrideObservationItem(BaseModel):
    id: str
    stride_letter: str = "T"
    verdict: Literal["OK", "ISSUE"] = "OK"
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS"] = "PASS"
    control_domain: str = ""
    title: str = ""
    filepath: str = ""
    line: int = 1
    code_snippet: str = ""
    observation_detail: str = ""
    why_ok_or_issue: str = ""
    risk_impact: str = ""
    corrective_action: str = ""
    cwe_or_standard: str = ""
    linked_finding_id: Optional[str] = None


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
    security_property: str = "Integrity"
    title: str
    status: Literal["MITIGATED", "ACTION_REQUIRED", "MONITORED"] = "MONITORED"
    verdict_label: str = "OK (ALL CONTROLS PASSED)"
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    total_checks_count: int = 0
    ok_count: int = 0
    issue_count: int = 0
    observations_count: int = 0
    ok_summary: str = ""
    issue_summary: str = ""
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
    observations: List[StrideObservationItem] = Field(default_factory=list)


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
    pasta_assessment: Optional["PastaAssessmentResponse"] = None


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


# ---------------------------------------------------------------------------
# 10. Token-Efficient Multi-Provider BYOK Frontier AI Models
# ---------------------------------------------------------------------------
AiProviderType = Literal["gemini", "openai", "anthropic", "openai_compatible"]


class AiTokenTelemetry(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    full_file_tokens_est: int = 0
    tokens_saved: int = 0
    savings_pct: float = 0.0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_full_file_tokens_est: int = 0
    total_tokens_saved: int = 0
    overall_savings_pct: float = 0.0
    cache_hits: int = 0
    total_cache_hits: int = 0
    total_requests: int = 0


class AiConfigUpdateRequest(BaseModel):
    provider: AiProviderType = "gemini"
    model: str = "gemini-2.5-flash"
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    persist_key: bool = True
    clear_api_key: bool = False


class AiPublicConfigResponse(BaseModel):
    provider: AiProviderType = "gemini"
    model: str = "gemini-2.5-flash"
    base_url: str = ""
    has_api_key: bool = False
    masked_api_key: str = ""
    persist_key: bool = True
    available_providers: List[Dict[str, Any]] = Field(default_factory=list)
    token_telemetry: AiTokenTelemetry = Field(default_factory=AiTokenTelemetry)


class AiConnectionTestResponse(BaseModel):
    ok: bool
    provider: str
    model: str
    latency_ms: int
    message: str
    error_code: Optional[str] = None


class AiValidateFindingsRequest(BaseModel):
    finding_ids: List[str] = Field(default_factory=list)
    max_batch: int = 10


class AiFindingVerdict(BaseModel):
    finding_id: str
    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"] = "NEEDS_REVIEW"
    confidence: float = 0.5
    exploitability_summary: str = ""
    recommended_action: str = ""
    suggested_triage_status: Literal["CONFIRMED", "PROPOSED_NOT_EXPLOITABLE", "TO_VERIFY"] = "TO_VERIFY"
    slice_lines_count: int = 0
    cache_hit: bool = False


class AiValidateFindingsResponse(BaseModel):
    ok: bool
    verdicts: List[AiFindingVerdict] = Field(default_factory=list)
    token_telemetry: AiTokenTelemetry = Field(default_factory=AiTokenTelemetry)
    error_code: Optional[str] = None
    user_message: Optional[str] = None


class AiCodeAuditRequest(BaseModel):
    filepath: str
    start_line: int
    end_line: int
    focus_question: Optional[str] = None


class AiCodeAuditObservation(BaseModel):
    line_range: str
    severity: str
    title: str
    explanation: str
    remediation: str


class AiCodeAuditResponse(BaseModel):
    ok: bool
    summary: str = ""
    risk_level: str = "INFO"
    observations: List[AiCodeAuditObservation] = Field(default_factory=list)
    secure_snippet: str = ""
    token_telemetry: AiTokenTelemetry = Field(default_factory=AiTokenTelemetry)
    error_code: Optional[str] = None
    user_message: Optional[str] = None


class AiPatchSynthesisRequest(BaseModel):
    finding_id: str


class AiPatchSynthesisResponse(BaseModel):
    ok: bool
    finding_id: str
    filepath: str = ""
    explanation: str = ""
    before_snippet: str = ""
    after_snippet: str = ""
    patched_full_content: Optional[str] = None
    token_telemetry: AiTokenTelemetry = Field(default_factory=AiTokenTelemetry)
    error_code: Optional[str] = None
    user_message: Optional[str] = None


class AiGraphExplainRequest(BaseModel):
    view_mode: str
    finding_id: Optional[str] = None
    nodes_digest: List[Dict[str, Any]] = Field(default_factory=list)
    edges_digest: List[Dict[str, Any]] = Field(default_factory=list)


class AiGraphExplainResponse(BaseModel):
    ok: bool
    headline: str = ""
    plain_english_story: str = ""
    step_walkthrough: List[str] = Field(default_factory=list)
    security_takeaway: str = ""
    token_telemetry: AiTokenTelemetry = Field(default_factory=AiTokenTelemetry)
    error_code: Optional[str] = None
    user_message: Optional[str] = None


# ---------------------------------------------------------------------------
# 11. Native TruffleHog-Grade Secret Scanner & Live Key Validator Models
# ---------------------------------------------------------------------------
class SecretScannerConfig(BaseModel):
    live_verification_enabled: bool = True
    scan_git_history: bool = True
    max_git_commits: int = 50
    supported_detectors_count: int = 14


class SecretScannerConfigUpdate(BaseModel):
    live_verification_enabled: Optional[bool] = None
    scan_git_history: Optional[bool] = None
    max_git_commits: Optional[int] = None


class SecretVerifyRequest(BaseModel):
    finding_ids: List[str] = Field(default_factory=list)
    force_refresh: bool = False
    allow_live_network: Optional[bool] = None


class SecretInventoryResponse(BaseModel):
    config: SecretScannerConfig = Field(default_factory=SecretScannerConfig)
    total_secrets: int = 0
    verified_active_count: int = 0
    revoked_count: int = 0
    structurally_valid_count: int = 0
    test_placeholder_count: int = 0
    git_history_count: int = 0
    secrets: List[Finding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 12. Multi-Framework API Endpoints & Inter-Procedural CPG Operations Tracer
# ---------------------------------------------------------------------------
ApiOperationCategory = Literal[
    "AUTH_GUARD",
    "INPUT_VALIDATION",
    "DATABASE_READ",
    "DATABASE_WRITE",
    "EXTERNAL_HTTP_OR_AI",
    "FILESYSTEM_IO",
    "OS_COMMAND_EXEC",
    "SECRET_OR_CRYPTO",
]


class ApiOperationItem(BaseModel):
    id: str
    step_index: int
    category: ApiOperationCategory
    operation_verb: str
    target_resource: str
    function_name: str
    call_chain: List[str] = Field(default_factory=list)
    filepath: str
    line_number: int
    code_snippet: str
    is_mutating: bool = False
    risk_note: Optional[str] = None


class ApiEndpointOperationDossier(BaseModel):
    id: str
    method: str
    route_path: str
    framework: str
    handler_name: str
    filepath: str
    start_line: int
    end_line: int
    auth_status: Literal["AUTHENTICATED", "UNAUTHENTICATED", "PARTIAL_OR_CUSTOM"] = "UNAUTHENTICATED"
    auth_mechanisms: List[str] = Field(default_factory=list)
    request_params: List[str] = Field(default_factory=list)
    response_type: Optional[str] = None
    operations: List[ApiOperationItem] = Field(default_factory=list)
    operation_categories: List[ApiOperationCategory] = Field(default_factory=list)
    calls_functions: List[str] = Field(default_factory=list)
    is_mutating: bool = False
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"] = "SAFE"
    linked_finding_ids: List[str] = Field(default_factory=list)
    linked_findings_count: int = 0
    plain_english_story: str = ""
    flow_nodes: List[Dict[str, Any]] = Field(default_factory=list)
    flow_edges: List[Dict[str, Any]] = Field(default_factory=list)


class ApiOperationsReportResponse(BaseModel):
    project_path: str
    total_endpoints: int
    authenticated_count: int
    unauthenticated_count: int
    mutating_endpoints_count: int
    db_endpoints_count: int
    external_http_endpoints_count: int
    exec_or_fs_endpoints_count: int
    vulnerable_endpoints_count: int
    frameworks_detected: List[str] = Field(default_factory=list)
    endpoints: List[ApiEndpointOperationDossier] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 13. 7-Stage PASTA Threat Modeling & SAR Go-Live Gate Models
# ---------------------------------------------------------------------------
PastaBusinessPreset = Literal[
    "AUTO_INFERRED",
    "FINTECH_PAYMENTS",
    "HEALTHCARE_PHI",
    "AI_SAAS_PUBLIC",
    "ENTERPRISE_INTERNAL",
]

GoLiveGateStatus = Literal[
    "MANDATORY_PRE_GO_LIVE",
    "POST_GO_LIVE_SLA",
    "RISK_ACCEPTED_WAIVER",
]

GoLiveSlaWindow = Literal[
    "PRE_LAUNCH",
    "7_DAYS",
    "14_DAYS",
    "30_DAYS",
    "90_DAYS",
    "WAIVED",
]

GoLiveVerdict = Literal[
    "APPROVED_FOR_GO_LIVE",
    "CONDITIONAL_GO_LIVE",
    "NO_GO_HOLD_RELEASE",
]


class PastaCrownJewelItem(BaseModel):
    id: str
    name: str
    category: str
    asset_count: int = 0
    weight_multiplier: float = 1.0
    sensitivity_label: str = "STANDARD"
    rationale: str = ""
    sample_locations: List[str] = Field(default_factory=list)


class PastaEvidenceItem(BaseModel):
    id: str
    stage_number: int
    verdict: Literal["OK", "GAP"] = "OK"
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS"] = "PASS"
    title: str
    detail: str = ""
    filepath: str = ""
    line: int = 1
    cwe_or_capec: str = ""
    stride_cross_ref: str = ""
    linked_finding_id: Optional[str] = None


class PastaStageItem(BaseModel):
    stage_number: int
    stage_code: str
    stage_roman: str
    title: str
    methodology_goal: str
    status: Literal["PASS", "MONITORED", "ACTION_REQUIRED"] = "PASS"
    ok_count: int = 0
    gap_count: int = 0
    summary: str = ""
    what_passed: List[str] = Field(default_factory=list)
    what_failed: List[str] = Field(default_factory=list)
    evidence_items: List[PastaEvidenceItem] = Field(default_factory=list)


class PastaAttackTreeNode(BaseModel):
    id: str
    node_role: Literal[
        "GOAL",
        "CAPEC_VECTOR",
        "ENTRYPOINT",
        "PROPAGATION",
        "VULN_SINK",
        "BFL_SHIELD",
        "CROWN_JEWEL",
    ]
    title: str
    subtitle: str = ""
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS"] = "MEDIUM"
    filepath: str = ""
    line: int = 1
    cwe_or_capec: str = ""
    is_severed: bool = False
    linked_finding_id: Optional[str] = None


class PastaAttackTreeEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str = ""
    is_blocked: bool = False


class PastaAttackTreeScenario(BaseModel):
    id: str
    title: str
    attacker_persona: str = "External Opportunistic Attacker"
    mitre_capec: str = ""
    stride_letter: str = "T"
    target_crown_jewel: str = ""
    status: Literal["EXPLOITABLE_PATH", "PARTIALLY_GUARDED", "SEVERED_BY_CONTROLS"] = "SEVERED_BY_CONTROLS"
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "LOW"
    narrative: str = ""
    bfl_remediation: str = ""
    projected_risk_reduction: int = 0
    linked_finding_id: Optional[str] = None
    primary_filepath: str = ""
    primary_line: int = 1
    nodes: List[PastaAttackTreeNode] = Field(default_factory=list)
    edges: List[PastaAttackTreeEdge] = Field(default_factory=list)


class GoLiveObservationItem(BaseModel):
    id: str
    source_type: Literal[
        "SAST",
        "SCA",
        "IAC",
        "SECRET_VAULT",
        "API_EXPOSURE",
        "PBOM",
        "STRIDE_GAP",
    ] = "SAST"
    title: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    cwe_or_standard: str = ""
    pasta_stage: int = 5
    stride_letter: str = "T"
    filepath: str = ""
    line: int = 1
    reachability_status: str = "REACHABLE"
    gate_status: GoLiveGateStatus = "POST_GO_LIVE_SLA"
    default_gate_status: GoLiveGateStatus = "POST_GO_LIVE_SLA"
    is_overridden: bool = False
    sla_window: GoLiveSlaWindow = "30_DAYS"
    why_issue: str = ""
    why_gate_classification: str = ""
    mandatory_fix_action: str = ""
    compensating_control: str = ""
    effort_estimate: str = "~30 mins"
    raci_owner: str = "Lead Developer (TECH_LEAD)"
    risk_reduction_points: int = 5
    linked_finding_id: Optional[str] = None


class PastaProfileUpdateRequest(BaseModel):
    project_path: Optional[str] = None
    business_preset: PastaBusinessPreset = "AUTO_INFERRED"
    crown_jewel_weights: Dict[str, float] = Field(default_factory=dict)
    reset_defaults: bool = False


class PastaGateOverrideRequest(BaseModel):
    project_path: Optional[str] = None
    observation_id: str
    gate_status: GoLiveGateStatus = "POST_GO_LIVE_SLA"
    sla_window: Optional[GoLiveSlaWindow] = None
    compensating_control_note: Optional[str] = None
    reset_override: bool = False


class PastaAssessmentResponse(BaseModel):
    project_path: str
    application_name: str
    generated_at: str
    selected_business_preset: PastaBusinessPreset = "AUTO_INFERRED"
    effective_business_preset: PastaBusinessPreset = "ENTERPRISE_INTERNAL"
    inferred_business_reason: str = ""
    compliance_frameworks: List[str] = Field(default_factory=list)
    crown_jewels: List[PastaCrownJewelItem] = Field(default_factory=list)
    inherent_risk_score: int = 20
    inherent_risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"] = "LOW"
    residual_risk_score: int = 12
    residual_risk_level: Literal["CRITICAL", "HIGH", "MODERATE", "LOW"] = "LOW"
    projected_golive_risk_score: int = 10
    projected_golive_risk_level: Literal["CRITICAL", "HIGH", "MODERATE", "LOW"] = "LOW"
    golive_verdict: GoLiveVerdict = "APPROVED_FOR_GO_LIVE"
    golive_verdict_label: str = "APPROVED FOR GO-LIVE"
    golive_executive_summary: str = ""
    mandatory_pre_golive_count: int = 0
    post_golive_sla_count: int = 0
    waived_count: int = 0
    passing_controls_count: int = 0
    stages: List[PastaStageItem] = Field(default_factory=list)
    attack_trees: List[PastaAttackTreeScenario] = Field(default_factory=list)
    golive_observations: List[GoLiveObservationItem] = Field(default_factory=list)
    make_it_live_checklist: List[str] = Field(default_factory=list)


SastPlusSuiteResponse.model_rebuild()






