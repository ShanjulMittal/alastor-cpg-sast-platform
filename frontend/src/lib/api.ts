import {
  AiCodeAuditResponse,
  AiConfigUpdatePayload,
  AiConnectionTestResponse,
  AiGraphExplainPayload,
  AiGraphExplainResponse,
  AiPatchSynthesisResponse,
  AiPublicConfig,
  AiValidateFindingsResponse,
  ApiOperationsReportResponse,
  BackendHealthResponse,
  BatchRemediateResponse,
  CommunityMapResponse,
  GraphDataResponse,
  GraphViewMode,
  LanguageCapabilitiesResponse,
  PastaAssessmentResponse,
  PastaGateOverridePayload,
  PastaProfileUpdatePayload,
  SastPlusSuiteResponse,
  SecretInventoryResponse,
  SecretScannerConfig,
  SecretScannerConfigUpdate,
  SecretVerifyRequestPayload,
  CognitivePlaybooksResponse,
  CognitiveHuntRequest,
  CognitiveHuntResponse,
  AdversarialVerifyRequest,
  AdversarialVerifyResponse,
  ExploitChainRequest,
  ExploitChainResponse,
  PatchPanelValidateRequest,
  PatchPanelValidateResponse,
  EvRunRequest,
  EvPlanResponse,
  EvRunResponse,
  EvReplayRequest,
  EvReplayResponse,
  EvReplayListResponse,
  EvDeleteReplayResponse,
  DoctorReport,
  EstimateReport,
  ScannerFusionRequest,
  ScannerFusionResponse,
  FleetRunRequest,
  FleetRunResponse,
  FleetRunListResponse,
  ScanRunCheckpointSummary,
  FleetRepoResult,
  GcRequest,
  GcReport,
} from "@/types/cpg";

export const BACKEND_URL =
  process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";
export const API_BASE = BACKEND_URL;

export class ApiRequestError extends Error {
  status: number;
  detail: string;
  payload?: unknown;

  constructor(message: string, status: number, detail?: string, payload?: unknown) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.detail = detail || message;
    this.payload = payload;
  }
}

function buildBackendUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) {
    return path;
  }
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${BACKEND_URL}${normalizedPath}`;
}

export async function apiFetchJson<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  const url = buildBackendUrl(path);
  const headers = new Headers(init?.headers || {});
  const hasBody = init?.body !== undefined && init?.body !== null;
  const isFormData =
    typeof FormData !== "undefined" && init?.body instanceof FormData;

  if (hasBody && !isFormData && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }

  const res = await fetch(url, {
    ...init,
    headers,
  });

  const raw = await res.text();

  if (!res.ok) {
    let errPayload: unknown = undefined;
    let detail = `HTTP ${res.status}`;
    if (raw) {
      try {
        errPayload = JSON.parse(raw);
        if (
          errPayload &&
          typeof errPayload === "object" &&
          "detail" in errPayload &&
          (errPayload as { detail?: unknown }).detail
        ) {
          detail = String((errPayload as { detail?: unknown }).detail);
        } else if (
          errPayload &&
          typeof errPayload === "object" &&
          "user_message" in errPayload &&
          (errPayload as { user_message?: unknown }).user_message
        ) {
          detail = String((errPayload as { user_message?: unknown }).user_message);
        } else {
          detail = raw;
        }
      } catch {
        detail = raw;
      }
    }
    throw new ApiRequestError(detail, res.status, detail, errPayload);
  }

  if (!raw) {
    return {} as T;
  }

  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new ApiRequestError(
      `Invalid JSON response from ${path}`,
      res.status,
      raw
    );
  }
}

export async function fetchGraphData(params?: {
  view_mode?: GraphViewMode | string;
  finding_id?: string | null;
  filepath?: string | null;
}): Promise<GraphDataResponse> {
  const qs = new URLSearchParams();
  qs.set("view_mode", params?.view_mode || "FINDING_PATH");
  if (params?.finding_id) {
    qs.set("finding_id", params.finding_id);
  }
  if (params?.filepath) {
    qs.set("filepath", params.filepath);
  }
  return apiFetchJson<GraphDataResponse>(`/api/graph?${qs.toString()}`);
}

export async function fetchBackendHealth(): Promise<BackendHealthResponse> {
  return apiFetchJson<BackendHealthResponse>("/api/health");
}

export async function fetchCommunityMap(): Promise<CommunityMapResponse> {
  return apiFetchJson<CommunityMapResponse>("/api/graph/communities");
}

export async function fetchLanguageCapabilities(): Promise<LanguageCapabilitiesResponse> {
  return apiFetchJson<LanguageCapabilitiesResponse>("/api/languages/capabilities");
}

export async function fetchAiConfig(): Promise<AiPublicConfig> {
  return apiFetchJson<AiPublicConfig>("/api/ai/config");
}

export async function updateAiConfig(
  payload: AiConfigUpdatePayload
): Promise<AiPublicConfig> {
  return apiFetchJson<AiPublicConfig>("/api/ai/config", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function testAiConnection(): Promise<AiConnectionTestResponse> {
  return apiFetchJson<AiConnectionTestResponse>("/api/ai/test-connection", {
    method: "POST",
  });
}

export async function validateFindingsWithAi(
  payload?:
    | string[]
    | {
        finding_ids?: string[];
        max_batch?: number;
      }
): Promise<AiValidateFindingsResponse> {
  const body = Array.isArray(payload)
    ? { finding_ids: payload }
    : {
        finding_ids: payload?.finding_ids ?? [],
        ...(typeof payload?.max_batch === "number"
          ? { max_batch: payload.max_batch }
          : {}),
      };
  return apiFetchJson<AiValidateFindingsResponse>("/api/ai/validate-findings", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function auditCodeSelectionWithAi(payload: {
  filepath: string;
  start_line: number;
  end_line: number;
  focus_question?: string;
}): Promise<AiCodeAuditResponse> {
  return apiFetchJson<AiCodeAuditResponse>("/api/ai/audit-code-selection", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function synthesizePatchWithAi(
  payload: string | { finding_id: string }
): Promise<AiPatchSynthesisResponse> {
  const finding_id =
    typeof payload === "string" ? payload : payload.finding_id;
  return apiFetchJson<AiPatchSynthesisResponse>("/api/ai/synthesize-patch", {
    method: "POST",
    body: JSON.stringify({ finding_id }),
  });
}

export async function explainGraphWithAi(
  payload: AiGraphExplainPayload
): Promise<AiGraphExplainResponse> {
  return apiFetchJson<AiGraphExplainResponse>("/api/ai/explain-graph", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function batchApplyRemediations(
  payload?: string[] | { finding_ids?: string[] }
): Promise<BatchRemediateResponse> {
  const finding_ids = Array.isArray(payload)
    ? payload
    : payload?.finding_ids ?? [];
  return apiFetchJson<BatchRemediateResponse>("/api/remediate/batch-apply", {
    method: "POST",
    body: JSON.stringify({ finding_ids }),
  });
}

export async function fetchSecretScannerConfig(): Promise<SecretScannerConfig> {
  return apiFetchJson<SecretScannerConfig>("/api/secrets/config");
}

export async function updateSecretScannerConfig(
  payload: SecretScannerConfigUpdate
): Promise<SecretScannerConfig> {
  return apiFetchJson<SecretScannerConfig>("/api/secrets/config", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchSecretInventory(): Promise<SecretInventoryResponse> {
  return apiFetchJson<SecretInventoryResponse>("/api/secrets/inventory");
}

export async function verifySecrets(
  payload?: SecretVerifyRequestPayload
): Promise<SecretInventoryResponse> {
  const body = {
    finding_ids: payload?.finding_ids ?? [],
    force_refresh: Boolean(payload?.force_refresh),
    ...(payload?.allow_live_network !== undefined
      ? { allow_live_network: payload.allow_live_network }
      : {}),
  };
  return apiFetchJson<SecretInventoryResponse>("/api/secrets/verify", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function isLikelyLocalProjectPath(
  projectPath?: string | null
): boolean {
  const trimmed = (projectPath || "").trim();
  return Boolean(trimmed && !/^(https?:\/\/|git@)/i.test(trimmed));
}

function normalizeLocalProjectPath(
  projectPath?: string | null
): string | undefined {
  const trimmed = (projectPath || "").trim();
  return isLikelyLocalProjectPath(trimmed) ? trimmed : undefined;
}

export async function fetchSastPlusSuite(
  projectPath?: string | null
): Promise<SastPlusSuiteResponse> {
  const qs = new URLSearchParams();
  const localPath = normalizeLocalProjectPath(projectPath);
  if (localPath) {
    qs.set("project_path", localPath);
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetchJson<SastPlusSuiteResponse>(`/api/aspm/suite${suffix}`);
}

export async function fetchApiOperationsReport(
  projectPath?: string | null
): Promise<ApiOperationsReportResponse> {
  const qs = new URLSearchParams();
  const localPath = normalizeLocalProjectPath(projectPath);
  if (localPath) {
    qs.set("project_path", localPath);
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetchJson<ApiOperationsReportResponse>(
    `/api/endpoints/operations${suffix}`
  );
}

export async function fetchPastaAssessment(
  projectPath?: string | null
): Promise<PastaAssessmentResponse> {
  const qs = new URLSearchParams();
  const localPath = normalizeLocalProjectPath(projectPath);
  if (localPath) {
    qs.set("project_path", localPath);
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetchJson<PastaAssessmentResponse>(`/api/aspm/pasta${suffix}`);
}

export async function updatePastaProfile(
  payload: PastaProfileUpdatePayload
): Promise<PastaAssessmentResponse> {
  const localPath = normalizeLocalProjectPath(payload.project_path);
  const body: PastaProfileUpdatePayload = {
    ...(localPath ? { project_path: localPath } : {}),
    ...(payload.business_preset
      ? { business_preset: payload.business_preset }
      : {}),
    ...(payload.crown_jewel_weights
      ? { crown_jewel_weights: payload.crown_jewel_weights }
      : {}),
    ...(typeof payload.reset_defaults === "boolean"
      ? { reset_defaults: payload.reset_defaults }
      : {}),
  };
  return apiFetchJson<PastaAssessmentResponse>("/api/aspm/pasta/profile", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function overridePastaGate(
  payload: PastaGateOverridePayload
): Promise<PastaAssessmentResponse> {
  const localPath = normalizeLocalProjectPath(payload.project_path);
  const body: PastaGateOverridePayload = {
    observation_id: payload.observation_id,
    ...(localPath ? { project_path: localPath } : {}),
    ...(payload.gate_status ? { gate_status: payload.gate_status } : {}),
    ...(payload.sla_window !== undefined
      ? { sla_window: payload.sla_window }
      : {}),
    ...(payload.compensating_control_note !== undefined
      ? { compensating_control_note: payload.compensating_control_note }
      : {}),
    ...(typeof payload.reset_override === "boolean"
      ? { reset_override: payload.reset_override }
      : {}),
  };
  return apiFetchJson<PastaAssessmentResponse>(
    "/api/aspm/pasta/gate-override",
    {
      method: "POST",
      body: JSON.stringify(body),
    }
  );
}

export async function downloadSarReportBlob(
  format: "docx" | "pdf",
  projectPath?: string | null
): Promise<{ blob: Blob; filename: string }> {
  const qs = new URLSearchParams();
  qs.set("format", format);
  const localPath = normalizeLocalProjectPath(projectPath);
  if (localPath) {
    qs.set("project_path", localPath);
  }
  const url = buildBackendUrl(`/api/export/sar-report?${qs.toString()}`);
  const res = await fetch(url, {
    method: "GET",
  });

  if (!res.ok) {
    const raw = await res.text();
    let errPayload: unknown = undefined;
    let detail = `HTTP ${res.status}`;
    if (raw) {
      try {
        errPayload = JSON.parse(raw);
        if (
          errPayload &&
          typeof errPayload === "object" &&
          "detail" in errPayload &&
          (errPayload as { detail?: unknown }).detail
        ) {
          detail = String((errPayload as { detail?: unknown }).detail);
        } else if (
          errPayload &&
          typeof errPayload === "object" &&
          "user_message" in errPayload &&
          (errPayload as { user_message?: unknown }).user_message
        ) {
          detail = String((errPayload as { user_message?: unknown }).user_message);
        } else {
          detail = raw;
        }
      } catch {
        detail = raw;
      }
    }
    throw new ApiRequestError(detail, res.status, detail, errPayload);
  }

  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^";\r\n]+)"?/i);
  const rawName = match && match[1] ? match[1].trim() : "";
  const sanitizedName = rawName.replace(/[\\/]+/g, "_");
  const filename = sanitizedName || `ALASTOR_SAR_GoLive_Report.${format}`;
  const blob = await res.blob();
  return { blob, filename };
}

// ---------------------------------------------------------------------------
// 15. ALASTOR v5.0 Pillar 2 — Cognitive Security API Clients
// ---------------------------------------------------------------------------
export async function fetchCognitivePlaybooks(
  projectPath?: string | null
): Promise<CognitivePlaybooksResponse> {
  const qs = new URLSearchParams();
  const localPath = normalizeLocalProjectPath(projectPath);
  if (localPath) {
    qs.set("project_path", localPath);
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetchJson<CognitivePlaybooksResponse>(
    `/api/cognitive/playbooks${suffix}`
  );
}

export async function runCognitiveHuntApi(
  payload: CognitiveHuntRequest
): Promise<CognitiveHuntResponse> {
  const localPath = normalizeLocalProjectPath(payload.project_path);
  const body: CognitiveHuntRequest = {
    ...(localPath ? { project_path: localPath } : {}),
    ...(payload.playbook_ids !== undefined
      ? { playbook_ids: payload.playbook_ids }
      : {}),
    ...(typeof payload.use_ai === "boolean" ? { use_ai: payload.use_ai } : {}),
    ...(typeof payload.include_sibling_sweep === "boolean"
      ? { include_sibling_sweep: payload.include_sibling_sweep }
      : {}),
    ...(typeof payload.max_ai_units === "number"
      ? { max_ai_units: payload.max_ai_units }
      : {}),
  };
  return apiFetchJson<CognitiveHuntResponse>("/api/cognitive/hunt", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function runAdversarialVerifyApi(
  payload: AdversarialVerifyRequest
): Promise<AdversarialVerifyResponse> {
  const localPath = normalizeLocalProjectPath(payload.project_path);
  const body: AdversarialVerifyRequest = {
    ...(localPath ? { project_path: localPath } : {}),
    ...(payload.finding_ids !== undefined
      ? { finding_ids: payload.finding_ids }
      : {}),
    ...(typeof payload.use_ai === "boolean" ? { use_ai: payload.use_ai } : {}),
    ...(typeof payload.max_batch === "number"
      ? { max_batch: payload.max_batch }
      : {}),
  };
  return apiFetchJson<AdversarialVerifyResponse>(
    "/api/cognitive/adversarial-verify",
    {
      method: "POST",
      body: JSON.stringify(body),
    }
  );
}

export async function fetchExploitChainsApi(
  projectPath?: string | null
): Promise<ExploitChainResponse> {
  const qs = new URLSearchParams();
  const localPath = normalizeLocalProjectPath(projectPath);
  if (localPath) {
    qs.set("project_path", localPath);
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetchJson<ExploitChainResponse>(
    `/api/cognitive/exploit-chains${suffix}`
  );
}

export async function synthesizeExploitChainsApi(
  payload: ExploitChainRequest
): Promise<ExploitChainResponse> {
  const localPath = normalizeLocalProjectPath(payload.project_path);
  const body: ExploitChainRequest = {
    ...(localPath ? { project_path: localPath } : {}),
    ...(typeof payload.use_ai === "boolean" ? { use_ai: payload.use_ai } : {}),
    ...(typeof payload.max_chains === "number"
      ? { max_chains: payload.max_chains }
      : {}),
  };
  return apiFetchJson<ExploitChainResponse>("/api/cognitive/exploit-chains", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function validatePatchPanelApi(
  payload: PatchPanelValidateRequest
): Promise<PatchPanelValidateResponse> {
  const localPath = normalizeLocalProjectPath(payload.project_path);
  const body: PatchPanelValidateRequest = {
    ...(localPath ? { project_path: localPath } : {}),
    ...(payload.finding_id !== undefined
      ? { finding_id: payload.finding_id }
      : {}),
    filepath: payload.filepath,
    original_code: payload.original_code,
    proposed_code: payload.proposed_code,
    ...(payload.cwe_id !== undefined ? { cwe_id: payload.cwe_id } : {}),
    ...(typeof payload.use_ai === "boolean" ? { use_ai: payload.use_ai } : {}),
  };
  return apiFetchJson<PatchPanelValidateResponse>(
    "/api/cognitive/validate-patch",
    {
      method: "POST",
      body: JSON.stringify(body),
    }
  );
}

// ---------------------------------------------------------------------------
// 16. ALASTOR v5.0 Pillar 3 — Live Exploit Verification & Post-Fix ev-replay
// ---------------------------------------------------------------------------
function buildEvProjectQuerySuffix(projectPath?: string | null): string {
  const qs = new URLSearchParams();
  const localPath = normalizeLocalProjectPath(projectPath);
  if (localPath) {
    qs.set("project_path", localPath);
  }
  const encoded = qs.toString();
  return encoded ? `?${encoded}` : "";
}

function buildEvRunBody(req: EvRunRequest): EvRunRequest {
  const localPath = normalizeLocalProjectPath(req.project_path) ?? "";
  return {
    project_path: localPath,
    target_url: req.target_url,
    ...(typeof req.armed === "boolean" ? { armed: req.armed } : {}),
    ...(typeof req.safe_mode === "boolean" ? { safe_mode: req.safe_mode } : {}),
    ...(typeof req.allow_private_staging_host === "boolean"
      ? { allow_private_staging_host: req.allow_private_staging_host }
      : {}),
    ...(req.authorized_staging_hosts !== undefined
      ? { authorized_staging_hosts: req.authorized_staging_hosts }
      : {}),
    ...(typeof req.timeout_seconds === "number"
      ? { timeout_seconds: req.timeout_seconds }
      : {}),
    ...(typeof req.max_probes === "number"
      ? { max_probes: req.max_probes }
      : {}),
    ...(req.collection_json !== undefined
      ? { collection_json: req.collection_json }
      : {}),
    ...(req.user_a_auth_header !== undefined
      ? { user_a_auth_header: req.user_a_auth_header }
      : {}),
    ...(req.user_b_auth_header !== undefined
      ? { user_b_auth_header: req.user_b_auth_header }
      : {}),
    ...(req.user_b_resource_id !== undefined
      ? { user_b_resource_id: req.user_b_resource_id }
      : {}),
    ...(req.extra_headers !== undefined
      ? { extra_headers: req.extra_headers }
      : {}),
    ...(req.probe_families !== undefined
      ? { probe_families: req.probe_families }
      : {}),
  };
}

export async function planEvProbes(req: EvRunRequest): Promise<EvPlanResponse> {
  return apiFetchJson<EvPlanResponse>("/api/ev/plan", {
    method: "POST",
    body: JSON.stringify(buildEvRunBody(req)),
  });
}

export async function runEvVerification(
  req: EvRunRequest
): Promise<EvRunResponse> {
  return apiFetchJson<EvRunResponse>("/api/ev/run", {
    method: "POST",
    body: JSON.stringify(buildEvRunBody(req)),
  });
}

export async function replayEvBundles(
  req: EvReplayRequest
): Promise<EvReplayResponse> {
  const localPath = normalizeLocalProjectPath(req.project_path) ?? "";
  const body: EvReplayRequest = {
    project_path: localPath,
    ...(req.target_url !== undefined ? { target_url: req.target_url } : {}),
    ...(req.replay_ids !== undefined ? { replay_ids: req.replay_ids } : {}),
    ...(typeof req.allow_private_staging_host === "boolean"
      ? { allow_private_staging_host: req.allow_private_staging_host }
      : {}),
    ...(req.authorized_staging_hosts !== undefined
      ? { authorized_staging_hosts: req.authorized_staging_hosts }
      : {}),
    ...(typeof req.timeout_seconds === "number"
      ? { timeout_seconds: req.timeout_seconds }
      : {}),
    ...(req.user_a_auth_header !== undefined
      ? { user_a_auth_header: req.user_a_auth_header }
      : {}),
    ...(req.user_b_auth_header !== undefined
      ? { user_b_auth_header: req.user_b_auth_header }
      : {}),
  };
  return apiFetchJson<EvReplayResponse>("/api/ev/replay", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function listEvReplays(
  projectPath: string
): Promise<EvReplayListResponse> {
  const suffix = buildEvProjectQuerySuffix(projectPath);
  return apiFetchJson<EvReplayListResponse>(`/api/ev/replays${suffix}`);
}

export async function deleteEvReplay(
  projectPath: string,
  replayId: string
): Promise<EvDeleteReplayResponse> {
  const suffix = buildEvProjectQuerySuffix(projectPath);
  return apiFetchJson<EvDeleteReplayResponse>(
    `/api/ev/replays/${encodeURIComponent(replayId)}${suffix}`,
    {
      method: "DELETE",
    }
  );
}

// ---------------------------------------------------------------------------
// 17. ALASTOR v5.0 Pillar 4 — Fleet Batch Runner, Checkpoints, GC & Scanner Fusion
// ---------------------------------------------------------------------------
export async function fetchFleetDoctor(
  checkNeo4j = false
): Promise<DoctorReport> {
  const suffix = checkNeo4j ? "?check_neo4j=true" : "";
  return apiFetchJson<DoctorReport>(`/api/fleet/doctor${suffix}`);
}

export async function estimateFleetRepo(
  projectPath?: string | null
): Promise<EstimateReport> {
  const localPath = normalizeLocalProjectPath(projectPath);
  return apiFetchJson<EstimateReport>("/api/fleet/estimate", {
    method: "POST",
    body: JSON.stringify(localPath ? { project_path: localPath } : {}),
  });
}

export async function importScannerFusion(
  req: ScannerFusionRequest
): Promise<ScannerFusionResponse> {
  const localPath = normalizeLocalProjectPath(req.project_path) ?? "";
  const body: ScannerFusionRequest = {
    project_path: localPath,
    report_json: req.report_json,
    ...(req.source_format !== undefined
      ? { source_format: req.source_format }
      : {}),
    ...(typeof req.run_s6_verify === "boolean"
      ? { run_s6_verify: req.run_s6_verify }
      : {}),
    ...(typeof req.correlate_cpg === "boolean"
      ? { correlate_cpg: req.correlate_cpg }
      : {}),
  };
  return apiFetchJson<ScannerFusionResponse>("/api/fusion/import", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function runFleetBatch(
  req: FleetRunRequest
): Promise<FleetRunResponse> {
  return apiFetchJson<FleetRunResponse>("/api/fleet/run", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function listFleetRuns(
  limit?: number
): Promise<FleetRunListResponse> {
  const qs = new URLSearchParams();
  if (typeof limit === "number") {
    qs.set("limit", String(limit));
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetchJson<FleetRunListResponse>(`/api/fleet/runs${suffix}`);
}

export async function listFleetCheckpoints(
  projectPath?: string,
  limit?: number
): Promise<ScanRunCheckpointSummary[]> {
  const qs = new URLSearchParams();
  const localPath = normalizeLocalProjectPath(projectPath);
  if (localPath) {
    qs.set("project_path", localPath);
  }
  if (typeof limit === "number") {
    qs.set("limit", String(limit));
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetchJson<ScanRunCheckpointSummary[]>(
    `/api/fleet/checkpoints${suffix}`
  );
}

export async function resumeFleetCheckpoint(
  runId: string,
  stopAfter?: string | null
): Promise<FleetRepoResult> {
  return apiFetchJson<FleetRepoResult>(
    `/api/fleet/checkpoints/${encodeURIComponent(runId)}/resume`,
    {
      method: "POST",
      body: JSON.stringify(
        stopAfter !== undefined ? { stop_after: stopAfter } : {}
      ),
    }
  );
}

export async function runFleetGc(req: GcRequest): Promise<GcReport> {
  return apiFetchJson<GcReport>("/api/fleet/gc", {
    method: "POST",
    body: JSON.stringify(req),
  });
}
