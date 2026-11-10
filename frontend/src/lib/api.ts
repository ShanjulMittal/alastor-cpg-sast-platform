import {
  AiCodeAuditResponse,
  AiConfigUpdatePayload,
  AiConnectionTestResponse,
  AiGraphExplainPayload,
  AiGraphExplainResponse,
  AiPatchSynthesisResponse,
  AiPublicConfig,
  AiValidateFindingsResponse,
  BatchRemediateResponse,
  GraphDataResponse,
  GraphViewMode,
} from "@/types/cpg";

export const BACKEND_URL =
  process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

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
