import type { FindingRecord, ModuleRuntimeState, OwaspModuleId, SecurityMode } from "./labLogic";

export interface LabStateResponse {
  ok: boolean;
  states: Record<OwaspModuleId, ModuleRuntimeState>;
  comments: {
    id: number;
    author: string;
    body_raw: string;
    body_escaped: string;
    mode: SecurityMode;
    created_at: string;
  }[];
  findings: FindingRecord[];
}

export interface HttpSimPayload {
  action: "login" | "fetch_profile" | "admin_export" | "xss_cookie_read" | "csrf_transfer";
  role: "guest" | "analyst" | "admin";
  username: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Strict" | "Lax" | "None";
  enforceRbac: boolean;
  hasSession: boolean;
  sessionToken?: string;
}

export interface HttpSimResponse {
  ok: boolean;
  status: number;
  reason: string;
  verdict: "secure" | "vulnerable";
  summary: string;
  rawRequest: string;
  rawResponse: string;
  body: Record<string, unknown>;
  stages: { id: string; label: string; detail: string }[];
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`Request failed (${res.status})`);
  }
  return res.json() as Promise<T>;
}

export async function fetchLabState(): Promise<LabStateResponse> {
  const res = await fetch("/api/py/lab/state");
  if (!res.ok) throw new Error(`Failed to fetch lab state (${res.status})`);
  return res.json() as Promise<LabStateResponse>;
}

export async function resetSandbox(): Promise<{ ok: boolean; message: string }> {
  return postJson("/api/py/reset", {});
}

export async function setModuleMode(moduleId: OwaspModuleId, mode: SecurityMode): Promise<{ ok: boolean; mode: SecurityMode }> {
  return postJson("/api/py/lab/mode", { moduleId, mode });
}

export async function runHttpSimulation(payload: HttpSimPayload): Promise<HttpSimResponse> {
  return postJson("/api/py/http-sim/request", payload);
}

export async function runSqliTest(query: string, mode?: SecurityMode) {
  return postJson<{
    ok: boolean;
    mode: SecurityMode;
    sqlExecuted: string;
    parameters: string[];
    rows: Record<string, unknown>[];
    exploited: boolean;
    sqlError?: string;
    statusLabel: string;
  }>("/api/py/lab/sqli", { query, mode });
}

export async function runXssTest(author: string, comment: string, mode?: SecurityMode) {
  return postJson<{
    ok: boolean;
    mode: SecurityMode;
    renderedHtml: string;
    vectorsDetected: string[];
    exploited: boolean;
    cspHeader: string;
    comments: LabStateResponse["comments"];
    statusLabel: string;
  }>("/api/py/lab/xss", { author, comment, mode });
}

export async function runIdorTest(params: {
  recordId: number;
  actingUserId: number;
  actingRole: string;
  action: "read_record" | "admin_export";
  mode?: SecurityMode;
}) {
  return postJson<{
    ok: boolean;
    httpStatus: number;
    mode: SecurityMode;
    exploited: boolean;
    record?: Record<string, unknown> | null;
    records?: Record<string, unknown>[];
    statusLabel: string;
  }>("/api/py/lab/idor", params);
}

export async function runAuthTest(params: {
  username: string;
  password: string;
  attemptCount: number;
  mode?: SecurityMode;
}) {
  return postJson<{
    ok: boolean;
    httpStatus: number;
    mode: SecurityMode;
    authenticated: boolean;
    exploited: boolean;
    hashSample: string;
    hashAlgorithm: string;
    issuedToken: string;
    rateLimited: boolean;
    statusLabel: string;
  }>("/api/py/lab/auth", params);
}

export async function runMisconfigTest(triggerError: boolean, mode?: SecurityMode) {
  return postJson<{
    ok: boolean;
    httpStatus: number;
    mode: SecurityMode;
    exploited: boolean;
    responseHeaders: Record<string, string>;
    responseBody: Record<string, unknown>;
    statusLabel: string;
  }>("/api/py/lab/misconfig", { triggerError, mode });
}

export async function saveFinding(payload: {
  moduleId: OwaspModuleId;
  identified?: number;
  testedExploit?: number;
  appliedFix?: number;
  documented?: number;
  severity?: "Critical" | "High" | "Medium";
  analystNotes?: string;
  evidenceSummary?: string;
  remediationNotes?: string;
}) {
  return postJson<{ ok: boolean; finding: FindingRecord }>("/api/py/findings", payload);
}
