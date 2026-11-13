import { AlertTriangle, ArrowRight, Cookie, Lock, Play, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { runHttpSimulation, type HttpSimPayload, type HttpSimResponse } from "../utils/api";
import { evaluateCookieSecurity } from "../utils/labLogic";

const ACTION_OPTIONS: { value: HttpSimPayload["action"]; label: string; description: string }[] = [
  {
    value: "login",
    label: "1. Login & Issue Session Cookie",
    description: "POST credentials to Python server and inspect Set-Cookie attributes.",
  },
  {
    value: "fetch_profile",
    label: "2. Authenticated Profile Request",
    description: "GET /py/account/profile carrying Cookie header for session lookup.",
  },
  {
    value: "admin_export",
    label: "3. Privileged Admin Export (RBAC)",
    description: "Test authorization boundaries between guest, analyst, and admin roles.",
  },
  {
    value: "xss_cookie_read",
    label: "4. XSS document.cookie Probe",
    description: "Verify whether HttpOnly blocks client-side script access to session_id.",
  },
  {
    value: "csrf_transfer",
    label: "5. Cross-Origin CSRF Probe",
    description: "Test whether SameSite policy stops third-party origins from sending cookies.",
  },
];

export function HttpLifecyclePage() {
  const [action, setAction] = useState<HttpSimPayload["action"]>("login");
  const [role, setRole] = useState<HttpSimPayload["role"]>("analyst");
  const [httpOnly, setHttpOnly] = useState(true);
  const [secure, setSecure] = useState(true);
  const [sameSite, setSameSite] = useState<"Strict" | "Lax" | "None">("Strict");
  const [enforceRbac, setEnforceRbac] = useState(true);
  const [hasSession, setHasSession] = useState(true);
  const [sessionToken, setSessionToken] = useState("sid_demo_8f4c19a2");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<HttpSimResponse | null>(null);

  const policyAssessment = evaluateCookieSecurity({
    httpOnly,
    secure,
    sameSite,
    enforceRbac,
  });

  const handleSendRequest = async (overrideAction?: HttpSimPayload["action"]) => {
    const activeAction = overrideAction ?? action;
    setLoading(true);
    setError(null);
    try {
      const data = await runHttpSimulation({
        action: activeAction,
        role,
        username: role === "admin" ? "admin" : role === "guest" ? "guest" : "alice",
        httpOnly,
        secure,
        sameSite,
        enforceRbac,
        hasSession,
        sessionToken,
      });
      setResult(data);
      const issued = data.body?.sessionToken;
      if (typeof issued === "string" && issued.length > 0) {
        setSessionToken(issued);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run HTTP simulation");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="max-w-6xl mx-auto px-6 py-10 space-y-8">
      <div className="space-y-2">
        <p className="text-sm font-medium text-[#881337]">
          Objective 1 · HTTP Lifecycle, Cookies, Sessions &amp; Authorization
        </p>
        <h1 className="text-3xl font-bold tracking-tight text-slate-900">
          HTTP Request/Response &amp; Session Inspector
        </h1>
        <p className="text-base text-slate-600 max-w-3xl">
          Send live requests to the Python HTTP handler, toggle browser cookie defenses and server-side RBAC enforcement, and inspect the exact wire headers returned.
        </p>
      </div>

      {/* Two-Zone Educational Sandbox Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Zone (60-65%): Visual Lifecycle Stage + Wire Inspector */}
        <section className="lg:col-span-7 space-y-6">
          {/* 5-Stage HTTP Lifecycle Visualizer */}
          <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-5">
            <div className="flex items-center justify-between gap-4">
              <h2 className="text-base font-bold text-slate-900">
                5-Stage HTTP Request/Response Lifecycle
              </h2>
              <span className="text-xs font-mono text-slate-500">
                {result ? `HTTP ${result.status} ${result.reason}` : "Ready to transmit"}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-5 gap-2.5">
              {(
                result?.stages ?? [
                  { id: "client", label: "1. Client", detail: "Browser builds HTTP method & headers" },
                  { id: "transport", label: "2. Transport", detail: secure ? "TLS encrypted channel" : "Plaintext HTTP risk" },
                  { id: "python", label: "3. Python", detail: "LabHandler parses request" },
                  { id: "auth", label: "4. Auth Gate", detail: enforceRbac ? "Server verifies role" : "RBAC check disabled" },
                  { id: "response", label: "5. Response", detail: "Status, Set-Cookie & JSON" },
                ]
              ).map((stage, idx) => (
                <div
                  key={stage.id}
                  className={`rounded-lg border p-3 text-xs space-y-1 transition-colors ${
                    result
                      ? result.verdict === "vulnerable" && idx >= 3
                        ? "border-rose-200 bg-rose-50/70"
                        : "border-slate-200 bg-slate-50"
                      : "border-slate-200 bg-slate-50/50"
                  }`}
                >
                  <div className="font-bold text-slate-900 flex items-center justify-between gap-1">
                    <span>{stage.label}</span>
                    {idx < 4 && <ArrowRight className="w-3 h-3 text-slate-400 hidden sm:inline shrink-0" aria-hidden="true" />}
                  </div>
                  <p className="text-slate-600 leading-snug">{stage.detail}</p>
                </div>
              ))}
            </div>

            {/* Security Verdict Banner */}
            {result ? (
              <div
                role="status"
                className={`rounded-lg border p-4 flex items-start gap-3 ${
                  result.verdict === "secure"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-900"
                    : "border-rose-200 bg-rose-50 text-rose-900"
                }`}
              >
                {result.verdict === "secure" ? (
                  <ShieldCheck className="w-5 h-5 text-emerald-700 shrink-0 mt-0.5" aria-hidden="true" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-rose-700 shrink-0 mt-0.5" aria-hidden="true" />
                )}
                <div className="space-y-1 text-sm">
                  <div className="font-bold">
                    {result.verdict === "secure" ? "Verified Secure Behavior" : "Security Exposure Detected"} · HTTP{" "}
                    <span className="font-mono tabular-nums">{result.status}</span>
                  </div>
                  <p>{result.summary}</p>
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-600">
                Select an HTTP action on the right and click <strong className="text-slate-900">Send Request</strong> to execute a real Python HTTP transaction and inspect the wire trace.
              </div>
            )}
          </div>

          {/* Raw Wire Trace: Request & Response */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-900 text-slate-100 rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
                <span>Raw HTTP Request</span>
                <span className="font-mono">Client → Python</span>
              </div>
              <pre className="font-mono text-xs leading-relaxed whitespace-pre-wrap break-all text-slate-200 min-h-40">
                {result?.rawRequest ??
                  `POST /py/session/login HTTP/1.1\nHost: sandbox.appseclab.local\nContent-Type: application/json\n\n{\n  "username": "${role === "admin" ? "admin" : "alice"}",\n  "role": "${role}"\n}`}
              </pre>
            </div>

            <div className="bg-slate-900 text-slate-100 rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
                <span>Raw HTTP Response</span>
                <span className="font-mono">Python → Browser</span>
              </div>
              <pre className="font-mono text-xs leading-relaxed whitespace-pre-wrap break-all text-emerald-300 min-h-40">
                {result?.rawResponse ??
                  `HTTP/1.1 200 OK\nServer: AppSecLabPython/3.10\nSet-Cookie: session_id=${sessionToken}; Path=/; Max-Age=3600${httpOnly ? "; HttpOnly" : ""}${secure ? "; Secure" : ""}; SameSite=${sameSite}\nContent-Type: application/json`}
              </pre>
            </div>
          </div>
        </section>

        {/* Right Zone (35-40%): Request Builder & Cookie/RBAC Controls */}
        <aside className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-6 space-y-6">
          <div className="space-y-3">
            <label htmlFor="http-action-select" className="block text-sm font-bold text-slate-900">
              HTTP Scenario
            </label>
            <select
              id="http-action-select"
              value={action}
              onChange={(e) => setAction(e.target.value as HttpSimPayload["action"])}
              className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 focus:border-[#881337] focus:outline-none"
            >
              {ACTION_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <p className="text-xs text-slate-600">
              {ACTION_OPTIONS.find((a) => a.value === action)?.description}
            </p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label htmlFor="http-role-select" className="block text-xs font-semibold text-slate-700">
                Authenticated Role
              </label>
              <select
                id="http-role-select"
                value={role}
                onChange={(e) => setRole(e.target.value as HttpSimPayload["role"])}
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900"
              >
                <option value="guest">guest</option>
                <option value="analyst">analyst</option>
                <option value="admin">admin</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="samesite-select" className="block text-xs font-semibold text-slate-700">
                SameSite Policy
              </label>
              <select
                id="samesite-select"
                value={sameSite}
                onChange={(e) => setSameSite(e.target.value as "Strict" | "Lax" | "None")}
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900"
              >
                <option value="Strict">Strict</option>
                <option value="Lax">Lax</option>
                <option value="None">None</option>
              </select>
            </div>
          </div>

          <fieldset className="space-y-2.5 pt-2 border-t border-slate-100">
            <legend className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Cookie className="w-4 h-4 text-[#881337]" aria-hidden="true" />
              Cookie &amp; Authorization Controls
            </legend>

            <label className="flex items-start gap-3 cursor-pointer py-1">
              <input
                type="checkbox"
                checked={httpOnly}
                onChange={(e) => setHttpOnly(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-[#881337]"
              />
              <span className="text-sm text-slate-700">
                <strong className="text-slate-900">HttpOnly</strong> — Blocks JavaScript <code className="font-mono text-xs">document.cookie</code> reads
              </span>
            </label>

            <label className="flex items-start gap-3 cursor-pointer py-1">
              <input
                type="checkbox"
                checked={secure}
                onChange={(e) => setSecure(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-[#881337]"
              />
              <span className="text-sm text-slate-700">
                <strong className="text-slate-900">Secure</strong> — Transmit cookie strictly over HTTPS
              </span>
            </label>

            <label className="flex items-start gap-3 cursor-pointer py-1">
              <input
                type="checkbox"
                checked={hasSession}
                onChange={(e) => setHasSession(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-[#881337]"
              />
              <span className="text-sm text-slate-700">
                <strong className="text-slate-900">Send Cookie Header</strong> — Include <code className="font-mono text-xs">session_id</code> on requests
              </span>
            </label>

            <label className="flex items-start gap-3 cursor-pointer py-1">
              <input
                type="checkbox"
                checked={enforceRbac}
                onChange={(e) => setEnforceRbac(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-[#881337]"
              />
              <span className="text-sm text-slate-700">
                <strong className="text-slate-900">Enforce Server RBAC</strong> — Verify <code className="font-mono text-xs">role == admin</code> in Python
              </span>
            </label>
          </fieldset>

          {error && (
            <div role="alert" className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800">
              {error}
            </div>
          )}

          <button
            type="button"
            onClick={() => handleSendRequest()}
            disabled={loading}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B] disabled:opacity-60 transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#881337]"
          >
            <Play className="w-4 h-4" aria-hidden="true" />
            {loading ? "Sending to Python..." : "Send Request"}
          </button>

          {/* Policy Audit Summary */}
          <div className="pt-4 border-t border-slate-200 space-y-2">
            <div className="flex items-center justify-between text-xs font-semibold">
              <span className="text-slate-600 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5" aria-hidden="true" />
                Live Policy Posture
              </span>
              <span className={policyAssessment.status === "Hardened" ? "text-emerald-700" : "text-rose-700"}>
                {policyAssessment.status}
              </span>
            </div>
            {policyAssessment.warnings.length > 0 ? (
              <ul className="space-y-1 text-xs text-rose-700 list-disc pl-4">
                {policyAssessment.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-emerald-700">
                All cookie flags and server-side RBAC controls are hardened.
              </p>
            )}
          </div>
        </aside>
      </div>
    </main>
  );
}
