import {
  AlertTriangle,
  CheckCircle2,
  Code2,
  FileText,
  FlaskConical,
  Search,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { useEffect, useState } from "react";
import {
  runAuthTest,
  runIdorTest,
  runMisconfigTest,
  runSqliTest,
  runXssTest,
  saveFinding,
  setModuleMode,
} from "../utils/api";
import {
  OWASP_MODULES,
  type FindingRecord,
  type LabPhase,
  type ModuleRuntimeState,
  type OwaspModuleId,
  type SecurityMode,
} from "../utils/labLogic";

interface OwaspLabPageProps {
  selectedModule: OwaspModuleId;
  onSelectModule: (id: OwaspModuleId) => void;
  states: Record<string, ModuleRuntimeState>;
  findings: FindingRecord[];
  onRefreshState: () => Promise<void>;
  onGoToReport: () => void;
}

const PHASES: { id: LabPhase; label: string; icon: typeof Search }[] = [
  { id: "identify", label: "1. Identify", icon: Search },
  { id: "test", label: "2. Test", icon: FlaskConical },
  { id: "fix", label: "3. Fix", icon: Wrench },
  { id: "document", label: "4. Document", icon: FileText },
];

export function OwaspLabPage({
  selectedModule,
  onSelectModule,
  states,
  findings,
  onRefreshState,
  onGoToReport,
}: OwaspLabPageProps) {
  const mod = OWASP_MODULES.find((m) => m.id === selectedModule) ?? OWASP_MODULES[0];
  const currentMode: SecurityMode = states[mod.id]?.mode ?? "vulnerable";
  const currentFinding = findings.find((f) => f.module_id === mod.id);

  const [phase, setPhase] = useState<LabPhase>("identify");
  const [codeTab, setCodeTab] = useState<"Python" | "JavaScript" | "HTML & CSS">("Python");
  const [busy, setBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [saveNotice, setSaveNotice] = useState<string | null>(null);

  // Per-module test inputs
  const [sqliQuery, setSqliQuery] = useState("' OR '1'='1");
  const [sqliResult, setSqliResult] = useState<Awaited<ReturnType<typeof runSqliTest>> | null>(null);

  const [xssAuthor, setXssAuthor] = useState("alice");
  const [xssComment, setXssComment] = useState('<img src=x onerror="alert(\'XSS\')">');
  const [xssResult, setXssResult] = useState<Awaited<ReturnType<typeof runXssTest>> | null>(null);

  const [idorRecordId, setIdorRecordId] = useState(102);
  const [idorActorRole, setIdorActorRole] = useState<"analyst" | "admin">("analyst");
  const [idorAction, setIdorAction] = useState<"read_record" | "admin_export">("read_record");
  const [idorResult, setIdorResult] = useState<Awaited<ReturnType<typeof runIdorTest>> | null>(null);

  const [authUsername, setAuthUsername] = useState("alice");
  const [authPassword, setAuthPassword] = useState("alice123");
  const [authAttempts, setAuthAttempts] = useState(1);
  const [authResult, setAuthResult] = useState<Awaited<ReturnType<typeof runAuthTest>> | null>(null);

  const [misconfigTriggerError, setMisconfigTriggerError] = useState(true);
  const [misconfigResult, setMisconfigResult] = useState<Awaited<ReturnType<typeof runMisconfigTest>> | null>(null);

  // Document phase fields
  const [docSeverity, setDocSeverity] = useState<"Critical" | "High" | "Medium">(mod.defaultSeverity);
  const [docEvidence, setDocEvidence] = useState("");
  const [docAnalystNotes, setDocAnalystNotes] = useState("");
  const [docRemediationNotes, setDocRemediationNotes] = useState("");

  useEffect(() => {
    setErrorMsg(null);
    setSaveNotice(null);
  }, [mod.id]);

  useEffect(() => {
    const f = findings.find((item) => item.module_id === mod.id);
    setDocSeverity(f?.severity ?? mod.defaultSeverity);
    setDocEvidence(f?.evidence_summary ?? "");
    setDocAnalystNotes(f?.analyst_notes ?? "");
    setDocRemediationNotes(f?.remediation_notes ?? "");
  }, [mod.id, mod.defaultSeverity, findings]);

  const handleToggleMode = async (nextMode: SecurityMode) => {
    setBusy(true);
    setErrorMsg(null);
    try {
      await setModuleMode(mod.id, nextMode);
      await onRefreshState();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to switch sandbox mode");
    } finally {
      setBusy(false);
    }
  };

  const handleMarkIdentified = async () => {
    setBusy(true);
    try {
      await saveFinding({ moduleId: mod.id, identified: 1 });
      await onRefreshState();
      setPhase("test");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to update checkpoint");
    } finally {
      setBusy(false);
    }
  };

  const handleRunTest = async (overrideMode?: SecurityMode) => {
    setBusy(true);
    setErrorMsg(null);
    try {
      if (mod.id === "sqli") {
        const res = await runSqliTest(sqliQuery, overrideMode);
        setSqliResult(res);
        if (!docEvidence) setDocEvidence(`Executed SQL: ${res.sqlExecuted} | Rows returned: ${res.rows.length} (${res.statusLabel})`);
      } else if (mod.id === "xss") {
        const res = await runXssTest(xssAuthor, xssComment, overrideMode);
        setXssResult(res);
        if (!docEvidence) setDocEvidence(`Rendered: ${res.renderedHtml} | CSP: ${res.cspHeader}`);
      } else if (mod.id === "idor") {
        const res = await runIdorTest({
          recordId: idorRecordId,
          actingUserId: idorActorRole === "admin" ? 4 : 1,
          actingRole: idorActorRole,
          action: idorAction,
          mode: overrideMode,
        });
        setIdorResult(res);
        if (!docEvidence) setDocEvidence(`HTTP ${res.httpStatus} | ${res.statusLabel}`);
      } else if (mod.id === "auth") {
        const res = await runAuthTest({
          username: authUsername,
          password: authPassword,
          attemptCount: authAttempts,
          mode: overrideMode,
        });
        setAuthResult(res);
        if (!docEvidence) setDocEvidence(`Algorithm: ${res.hashAlgorithm} | Token: ${res.issuedToken} | Status: ${res.httpStatus}`);
      } else if (mod.id === "misconfig") {
        const res = await runMisconfigTest(misconfigTriggerError, overrideMode);
        setMisconfigResult(res);
        if (!docEvidence) setDocEvidence(`HTTP ${res.httpStatus} | ${res.statusLabel}`);
      }
      await onRefreshState();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Sandbox test failed");
    } finally {
      setBusy(false);
    }
  };

  const handleSaveDocumentation = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErrorMsg(null);
    setSaveNotice(null);
    try {
      await saveFinding({
        moduleId: mod.id,
        identified: 1,
        documented: 1,
        severity: docSeverity,
        evidenceSummary: docEvidence.trim() || `${mod.title} tested in Python sandbox.`,
        analystNotes: docAnalystNotes.trim(),
        remediationNotes: docRemediationNotes.trim() || mod.remediationSteps[0],
      });
      await onRefreshState();
      setSaveNotice("Finding saved to Vulnerability Report.");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to save finding");
    } finally {
      setBusy(false);
    }
  };

  const activeLayer = mod.codeLayers.find((l) => l.language === codeTab) ?? mod.codeLayers[0];

  return (
    <main className="max-w-6xl mx-auto px-6 py-10 space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1.5">
          <p className="text-sm font-medium text-[#881337]">
            Objectives 2 &amp; 3 · OWASP Top 10 Secure Web Application Sandbox
          </p>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900">
            Identify → Test → Fix → Document Lab
          </h1>
        </div>
        <button
          type="button"
          onClick={onGoToReport}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors"
        >
          <FileText className="w-4 h-4 text-[#881337]" aria-hidden="true" />
          Open Vulnerability Report
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Sidebar: 5 OWASP Modules */}
        <aside aria-label="OWASP Modules" className="lg:col-span-4 space-y-2.5">
          {OWASP_MODULES.map((item) => {
            const isSelected = item.id === mod.id;
            const mode = states[item.id]?.mode ?? "vulnerable";
            const f = findings.find((x) => x.module_id === item.id);
            const stepsDone =
              (f?.identified ? 1 : 0) +
              (f?.tested_exploit ? 1 : 0) +
              (f?.applied_fix || mode === "patched" ? 1 : 0) +
              (f?.documented ? 1 : 0);

            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectModule(item.id)}
                className={`w-full text-left rounded-xl border p-4 transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-[#881337] ${
                  isSelected
                    ? "bg-white border-[#881337] shadow-xs"
                    : "bg-white/70 border-slate-200 hover:bg-white"
                }`}
              >
                <div className="flex items-center justify-between gap-2 text-xs text-slate-500">
                  <span>
                    {item.owaspCode} · {item.cwe}
                  </span>
                  <span className="font-mono tabular-nums">{stepsDone}/4</span>
                </div>
                <div className="font-bold text-slate-900 mt-1">{item.title}</div>
                <div className="mt-2 flex items-center gap-2 text-xs font-medium">
                  {mode === "patched" ? (
                    <span className="inline-flex items-center gap-1 text-emerald-700">
                      <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
                      Patched
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-rose-700">
                      <ShieldAlert className="w-3.5 h-3.5" aria-hidden="true" />
                      Vulnerable
                    </span>
                  )}
                  <span aria-hidden="true" className="text-slate-300">·</span>
                  <span className="text-slate-600">{f?.severity ?? item.defaultSeverity}</span>
                </div>
              </button>
            );
          })}
        </aside>

        {/* Right Workspace */}
        <section className="lg:col-span-8 bg-white border border-slate-200 rounded-xl p-6 sm:p-8 space-y-6">
          {/* Module Header + Live Python Mode Switch */}
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-6 border-b border-slate-200">
            <div className="space-y-1 flex-1 min-w-0">
              <div className="text-xs font-medium text-slate-500">
                {mod.owaspCode} · {mod.cwe} · {currentFinding?.severity ?? mod.defaultSeverity} Severity
              </div>
              <h2 className="text-2xl font-bold text-slate-900">{mod.title}</h2>
              <p className="text-sm text-slate-600 leading-relaxed">{mod.summary}</p>
            </div>

            <div className="space-y-1.5 shrink-0">
              <span className="block text-xs font-semibold text-slate-500">Python Backend Mode</span>
              <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => handleToggleMode("vulnerable")}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    currentMode === "vulnerable"
                      ? "bg-white text-rose-700 shadow-xs"
                      : "text-slate-600 hover:text-slate-900"
                  }`}
                >
                  Vulnerable
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => handleToggleMode("patched")}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    currentMode === "patched"
                      ? "bg-white text-emerald-700 shadow-xs"
                      : "text-slate-600 hover:text-slate-900"
                  }`}
                >
                  Patched
                </button>
              </div>
            </div>
          </div>

          {/* 4-Step Lab Workflow Tabs */}
          <div role="tablist" aria-label="Lab workflow steps" className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-1 bg-slate-100 rounded-xl">
            {PHASES.map((p) => {
              const Icon = p.icon;
              const active = phase === p.id;
              return (
                <button
                  key={p.id}
                  role="tab"
                  aria-selected={active}
                  type="button"
                  onClick={() => setPhase(p.id)}
                  className={`flex items-center justify-center gap-1.5 px-3 py-2 text-xs sm:text-sm font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 ${
                    active
                      ? "bg-white text-[#881337] shadow-xs"
                      : "text-slate-600 hover:text-slate-900"
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                  <span>{p.label}</span>
                </button>
              );
            })}
          </div>

          {errorMsg && (
            <div role="alert" className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">
              {errorMsg}
            </div>
          )}

          {/* PHASE 1: IDENTIFY */}
          {phase === "identify" && (
            <div className="space-y-6">
              <div className="space-y-3">
                <h3 className="text-base font-bold text-slate-900">What to Inspect Across the Stack</h3>
                <ul className="space-y-2 text-sm text-slate-700 list-disc pl-5">
                  {mod.identifyPoints.map((pt) => (
                    <li key={pt}>{pt}</li>
                  ))}
                </ul>
              </div>

              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <span className="text-sm font-bold text-slate-900 flex items-center gap-2">
                    <Code2 className="w-4 h-4 text-[#881337]" aria-hidden="true" />
                    Source Code Inspection ({currentMode === "vulnerable" ? "Vulnerable" : "Patched"} View)
                  </span>
                  <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
                    {(["Python", "JavaScript", "HTML & CSS"] as const).map((lang) => (
                      <button
                        key={lang}
                        type="button"
                        onClick={() => setCodeTab(lang)}
                        className={`px-3 py-1 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
                          codeTab === lang
                            ? "bg-white text-slate-900 shadow-xs"
                            : "text-slate-600 hover:text-slate-900"
                        }`}
                      >
                        {lang}
                      </button>
                    ))}
                  </div>
                </div>

                <pre className="bg-slate-900 text-slate-100 rounded-xl p-4 font-mono text-xs leading-relaxed overflow-x-auto">
                  {currentMode === "vulnerable" ? activeLayer.vulnerable : activeLayer.patched}
                </pre>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-xs text-slate-500">
                  {currentFinding?.identified ? "Identified checkpoint completed" : "Review the code above, then proceed to Test"}
                </span>
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleMarkIdentified}
                  className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B]"
                >
                  Mark Identified &amp; Continue to Test
                </button>
              </div>
            </div>
          )}

          {/* PHASE 2: TEST */}
          {phase === "test" && (
            <div className="space-y-6">
              {/* Presets */}
              <div className="space-y-2">
                <span className="block text-xs font-semibold text-slate-600">Quick Sandbox Test Payloads</span>
                <div className="flex flex-wrap gap-2">
                  {mod.presets.map((preset) => (
                    <button
                      key={preset.label}
                      type="button"
                      onClick={() => {
                        if (mod.id === "sqli") setSqliQuery(preset.value);
                        if (mod.id === "xss") setXssComment(preset.value);
                        if (mod.id === "idor") {
                          setIdorAction("read_record");
                          setIdorRecordId(Number(preset.value));
                        }
                        if (mod.id === "auth") setAuthPassword(preset.value);
                        if (mod.id === "misconfig") setMisconfigTriggerError(preset.value === "error");
                      }}
                      className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 bg-slate-50 text-slate-800 hover:bg-slate-100 transition-colors"
                      title={preset.description}
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Module-specific interactive sandbox forms */}
              {mod.id === "sqli" && (
                <div className="space-y-4">
                  <div className="space-y-1.5">
                    <label htmlFor="sqli-input" className="block text-sm font-semibold text-slate-900">
                      Employee Username Lookup Input
                    </label>
                    <div className="flex flex-col sm:flex-row gap-3">
                      <input
                        id="sqli-input"
                        type="text"
                        value={sqliQuery}
                        onChange={(e) => setSqliQuery(e.target.value)}
                        className="flex-1 rounded-lg border border-slate-300 px-3.5 py-2 font-mono text-sm text-slate-900 focus:border-[#881337] focus:outline-none"
                        placeholder="Enter username or SQL payload"
                      />
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => handleRunTest()}
                        className="px-5 py-2 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B] whitespace-nowrap shrink-0"
                      >
                        {busy ? "Running..." : "Run Exploit Test"}
                      </button>
                    </div>
                  </div>

                  {sqliResult && (
                    <div className="space-y-4 pt-2">
                      <div
                        role="status"
                        className={`rounded-lg border p-3.5 flex items-center gap-2.5 text-sm font-medium ${
                          sqliResult.exploited
                            ? "border-rose-200 bg-rose-50 text-rose-900"
                            : "border-emerald-200 bg-emerald-50 text-emerald-900"
                        }`}
                      >
                        {sqliResult.exploited ? (
                          <AlertTriangle className="w-4 h-4 text-rose-700 shrink-0" aria-hidden="true" />
                        ) : (
                          <ShieldCheck className="w-4 h-4 text-emerald-700 shrink-0" aria-hidden="true" />
                        )}
                        <span>{sqliResult.statusLabel}</span>
                      </div>

                      <div className="bg-slate-900 text-slate-100 rounded-lg p-3.5 font-mono text-xs space-y-1">
                        <div className="text-slate-400">SQLite Statement Executed by Python:</div>
                        <div className="text-amber-300 break-all">{sqliResult.sqlExecuted}</div>
                        {sqliResult.parameters.length > 0 && (
                          <div className="text-emerald-300">Bound Params: {JSON.stringify(sqliResult.parameters)}</div>
                        )}
                      </div>

                      {sqliResult.rows.length > 0 ? (
                        <div className="overflow-x-auto border border-slate-200 rounded-lg">
                          <table className="w-full text-left text-xs border-collapse">
                            <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
                              <tr>
                                {Object.keys(sqliResult.rows[0]).map((col) => (
                                  <th key={col} className="py-2 px-3 font-semibold">{col}</th>
                                ))}
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 font-mono">
                              {sqliResult.rows.map((row, idx) => (
                                <tr key={idx}>
                                  {Object.values(row).map((val, cIdx) => (
                                    <td key={cIdx} className="py-2 px-3 text-slate-800">{String(val)}</td>
                                  ))}
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <p className="text-sm text-slate-600">0 rows returned from sandbox database.</p>
                      )}
                    </div>
                  )}
                </div>
              )}

              {mod.id === "xss" && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                    <div>
                      <label htmlFor="xss-author" className="block text-xs font-semibold text-slate-700 mb-1">
                        Author
                      </label>
                      <input
                        id="xss-author"
                        type="text"
                        value={xssAuthor}
                        onChange={(e) => setXssAuthor(e.target.value)}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
                      />
                    </div>
                    <div className="sm:col-span-3">
                      <label htmlFor="xss-comment" className="block text-xs font-semibold text-slate-700 mb-1">
                        Comment Payload
                      </label>
                      <div className="flex flex-col sm:flex-row gap-2">
                        <input
                          id="xss-comment"
                          type="text"
                          value={xssComment}
                          onChange={(e) => setXssComment(e.target.value)}
                          className="flex-1 rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm text-slate-900"
                        />
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => handleRunTest()}
                          className="px-5 py-2 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B] whitespace-nowrap shrink-0"
                        >
                          {busy ? "Testing..." : "Run Exploit Test"}
                        </button>
                      </div>
                    </div>
                  </div>

                  {xssResult && (
                    <div className="space-y-3 pt-2">
                      <div
                        role="status"
                        className={`rounded-lg border p-3.5 flex items-center gap-2.5 text-sm font-medium ${
                          xssResult.exploited
                            ? "border-rose-200 bg-rose-50 text-rose-900"
                            : "border-emerald-200 bg-emerald-50 text-emerald-900"
                        }`}
                      >
                        {xssResult.exploited ? (
                          <AlertTriangle className="w-4 h-4 text-rose-700 shrink-0" aria-hidden="true" />
                        ) : (
                          <ShieldCheck className="w-4 h-4 text-emerald-700 shrink-0" aria-hidden="true" />
                        )}
                        <span>{xssResult.statusLabel}</span>
                      </div>

                      <div className="bg-slate-900 text-slate-100 rounded-lg p-3.5 font-mono text-xs space-y-1.5">
                        <div className="text-slate-400">HTML Output Produced by Python Template:</div>
                        <div className="text-amber-300 break-all">{xssResult.renderedHtml}</div>
                        <div className="text-slate-400 pt-1">
                          Content-Security-Policy: <span className="text-emerald-300">{xssResult.cspHeader}</span>
                        </div>
                        {xssResult.vectorsDetected.length > 0 && (
                          <div className="text-rose-300">
                            Vectors in Payload: {xssResult.vectorsDetected.join(" · ")}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {mod.id === "idor" && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <label htmlFor="idor-actor" className="block text-xs font-semibold text-slate-700 mb-1">
                        Acting Session User
                      </label>
                      <select
                        id="idor-actor"
                        value={idorActorRole}
                        onChange={(e) => setIdorActorRole(e.target.value as "analyst" | "admin")}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 bg-white"
                      >
                        <option value="analyst">Alice (User #1 · analyst)</option>
                        <option value="admin">Admin (User #4 · admin)</option>
                      </select>
                    </div>
                    <div>
                      <label htmlFor="idor-action" className="block text-xs font-semibold text-slate-700 mb-1">
                        Endpoint Action
                      </label>
                      <select
                        id="idor-action"
                        value={idorAction}
                        onChange={(e) => setIdorAction(e.target.value as "read_record" | "admin_export")}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 bg-white"
                      >
                        <option value="read_record">GET /records?id=...</option>
                        <option value="admin_export">POST /admin/export</option>
                      </select>
                    </div>
                    <div>
                      <label htmlFor="idor-record-id" className="block text-xs font-semibold text-slate-700 mb-1">
                        Target Record ID
                      </label>
                      <select
                        id="idor-record-id"
                        value={idorRecordId}
                        disabled={idorAction === "admin_export"}
                        onChange={(e) => setIdorRecordId(Number(e.target.value))}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 bg-white disabled:opacity-50"
                      >
                        <option value={101}>#101 · Alice Triage Notes (Owner #1)</option>
                        <option value={102}>#102 · Bob Payroll (Owner #2)</option>
                        <option value={103}>#103 · Carol Assessment (Owner #3)</option>
                        <option value={104}>#104 · Root KMS Plan (Owner #4)</option>
                      </select>
                    </div>
                  </div>

                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleRunTest()}
                    className="px-5 py-2 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B]"
                  >
                    {busy ? "Executing..." : "Run Access Control Test"}
                  </button>

                  {idorResult && (
                    <div className="space-y-3 pt-2">
                      <div
                        role="status"
                        className={`rounded-lg border p-3.5 flex items-center gap-2.5 text-sm font-medium ${
                          idorResult.exploited
                            ? "border-rose-200 bg-rose-50 text-rose-900"
                            : "border-emerald-200 bg-emerald-50 text-emerald-900"
                        }`}
                      >
                        {idorResult.exploited ? (
                          <AlertTriangle className="w-4 h-4 text-rose-700 shrink-0" aria-hidden="true" />
                        ) : (
                          <ShieldCheck className="w-4 h-4 text-emerald-700 shrink-0" aria-hidden="true" />
                        )}
                        <span>
                          HTTP <span className="font-mono">{idorResult.httpStatus}</span> · {idorResult.statusLabel}
                        </span>
                      </div>

                      {(idorResult.record || idorResult.records) && (
                        <pre className="bg-slate-900 text-emerald-300 rounded-lg p-3.5 font-mono text-xs overflow-x-auto">
                          {JSON.stringify(idorResult.record ?? idorResult.records, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              )}

              {mod.id === "auth" && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <label htmlFor="auth-user" className="block text-xs font-semibold text-slate-700 mb-1">
                        Username
                      </label>
                      <input
                        id="auth-user"
                        type="text"
                        value={authUsername}
                        onChange={(e) => setAuthUsername(e.target.value)}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
                      />
                    </div>
                    <div>
                      <label htmlFor="auth-pass" className="block text-xs font-semibold text-slate-700 mb-1">
                        Password Input
                      </label>
                      <input
                        id="auth-pass"
                        type="text"
                        value={authPassword}
                        onChange={(e) => setAuthPassword(e.target.value)}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm text-slate-900"
                      />
                    </div>
                    <div>
                      <label htmlFor="auth-attempts" className="block text-xs font-semibold text-slate-700 mb-1">
                        Simulated Attempt #
                      </label>
                      <input
                        id="auth-attempts"
                        type="number"
                        min={1}
                        max={10}
                        value={authAttempts}
                        onChange={(e) => setAuthAttempts(Number(e.target.value) || 1)}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm text-slate-900 tabular-nums"
                      />
                    </div>
                  </div>

                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleRunTest()}
                    className="px-5 py-2 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B]"
                  >
                    {busy ? "Testing..." : "Run Auth Test"}
                  </button>

                  {authResult && (
                    <div className="space-y-3 pt-2">
                      <div
                        role="status"
                        className={`rounded-lg border p-3.5 flex items-center gap-2.5 text-sm font-medium ${
                          authResult.exploited
                            ? "border-rose-200 bg-rose-50 text-rose-900"
                            : "border-emerald-200 bg-emerald-50 text-emerald-900"
                        }`}
                      >
                        {authResult.exploited ? (
                          <AlertTriangle className="w-4 h-4 text-rose-700 shrink-0" aria-hidden="true" />
                        ) : (
                          <ShieldCheck className="w-4 h-4 text-emerald-700 shrink-0" aria-hidden="true" />
                        )}
                        <span>{authResult.statusLabel}</span>
                      </div>
                      <div className="bg-slate-900 text-slate-100 rounded-lg p-3.5 font-mono text-xs space-y-1">
                        <div>HTTP Status: {authResult.httpStatus}</div>
                        <div>Hash Scheme: <span className="text-amber-300">{authResult.hashAlgorithm}</span></div>
                        <div>Stored Digest Sample: {authResult.hashSample}</div>
                        <div>Issued Session Token: <span className="text-emerald-300">{authResult.issuedToken}</span></div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {mod.id === "misconfig" && (
                <div className="space-y-4">
                  <label className="flex items-center gap-2.5 text-sm text-slate-800 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={misconfigTriggerError}
                      onChange={(e) => setMisconfigTriggerError(e.target.checked)}
                      className="h-4 w-4 accent-[#881337]"
                    />
                    <span>Trigger unhandled Python runtime exception to test error leakage</span>
                  </label>

                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleRunTest()}
                    className="px-5 py-2 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B]"
                  >
                    {busy ? "Probing..." : "Run Misconfiguration Probe"}
                  </button>

                  {misconfigResult && (
                    <div className="space-y-3 pt-2">
                      <div
                        role="status"
                        className={`rounded-lg border p-3.5 flex items-center gap-2.5 text-sm font-medium ${
                          misconfigResult.exploited
                            ? "border-rose-200 bg-rose-50 text-rose-900"
                            : "border-emerald-200 bg-emerald-50 text-emerald-900"
                        }`}
                      >
                        {misconfigResult.exploited ? (
                          <AlertTriangle className="w-4 h-4 text-rose-700 shrink-0" aria-hidden="true" />
                        ) : (
                          <ShieldCheck className="w-4 h-4 text-emerald-700 shrink-0" aria-hidden="true" />
                        )}
                        <span>{misconfigResult.statusLabel}</span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <pre className="bg-slate-900 text-slate-100 rounded-lg p-3.5 font-mono text-xs overflow-x-auto">
                          {`// Response Headers\n${JSON.stringify(misconfigResult.responseHeaders, null, 2)}`}
                        </pre>
                        <pre className="bg-slate-900 text-amber-300 rounded-lg p-3.5 font-mono text-xs overflow-x-auto">
                          {`// Response Body (HTTP ${misconfigResult.httpStatus})\n${JSON.stringify(misconfigResult.responseBody, null, 2)}`}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* PHASE 3: FIX */}
          {phase === "fix" && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h3 className="text-base font-bold text-slate-900">Secure Coding Remediation</h3>
                  <p className="text-sm text-slate-600">
                    Compare vulnerable vs. hardened code across Python, JavaScript, and HTML/CSS, then patch the live sandbox.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={async () => {
                      await handleToggleMode("patched");
                      setPhase("test");
                    }}
                    className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-emerald-700 rounded-lg hover:bg-emerald-800"
                  >
                    <ShieldCheck className="w-4 h-4" aria-hidden="true" />
                    Apply Patch &amp; Re-Test
                  </button>
                </div>
              </div>

              <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
                {(["Python", "JavaScript", "HTML & CSS"] as const).map((lang) => (
                  <button
                    key={lang}
                    type="button"
                    onClick={() => setCodeTab(lang)}
                    className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
                      codeTab === lang
                        ? "bg-white text-slate-900 shadow-xs"
                        : "text-slate-600 hover:text-slate-900"
                    }`}
                  >
                    {lang}
                  </button>
                ))}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <div className="text-xs font-semibold text-rose-700">Vulnerable {codeTab}</div>
                  <pre className="bg-slate-900 text-rose-200 rounded-xl p-4 font-mono text-xs leading-relaxed overflow-x-auto min-h-32">
                    {activeLayer.vulnerable}
                  </pre>
                </div>
                <div className="space-y-1.5">
                  <div className="text-xs font-semibold text-emerald-700">Patched {codeTab}</div>
                  <pre className="bg-slate-900 text-emerald-200 rounded-xl p-4 font-mono text-xs leading-relaxed overflow-x-auto min-h-32">
                    {activeLayer.patched}
                  </pre>
                </div>
              </div>

              <div className="space-y-2 pt-2 border-t border-slate-100">
                <h4 className="text-sm font-bold text-slate-900">Remediation Checklist</h4>
                <ul className="space-y-1.5 text-sm text-slate-700 list-disc pl-5">
                  {mod.remediationSteps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {/* PHASE 4: DOCUMENT */}
          {phase === "document" && (
            <form onSubmit={handleSaveDocumentation} className="space-y-5">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="doc-severity" className="block text-sm font-semibold text-slate-900 mb-1">
                    Finding Severity
                  </label>
                  <select
                    id="doc-severity"
                    value={docSeverity}
                    onChange={(e) => setDocSeverity(e.target.value as "Critical" | "High" | "Medium")}
                    className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                  </select>
                </div>
                <div className="flex items-end">
                  <p className="text-xs text-slate-500 pb-2">
                    Live Backend Mode: <strong className="text-slate-900">{currentMode === "patched" ? "Patched" : "Vulnerable"}</strong>
                  </p>
                </div>
              </div>

              <div>
                <label htmlFor="doc-evidence" className="block text-sm font-semibold text-slate-900 mb-1">
                  Observed Exploit / Verification Evidence
                </label>
                <textarea
                  id="doc-evidence"
                  rows={3}
                  value={docEvidence}
                  onChange={(e) => setDocEvidence(e.target.value)}
                  placeholder="Describe the payload tested, HTTP status, or leaked rows observed..."
                  className="w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm text-slate-900 focus:border-[#881337] focus:outline-none"
                />
              </div>

              <div>
                <label htmlFor="doc-remediation" className="block text-sm font-semibold text-slate-900 mb-1">
                  Remediation Recommendation
                </label>
                <textarea
                  id="doc-remediation"
                  rows={2}
                  value={docRemediationNotes}
                  onChange={(e) => setDocRemediationNotes(e.target.value)}
                  placeholder={mod.remediationSteps[0]}
                  className="w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm text-slate-900 focus:border-[#881337] focus:outline-none"
                />
              </div>

              <div>
                <label htmlFor="doc-notes" className="block text-sm font-semibold text-slate-900 mb-1">
                  Analyst Notes (Optional)
                </label>
                <textarea
                  id="doc-notes"
                  rows={2}
                  value={docAnalystNotes}
                  onChange={(e) => setDocAnalystNotes(e.target.value)}
                  placeholder="Additional context for the demo walkthrough..."
                  className="w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm text-slate-900 focus:border-[#881337] focus:outline-none"
                />
              </div>

              {saveNotice && (
                <div role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-2.5 text-sm text-emerald-800 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden="true" />
                  <span>{saveNotice}</span>
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                <button
                  type="button"
                  onClick={onGoToReport}
                  className="text-sm font-semibold text-[#881337] hover:underline"
                >
                  Proceed to Final Report &amp; Walkthrough
                </button>
                <button
                  type="submit"
                  disabled={busy}
                  className="px-5 py-2.5 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B]"
                >
                  {busy ? "Saving..." : "Document Finding"}
                </button>
              </div>
            </form>
          )}
        </section>
      </div>
    </main>
  );
}
