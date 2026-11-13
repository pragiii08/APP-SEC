import {
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  PlayCircle,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import {
  calculateLabProgress,
  generateMarkdownReport,
  OWASP_MODULES,
  type FindingRecord,
  type ModuleRuntimeState,
  type OwaspModuleId,
} from "../utils/labLogic";

interface ReportPageProps {
  findings: FindingRecord[];
  states: Record<string, ModuleRuntimeState>;
  onOpenModule: (moduleId: OwaspModuleId) => void;
}

export function ReportPage({ findings, states, onOpenModule }: ReportPageProps) {
  const [analystName, setAnalystName] = useState("Security Lab Analyst");
  const [copied, setCopied] = useState(false);
  const [walkthroughOpen, setWalkthroughOpen] = useState(false);
  const [walkthroughStep, setWalkthroughStep] = useState(0);

  const progress = calculateLabProgress(findings, states);
  const findingsById = new Map(findings.map((f) => [f.module_id, f]));
  const markdownText = generateMarkdownReport(findings, states, analystName.trim() || "Security Lab Analyst");

  const walkthroughSlides = [
    {
      title: "1. Web Architecture & HTTP/Auth Foundations",
      subtitle: "Objective 1 · Python HTTP Server, Cookies, Sessions & RBAC",
      summary:
        "Requests travel from the browser JavaScript client to the Python 3 HTTP handler. Session cookies require HttpOnly (blocking XSS document.cookie theft), Secure (HTTPS-only transport), and SameSite=Strict/Lax (mitigating CSRF), paired with server-side RBAC checks.",
      metrics: [
        `Backend Runtime: Python 3.10 + SQLite 3`,
        `Frontend Layers: JavaScript + HTML + CSS`,
        `Session Controls: HttpOnly · Secure · SameSite · RBAC`,
      ],
    },
    {
      title: "2. OWASP Top 10 Exploits Identified & Tested",
      subtitle: "Objective 2 · Safe Sandbox Exploitation",
      summary: `Executed controlled attack tests across ${progress.testedCount}/${progress.totalModules} OWASP modules: SQL tautology/UNION leaks, unescaped HTML/script XSS injection, horizontal/vertical IDOR access, weak MD5/predictable session tokens, and verbose traceback leakage.`,
      metrics: [
        `Modules Identified: ${progress.identifiedCount}/${progress.totalModules}`,
        `Exploits Verified: ${progress.testedCount}/${progress.totalModules}`,
        `Primary Vectors: CWE-89 · CWE-79 · CWE-639 · CWE-287 · CWE-16`,
      ],
    },
    {
      title: "3. Multi-Layer Remediation Applied",
      subtitle: "Objective 3 · Python, JavaScript, HTML & CSS Hardening",
      summary: `Applied secure coding fixes across the stack: parameterized sqlite3 ? queries, Python html.escape() + textContent + CSP headers, server-side ownership & role checks (403 Forbidden), salted scrypt + secrets.token_urlsafe(32) + rate limiting (429), and hardened response headers.`,
      metrics: [
        `Modules Patched Live: ${progress.patchedLiveCount}/${progress.totalModules}`,
        `Findings Documented: ${progress.documentedCount}/${progress.totalModules}`,
        `Security Posture: ${progress.postureLabel}`,
      ],
    },
    {
      title: "4. Verification & Final Deliverable Summary",
      subtitle: "Objective 4 · Report & Remediation Sign-Off",
      summary:
        "Re-running each attack payload against the patched Python endpoints confirms blocked injections, neutralized markup, rejected unauthorized IDOR reads, and sanitized error responses. Export the full Markdown or JSON assessment report below.",
      metrics: [
        `Lab Completion: ${progress.completionPercent}%`,
        `Deliverables Ready: OWASP Analysis · Vulnerability Report · Remediation Plan`,
        `Walkthrough Status: Ready for Presentation`,
      ],
    },
  ];

  const handleDownload = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleCopyMarkdown = async () => {
    try {
      await navigator.clipboard.writeText(markdownText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback noop if clipboard permission is unavailable
    }
  };

  return (
    <main className="max-w-6xl mx-auto px-6 py-10 space-y-10">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1.5">
          <p className="text-sm font-medium text-[#881337]">
            Objective 4 · OWASP Analysis, Vulnerability Report &amp; Demo Walkthrough
          </p>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900">
            Security Assessment Report &amp; Walkthrough
          </h1>
        </div>

        <button
          type="button"
          onClick={() => {
            setWalkthroughStep(0);
            setWalkthroughOpen((prev) => !prev);
          }}
          className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B] transition-colors"
        >
          <PlayCircle className="w-4 h-4" aria-hidden="true" />
          {walkthroughOpen ? "Hide Demo Walkthrough" : "Start Demo Walkthrough"}
        </button>
      </div>

      {/* Interactive Demo Walkthrough Deck */}
      {walkthroughOpen && (
        <section
          aria-label="Demo Walkthrough Presentation"
          className="bg-slate-900 text-slate-100 rounded-xl p-6 sm:p-8 space-y-6"
        >
          <div className="flex flex-wrap items-center justify-between gap-4">
            <span className="text-xs font-mono text-rose-300">
              {walkthroughSlides[walkthroughStep].subtitle}
            </span>
            <span className="text-xs font-mono tabular-nums text-slate-400">
              Slide {walkthroughStep + 1} / {walkthroughSlides.length}
            </span>
          </div>

          <div className="space-y-3">
            <h2 className="text-2xl font-bold text-white">
              {walkthroughSlides[walkthroughStep].title}
            </h2>
            <p className="text-base text-slate-300 leading-relaxed max-w-3xl">
              {walkthroughSlides[walkthroughStep].summary}
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
            {walkthroughSlides[walkthroughStep].metrics.map((m) => (
              <div key={m} className="rounded-lg border border-slate-700 bg-slate-800/70 px-4 py-3 text-xs font-mono text-slate-200">
                {m}
              </div>
            ))}
          </div>

          <div className="flex items-center justify-between pt-4 border-t border-slate-800">
            <button
              type="button"
              disabled={walkthroughStep === 0}
              onClick={() => setWalkthroughStep((s) => Math.max(0, s - 1))}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-lg border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:opacity-40"
            >
              <ChevronLeft className="w-4 h-4" aria-hidden="true" />
              Previous
            </button>
            <button
              type="button"
              disabled={walkthroughStep === walkthroughSlides.length - 1}
              onClick={() => setWalkthroughStep((s) => Math.min(walkthroughSlides.length - 1, s + 1))}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-semibold rounded-lg bg-[#881337] text-white hover:bg-[#6B0F2B] disabled:opacity-40"
            >
              Next
              <ChevronRight className="w-4 h-4" aria-hidden="true" />
            </button>
          </div>
        </section>
      )}

      {/* Executive Summary Bar */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-4 tabular-nums">
        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <p className="text-xs text-slate-500">Overall Posture</p>
          <p className="text-lg font-bold text-slate-900 mt-1">{progress.postureLabel}</p>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <p className="text-xs text-slate-500">Modules Patched</p>
          <p className="text-lg font-bold text-slate-900 mt-1">
            {progress.patchedLiveCount} of {progress.totalModules}
          </p>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <p className="text-xs text-slate-500">Findings Documented</p>
          <p className="text-lg font-bold text-slate-900 mt-1">
            {progress.documentedCount} of {progress.totalModules}
          </p>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <p className="text-xs text-slate-500">Lab Completion</p>
          <p className="text-lg font-bold text-slate-900 mt-1">{progress.completionPercent}%</p>
        </div>
      </section>

      {/* OWASP Analysis & Remediation Findings Table */}
      <section className="space-y-4">
        <h2 className="text-xl font-bold text-slate-900">
          OWASP Analysis &amp; Remediation Recommendations
        </h2>

        <div className="space-y-4">
          {OWASP_MODULES.map((mod) => {
            const f = findingsById.get(mod.id);
            const liveMode = states[mod.id]?.mode ?? "vulnerable";
            return (
              <article
                key={mod.id}
                className="bg-white border border-slate-200 rounded-xl p-6 space-y-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="space-y-1">
                    <div className="text-xs text-slate-500">
                      {mod.owaspCode} · {mod.cwe} · Severity: <strong className="text-slate-800">{f?.severity ?? mod.defaultSeverity}</strong>
                    </div>
                    <h3 className="text-lg font-bold text-slate-900">{mod.title}</h3>
                  </div>

                  <div className="flex items-center gap-4">
                    {liveMode === "patched" ? (
                      <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-emerald-700">
                        <ShieldCheck className="w-4 h-4" aria-hidden="true" />
                        Remediated
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-rose-700">
                        <ShieldAlert className="w-4 h-4" aria-hidden="true" />
                        Open in Sandbox
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => onOpenModule(mod.id)}
                      className="text-sm font-semibold text-[#881337] hover:underline"
                    >
                      Edit in Lab
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2 border-t border-slate-100 text-sm">
                  <div className="space-y-1.5">
                    <h4 className="font-semibold text-slate-900">Observed Evidence &amp; Notes</h4>
                    <p className="text-slate-600 leading-relaxed">
                      {f?.evidence_summary?.trim()
                        ? f.evidence_summary
                        : mod.summary}
                    </p>
                    {f?.analyst_notes?.trim() && (
                      <p className="text-slate-500 text-xs pt-1">Analyst Note: {f.analyst_notes}</p>
                    )}
                  </div>
                  <div className="space-y-1.5">
                    <h4 className="font-semibold text-slate-900">Remediation Recommendations</h4>
                    <ul className="space-y-1 text-slate-600 list-disc pl-4">
                      {f?.remediation_notes?.trim() && <li>{f.remediation_notes}</li>}
                      {mod.remediationSteps.map((step) => (
                        <li key={step}>{step}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      </section>

      {/* Export Deliverable Section */}
      <section className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="space-y-1.5 flex-1 min-w-60 max-w-sm">
            <label htmlFor="report-author" className="block text-sm font-semibold text-slate-900">
              Analyst / Student Name for Submission
            </label>
            <input
              id="report-author"
              type="text"
              value={analystName}
              onChange={(e) => setAnalystName(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm text-slate-900 focus:border-[#881337] focus:outline-none"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={handleCopyMarkdown}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-700" aria-hidden="true" /> : <Copy className="w-4 h-4" aria-hidden="true" />}
              {copied ? "Copied Markdown" : "Copy Markdown"}
            </button>
            <button
              type="button"
              onClick={() => handleDownload(markdownText, "owasp-vulnerability-report.md", "text/markdown")}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B]"
            >
              <Download className="w-4 h-4" aria-hidden="true" />
              Export Markdown Report
            </button>
            <button
              type="button"
              onClick={() =>
                handleDownload(
                  JSON.stringify({ analystName, progress, states, findings }, null, 2),
                  "owasp-vulnerability-report.json",
                  "application/json"
                )
              }
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50"
            >
              <Download className="w-4 h-4" aria-hidden="true" />
              Export JSON
            </button>
          </div>
        </div>

        <pre className="bg-slate-900 text-slate-200 rounded-xl p-4 font-mono text-xs leading-relaxed max-h-72 overflow-y-auto whitespace-pre-wrap">
          {markdownText}
        </pre>
      </section>
    </main>
  );
}
