import { ArrowRight, CheckCircle2, CheckSquare, ShieldAlert, ShieldCheck } from "lucide-react";
import {
  calculateLabProgress,
  KEY_OBJECTIVES,
  OWASP_MODULES,
  type FindingRecord,
  type ModuleRuntimeState,
  type PageRoute,
} from "../utils/labLogic";

interface OverviewPageProps {
  findings: FindingRecord[];
  states: Record<string, ModuleRuntimeState>;
  onNavigate: (route: PageRoute, moduleId?: string) => void;
}

const METHODOLOGY_STEPS = [
  { step: "1. Identify", detail: "Inspect Python, JavaScript, HTML, and CSS layers for unsafe sinks and missing server checks." },
  { step: "2. Test", detail: "Execute safe exploit payloads against the isolated Python HTTP and SQLite sandbox." },
  { step: "3. Fix", detail: "Apply parameterized SQL, output escaping, RBAC gates, scrypt hashing, and security headers." },
  { step: "4. Document", detail: "Record observed evidence, CVSS-aligned severity, and export a walkthrough report." },
];

export function OverviewPage({ findings, states, onNavigate }: OverviewPageProps) {
  const progress = calculateLabProgress(findings, states);
  const findingsById = new Map(findings.map((f) => [f.module_id, f]));

  return (
    <main className="max-w-6xl mx-auto px-6 py-10 space-y-12">
      {/* Hero + Key Objectives matching syllabus screenshot */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
        <div className="lg:col-span-5 space-y-6">
          <p className="text-sm font-medium text-[#881337]">
            Python · JavaScript · HTML · CSS Security Sandbox
          </p>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-slate-900 leading-tight">
            Secure Web Application Lab &amp; OWASP Top 10 Workbench
          </h1>
          <p className="text-base text-slate-600 leading-relaxed">
            Explore how HTTP requests, cookies, and sessions operate across a live Python backend and browser frontend—then identify, exploit, patch, and document OWASP Top 10 vulnerabilities in a safe sandbox.
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              type="button"
              onClick={() => onNavigate("/owasp-lab")}
              className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B] transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#881337]"
            >
              Start OWASP Lab
              <ArrowRight className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={() => onNavigate("/http-lifecycle")}
              className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#881337]"
            >
              Inspect HTTP &amp; Cookies
            </button>
          </div>

          <div className="pt-4 border-t border-slate-200 grid grid-cols-3 gap-4 tabular-nums">
            <div>
              <p className="text-xs text-slate-500">Lab Progress</p>
              <p className="text-2xl font-bold text-slate-900 mt-0.5">{progress.completionPercent}%</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Modules Patched</p>
              <p className="text-2xl font-bold text-slate-900 mt-0.5">
                {progress.patchedLiveCount}/{progress.totalModules}
              </p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Documented</p>
              <p className="text-2xl font-bold text-slate-900 mt-0.5">
                {progress.documentedCount}/{progress.totalModules}
              </p>
            </div>
          </div>
        </div>

        {/* Key Objectives Panel matching attached reference screenshot */}
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-6 sm:p-8 shadow-xs">
          <div className="flex items-center gap-2.5 mb-6">
            <CheckSquare className="w-4 h-4 text-[#881337]" aria-hidden="true" />
            <h2 className="text-sm font-bold tracking-wider uppercase text-slate-600">
              Key Objectives
            </h2>
          </div>

          <ol className="space-y-5">
            {KEY_OBJECTIVES.map((obj) => (
              <li
                key={obj.number}
                className="flex items-start gap-4 pb-5 border-b border-slate-100 last:border-b-0 last:pb-0"
              >
                <span
                  aria-hidden="true"
                  className="w-8 h-8 rounded-full bg-slate-100 border border-slate-200 text-[#881337] font-bold text-sm flex items-center justify-center shrink-0 tabular-nums mt-0.5"
                >
                  {obj.number}
                </span>
                <div className="flex-1 min-w-0 space-y-2">
                  <p className="text-base text-slate-800 leading-relaxed font-medium">
                    {obj.text}
                  </p>
                  <button
                    type="button"
                    onClick={() => onNavigate(obj.targetRoute)}
                    className="inline-flex items-center gap-1.5 text-sm font-semibold text-[#881337] hover:underline focus-visible:outline-2 focus-visible:outline-[#881337]"
                  >
                    {obj.targetLabel}
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* Lab Workflow Strip */}
      <section aria-labelledby="methodology-heading" className="space-y-4">
        <div className="flex flex-wrap items-baseline justify-between gap-4">
          <h2 id="methodology-heading" className="text-xl font-bold text-slate-900">
            Secure Web Application Lab Workflow
          </h2>
          <p className="text-sm text-slate-500">
            Posture: <span className="font-semibold text-slate-800">{progress.postureLabel}</span>
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {METHODOLOGY_STEPS.map((item) => (
            <div key={item.step} className="bg-white border border-slate-200 rounded-xl p-5 space-y-2">
              <h3 className="text-base font-bold text-slate-900">{item.step}</h3>
              <p className="text-sm text-slate-600 leading-relaxed">{item.detail}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Live Sandbox Modules Matrix */}
      <section aria-labelledby="modules-heading" className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h2 id="modules-heading" className="text-xl font-bold text-slate-900">
            Sandbox Modules &amp; Remediation Status
          </h2>
          <button
            type="button"
            onClick={() => onNavigate("/report")}
            className="text-sm font-semibold text-[#881337] hover:underline"
          >
            View Vulnerability Report &amp; Walkthrough
          </button>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50/70 text-xs font-semibold text-slate-600">
                  <th className="py-3 px-4">OWASP Module</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Sandbox State</th>
                  <th className="py-3 px-4 text-right">Checkpoints</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-sm">
                {OWASP_MODULES.map((mod) => {
                  const runtime = states[mod.id]?.mode ?? "vulnerable";
                  const f = findingsById.get(mod.id);
                  const doneCount =
                    (f?.identified ? 1 : 0) +
                    (f?.tested_exploit ? 1 : 0) +
                    (f?.applied_fix || runtime === "patched" ? 1 : 0) +
                    (f?.documented ? 1 : 0);

                  return (
                    <tr key={mod.id} className="hover:bg-slate-50/60 transition-colors">
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-slate-900">{mod.title}</div>
                        <div className="text-xs text-slate-500 mt-0.5">
                          {mod.owaspCode} · {mod.cwe}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 text-slate-700 font-medium">
                        {f?.severity ?? mod.defaultSeverity}
                      </td>
                      <td className="py-3.5 px-4">
                        {runtime === "patched" ? (
                          <span className="inline-flex items-center gap-1.5 font-medium text-emerald-700">
                            <ShieldCheck className="w-4 h-4 shrink-0" aria-hidden="true" />
                            Patched
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 font-medium text-rose-700">
                            <ShieldAlert className="w-4 h-4 shrink-0" aria-hidden="true" />
                            Vulnerable
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-right font-mono tabular-nums text-slate-700">
                        {doneCount}/4
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          type="button"
                          onClick={() => onNavigate("/owasp-lab", mod.id)}
                          className="inline-flex items-center gap-1 text-sm font-semibold text-[#881337] hover:underline"
                        >
                          {doneCount === 4 ? (
                            <>
                              <CheckCircle2 className="w-4 h-4" aria-hidden="true" />
                              Review
                            </>
                          ) : (
                            "Open Lab"
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </main>
  );
}
