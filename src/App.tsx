import { useCallback, useEffect, useState } from "react";
import { TopNav } from "./components/TopNav";
import { HttpLifecyclePage } from "./pages/HttpLifecyclePage";
import { OverviewPage } from "./pages/OverviewPage";
import { OwaspLabPage } from "./pages/OwaspLabPage";
import { ReportPage } from "./pages/ReportPage";
import { fetchLabState, resetSandbox } from "./utils/api";
import {
  normalizeRoute,
  OWASP_MODULES,
  type FindingRecord,
  type ModuleRuntimeState,
  type OwaspModuleId,
  type PageRoute,
} from "./utils/labLogic";

const DEFAULT_STATES: Record<OwaspModuleId, ModuleRuntimeState> = {
  sqli: { mode: "vulnerable", failedAttempts: 0 },
  xss: { mode: "vulnerable", failedAttempts: 0 },
  idor: { mode: "vulnerable", failedAttempts: 0 },
  auth: { mode: "vulnerable", failedAttempts: 0 },
  misconfig: { mode: "vulnerable", failedAttempts: 0 },
};

const DEFAULT_FINDINGS: FindingRecord[] = OWASP_MODULES.map((m) => ({
  module_id: m.id,
  identified: 0,
  tested_exploit: 0,
  applied_fix: 0,
  documented: 0,
  severity: m.defaultSeverity,
  analyst_notes: "",
  evidence_summary: "",
  remediation_notes: "",
  updated_at: "",
}));

export default function App() {
  const [route, setRoute] = useState<PageRoute>(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("autostart") === "1") return "/owasp-lab";
    return normalizeRoute(window.location.pathname);
  });
  const [selectedModule, setSelectedModule] = useState<OwaspModuleId>("sqli");
  const [states, setStates] = useState<Record<OwaspModuleId, ModuleRuntimeState>>(DEFAULT_STATES);
  const [findings, setFindings] = useState<FindingRecord[]>(DEFAULT_FINDINGS);
  const [isLoading, setIsLoading] = useState(true);
  const [isResetting, setIsResetting] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const refreshState = useCallback(async () => {
    try {
      const data = await fetchLabState();
      setStates(data.states);
      setFindings(data.findings);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Could not reach Python sandbox server");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshState();
  }, [refreshState]);

  useEffect(() => {
    const onPopState = () => {
      setRoute(normalizeRoute(window.location.pathname));
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = useCallback((nextRoute: PageRoute, moduleId?: string) => {
    if (moduleId && OWASP_MODULES.some((m) => m.id === moduleId)) {
      setSelectedModule(moduleId as OwaspModuleId);
    }
    if (window.location.pathname !== nextRoute) {
      window.history.pushState({}, "", nextRoute);
    }
    setRoute(nextRoute);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const handleResetSandbox = async () => {
    setIsResetting(true);
    try {
      await resetSandbox();
      await refreshState();
    } finally {
      setIsResetting(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#F8FAFC] text-[#1E293B]">
      <TopNav
        currentRoute={route}
        onNavigate={(next) => navigate(next)}
        onResetSandbox={handleResetSandbox}
        isResetting={isResetting}
      />

      {loadError && (
        <div role="alert" className="max-w-6xl mx-auto w-full px-6 pt-6">
          <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900 flex items-center justify-between gap-4">
            <span>Sandbox sync notice: {loadError}</span>
            <button
              type="button"
              onClick={refreshState}
              className="font-semibold underline shrink-0"
            >
              Retry
            </button>
          </div>
        </div>
      )}

      <div className="flex-1">
        {isLoading ? (
          <div className="max-w-6xl mx-auto px-6 py-12 space-y-6" aria-busy="true">
            <div className="h-8 w-72 bg-slate-200 rounded animate-pulse" />
            <div className="h-64 w-full bg-slate-200/70 rounded-xl animate-pulse" />
          </div>
        ) : route === "/" ? (
          <OverviewPage
            findings={findings}
            states={states}
            onNavigate={(next, modId) => navigate(next, modId)}
          />
        ) : route === "/http-lifecycle" ? (
          <HttpLifecyclePage />
        ) : route === "/owasp-lab" ? (
          <OwaspLabPage
            selectedModule={selectedModule}
            onSelectModule={setSelectedModule}
            states={states}
            findings={findings}
            onRefreshState={refreshState}
            onGoToReport={() => navigate("/report")}
          />
        ) : (
          <ReportPage
            findings={findings}
            states={states}
            onOpenModule={(modId) => navigate("/owasp-lab", modId)}
          />
        )}
      </div>

      <footer className="border-t border-slate-200 bg-white mt-12">
        <div className="max-w-6xl mx-auto px-6 py-6 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-500">
          <span>AppSec Lab · Safe Python, JavaScript, HTML &amp; CSS Educational Sandbox</span>
          <div className="flex items-center gap-4">
            <a
              href="/"
              onClick={(e) => {
                e.preventDefault();
                navigate("/");
              }}
              className="hover:text-slate-900"
            >
              Overview
            </a>
            <a
              href="/http-lifecycle"
              onClick={(e) => {
                e.preventDefault();
                navigate("/http-lifecycle");
              }}
              className="hover:text-slate-900"
            >
              HTTP &amp; Auth
            </a>
            <a
              href="/owasp-lab"
              onClick={(e) => {
                e.preventDefault();
                navigate("/owasp-lab");
              }}
              className="hover:text-slate-900"
            >
              OWASP Lab
            </a>
            <a
              href="/report"
              onClick={(e) => {
                e.preventDefault();
                navigate("/report");
              }}
              className="hover:text-slate-900"
            >
              Report
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
