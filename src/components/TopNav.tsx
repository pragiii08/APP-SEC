import { Menu, X } from "lucide-react";
import { useState } from "react";
import type { PageRoute } from "../utils/labLogic";

interface TopNavProps {
  currentRoute: PageRoute;
  onNavigate: (route: PageRoute) => void;
  onResetSandbox: () => void;
  isResetting: boolean;
}

const NAV_ITEMS: { route: PageRoute; label: string }[] = [
  { route: "/", label: "Overview" },
  { route: "/http-lifecycle", label: "HTTP & Auth" },
  { route: "/owasp-lab", label: "OWASP Lab" },
  { route: "/report", label: "Report" },
];

export function TopNav({ currentRoute, onNavigate, onResetSandbox, isResetting }: TopNavProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleNavClick = (e: React.MouseEvent<HTMLAnchorElement>, route: PageRoute) => {
    e.preventDefault();
    setMobileOpen(false);
    onNavigate(route);
  };

  return (
    <header className="sticky top-0 z-30 bg-white/95 backdrop-blur border-b border-slate-200">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between gap-8">
        {/* Zone 1: Single-line brand wordmark */}
        <a
          href="/"
          onClick={(e) => handleNavClick(e, "/")}
          className="text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#881337]"
        >
          AppSec Lab
        </a>

        {/* Zone 2: 4 single-line navigation links */}
        <nav aria-label="Primary navigation" className="hidden md:flex items-center gap-6">
          {NAV_ITEMS.map((item) => {
            const active = currentRoute === item.route;
            return (
              <a
                key={item.route}
                href={item.route}
                onClick={(e) => handleNavClick(e, item.route)}
                aria-current={active ? "page" : undefined}
                className={`py-1 text-sm font-medium whitespace-nowrap shrink-0 border-b-2 transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#881337] ${
                  active
                    ? "text-[#881337] border-[#881337]"
                    : "text-slate-600 border-transparent hover:text-slate-900 hover:border-slate-300"
                }`}
              >
                {item.label}
              </a>
            );
          })}
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          {currentRoute === "/" ? (
            <button
              type="button"
              onClick={() => onNavigate("/owasp-lab")}
              className="hidden sm:inline-flex items-center justify-center px-4 py-2 text-sm font-medium text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B] transition-colors duration-150 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#881337]"
            >
              Launch Lab
            </button>
          ) : (
            <button
              type="button"
              onClick={onResetSandbox}
              disabled={isResetting}
              className="hidden sm:inline-flex items-center justify-center px-4 py-2 text-sm font-medium text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B] disabled:opacity-60 transition-colors duration-150 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#881337]"
            >
              {isResetting ? "Resetting..." : "Reset Sandbox"}
            </button>
          )}

          <button
            type="button"
            onClick={() => setMobileOpen((prev) => !prev)}
            aria-label={mobileOpen ? "Close navigation menu" : "Open navigation menu"}
            aria-expanded={mobileOpen}
            className="md:hidden inline-flex items-center justify-center w-10 h-10 rounded-lg border border-slate-200 text-slate-700 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-[#881337]"
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {mobileOpen && (
        <nav
          aria-label="Mobile navigation"
          className="md:hidden border-t border-slate-200 bg-white px-6 py-4 space-y-2"
        >
          {NAV_ITEMS.map((item) => {
            const active = currentRoute === item.route;
            return (
              <a
                key={item.route}
                href={item.route}
                onClick={(e) => handleNavClick(e, item.route)}
                aria-current={active ? "page" : undefined}
                className={`block py-2.5 px-3 rounded-lg text-sm font-medium transition-colors ${
                  active
                    ? "bg-[#881337]/10 text-[#881337]"
                    : "text-slate-700 hover:bg-slate-100"
                }`}
              >
                {item.label}
              </a>
            );
          })}
          <div className="pt-2 border-t border-slate-100">
            <button
              type="button"
              onClick={() => {
                setMobileOpen(false);
                if (currentRoute === "/") onNavigate("/owasp-lab");
                else onResetSandbox();
              }}
              className="w-full py-2.5 px-4 text-sm font-medium text-white bg-[#881337] rounded-lg hover:bg-[#6B0F2B]"
            >
              {currentRoute === "/" ? "Launch Lab" : "Reset Sandbox"}
            </button>
          </div>
        </nav>
      )}
    </header>
  );
}
