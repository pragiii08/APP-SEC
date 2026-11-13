import test from "node:test";
import assert from "node:assert/strict";
import {
  calculateLabProgress,
  evaluateCookieSecurity,
  generateMarkdownReport,
  normalizeRoute,
  OWASP_MODULES,
  type FindingRecord,
  type ModuleRuntimeState,
  type OwaspModuleId,
} from "./labLogic";

test("normalizeRoute maps supported multipage routes and strips trailing slashes/queries", () => {
  assert.equal(normalizeRoute("/"), "/");
  assert.equal(normalizeRoute("/http-lifecycle"), "/http-lifecycle");
  assert.equal(normalizeRoute("/owasp-lab/?autostart=1"), "/owasp-lab");
  assert.equal(normalizeRoute("/report/"), "/report");
  assert.equal(normalizeRoute("/unknown-path"), "/");
});

test("evaluateCookieSecurity reports Hardened when all flags and RBAC are enabled", () => {
  const result = evaluateCookieSecurity({
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    enforceRbac: true,
  });
  assert.equal(result.status, "Hardened");
  assert.equal(result.warnings.length, 0);
  assert.equal(result.protections.length, 4);
});

test("evaluateCookieSecurity flags missing HttpOnly, SameSite=None, and disabled RBAC", () => {
  const result = evaluateCookieSecurity({
    httpOnly: false,
    secure: true,
    sameSite: "None",
    enforceRbac: false,
  });
  assert.equal(result.status, "At Risk");
  assert.equal(result.warnings.length, 3);
  assert.ok(result.warnings.some((w) => w.includes("HttpOnly")));
  assert.ok(result.warnings.some((w) => w.includes("SameSite=None")));
  assert.ok(result.warnings.some((w) => w.includes("RBAC")));
});

test("calculateLabProgress tracks milestones and posture transitions accurately", () => {
  const baseFindings: FindingRecord[] = OWASP_MODULES.map((m) => ({
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

  const emptyStates: Record<OwaspModuleId, ModuleRuntimeState> = {
    sqli: { mode: "vulnerable", failedAttempts: 0 },
    xss: { mode: "vulnerable", failedAttempts: 0 },
    idor: { mode: "vulnerable", failedAttempts: 0 },
    auth: { mode: "vulnerable", failedAttempts: 0 },
    misconfig: { mode: "vulnerable", failedAttempts: 0 },
  };

  const initial = calculateLabProgress(baseFindings, emptyStates);
  assert.equal(initial.completionPercent, 0);
  assert.equal(initial.postureLabel, "Baseline Vulnerable");

  // Patch sqli and complete its 4 steps
  baseFindings[0].identified = 1;
  baseFindings[0].tested_exploit = 1;
  baseFindings[0].applied_fix = 1;
  baseFindings[0].documented = 1;
  emptyStates.sqli.mode = "patched";

  const mid = calculateLabProgress(baseFindings, emptyStates);
  assert.equal(mid.patchedLiveCount, 1);
  assert.equal(mid.completionPercent, 20);
  assert.equal(mid.postureLabel, "Remediation In Progress");

  // Patch all modules
  for (const k of Object.keys(emptyStates) as Array<keyof typeof emptyStates>) {
    emptyStates[k].mode = "patched";
  }
  const hardened = calculateLabProgress(baseFindings, emptyStates);
  assert.equal(hardened.patchedLiveCount, 5);
  assert.equal(hardened.postureLabel, "Hardened");
});

test("generateMarkdownReport includes analyst name, evidence, and all OWASP modules", () => {
  const findings: FindingRecord[] = OWASP_MODULES.map((m) => ({
    module_id: m.id,
    identified: m.id === "sqli" ? 1 : 0,
    tested_exploit: m.id === "sqli" ? 1 : 0,
    applied_fix: m.id === "sqli" ? 1 : 0,
    documented: m.id === "sqli" ? 1 : 0,
    severity: m.defaultSeverity,
    analyst_notes: m.id === "sqli" ? "Confirmed UNION leak on /py/lab/sqli." : "",
    evidence_summary: m.id === "sqli" ? "Payload ' OR '1'='1 returned 4 rows." : "",
    remediation_notes: "",
    updated_at: "",
  }));
  const states = {
    sqli: { mode: "patched" as const, failedAttempts: 0 },
    xss: { mode: "vulnerable" as const, failedAttempts: 0 },
    idor: { mode: "vulnerable" as const, failedAttempts: 0 },
    auth: { mode: "vulnerable" as const, failedAttempts: 0 },
    misconfig: { mode: "vulnerable" as const, failedAttempts: 0 },
  };

  const md = generateMarkdownReport(findings, states, "Alex Rivera");
  assert.ok(md.includes("Alex Rivera"));
  assert.ok(md.includes("SQL Injection (SQLi)"));
  assert.ok(md.includes("Remediated (Patched)"));
  assert.ok(md.includes("Payload ' OR '1'='1 returned 4 rows."));
  assert.ok(md.includes("## 3. Demo Walkthrough Outline"));
});
