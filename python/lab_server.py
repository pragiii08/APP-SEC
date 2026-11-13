#!/usr/bin/env python3
"""
AppSec Lab — Real Python HTTP & SQLite Security Sandbox Server.
Uses Python 3 standard library only (http.server, sqlite3, html, hashlib, hmac, secrets).
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import sys
import time
import traceback

DB_PATH = os.environ.get("APPSEC_DB_PATH", "/tmp/appsec_lab_sandbox.db")
PORT = int(os.environ.get("APPSEC_PY_PORT", "5051"))
START_TIME = time.time()

SEED_USERS = [
    (1, "alice", "alice123", "analyst", "alice@sandbox.local", "$94,000", "Q4 SOC rotation schedule"),
    (2, "bob", "hunter2", "analyst", "bob@sandbox.local", "$98,500", "API token backup: tok_live_9821a"),
    (3, "carol", "Summer2026!", "manager", "carol@sandbox.local", "$132,000", "Audit signoff key: key_mgr_44b"),
    (4, "admin", "Sup3rS3cur3!99", "admin", "admin@sandbox.local", "$165,000", "Root vault seed: vault_9910_root"),
]

SEED_RECORDS = [
    (101, 1, "Alice Incident Triage Notes", "INTERNAL", "Reviewed 14 WAF alerts from edge proxy; 2 false positives cleared."),
    (102, 2, "Bob Payroll & Direct Deposit", "CONFIDENTIAL", "Account ending 4821 · Annual base $98,500 · Performance bonus 12%."),
    (103, 3, "Carol Vendor Security Assessment", "RESTRICTED", "Third-party SSO integration findings and renewal terms."),
    (104, 4, "Root Signing Key Rotation Plan", "TOP SECRET", "Primary KMS key rotation scheduled; emergency break-glass procedure."),
]

SEED_COMMENTS = [
    (1, "alice", "Verified TLS certificate chain on staging gateway.", "Verified TLS certificate chain on staging gateway.", "patched", "2026-11-12T09:15:00Z"),
    (2, "carol", "Remember to escape all user-submitted notes before rendering.", "Remember to escape all user-submitted notes before rendering.", "patched", "2026-11-12T10:30:00Z"),
]

MODULES = ["sqli", "xss", "idor", "auth", "misconfig"]


def md5_unsalted(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def scrypt_salted(password: str, salt_hex: str | None = None) -> str:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_scrypt(password: str, stored: str) -> bool:
    try:
        _, salt_hex, hash_hex = stored.split("$", 2)
        candidate = scrypt_salted(password, salt_hex)
        return hmac.compare_digest(candidate, stored)
    except Exception:
        return False


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(reset: bool = False) -> None:
    conn = get_conn()
    cur = conn.cursor()
    if reset:
        for tbl in ("users", "records", "comments", "sessions", "lab_state", "findings"):
            cur.execute(f"DROP TABLE IF EXISTS {tbl}")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            md5_hash TEXT NOT NULL,
            scrypt_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL,
            salary TEXT NOT NULL,
            api_note TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            classification TEXT NOT NULL,
            content TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            body_raw TEXT NOT NULL,
            body_escaped TEXT NOT NULL,
            mode TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            httponly INTEGER NOT NULL,
            secure INTEGER NOT NULL,
            samesite TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS lab_state (
            module_id TEXT PRIMARY KEY,
            mode TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            module_id TEXT PRIMARY KEY,
            identified INTEGER NOT NULL DEFAULT 0,
            tested_exploit INTEGER NOT NULL DEFAULT 0,
            applied_fix INTEGER NOT NULL DEFAULT 0,
            documented INTEGER NOT NULL DEFAULT 0,
            severity TEXT NOT NULL DEFAULT 'High',
            analyst_notes TEXT NOT NULL DEFAULT '',
            evidence_summary TEXT NOT NULL DEFAULT '',
            remediation_notes TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        )
    """)

    existing_users = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing_users == 0:
        for uid, uname, pw, role, email, salary, api_note in SEED_USERS:
            cur.execute(
                "INSERT INTO users (id, username, md5_hash, scrypt_hash, role, email, salary, api_note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (uid, uname, md5_unsalted(pw), scrypt_salted(pw), role, email, salary, api_note),
            )
        for rid, owner_id, title, classification, content in SEED_RECORDS:
            cur.execute(
                "INSERT INTO records (id, owner_id, title, classification, content) VALUES (?, ?, ?, ?, ?)",
                (rid, owner_id, title, classification, content),
            )
        for cid, author, raw_b, esc_b, mode, ts in SEED_COMMENTS:
            cur.execute(
                "INSERT INTO comments (id, author, body_raw, body_escaped, mode, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (cid, author, raw_b, esc_b, mode, ts),
            )
        for mod in MODULES:
            cur.execute(
                "INSERT OR IGNORE INTO lab_state (module_id, mode, failed_attempts) VALUES (?, 'vulnerable', 0)",
                (mod,),
            )
            cur.execute(
                "INSERT OR IGNORE INTO findings (module_id, identified, tested_exploit, applied_fix, documented, severity, analyst_notes, evidence_summary, remediation_notes, updated_at) VALUES (?, 0, 0, 0, 0, ?, '', '', '', '')",
                (mod, "Critical" if mod in ("sqli", "idor") else "High"),
            )

    conn.commit()
    conn.close()


def detect_xss_vectors(payload: str) -> list[str]:
    patterns = [
        (r"<\s*script\b", "<script> tag execution"),
        (r"\bon\w+\s*=", "Inline DOM event handler (onerror/onload/etc.)"),
        (r"javascript\s*:", "javascript: URI scheme"),
        (r"<\s*(svg|iframe|img|body)\b", "Injectable HTML element vector"),
    ]
    found = []
    for regex, label in patterns:
        if re.search(regex, payload, re.IGNORECASE):
            found.append(label)
    return found


def get_module_mode(conn: sqlite3.Connection, module_id: str, override_mode: str | None = None) -> str:
    if override_mode in ("vulnerable", "patched"):
        return override_mode
    row = conn.execute("SELECT mode FROM lab_state WHERE module_id = ?", (module_id,)).fetchone()
    return row["mode"] if row else "vulnerable"


class LabHandler(BaseHTTPRequestHandler):
    server_version = "AppSecLabPython/3.10"

    def log_message(self, format: str, *args) -> None:
        # Quiet clean stdout logging
        pass

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _send_json(self, status: int, data: dict, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/py/health":
            conn = get_conn()
            states = {r["module_id"]: r["mode"] for r in conn.execute("SELECT module_id, mode FROM lab_state").fetchall()}
            conn.close()
            self._send_json(200, {
                "ok": True,
                "pythonVersion": sys.version.split()[0],
                "sqliteVersion": sqlite3.sqlite_version,
                "uptimeSeconds": round(time.time() - START_TIME, 1),
                "modules": states,
            })
            return

        if path == "/py/lab/state":
            conn = get_conn()
            states = {
                r["module_id"]: {"mode": r["mode"], "failedAttempts": r["failed_attempts"]}
                for r in conn.execute("SELECT module_id, mode, failed_attempts FROM lab_state").fetchall()
            }
            comments = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, author, body_raw, body_escaped, mode, created_at FROM comments ORDER BY id DESC LIMIT 12"
                ).fetchall()
            ]
            findings = [dict(r) for r in conn.execute("SELECT * FROM findings").fetchall()]
            conn.close()
            self._send_json(200, {
                "ok": True,
                "states": states,
                "comments": comments,
                "findings": findings,
            })
            return

        if path == "/py/findings":
            conn = get_conn()
            findings = [dict(r) for r in conn.execute("SELECT * FROM findings").fetchall()]
            conn.close()
            self._send_json(200, {"ok": True, "findings": findings})
            return

        self._send_json(404, {"ok": False, "error": f"Unknown endpoint: {path}"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        payload = self._read_json()

        if path == "/py/reset":
            init_db(reset=True)
            self._send_json(200, {"ok": True, "message": "Sandbox database and lab states reset to baseline."})
            return

        if path == "/py/lab/mode":
            module_id = payload.get("moduleId", "")
            mode = payload.get("mode", "vulnerable")
            if module_id not in MODULES or mode not in ("vulnerable", "patched"):
                self._send_json(400, {"ok": False, "error": "Invalid moduleId or mode."})
                return
            conn = get_conn()
            conn.execute("UPDATE lab_state SET mode = ?, failed_attempts = 0 WHERE module_id = ?", (mode, module_id))
            if mode == "patched":
                conn.execute("UPDATE findings SET applied_fix = 1 WHERE module_id = ?", (module_id,))
            conn.commit()
            conn.close()
            self._send_json(200, {"ok": True, "moduleId": module_id, "mode": mode})
            return

        if path == "/py/findings":
            module_id = payload.get("moduleId", "")
            if module_id not in MODULES:
                self._send_json(400, {"ok": False, "error": "Invalid moduleId."})
                return
            conn = get_conn()
            conn.execute(
                """
                UPDATE findings
                SET identified = COALESCE(?, identified),
                    tested_exploit = COALESCE(?, tested_exploit),
                    applied_fix = COALESCE(?, applied_fix),
                    documented = COALESCE(?, documented),
                    severity = COALESCE(?, severity),
                    analyst_notes = COALESCE(?, analyst_notes),
                    evidence_summary = COALESCE(?, evidence_summary),
                    remediation_notes = COALESCE(?, remediation_notes),
                    updated_at = ?
                WHERE module_id = ?
                """,
                (
                    payload.get("identified"),
                    payload.get("testedExploit"),
                    payload.get("appliedFix"),
                    payload.get("documented"),
                    payload.get("severity"),
                    payload.get("analystNotes"),
                    payload.get("evidenceSummary"),
                    payload.get("remediationNotes"),
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    module_id,
                ),
            )
            conn.commit()
            row = dict(conn.execute("SELECT * FROM findings WHERE module_id = ?", (module_id,)).fetchone())
            conn.close()
            self._send_json(200, {"ok": True, "finding": row})
            return

        if path == "/py/http-sim/request":
            self._handle_http_sim(payload)
            return

        if path == "/py/lab/sqli":
            self._handle_sqli(payload)
            return

        if path == "/py/lab/xss":
            self._handle_xss(payload)
            return

        if path == "/py/lab/idor":
            self._handle_idor(payload)
            return

        if path == "/py/lab/auth":
            self._handle_auth(payload)
            return

        if path == "/py/lab/misconfig":
            self._handle_misconfig(payload)
            return

        self._send_json(404, {"ok": False, "error": f"Unknown endpoint: {path}"})

    def _handle_http_sim(self, payload: dict) -> None:
        action = payload.get("action", "login")
        role = payload.get("role", "analyst")
        http_only = bool(payload.get("httpOnly", True))
        secure = bool(payload.get("secure", True))
        same_site = payload.get("sameSite", "Strict")
        if same_site not in ("Strict", "Lax", "None"):
            same_site = "Strict"
        enforce_rbac = bool(payload.get("enforceRbac", True))
        has_session = bool(payload.get("hasSession", True))
        username = str(payload.get("username", "alice" if role != "admin" else "admin"))
        session_token = str(payload.get("sessionToken", "")) or f"sid_{secrets.token_hex(12)}"

        cookie_parts = [f"session_id={session_token}", "Path=/", "Max-Age=3600"]
        if http_only:
            cookie_parts.append("HttpOnly")
        if secure:
            cookie_parts.append("Secure")
        cookie_parts.append(f"SameSite={same_site}")
        set_cookie_header = "; ".join(cookie_parts)

        req_lines = []
        resp_status = 200
        resp_reason = "OK"
        resp_headers = {
            "Server": "AppSecLabPython/3.10",
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
        }
        body_out = {}
        verdict = "secure"
        summary = ""

        if action == "login":
            req_body = json.dumps({"username": username, "password": "********", "role": role})
            req_lines = [
                "POST /py/session/login HTTP/1.1",
                "Host: sandbox.appseclab.local",
                "Content-Type: application/json",
                f"Content-Length: {len(req_body)}",
                "",
                req_body,
            ]
            resp_headers["Set-Cookie"] = set_cookie_header
            if not http_only or not secure or same_site == "None":
                verdict = "vulnerable"
                missing = []
                if not http_only:
                    missing.append("HttpOnly")
                if not secure:
                    missing.append("Secure")
                if same_site == "None":
                    missing.append("SameSite=Lax/Strict")
                summary = f"Session issued, but cookie lacks {', '.join(missing)} — exposed to theft or CSRF."
            else:
                summary = "Session cookie issued with HttpOnly, Secure, and SameSite=Strict protections."
            body_out = {
                "authenticated": True,
                "user": username,
                "role": role,
                "sessionToken": session_token,
                "cookiePolicy": {"httpOnly": http_only, "secure": secure, "sameSite": same_site},
            }

        elif action == "fetch_profile":
            cookie_hdr = f"session_id={session_token}" if has_session else "(none)"
            req_lines = [
                "GET /py/account/profile HTTP/1.1",
                "Host: sandbox.appseclab.local",
                f"Cookie: {cookie_hdr}",
                "Accept: application/json",
            ]
            if not has_session:
                resp_status, resp_reason = 401, "Unauthorized"
                verdict = "secure"
                summary = "Unauthenticated request rejected with 401 Unauthorized because no valid session cookie was sent."
                body_out = {"error": "Authentication required", "code": "NO_SESSION_COOKIE"}
            else:
                verdict = "secure"
                summary = f"Valid session cookie verified for '{username}' ({role}); profile payload returned."
                body_out = {"username": username, "role": role, "sessionVerified": True}

        elif action == "admin_export":
            cookie_hdr = f"session_id={session_token}" if has_session else "(none)"
            req_lines = [
                "POST /py/admin/export-users HTTP/1.1",
                "Host: sandbox.appseclab.local",
                f"Cookie: {cookie_hdr}",
                f"X-Claimed-Role: {role}",
            ]
            if not has_session:
                resp_status, resp_reason = 401, "Unauthorized"
                verdict = "secure"
                summary = "Blocked: missing session cookie cannot reach privileged admin export."
                body_out = {"error": "Unauthorized"}
            elif role != "admin" and enforce_rbac:
                resp_status, resp_reason = 403, "Forbidden"
                verdict = "secure"
                summary = f"RBAC Enforced: authenticated user '{username}' (role={role}) denied access to admin export (403 Forbidden)."
                body_out = {"error": "Forbidden: admin role required", "actualRole": role}
            elif role != "admin" and not enforce_rbac:
                resp_status, resp_reason = 200, "OK"
                verdict = "vulnerable"
                summary = f"Broken Access Control: server trusted session without role check; '{role}' exported all admin records!"
                body_out = {"warning": "PRIVILEGE ESCALATION", "exportedRecords": 4, "actorRole": role}
            else:
                resp_status, resp_reason = 200, "OK"
                verdict = "secure"
                summary = "Authorized admin session verified server-side; audit export succeeded."
                body_out = {"exportedRecords": 4, "actorRole": "admin"}

        elif action == "xss_cookie_read":
            req_lines = [
                "GET /sandbox/xss-probe HTTP/1.1",
                "Host: sandbox.appseclab.local",
                "Script-Probe: document.cookie",
            ]
            if http_only:
                resp_status, resp_reason = 200, "OK"
                verdict = "secure"
                summary = "HttpOnly flag blocked JavaScript from reading session_id via document.cookie."
                body_out = {"documentCookie": "", "sessionExposed": False, "mitigation": "HttpOnly"}
            else:
                resp_status, resp_reason = 200, "OK"
                verdict = "vulnerable"
                summary = "HttpOnly is disabled! Any XSS payload can exfiltrate session_id via document.cookie."
                body_out = {"documentCookie": f"session_id={session_token}", "sessionExposed": True}

        elif action == "csrf_transfer":
            req_lines = [
                "POST /py/account/transfer HTTP/1.1",
                "Host: sandbox.appseclab.local",
                "Origin: https://evil-thirdparty.example",
                f"Cookie: session_id={session_token}" if same_site == "None" else "(Cookie withheld by browser SameSite policy)",
            ]
            if same_site in ("Strict", "Lax"):
                resp_status, resp_reason = 403, "Forbidden"
                verdict = "secure"
                summary = f"SameSite={same_site} prevented cross-origin browser request from attaching session cookie."
                body_out = {"blocked": True, "reason": f"Cross-site cookie blocked by SameSite={same_site}"}
            else:
                resp_status, resp_reason = 200, "OK"
                verdict = "vulnerable"
                summary = "SameSite=None allowed cross-origin site to submit authenticated POST with your cookie!"
                body_out = {"blocked": False, "warning": "CSRF state change executed with victim cookie"}

        raw_resp_headers = [f"HTTP/1.1 {resp_status} {resp_reason}"]
        for k, v in resp_headers.items():
            raw_resp_headers.append(f"{k}: {v}")
        raw_resp_headers.append("")
        raw_resp_headers.append(json.dumps(body_out, indent=2))

        stages = [
            {"id": "client", "label": "1. Client Request", "detail": f"{action.replace('_', ' ').title()} initiated from browser"},
            {"id": "transport", "label": "2. Transport & Headers", "detail": "HTTPS + Cookie header transmitted" if secure else "Plain HTTP / insecure cookie flags"},
            {"id": "python", "label": "3. Python Handler", "detail": "LabHandler parses headers, cookies & JSON body"},
            {"id": "auth", "label": "4. Auth / RBAC Gate", "detail": f"Session={has_session} · Role={role} · RBAC={'On' if enforce_rbac else 'Off'}"},
            {"id": "response", "label": "5. HTTP Response", "detail": f"{resp_status} {resp_reason} · Verdict: {verdict.upper()}"},
        ]

        self._send_json(200, {
            "ok": True,
            "status": resp_status,
            "reason": resp_reason,
            "verdict": verdict,
            "summary": summary,
            "rawRequest": "\n".join(req_lines),
            "rawResponse": "\n".join(raw_resp_headers),
            "body": body_out,
            "stages": stages,
        })

    def _handle_sqli(self, payload: dict) -> None:
        query = str(payload.get("query", ""))
        conn = get_conn()
        mode = get_module_mode(conn, "sqli", payload.get("mode"))
        cur = conn.cursor()

        if mode == "vulnerable":
            sql_text = f"SELECT id, username, role, email, salary FROM users WHERE username = '{query}'"
            try:
                rows = [dict(r) for r in cur.execute(sql_text).fetchall()]
                exploited = len(rows) > 1 or any(r.get("username") != query for r in rows) or ("UNION" in query.upper() and len(rows) > 0)
                if exploited:
                    conn.execute("UPDATE findings SET identified = 1, tested_exploit = 1 WHERE module_id = 'sqli'")
                    conn.commit()
                conn.close()
                self._send_json(200, {
                    "ok": True,
                    "mode": "vulnerable",
                    "sqlExecuted": sql_text,
                    "parameters": [],
                    "rows": rows,
                    "exploited": exploited,
                    "statusLabel": "EXPLOIT SUCCEEDED — Unauthorized rows leaked" if exploited else "Normal query result (vulnerable interpolation active)",
                })
            except sqlite3.Error as err:
                conn.close()
                self._send_json(200, {
                    "ok": True,
                    "mode": "vulnerable",
                    "sqlExecuted": sql_text,
                    "parameters": [],
                    "rows": [],
                    "exploited": False,
                    "sqlError": str(err),
                    "statusLabel": f"SQL Syntax Error leaked: {err}",
                })
        else:
            sql_text = "SELECT id, username, role, email FROM users WHERE username = ?"
            rows = [dict(r) for r in cur.execute(sql_text, (query,)).fetchall()]
            conn.close()
            self._send_json(200, {
                "ok": True,
                "mode": "patched",
                "sqlExecuted": sql_text,
                "parameters": [query],
                "rows": rows,
                "exploited": False,
                "statusLabel": "BLOCKED — Parameterized query treated payload as literal text",
            })

    def _handle_xss(self, payload: dict) -> None:
        author = str(payload.get("author", "student"))[:40] or "student"
        comment = str(payload.get("comment", ""))
        conn = get_conn()
        mode = get_module_mode(conn, "xss", payload.get("mode"))

        escaped_author = html.escape(author, quote=True)
        escaped_comment = html.escape(comment, quote=True)
        vectors = detect_xss_vectors(comment)

        if mode == "vulnerable":
            rendered_html = f'<div class="comment-item"><strong>{author}</strong><p>{comment}</p></div>'
            exploited = len(vectors) > 0
            if exploited:
                conn.execute("UPDATE findings SET identified = 1, tested_exploit = 1 WHERE module_id = 'xss'")
            csp_header = "(none)"
            status_label = "EXPLOIT SUCCEEDED — Unescaped HTML/JS vector injected into DOM" if exploited else "Rendered raw HTML without escaping"
        else:
            rendered_html = f'<div class="comment-item"><strong>{escaped_author}</strong><p>{escaped_comment}</p></div>'
            exploited = False
            csp_header = "default-src 'self'; script-src 'self'; object-src 'none'"
            status_label = "BLOCKED — html.escape() neutralized markup and CSP restricted scripts"

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn.execute(
            "INSERT INTO comments (author, body_raw, body_escaped, mode, created_at) VALUES (?, ?, ?, ?, ?)",
            (escaped_author, comment, escaped_comment, mode, ts),
        )
        conn.commit()
        recent = [
            dict(r)
            for r in conn.execute("SELECT id, author, body_raw, body_escaped, mode, created_at FROM comments ORDER BY id DESC LIMIT 6").fetchall()
        ]
        conn.close()

        extra_headers = {}
        if mode == "patched":
            extra_headers["Content-Security-Policy"] = csp_header

        self._send_json(
            200,
            {
                "ok": True,
                "mode": mode,
                "renderedHtml": rendered_html,
                "vectorsDetected": vectors,
                "exploited": exploited,
                "cspHeader": csp_header,
                "comments": recent,
                "statusLabel": status_label,
            },
            extra_headers=extra_headers,
        )

    def _handle_idor(self, payload: dict) -> None:
        record_id = int(payload.get("recordId", 102))
        acting_user_id = int(payload.get("actingUserId", 1))
        acting_role = str(payload.get("actingRole", "analyst"))
        action = str(payload.get("action", "read_record"))

        conn = get_conn()
        mode = get_module_mode(conn, "idor", payload.get("mode"))

        if action == "admin_export":
            if mode == "vulnerable":
                rows = [dict(r) for r in conn.execute("SELECT id, owner_id, title, classification FROM records").fetchall()]
                exploited = acting_role != "admin"
                if exploited:
                    conn.execute("UPDATE findings SET identified = 1, tested_exploit = 1 WHERE module_id = 'idor'")
                    conn.commit()
                conn.close()
                self._send_json(200, {
                    "ok": True,
                    "httpStatus": 200,
                    "mode": "vulnerable",
                    "exploited": exploited,
                    "records": rows,
                    "statusLabel": "EXPLOIT SUCCEEDED — Missing role check allowed non-admin export" if exploited else "Admin export returned",
                })
                return
            else:
                conn.close()
                if acting_role != "admin":
                    self._send_json(200, {
                        "ok": True,
                        "httpStatus": 403,
                        "mode": "patched",
                        "exploited": False,
                        "records": [],
                        "statusLabel": "BLOCKED (403 Forbidden) — Server verified actingRole != 'admin'",
                    })
                    return
                conn = get_conn()
                rows = [dict(r) for r in conn.execute("SELECT id, owner_id, title, classification FROM records").fetchall()]
                conn.close()
                self._send_json(200, {
                    "ok": True,
                    "httpStatus": 200,
                    "mode": "patched",
                    "exploited": False,
                    "records": rows,
                    "statusLabel": "ALLOWED (200 OK) — Valid admin role verified server-side",
                })
                return

        row = conn.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
        if not row:
            conn.close()
            self._send_json(200, {"ok": True, "httpStatus": 404, "mode": mode, "exploited": False, "record": None, "statusLabel": "Record not found"})
            return

        record = dict(row)
        is_owner = record["owner_id"] == acting_user_id

        if mode == "vulnerable":
            exploited = not is_owner and acting_role != "admin"
            if exploited:
                conn.execute("UPDATE findings SET identified = 1, tested_exploit = 1 WHERE module_id = 'idor'")
                conn.commit()
            conn.close()
            self._send_json(200, {
                "ok": True,
                "httpStatus": 200,
                "mode": "vulnerable",
                "exploited": exploited,
                "record": record,
                "statusLabel": f"EXPLOIT SUCCEEDED (IDOR) — User #{acting_user_id} read User #{record['owner_id']}'s {record['classification']} record" if exploited else "Authorized own record read",
            })
        else:
            conn.close()
            if not is_owner and acting_role != "admin":
                self._send_json(200, {
                    "ok": True,
                    "httpStatus": 403,
                    "mode": "patched",
                    "exploited": False,
                    "record": None,
                    "statusLabel": f"BLOCKED (403 Forbidden) — Ownership check denied User #{acting_user_id} access to Record #{record_id}",
                })
            else:
                self._send_json(200, {
                    "ok": True,
                    "httpStatus": 200,
                    "mode": "patched",
                    "exploited": False,
                    "record": record,
                    "statusLabel": "ALLOWED (200 OK) — Server verified resource ownership",
                })

    def _handle_auth(self, payload: dict) -> None:
        username = str(payload.get("username", "alice"))
        password = str(payload.get("password", ""))
        attempt_count = int(payload.get("attemptCount", 1))

        conn = get_conn()
        mode = get_module_mode(conn, "auth", payload.get("mode"))
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if mode == "vulnerable":
            weak_hash = md5_unsalted(password)
            matched = bool(user and user["md5_hash"] == weak_hash)
            predictable_token = f"sess-{username}-0001"
            exploited = True  # Vulnerable auth leaks weak scheme / no lockout / predictable token
            conn.execute("UPDATE findings SET identified = 1, tested_exploit = 1 WHERE module_id = 'auth'")
            conn.commit()
            conn.close()
            self._send_json(200, {
                "ok": True,
                "httpStatus": 200 if matched else 401,
                "mode": "vulnerable",
                "authenticated": matched,
                "exploited": exploited,
                "hashSample": user["md5_hash"] if user else weak_hash,
                "hashAlgorithm": "Unsalted MD5 (32-char crackable)",
                "issuedToken": predictable_token if matched else "(none)",
                "rateLimited": False,
                "statusLabel": f"WEAK AUTH — Unsalted MD5, predictable token '{predictable_token}', and 0 rate-limit lockouts after {attempt_count} tries",
            })
        else:
            if attempt_count > 3:
                conn.close()
                self._send_json(200, {
                    "ok": True,
                    "httpStatus": 429,
                    "mode": "patched",
                    "authenticated": False,
                    "exploited": False,
                    "hashSample": user["scrypt_hash"][:44] + "..." if user else "scrypt$...",
                    "hashAlgorithm": "Salted scrypt (N=16384) + hmac.compare_digest",
                    "issuedToken": "(locked)",
                    "rateLimited": True,
                    "statusLabel": "BLOCKED (429 Too Many Requests) — Rate limiter locked brute-force attempts after 3 tries",
                })
                return

            matched = bool(user and verify_scrypt(password, user["scrypt_hash"]))
            strong_token = secrets.token_urlsafe(32) if matched else "(none)"
            conn.close()
            self._send_json(200, {
                "ok": True,
                "httpStatus": 200 if matched else 401,
                "mode": "patched",
                "authenticated": matched,
                "exploited": False,
                "hashSample": user["scrypt_hash"][:44] + "..." if user else "scrypt$...",
                "hashAlgorithm": "Salted scrypt (N=16384) + hmac.compare_digest",
                "issuedToken": strong_token,
                "rateLimited": False,
                "statusLabel": "SECURE AUTH — Salted scrypt + 256-bit cryptographic session token" if matched else "401 Unauthorized — Invalid credentials (attempt tracked for lockout)",
            })

    def _handle_misconfig(self, payload: dict) -> None:
        trigger_error = bool(payload.get("triggerError", True))
        conn = get_conn()
        mode = get_module_mode(conn, "misconfig", payload.get("mode"))

        if mode == "vulnerable":
            headers = {
                "Server": "Werkzeug/2.0.1 Python/3.10.12",
                "X-Debug-Mode": "True",
            }
            if trigger_error:
                try:
                    raise RuntimeError(f"Database cursor failed at {DB_PATH} (APP_SECRET=dev_secret_9912)")
                except RuntimeError:
                    tb = traceback.format_exc()
                conn.execute("UPDATE findings SET identified = 1, tested_exploit = 1 WHERE module_id = 'misconfig'")
                conn.commit()
                conn.close()
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "httpStatus": 500,
                        "mode": "vulnerable",
                        "exploited": True,
                        "responseHeaders": headers,
                        "responseBody": {
                            "error": "Internal Server Error",
                            "debug": True,
                            "dbPath": DB_PATH,
                            "traceback": tb.splitlines()[-5:],
                        },
                        "statusLabel": "EXPLOIT SUCCEEDED — Verbose stack trace, DB path, and missing CSP/X-Frame-Options headers exposed",
                    },
                )
            else:
                conn.close()
                self._send_json(200, {
                    "ok": True,
                    "httpStatus": 200,
                    "mode": "vulnerable",
                    "exploited": True,
                    "responseHeaders": headers,
                    "responseBody": {"status": "ok", "debugEnabled": True},
                    "statusLabel": "MISCONFIGURED — Security headers missing and server banner leaks stack version",
                })
        else:
            conn.close()
            headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            }
            self._send_json(
                200,
                {
                    "ok": True,
                    "httpStatus": 500 if trigger_error else 200,
                    "mode": "patched",
                    "exploited": False,
                    "responseHeaders": headers,
                    "responseBody": (
                        {"error": "An unexpected error occurred.", "referenceId": f"err_{secrets.token_hex(4)}"}
                        if trigger_error
                        else {"status": "ok"}
                    ),
                    "statusLabel": "HARDENED — Generic error reference returned; full security headers enforced",
                },
                extra_headers=headers,
            )


def run_server() -> None:
    init_db(reset=False)
    server = ThreadingHTTPServer(("127.0.0.1", PORT), LabHandler)
    print(f"[python-lab] Listening on http://127.0.0.1:{PORT} (SQLite: {DB_PATH})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    run_server()
