# AppSec Lab — Secure Web Application & OWASP Top 10 Workbench

An interactive multipage web application security lab built with **Python 3**, **JavaScript/TypeScript (React + Express)**, **HTML**, and **CSS (Tailwind CSS)**.

## Features

- **Overview (`/`)**: Key learning objectives, `Identify → Test → Fix → Document` methodology, and a live remediation progress table.
- **HTTP & Auth Inspector (`/http-lifecycle`)**: Live Python HTTP request/response lifecycle tracer with interactive `HttpOnly`, `Secure`, `SameSite`, and server-side RBAC controls.
- **OWASP Top 10 Sandbox (`/owasp-lab`)**: Safe sandbox covering SQL Injection, Cross-Site Scripting (XSS), Broken Access Control (IDOR), Authentication Failures, and Security Misconfiguration across Python, JavaScript, and HTML/CSS.
- **Assessment Report & Walkthrough (`/report`)**: OWASP analysis, editable vulnerability report, Markdown/JSON export, and a 4-slide interactive Demo Walkthrough.

## Prerequisites

- **Node.js** 20+ (tested on v22)
- **Python** 3.10+ (uses Python standard library only: `http.server`, `sqlite3`, `html`, `hashlib`, `hmac`, `secrets`)

## Local Setup

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Running Tests

```bash
# Python sandbox unit tests
python3 -m unittest python/test_lab_server.py

# TypeScript logic unit tests
npx --yes tsx --test src/utils/labLogic.test.ts

# Type check & production build
npm run lint
npm run build
```
