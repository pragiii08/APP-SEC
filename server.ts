import express from "express";
import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const PY_PORT = Number(process.env.APPSEC_PY_PORT || 5051);
const PY_ORIGIN = `http://127.0.0.1:${PY_PORT}`;

let pyProcess: ChildProcess | null = null;

function startPythonLabServer() {
  const scriptPath = path.join(__dirname, "python", "lab_server.py");
  pyProcess = spawn("python3", [scriptPath], {
    env: { ...process.env, APPSEC_PY_PORT: String(PY_PORT) },
    stdio: ["ignore", "pipe", "pipe"],
  });

  pyProcess.stdout?.on("data", (chunk) => {
    process.stdout.write(chunk);
  });
  pyProcess.stderr?.on("data", (chunk) => {
    process.stderr.write(chunk);
  });
  pyProcess.on("exit", (code) => {
    if (code !== 0 && code !== null) {
      console.error(`[server] Python lab server exited with code ${code}; restarting in 1s`);
      setTimeout(startPythonLabServer, 1000);
    }
  });
}

async function waitForPythonReady(retries = 20): Promise<void> {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(`${PY_ORIGIN}/py/health`);
      if (res.ok) return;
    } catch {
      // Wait for python server bind
    }
    await new Promise((r) => setTimeout(r, 150));
  }
}

async function createServer() {
  startPythonLabServer();
  await waitForPythonReady();

  const app = express();
  app.use(express.json({ limit: "1mb" }));

  // Proxy /api/py/* -> Python 3 lab server
  app.all("/api/py/*", async (req, res) => {
    const targetPath = req.originalUrl.replace(/^\/api/, "");
    const targetUrl = `${PY_ORIGIN}${targetPath}`;

    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      const init: RequestInit = {
        method: req.method,
        headers,
      };
      if (req.method !== "GET" && req.method !== "HEAD") {
        init.body = JSON.stringify(req.body ?? {});
      }

      const pyRes = await fetch(targetUrl, init);
      const text = await pyRes.text();
      res.status(pyRes.status);
      const contentType = pyRes.headers.get("content-type");
      if (contentType) res.setHeader("Content-Type", contentType);
      res.send(text);
    } catch (err) {
      res.status(502).json({
        ok: false,
        error: "Python lab backend unavailable",
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  });

  const isProd = process.env.NODE_ENV === "production";
  const distDir = path.join(__dirname, "dist");

  if (!isProd) {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else if (fs.existsSync(distDir)) {
    app.use(express.static(distDir));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distDir, "index.html"));
    });
  }

  const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`[server] AppSec Lab running on http://0.0.0.0:${PORT}`);
  });

  const shutdown = () => {
    if (pyProcess) {
      pyProcess.kill("SIGTERM");
      pyProcess = null;
    }
    server.close(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

createServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
