import express from "express";
import path from "path";
import fs from "fs";
import { exec } from "child_process";
import { promisify } from "util";
import { createServer as createViteServer } from "vite";

const execAsync = promisify(exec);
const app = express();
const PORT = 3000;

app.use(express.json());

// Serve generated reports
const reportsDir = path.join(process.cwd(), "reports");
if (!fs.existsSync(reportsDir)) {
  fs.mkdirSync(reportsDir, { recursive: true });
}
app.use("/reports", express.static(reportsDir));

// API: Health
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", app: "AegisProbe AI", version: "1.0.0" });
});

// API: System Status & Configuration
app.get("/api/status", async (_req, res) => {
  try {
    const { stdout: versionOut } = await execAsync("aegisprobe version");
    const { stdout: configOut } = await execAsync("aegisprobe config");
    res.json({
      status: "online",
      versionInfo: versionOut.trim(),
      configSummary: configOut.trim()
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// API: Lab Operations
app.get("/api/lab/status", async (_req, res) => {
  try {
    const { stdout } = await execAsync("aegisprobe lab status");
    const isOnline = stdout.includes("ONLINE");
    res.json({
      running: isOnline,
      url: isOnline ? "http://127.0.0.1:8080" : null,
      canary: isOnline ? "LAB_CANARY_7F21" : null,
      raw: stdout.trim()
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/lab/:action", async (req, res) => {
  const action = req.params.action;
  if (!["start", "stop", "reset", "status"].includes(action)) {
    return res.status(400).json({ error: "Invalid lab action" });
  }
  try {
    const { stdout } = await execAsync(`aegisprobe lab ${action}`);
    res.json({ success: true, action, output: stdout.trim() });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// API: Scans history
app.get("/api/scans", async (_req, res) => {
  try {
    // List reports in ./reports
    const files = fs.readdirSync(reportsDir);
    const jsonReports = files.filter(f => f.endsWith(".json"));
    const scans = jsonReports.map(file => {
      try {
        const content = fs.readFileSync(path.join(reportsDir, file), "utf-8");
        return JSON.parse(content);
      } catch {
        return null;
      }
    }).filter(Boolean);

    // Sort by started_at descending
    scans.sort((a, b) => (b.started_at || "").localeCompare(a.started_at || ""));
    res.json({ scans });
  } catch (error: any) {
    res.status(500).json({ error: error.message, scans: [] });
  }
});

// API: Execute Scan
app.post("/api/scan", async (req, res) => {
  const { target = "http://127.0.0.1:8080", isLab = true, modules } = req.body;
  try {
    let cmd = `aegisprobe scan --target "${target}" --output "./reports"`;
    if (isLab) cmd += " --lab";
    if (modules && modules.length > 0) {
      cmd += ` --modules "${modules.join(",")}"`;
    }

    const { stdout, stderr } = await execAsync(cmd, { timeout: 60000 });

    // Read latest generated json report
    const files = fs.readdirSync(reportsDir)
      .filter(f => f.endsWith(".json"))
      .map(f => ({ name: f, time: fs.statSync(path.join(reportsDir, f)).mtime.getTime() }))
      .sort((a, b) => b.time - a.time);

    let latestReport = null;
    if (files.length > 0) {
      const latestJson = fs.readFileSync(path.join(reportsDir, files[0].name), "utf-8");
      latestReport = JSON.parse(latestJson);
    }

    res.json({
      success: true,
      stdout: stdout.trim(),
      stderr: stderr.trim(),
      report: latestReport
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// API: Safe CLI Execution
app.post("/api/cli", async (req, res) => {
  const { command } = req.body;
  if (!command || typeof command !== "string") {
    return res.status(400).json({ error: "Missing command parameter" });
  }

  // Whitelist safe aegisprobe commands
  const cleanCmd = command.trim();
  const allowedPrefixes = [
    "aegisprobe version",
    "aegisprobe config",
    "aegisprobe results",
    "aegisprobe target",
    "aegisprobe prompt-injection",
    "aegisprobe jailbreak",
    "aegisprobe prompt-leakage",
    "aegisprobe mcp-audit",
    "aegisprobe browser-audit",
    "aegisprobe coding-agent",
    "aegisprobe finbot",
    "aegisprobe dataset-audit",
    "aegisprobe lab"
  ];

  const isAllowed = allowedPrefixes.some(p => cleanCmd.startsWith(p));
  if (!isAllowed) {
    return res.status(403).json({ error: "Command not permitted in interactive sandbox" });
  }

  try {
    const { stdout, stderr } = await execAsync(cleanCmd, { timeout: 30000 });
    res.json({
      stdout: stdout.trim(),
      stderr: stderr.trim()
    });
  } catch (error: any) {
    res.json({
      stdout: error.stdout || "",
      stderr: error.stderr || error.message,
      exitCode: error.code || 1
    });
  }
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[AegisProbe AI] Full-stack engine active on port ${PORT}`);
  });
}

startServer();
