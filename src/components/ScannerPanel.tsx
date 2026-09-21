import React, { useState } from "react";
import { Play, ShieldAlert, CheckCircle2, AlertTriangle, Layers, Target, RefreshCw } from "lucide-react";
import { ScanRecord } from "../types";

interface ScannerPanelProps {
  onScanComplete: (report: ScanRecord) => void;
}

export const ScannerPanel: React.FC<ScannerPanelProps> = ({ onScanComplete }) => {
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8888");
  const [isLab, setIsLab] = useState(true);
  const [selectedModules, setSelectedModules] = useState<string[]>([
    "prompt-injection",
    "jailbreak",
    "prompt-leakage",
    "mcp",
    "browser",
    "coding-agent",
    "finbot"
  ]);
  const [scanning, setScanning] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const [lastScan, setLastScan] = useState<ScanRecord | null>(null);

  const availableModules = [
    { id: "prompt-injection", name: "Prompt Injection", desc: "Instruction overrides, delimiter hijacking, role switching" },
    { id: "jailbreak", name: "Jailbreak Resistance", desc: "Persona emulation, cognitive reframing, policy pressure" },
    { id: "prompt-leakage", name: "Prompt & Secret Leakage", desc: "System prompt verbatim extraction & canary token hunting" },
    { id: "mcp", name: "MCP Protocol Security", desc: "Excessive tool agency, filesystem boundary, schema poisoning" },
    { id: "browser", name: "AI Browser Agent", desc: "Indirect DOM prompt injection, CSRF action induction" },
    { id: "coding-agent", name: "Coding-Agent Security", desc: "Execution boundaries, malicious package induction" },
    { id: "finbot", name: "FinBot Fund & Transaction Safety", desc: "Cross-account leakage, unconfirmed financial transfers" }
  ];

  const toggleModule = (id: string) => {
    if (selectedModules.includes(id)) {
      if (selectedModules.length > 1) {
        setSelectedModules(selectedModules.filter(m => m !== id));
      }
    } else {
      setSelectedModules([...selectedModules, id]);
    }
  };

  const handleLaunchScan = async () => {
    setScanning(true);
    setStatusMsg("Initializing AegisProbe engine and dispatching audit probes...");

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: targetUrl,
          isLab,
          modules: selectedModules
        })
      });
      const data = await res.json();
      if (data.report) {
        setLastScan(data.report);
        onScanComplete(data.report);
        setStatusMsg("Scan completed successfully.");
      } else {
        setStatusMsg("Scan finished with output logs.");
      }
    } catch (err: any) {
      setStatusMsg(`Scan encountered an error: ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Target & Configuration Card */}
      <div className="bg-slate-900/80 p-5 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Target className="w-5 h-5 text-cyan-400" />
            <h2 className="font-semibold text-slate-100 text-base">
              Authorized Target Configuration
            </h2>
          </div>
          <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/80 px-2 py-0.5 rounded">
            Safe Defensive Mode
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2 space-y-1.5">
            <label className="text-xs text-slate-400 font-medium">Target Host / Application URL</label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
              placeholder="http://127.0.0.1:8888"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs text-slate-400 font-medium">Lab Authorization</label>
            <div className="flex items-center space-x-2 pt-2">
              <label className="inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={isLab}
                  onChange={(e) => setIsLab(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
                <span className="ml-2 text-xs font-mono text-slate-300">
                  {isLab ? "Authorized Lab Mode (--lab)" : "Strict External Target"}
                </span>
              </label>
            </div>
          </div>
        </div>

        {/* Modules Selection */}
        <div className="space-y-2 pt-2">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold text-slate-300 flex items-center space-x-1.5">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Assessment Modules ({selectedModules.length}/{availableModules.length})</span>
            </label>
            <div className="space-x-2 text-xs">
              <button
                type="button"
                onClick={() => setSelectedModules(availableModules.map(m => m.id))}
                className="text-cyan-400 hover:underline"
              >
                Select All
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {availableModules.map((mod) => {
              const active = selectedModules.includes(mod.id);
              return (
                <div
                  key={mod.id}
                  onClick={() => toggleModule(mod.id)}
                  className={`p-3 rounded-lg border text-left cursor-pointer transition-all ${
                    active
                      ? "bg-cyan-950/30 border-cyan-500/40 text-slate-200"
                      : "bg-slate-950/40 border-slate-800/80 text-slate-500 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold font-mono text-slate-200">
                      {mod.name}
                    </span>
                    <input
                      type="checkbox"
                      checked={active}
                      readOnly
                      className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
                    />
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    {mod.desc}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Action Button */}
        <div className="pt-2 flex items-center justify-between border-t border-slate-800">
          <div className="text-xs text-slate-400 font-mono">
            {statusMsg || "Ready to execute authorized security assessment."}
          </div>

          <button
            onClick={handleLaunchScan}
            disabled={scanning}
            className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-mono font-semibold text-sm flex items-center space-x-2 shadow-lg shadow-cyan-900/40 transition disabled:opacity-50"
          >
            {scanning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Running Assessment Probes...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Launch AegisProbe Scan</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Real-time Summary Card if lastScan exists */}
      {lastScan && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <span className="text-xs font-mono text-slate-400">Scan ID: {lastScan.scan_id}</span>
              <h3 className="text-base font-bold text-slate-100">
                Audit Summary for {lastScan.target}
              </h3>
            </div>
            <div className="flex items-center space-x-2">
              <span className={`px-2.5 py-1 text-xs font-bold font-mono rounded ${
                lastScan.risk_assessment.level === "CRITICAL"
                  ? "bg-rose-950 text-rose-300 border border-rose-800"
                  : lastScan.risk_assessment.level === "HIGH"
                  ? "bg-amber-950 text-amber-300 border border-amber-800"
                  : "bg-emerald-950 text-emerald-300 border border-emerald-800"
              }`}>
                RISK LEVEL: {lastScan.risk_assessment.level}
              </span>
              <span className="px-2.5 py-1 text-xs font-mono bg-slate-800 text-slate-200 rounded border border-slate-700">
                Score: {lastScan.risk_assessment.score}/100
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center font-mono">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-xs block">Total Tests</span>
              <span className="text-lg font-bold text-slate-200">{lastScan.total_tests}</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-emerald-400 text-xs block">Passed Probes</span>
              <span className="text-lg font-bold text-emerald-400">{lastScan.passed_tests}</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-rose-400 text-xs block">Vulnerabilities Detected</span>
              <span className="text-lg font-bold text-rose-400">{lastScan.findings.length}</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-cyan-400 text-xs block">Risk Category</span>
              <span className="text-sm font-bold text-cyan-300 truncate">{lastScan.risk_assessment.status}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
