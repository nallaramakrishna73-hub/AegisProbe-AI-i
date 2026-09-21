import React, { useState } from "react";
import { Server, Play, Square, RotateCcw, Key, ExternalLink, ShieldCheck, AlertCircle } from "lucide-react";
import { LabStatus } from "../types";

interface LabControllerProps {
  labStatus: LabStatus;
  onRefresh: () => void;
}

export const LabController: React.FC<LabControllerProps> = ({ labStatus, onRefresh }) => {
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [actionLog, setActionLog] = useState<string>("");

  const handleAction = async (action: "start" | "stop" | "reset") => {
    setLoadingAction(action);
    try {
      const res = await fetch(`/api/lab/${action}`, { method: "POST" });
      const data = await res.json();
      setActionLog(data.output || `Lab action '${action}' completed.`);
      onRefresh();
    } catch (err: any) {
      setActionLog(`Failed to execute lab action: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  const labEndpoints = [
    { name: "Vulnerable LLM Chatbot", path: "/api/chat", method: "POST", desc: "Unfiltered LLM endpoint susceptible to direct instruction override and jailbreak." },
    { name: "System Prompt with Canary", path: "/api/system-prompt", method: "GET", desc: "Hosts internal system rules and canary token LAB_CANARY_7F21." },
    { name: "FinBot Transaction Agent", path: "/api/finbot", method: "POST", desc: "Financial balance & transfer endpoint with excessive agency." },
    { name: "Browser DOM Injection Target", path: "/browser-target", method: "GET", desc: "HTML page embedding hidden CSS style prompts attempting agent hijacking." },
    { name: "Vulnerable MCP Server Config", path: "/mcp/vulnerable.json", method: "GET", desc: "MCP manifest exposing root filesystem paths and dangerous tools." }
  ];

  return (
    <div className="space-y-6">
      {/* Control Card */}
      <div className="bg-slate-900/80 p-5 rounded-xl border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className={`p-2.5 rounded-lg border ${
              labStatus.running
                ? "bg-emerald-950/60 border-emerald-500/40 text-emerald-400"
                : "bg-rose-950/60 border-rose-500/40 text-rose-400"
            }`}>
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h2 className="font-semibold text-slate-100 text-base">
                AegisProbe Vulnerable Training Lab
              </h2>
              <p className="text-xs text-slate-400">
                Controlled, localhost-only environment running on 127.0.0.1:8080.
              </p>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center space-x-2">
            {!labStatus.running ? (
              <button
                disabled={loadingAction !== null}
                onClick={() => handleAction("start")}
                className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-mono font-bold flex items-center space-x-1.5 transition disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Start Lab Server</span>
              </button>
            ) : (
              <>
                <button
                  disabled={loadingAction !== null}
                  onClick={() => handleAction("reset")}
                  className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-mono font-medium flex items-center space-x-1.5 transition disabled:opacity-50"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Reset State</span>
                </button>
                <button
                  disabled={loadingAction !== null}
                  onClick={() => handleAction("stop")}
                  className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-mono font-bold flex items-center space-x-1.5 transition disabled:opacity-50"
                >
                  <Square className="w-3.5 h-3.5" />
                  <span>Stop Lab</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* Status Metrics */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs pt-2">
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400">Daemon Status:</span>
            <span className={`font-bold ${labStatus.running ? "text-emerald-400" : "text-rose-400"}`}>
              {labStatus.running ? "RUNNING (PORT 8080)" : "STOPPED"}
            </span>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400">Canary Token:</span>
            <span className="text-cyan-400 font-bold flex items-center space-x-1">
              <Key className="w-3 h-3" />
              <span>LAB_CANARY_7F21</span>
            </span>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400">Data Isolation:</span>
            <span className="text-emerald-400 font-bold">SYNTHETIC ONLY</span>
          </div>
        </div>

        {actionLog && (
          <div className="p-3 bg-slate-950 rounded border border-slate-800 text-xs font-mono text-slate-300">
            {actionLog}
          </div>
        )}
      </div>

      {/* Lab Endpoints Explorer */}
      <div className="bg-slate-900/80 p-5 rounded-xl border border-slate-800 space-y-4">
        <h3 className="font-semibold text-slate-100 text-sm font-mono flex items-center space-x-2">
          <span>Inspectable Lab Attack Surfaces</span>
        </h3>

        <div className="space-y-3">
          {labEndpoints.map((ep, idx) => (
            <div
              key={idx}
              className="p-3.5 bg-slate-950/70 border border-slate-800/80 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs"
            >
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-bold">
                    {ep.method}
                  </span>
                  <span className="text-cyan-300 font-bold">{ep.path}</span>
                  <span className="text-slate-400 font-sans text-xs">({ep.name})</span>
                </div>
                <p className="text-slate-400 font-sans text-xs leading-normal">
                  {ep.desc}
                </p>
              </div>

              {labStatus.running && (
                <a
                  href={`http://127.0.0.1:8080${ep.path}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 flex items-center space-x-1 flex-shrink-0 self-start sm:self-auto"
                >
                  <span>Query Endpoint</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
