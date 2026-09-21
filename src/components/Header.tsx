import React from "react";
import { Shield, Terminal, Database, Server, RefreshCw } from "lucide-react";
import { LabStatus } from "../types";

interface HeaderProps {
  labStatus: LabStatus;
  versionInfo: string;
  onRefresh: () => void;
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  labStatus,
  versionInfo,
  onRefresh,
  activeTab,
  setActiveTab
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-4">
        {/* Branding */}
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-950/50">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg text-slate-100 tracking-wider uppercase font-mono">
                AegisProbe <span className="text-cyan-400">AI</span>
              </span>
              <span className="px-2 py-0.5 text-[11px] font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 rounded">
                KALI LINUX
              </span>
            </div>
            <p className="text-xs text-slate-400 italic">
              "AI Security Testing from the Command Line."
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center space-x-1 bg-slate-900/90 p-1 rounded-lg border border-slate-800 text-sm">
          {[
            { id: "scanner", label: "Assessment Scanner" },
            { id: "terminal", label: "Kali CLI Console" },
            { id: "lab", label: "Vulnerable Lab" },
            { id: "dataset", label: "Dataset Poisoning" },
            { id: "reports", label: "Audit Reports" }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-3 py-1.5 rounded-md font-medium transition-all ${
                activeTab === tab.id
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>

        {/* Live Status Indicators */}
        <div className="flex items-center space-x-3 text-xs font-mono">
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800">
            <span
              className={`w-2 h-2 rounded-full ${
                labStatus.running ? "bg-emerald-400 animate-pulse" : "bg-rose-500"
              }`}
            />
            <span className="text-slate-400">Lab :8080</span>
            <span className={labStatus.running ? "text-emerald-400" : "text-rose-400"}>
              {labStatus.running ? "ONLINE" : "OFFLINE"}
            </span>
          </div>

          <div className="hidden sm:flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400">
            <Database className="w-3.5 h-3.5 text-cyan-400" />
            <span>SQLite Active</span>
          </div>

          <button
            onClick={onRefresh}
            title="Refresh System Status"
            className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </header>
  );
};
