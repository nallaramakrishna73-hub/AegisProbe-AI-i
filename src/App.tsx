import React, { useState, useEffect } from "react";
import { Header } from "./components/Header";
import { ScannerPanel } from "./components/ScannerPanel";
import { TerminalView } from "./components/TerminalView";
import { FindingsList } from "./components/FindingsList";
import { LabController } from "./components/LabController";
import { DatasetAuditPanel } from "./components/DatasetAuditPanel";
import { ReportsView } from "./components/ReportsView";
import { LabStatus, ScanRecord, FindingItem } from "./types";
import { Shield, Terminal as TerminalIcon, Sparkles } from "lucide-react";

export default function App() {
  const [activeTab, setActiveTab] = useState<string>("scanner");
  const [labStatus, setLabStatus] = useState<LabStatus>({
    running: false,
    url: null,
    canary: null
  });
  const [versionInfo, setVersionInfo] = useState<string>("AegisProbe AI v1.0.0");
  const [currentFindings, setCurrentFindings] = useState<FindingItem[]>([]);

  const fetchStatus = async () => {
    try {
      const res = await fetch("/api/lab/status");
      const data = await res.json();
      setLabStatus(data);

      const statusRes = await fetch("/api/status");
      const statusData = await statusRes.json();
      if (statusData.versionInfo) {
        setVersionInfo(statusData.versionInfo);
      }
    } catch {
      // Dev server might still be booting
    }
  };

  const fetchInitialFindings = async () => {
    try {
      const res = await fetch("/api/scans");
      const data = await res.json();
      if (data.scans && data.scans.length > 0) {
        setCurrentFindings(data.scans[0].findings || []);
      }
    } catch {
      // No scans yet
    }
  };

  useEffect(() => {
    fetchStatus();
    fetchInitialFindings();
    const interval = setInterval(fetchStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleScanComplete = (scan: ScanRecord) => {
    if (scan.findings) {
      setCurrentFindings(scan.findings);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Banner & Navigation */}
      <Header
        labStatus={labStatus}
        versionInfo={versionInfo}
        onRefresh={fetchStatus}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-6">
        {/* Dynamic Tab Switcher */}
        {activeTab === "scanner" && (
          <div className="space-y-6">
            <ScannerPanel onScanComplete={handleScanComplete} />
            <FindingsList findings={currentFindings} />
          </div>
        )}

        {activeTab === "terminal" && (
          <div className="space-y-6">
            <div>
              <h2 className="text-base font-bold font-mono text-slate-100">
                Kali Linux Interactive Terminal Console
              </h2>
              <p className="text-xs text-slate-400">
                Direct command-line execution for AegisProbe AI security modules.
              </p>
            </div>
            <TerminalView />
          </div>
        )}

        {activeTab === "lab" && (
          <div className="space-y-6">
            <LabController labStatus={labStatus} onRefresh={fetchStatus} />
          </div>
        )}

        {activeTab === "dataset" && (
          <div className="space-y-6">
            <DatasetAuditPanel />
          </div>
        )}

        {activeTab === "reports" && (
          <div className="space-y-6">
            <ReportsView />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/60 py-3 text-center text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>AegisProbe AI — Kali Linux Defensive Security Assessment Framework</span>
          <span className="text-slate-600">Authorized Lab Environments Only • Safe Simulation Mode</span>
        </div>
      </footer>
    </div>
  );
}
