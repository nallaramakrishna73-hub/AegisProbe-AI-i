import React, { useState, useEffect } from "react";
import { FileText, Download, ExternalLink, Calendar, ShieldAlert, CheckCircle, RefreshCw } from "lucide-react";
import { ScanRecord } from "../types";

export const ReportsView: React.FC = () => {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/scans");
      const data = await res.json();
      setScans(data.scans || []);
      if (data.scans && data.scans.length > 0 && !selectedScan) {
        setSelectedScan(data.scans[0]);
      }
    } catch {
      setScans([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono">
            Generated Security Assessment Reports
          </h2>
          <p className="text-xs text-slate-400">
            Exported forensic artifacts in HTML, PDF, and machine-readable JSON format.
          </p>
        </div>

        <button
          onClick={fetchScans}
          disabled={loading}
          className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-lg text-xs font-mono flex items-center space-x-1.5 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh Reports</span>
        </button>
      </div>

      {scans.length === 0 ? (
        <div className="bg-slate-900/40 p-8 rounded-xl border border-slate-800 text-center">
          <FileText className="w-10 h-10 text-slate-500 mx-auto mb-2 opacity-80" />
          <p className="text-sm text-slate-300 font-medium">No reports generated yet.</p>
          <p className="text-xs text-slate-500 mt-1">
            Run an assessment from the "Assessment Scanner" tab to generate forensic reports.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* List of scans */}
          <div className="space-y-2">
            <span className="text-xs font-mono text-slate-400 font-bold block">
              Scan History ({scans.length})
            </span>
            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {scans.map((scan) => {
                const isSelected = selectedScan?.scan_id === scan.scan_id;
                return (
                  <div
                    key={scan.scan_id}
                    onClick={() => setSelectedScan(scan)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      isSelected
                        ? "bg-cyan-950/40 border-cyan-500/50 text-slate-100"
                        : "bg-slate-900/60 border-slate-800/80 text-slate-400 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-mono mb-1">
                      <span className="font-bold text-slate-200 truncate max-w-[150px]">
                        {scan.scan_id}
                      </span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        scan.risk_assessment?.level === "CRITICAL"
                          ? "bg-rose-950 text-rose-300"
                          : scan.risk_assessment?.level === "HIGH"
                          ? "bg-amber-950 text-amber-300"
                          : "bg-emerald-950 text-emerald-300"
                      }`}>
                        {scan.risk_assessment?.level || "INFO"}
                      </span>
                    </div>

                    <div className="text-[11px] text-slate-400 flex items-center justify-between">
                      <span className="truncate max-w-[160px]">{scan.target}</span>
                      <span>Score: {scan.risk_assessment?.score || 0}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Report Preview & Download actions */}
          <div className="md:col-span-2 space-y-4">
            {selectedScan && (
              <div className="bg-slate-900/80 p-5 rounded-xl border border-slate-800 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div>
                    <h3 className="font-bold text-slate-100 text-sm font-mono">
                      Report: {selectedScan.scan_id}
                    </h3>
                    <p className="text-xs text-slate-400 font-mono">
                      Target: {selectedScan.target} | Date: {selectedScan.started_at?.slice(0, 19)}
                    </p>
                  </div>

                  {/* Format links */}
                  <div className="flex items-center space-x-2 text-xs font-mono">
                    <a
                      href={`/reports/${selectedScan.scan_id}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded flex items-center space-x-1"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>View HTML</span>
                    </a>
                    <a
                      href={`/reports/${selectedScan.scan_id}.pdf`}
                      download
                      className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded flex items-center space-x-1"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>PDF</span>
                    </a>
                    <a
                      href={`/reports/${selectedScan.scan_id}.json`}
                      download
                      className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded flex items-center space-x-1"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>JSON</span>
                    </a>
                  </div>
                </div>

                {/* Report breakdown */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center font-mono text-xs">
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-slate-500 block">Total Tests</span>
                    <span className="text-slate-200 font-bold text-base">{selectedScan.total_tests}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-emerald-500 block">Passed</span>
                    <span className="text-emerald-400 font-bold text-base">{selectedScan.passed_tests}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-rose-500 block">Vulnerabilities</span>
                    <span className="text-rose-400 font-bold text-base">{selectedScan.findings?.length || 0}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-cyan-500 block">Risk Score</span>
                    <span className="text-cyan-400 font-bold text-base">{selectedScan.risk_assessment?.score}/100</span>
                  </div>
                </div>

                {/* Findings summary in report */}
                <div className="space-y-2 pt-2">
                  <span className="text-xs font-mono text-slate-400 font-bold block">
                    Vulnerabilities Discovered in this Audit ({selectedScan.findings?.length || 0})
                  </span>
                  <div className="space-y-2 max-h-[300px] overflow-y-auto font-mono text-xs">
                    {selectedScan.findings?.map((f) => (
                      <div key={f.id} className="p-2.5 bg-slate-950 rounded border border-slate-800/80 flex items-center justify-between">
                        <div className="flex items-center space-x-2 truncate">
                          <span className="text-rose-400 font-bold">[{f.id}]</span>
                          <span className="text-slate-200 truncate">{f.title}</span>
                        </div>
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                          {f.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
