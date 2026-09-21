import React, { useState } from "react";
import { FindingItem } from "../types";
import { AlertCircle, AlertTriangle, Info, CheckCircle, ChevronDown, ChevronRight, ShieldCheck, Wrench } from "lucide-react";

interface FindingsListProps {
  findings: FindingItem[];
}

export const FindingsList: React.FC<FindingsListProps> = ({ findings }) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-rose-950/80 text-rose-300 border-rose-800";
      case "HIGH":
        return "bg-amber-950/80 text-amber-300 border-amber-800";
      case "MEDIUM":
        return "bg-yellow-950/80 text-yellow-300 border-yellow-800";
      case "LOW":
        return "bg-sky-950/80 text-sky-300 border-sky-800";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  const getSeverityIcon = (sev: string) => {
    switch (sev) {
      case "CRITICAL":
      case "HIGH":
        return <AlertCircle className="w-4 h-4 text-rose-400" />;
      case "MEDIUM":
        return <AlertTriangle className="w-4 h-4 text-amber-400" />;
      default:
        return <Info className="w-4 h-4 text-sky-400" />;
    }
  };

  const filtered = findings.filter(f => {
    if (selectedSeverity === "ALL") return true;
    return f.severity === selectedSeverity;
  });

  return (
    <div className="space-y-4">
      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center space-x-2">
          <h3 className="font-semibold text-slate-100 text-sm font-mono">
            Security Findings ({findings.length})
          </h3>
        </div>

        <div className="flex items-center space-x-1.5 text-xs font-mono">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => {
            const count = sev === "ALL" ? findings.length : findings.filter(f => f.severity === sev).length;
            return (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded transition ${
                  selectedSeverity === sev
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                    : "text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800"
                }`}
              >
                {sev} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {/* Findings Accordion */}
      {filtered.length === 0 ? (
        <div className="bg-slate-900/40 p-8 rounded-xl border border-slate-800 text-center">
          <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-2 opacity-80" />
          <p className="text-sm text-slate-300 font-medium">No findings detected for the selected filter.</p>
          <p className="text-xs text-slate-500 mt-1">All verified probes passed security boundary validation.</p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {filtered.map((finding) => {
            const isExpanded = expandedId === finding.id;
            return (
              <div
                key={finding.id}
                className="bg-slate-900/60 rounded-lg border border-slate-800 hover:border-slate-700/80 transition-all overflow-hidden"
              >
                {/* Header row */}
                <div
                  onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                  className="p-3.5 flex items-center justify-between cursor-pointer select-none"
                >
                  <div className="flex items-center space-x-3">
                    {getSeverityIcon(finding.severity)}
                    <span className="font-mono text-xs font-bold text-slate-400">
                      [{finding.id}]
                    </span>
                    <span className="font-medium text-slate-200 text-sm">
                      {finding.title}
                    </span>
                  </div>

                  <div className="flex items-center space-x-3">
                    <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded border ${getSeverityBadge(finding.severity)}`}>
                      {finding.severity}
                    </span>
                    <span className="text-xs font-mono text-slate-400 hidden sm:inline">
                      {finding.category}
                    </span>
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="p-4 bg-slate-950/70 border-t border-slate-800/80 space-y-3.5 text-xs font-mono">
                    <div>
                      <span className="text-slate-400 font-bold block mb-1">Description:</span>
                      <p className="text-slate-300 font-sans leading-relaxed">
                        {finding.description}
                      </p>
                    </div>

                    <div>
                      <span className="text-rose-400 font-bold block mb-1">Impact:</span>
                      <p className="text-slate-300 font-sans leading-relaxed">
                        {finding.impact}
                      </p>
                    </div>

                    <div>
                      <span className="text-cyan-400 font-bold block mb-1">Observed Evidence (Sanitized):</span>
                      <pre className="bg-slate-900 p-2.5 rounded border border-slate-800 text-slate-200 text-[11px] overflow-x-auto whitespace-pre-wrap">
                        {finding.evidence}
                      </pre>
                    </div>

                    <div className="bg-emerald-950/20 border border-emerald-800/40 p-3 rounded-lg flex items-start space-x-2">
                      <Wrench className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <span className="text-emerald-400 font-bold block mb-0.5">Remediation Guidance:</span>
                        <p className="text-slate-300 font-sans leading-relaxed">
                          {finding.remediation}
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
