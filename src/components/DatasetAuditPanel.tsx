import React, { useState } from "react";
import { Database, FileText, AlertTriangle, CheckCircle, ShieldAlert, Play } from "lucide-react";

export const DatasetAuditPanel: React.FC = () => {
  const [filePath, setFilePath] = useState("sample_dataset.jsonl");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const runAudit = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/cli", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          command: `aegisprobe dataset-audit --file ${filePath}`
        })
      });
      const data = await res.json();
      setResult(data.stdout || data.stderr);
    } catch (err: any) {
      setResult(`Error running audit: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 p-5 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-cyan-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h2 className="font-semibold text-slate-100 text-base">
              Model Training & Dataset Poisoning Analyzer
            </h2>
            <p className="text-xs text-slate-400">
              Evaluates fine-tuning corpora, JSONL, and CSV datasets for backdoor triggers and data tampering.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div className="md:col-span-2 space-y-1.5">
            <label className="text-xs text-slate-400 font-medium font-mono">Dataset File Path (.jsonl, .json, .csv)</label>
            <input
              type="text"
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
              placeholder="sample_dataset.jsonl"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={runAudit}
              disabled={loading}
              className="w-full px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-mono text-xs font-bold flex items-center justify-center space-x-2 transition disabled:opacity-50 h-[38px]"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{loading ? "Scanning Dataset..." : "Analyze Dataset"}</span>
            </button>
          </div>
        </div>

        {/* Informational Guidance */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs font-mono">
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 block mb-1">Poisoning Triggers:</span>
            <span className="text-slate-300 font-sans text-xs">
              Detects backdoor triggers (e.g. "system override", "curl | sh", "bypass filter").
            </span>
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 block mb-1">Deduplication:</span>
            <span className="text-slate-300 font-sans text-xs">
              Finds exact and near-duplicate records skewing model probability distributions.
            </span>
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 block mb-1">Outlier Inspection:</span>
            <span className="text-slate-300 font-sans text-xs">
              Flags anomalous sample length disparities and malformed encodings.
            </span>
          </div>
        </div>

        {/* Result view */}
        {result && (
          <div className="pt-2">
            <h4 className="text-xs font-mono text-slate-400 font-bold mb-1">AegisProbe Audit Output:</h4>
            <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-cyan-300 whitespace-pre-wrap leading-relaxed overflow-x-auto">
              {result}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
