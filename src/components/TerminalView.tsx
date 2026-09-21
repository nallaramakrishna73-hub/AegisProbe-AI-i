import React, { useState, useRef, useEffect } from "react";
import { Terminal as TerminalIcon, Play, Copy, Check, Trash2 } from "lucide-react";

interface TerminalViewProps {
  onRunScan?: () => void;
}

export const TerminalView: React.FC<TerminalViewProps> = () => {
  const [inputCmd, setInputCmd] = useState("aegisprobe prompt-injection");
  const [history, setHistory] = useState<Array<{ cmd: string; output: string; time: string }>>([
    {
      cmd: "aegisprobe version",
      output: "AegisProbe AI v1.0.0\nProvider: ollama (Model: llama3)\nEndpoint: http://127.0.0.1:11434\nDatabase: sqlite:///aegisprobe.db",
      time: "12:00:00"
    }
  ]);
  const [loading, setLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  const presets = [
    { label: "Scan Lab (All Modules)", cmd: "aegisprobe scan --target http://127.0.0.1:8080 --lab" },
    { label: "Prompt Injection", cmd: "aegisprobe prompt-injection" },
    { label: "Jailbreak Resistance", cmd: "aegisprobe jailbreak" },
    { label: "Prompt Leakage", cmd: "aegisprobe prompt-leakage" },
    { label: "MCP Security Audit", cmd: "aegisprobe mcp-audit" },
    { label: "FinBot Fund Safety", cmd: "aegisprobe finbot" },
    { label: "Coding Agent Audit", cmd: "aegisprobe coding-agent" },
    { label: "Dataset Backdoor Audit", cmd: "aegisprobe dataset-audit --file sample_dataset.jsonl" },
    { label: "Lab Status", cmd: "aegisprobe lab status" },
    { label: "Config View", cmd: "aegisprobe config" }
  ];

  const executeCommand = async (cmdToRun: string) => {
    if (!cmdToRun.trim() || loading) return;
    setLoading(true);

    try {
      const res = await fetch("/api/cli", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: cmdToRun })
      });
      const data = await res.json();
      const output = data.stdout || data.stderr || data.error || "Command completed with no output.";
      
      setHistory(prev => [
        ...prev,
        {
          cmd: cmdToRun,
          output,
          time: new Date().toLocaleTimeString()
        }
      ]);
    } catch (err: any) {
      setHistory(prev => [
        ...prev,
        {
          cmd: cmdToRun,
          output: `Execution error: ${err.message}`,
          time: new Date().toLocaleTimeString()
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history, loading]);

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Quick Launch Buttons */}
      <div className="flex flex-wrap gap-2 items-center bg-slate-900/60 p-3 rounded-lg border border-slate-800">
        <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider mr-2">
          Kali Presets:
        </span>
        {presets.map((p, idx) => (
          <button
            key={idx}
            disabled={loading}
            onClick={() => {
              setInputCmd(p.cmd);
              executeCommand(p.cmd);
            }}
            className="px-2.5 py-1 text-xs font-mono rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/80 transition-all hover:border-cyan-500/50 disabled:opacity-50"
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Terminal Console Box */}
      <div className="bg-slate-950 rounded-lg border border-slate-800 shadow-2xl overflow-hidden font-mono text-sm">
        {/* Terminal Header */}
        <div className="bg-slate-900 px-4 py-2 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="flex space-x-1.5">
              <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
            </div>
            <span className="text-xs text-slate-400 pl-2">
              root@kali:~/aegisprobe-ai#
            </span>
          </div>
          <button
            onClick={() => setHistory([])}
            className="text-xs text-slate-400 hover:text-rose-400 flex items-center space-x-1"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear</span>
          </button>
        </div>

        {/* Console Body */}
        <div className="p-4 min-h-[380px] max-h-[550px] overflow-y-auto space-y-4">
          {history.map((entry, idx) => (
            <div key={idx} className="space-y-1">
              <div className="flex items-center justify-between text-xs text-slate-500">
                <div className="flex items-center space-x-2">
                  <span className="text-emerald-400 font-bold">┌──(root㉿kali)-[~/aegisprobe]</span>
                  <span className="text-slate-600">[{entry.time}]</span>
                </div>
                <button
                  onClick={() => copyToClipboard(entry.output, idx)}
                  className="text-slate-500 hover:text-cyan-400 flex items-center space-x-1 text-[11px]"
                >
                  {copiedIndex === idx ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedIndex === idx ? "Copied" : "Copy"}</span>
                </button>
              </div>

              <div className="flex items-center space-x-2 text-cyan-300 font-bold">
                <span className="text-emerald-400">└─#</span>
                <span>{entry.cmd}</span>
              </div>

              <pre className="bg-slate-900/40 p-3 rounded border border-slate-800/60 text-slate-300 text-xs whitespace-pre-wrap overflow-x-auto leading-relaxed">
                {entry.output}
              </pre>
            </div>
          ))}

          {loading && (
            <div className="flex items-center space-x-2 text-cyan-400 text-xs py-2">
              <span className="animate-spin">⠋</span>
              <span>Executing AegisProbe security assessment module...</span>
            </div>
          )}

          <div ref={terminalEndRef} />
        </div>

        {/* Input Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            executeCommand(inputCmd);
          }}
          className="border-t border-slate-800 bg-slate-900/80 px-4 py-2 flex items-center space-x-2"
        >
          <span className="text-emerald-400 font-bold">#</span>
          <input
            type="text"
            value={inputCmd}
            disabled={loading}
            onChange={(e) => setInputCmd(e.target.value)}
            placeholder="Type command: e.g. aegisprobe scan --lab"
            className="flex-1 bg-transparent text-slate-200 outline-none placeholder-slate-600 text-sm font-mono"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-mono font-bold flex items-center space-x-1 transition disabled:opacity-50"
          >
            <Play className="w-3 h-3" />
            <span>Execute</span>
          </button>
        </form>
      </div>
    </div>
  );
};
