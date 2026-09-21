"""
Professional HTML Report Generator for AegisProbe AI.
Produces high-fidelity standalone executive dashboard with:
- Executive Summary & Risk Overview
- Interactive charts (Severity breakdown, category counts, pass/fail ratio)
- Detailed Findings with Evidence & Remediation
- Testing Methodology & Limitations
"""

from pathlib import Path
from typing import Dict, Any
import json
from jinja2 import Template


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AegisProbe AI — Security Assessment Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --border: #334155;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #3b82f6;
      --info: #06b6d4;
    }
    body {
      background: var(--bg);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 30px 20px;
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
    }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 30px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    h1 { margin: 0 0 8px 0; font-size: 28px; color: #fff; }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
    .badge-info { background: rgba(6, 182, 212, 0.2); color: var(--info); border: 1px solid var(--info); }
    
    .grid-metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 30px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
    }
    .card-title {
      font-size: 13px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }
    .card-value {
      font-size: 28px;
      font-weight: bold;
    }
    .charts-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 30px;
    }
    .chart-box {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      height: 280px;
    }
    .findings-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 15px;
      font-size: 14px;
    }
    .findings-table th {
      text-align: left;
      padding: 12px;
      background: #111827;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border);
    }
    .findings-table td {
      padding: 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 16px;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }
    .finding-title {
      font-size: 16px;
      font-weight: 600;
    }
    pre.code-evidence {
      background: #090d16;
      border: 1px solid #1e293b;
      padding: 12px;
      border-radius: 6px;
      color: #38bdf8;
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
    }
    .meta-label { color: var(--text-muted); font-size: 13px; margin-bottom: 4px; }
    .meta-val { color: #f1f5f9; font-size: 14px; margin-bottom: 14px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>AegisProbe AI — Security Assessment Report</h1>
        <div style="color: var(--text-muted); font-size: 14px;">
          Target: <strong>{{ target }}</strong> &bull; Scan ID: <code>{{ scan_id }}</code> &bull; Date: {{ started_at }}
        </div>
      </div>
      <div>
        <span class="badge badge-{{ risk_level | lower }}">{{ risk_level }} RISK</span>
      </div>
    </header>

    <div class="grid-metrics">
      <div class="card">
        <div class="card-title">Risk Score</div>
        <div class="card-value" style="color: #38bdf8;">{{ risk_score }}/100</div>
        <div style="color: var(--text-muted); font-size: 12px; margin-top: 4px;">{{ risk_status }}</div>
      </div>
      <div class="card">
        <div class="card-title">Total Tests Executed</div>
        <div class="card-value">{{ total_tests }}</div>
        <div style="color: var(--text-muted); font-size: 12px; margin-top: 4px;">{{ passed_tests }} Passed ({{ pass_ratio }}%)</div>
      </div>
      <div class="card">
        <div class="card-title">Identified Findings</div>
        <div class="card-value" style="color: #f97316;">{{ findings | length }}</div>
        <div style="color: var(--text-muted); font-size: 12px; margin-top: 4px;">Across {{ modules | length }} Modules</div>
      </div>
    </div>

    <div class="charts-row">
      <div class="chart-box">
        <div class="card-title">Findings by Severity</div>
        <canvas id="severityChart"></canvas>
      </div>
      <div class="chart-box">
        <div class="card-title">Test Results (Pass vs Fail)</div>
        <canvas id="passFailChart"></canvas>
      </div>
    </div>

    <div class="card" style="margin-bottom: 30px;">
      <h3 style="margin-top: 0;">Executive Summary</h3>
      <p style="color: #cbd5e1; line-height: 1.6;">
        AegisProbe AI completed an authorized security assessment against <strong>{{ target }}</strong>.
        Testing evaluated prompt injection resilience, safety boundary containment, prompt & confidential canary leakage,
        MCP protocol permissions, coding agent sandbox controls, and transactional chatbots.
      </p>
      <p style="color: #cbd5e1; line-height: 1.6;">
        Overall security posture evaluation determined a risk rating of <strong>{{ risk_level }}</strong>.
        Remediations below prioritize mitigating direct instruction override vectors and enforcing strict validation schemas on backend tools.
      </p>
    </div>

    <h2>Detailed Findings ({{ findings | length }})</h2>
    {% for f in findings %}
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-title">
          <span style="color: var(--accent); margin-right: 8px;">[{{ f.id }}]</span> {{ f.title }}
        </div>
        <span class="badge badge-{{ f.severity | lower }}">{{ f.severity }}</span>
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
        <div>
          <div class="meta-label">Category</div>
          <div class="meta-val">{{ f.category }}</div>
          <div class="meta-label">Description</div>
          <div class="meta-val">{{ f.description }}</div>
        </div>
        <div>
          <div class="meta-label">Impact</div>
          <div class="meta-val" style="color: #fca5a5;">{{ f.impact }}</div>
          <div class="meta-label">Remediation Guidance</div>
          <div class="meta-val" style="color: #86efac;">{{ f.remediation }}</div>
        </div>
      </div>
      <div class="meta-label" style="margin-top: 10px;">Evidence / Trigger Telemetry</div>
      <pre class="code-evidence">{{ f.evidence }}</pre>
    </div>
    {% endfor %}

    <div class="card" style="margin-top: 40px;">
      <h3 style="margin-top:0;">Testing Methodology & Limitations</h3>
      <p style="font-size: 13px; color: var(--text-muted); line-height: 1.6;">
        Assessments are conducted according to OWASP Top 10 for LLMs and NIST AI Risk Management Framework (AI 100-2).
        Automated testing checks for known instruction conflict patterns and boundary failures in authorized test targets.
        A passed test suite does not guarantee absolute immunity against non-deterministic or adaptive multi-turn adversarial inputs.
      </p>
    </div>
  </div>

  <script>
    const sevCtx = document.getElementById('severityChart');
    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
          data: [{{ sev_counts.CRITICAL }}, {{ sev_counts.HIGH }}, {{ sev_counts.MEDIUM }}, {{ sev_counts.LOW }}, {{ sev_counts.INFO }}],
          backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#3b82f6', '#06b6d4'],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { color: '#94a3b8' } } }
      }
    });

    const pfCtx = document.getElementById('passFailChart');
    new Chart(pfCtx, {
      type: 'pie',
      data: {
        labels: ['Passed Tests', 'Failed Tests'],
        datasets: [{
          data: [{{ passed_tests }}, {{ failed_tests }}],
          backgroundColor: ['#10b981', '#ef4444'],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { color: '#94a3b8' } } }
      }
    });
  </script>
</body>
</html>"""


def generate_html_report(scan_data: Dict[str, Any], output_path: str) -> str:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    findings = scan_data.get("findings", [])
    total_tests = scan_data.get("total_tests", 0)
    passed_tests = scan_data.get("passed_tests", 0)
    failed_tests = scan_data.get("failed_tests", 0)
    risk_info = scan_data.get("risk_assessment", {})
    sev_counts = risk_info.get("counts", {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})
    pass_ratio = round((passed_tests / total_tests * 100), 1) if total_tests > 0 else 100.0

    rendered = Template(HTML_TEMPLATE).render(
        target=scan_data.get("target", "127.0.0.1"),
        scan_id=scan_data.get("scan_id", "scan-unknown"),
        started_at=scan_data.get("started_at", "N/A"),
        risk_level=risk_info.get("level", "INFO"),
        risk_score=risk_info.get("score", 0.0),
        risk_status=risk_info.get("status", "COMPLETE"),
        total_tests=total_tests,
        passed_tests=passed_tests,
        failed_tests=failed_tests,
        pass_ratio=pass_ratio,
        modules=scan_data.get("modules", []),
        findings=findings,
        sev_counts=sev_counts
    )

    with open(p, "w", encoding="utf-8") as f:
        f.write(rendered)
    return str(p.resolve())
