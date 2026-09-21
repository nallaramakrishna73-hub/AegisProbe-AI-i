"""
AegisProbe AI — Professional Command Line Interface for Kali Linux.
"AI Security Testing from the Command Line."
"""

import sys
import os
import asyncio
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

from aegisprobe import __version__
from aegisprobe.config import load_config, save_config, AegisConfig
from aegisprobe.core.engine import AegisScannerEngine
from aegisprobe.core.safety import is_target_authorized, save_authorized_target, load_authorized_targets
from aegisprobe.database.repository import DatabaseRepository
from aegisprobe.reporting.json_report import generate_json_report
from aegisprobe.reporting.html_report import generate_html_report
from aegisprobe.reporting.pdf_report import generate_pdf_report

# Modules
from aegisprobe.modules.prompt_injection.scanner import PromptInjectionScanner
from aegisprobe.modules.jailbreak.scanner import JailbreakScanner
from aegisprobe.modules.prompt_leakage.scanner import PromptLeakageScanner
from aegisprobe.modules.mcp.auditor import MCPSecurityAuditor
from aegisprobe.modules.browser_agent.auditor import BrowserAgentAuditor
from aegisprobe.modules.coding_agent.auditor import CodingAgentAuditor
from aegisprobe.modules.finbot.scanner import FinBotSecurityScanner
from aegisprobe.modules.dataset_poisoning.analyzer import DatasetPoisoningAnalyzer
from aegisprobe.lab.manager import LabManager

app = typer.Typer(
    help="AegisProbe AI — Authorized AI/LLM Security Assessment Framework for Kali Linux",
    no_args_is_help=False
)
console = Console()


def print_banner():
    banner_text = (
        "[bold cyan]╔══════════════════════════════════════════════════════════════════╗[/bold cyan]\n"
        "[bold cyan]║[/bold cyan]                         [bold white]AEGISPROBE AI[/bold white]                            [bold cyan]║[/bold cyan]\n"
        "[bold cyan]║[/bold cyan]            [dim]AI Security Assessment Framework for Kali Linux[/dim]       [bold cyan]║[/bold cyan]\n"
        "[bold cyan]║[/bold cyan]          [italic green]\"AI Security Testing from the Command Line.\"[/italic green]            [bold cyan]║[/bold cyan]\n"
        "[bold cyan]╚══════════════════════════════════════════════════════════════════╝[/bold cyan]"
    )
    console.print(banner_text)
    console.print(f"[dim]Version: {__version__} | Mode: Authorized Defensive Security Testing[/dim]\n")


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context):
    """Entry point showing polished Kali Linux banner when run without arguments."""
    if ctx.invoked_subcommand is None:
        print_banner()
        table = Table(title="Available AegisProbe Security Commands", box=box.ROUNDED)
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")

        table.add_row("scan", "Run multi-module assessment against an authorized target")
        table.add_row("prompt-injection", "Evaluate prompt injection & untrusted instruction handling")
        table.add_row("jailbreak", "Benchmark safety policy resistance & boundary containment")
        table.add_row("prompt-leakage", "Detect system prompt, canary & configuration disclosures")
        table.add_row("mcp-audit", "Audit Model Context Protocol (MCP) server & tool configurations")
        table.add_row("browser-audit", "Assess AI browser agents against adversarial web targets")
        table.add_row("coding-agent", "Audit local coding-agent workspaces & execution guardrails")
        table.add_row("finbot", "Test financial chatbot authorization boundaries & fund safety")
        table.add_row("dataset-audit", "Analyze datasets for poisoning triggers, outliers & duplicates")
        table.add_row("lab", "Manage local intentionally vulnerable training lab services")
        table.add_row("report", "Generate HTML, PDF, and JSON reports from past scans")
        table.add_row("results", "List stored scan history and risk scores in database")
        table.add_row("target", "Manage and view authorized test target list")
        table.add_row("config", "Inspect or update AegisProbe runtime configuration")
        table.add_row("version", "Show framework version and active AI provider")

        console.print(table)
        console.print("\n[dim]Run [bold]aegisprobe <command> --help[/bold] for detailed command options.[/dim]")


@app.command("version")
def version():
    """Show AegisProbe AI version, engine status, and provider info."""
    cfg = load_config()
    console.print(f"[bold cyan]AegisProbe AI[/bold cyan] v{__version__}")
    console.print(f"Provider: [green]{cfg.provider}[/green] (Model: {cfg.model})")
    console.print(f"Endpoint: {cfg.base_url}")
    console.print(f"Database: {cfg.database_url}")


@app.command("config")
def config_cmd(
    action: str = typer.Argument("show", help="show or set"),
    key: Optional[str] = typer.Option(None, "--key", "-k", help="Config key to set"),
    value: Optional[str] = typer.Option(None, "--value", "-v", help="Config value to set")
):
    """Inspect or update AegisProbe runtime configuration."""
    cfg = load_config()
    if action == "set":
        if not key or value is None:
            console.print("[red]Error:[/red] Specify --key and --value to update configuration.")
            raise typer.Exit(1)
        if hasattr(cfg, key):
            setattr(cfg, key, value)
            save_config(cfg)
            console.print(f"[green]✓ Updated {key} = {value}[/green]")
        else:
            console.print(f"[red]Invalid config key '{key}'[/red]")
    else:
        table = Table(title="AegisProbe Runtime Configuration", box=box.ROUNDED)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="white")
        for k, v in cfg.model_dump().items():
            if "key" in k.lower() or "token" in k.lower():
                val_str = "********" if v else "[dim]not set[/dim]"
            else:
                val_str = str(v)
            table.add_row(k, val_str)
        console.print(table)


@app.command("target")
def target_cmd(
    action: str = typer.Argument("list", help="list or add"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Target URL to authorize"),
    description: Optional[str] = typer.Option("", "--desc", "-d", help="Target description")
):
    """Manage authorized target domains and endpoints."""
    if action == "add":
        if not url:
            console.print("[bold red]Error:[/bold red] Please provide target URL with --url <url>")
            raise typer.Exit(1)
        save_authorized_target(url, description or "")
        console.print(f"[green]✓ Target authorized and saved:[/green] {url}")
    else:
        targets = load_authorized_targets()
        table = Table(title="Explicitly Authorized External Targets", box=box.SIMPLE)
        table.add_column("Target URL", style="cyan")
        table.add_column("Description", style="white")
        table.add_row("localhost / 127.0.0.1", "Default Loopback (Always Authorized)")
        for t in targets:
            table.add_row(t.get("url", ""), t.get("description", ""))
        console.print(table)


@app.command("scan")
def scan_cmd(
    target: str = typer.Option("http://127.0.0.1:8080", "--target", "-t", help="Target endpoint to test"),
    modules: Optional[str] = typer.Option(None, "--modules", "-m", help="Comma-separated module list"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory for reports"),
    lab: bool = typer.Option(False, "--lab", help="Enable test against local intentionally vulnerable lab"),
    format: str = typer.Option("all", "--format", "-f", help="Report format: html, pdf, json, or all")
):
    """Execute unified multi-module AI security assessment."""
    print_banner()

    # Safety confirmation for external targets
    if not is_target_authorized(target, is_lab_mode=lab):
        console.print(Panel(
            f"[bold red]WARNING: External Target Detected[/bold red]\n\n"
            f"You are about to test: [bold underline]{target}[/bold underline]\n\n"
            "AegisProbe AI is an authorized defensive security tool.\n"
            "Confirm that you possess explicit authorization to test this endpoint.",
            box=box.ROUNDED,
            border_style="red"
        ))
        confirm = typer.confirm("Continue scan?", default=False)
        if not confirm:
            console.print("[yellow]Scan aborted by user.[/yellow]")
            raise typer.Exit(0)
        save_authorized_target(target, "User confirmed authorized scan")

    engine = AegisScannerEngine()
    active_mods = [m.strip() for m in modules.split(",")] if modules else None

    console.print(Panel(
        f"[bold white]AegisProbe AI Security Assessment[/bold white]\n"
        f"Target: [cyan]{target}[/cyan]  |  Lab Mode: {'[green]Active[/green]' if lab else '[dim]Standard[/dim]'}",
        box=box.ROUNDED,
        border_style="cyan"
    ))

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40, style="cyan", complete_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[1/6] Running Security Modules...", total=100)

        def cb(mod_name, step, total_steps):
            pct = (step / total_steps) * 100
            progress.update(task, description=f"[{step}/{total_steps}] Testing {mod_name}...", completed=pct)

        result = asyncio.run(engine.execute_scan(target, modules=active_mods, is_lab=lab, progress_callback=cb))
        progress.update(task, description="[bold green]Scan complete![/bold green]", completed=100)

    # Print Summary Table
    counts = result.risk_assessment.get("counts", {})
    console.print("\n[bold]Risk Breakdown:[/bold]")
    console.print(f"  CRITICAL: [bold red]{counts.get('CRITICAL', 0)}[/bold red]")
    console.print(f"  HIGH:     [bold yellow]{counts.get('HIGH', 0)}[/bold yellow]")
    console.print(f"  MEDIUM:   [yellow]{counts.get('MEDIUM', 0)}[/yellow]")
    console.print(f"  LOW:      [blue]{counts.get('LOW', 0)}[/blue]")
    console.print(f"  INFO:     [cyan]{counts.get('INFO', 0)}[/cyan]")
    console.print(f"  Overall Score: [bold cyan]{result.risk_assessment.get('score')}/100[/bold cyan] ({result.risk_assessment.get('status')})\n")

    # Generate Reports
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    scan_data = result.to_dict()

    html_file = out_dir / f"{result.scan_id}.html"
    pdf_file = out_dir / f"{result.scan_id}.pdf"
    json_file = out_dir / f"{result.scan_id}.json"

    if format in ("html", "all"):
        generate_html_report(scan_data, str(html_file))
        console.print(f"[green]✓ HTML Report:[/green] {html_file}")
    if format in ("pdf", "all"):
        try:
            generate_pdf_report(scan_data, str(pdf_file))
            console.print(f"[green]✓ PDF Report:[/green]  {pdf_file}")
        except Exception as e:
            console.print(f"[yellow]! PDF Generation Notice:[/yellow] {e}")
    if format in ("json", "all"):
        generate_json_report(scan_data, str(json_file))
        console.print(f"[green]✓ JSON Report:[/green] {json_file}")


@app.command("prompt-injection")
def prompt_injection_cmd(
    target: str = typer.Option("http://127.0.0.1:8080", "--target", "-t", help="Target URL")
):
    """Execute categorized prompt injection test suite."""
    print_banner()
    console.print(f"[bold cyan]Running Prompt Injection Assessment against {target}...[/bold cyan]")
    scanner = PromptInjectionScanner()
    res = asyncio.run(scanner.run(target))

    table = Table(title="Prompt Injection Assessment", box=box.ROUNDED)
    table.add_column("Test ID", style="cyan")
    table.add_column("Category", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Severity")

    for d in res["details"]:
        status_str = "[green]PASSED[/green]" if d["passed"] else "[red]FAILED[/red]"
        table.add_row(d["id"], d["category"], status_str, d["severity"])

    console.print(table)
    console.print(f"\nTests: {res['total']} | Passed: [green]{res['passed']}[/green] | Potential Issues: [red]{res['failed']}[/red]")


@app.command("jailbreak")
def jailbreak_cmd(
    target: str = typer.Option("http://127.0.0.1:8080", "--target", "-t", help="Target URL")
):
    """Evaluate jailbreak resistance and policy boundary preservation."""
    print_banner()
    console.print(f"[bold cyan]Running Jailbreak Resistance Evaluation against {target}...[/bold cyan]")
    scanner = JailbreakScanner()
    res = asyncio.run(scanner.run(target))

    table = Table(title="Jailbreak Resistance Assessment", box=box.ROUNDED)
    table.add_column("Test ID", style="cyan")
    table.add_column("Category", style="white")
    table.add_column("Status", style="bold")

    for d in res["details"]:
        status_str = "[green]PASSED[/green]" if d["passed"] else "[red]BOUNDARY FAILURE[/red]"
        table.add_row(d["id"], d["category"], status_str)

    console.print(table)
    console.print(f"\nResistance Score: [bold green]{res['resistance_score']}%[/bold green]")


@app.command("prompt-leakage")
def prompt_leakage_cmd(
    target: str = typer.Option("http://127.0.0.1:8080", "--target", "-t", help="Target URL")
):
    """Detect hidden system instructions, canaries, and confidential configuration leaks."""
    print_banner()
    console.print(f"[bold cyan]Running Prompt & Secret Leakage Scanner against {target}...[/bold cyan]")
    scanner = PromptLeakageScanner()
    res = asyncio.run(scanner.run(target))

    table = Table(title="Prompt Leakage Assessment", box=box.ROUNDED)
    table.add_column("Test ID", style="cyan")
    table.add_column("Asset Tested", style="white")
    table.add_column("Status", style="bold")

    for d in res["details"]:
        status_str = "[green]PROTECTED[/green]" if d["passed"] else "[red]LEAK DETECTED[/red]"
        table.add_row(d["id"], d["asset"], status_str)

    console.print(table)


@app.command("mcp-audit")
def mcp_audit_cmd(
    config: str = typer.Option("mcp.json", "--config", "-c", help="Path to MCP configuration file")
):
    """Audit Model Context Protocol (MCP) server & tool configuration boundaries."""
    print_banner()
    auditor = MCPSecurityAuditor()
    res = auditor.audit_file(config)
    if "error" in res and res.get("total_checks", 0) == 0:
        # Generate inline sample audit if file not found
        console.print(f"[yellow]Config '{config}' not found, auditing sample MCP template...[/yellow]")
        sample = {
            "mcpServers": {
                "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]},
                "shell_helper": {"command": "sh", "args": ["-c", "run.sh"]},
                "db": {"command": "uvx", "args": ["mcp-server-sqlite", "app.db"], "env": {"API_KEY": "sk-12345"}}
            }
        }
        res = auditor.audit_config_data(sample, source_name="sample_mcp.json")

    console.print("\n[bold]MCP Security Assessment Results:[/bold]")
    for f in res["findings"]:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        console.print(f"[{f.severity.color}][{sev}][/{f.severity.color}] {f.title}")
        console.print(f"  [dim]Evidence: {f.evidence}[/dim]")
        console.print(f"  [green]Remediation: {f.remediation}[/green]\n")


@app.command("browser-audit")
def browser_audit_cmd(
    url: str = typer.Option("http://127.0.0.1:8080/browser-target", "--url", "-u", help="URL to audit")
):
    """Audit AI Browser Agent interactions against adversarial web page instructions."""
    print_banner()
    console.print(f"[bold cyan]Auditing Browser Agent Security on {url}...[/bold cyan]")
    auditor = BrowserAgentAuditor()
    res = asyncio.run(auditor.audit_url(url))

    if "error" in res:
        console.print(f"[red]Error:[/red] {res['error']}")
        raise typer.Exit(1)

    console.print(f"Checks: {res['total_checks']} | Passed: [green]{res['passed']}[/green] | Findings: [red]{res['failed']}[/red]")
    for f in res["findings"]:
        console.print(f"[{f.severity.color}][{f.severity.value}][/{f.severity.color}] {f.title}")


@app.command("coding-agent")
def coding_agent_cmd(
    workspace: str = typer.Option(".", "--workspace", "-w", help="Path to coding agent workspace directory")
):
    """Audit coding agent workspace permissions, dangerous commands, and secret exposure."""
    print_banner()
    console.print(f"[bold cyan]Auditing Coding Agent Workspace at '{workspace}'...[/bold cyan]")
    auditor = CodingAgentAuditor(workspace)
    res = auditor.audit_workspace()

    console.print(f"Checks: {res['total_checks']} | Passed: [green]{res['passed']}[/green] | Findings: [red]{res['failed']}[/red]")
    for f in res["findings"]:
        console.print(f"[{f.severity.color}][{f.severity.value}][/{f.severity.color}] {f.title}")
        console.print(f"  [dim]{f.description}[/dim]")


@app.command("finbot")
def finbot_cmd(
    target: str = typer.Option("http://127.0.0.1:8080", "--target", "-t", help="FinBot target endpoint")
):
    """Test AI Financial chatbot authorization boundaries and fund protection."""
    print_banner()
    console.print(f"[bold cyan]Testing FinBot Security against {target}...[/bold cyan]")
    scanner = FinBotSecurityScanner()
    res = asyncio.run(scanner.run(target))

    table = Table(title="FinBot Security Assessment (Synthetic Data Only)", box=box.ROUNDED)
    table.add_column("Test ID", style="cyan")
    table.add_column("Scenario", style="white")
    table.add_column("Status", style="bold")

    for d in res["details"]:
        status_str = "[green]SECURE[/green]" if d["passed"] else "[red]VULNERABILITY DETECTED[/red]"
        table.add_row(d["id"], d["scenario"], status_str)

    console.print(table)


@app.command("dataset-audit")
def dataset_audit_cmd(
    file: str = typer.Option(..., "--file", "-f", help="Path to dataset file (.jsonl, .json, .csv, .txt)")
):
    """Analyze training datasets for poisoning triggers, outliers, anomalies, and duplicate density."""
    print_banner()
    analyzer = DatasetPoisoningAnalyzer(file)
    res = analyzer.analyze()

    if "error" in res:
        console.print(f"[red]Error:[/red] {res['error']}")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold white]Dataset Security Audit[/bold white]\n"
        f"File: [cyan]{res['file']}[/cyan] ({res['format']})\n\n"
        f"Records: [bold]{res['records']:,}[/bold]\n"
        f"Duplicates: [yellow]{res['duplicates']}[/yellow]\n"
        f"Outliers: [yellow]{res['outliers']}[/yellow]\n"
        f"Suspicious Samples: [bold red]{res['suspicious_samples']}[/bold red]\n"
        f"Malformed Records: [red]{res['malformed_records']}[/red]\n\n"
        f"Risk: [bold yellow]{res['risk']}[/bold yellow]",
        box=box.ROUNDED,
        border_style="yellow"
    ))


@app.command("lab")
def lab_cmd(
    action: str = typer.Argument("status", help="start, stop, status, or reset")
):
    """Manage local intentionally vulnerable training lab services."""
    print_banner()
    act = action.lower()
    if act == "start":
        res = LabManager.start()
        console.print(f"[green]✓ {res['message']}[/green]")
        console.print(f"Canary: [cyan]{res['canary']}[/cyan]")
    elif act == "stop":
        res = LabManager.stop()
        console.print(f"[yellow]{res['message']}[/yellow]")
    elif act == "reset":
        res = LabManager.reset()
        console.print(f"[green]✓ {res['message']}[/green]")
    else:
        res = LabManager.status()
        status_color = "green" if res["running"] else "red"
        console.print(f"Lab Status: [{status_color}]{res['status']}[/{status_color}]")
        if res["running"]:
            console.print(f"Endpoint: {res['url']}")
            console.print(f"Synthetic Canary: {res['canary']}")


@app.command("results")
def results_cmd(
    limit: int = typer.Option(10, "--limit", "-l", help="Number of scans to display")
):
    """List historical scan records and ratings from local SQLite database."""
    print_banner()
    repo = DatabaseRepository()
    scans = repo.list_scans(limit=limit)

    if not scans:
        console.print("[dim]No past scans found in database. Run 'aegisprobe scan' to initiate a security audit.[/dim]")
        return

    table = Table(title="Recent AegisProbe AI Security Audits", box=box.ROUNDED)
    table.add_column("Scan ID", style="cyan")
    table.add_column("Target URL", style="white")
    table.add_column("Risk Level", style="bold")
    table.add_column("Score", style="yellow")
    table.add_column("Pass / Fail", style="dim")

    for s in scans:
        table.add_row(
            s["id"],
            s["target_url"],
            s["risk_level"],
            f"{s['risk_score']}/100",
            f"{s['passed_tests']} / {s['failed_tests']}"
        )
    console.print(table)


@app.command("report")
def report_cmd(
    scan_id: Optional[str] = typer.Option(None, "--id", "-i", help="Scan ID to export"),
    format: str = typer.Option("html", "--format", "-f", help="html, pdf, or json"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory")
):
    """Export report for an existing scan."""
    repo = DatabaseRepository()
    if not scan_id:
        scans = repo.list_scans(limit=1)
        if not scans:
            console.print("[red]No scans found to report.[/red]")
            raise typer.Exit(1)
        scan_id = scans[0]["id"]

    scan_data = repo.get_scan(scan_id)
    if not scan_data:
        console.print(f"[red]Scan ID '{scan_id}' not found.[/red]")
        raise typer.Exit(1)

    out_path = Path(output)
    out_path.mkdir(parents=True, exist_ok=True)

    if format == "html":
        fp = out_path / f"{scan_id}.html"
        generate_html_report(scan_data, str(fp))
        console.print(f"[green]✓ Generated HTML report:[/green] {fp}")
    elif format == "pdf":
        fp = out_path / f"{scan_id}.pdf"
        generate_pdf_report(scan_data, str(fp))
        console.print(f"[green]✓ Generated PDF report:[/green] {fp}")
    elif format == "json":
        fp = out_path / f"{scan_id}.json"
        generate_json_report(scan_data, str(fp))
        console.print(f"[green]✓ Generated JSON report:[/green] {fp}")


def main():
    app()


if __name__ == "__main__":
    main()
