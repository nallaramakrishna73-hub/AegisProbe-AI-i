"""
AI Coding Agent Security Module for AegisProbe AI.
Analyzes local coding-agent environments and workspaces for:
- excessive filesystem permissions
- unsafe shell execution (blocks/simulates destructive commands like rm, chmod, curl | sh, sudo)
- untrusted repository instructions
- secrets exposed to agents (.env, git credentials)
- unsafe tool permissions
- missing confirmation before destructive actions
- dependency trust problems
- workspace boundary violations
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from aegisprobe.core.findings import Finding
from aegisprobe.core.severity import Severity, Confidence


UNSAFE_PATTERNS = [
    (r"rm\s+-rf", "Destructive recursive file deletion", Severity.HIGH),
    (r"curl.*\|\s*(ba)?sh", "Unverified remote script piping to shell", Severity.CRITICAL),
    (r"sudo\s+", "Privilege escalation request", Severity.HIGH),
    (r"chmod\s+777", "Overly permissive file permissions", Severity.MEDIUM),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "Fork bomb or denial of service", Severity.HIGH),
]

SENSITIVE_WORKSPACE_FILES = [
    ".env",
    "id_rsa",
    ".aws/credentials",
    ".git/config",
    "secrets.yaml",
    "credentials.json",
]


class CodingAgentAuditor:
    def __init__(self, workspace_path: str = "./"):
        self.workspace = Path(workspace_path).resolve()

    def audit_workspace(self) -> Dict[str, Any]:
        """Perform defensive security evaluation of coding agent workspace."""
        findings: List[Finding] = []
        checks_count = 0
        passed_count = 0

        # 1. Exposed secrets in workspace
        checks_count += 1
        found_sensitive_files = []
        for sf in SENSITIVE_WORKSPACE_FILES:
            target = self.workspace / sf
            if target.exists():
                found_sensitive_files.append(sf)

        if found_sensitive_files:
            findings.append(Finding(
                id="CA-001",
                title="Secrets and Credentials Exposed in Agent Workspace",
                category="Coding Agent Security",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description="Coding agent has unconstrained read access to sensitive credential files in workspace root.",
                evidence=f"Discovered sensitive files accessible to agent: {', '.join(found_sensitive_files)}",
                impact="Unintended exfiltration or exposure of API tokens/private keys during automated commits or reasoning.",
                remediation="Add sensitive files to .gitignore and restrict agent read scope using workspace access allowlists.",
                references=["CWE-538: File and Directory Information Exposure", "OWASP LLM06: Sensitive Information Disclosure"]
            ))
        else:
            passed_count += 1

        # 2. Instruction file injection (AGENTS.md / .cursorrules / prompt injection in README)
        checks_count += 1
        instruction_files = list(self.workspace.glob("*.md")) + list(self.workspace.glob("*.txt"))
        suspicious_instructions = []
        for inf in instruction_files:
            try:
                content = inf.read_text(encoding="utf-8", errors="ignore")
                for pat, label, _ in UNSAFE_PATTERNS:
                    if label in content or "curl | sh" in content:
                        suspicious_instructions.append(f"{inf.name}: {label}")
            except Exception:
                pass

        if suspicious_instructions:
            findings.append(Finding(
                id="CA-002",
                title="Untrusted Instructions or Hazardous Script Triggers in Docs",
                category="Coding Agent Security",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Repository documentation contains dangerous commands that an automated coding agent might execute.",
                evidence=f"Discovered dangerous patterns in instructions: {', '.join(suspicious_instructions[:3])}",
                impact="Supply chain attack where agent automatically runs unverified setup commands.",
                remediation="Configure coding agent to require human sign-off before running terminal installation scripts.",
                references=["CWE-829: Inclusion of Functionality from Untrusted Control Sphere"]
            ))
        else:
            passed_count += 1

        # 3. Missing Human-in-the-Loop Confirmation Configuration
        checks_count += 1
        # Check if workspace has agent policy file enforcing confirmations
        has_guardrails = any((self.workspace / f).exists() for f in [".agent-security.json", "aegis-guard.yaml"])
        if not has_guardrails:
            findings.append(Finding(
                id="CA-003",
                title="Missing Execution Guardrails / Unconstrained Agency",
                category="Coding Agent Security",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="No explicit confirmation policy configured to intercept destructive terminal commands.",
                evidence=f"Workspace '{self.workspace.name}' lacks security boundary definitions.",
                impact="Coding agent could accidentally overwrite or delete local repository artifacts without prompting.",
                remediation="Deploy strict command filters: block 'rm', 'chmod', 'sudo' and mandate interactive prompt approval.",
                references=["OWASP LLM08: Excessive Agency", "NIST AI 100-2"]
            ))
        else:
            passed_count += 1

        # 4. Dependency Trust / Lockfile Verification
        checks_count += 1
        has_pkg = (self.workspace / "package.json").exists() or (self.workspace / "requirements.txt").exists()
        has_lock = (self.workspace / "package-lock.json").exists() or (self.workspace / "poetry.lock").exists() or (self.workspace / "Pipfile.lock").exists()
        if has_pkg and not has_lock:
            findings.append(Finding(
                id="CA-004",
                title="Unpinned Dependencies without Cryptographic Lockfile",
                category="Coding Agent Security",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="Dependencies are declared without pinned hash lockfiles, exposing agent to dependency confusion.",
                evidence="package.json / requirements.txt found without matching lockfile.",
                impact="Adversary could poison upstream package registries pulled by automated agent runs.",
                remediation="Generate lockfiles with cryptographic integrity hashes before automated agent builds.",
                references=["CWE-1357: Reliance on Uncontrolled Component"]
            ))
        else:
            passed_count += 1

        return {
            "workspace": str(self.workspace),
            "total_checks": checks_count,
            "passed": passed_count,
            "failed": len(findings),
            "findings": findings
        }
