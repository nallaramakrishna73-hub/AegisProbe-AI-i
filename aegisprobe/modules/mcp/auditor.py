"""
Model Context Protocol (MCP) Security Auditor for AegisProbe AI.
Analyzes mcp.json and tool configurations for:
- excessive permissions
- dangerous tool capabilities
- missing validation
- unclear tool descriptions
- untrusted tool metadata
- overly broad filesystem access
- network access
- missing authorization boundaries
- unsafe parameter handling
Provides safe simulated audit without executing untrusted tools.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from aegisprobe.core.findings import Finding
from aegisprobe.core.severity import Severity, Confidence


DANGEROUS_COMMANDS = {"rm", "chmod", "curl", "wget", "bash", "sh", "sudo", "eval", "exec", "nc", "python -c"}
SENSITIVE_PATHS = {"/", "/etc", "/root", "/var", "~/.ssh", "~/.aws", "C:\\Windows"}


class MCPSecurityAuditor:
    def __init__(self, simulate: bool = True):
        self.simulate = simulate

    def audit_config_data(self, data: Dict[str, Any], source_name: str = "mcp.json") -> Dict[str, Any]:
        """Perform static security audit of MCP servers, tools, and permission boundaries."""
        findings: List[Finding] = []
        checks_count = 0
        passed_count = 0

        servers = data.get("mcpServers", {}) or data.get("servers", {})
        if not servers and isinstance(data, dict):
            # Might be flat tool list
            servers = {"default": data}

        for server_name, server_cfg in servers.items():
            checks_count += 1
            command = server_cfg.get("command", "")
            args = server_cfg.get("args", [])
            args_str = " ".join(str(a) for a in args)
            env = server_cfg.get("env", {})

            # 1. Check dangerous execution command
            if any(dc in command.lower() for dc in DANGEROUS_COMMANDS):
                findings.append(Finding(
                    id=f"MCP-001-{server_name}",
                    title="Excessive Tool Permission: Dangerous Base Command",
                    category="MCP Security",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Server '{server_name}' uses high-risk executable: '{command}'",
                    evidence=f"Server command: {command} {args_str}",
                    impact="Potential arbitrary command execution if prompt injection occurs.",
                    remediation="Wrap commands in restricted, sandboxed binaries with argument whitelisting.",
                    references=["MCP Specification Security Guidelines", "CWE-78: OS Command Injection"]
                ))
            else:
                passed_count += 1

            # 2. Check filesystem scope & paths
            checks_count += 1
            has_broad_path = False
            for path in SENSITIVE_PATHS:
                if path in args_str:
                    has_broad_path = True
                    findings.append(Finding(
                        id=f"MCP-002-{server_name}",
                        title="Overly Broad Filesystem Access in MCP Scope",
                        category="MCP Security",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"Server '{server_name}' allows access to sensitive root/system directory: {path}",
                        evidence=f"Arguments contain path reference: {path}",
                        impact="Host file inspection, secret leakage, or unauthorized filesystem tampering.",
                        remediation="Constrain filesystem MCP tool to a specific isolated workspace folder.",
                        references=["CWE-22: Path Traversal", "MCP Filesystem Server Security"]
                    ))
                    break
            if not has_broad_path:
                passed_count += 1

            # 3. Check environment secret exposure
            checks_count += 1
            exposed_keys = []
            for k in env.keys():
                if any(secret_term in k.upper() for secret_term in ["KEY", "SECRET", "TOKEN", "PASS"]):
                    exposed_keys.append(k)
            if exposed_keys:
                findings.append(Finding(
                    id=f"MCP-003-{server_name}",
                    title="Sensitive Environment Variables Statically Configured",
                    category="MCP Security",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=f"Server '{server_name}' stores sensitive credentials directly in configuration.",
                    evidence=f"Sensitive keys detected: {', '.join(exposed_keys)}",
                    impact="Credential theft from version-controlled configuration files.",
                    remediation="Inject credentials at runtime via secret managers or system keychains.",
                    references=["CWE-798: Use of Hard-coded Credentials"]
                ))
            else:
                passed_count += 1

            # 4. Check tool schemas and input validation
            tools = server_cfg.get("tools", [])
            for tool in tools:
                checks_count += 1
                name = tool.get("name", "unnamed")
                desc = tool.get("description", "")
                schema = tool.get("inputSchema", {})

                # Missing or vague description
                if len(desc.strip()) < 15:
                    findings.append(Finding(
                        id=f"MCP-004-{name}",
                        title="Unclear Tool Description / Ambiguous Trust Boundary",
                        category="MCP Security",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        description=f"Tool '{name}' lacks clear description of intended constraints.",
                        evidence=f"Description length: {len(desc)} characters ('{desc}')",
                        impact="Agent confusion during tool routing; increased susceptibility to prompt injection.",
                        remediation="Provide unambiguous documentation of tool boundaries and limitations.",
                        references=["OWASP LLM07: Insecure Plugin Design"]
                    ))
                else:
                    passed_count += 1

                # Missing JSON Schema type constraints
                checks_count += 1
                if not schema.get("properties"):
                    findings.append(Finding(
                        id=f"MCP-005-{name}",
                        title="Missing Input Validation Schema in Tool Definition",
                        category="MCP Security",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"Tool '{name}' accepts unvalidated freeform arguments.",
                        evidence=f"Schema properties are empty or unconstrained: {schema}",
                        impact="Unvalidated input passed directly to backend tool handler.",
                        remediation="Define strict JSON schemas specifying types, patterns, and required fields.",
                        references=["CWE-20: Improper Input Validation"]
                    ))
                else:
                    passed_count += 1

        # Audit Logging check
        checks_count += 1
        if not data.get("logging") and not data.get("audit"):
            findings.append(Finding(
                id="MCP-006",
                title="Missing Audit Logging Configuration",
                category="MCP Security",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="MCP server configuration does not specify audit trail logging for tool invocations.",
                evidence="No 'logging' or 'audit' keys defined in root MCP configuration.",
                impact="Inability to reconstruct forensic evidence in event of agent misbehavior.",
                remediation="Enable centralized audit logging for all MCP tool requests and responses.",
                references=["NIST SP 800-92: Guide to Computer Security Log Management"]
            ))
        else:
            passed_count += 1

        return {
            "source": source_name,
            "total_checks": checks_count,
            "passed": passed_count,
            "failed": len(findings),
            "findings": findings
        }

    def audit_file(self, config_path: str) -> Dict[str, Any]:
        p = Path(config_path)
        if not p.exists():
            return {
                "error": f"Config file not found: {config_path}",
                "total_checks": 0,
                "passed": 0,
                "failed": 0,
                "findings": []
            }
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            return self.audit_config_data(data, source_name=p.name)
        except Exception as e:
            return {
                "error": f"Failed to parse MCP JSON: {str(e)}",
                "total_checks": 0,
                "passed": 0,
                "failed": 0,
                "findings": []
            }
