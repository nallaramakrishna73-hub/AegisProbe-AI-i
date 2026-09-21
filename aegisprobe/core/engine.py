"""
Unified Scanning Engine for AegisProbe AI.
Orchestrates:
Target validation -> Module selection -> Test execution -> Evidence collection -> Finding generation -> Severity calculation -> Report generation
"""

import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from aegisprobe.core.target import Target
from aegisprobe.core.safety import is_target_authorized
from aegisprobe.core.severity import calculate_risk_score, Severity
from aegisprobe.core.findings import Finding
from aegisprobe.providers import get_ai_provider
from aegisprobe.config import AegisConfig, load_config
from aegisprobe.database.repository import DatabaseRepository

# Modules
from aegisprobe.modules.prompt_injection.scanner import PromptInjectionScanner
from aegisprobe.modules.jailbreak.scanner import JailbreakScanner
from aegisprobe.modules.prompt_leakage.scanner import PromptLeakageScanner
from aegisprobe.modules.mcp.auditor import MCPSecurityAuditor
from aegisprobe.modules.browser_agent.auditor import BrowserAgentAuditor
from aegisprobe.modules.coding_agent.auditor import CodingAgentAuditor
from aegisprobe.modules.finbot.scanner import FinBotSecurityScanner
from aegisprobe.modules.dataset_poisoning.analyzer import DatasetPoisoningAnalyzer


ALL_MODULES = [
    "prompt-injection",
    "jailbreak",
    "prompt-leakage",
    "mcp",
    "browser",
    "coding-agent",
    "finbot"
]


class ScanResult:
    def __init__(self, scan_id: str, target: str, modules: List[str]):
        self.scan_id = scan_id
        self.target = target
        self.modules = modules
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.completed_at: Optional[str] = None
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.findings: List[Finding] = []
        self.module_results: Dict[str, Any] = {}
        self.risk_assessment: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        sanitized_mod_results = {}
        for mod_name, mod_data in self.module_results.items():
            if isinstance(mod_data, dict):
                clean_dict = {}
                for k, v in mod_data.items():
                    if k == "findings" and isinstance(v, list):
                        clean_dict[k] = [f.to_dict() if hasattr(f, "to_dict") else f for f in v]
                    else:
                        clean_dict[k] = v
                sanitized_mod_results[mod_name] = clean_dict
            else:
                sanitized_mod_results[mod_name] = mod_data

        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "modules": self.modules,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "risk_assessment": self.risk_assessment,
            "findings": [f.to_dict() for f in self.findings],
            "module_results": sanitized_mod_results
        }


class AegisScannerEngine:
    def __init__(self, config: Optional[AegisConfig] = None):
        self.config = config or load_config()
        self.repo = DatabaseRepository(self.config.database_url)

    async def execute_scan(
        self,
        target_url: str,
        modules: Optional[List[str]] = None,
        is_lab: bool = False,
        progress_callback = None
    ) -> ScanResult:
        """Run full authorized security scan against target."""
        # 1. Target Validation & Safety Check
        target_obj = Target(url=target_url, is_lab=is_lab)
        if not is_target_authorized(target_obj.url, is_lab_mode=is_lab):
            raise PermissionError(
                f"Target '{target_url}' is not authorized. Localhost and lab targets are allowed by default. "
                f"Add external targets via 'aegisprobe target add <url>' or specify --lab."
            )

        if is_lab:
            try:
                from aegisprobe.lab.vulnerable_apps import LabServer
                if not LabServer.is_running():
                    LabServer.start()
            except Exception:
                pass

        active_modules = modules or ALL_MODULES
        scan_id = f"scan-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
        result = ScanResult(scan_id, target_obj.url, active_modules)

        provider = None
        try:
            provider = get_ai_provider(self.config)
        except Exception:
            provider = None

        total_steps = len(active_modules)

        for step_idx, mod in enumerate(active_modules, 1):
            if progress_callback:
                progress_callback(mod, step_idx, total_steps)

            mod_lower = mod.lower().replace("_", "-")

            if mod_lower in ("prompt-injection", "pi"):
                pi_scanner = PromptInjectionScanner(provider=provider)
                res = await pi_scanner.run(target_obj.url)
                result.module_results["prompt_injection"] = res
                result.findings.extend(res["findings"])
                result.total_tests += res["total"]
                result.passed_tests += res["passed"]
                result.failed_tests += res["failed"]

            elif mod_lower in ("jailbreak", "jb"):
                jb_scanner = JailbreakScanner(provider=provider)
                res = await jb_scanner.run(target_obj.url)
                result.module_results["jailbreak"] = res
                result.findings.extend(res["findings"])
                result.total_tests += res["total"]
                result.passed_tests += res["passed"]
                result.failed_tests += res["failed"]

            elif mod_lower in ("prompt-leakage", "pl"):
                pl_scanner = PromptLeakageScanner(provider=provider)
                res = await pl_scanner.run(target_obj.url)
                result.module_results["prompt_leakage"] = res
                result.findings.extend(res["findings"])
                result.total_tests += res["total"]
                result.passed_tests += res["passed"]
                result.failed_tests += res["failed"]

            elif mod_lower in ("mcp", "mcp-security", "mcp-audit"):
                auditor = MCPSecurityAuditor(simulate=True)
                sample_mcp = {
                    "mcpServers": {
                        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]},
                        "sqlite": {"command": "uvx", "args": ["mcp-server-sqlite", "--db-path", "test.db"]}
                    }
                }
                res = auditor.audit_config_data(sample_mcp, source_name="default_mcp_scope")
                result.module_results["mcp"] = res
                result.findings.extend(res["findings"])
                result.total_tests += res["total_checks"]
                result.passed_tests += res["passed"]
                result.failed_tests += res["failed"]

            elif mod_lower in ("browser", "browser-security", "browser-audit"):
                b_auditor = BrowserAgentAuditor()
                res = await b_auditor.audit_url(target_obj.url)
                result.module_results["browser"] = res
                result.findings.extend(res["findings"])
                result.total_tests += res["total_checks"]
                result.passed_tests += res["passed"]
                result.failed_tests += res["failed"]

            elif mod_lower in ("coding-agent", "coding"):
                c_auditor = CodingAgentAuditor()
                res = c_auditor.audit_workspace()
                result.module_results["coding_agent"] = res
                result.findings.extend(res["findings"])
                result.total_tests += res["total_checks"]
                result.passed_tests += res["passed"]
                result.failed_tests += res["failed"]

            elif mod_lower in ("finbot", "financial"):
                f_scanner = FinBotSecurityScanner(provider=provider)
                res = await f_scanner.run(target_obj.url)
                result.module_results["finbot"] = res
                result.findings.extend(res["findings"])
                result.total_tests += res["total"]
                result.passed_tests += res["passed"]
                result.failed_tests += res["failed"]

        result.completed_at = datetime.now(timezone.utc).isoformat()
        result.risk_assessment = calculate_risk_score(result.findings)

        # Save to database
        try:
            self.repo.save_scan(
                scan_id=result.scan_id,
                target_url=result.target,
                modules=result.modules,
                risk_score=result.risk_assessment["score"],
                risk_level=result.risk_assessment["level"],
                total_tests=result.total_tests,
                passed_tests=result.passed_tests,
                failed_tests=result.failed_tests,
                findings=result.findings
            )
        except Exception:
            pass

        return result
