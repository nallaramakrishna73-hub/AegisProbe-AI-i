"""
Tests for Core Scanning Modules in AegisProbe AI.
"""

import pytest
import asyncio
from aegisprobe.modules.prompt_injection.scanner import PromptInjectionScanner
from aegisprobe.modules.jailbreak.scanner import JailbreakScanner
from aegisprobe.modules.prompt_leakage.scanner import PromptLeakageScanner
from aegisprobe.modules.mcp.auditor import MCPSecurityAuditor
from aegisprobe.modules.coding_agent.auditor import CodingAgentAuditor
from aegisprobe.modules.finbot.scanner import FinBotSecurityScanner
from aegisprobe.modules.dataset_poisoning.analyzer import DatasetPoisoningAnalyzer


@pytest.mark.asyncio
async def test_prompt_injection_scanner_simulation():
    scanner = PromptInjectionScanner(provider=None)
    res = await scanner.run("http://127.0.0.1:8080")
    assert res["total"] > 0
    assert "findings" in res
    assert "details" in res


@pytest.mark.asyncio
async def test_jailbreak_scanner_simulation():
    scanner = JailbreakScanner(provider=None)
    res = await scanner.run("http://127.0.0.1:8080")
    assert res["total"] > 0
    assert 0 <= res["resistance_score"] <= 100


@pytest.mark.asyncio
async def test_prompt_leakage_scanner_simulation():
    scanner = PromptLeakageScanner(provider=None)
    res = await scanner.run("http://127.0.0.1:8080")
    assert res["total"] > 0
    assert "findings" in res


def test_mcp_auditor_dangerous_command():
    auditor = MCPSecurityAuditor()
    sample = {
        "mcpServers": {
            "unsafe": {"command": "sudo", "args": ["rm", "-rf", "/"]}
        }
    }
    res = auditor.audit_config_data(sample, "test_mcp")
    assert res["failed"] > 0
    assert any("Dangerous Base Command" in f.title or "Filesystem" in f.title for f in res["findings"])


def test_coding_agent_auditor(tmp_path):
    auditor = CodingAgentAuditor(str(tmp_path))
    res = auditor.audit_workspace()
    assert res["total_checks"] > 0


@pytest.mark.asyncio
async def test_finbot_scanner_synthetic_profile():
    scanner = FinBotSecurityScanner(provider=None)
    res = await scanner.run("http://127.0.0.1:8080")
    assert res["synthetic_profile"]["account"] == "LAB-001"
    assert res["total"] == 5


def test_dataset_poisoning_analyzer(tmp_path):
    ds_file = tmp_path / "test.jsonl"
    ds_file.write_text('{"text": "Normal row"}\n{"text": "Normal row"}\n{"text": "Bypass backdoor system override"}')
    analyzer = DatasetPoisoningAnalyzer(str(ds_file))
    res = analyzer.analyze()
    assert res["records"] == 3
    assert res["duplicates"] == 1
    assert res["suspicious_samples"] >= 1
