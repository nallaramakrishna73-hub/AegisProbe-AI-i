"""
Tests for Typer CLI Entry Points in AegisProbe AI.
"""

from typer.testing import CliRunner
from aegisprobe.cli import app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "AegisProbe AI" in result.stdout


def test_cli_config_show():
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "Runtime Configuration" in result.stdout


def test_cli_target_list():
    result = runner.invoke(app, ["target", "list"])
    assert result.exit_code == 0
    assert "Authorized External Targets" in result.stdout


def test_cli_prompt_injection():
    result = runner.invoke(app, ["prompt-injection", "--target", "http://127.0.0.1:8080"])
    assert result.exit_code == 0
    assert "Prompt Injection Assessment" in result.stdout


def test_cli_jailbreak():
    result = runner.invoke(app, ["jailbreak", "--target", "http://127.0.0.1:8080"])
    assert result.exit_code == 0
    assert "Jailbreak Resistance" in result.stdout


def test_cli_finbot():
    result = runner.invoke(app, ["finbot", "--target", "http://127.0.0.1:8080"])
    assert result.exit_code == 0
    assert "FinBot Security Assessment" in result.stdout
