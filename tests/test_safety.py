"""
Tests for Target Authorization and Safety Enforcement in AegisProbe AI.
"""

import pytest
from aegisprobe.core.safety import is_target_authorized, get_default_authorized_hosts
from aegisprobe.core.target import Target


def test_localhost_authorized():
    assert is_target_authorized("http://localhost:8080") is True
    assert is_target_authorized("http://127.0.0.1:5000") is True


def test_default_hosts():
    hosts = get_default_authorized_hosts()
    assert "localhost" in hosts
    assert "127.0.0.1" in hosts


def test_external_unauthorized_by_default():
    assert is_target_authorized("https://example.com") is False
    assert is_target_authorized("http://192.168.1.100:8080") is False


def test_lab_mode_authorization():
    # In lab mode, targets are permitted
    assert is_target_authorized("http://127.0.0.1:8080", is_lab_mode=True) is True


def test_target_model_validation():
    t = Target(url="http://127.0.0.1:8080")
    assert t.is_local is True
    assert t.port == 8080

    t_ext = Target(url="https://api.test-internal.local/v1")
    assert t_ext.is_local is False
