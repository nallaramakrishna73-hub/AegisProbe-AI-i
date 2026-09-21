"""
Tests for Database Repository and Storage in AegisProbe AI.
"""

import pytest
from aegisprobe.database.repository import DatabaseRepository
from aegisprobe.core.findings import Finding
from aegisprobe.core.severity import Severity, Confidence


def test_database_scan_lifecycle(tmp_path):
    db_file = tmp_path / "test_aegis.db"
    repo = DatabaseRepository(f"sqlite:///{db_file}")

    f = Finding(
        id="TEST-001",
        title="Test Finding Title",
        category="Test Category",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Test description of finding",
        evidence="Sanitized evidence string",
        impact="Test impact",
        remediation="Test remediation"
    )

    repo.save_scan(
        scan_id="test-scan-123",
        target_url="http://127.0.0.1:8080",
        modules=["prompt-injection", "jailbreak"],
        risk_score=75.0,
        risk_level="HIGH",
        total_tests=10,
        passed_tests=8,
        failed_tests=2,
        findings=[f]
    )

    scans = repo.list_scans(limit=10)
    assert len(scans) == 1
    assert scans[0]["id"] == "test-scan-123"
    assert scans[0]["risk_level"] == "HIGH"

    fetched = repo.get_scan("test-scan-123")
    assert fetched is not None
    assert len(fetched["findings"]) == 1
    assert fetched["findings"][0]["title"] == "Test Finding Title"
