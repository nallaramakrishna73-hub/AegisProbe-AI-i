"""
Tests for Report Generation in AegisProbe AI (HTML, PDF, JSON).
"""

from aegisprobe.reporting.json_report import generate_json_report
from aegisprobe.reporting.html_report import generate_html_report
from aegisprobe.reporting.pdf_report import generate_pdf_report


SAMPLE_SCAN_DATA = {
    "scan_id": "test-report-001",
    "target": "http://127.0.0.1:8080",
    "started_at": "2026-09-21T12:00:00Z",
    "total_tests": 10,
    "passed_tests": 8,
    "failed_tests": 2,
    "risk_assessment": {
        "score": 45.0,
        "level": "MEDIUM",
        "status": "EVALUATE",
        "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0}
    },
    "modules": ["prompt-injection", "jailbreak"],
    "findings": [
        {
            "id": "PI-001",
            "title": "Direct Instruction Override",
            "category": "Prompt Injection",
            "severity": "HIGH",
            "description": "Direct injection test finding",
            "evidence": "Observed test output",
            "impact": "Security bypass",
            "remediation": "Validate input schema"
        }
    ]
}


def test_generate_json_report(tmp_path):
    fp = tmp_path / "report.json"
    res = generate_json_report(SAMPLE_SCAN_DATA, str(fp))
    assert fp.exists()
    assert "test-report-001" in fp.read_text()


def test_generate_html_report(tmp_path):
    fp = tmp_path / "report.html"
    res = generate_html_report(SAMPLE_SCAN_DATA, str(fp))
    assert fp.exists()
    html_content = fp.read_text()
    assert "AegisProbe AI" in html_content
    assert "Direct Instruction Override" in html_content


def test_generate_pdf_report(tmp_path):
    fp = tmp_path / "report.pdf"
    res = generate_pdf_report(SAMPLE_SCAN_DATA, str(fp))
    assert fp.exists()
    assert fp.stat().st_size > 1000
