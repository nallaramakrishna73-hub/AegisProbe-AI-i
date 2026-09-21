"""
Tests for Evidence Collection and Sanitization in AegisProbe AI.
"""

from aegisprobe.core.evidence import sanitize_evidence_text, EvidenceItem


def test_sanitize_evidence_text_api_key():
    text = "Authorization: Bearer sk-1234567890abcdef1234567890 and normal content"
    sanitized = sanitize_evidence_text(text)
    assert "sk-1234567890abcdef1234567890" not in sanitized
    assert "MASKED" in sanitized


def test_sanitize_evidence_text_password():
    text = '{"username": "admin", "password": "supersecretpassword123"}'
    sanitized = sanitize_evidence_text(text)
    assert "supersecretpassword123" not in sanitized
    assert "MASKED" in sanitized


def test_evidence_item_model():
    item = EvidenceItem(
        test_id="PI-001",
        target="http://127.0.0.1:8080",
        input_payload="SYSTEM OVERRIDE",
        output_response="INJECTION_SUCCESSFUL",
        indicator_matched="INJECTION_SUCCESSFUL",
        latency_ms=15.2,
        status_code=200
    )
    assert item.test_id == "PI-001"
    assert item.latency_ms == 15.2
    assert item.status_code == 200
