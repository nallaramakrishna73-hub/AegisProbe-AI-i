"""
Evidence collection and sanitization for AegisProbe AI.
Ensures no real credentials or sensitive telemetry are stored.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
import re


class EvidenceItem(BaseModel):
    test_id: str
    target: str
    input_payload: str
    output_response: str
    indicator_matched: str
    latency_ms: float = 0.0
    status_code: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


def sanitize_evidence_text(text: str) -> str:
    """Mask potential real API keys or sensitive authorization headers if present."""
    if not text:
        return ""
    # Mask OpenAI-like keys: sk-...
    text = re.sub(r'sk-[a-zA-Z0-9]{20,}', 'sk-***MASKED_API_KEY***', text)
    # Mask Bearer tokens
    text = re.sub(r'(Bearer\s+)[a-zA-Z0-9_\-\.]{15,}', r'\1***MASKED_TOKEN***', text, flags=re.IGNORECASE)
    # Mask password fields
    text = re.sub(r'("password"\s*:\s*")[^"]+(")', r'\1***MASKED***\2', text, flags=re.IGNORECASE)
    return text
