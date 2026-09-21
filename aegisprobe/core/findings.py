"""
Finding data model for AegisProbe AI security assessments.
Matches Section 18 requirement:
{
  "id": "PI-001",
  "title": "Untrusted Instruction Handling",
  "category": "Prompt Injection",
  "severity": "HIGH",
  "confidence": "HIGH",
  "description": "...",
  "evidence": "...",
  "impact": "...",
  "remediation": "...",
  "references": []
}
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from aegisprobe.core.severity import Severity, Confidence


class Finding(BaseModel):
    id: str = Field(..., description="Unique vulnerability identifier, e.g. PI-001, JB-003, MCP-002")
    title: str = Field(..., description="Concise finding headline")
    category: str = Field(..., description="Security category (Prompt Injection, MCP Security, etc.)")
    severity: Severity = Field(default=Severity.MEDIUM)
    confidence: Confidence = Field(default=Confidence.HIGH)
    description: str = Field(..., description="Detailed description of the observed vulnerability")
    evidence: str = Field(..., description="Exact payload, model response, or configuration trigger")
    impact: str = Field(..., description="Potential security impact in production")
    remediation: str = Field(..., description="Concrete defensive remediation guidance")
    references: List[str] = Field(default_factory=list, description="CWE, OWASP Top 10 for LLM, or NIST AI RMF references")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target: Optional[str] = None
    module: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = self.model_dump()
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        return data
