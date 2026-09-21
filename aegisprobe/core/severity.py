"""
Severity definitions and scoring algorithms for AegisProbe AI.
"""

from enum import Enum
from typing import Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> float:
        scores = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 0.0,
        }
        return scores.get(self.value, 0.0)

    @property
    def color(self) -> str:
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim cyan",
        }
        return colors.get(self.value, "white")

    @property
    def badge_color(self) -> str:
        hex_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#2563eb",
            "INFO": "#0284c7",
        }
        return hex_colors.get(self.value, "#64748b")


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


def calculate_risk_score(findings: list) -> Dict[str, Any]:
    """Calculate overall security risk rating based on CVSS-style weighting."""
    if not findings:
        return {"score": 0.0, "level": "LOW", "status": "SECURE"}

    weights = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.5, "INFO": 0.0}
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    total_weight = 0.0
    for f in findings:
        sev = getattr(f, "severity", "INFO")
        if isinstance(sev, Severity):
            sev = sev.value
        counts[sev] = counts.get(sev, 0) + 1
        total_weight += weights.get(sev, 0.0)

    # Normalize to 0-100 scale with ceiling dampening
    raw_score = min(100.0, total_weight * 3.5)

    if counts["CRITICAL"] > 0 or raw_score >= 80:
        level = "CRITICAL"
        status = "IMMEDIATE ATTENTION REQUIRED"
    elif counts["HIGH"] > 0 or raw_score >= 50:
        level = "HIGH"
        status = "SIGNIFICANT RISKS IDENTIFIED"
    elif counts["MEDIUM"] > 0 or raw_score >= 25:
        level = "MEDIUM"
        status = "MODERATE RISKS DETECTED"
    elif counts["LOW"] > 0:
        level = "LOW"
        status = "LOW RISK - MINOR REMEDIATION"
    else:
        level = "CLEAN"
        status = "DEFENSIVE CONTROLS OPERATIONAL"

    return {
        "score": round(raw_score, 1),
        "level": level,
        "status": status,
        "counts": counts,
    }
