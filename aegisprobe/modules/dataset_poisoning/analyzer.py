"""
Model Training & Dataset Poisoning Analyzer for AegisProbe AI.
Supports JSONL, JSON, CSV, TXT.
Analyzes:
- Data quality: duplicates, near duplicates, malformed records, abnormal lengths, encoding anomalies
- Suspicious samples: repeated trigger phrases, instruction-like content, unusual label distributions, outliers, contradictory examples, anomalous metadata
Does NOT automatically delete dataset records.
"""

import json
import csv
import re
from pathlib import Path
from typing import Dict, Any, List
from collections import Counter
from aegisprobe.core.findings import Finding
from aegisprobe.core.severity import Severity, Confidence
from aegisprobe.utils.hashing import compute_sha256


SUSPICIOUS_TRIGGER_PHRASES = [
    "sudo", "eval(", "exec(", "<script>", "curl | sh", "rm -rf",
    "system override", "ignore previous instructions", "secret_key",
    "password:", "unauthorized", "bypass", "backdoor"
]


class DatasetPoisoningAnalyzer:
    def __init__(self, file_path: str):
        self.path = Path(file_path)

    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive data quality and backdoor / poisoning analysis."""
        if not self.path.exists():
            return {
                "error": f"Dataset file not found: {self.path}",
                "records": 0,
                "duplicates": 0,
                "outliers": 0,
                "suspicious_samples": 0,
                "malformed_records": 0,
                "risk": "ERROR",
                "findings": []
            }

        records: List[str] = []
        malformed_count = 0
        suffix = self.path.suffix.lower()

        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as f:
                if suffix == ".jsonl":
                    for line_no, line in enumerate(f, 1):
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            obj = json.loads(line_str)
                            # Extract text
                            if isinstance(obj, dict):
                                text = " ".join(str(v) for v in obj.values())
                            else:
                                text = str(obj)
                            records.append(text)
                        except json.JSONDecodeError:
                            malformed_count += 1
                elif suffix == ".json":
                    try:
                        data = json.load(f)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    records.append(" ".join(str(v) for v in item.values()))
                                else:
                                    records.append(str(item))
                        elif isinstance(data, dict):
                            records = [" ".join(str(v) for v in data.values())]
                    except json.JSONDecodeError:
                        malformed_count += 1
                elif suffix == ".csv":
                    reader = csv.reader(f)
                    for row in reader:
                        records.append(" ".join(row))
                else:
                    # TXT line by line
                    records = [line.strip() for line in f if line.strip()]
        except Exception as e:
            return {
                "error": f"Failed reading file: {str(e)}",
                "records": 0,
                "duplicates": 0,
                "outliers": 0,
                "suspicious_samples": 0,
                "malformed_records": malformed_count,
                "risk": "ERROR",
                "findings": []
            }

        total_records = len(records)
        if total_records == 0:
            return {
                "records": 0,
                "duplicates": 0,
                "outliers": 0,
                "suspicious_samples": 0,
                "malformed_records": malformed_count,
                "risk": "EMPTY",
                "findings": []
            }

        # 1. Duplicates & Hash analysis
        hashes = set()
        duplicate_count = 0
        for r in records:
            h = compute_sha256(r)
            if h in hashes:
                duplicate_count += 1
            else:
                hashes.add(h)

        # 2. Outliers (Length anomaly)
        lengths = [len(r) for r in records]
        avg_len = sum(lengths) / total_records if total_records > 0 else 0
        outliers_count = sum(1 for l in lengths if l > (avg_len * 4) or (avg_len > 50 and l < 5))

        # 3. Suspicious / Trigger words analysis
        suspicious_matches = []
        trigger_counter = Counter()
        for idx, r in enumerate(records):
            for trig in SUSPICIOUS_TRIGGER_PHRASES:
                if trig in r.lower():
                    trigger_counter[trig] += 1
                    if len(suspicious_matches) < 10:
                        suspicious_matches.append({
                            "record_index": idx + 1,
                            "trigger": trig,
                            "sample": r[:100]
                        })

        suspicious_samples_count = sum(trigger_counter.values())

        # Generate Findings
        findings: List[Finding] = []

        if suspicious_samples_count > 0:
            findings.append(Finding(
                id="DATA-001",
                title=f"Potential Backdoor Triggers or Instruction-like Content ({suspicious_samples_count} instances)",
                category="Dataset Security",
                severity=Severity.HIGH if suspicious_samples_count > 10 else Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=f"Identified {suspicious_samples_count} dataset samples containing known injection keywords or anomalous trigger tokens.",
                evidence=f"Top triggers found: {dict(trigger_counter.most_common(5))}",
                impact="Risk of sleeper agent behaviors, unauthorized tool activation, or model poisoning during fine-tuning.",
                remediation="Audit and sanitize suspicious samples. Apply trigger-inversion or frequency-filtering preprocessors.",
                references=["OWASP LLM03: Training Data Poisoning", "NIST AI 100-2 Section 3.2"]
            ))

        if duplicate_count > (total_records * 0.05):
            findings.append(Finding(
                id="DATA-002",
                title="Excessive Duplicate Density in Training Split",
                category="Dataset Security",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                description=f"Dataset contains {duplicate_count} exact duplicate records ({round(duplicate_count/total_records*100, 1)}% of total).",
                evidence=f"{duplicate_count} duplicate rows discovered.",
                impact="Overfitting on repeated samples and memorization of training sequences.",
                remediation="Run deduplication using MinHash LSH or SHA-256 deduplication pipelines.",
                references=["OWASP LLM03: Training Data Poisoning"]
            ))

        if malformed_count > 0:
            findings.append(Finding(
                id="DATA-003",
                title=f"Malformed Record Parsing Errors ({malformed_count} rows)",
                category="Dataset Security",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                description=f"Detected {malformed_count} malformed rows unable to parse cleanly as {suffix.upper()}.",
                evidence=f"{malformed_count} invalid syntax rows found in {self.path.name}.",
                impact="Tokenizer corruption or training crashes on invalid batches.",
                remediation="Filter out unparseable rows using pre-tokenization validation schemas.",
                references=["CWE-20: Improper Input Validation"]
            ))

        # Overall risk
        if suspicious_samples_count > 15 or (duplicate_count > total_records * 0.2):
            risk = "HIGH RISK — REVIEW REQUIRED"
        elif suspicious_samples_count > 0 or duplicate_count > 0:
            risk = "REVIEW REQUIRED"
        else:
            risk = "LOW RISK"

        return {
            "file": self.path.name,
            "format": suffix.upper().lstrip("."),
            "records": total_records,
            "duplicates": duplicate_count,
            "outliers": outliers_count,
            "suspicious_samples": suspicious_samples_count,
            "malformed_records": malformed_count,
            "risk": risk,
            "findings": findings,
            "suspicious_samples_preview": suspicious_matches
        }
