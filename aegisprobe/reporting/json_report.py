"""
JSON Report Generator for AegisProbe AI.
Exports complete machine-readable scan results.
"""

import json
from pathlib import Path
from typing import Dict, Any


def generate_json_report(scan_data: Dict[str, Any], output_path: str) -> str:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2, ensure_ascii=False)
    return str(p.resolve())
