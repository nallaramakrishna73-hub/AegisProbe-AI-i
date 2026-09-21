"""
Validators for URLs, JSON datasets, MCP configs, and workspaces.
"""

import json
from pathlib import Path
from typing import Tuple, List, Dict, Any
from urllib.parse import urlparse


def validate_endpoint_url(url: str) -> Tuple[bool, str]:
    """Validate target URL syntax and protocol."""
    if not url:
        return False, "Target URL cannot be empty"
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    parsed = urlparse(url)
    if not parsed.netloc:
        return False, f"Invalid target netloc in URL: '{url}'"
    return True, url


def validate_mcp_config_json(content: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """Validate that MCP configuration is valid JSON with expected tool/server fields."""
    try:
        data = json.loads(content)
        if not isinstance(data, dict):
            return False, None, "MCP config must be a JSON object"
        return True, data, "Valid JSON"
    except json.JSONDecodeError as e:
        return False, None, f"JSON syntax error: {str(e)}"


def validate_dataset_file(file_path: str) -> Tuple[bool, str]:
    """Check that dataset file exists and has supported extension."""
    p = Path(file_path)
    if not p.exists():
        return False, f"Dataset file does not exist: {file_path}"
    if p.suffix.lower() not in (".jsonl", ".json", ".csv", ".txt"):
        return False, f"Unsupported dataset format '{p.suffix}'. Supported: .jsonl, .json, .csv, .txt"
    return True, "Valid file"
