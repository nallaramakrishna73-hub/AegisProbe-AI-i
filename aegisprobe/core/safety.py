"""
Safety and Authorization Layer for AegisProbe AI.
Enforces strict authorized-target validation, prevents arbitrary third-party scans,
and protects against misuse.
"""

import json
import os
from pathlib import Path
from typing import List, Set
from urllib.parse import urlparse

from aegisprobe.core.target import Target


AUTHORIZED_TARGETS_FILE = Path(os.path.expanduser("~/.config/aegisprobe/authorized_targets.json"))


def get_default_authorized_hosts() -> Set[str]:
    return {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "host.docker.internal",
    }


def load_authorized_targets() -> List[dict]:
    """Load authorized target list from local config."""
    if not AUTHORIZED_TARGETS_FILE.exists():
        return []
    try:
        with open(AUTHORIZED_TARGETS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("targets", [])
    except Exception:
        return []


def save_authorized_target(target_url: str, description: str = "") -> bool:
    """Store authorized target locally."""
    AUTHORIZED_TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    targets = load_authorized_targets()

    # Deduplicate
    existing_urls = {t.get("url") for t in targets}
    if target_url in existing_urls:
        return True

    targets.append({
        "url": target_url,
        "description": description,
        "added_at": str(Path(__file__).stat().st_mtime)
    })

    with open(AUTHORIZED_TARGETS_FILE, "w", encoding="utf-8") as f:
        json.dump({"targets": targets}, f, indent=2)
    return True


def is_target_authorized(target_input: str, is_lab_mode: bool = False) -> bool:
    """
    Verify if a target is authorized to test:
    - Automatically allowed if localhost / 127.0.0.1 / private loopback
    - Automatically allowed if --lab mode is active
    - Allowed if explicitly registered via `aegisprobe target add`
    """
    if is_lab_mode:
        return True

    try:
        t = Target(url=target_input)
    except Exception:
        return False

    if t.is_local:
        return True

    # Check authorized store
    stored = load_authorized_targets()
    stored_hosts = set()
    for item in stored:
        u = item.get("url", "")
        parsed = urlparse(u if u.startswith("http") else f"http://{u}")
        if parsed.hostname:
            stored_hosts.add(parsed.hostname.lower())

    return t.hostname.lower() in stored_hosts
