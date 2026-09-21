"""
Cryptographic hashing, synthetic canary generation, and similarity checking.
"""

import hashlib
import secrets
import string
import difflib
from typing import Optional


def generate_canary(prefix: str = "LAB_CANARY", length: int = 6) -> str:
    """Generate a harmless synthetic canary token, e.g. LAB_CANARY_7F21."""
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(length))
    return f"{prefix}_{suffix}"


def compute_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_similarity(str1: str, str2: str) -> float:
    """Compute string similarity ratio (0.0 to 1.0) using SequenceMatcher."""
    if not str1 or not str2:
        return 0.0
    return difflib.SequenceMatcher(None, str1.lower().strip(), str2.lower().strip()).ratio()


def token_overlap_ratio(needle: str, haystack: str) -> float:
    """Calculate word token overlap percentage."""
    n_tokens = set(needle.lower().split())
    h_tokens = set(haystack.lower().split())
    if not n_tokens:
        return 0.0
    return len(n_tokens.intersection(h_tokens)) / len(n_tokens)
