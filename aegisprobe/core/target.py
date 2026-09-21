"""
Target model and validation for AegisProbe AI.
"""

import ipaddress
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator
from typing import Optional


class Target(BaseModel):
    url: str = Field(..., description="Target endpoint or host URL")
    name: Optional[str] = None
    description: Optional[str] = None
    is_lab: bool = False
    authorized: bool = False
    created_at: Optional[str] = None

    @field_validator("url")
    def validate_target_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target URL cannot be empty")
        
        # If user passed hostname:port or ip:port without scheme, prepend http://
        if not v.startswith(("http://", "https://", "ws://", "wss://")):
            v = f"http://{v}"

        parsed = urlparse(v)
        if not parsed.hostname:
            raise ValueError(f"Invalid target URL: '{v}' has no hostname")

        return v

    @property
    def hostname(self) -> str:
        parsed = urlparse(self.url)
        return parsed.hostname or ""

    @property
    def port(self) -> Optional[int]:
        parsed = urlparse(self.url)
        return parsed.port

    @property
    def is_local(self) -> bool:
        """Check if target points strictly to local loopback machine."""
        host = self.hostname.lower()
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"):
            return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_loopback
        except ValueError:
            return False
