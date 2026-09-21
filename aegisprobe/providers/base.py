"""
Abstract Base Provider for AegisProbe AI.
Provides unified query interface for local models, Ollama, and OpenAI-compatible endpoints.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import BaseModel


class ProviderResponse(BaseModel):
    content: str
    latency_ms: float = 0.0
    status_code: int = 200
    model: str = ""
    raw: Dict[str, Any] = {}
    error: Optional[str] = None


class BaseAIProvider(ABC):
    def __init__(self, model: str, base_url: str, api_key: Optional[str] = None, timeout: int = 30):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or ""
        self.timeout = timeout

    @abstractmethod
    async def query(self, prompt: str, system_prompt: Optional[str] = None) -> ProviderResponse:
        """Send prompt to the AI provider and return unified response."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify provider availability."""
        pass
