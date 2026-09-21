"""
Factory to instantiate configured AI Provider.
"""

from typing import Optional
from aegisprobe.config import AegisConfig, load_config
from aegisprobe.providers.base import BaseAIProvider
from aegisprobe.providers.openai_compatible import OpenAICompatibleProvider
from aegisprobe.providers.ollama import OllamaProvider


def get_ai_provider(config: Optional[AegisConfig] = None) -> BaseAIProvider:
    cfg = config or load_config()
    provider_type = (cfg.provider or "ollama").lower()

    if provider_type in ("openai", "openai-compatible", "vllm", "localai", "groq"):
        return OpenAICompatibleProvider(
            model=cfg.model or "gpt-4o-mini",
            base_url=cfg.base_url or "https://api.openai.com",
            api_key=cfg.api_key,
            timeout=cfg.timeout
        )
    else:
        # Default to Ollama / local model
        return OllamaProvider(
            model=cfg.model or "llama3",
            base_url=cfg.base_url or "http://127.0.0.1:11434",
            api_key=cfg.api_key,
            timeout=cfg.timeout
        )
