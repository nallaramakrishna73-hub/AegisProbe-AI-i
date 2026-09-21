"""
OpenAI-compatible API provider for AegisProbe AI.
Works with any v1/chat/completions endpoint (OpenAI, Groq, vLLM, LocalAI, LM Studio, etc.).
"""

import time
import httpx
from typing import Optional
from aegisprobe.providers.base import BaseAIProvider, ProviderResponse


class OpenAICompatibleProvider(BaseAIProvider):
    async def query(self, prompt: str, system_prompt: Optional[str] = None) -> ProviderResponse:
        url = f"{self.base_url}/v1/chat/completions" if not self.base_url.endswith("/chat/completions") else self.base_url
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": 1000,
        }

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(url, json=payload, headers=headers)
                latency = (time.perf_counter() - start_time) * 1000

                if res.status_code != 200:
                    return ProviderResponse(
                        content="",
                        latency_ms=latency,
                        status_code=res.status_code,
                        model=self.model,
                        error=f"HTTP {res.status_code}: {res.text[:200]}"
                    )

                data = res.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return ProviderResponse(
                    content=content,
                    latency_ms=latency,
                    status_code=200,
                    model=self.model,
                    raw=data
                )
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000
            return ProviderResponse(
                content="",
                latency_ms=latency,
                status_code=500,
                model=self.model,
                error=str(e)
            )

    async def health_check(self) -> bool:
        try:
            url = f"{self.base_url}/v1/models"
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            async with httpx.AsyncClient(timeout=5) as client:
                res = await client.get(url, headers=headers)
                return res.status_code == 200
        except Exception:
            return False
