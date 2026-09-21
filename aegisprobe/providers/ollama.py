"""
Ollama and local model provider for AegisProbe AI.
Connects to local Ollama daemon at default http://127.0.0.1:11434.
"""

import time
import httpx
from typing import Optional
from aegisprobe.providers.base import BaseAIProvider, ProviderResponse


class OllamaProvider(BaseAIProvider):
    async def query(self, prompt: str, system_prompt: Optional[str] = None) -> ProviderResponse:
        url = f"{self.base_url}/api/chat"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.0}
        }

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(url, json=payload)
                latency = (time.perf_counter() - start_time) * 1000

                if res.status_code != 200:
                    # Fallback to /api/generate
                    gen_url = f"{self.base_url}/api/generate"
                    gen_payload = {
                        "model": self.model,
                        "prompt": f"{system_prompt + chr(10) if system_prompt else ''}{prompt}",
                        "stream": False
                    }
                    res = await client.post(gen_url, json=gen_payload)
                    if res.status_code != 200:
                        return ProviderResponse(
                            content="",
                            latency_ms=latency,
                            status_code=res.status_code,
                            model=self.model,
                            error=f"Ollama returned HTTP {res.status_code}"
                        )
                    data = res.json()
                    return ProviderResponse(
                        content=data.get("response", ""),
                        latency_ms=latency,
                        status_code=200,
                        model=self.model,
                        raw=data
                    )

                data = res.json()
                content = data.get("message", {}).get("content", "")
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
            async with httpx.AsyncClient(timeout=3) as client:
                res = await client.get(f"{self.base_url}/api/tags")
                return res.status_code == 200
        except Exception:
            return False
