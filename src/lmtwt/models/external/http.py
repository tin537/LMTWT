"""HTTP external-API adapter (POST/GET, single round-trip)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from ..async_base import ChatResponse, Chunk
from ..conversation import Conversation
from .base import BaseExternalModel, extract

_RETRYABLE = (
    httpx.NetworkError,
    httpx.TimeoutException,
    httpx.RemoteProtocolError,
)


class HTTPExternalModel(BaseExternalModel):
    """Schema-driven async HTTP adapter (POST or GET)."""

    def __init__(self, api_config: dict[str, Any], model_name: str | None = None, **kw):
        super().__init__(
            api_config, model_name, retryable_exceptions=_RETRYABLE, **kw
        )
        self.method = api_config.get("method", "POST").upper()
        self._client: httpx.AsyncClient | None = None

    async def initialize(self) -> None:
        if self._client is not None:
            return
        self._client = httpx.AsyncClient(
            headers=self.headers, params=self.params, timeout=self.timeout
        )

    async def chat(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,  # noqa: ARG002 — schema may not honor this
    ) -> ChatResponse:
        await self.initialize()
        assert self._client is not None
        payload = self.build_payload(conversation, temperature)

        async def _call():
            async with self._limiter:
                if self.method == "POST":
                    r = await self._client.post(self.endpoint, json=payload)
                else:
                    r = await self._client.get(self.endpoint, params=payload)
                r.raise_for_status()
                return r

        resp = None
        async for attempt in self._retry:
            with attempt:
                resp = await _call()

        try:
            data = resp.json()
        except json.JSONDecodeError:
            data = resp.text

        path = self.api_config.get("response_path")
        if path and isinstance(data, dict):
            text = extract(data, path)
        elif isinstance(data, str):
            text = data
        else:
            text = json.dumps(data)

        return ChatResponse(content=text, model=self.model_name, raw=data)

    async def astream(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[Chunk]:
        # Plain HTTP can't stream — emit the full response as one chunk.
        resp = await self.chat(
            conversation, temperature=temperature, max_tokens=max_tokens
        )
        yield Chunk(delta=resp.content, finish_reason="stop")

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
