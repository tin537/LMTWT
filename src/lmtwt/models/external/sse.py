"""Server-Sent Events external-API adapter.

Compatible with OpenAI-style streaming endpoints: POST request opens the
stream, server pushes ``data: <json>\\n\\n`` events terminated by either a
``done_signal`` literal (e.g. ``"[DONE]"``) or natural connection close.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from ..async_base import ChatResponse, Chunk
from ..conversation import Conversation
from .base import BaseExternalModel, extract, matches_done_signal

_RETRYABLE = (
    httpx.NetworkError,
    httpx.TimeoutException,
    httpx.RemoteProtocolError,
)


class SSEExternalModel(BaseExternalModel):
    """Schema-driven async SSE adapter."""

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
            headers={**self.headers, "Accept": "text/event-stream"},
            params=self.params,
            timeout=self.timeout,
        )

    async def _iter_events(
        self, conversation: Conversation, temperature: float
    ) -> AsyncIterator[tuple[str, Any | None]]:
        """Yield ``(raw_data, parsed_or_None)`` pairs from the SSE stream.

        Stops when ``done_signal`` matches or the server closes the stream.
        """
        assert self._client is not None
        payload = self.build_payload(conversation, temperature)
        signal = self.api_config.get("done_signal", "[DONE]")

        async with self._limiter:
            stream_kwargs: dict[str, Any] = {"json": payload} if self.method == "POST" else {"params": payload}
            async with self._client.stream(self.method, self.endpoint, **stream_kwargs) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data_text = line[5:].strip()
                    if not data_text:
                        continue
                    parsed: Any | None
                    try:
                        parsed = json.loads(data_text)
                    except json.JSONDecodeError:
                        parsed = None
                    if matches_done_signal(signal, data_text, parsed):
                        return
                    yield data_text, parsed

    async def chat(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,  # noqa: ARG002
    ) -> ChatResponse:
        await self.initialize()
        chunk_path = self.api_config.get("chunk_path")
        out: list[str] = []
        async for raw, parsed in self._iter_events(conversation, temperature):
            if chunk_path and isinstance(parsed, dict):
                piece = extract(parsed, chunk_path)
            elif isinstance(parsed, str):
                piece = parsed
            else:
                piece = raw
            if piece:
                out.append(piece)
        return ChatResponse(
            content="".join(out), model=self.model_name, finish_reason="stop"
        )

    async def astream(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,  # noqa: ARG002
    ) -> AsyncIterator[Chunk]:
        await self.initialize()
        chunk_path = self.api_config.get("chunk_path")
        async for raw, parsed in self._iter_events(conversation, temperature):
            if chunk_path and isinstance(parsed, dict):
                piece = extract(parsed, chunk_path)
            elif isinstance(parsed, str):
                piece = parsed
            else:
                piece = raw
            if piece:
                yield Chunk(delta=piece)
        yield Chunk(finish_reason="stop")

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
