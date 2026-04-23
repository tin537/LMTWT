"""WebSocket external-API adapter.

Builds on the ``websockets`` library (pulled in transitively via google-genai;
also a real future-roadmap item for Burp WebSocket interception). Each
``chat()`` opens a connection, optionally sends an ``auth_message``, sends the
request frame, aggregates streamed chunks until ``done_signal`` matches or the
server closes the socket, then closes.

Set ``keep_alive=True`` in the target-config to reuse one connection across
``chat()`` calls (reconnects on drop).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import websockets
from websockets.exceptions import ConnectionClosed

from .._transport import websocket_ssl_context
from ..async_base import ChatResponse, Chunk
from ..conversation import Conversation
from .base import BaseExternalModel, extract, matches_done_signal

_RETRYABLE = (ConnectionClosed, OSError)


class WebSocketExternalModel(BaseExternalModel):
    """Schema-driven async WebSocket adapter."""

    def __init__(self, api_config: dict[str, Any], model_name: str | None = None, **kw):
        super().__init__(
            api_config, model_name, retryable_exceptions=_RETRYABLE, **kw
        )
        self.subprotocol = api_config.get("subprotocol")
        self.message_format = api_config.get("message_format", "json")
        self.auth_message = api_config.get("auth_message")
        self.keep_alive = bool(api_config.get("keep_alive", False))
        self.ping_interval = api_config.get("ping_interval", 20)
        self._socket = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        # Connection deferred until first chat()/astream() so we can re-create on close.
        return

    async def _connect(self):
        kwargs: dict[str, Any] = {
            "additional_headers": self.headers or None,
            "ping_interval": self.ping_interval,
        }
        if self.subprotocol:
            kwargs["subprotocols"] = [self.subprotocol]
        if self.proxy:
            kwargs["proxy"] = self.proxy
        ssl_ctx = websocket_ssl_context(self.ca_bundle, self.verify)
        if ssl_ctx is not None:
            kwargs["ssl"] = ssl_ctx
        sock = await websockets.connect(
            self.endpoint, **{k: v for k, v in kwargs.items() if v is not None}
        )
        if self.auth_message is not None:
            await sock.send(self._encode(self.auth_message))
        return sock

    async def _ensure_socket(self):
        if not self.keep_alive:
            return await self._connect()
        async with self._lock:
            if self._socket is None or self._socket.state.name == "CLOSED":
                self._socket = await self._connect()
            return self._socket

    def _encode(self, payload: Any) -> str:
        if self.message_format == "text" and isinstance(payload, str):
            return payload
        return json.dumps(payload)

    async def _iter_frames(
        self, conversation: Conversation, temperature: float
    ) -> AsyncIterator[tuple[str, Any | None]]:
        sock = await self._ensure_socket()
        signal = self.api_config.get("done_signal")
        payload = self.build_payload(conversation, temperature)

        async with self._limiter:
            try:
                await sock.send(self._encode(payload))
                async for raw in sock:
                    text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
                    parsed: Any | None
                    try:
                        parsed = json.loads(text)
                    except json.JSONDecodeError:
                        parsed = None
                    if matches_done_signal(signal, text, parsed):
                        return
                    yield text, parsed
            except ConnectionClosed:
                return
            finally:
                if not self.keep_alive:
                    await sock.close()

    async def chat(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,  # noqa: ARG002
    ) -> ChatResponse:
        chunk_path = self.api_config.get("chunk_path")
        out: list[str] = []
        async for raw, parsed in self._iter_frames(conversation, temperature):
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
        chunk_path = self.api_config.get("chunk_path")
        async for raw, parsed in self._iter_frames(conversation, temperature):
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
        if self._socket is not None:
            await self._socket.close()
            self._socket = None
