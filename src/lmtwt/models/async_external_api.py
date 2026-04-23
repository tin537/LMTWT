"""Async External-API provider — generic HTTP target via ``httpx.AsyncClient``.

Mirrors the sync ``ExternalAPIModel`` schema. The roadmap calls for splitting
this into HTTP / SSE / WebSocket adapters in a future PR; today it covers
HTTP only.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
from aiolimiter import AsyncLimiter
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .async_base import AsyncAIModel, ChatResponse, Chunk
from .conversation import Conversation

_RETRYABLE = (
    httpx.NetworkError,
    httpx.TimeoutException,
    httpx.RemoteProtocolError,
)


def _extract(data: Any, dotted_path: str) -> str:
    """Walk a dotted/numeric path through nested dicts/lists. Returns '' on miss."""
    cursor: Any = data
    for part in dotted_path.split("."):
        if isinstance(cursor, list):
            try:
                cursor = cursor[int(part)]
            except (ValueError, IndexError):
                return ""
        elif isinstance(cursor, dict):
            if part not in cursor:
                return ""
            cursor = cursor[part]
        else:
            return ""
    return cursor if isinstance(cursor, str) else json.dumps(cursor)


class AsyncExternalAPIModel(AsyncAIModel):
    """Schema-driven async HTTP adapter."""

    def __init__(
        self,
        api_config: dict[str, Any],
        model_name: str | None = None,
        *,
        max_rate: int = 60,
        time_period: float = 60.0,
        max_attempts: int = 3,
        timeout: float = 30.0,
    ) -> None:
        if not api_config.get("endpoint"):
            raise ValueError("api_config must include 'endpoint'")
        self.api_config = api_config
        self.model_name = model_name or api_config.get("model", "external-api")
        self.endpoint = api_config["endpoint"]
        self.method = api_config.get("method", "POST").upper()
        self.headers = api_config.get("headers", {})
        self.params = api_config.get("params", {})
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._limiter = AsyncLimiter(max_rate=max_rate, time_period=time_period)
        self._retry = AsyncRetrying(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(multiplier=1, min=2, max=10),
            retry=retry_if_exception_type(_RETRYABLE),
            reraise=True,
        )

    async def initialize(self) -> None:
        if self._client is not None:
            return
        self._client = httpx.AsyncClient(
            headers=self.headers,
            params=self.params,
            timeout=self.timeout,
        )

    def _build_payload(
        self,
        conversation: Conversation,
        temperature: float,
    ) -> dict[str, Any]:
        # Last user turn is the "prompt" the schema expects.
        last_user = next(
            (m.content for m in reversed(conversation.messages) if m.role == "user"),
            "",
        )
        payload = dict(self.api_config.get("payload_template", {}))
        payload["prompt"] = last_user
        if conversation.system and self.api_config.get("supports_system_prompt", False):
            sys_key = self.api_config.get("system_key")
            if sys_key:
                payload[sys_key] = conversation.system
            else:
                payload["prompt"] = f"{conversation.system}\n\n{last_user}"
        if self.api_config.get("supports_temperature", False):
            payload[self.api_config.get("temperature_key", "temperature")] = temperature
        if "model_key" in self.api_config:
            payload[self.api_config["model_key"]] = self.model_name
        return payload

    async def chat(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,  # noqa: ARG002 — schema may not honor this
    ) -> ChatResponse:
        await self.initialize()
        assert self._client is not None
        payload = self._build_payload(conversation, temperature)

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
            text = _extract(data, path)
        elif isinstance(data, str):
            text = data
        else:
            text = json.dumps(data)

        return ChatResponse(
            content=text,
            model=self.model_name,
            finish_reason=None,
            raw=data,
        )

    async def astream(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[Chunk]:
        # No streaming for plain HTTP. SSE/WebSocket adapters land in a future PR.
        resp = await self.chat(
            conversation, temperature=temperature, max_tokens=max_tokens
        )
        yield Chunk(delta=resp.content, finish_reason="stop")

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
