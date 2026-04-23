"""Async Anthropic provider — sibling of the legacy sync ``AnthropicModel``."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import anthropic
from aiolimiter import AsyncLimiter
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .async_base import AsyncAIModel, ChatResponse, Chunk, Usage
from .conversation import Conversation

_RETRYABLE = (
    anthropic.RateLimitError,
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
    anthropic.InternalServerError,
)


class AsyncAnthropicModel(AsyncAIModel):
    """Anthropic provider on top of ``anthropic.AsyncAnthropic``.

    Resilience: per-instance ``aiolimiter`` for rate limiting plus ``tenacity``
    retries on transient errors. Replaces the homegrown circuit breaker on the
    async path.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "claude-opus-4-7",
        *,
        max_rate: int = 50,
        time_period: float = 60.0,
        max_attempts: int = 3,
        cache_system: bool = True,
    ) -> None:
        self.api_key = api_key
        self.model_name = model_name
        self.cache_system = cache_system
        self._client: anthropic.AsyncAnthropic | None = None
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
        api_key = self.api_key or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("Anthropic API key not provided and ANTHROPIC_API_KEY not set")
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

    def _build_kwargs(
        self,
        conversation: Conversation,
        temperature: float,
        max_tokens: int,
    ) -> dict:
        kwargs: dict = {
            "model": self.model_name,
            "messages": conversation.to_anthropic(),
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if conversation.system:
            if self.cache_system:
                # Anthropic prompt caching: mark the system block as ephemeral
                # so repeated calls with the same system prompt hit the cache.
                # Surfaces in usage.cache_read_input_tokens.
                kwargs["system"] = [
                    {
                        "type": "text",
                        "text": conversation.system,
                        "cache_control": {"type": "ephemeral"},
                    }
                ]
            else:
                kwargs["system"] = conversation.system
        return kwargs

    @staticmethod
    def _usage_from(raw_usage) -> Usage | None:
        if raw_usage is None:
            return None
        return Usage(
            input_tokens=getattr(raw_usage, "input_tokens", None),
            output_tokens=getattr(raw_usage, "output_tokens", None),
            cached_input_tokens=getattr(raw_usage, "cache_read_input_tokens", None),
        )

    async def chat(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> ChatResponse:
        await self.initialize()
        assert self._client is not None
        kwargs = self._build_kwargs(conversation, temperature, max_tokens)

        async def _call():
            async with self._limiter:
                return await self._client.messages.create(**kwargs)

        resp = None
        async for attempt in self._retry:
            with attempt:
                resp = await _call()

        text = resp.content[0].text if resp.content else ""
        return ChatResponse(
            content=text,
            model=self.model_name,
            finish_reason=getattr(resp, "stop_reason", None),
            usage=self._usage_from(getattr(resp, "usage", None)),
            raw=resp,
        )

    async def astream(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[Chunk]:
        await self.initialize()
        assert self._client is not None
        kwargs = self._build_kwargs(conversation, temperature, max_tokens)

        async with self._limiter:
            async with self._client.messages.stream(**kwargs) as stream:
                async for text in stream.text_stream:
                    yield Chunk(delta=text)
                final = await stream.get_final_message()
                yield Chunk(
                    finish_reason=getattr(final, "stop_reason", None),
                    usage=self._usage_from(getattr(final, "usage", None)),
                )

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None
