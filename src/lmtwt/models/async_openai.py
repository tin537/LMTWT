"""Async OpenAI provider — sibling of the legacy sync ``OpenAIModel``."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import openai
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
    openai.RateLimitError,
    openai.APIConnectionError,
    openai.APITimeoutError,
    openai.InternalServerError,
)


class AsyncOpenAIModel(AsyncAIModel):
    """OpenAI provider on top of ``openai.AsyncOpenAI``."""

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "gpt-4o",
        *,
        max_rate: int = 60,
        time_period: float = 60.0,
        max_attempts: int = 3,
    ) -> None:
        self.api_key = api_key
        self.model_name = model_name
        self._client: openai.AsyncOpenAI | None = None
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
        api_key = self.api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key not provided and OPENAI_API_KEY not set")
        self._client = openai.AsyncOpenAI(api_key=api_key)

    @staticmethod
    def _usage_from(raw_usage) -> Usage | None:
        if raw_usage is None:
            return None
        cached = None
        details = getattr(raw_usage, "prompt_tokens_details", None)
        if details is not None:
            cached = getattr(details, "cached_tokens", None)
        return Usage(
            input_tokens=getattr(raw_usage, "prompt_tokens", None),
            output_tokens=getattr(raw_usage, "completion_tokens", None),
            cached_input_tokens=cached,
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

        async def _call():
            async with self._limiter:
                return await self._client.chat.completions.create(
                    model=self.model_name,
                    messages=conversation.to_openai(),
                    temperature=temperature,
                    max_tokens=max_tokens,
                )

        resp = None
        async for attempt in self._retry:
            with attempt:
                resp = await _call()

        choice = resp.choices[0]
        return ChatResponse(
            content=choice.message.content or "",
            model=self.model_name,
            finish_reason=getattr(choice, "finish_reason", None),
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

        async with self._limiter:
            stream = await self._client.chat.completions.create(
                model=self.model_name,
                messages=conversation.to_openai(),
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
                stream_options={"include_usage": True},
            )
            finish_reason: str | None = None
            usage = None
            async for chunk in stream:
                if not chunk.choices:
                    # final usage-only chunk
                    usage = self._usage_from(getattr(chunk, "usage", None))
                    continue
                choice = chunk.choices[0]
                delta = getattr(choice.delta, "content", None) or ""
                if delta:
                    yield Chunk(delta=delta)
                if getattr(choice, "finish_reason", None):
                    finish_reason = choice.finish_reason
            yield Chunk(finish_reason=finish_reason, usage=usage)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None
