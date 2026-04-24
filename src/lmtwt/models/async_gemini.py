"""Async Gemini provider — uses the new ``google-genai`` SDK.

Replaces the deprecated ``google-generativeai`` package the sync ``GeminiModel``
still depends on.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

from aiolimiter import AsyncLimiter
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .async_base import AsyncAIModel, ChatResponse, Chunk, Usage
from .conversation import Conversation

_RETRYABLE = (
    genai_errors.APIError,
    genai_errors.ServerError,
)


class AsyncGeminiModel(AsyncAIModel):
    """Gemini provider on top of ``google.genai.Client.aio``."""

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "gemini-2.0-flash",
        *,
        max_rate: int = 60,
        time_period: float = 60.0,
        max_attempts: int = 3,
        proxy: str | None = None,
        ca_bundle: str | None = None,
        verify: bool = True,
    ) -> None:
        self.api_key = api_key
        self.model_name = model_name
        self.proxy = proxy
        self.ca_bundle = ca_bundle
        self.verify = verify
        self._client: genai.Client | None = None
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
        api_key = self.api_key or os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("Gemini API key not provided and GEMINI_API_KEY not set")
        client_kwargs: dict = {"api_key": api_key}
        if self.proxy or self.ca_bundle or not self.verify:
            from ._transport import httpx_client_kwargs

            client_kwargs["http_options"] = genai_types.HttpOptions(
                async_client_args=httpx_client_kwargs(
                    self.proxy, self.ca_bundle, self.verify
                )
            )
        self._client = genai.Client(**client_kwargs)

    def _build_config(
        self,
        conversation: Conversation,
        temperature: float,
        max_tokens: int,
    ) -> genai_types.GenerateContentConfig:
        kwargs: dict = {
            "temperature": temperature,
            "max_output_tokens": max_tokens,
        }
        if conversation.system:
            kwargs["system_instruction"] = conversation.system
        return genai_types.GenerateContentConfig(**kwargs)

    @staticmethod
    def _usage_from(raw_usage) -> Usage | None:
        if raw_usage is None:
            return None
        return Usage(
            input_tokens=getattr(raw_usage, "prompt_token_count", None),
            output_tokens=getattr(raw_usage, "candidates_token_count", None),
            cached_input_tokens=getattr(raw_usage, "cached_content_token_count", None),
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
        config = self._build_config(conversation, temperature, max_tokens)
        contents = conversation.to_gemini()

        async def _call():
            async with self._limiter:
                return await self._client.aio.models.generate_content(
                    model=self.model_name,
                    contents=contents,  # type: ignore[arg-type]  # SDK stub is over-narrow
                    config=config,
                )

        resp = None
        async for attempt in self._retry:
            with attempt:
                resp = await _call()

        finish_reason = None
        candidates = getattr(resp, "candidates", None) or []
        if candidates:
            finish_reason = getattr(candidates[0], "finish_reason", None)
            if finish_reason is not None:
                finish_reason = str(finish_reason)

        return ChatResponse(
            content=getattr(resp, "text", "") or "",
            model=self.model_name,
            finish_reason=finish_reason,
            usage=self._usage_from(getattr(resp, "usage_metadata", None)),
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
        config = self._build_config(conversation, temperature, max_tokens)
        contents = conversation.to_gemini()

        async with self._limiter:
            stream = await self._client.aio.models.generate_content_stream(
                model=self.model_name,
                contents=contents,  # type: ignore[arg-type]  # SDK stub is over-narrow
                config=config,
            )
            final_resp = None
            async for resp in stream:
                final_resp = resp
                text = getattr(resp, "text", "") or ""
                if text:
                    yield Chunk(delta=text)

            finish_reason = None
            usage = None
            if final_resp is not None:
                candidates = getattr(final_resp, "candidates", None) or []
                if candidates:
                    fr = getattr(candidates[0], "finish_reason", None)
                    finish_reason = str(fr) if fr is not None else None
                usage = self._usage_from(getattr(final_resp, "usage_metadata", None))
            yield Chunk(finish_reason=finish_reason, usage=usage)

    async def aclose(self) -> None:
        # google-genai client has no explicit close; nothing to release.
        self._client = None
