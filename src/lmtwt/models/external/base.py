"""Shared scaffolding for external-API adapters."""

from __future__ import annotations

import json
from typing import Any

from aiolimiter import AsyncLimiter
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..async_base import AsyncAIModel
from ..conversation import Conversation


def extract(data: Any, dotted_path: str) -> str:
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


def matches_done_signal(signal: Any, frame_text: str, frame_data: Any) -> bool:
    """Decide whether a streamed frame ends the response.

    ``signal`` may be:
    - ``None`` → never; caller terminates on stream close
    - a string literal → match against ``frame_text``
    - a dict ``{"path": ..., "value": ...}`` → match path on parsed ``frame_data``
    """
    if signal is None:
        return False
    if isinstance(signal, str):
        return frame_text.strip() == signal
    if isinstance(signal, dict) and "path" in signal:
        return extract(frame_data, signal["path"]) == str(signal.get("value", ""))
    return False


class BaseExternalModel(AsyncAIModel):
    """Shared init, payload composition, retry/limiter scaffolding."""

    def __init__(
        self,
        api_config: dict[str, Any],
        model_name: str | None = None,
        *,
        max_rate: int = 60,
        time_period: float = 60.0,
        max_attempts: int = 3,
        timeout: float = 30.0,
        retryable_exceptions: tuple[type[BaseException], ...] = (),
        proxy: str | None = None,
        ca_bundle: str | None = None,
        verify: bool = True,
    ) -> None:
        if not api_config.get("endpoint"):
            raise ValueError("api_config must include 'endpoint'")
        self.api_config = api_config
        self.model_name = model_name or api_config.get("model", "external-api")
        self.endpoint = api_config["endpoint"]
        self.headers = api_config.get("headers", {})
        self.params = api_config.get("params", {})
        self.timeout = timeout
        # Per-target overrides win over CLI-level kwargs.
        self.proxy = api_config.get("proxy", proxy)
        self.ca_bundle = api_config.get("ca_bundle", ca_bundle)
        self.verify = not api_config.get("insecure", False) if "insecure" in api_config else verify

        self._limiter = AsyncLimiter(max_rate=max_rate, time_period=time_period)
        self._retry = AsyncRetrying(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(multiplier=1, min=2, max=10),
            retry=retry_if_exception_type(retryable_exceptions or (Exception,)),
            reraise=True,
        )

    def build_payload(
        self,
        conversation: Conversation,
        temperature: float,
    ) -> dict[str, Any]:
        last_user = next(
            (m.content for m in reversed(conversation.messages) if m.role == "user"),
            "",
        )
        payload = dict(self.api_config.get("payload_template", {}))
        # Targets vary on which field carries the user message — default to
        # ``prompt`` for backward compat, override via ``prompt_key`` (e.g.
        # ``"message"`` for chatbot APIs that don't use the OpenAI shape).
        prompt_key = self.api_config.get("prompt_key", "prompt")
        payload[prompt_key] = last_user
        if conversation.system and self.api_config.get("supports_system_prompt", False):
            sys_key = self.api_config.get("system_key")
            if sys_key:
                payload[sys_key] = conversation.system
            else:
                payload[prompt_key] = f"{conversation.system}\n\n{last_user}"
        if self.api_config.get("supports_temperature", False):
            payload[self.api_config.get("temperature_key", "temperature")] = temperature
        if "model_key" in self.api_config:
            payload[self.api_config["model_key"]] = self.model_name
        return payload
