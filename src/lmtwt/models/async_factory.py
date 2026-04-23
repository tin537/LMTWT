"""Async-side factory."""

from __future__ import annotations

from typing import Any

from .async_anthropic import AsyncAnthropicModel
from .async_base import AsyncAIModel
from .async_gemini import AsyncGeminiModel
from .async_openai import AsyncOpenAIModel
from .external import HTTPExternalModel, SSEExternalModel, WebSocketExternalModel

_EXTERNAL_PROTOCOLS = {
    "http": HTTPExternalModel,
    "sse": SSEExternalModel,
    "websocket": WebSocketExternalModel,
    "ws": WebSocketExternalModel,
    "wss": WebSocketExternalModel,
}

__all__ = ["async_get_model"]


def async_get_model(
    provider: str,
    api_key: str | None = None,
    model_name: str | None = None,
    api_config: dict[str, Any] | None = None,
    *,
    proxy: str | None = None,
    ca_bundle: str | None = None,
    verify: bool = True,
) -> AsyncAIModel:
    """Construct an async provider for the given name.

    ``proxy``, ``ca_bundle``, and ``verify`` are forwarded to every provider.
    For ``external-api`` targets the corresponding ``api_config`` keys
    (``proxy``, ``ca_bundle``, ``insecure``) take precedence.
    """

    p = provider.lower()

    transport_kwargs: dict[str, Any] = {
        "proxy": proxy,
        "ca_bundle": ca_bundle,
        "verify": verify,
    }

    if p == "gemini":
        kwargs: dict[str, Any] = {"api_key": api_key, **transport_kwargs}
        if model_name:
            kwargs["model_name"] = model_name
        return AsyncGeminiModel(**kwargs)

    if p == "openai":
        kwargs = {"api_key": api_key, **transport_kwargs}
        if model_name:
            kwargs["model_name"] = model_name
        return AsyncOpenAIModel(**kwargs)

    if p == "anthropic":
        kwargs = {"api_key": api_key, **transport_kwargs}
        if model_name:
            kwargs["model_name"] = model_name
        return AsyncAnthropicModel(**kwargs)

    if p == "external-api":
        if not api_config:
            raise ValueError("api_config is required for external-api targets")
        protocol = api_config.get("protocol", "http").lower()
        cls = _EXTERNAL_PROTOCOLS.get(protocol)
        if cls is None:
            raise ValueError(
                f"Unknown external-api protocol: {protocol!r}. "
                f"Choose one of: {sorted(_EXTERNAL_PROTOCOLS)}"
            )
        kwargs = {"api_config": api_config, **transport_kwargs}
        if model_name:
            kwargs["model_name"] = model_name
        return cls(**kwargs)

    if p == "huggingface":
        # Imported here so torch/transformers stay optional at install time.
        from .async_huggingface import AsyncHuggingFaceModel

        kwargs = {"api_key": api_key}
        if model_name:
            kwargs["model_name"] = model_name
        # HuggingFace local inference doesn't go through proxies; ignored.
        return AsyncHuggingFaceModel(**kwargs)

    raise ValueError(f"Unsupported provider: {provider}")
