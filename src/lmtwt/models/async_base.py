"""Async-first AIModel base class. Sibling of the legacy sync ``base.AIModel``.

This is the future of the model layer (see docs/roadmap.md Phase 2). The sync
``AIModel`` and its subclasses still drive the CLI and Web UI today; providers
will be migrated one at a time.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

from pydantic import BaseModel

from .conversation import Conversation


class Usage(BaseModel):
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_input_tokens: int | None = None


class ChatResponse(BaseModel):
    """Typed response from a single ``chat()`` call."""

    content: str
    model: str
    finish_reason: str | None = None
    usage: Usage | None = None
    # Opaque provider-native object kept around for debugging only. Not validated.
    raw: Any = None

    model_config = {"arbitrary_types_allowed": True}


class Chunk(BaseModel):
    """One streaming delta from ``astream()``."""

    delta: str = ""
    finish_reason: str | None = None
    usage: Usage | None = None


class AsyncAIModel(ABC):
    """Common interface for async LLM providers.

    Subclasses MUST be safe to use from multiple coroutines after ``initialize``.
    """

    model_name: str

    @abstractmethod
    async def initialize(self) -> None:
        """Construct the underlying client. Idempotent."""

    @abstractmethod
    async def chat(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> ChatResponse:
        """Send the conversation and return the full response."""

    @abstractmethod
    def astream(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[Chunk]:
        """Send the conversation and yield streaming chunks.

        Note: declared as a regular method that returns an ``AsyncIterator`` so
        subclasses can implement it as ``async def`` with ``yield`` statements
        without tripping the ABC machinery.
        """

    async def aclose(self) -> None:
        """Release any underlying client resources. Default is a no-op."""
        return None
