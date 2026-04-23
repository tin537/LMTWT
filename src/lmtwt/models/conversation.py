"""Conversation value object — explicit, caller-owned chat history.

Replaces the implicit ``AIModel.history`` mutation pattern. Callers build a
``Conversation``, pass it to ``AsyncAIModel.chat``/``astream``, and receive a
new ``Conversation`` back with the assistant turn appended. Models never
mutate caller state.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Literal

Role = Literal["user", "assistant", "system"]


@dataclass(frozen=True, slots=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True, slots=True)
class Conversation:
    """Immutable chat transcript. Mutation methods return a new instance."""

    messages: tuple[Message, ...] = field(default_factory=tuple)
    system: str | None = None

    def append(self, role: Role, content: str) -> Conversation:
        return replace(self, messages=(*self.messages, Message(role, content)))

    def with_system(self, system: str | None) -> Conversation:
        return replace(self, system=system)

    def to_openai(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        if self.system:
            out.append({"role": "system", "content": self.system})
        out.extend({"role": m.role, "content": m.content} for m in self.messages)
        return out

    def to_anthropic(self) -> list[dict[str, str]]:
        # Anthropic takes ``system`` as a separate kwarg; only user/assistant in messages.
        return [{"role": m.role, "content": m.content} for m in self.messages]

    def to_gemini(self) -> list[dict[str, Any]]:
        # Gemini uses ``model`` instead of ``assistant`` and a ``parts`` list.
        out: list[dict[str, Any]] = []
        for m in self.messages:
            role = "model" if m.role == "assistant" else m.role
            out.append({"role": role, "parts": [{"text": m.content}]})
        return out
