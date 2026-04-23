"""LLM-targeted attacks delivered through real chatbot protocols.

These modules use the production chatbot's own protocol (Socket.IO, HTTP,
WebSocket) as a delivery vector for attacks on the *model's behavior* —
not as generic protocol fuzzers. Every attack here answers a question
about the LLM:

- ``session_lifecycle`` — does mutating the routing payload (``flow`` /
  ``subFlow`` / ``sessionId``) change the system-prompt context the LLM
  receives?
- ``channel_inconsistency`` — does the LLM's refusal verdict differ when
  the same prompt is delivered over different channels?
- ``jwt_claims`` (stub) — does forging user-context claims unlock different
  model capabilities?
- ``conversation_hijack`` (stub) — can a guessed/replayed ``sessionId`` be
  used to extract another user's conversation memory from the LLM?
- ``cost_amplification`` (stub) — what prompts maximize backend token
  spend before the LLM refuses?

The non-stub modules ship with full tests; the stubs raise
``NotImplementedError`` and are tracked in ``docs/roadmap.md`` Phase 5.4.
"""

from .channel_inconsistency import ChannelInconsistencyAttack, ChannelVerdict
from .session_lifecycle import (
    SessionLifecycleAttack,
    SessionLifecycleFinding,
    SessionMutation,
)

__all__ = [
    "ChannelInconsistencyAttack",
    "ChannelVerdict",
    "SessionLifecycleAttack",
    "SessionLifecycleFinding",
    "SessionMutation",
]
