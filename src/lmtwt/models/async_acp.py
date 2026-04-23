"""Async Agent Client Protocol (ACP) provider.

Spawns an ACP-speaking subprocess (default: ``claude``) and exchanges
JSON-RPC 2.0 messages over stdio. Designed primarily for routing
Claude Code as an attacker or target, but works with any ACP-conforming
agent.

ACP is an evolving spec (https://agent-client-protocol.com). The default
message shapes here cover the standard ``initialize`` / ``session/new`` /
``session/prompt`` flow with ``session/update`` notifications; if your
agent uses different method names or content-block shapes, override
``_build_prompt_params`` or ``_extract_text_blocks`` in a subclass.

Security note: the agent may issue requests back to us (filesystem reads,
terminal commands). By default every such request is rejected with JSON-RPC
error -32601 ("Method not implemented") so the agent can't escape into the
host. Subclass and override ``_handle_agent_request`` to selectively allow.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from collections.abc import AsyncIterator
from typing import Any

from .async_base import AsyncAIModel, ChatResponse, Chunk
from .conversation import Conversation


class AsyncACPModel(AsyncAIModel):
    """JSON-RPC-over-stdio ACP client. Implements ``AsyncAIModel``."""

    def __init__(
        self,
        binary: str | None = None,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        model_name: str = "claude-code-acp",
        *,
        startup_timeout: float = 10.0,
        request_timeout: float = 120.0,
    ) -> None:
        self.binary = binary or os.getenv("CLAUDE_CODE_PATH", "claude")
        if args is None:
            raw = os.getenv("CLAUDE_CODE_ARGS", "")
            args = shlex.split(raw) if raw else []
        self.args = args
        self.env = env
        self.model_name = model_name
        self.startup_timeout = startup_timeout
        self.request_timeout = request_timeout

        self._proc: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task | None = None
        self._next_id = 1
        self._pending: dict[int, asyncio.Future] = {}
        self._notifications: asyncio.Queue = asyncio.Queue()
        self._session_id: str | None = None
        self._write_lock = asyncio.Lock()

    # ---- lifecycle ----

    async def initialize(self) -> None:
        if self._proc is not None:
            return
        self._proc = await asyncio.create_subprocess_exec(
            self.binary,
            *self.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
        )
        self._reader_task = asyncio.create_task(self._reader_loop())

        await self._send_request(
            "initialize",
            {"protocolVersion": "2024-11-05", "clientCapabilities": {}},
        )
        result = await self._send_request("session/new", {})
        if isinstance(result, dict):
            self._session_id = result.get("sessionId")

    async def aclose(self) -> None:
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        if self._proc is not None:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except (TimeoutError, asyncio.TimeoutError):
                self._proc.kill()
                await self._proc.wait()
            self._proc = None
        # Cancel any pending requests
        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    # ---- JSON-RPC plumbing ----

    async def _reader_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            line = await self._proc.stdout.readline()
            if not line:
                break
            try:
                msg = json.loads(line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            await self._dispatch(msg)

    async def _dispatch(self, msg: dict) -> None:
        # JSON-RPC response (carries id + result/error)
        if "id" in msg and ("result" in msg or "error" in msg):
            fut = self._pending.pop(msg["id"], None)
            if fut is not None and not fut.done():
                if "error" in msg:
                    fut.set_exception(RuntimeError(str(msg["error"])))
                else:
                    fut.set_result(msg.get("result"))
            return

        # Notification (no id) — push for chat() to consume
        if "method" in msg and "id" not in msg:
            await self._notifications.put(msg)
            return

        # Agent-initiated request — respond with error by default (security).
        if "method" in msg and "id" in msg:
            await self._handle_agent_request(msg)

    async def _handle_agent_request(self, msg: dict) -> None:
        """Reject by default — agent can't read FS / run commands through us."""
        await self._write_message(
            {
                "jsonrpc": "2.0",
                "id": msg["id"],
                "error": {
                    "code": -32601,
                    "message": f"Method not implemented: {msg.get('method')}",
                },
            }
        )

    async def _send_request(self, method: str, params: dict) -> Any:
        req_id = self._next_id
        self._next_id += 1
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut
        await self._write_message(
            {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        )
        try:
            return await asyncio.wait_for(fut, timeout=self.request_timeout)
        finally:
            self._pending.pop(req_id, None)

    async def _write_message(self, msg: dict) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        line = (json.dumps(msg) + "\n").encode("utf-8")
        async with self._write_lock:
            self._proc.stdin.write(line)
            await self._proc.stdin.drain()

    # ---- prompt/response flow ----

    def _build_prompt_params(self, conversation: Conversation) -> dict:
        last_user = next(
            (m.content for m in reversed(conversation.messages) if m.role == "user"),
            "",
        )
        return {
            "sessionId": self._session_id,
            "prompt": [{"type": "text", "text": last_user}],
        }

    @staticmethod
    def _extract_text_blocks(notif: dict) -> list[str]:
        """Pull text deltas from a ``session/update`` notification."""
        out: list[str] = []
        update = notif.get("params", {}).get("update", {})
        for block in update.get("content", []) or []:
            if block.get("type") == "text":
                out.append(block.get("text", ""))
        return out

    async def chat(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,  # noqa: ARG002 — agent owns its sampling
        max_tokens: int = 4096,  # noqa: ARG002
    ) -> ChatResponse:
        await self.initialize()
        params = self._build_prompt_params(conversation)
        prompt_task = asyncio.create_task(self._send_request("session/prompt", params))

        text_parts: list[str] = []
        while not prompt_task.done():
            try:
                notif = await asyncio.wait_for(self._notifications.get(), timeout=0.5)
            except (TimeoutError, asyncio.TimeoutError):
                continue
            if notif.get("method") == "session/update":
                text_parts.extend(self._extract_text_blocks(notif))

        result = await prompt_task
        # Drain any notifications that arrived between the response and now.
        while not self._notifications.empty():
            notif = self._notifications.get_nowait()
            if notif.get("method") == "session/update":
                text_parts.extend(self._extract_text_blocks(notif))

        finish_reason = (
            result.get("stopReason") if isinstance(result, dict) else None
        )
        return ChatResponse(
            content="".join(text_parts),
            model=self.model_name,
            finish_reason=finish_reason,
            raw=result,
        )

    async def astream(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,  # noqa: ARG002
        max_tokens: int = 4096,  # noqa: ARG002
    ) -> AsyncIterator[Chunk]:
        await self.initialize()
        params = self._build_prompt_params(conversation)
        prompt_task = asyncio.create_task(self._send_request("session/prompt", params))

        while not prompt_task.done():
            try:
                notif = await asyncio.wait_for(self._notifications.get(), timeout=0.5)
            except (TimeoutError, asyncio.TimeoutError):
                continue
            if notif.get("method") == "session/update":
                for piece in self._extract_text_blocks(notif):
                    if piece:
                        yield Chunk(delta=piece)

        result = await prompt_task
        while not self._notifications.empty():
            notif = self._notifications.get_nowait()
            if notif.get("method") == "session/update":
                for piece in self._extract_text_blocks(notif):
                    if piece:
                        yield Chunk(delta=piece)

        finish_reason = (
            result.get("stopReason") if isinstance(result, dict) else None
        )
        yield Chunk(finish_reason=finish_reason)
