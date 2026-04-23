"""Tests for the ACP provider — fakes the subprocess via in-memory streams."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lmtwt.models.async_acp import AsyncACPModel
from lmtwt.models.async_factory import async_get_model
from lmtwt.models.conversation import Conversation

# ---- Fake subprocess scaffolding ----


class _FakeStreamReader:
    """Minimal asyncio.StreamReader-like with feed_data + readline."""

    def __init__(self):
        self._buf = bytearray()
        self._cond = asyncio.Condition()
        self._closed = False

    async def readline(self) -> bytes:
        async with self._cond:
            while not self._buf and not self._closed:
                await self._cond.wait()
            if not self._buf:
                return b""
            nl = self._buf.find(b"\n")
            if nl == -1:
                line = bytes(self._buf)
                self._buf.clear()
                return line
            line = bytes(self._buf[: nl + 1])
            del self._buf[: nl + 1]
            return line

    async def feed(self, line: bytes) -> None:
        async with self._cond:
            self._buf.extend(line)
            self._cond.notify_all()

    async def close(self) -> None:
        async with self._cond:
            self._closed = True
            self._cond.notify_all()


class _FakeStreamWriter:
    def __init__(self):
        self.written: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.written.append(data)

    async def drain(self) -> None:
        return None


class _FakeProc:
    def __init__(self):
        self.stdin = _FakeStreamWriter()
        self.stdout = _FakeStreamReader()
        self.stderr = _FakeStreamReader()
        self.returncode = None

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = -9

    async def wait(self):
        return self.returncode or 0


def _written_messages(proc: _FakeProc) -> list[dict]:
    """Decode every line the model wrote to the fake subprocess stdin."""
    out: list[dict] = []
    for chunk in proc.stdin.written:
        for raw in chunk.splitlines():
            if raw.strip():
                out.append(json.loads(raw))
    return out


async def _autorespond(proc: _FakeProc):
    """Background task: respond to ACP requests as a real agent would."""
    seen_initialize = False
    seen_session_new = False
    while True:
        await asyncio.sleep(0.01)
        msgs = _written_messages(proc)

        if not seen_initialize:
            init = next(
                (m for m in msgs if m.get("method") == "initialize"), None
            )
            if init is not None:
                await proc.stdout.feed(
                    (
                        json.dumps(
                            {"jsonrpc": "2.0", "id": init["id"], "result": {}}
                        )
                        + "\n"
                    ).encode()
                )
                seen_initialize = True
                continue

        if seen_initialize and not seen_session_new:
            sn = next(
                (m for m in msgs if m.get("method") == "session/new"), None
            )
            if sn is not None:
                await proc.stdout.feed(
                    (
                        json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": sn["id"],
                                "result": {"sessionId": "sess-1"},
                            }
                        )
                        + "\n"
                    ).encode()
                )
                seen_session_new = True
                continue

        if seen_session_new:
            prompt = next(
                (m for m in msgs if m.get("method") == "session/prompt"), None
            )
            if prompt is not None:
                # Stream two text chunks, then return the final response.
                for piece in ["he", "llo"]:
                    await proc.stdout.feed(
                        (
                            json.dumps(
                                {
                                    "jsonrpc": "2.0",
                                    "method": "session/update",
                                    "params": {
                                        "update": {
                                            "content": [
                                                {"type": "text", "text": piece}
                                            ]
                                        }
                                    },
                                }
                            )
                            + "\n"
                        ).encode()
                    )
                await asyncio.sleep(0.02)
                await proc.stdout.feed(
                    (
                        json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": prompt["id"],
                                "result": {"stopReason": "end_turn"},
                            }
                        )
                        + "\n"
                    ).encode()
                )
                return


# ---- factory ----


def test_factory_picks_claude_code():
    m = async_get_model("claude-code")
    assert isinstance(m, AsyncACPModel)


def test_factory_picks_acp_alias():
    m = async_get_model("acp")
    assert isinstance(m, AsyncACPModel)


def test_factory_passes_model_name_through():
    m = async_get_model("claude-code", model_name="custom-acp-agent")
    assert m.model_name == "custom-acp-agent"


# ---- construction defaults ----


def test_default_binary_is_claude(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_PATH", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_ARGS", raising=False)
    m = AsyncACPModel()
    assert m.binary == "claude"
    assert m.args == []


def test_env_var_overrides_binary_and_args(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_PATH", "/usr/local/bin/myagent")
    monkeypatch.setenv("CLAUDE_CODE_ARGS", "--agent-mode --port 1234")
    m = AsyncACPModel()
    assert m.binary == "/usr/local/bin/myagent"
    assert m.args == ["--agent-mode", "--port", "1234"]


# ---- end-to-end via fake subprocess ----


async def test_chat_runs_full_acp_handshake_and_returns_streamed_text():
    fake_proc = _FakeProc()

    async def _spawn(*a, **kw):
        return fake_proc

    with patch(
        "lmtwt.models.async_acp.asyncio.create_subprocess_exec",
        side_effect=_spawn,
    ):
        model = AsyncACPModel(binary="fake")
        # Background "server" that replies to our requests.
        server = asyncio.create_task(_autorespond(fake_proc))
        try:
            response = await model.chat(
                Conversation().append("user", "say hello")
            )
        finally:
            server.cancel()
            await fake_proc.stdout.close()
            await model.aclose()

    assert response.content == "hello"
    assert response.finish_reason == "end_turn"
    assert response.model == "claude-code-acp"

    # Verify the wire protocol: initialize → session/new → session/prompt
    methods = [m.get("method") for m in _written_messages(fake_proc)]
    assert methods[:3] == ["initialize", "session/new", "session/prompt"]


async def test_agent_initiated_request_is_rejected_with_minus_32601():
    """Security: agent must not be able to read FS / run commands through us."""
    fake_proc = _FakeProc()

    async def _spawn(*a, **kw):
        return fake_proc

    with patch(
        "lmtwt.models.async_acp.asyncio.create_subprocess_exec",
        side_effect=_spawn,
    ):
        model = AsyncACPModel(binary="fake")
        # Manually start the reader without going through full initialize() so
        # we can drive the agent-request flow without responding to initialize.
        model._proc = await _spawn()
        model._reader_task = asyncio.create_task(model._reader_loop())

        try:
            # Push an unsolicited request from the agent.
            await fake_proc.stdout.feed(
                (
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 999,
                            "method": "fs/read",
                            "params": {"path": "/etc/passwd"},
                        }
                    )
                    + "\n"
                ).encode()
            )

            # Wait until the model has dispatched its rejection.
            for _ in range(40):
                await asyncio.sleep(0.02)
                if any(
                    m.get("id") == 999 for m in _written_messages(fake_proc)
                ):
                    break
        finally:
            await fake_proc.stdout.close()
            await model.aclose()

    written = _written_messages(fake_proc)
    rejection = next((m for m in written if m.get("id") == 999), None)
    assert rejection is not None, "model did not respond to agent request"
    assert rejection.get("error", {}).get("code") == -32601


async def test_aclose_terminates_subprocess():
    fake_proc = _FakeProc()
    fake_proc.terminate = MagicMock()
    fake_proc.wait = AsyncMock(return_value=0)

    async def _spawn(*a, **kw):
        return fake_proc

    with patch(
        "lmtwt.models.async_acp.asyncio.create_subprocess_exec",
        side_effect=_spawn,
    ):
        model = AsyncACPModel(binary="fake")
        # Don't call initialize — just simulate being open.
        model._proc = fake_proc
        model._reader_task = asyncio.create_task(asyncio.sleep(60))
        await model.aclose()

    fake_proc.terminate.assert_called_once()
    assert model._proc is None
