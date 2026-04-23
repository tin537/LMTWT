from unittest.mock import AsyncMock, MagicMock, patch

from lmtwt.models.conversation import Conversation
from lmtwt.models.external.websocket import WebSocketExternalModel


class _FakeSocket:
    """Minimal stand-in for a ``websockets`` connection."""

    def __init__(self, frames: list[str]):
        self._frames = frames
        self.sent: list[str] = []
        self.closed = False
        # Mimic websockets ConnectionState (.name)
        state = MagicMock()
        state.name = "OPEN"
        self.state = state

    async def send(self, msg):
        self.sent.append(msg)

    async def close(self):
        self.closed = True
        self.state.name = "CLOSED"

    def __aiter__(self):
        async def gen():
            for f in self._frames:
                yield f

        return gen()


async def test_ws_chat_aggregates_until_done_signal():
    model = WebSocketExternalModel(
        api_config={
            "endpoint": "wss://api.example.com/v1/realtime",
            "chunk_path": "delta",
            "done_signal": {"path": "type", "value": "done"},
        }
    )
    frames = [
        '{"type":"chunk","delta":"hel"}',
        '{"type":"chunk","delta":"lo"}',
        '{"type":"done","delta":""}',
        '{"type":"chunk","delta":"NEVER"}',
    ]
    sock = _FakeSocket(frames)
    with patch(
        "lmtwt.models.external.websocket.websockets.connect",
        AsyncMock(return_value=sock),
    ):
        resp = await model.chat(Conversation().append("user", "hi"))

    assert resp.content == "hello"
    # Verify the request frame was sent.
    assert len(sock.sent) == 1
    assert "hi" in sock.sent[0]


async def test_ws_sends_auth_message_first():
    model = WebSocketExternalModel(
        api_config={
            "endpoint": "wss://api.example.com/v1/auth",
            "auth_message": {"type": "auth", "token": "abc"},
            "chunk_path": "delta",
            "done_signal": {"path": "type", "value": "done"},
        }
    )
    frames = ['{"type":"done","delta":""}']
    sock = _FakeSocket(frames)
    with patch(
        "lmtwt.models.external.websocket.websockets.connect",
        AsyncMock(return_value=sock),
    ):
        await model.chat(Conversation().append("user", "hi"))

    # Auth message goes first, then the request payload.
    assert len(sock.sent) == 2
    assert "auth" in sock.sent[0]
    assert "hi" in sock.sent[1]


async def test_ws_astream_yields_chunks():
    model = WebSocketExternalModel(
        api_config={
            "endpoint": "wss://api.example.com/v1/realtime",
            "chunk_path": "delta",
            "done_signal": "[DONE]",
        }
    )
    frames = [
        '{"delta":"a"}',
        '{"delta":"b"}',
        "[DONE]",
    ]
    sock = _FakeSocket(frames)
    with patch(
        "lmtwt.models.external.websocket.websockets.connect",
        AsyncMock(return_value=sock),
    ):
        chunks = [
            c async for c in model.astream(Conversation().append("user", "hi"))
        ]

    deltas = [c.delta for c in chunks if c.delta]
    assert deltas == ["a", "b"]
    assert chunks[-1].finish_reason == "stop"


async def test_ws_keep_alive_reuses_socket():
    model = WebSocketExternalModel(
        api_config={
            "endpoint": "wss://api.example.com/v1/realtime",
            "chunk_path": "delta",
            "done_signal": "[DONE]",
            "keep_alive": True,
        }
    )

    def _make_socket():
        return _FakeSocket(['{"delta":"x"}', "[DONE]"])

    connect_mock = AsyncMock(side_effect=lambda *a, **kw: _make_socket())
    with patch("lmtwt.models.external.websocket.websockets.connect", connect_mock):
        await model.chat(Conversation().append("user", "hi"))
        await model.chat(Conversation().append("user", "again"))

    # keep_alive=True should mean only one connect call.
    assert connect_mock.call_count == 1
