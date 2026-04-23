import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lmtwt.models.conversation import Conversation
from lmtwt.models.external.socketio import (
    SocketIOExternalModel,
    _ensure_eio_query,
    _parse_socketio_packet,
    _set_path,
)


# ----------------------------------------------------------------- helpers


class _FakeSioSocket:
    """Programmable Socket.IO server stand-in.

    Hands out frames in order via async-iteration. Each ``send`` may push
    additional frames via the ``on_send`` callback so tests can react to a
    client emit (e.g. produce an ack + an inbound ``receive_message``).
    """

    def __init__(self, frames=None, on_send=None):
        self._initial = list(frames or [])
        self._pending: asyncio.Queue = asyncio.Queue()
        for f in self._initial:
            self._pending.put_nowait(f)
        self._on_send = on_send
        self.sent: list[str] = []
        state = MagicMock()
        state.name = "OPEN"
        self.state = state

    async def send(self, msg):
        self.sent.append(msg)
        if self._on_send is not None:
            for extra in self._on_send(msg) or ():
                await self._pending.put(extra)

    async def close(self):
        self.state.name = "CLOSED"
        await self._pending.put(None)  # sentinel — end iteration

    def __aiter__(self):
        return self

    async def __anext__(self):
        item = await self._pending.get()
        if item is None:
            raise StopAsyncIteration
        return item


def _make_model(**overrides):
    cfg = {
        "endpoint": "wss://chat.example.com/socket.io/",
        "event_name": "send_message",
        "response_event": "receive_message",
        "payload_template": {
            "messageContent": [{"content": "", "type": "TEXT"}],
            "messageId": "",
            "sessionId": "",
        },
        "prompt_path": "messageContent.0.content",
        "message_id_key": "messageId",
        "session_id_key": "sessionId",
        "session_id": "20260408101704ba513af3",
        "response_path": "messageContent.0.content",
        "ack_timeout": 2,
        "response_timeout": 2,
        "connect_timeout": 2,
    }
    cfg.update(overrides)
    return SocketIOExternalModel(api_config=cfg)


# ----------------------------------------------------------- pure-helper unit tests


def test_set_path_dict_and_list_indexing():
    payload = {"messageContent": [{"content": "OLD"}], "messageId": ""}
    _set_path(payload, "messageContent.0.content", "NEW")
    _set_path(payload, "messageId", "abc")
    assert payload == {"messageContent": [{"content": "NEW"}], "messageId": "abc"}


def test_ensure_eio_query_appends_engineio_v4_params():
    out = _ensure_eio_query("wss://x.example.com/socket.io/")
    assert "EIO=4" in out and "transport=websocket" in out

    # Existing params are preserved and not duplicated.
    out2 = _ensure_eio_query("wss://x.example.com/socket.io/?EIO=4&transport=websocket")
    assert out2.count("EIO=4") == 1
    assert out2.count("transport=websocket") == 1


def test_ensure_eio_query_honors_v3():
    out = _ensure_eio_query("wss://x.example.com/socket.io/", eio_version="3")
    assert "EIO=3" in out
    assert "EIO=4" not in out


def test_parse_socketio_packet_event_with_ack_id():
    pkt = _parse_socketio_packet('21["send_message",{"x":1}]')
    assert pkt == {
        "type": "2",
        "namespace": "/",
        "ack_id": 1,
        "data": ["send_message", {"x": 1}],
    }


def test_parse_socketio_packet_ack():
    pkt = _parse_socketio_packet('31[{"status":"SUCCESS"},null]')
    assert pkt["type"] == "3"
    assert pkt["ack_id"] == 1
    assert pkt["data"] == [{"status": "SUCCESS"}, None]


def test_parse_socketio_packet_with_namespace():
    pkt = _parse_socketio_packet('2/chat,5["evt",{}]')
    assert pkt["namespace"] == "/chat"
    assert pkt["ack_id"] == 5
    assert pkt["data"] == ["evt", {}]


# ---------------------------------------------------------- payload composition


def test_build_payload_injects_prompt_message_and_session_ids():
    model = _make_model()
    payload = model.build_payload(
        Conversation().append("user", "hello"), temperature=0.7
    )
    assert payload["messageContent"][0]["content"] == "hello"
    assert payload["sessionId"] == "20260408101704ba513af3"
    # messageId is a fresh UUID per call — just check it's non-empty and stringy.
    assert isinstance(payload["messageId"], str) and len(payload["messageId"]) > 8


def test_build_payload_does_not_mutate_template():
    model = _make_model()
    original = json.dumps(model.api_config["payload_template"])
    model.build_payload(Conversation().append("user", "hello"), temperature=0.7)
    assert json.dumps(model.api_config["payload_template"]) == original


# ---------------------------------------------------------- end-to-end roundtrip


async def test_chat_full_socketio_handshake_and_event_roundtrip():
    """Walk the full Engine.IO open → SIO connect → emit → ack → response loop."""
    model = _make_model()

    # The reader loop reacts to whatever the server pushes. We script:
    #   1. Engine.IO open
    #   2. Socket.IO connect ack (in response to the client's '40')
    #   3. Ack '431[...]' + inbound event '42["receive_message", ...]'
    #      pushed in response to the client's '421[...]' emit.
    def on_send(msg):
        if msg == "40":
            return ['40{"sid":"abc"}']
        if msg.startswith("421"):
            ack = (
                '431[{"messageId":"req-id","serverMessageId":"5754",'
                '"status":"SUCCESS","timestamp":"2026-04-08T10:17:35Z"},null]'
            )
            event = (
                '42["receive_message",{"timestamp":"2026-04-08T10:17:44Z",'
                '"sessionId":"20260408101704ba513af3","messageId":"5755",'
                '"role":"CHATBOT","messageContent":[{"content":"test back",'
                '"type":"TEXT"}],"card":null}]'
            )
            return [ack, event]
        return ()

    sock = _FakeSioSocket(frames=['0{"sid":"eio-sid","pingInterval":25000}'], on_send=on_send)
    with patch(
        "lmtwt.models.external.socketio.websockets.connect",
        AsyncMock(return_value=sock),
    ):
        resp = await model.chat(Conversation().append("user", "test"))

    assert resp.content == "test back"

    # Validate the wire shape we emitted.
    sio_emit = next(s for s in sock.sent if s.startswith("421"))
    assert sio_emit.startswith('421["send_message",')
    body = json.loads(sio_emit[3:])
    assert body[0] == "send_message"
    assert body[1]["messageContent"][0]["content"] == "test"
    assert body[1]["sessionId"] == "20260408101704ba513af3"

    await model.aclose()


async def test_chat_responds_to_engineio_ping_with_pong():
    model = _make_model()

    def on_send(msg):
        if msg == "40":
            return ['40{"sid":"abc"}']
        if msg.startswith("421"):
            return [
                "2",  # server ping arrives mid-flight
                '431[{"status":"SUCCESS"},null]',
                '42["receive_message",{"messageContent":[{"content":"hi","type":"TEXT"}]}]',
            ]
        return ()

    sock = _FakeSioSocket(frames=['0{"sid":"eio-sid"}'], on_send=on_send)
    with patch(
        "lmtwt.models.external.socketio.websockets.connect",
        AsyncMock(return_value=sock),
    ):
        await model.chat(Conversation().append("user", "ping me"))

    assert "3" in sock.sent  # we replied to the engine.io ping
    await model.aclose()


async def test_chat_eio_v3_skips_explicit_connect_frame():
    """EIO v3 default-namespace flow: connection ready as soon as '0{...}' arrives;
    client must NOT send '40' (server auto-connects)."""
    model = _make_model(eio_version="3")

    def on_send(msg):
        if msg.startswith("421"):
            return [
                '431[{"status":"SUCCESS"},null]',
                '42["receive_message",{"messageContent":[{"content":"v3 reply","type":"TEXT"}]}]',
            ]
        return ()

    sock = _FakeSioSocket(
        frames=['0{"sid":"v3-sid","pingInterval":25000,"pingTimeout":5000}'],
        on_send=on_send,
    )
    with patch(
        "lmtwt.models.external.socketio.websockets.connect",
        AsyncMock(return_value=sock),
    ):
        resp = await model.chat(Conversation().append("user", "hi v3"))

    assert resp.content == "v3 reply"
    # The reader must NOT have synthesised a '40' connect frame for v3 default ns.
    assert not any(s.startswith("40") for s in sock.sent)
    await model.aclose()


async def test_chat_raises_on_ack_timeout():
    model = _make_model(ack_timeout=0.1, response_timeout=0.1)

    def on_send(msg):
        if msg == "40":
            return ['40{"sid":"abc"}']
        # Deliberately do NOT ack the emit.
        return ()

    sock = _FakeSioSocket(frames=['0{"sid":"eio-sid"}'], on_send=on_send)
    with patch(
        "lmtwt.models.external.socketio.websockets.connect",
        AsyncMock(return_value=sock),
    ):
        with pytest.raises(TimeoutError, match="ack"):
            await model.chat(Conversation().append("user", "test"))

    await model.aclose()
