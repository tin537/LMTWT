"""Socket.IO v5 / Engine.IO v4 external-API adapter.

Speaks the Socket.IO sub-protocol over a raw WebSocket so that LMTWT can target
chatbots that expose Socket.IO endpoints (common in customer-service / fintech
chat backends). Implemented directly on the existing ``websockets`` dependency
to avoid pulling in ``python-socketio``.

Wire-format reference (Engine.IO v4 + Socket.IO v5):

- ``0{...}``                    Engine.IO open  (server → client)
- ``2`` / ``3``                 Engine.IO ping / pong
- ``40[/ns,]{auth?}``           Socket.IO connect
- ``42[/ns,][id]["event",data]`` Socket.IO event (optional namespace + ack id)
- ``43[/ns,]id[...]``           Socket.IO ack to a previously-sent event

Each ``chat()`` emits one event (default ``"send_message"``), optionally waits
for the matching ``43`` ack, then waits for a configurable inbound event
(default ``"receive_message"``) and extracts the assistant text via
``response_path``.
"""

from __future__ import annotations

import asyncio
import copy
import itertools
import json
import os
import re
import sys
import uuid
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import websockets
from websockets.exceptions import ConnectionClosed

_DEBUG = os.environ.get("LMTWT_SOCKETIO_DEBUG") in ("1", "true", "yes")


def _trace(direction: str, frame: str) -> None:
    if _DEBUG:
        snippet = frame if len(frame) <= 500 else frame[:500] + f"...<+{len(frame)-500}b>"
        print(f"[socketio {direction}] {snippet}", file=sys.stderr, flush=True)

from .._transport import websocket_ssl_context
from ..async_base import ChatResponse, Chunk
from ..conversation import Conversation
from .base import BaseExternalModel, extract

_RETRYABLE = (ConnectionClosed, OSError, asyncio.TimeoutError)

_EIO_OPEN = "0"
_EIO_CLOSE = "1"
_EIO_PING = "2"
_EIO_PONG = "3"
_EIO_MESSAGE = "4"

_SIO_CONNECT = "0"
_SIO_DISCONNECT = "1"
_SIO_EVENT = "2"
_SIO_ACK = "3"
_SIO_CONNECT_ERROR = "4"

_NS_RE = re.compile(r"^(/[^,]+),")


def _set_path(target: Any, dotted_path: str, value: Any) -> None:
    """Assign ``value`` at ``dotted_path`` inside an existing nested dict/list.

    Numeric segments index lists; everything else is a dict key. Containers are
    NOT auto-created — the caller's ``payload_template`` must already define
    the structure (only the leaf scalar is overwritten).
    """
    parts = dotted_path.split(".")
    cursor: Any = target
    for part in parts[:-1]:
        cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
    last = parts[-1]
    if isinstance(cursor, list):
        cursor[int(last)] = value
    else:
        cursor[last] = value


def _ensure_eio_query(url: str, eio_version: str = "4") -> str:
    """Append ``EIO=<version>&transport=websocket`` query params if not already set."""
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q.setdefault("EIO", str(eio_version))
    q.setdefault("transport", "websocket")
    return urlunparse(parsed._replace(query=urlencode(q)))


def _parse_socketio_packet(rest: str) -> dict[str, Any] | None:
    """Parse the bytes following the leading ``4`` (EIO_MESSAGE) byte.

    Returns ``{"type", "namespace", "ack_id", "data"}`` or ``None`` when
    unparseable. ``data`` is the JSON-decoded body (dict / list / scalar) or
    the raw remainder when the body isn't JSON.
    """
    if not rest:
        return None
    sio_type = rest[0]
    rest = rest[1:]
    namespace = "/"
    m = _NS_RE.match(rest)
    if m:
        namespace = m.group(1)
        rest = rest[m.end():]
    digits = ""
    while rest and rest[0].isdigit():
        digits += rest[0]
        rest = rest[1:]
    ack_id = int(digits) if digits else None
    data: Any = None
    if rest:
        try:
            data = json.loads(rest)
        except json.JSONDecodeError:
            data = rest
    return {"type": sio_type, "namespace": namespace, "ack_id": ack_id, "data": data}


class SocketIOExternalModel(BaseExternalModel):
    """Async Socket.IO v5 / Engine.IO v4 chat adapter.

    Designed for one in-flight ``chat()`` per instance — concurrent chats on
    the same model object are serialized via an internal lock so that the
    event-correlation logic stays simple. Spin up multiple instances if you
    need parallelism per target.
    """

    def __init__(self, api_config: dict[str, Any], model_name: str | None = None, **kw):
        super().__init__(api_config, model_name, retryable_exceptions=_RETRYABLE, **kw)
        self.namespace = api_config.get("namespace", "/")
        self.auth = api_config.get("auth")
        self.event_name = api_config.get("event_name", "message")
        self.response_event = api_config.get("response_event")
        self.prompt_path = api_config.get("prompt_path")
        self.message_id_key = api_config.get("message_id_key")
        self.session_id_key = api_config.get("session_id_key")
        self.explicit_session_id = api_config.get("session_id")
        self.response_path = api_config.get("response_path")
        self.request_ack = bool(api_config.get("request_ack", True))
        self.ack_timeout = float(api_config.get("ack_timeout", 30.0))
        self.response_timeout = float(api_config.get("response_timeout", 60.0))
        self.connect_timeout = float(api_config.get("connect_timeout", 30.0))
        self.keep_alive = bool(api_config.get("keep_alive", True))
        self.subprotocol = api_config.get("subprotocol")
        self.eio_version = str(api_config.get("eio_version", "4"))

        self._socket = None
        self._reader_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._ack_counter = itertools.count(1)
        self._ack_waiters: dict[int, asyncio.Future] = {}
        self._event_queue: asyncio.Queue | None = None
        self._connect_event: asyncio.Event | None = None
        self._connect_error: BaseException | None = None
        self._connect_lock = asyncio.Lock()
        self._call_lock = asyncio.Lock()
        self._session_id_cache: str | None = None

    # ------------------------------------------------------------------ AsyncAIModel

    async def initialize(self) -> None:
        return  # connect lazily on first chat()

    async def aclose(self) -> None:
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except (asyncio.CancelledError, Exception):
                pass
            self._heartbeat_task = None
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
            self._reader_task = None
        if self._socket is not None:
            try:
                await self._socket.send(_EIO_MESSAGE + _SIO_DISCONNECT)
            except Exception:
                pass
            try:
                await self._socket.close()
            except Exception:
                pass
            self._socket = None

    async def chat(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,  # noqa: ARG002
    ) -> ChatResponse:
        content = await self._roundtrip(conversation, temperature)
        return ChatResponse(content=content, model=self.model_name, finish_reason="stop")

    async def astream(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,  # noqa: ARG002
    ) -> AsyncIterator[Chunk]:
        # Socket.IO is event-based, not chunked — emit the full reply as one delta.
        content = await self._roundtrip(conversation, temperature)
        if content:
            yield Chunk(delta=content)
        yield Chunk(finish_reason="stop")

    # -------------------------------------------------------------- Payload assembly

    def build_payload(
        self,
        conversation: Conversation,
        temperature: float,
    ) -> dict[str, Any]:
        last_user = next(
            (m.content for m in reversed(conversation.messages) if m.role == "user"),
            "",
        )
        payload = copy.deepcopy(self.api_config.get("payload_template", {}))
        is_dict = isinstance(payload, dict)

        if self.prompt_path:
            _set_path(payload, self.prompt_path, last_user)
        elif is_dict:
            payload["prompt"] = last_user

        if is_dict and self.message_id_key:
            _set_path(payload, self.message_id_key, str(uuid.uuid4()))

        if is_dict and self.session_id_key:
            _set_path(payload, self.session_id_key, self._session_id())

        if is_dict and conversation.system and self.api_config.get(
            "supports_system_prompt", False
        ):
            _set_path(payload, self.api_config.get("system_key", "system"), conversation.system)

        if is_dict and self.api_config.get("supports_temperature", False):
            _set_path(
                payload,
                self.api_config.get("temperature_key", "temperature"),
                temperature,
            )

        return payload

    def _session_id(self) -> str:
        if self.explicit_session_id:
            return self.explicit_session_id
        if self._session_id_cache is None:
            self._session_id_cache = uuid.uuid4().hex
        return self._session_id_cache

    # ---------------------------------------------------------------- Connect / read

    async def _ensure_connected(self):
        if (
            self.keep_alive
            and self._socket is not None
            and getattr(self._socket.state, "name", "") == "OPEN"
        ):
            return self._socket
        async with self._connect_lock:
            if (
                self.keep_alive
                and self._socket is not None
                and getattr(self._socket.state, "name", "") == "OPEN"
            ):
                return self._socket
            await self._connect()
            return self._socket

    async def _connect(self):
        url = _ensure_eio_query(self.endpoint, self.eio_version)
        kwargs: dict[str, Any] = {"additional_headers": self.headers or None}
        if self.subprotocol:
            kwargs["subprotocols"] = [self.subprotocol]
        if self.proxy:
            kwargs["proxy"] = self.proxy
        ssl_ctx = websocket_ssl_context(self.ca_bundle, self.verify)
        if ssl_ctx is not None:
            kwargs["ssl"] = ssl_ctx
        sock = await websockets.connect(
            url, **{k: v for k, v in kwargs.items() if v is not None}
        )
        self._socket = sock
        self._connect_event = asyncio.Event()
        self._connect_error = None
        self._event_queue = asyncio.Queue()
        self._reader_task = asyncio.create_task(self._reader_loop(sock))
        try:
            await asyncio.wait_for(self._connect_event.wait(), timeout=self.connect_timeout)
        except asyncio.TimeoutError as exc:
            await self.aclose()
            raise TimeoutError(
                f"Timed out waiting for Socket.IO connect ack ({self.connect_timeout}s)"
            ) from exc
        if self._connect_error is not None:
            err = self._connect_error
            await self.aclose()
            raise err
        return sock

    async def _reader_loop(self, sock):
        try:
            async for raw in sock:
                text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
                if not text:
                    continue
                _trace("recv", text)
                eio = text[0]
                rest = text[1:]
                if eio == _EIO_OPEN:
                    await self._handle_eio_open(sock, rest)
                elif eio == _EIO_PING:
                    # Engine.IO v4: server-driven ping → reply pong.
                    try:
                        await sock.send(_EIO_PONG)
                    except ConnectionClosed:
                        return
                elif eio == _EIO_PONG:
                    # Engine.IO v3: ack of our client-driven ping.
                    pass
                elif eio == _EIO_CLOSE:
                    return
                elif eio == _EIO_MESSAGE:
                    self._dispatch_socketio(rest)
        except ConnectionClosed:
            return
        finally:
            for fut in list(self._ack_waiters.values()):
                if not fut.done():
                    fut.set_exception(ConnectionError("Socket.IO connection closed"))
            self._ack_waiters.clear()

    async def _handle_eio_open(self, sock, rest: str) -> None:
        """React to the Engine.IO ``0{...}`` open packet.

        - **EIO v4** (Socket.IO v5): client must send ``40[/ns,]{auth?}`` and
          wait for the server's ``40{"sid":"..."}`` reply. Server drives ping.
        - **EIO v3** (Socket.IO v2): server auto-connects to the default
          namespace; client only sends ``40/ns,`` for non-default namespaces.
          Client drives ping using ``pingInterval`` from this open packet.
        """
        # Parse open payload to get pingInterval (used for EIO v3 heartbeat).
        ping_interval_ms = 25000
        try:
            info = json.loads(rest) if rest else {}
            ping_interval_ms = int(info.get("pingInterval", ping_interval_ms))
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        ns = self.namespace if self.namespace and self.namespace != "/" else ""

        if self.eio_version == "3":
            # Default namespace: connection is ready immediately.
            if not ns and self._connect_event is not None:
                self._connect_event.set()
            else:
                # Non-default namespace: send '40/ns,' (no JSON auth in v3).
                try:
                    await sock.send(f"{_EIO_MESSAGE}{_SIO_CONNECT}{ns},")
                except ConnectionClosed:
                    return
            # Start client-side ping loop.
            self._heartbeat_task = asyncio.create_task(
                self._heartbeat_loop(sock, ping_interval_ms / 1000.0)
            )
            return

        # EIO v4: send Socket.IO connect frame, optionally with auth payload.
        auth_str = json.dumps(self.auth) if self.auth is not None else ""
        frame = (
            f"{_EIO_MESSAGE}{_SIO_CONNECT}{ns},{auth_str}"
            if ns
            else f"{_EIO_MESSAGE}{_SIO_CONNECT}{auth_str}"
        )
        try:
            await sock.send(frame)
        except ConnectionClosed:
            return

    async def _heartbeat_loop(self, sock, interval: float) -> None:
        """Engine.IO v3 client-driven ping. Quietly exits on close/cancel."""
        try:
            while True:
                await asyncio.sleep(interval)
                try:
                    await sock.send(_EIO_PING)
                except ConnectionClosed:
                    return
        except asyncio.CancelledError:
            return

    def _dispatch_socketio(self, rest: str) -> None:
        pkt = _parse_socketio_packet(rest)
        if pkt is None or pkt["namespace"] != self.namespace:
            return
        sio = pkt["type"]
        if sio == _SIO_CONNECT:
            if self._connect_event is not None:
                self._connect_event.set()
        elif sio == _SIO_CONNECT_ERROR:
            self._connect_error = ConnectionError(
                f"Socket.IO connect_error: {pkt['data']!r}"
            )
            if self._connect_event is not None:
                self._connect_event.set()
        elif sio == _SIO_DISCONNECT:
            return
        elif sio == _SIO_EVENT:
            if not (isinstance(pkt["data"], list) and pkt["data"]):
                return
            event_name = pkt["data"][0]
            event_args = pkt["data"][1:]
            if (
                self.response_event
                and event_name == self.response_event
                and self._event_queue is not None
            ):
                self._event_queue.put_nowait(event_args)
        elif sio == _SIO_ACK:
            ack_id = pkt["ack_id"]
            if ack_id is None:
                return
            waiter = self._ack_waiters.pop(ack_id, None)
            if waiter is not None and not waiter.done():
                waiter.set_result(pkt["data"])

    # ---------------------------------------------------------------------- Round-trip

    async def _roundtrip(self, conversation: Conversation, temperature: float) -> str:
        async with self._call_lock:
            sock = await self._ensure_connected()
            payload = self.build_payload(conversation, temperature)

            ack_future: asyncio.Future | None = None
            ack_id_str = ""
            ack_id_int: int | None = None
            if self.request_ack:
                ack_id_int = next(self._ack_counter)
                ack_future = asyncio.get_running_loop().create_future()
                self._ack_waiters[ack_id_int] = ack_future
                ack_id_str = str(ack_id_int)

            # Drain any stale buffered response events from a prior aborted call
            # so we don't return them to the wrong chat.
            if self._event_queue is not None:
                while not self._event_queue.empty():
                    try:
                        self._event_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break

            ns = self.namespace if self.namespace and self.namespace != "/" else ""
            prefix = f"{_EIO_MESSAGE}{_SIO_EVENT}"
            if ns:
                prefix += f"{ns},"
            body = json.dumps([self.event_name, payload])
            frame = f"{prefix}{ack_id_str}{body}"

            async with self._limiter:
                _trace("send", frame)
                await sock.send(frame)

                ack_data: Any = None
                if ack_future is not None:
                    try:
                        ack_data = await asyncio.wait_for(
                            ack_future, timeout=self.ack_timeout
                        )
                    except asyncio.TimeoutError as exc:
                        if ack_id_int is not None:
                            self._ack_waiters.pop(ack_id_int, None)
                        raise TimeoutError(
                            f"Timed out waiting for Socket.IO ack {ack_id_str} "
                            f"({self.ack_timeout}s)"
                        ) from exc

                if self.response_event:
                    try:
                        args = await asyncio.wait_for(
                            self._event_queue.get(),  # type: ignore[union-attr]
                            timeout=self.response_timeout,
                        )
                    except asyncio.TimeoutError as exc:
                        raise TimeoutError(
                            f"Timed out waiting for Socket.IO event "
                            f"{self.response_event!r} ({self.response_timeout}s)"
                        ) from exc
                    source: Any = args[0] if args else None
                else:
                    source = (
                        ack_data[0]
                        if isinstance(ack_data, list) and ack_data
                        else ack_data
                    )

            if isinstance(source, (dict, list)):
                if self.response_path:
                    return extract(source, self.response_path)
                return json.dumps(source)
            return source if isinstance(source, str) else json.dumps(source)
