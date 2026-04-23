from unittest.mock import MagicMock, patch

from lmtwt.models.conversation import Conversation
from lmtwt.models.external.sse import SSEExternalModel


class _FakeStreamResponse:
    """Minimal stand-in for ``httpx.Response`` returned from ``client.stream(...)``."""

    def __init__(self, lines: list[str]):
        self._lines = lines

    def raise_for_status(self):
        return None

    async def aiter_lines(self):
        for line in self._lines:
            yield line

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None


def _patched_client(lines: list[str]):
    fake_client = MagicMock()
    fake_client.stream = MagicMock(return_value=_FakeStreamResponse(lines))
    return fake_client


async def test_sse_chat_aggregates_chunks_until_done_signal():
    model = SSEExternalModel(
        api_config={
            "endpoint": "https://api.example.com/v1/stream",
            "chunk_path": "choices.0.delta.content",
            "done_signal": "[DONE]",
        }
    )
    lines = [
        'data: {"choices":[{"delta":{"content":"hel"}}]}',
        "",  # blank line — should be ignored
        'data: {"choices":[{"delta":{"content":"lo "}}]}',
        'data: {"choices":[{"delta":{"content":"there"}}]}',
        "data: [DONE]",
        # Anything after [DONE] should be unreachable.
        'data: {"choices":[{"delta":{"content":"NEVER"}}]}',
    ]
    with patch(
        "lmtwt.models.external.sse.httpx.AsyncClient",
        return_value=_patched_client(lines),
    ):
        resp = await model.chat(Conversation().append("user", "hi"))

    assert resp.content == "hello there"
    assert resp.finish_reason == "stop"


async def test_sse_astream_yields_each_chunk_then_terminator():
    model = SSEExternalModel(
        api_config={
            "endpoint": "https://api.example.com/v1/stream",
            "chunk_path": "choices.0.delta.content",
        }
    )
    lines = [
        'data: {"choices":[{"delta":{"content":"a"}}]}',
        'data: {"choices":[{"delta":{"content":"b"}}]}',
        "data: [DONE]",
    ]
    with patch(
        "lmtwt.models.external.sse.httpx.AsyncClient",
        return_value=_patched_client(lines),
    ):
        chunks = [c async for c in model.astream(Conversation().append("user", "hi"))]

    deltas = [c.delta for c in chunks if c.delta]
    assert deltas == ["a", "b"]
    assert chunks[-1].finish_reason == "stop"


async def test_sse_path_based_done_signal():
    model = SSEExternalModel(
        api_config={
            "endpoint": "https://api.example.com/v1/stream",
            "chunk_path": "delta",
            "done_signal": {"path": "type", "value": "done"},
        }
    )
    lines = [
        'data: {"type":"chunk","delta":"first"}',
        'data: {"type":"chunk","delta":"second"}',
        'data: {"type":"done","delta":""}',
        # not reached
        'data: {"type":"chunk","delta":"NEVER"}',
    ]
    with patch(
        "lmtwt.models.external.sse.httpx.AsyncClient",
        return_value=_patched_client(lines),
    ):
        resp = await model.chat(Conversation().append("user", "hi"))

    assert resp.content == "firstsecond"
