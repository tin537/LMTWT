from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lmtwt.models.async_gemini import AsyncGeminiModel
from lmtwt.models.conversation import Conversation


def _make_response(text="hi from gemini", finish="STOP", in_tok=12, out_tok=4):
    resp = MagicMock()
    resp.text = text
    cand = MagicMock(finish_reason=finish)
    resp.candidates = [cand]
    resp.usage_metadata = MagicMock(
        prompt_token_count=in_tok,
        candidates_token_count=out_tok,
        cached_content_token_count=0,
    )
    return resp


async def test_chat_returns_typed_response():
    model = AsyncGeminiModel(api_key="fake")
    fake_client = MagicMock()
    fake_client.aio.models.generate_content = AsyncMock(return_value=_make_response())

    with patch(
        "lmtwt.models.async_gemini.genai.Client",
        return_value=fake_client,
    ):
        conv = Conversation().with_system("be terse").append("user", "hi")
        response = await model.chat(conv)

    assert response.content == "hi from gemini"
    assert response.model == "gemini-2.0-flash"
    assert response.finish_reason == "STOP"
    assert response.usage.input_tokens == 12
    assert response.usage.output_tokens == 4

    call_kwargs = fake_client.aio.models.generate_content.call_args.kwargs
    assert call_kwargs["model"] == "gemini-2.0-flash"
    assert call_kwargs["contents"] == [{"role": "user", "parts": [{"text": "hi"}]}]


async def test_chat_raises_without_api_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        await AsyncGeminiModel().chat(Conversation().append("user", "hi"))


async def test_astream_yields_deltas_then_final_chunk():
    model = AsyncGeminiModel(api_key="fake")
    chunks_data = [
        _make_response(text="hel", finish=None),
        _make_response(text="lo", finish=None),
        _make_response(text="", finish="STOP"),
    ]

    async def fake_stream(*a, **kw):
        async def gen():
            for c in chunks_data:
                yield c

        return gen()

    fake_client = MagicMock()
    fake_client.aio.models.generate_content_stream = AsyncMock(side_effect=fake_stream)

    with patch(
        "lmtwt.models.async_gemini.genai.Client",
        return_value=fake_client,
    ):
        chunks = [c async for c in model.astream(Conversation().append("user", "hi"))]

    deltas = [c.delta for c in chunks if c.delta]
    assert "".join(deltas) == "hello"
    assert chunks[-1].finish_reason == "STOP"
