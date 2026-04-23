from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lmtwt.models.async_openai import AsyncOpenAIModel
from lmtwt.models.conversation import Conversation


def _make_response(text="hi back", finish="stop", in_tok=10, out_tok=2, cached=4):
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message = MagicMock(content=text)
    resp.choices[0].finish_reason = finish
    resp.usage = MagicMock(
        prompt_tokens=in_tok,
        completion_tokens=out_tok,
        prompt_tokens_details=MagicMock(cached_tokens=cached),
    )
    return resp


async def test_chat_returns_typed_response():
    model = AsyncOpenAIModel(api_key="fake")
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_make_response())

    with patch(
        "lmtwt.models.async_openai.openai.AsyncOpenAI",
        return_value=fake_client,
    ):
        conv = Conversation().with_system("be terse").append("user", "hi")
        response = await model.chat(conv)

    assert response.content == "hi back"
    assert response.model == "gpt-4o"
    assert response.finish_reason == "stop"
    assert response.usage.input_tokens == 10
    assert response.usage.output_tokens == 2
    assert response.usage.cached_input_tokens == 4

    call_kwargs = fake_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["messages"] == [
        {"role": "system", "content": "be terse"},
        {"role": "user", "content": "hi"},
    ]


async def test_chat_raises_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        await AsyncOpenAIModel().chat(Conversation().append("user", "hi"))


async def test_chat_handles_none_content():
    model = AsyncOpenAIModel(api_key="fake")
    fake_client = MagicMock()
    resp = _make_response(text=None)
    fake_client.chat.completions.create = AsyncMock(return_value=resp)

    with patch(
        "lmtwt.models.async_openai.openai.AsyncOpenAI",
        return_value=fake_client,
    ):
        response = await model.chat(Conversation().append("user", "hi"))

    assert response.content == ""


async def test_astream_yields_deltas_then_final_chunk():
    model = AsyncOpenAIModel(api_key="fake")

    def _stream_event(text=None, finish=None, usage=None):
        ev = MagicMock()
        if text is None and finish is None:
            ev.choices = []
            ev.usage = usage
        else:
            ev.choices = [MagicMock()]
            ev.choices[0].delta = MagicMock(content=text)
            ev.choices[0].finish_reason = finish
        return ev

    async def fake_stream(*a, **kw):
        async def gen():
            yield _stream_event(text="hel")
            yield _stream_event(text="lo")
            yield _stream_event(finish="stop")
            yield _stream_event(
                usage=MagicMock(
                    prompt_tokens=5,
                    completion_tokens=2,
                    prompt_tokens_details=MagicMock(cached_tokens=0),
                )
            )

        return gen()

    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(side_effect=fake_stream)

    with patch(
        "lmtwt.models.async_openai.openai.AsyncOpenAI",
        return_value=fake_client,
    ):
        chunks = [c async for c in model.astream(Conversation().append("user", "hi"))]

    deltas = [c.delta for c in chunks if c.delta]
    assert "".join(deltas) == "hello"
    assert chunks[-1].finish_reason == "stop"
    assert chunks[-1].usage.input_tokens == 5
