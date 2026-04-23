from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lmtwt.models.async_anthropic import AsyncAnthropicModel
from lmtwt.models.conversation import Conversation


def _make_response(
    text="hello there",
    stop_reason="end_turn",
    in_tokens=10,
    out_tokens=2,
    cached=0,
):
    resp = MagicMock()
    resp.content = [MagicMock(text=text)]
    resp.stop_reason = stop_reason
    resp.usage = MagicMock(
        input_tokens=in_tokens,
        output_tokens=out_tokens,
        cache_read_input_tokens=cached,
    )
    return resp


async def test_chat_returns_typed_response():
    model = AsyncAnthropicModel(api_key="fake")
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_make_response())

    with patch(
        "lmtwt.models.async_anthropic.anthropic.AsyncAnthropic",
        return_value=fake_client,
    ):
        conv = Conversation().with_system("be terse").append("user", "hi")
        response = await model.chat(conv)

    assert response.content == "hello there"
    assert response.model == "claude-opus-4-7"
    assert response.finish_reason == "end_turn"
    assert response.usage.input_tokens == 10
    assert response.usage.output_tokens == 2

    call_kwargs = fake_client.messages.create.call_args.kwargs
    # Default-on prompt caching wraps system in a typed block with cache_control.
    assert call_kwargs["system"] == [
        {
            "type": "text",
            "text": "be terse",
            "cache_control": {"type": "ephemeral"},
        }
    ]
    assert call_kwargs["messages"] == [{"role": "user", "content": "hi"}]
    assert call_kwargs["max_tokens"] == 4096


async def test_chat_omits_system_when_absent():
    model = AsyncAnthropicModel(api_key="fake")
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_make_response())

    with patch(
        "lmtwt.models.async_anthropic.anthropic.AsyncAnthropic",
        return_value=fake_client,
    ):
        await model.chat(Conversation().append("user", "hi"))

    call_kwargs = fake_client.messages.create.call_args.kwargs
    assert "system" not in call_kwargs


async def test_chat_raises_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    model = AsyncAnthropicModel()
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        await model.chat(Conversation().append("user", "hi"))


async def test_initialize_is_idempotent():
    model = AsyncAnthropicModel(api_key="fake")
    with patch("lmtwt.models.async_anthropic.anthropic.AsyncAnthropic") as fake_cls:
        await model.initialize()
        await model.initialize()
    fake_cls.assert_called_once()


async def test_astream_yields_text_then_final_chunk():
    model = AsyncAnthropicModel(api_key="fake")
    final_resp = _make_response()

    class FakeTextStream:
        def __aiter__(self):
            async def gen():
                for t in ["hel", "lo ", "there"]:
                    yield t

            return gen()

    class FakeStream:
        text_stream = FakeTextStream()

        async def get_final_message(self):
            return final_resp

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

    fake_client = MagicMock()
    fake_client.messages.stream = MagicMock(return_value=FakeStream())

    with patch(
        "lmtwt.models.async_anthropic.anthropic.AsyncAnthropic",
        return_value=fake_client,
    ):
        chunks = [c async for c in model.astream(Conversation().append("user", "hi"))]

    text_chunks = [c.delta for c in chunks if c.delta]
    assert "".join(text_chunks) == "hello there"
    assert chunks[-1].finish_reason == "end_turn"
    assert chunks[-1].usage.input_tokens == 10


async def test_chat_sends_plain_string_when_cache_disabled():
    model = AsyncAnthropicModel(api_key="fake", cache_system=False)
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_make_response())

    with patch(
        "lmtwt.models.async_anthropic.anthropic.AsyncAnthropic",
        return_value=fake_client,
    ):
        await model.chat(Conversation().with_system("be terse").append("user", "hi"))

    call_kwargs = fake_client.messages.create.call_args.kwargs
    assert call_kwargs["system"] == "be terse"  # plain string, no cache_control


async def test_chat_surfaces_cache_hit_in_usage():
    model = AsyncAnthropicModel(api_key="fake")
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(
        return_value=_make_response(in_tokens=2, cached=1234)
    )

    with patch(
        "lmtwt.models.async_anthropic.anthropic.AsyncAnthropic",
        return_value=fake_client,
    ):
        response = await model.chat(
            Conversation().with_system("repeated system").append("user", "hi")
        )

    assert response.usage.cached_input_tokens == 1234


async def test_aclose_releases_client():
    model = AsyncAnthropicModel(api_key="fake")
    fake_client = MagicMock()
    fake_client.close = AsyncMock()

    with patch(
        "lmtwt.models.async_anthropic.anthropic.AsyncAnthropic",
        return_value=fake_client,
    ):
        await model.initialize()
        await model.aclose()

    fake_client.close.assert_awaited_once()
    assert model._client is None
