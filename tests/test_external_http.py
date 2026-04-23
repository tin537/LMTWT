import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lmtwt.models.conversation import Conversation
from lmtwt.models.external.base import extract
from lmtwt.models.external.http import HTTPExternalModel


def test_extract_handles_dict_path():
    data = {"choices": [{"message": {"content": "hello"}}]}
    assert extract(data, "choices.0.message.content") == "hello"


def test_extract_returns_empty_on_miss():
    assert extract({"a": 1}, "b.c") == ""


def test_extract_serializes_non_string():
    assert extract({"x": [1, 2]}, "x") == "[1, 2]"


def test_init_requires_endpoint():
    with pytest.raises(ValueError, match="endpoint"):
        HTTPExternalModel(api_config={})


async def test_chat_posts_payload_and_extracts_response():
    model = HTTPExternalModel(
        api_config={
            "endpoint": "https://api.example.com/v1/chat",
            "method": "POST",
            "supports_system_prompt": True,
            "system_key": "system",
            "supports_temperature": True,
            "model_key": "model",
            "model": "test-model-v1",
            "response_path": "choices.0.message.content",
        }
    )

    fake_response = MagicMock()
    fake_response.json = MagicMock(
        return_value={"choices": [{"message": {"content": "remote answer"}}]}
    )
    fake_response.raise_for_status = MagicMock()

    fake_client = MagicMock()
    fake_client.post = AsyncMock(return_value=fake_response)

    with patch(
        "lmtwt.models.external.http.httpx.AsyncClient", return_value=fake_client
    ):
        conv = Conversation().with_system("be helpful").append("user", "what's up?")
        response = await model.chat(conv, temperature=0.5)

    assert response.content == "remote answer"
    assert response.model == "test-model-v1"

    call_args = fake_client.post.call_args
    assert call_args.args[0] == "https://api.example.com/v1/chat"
    sent_payload = call_args.kwargs["json"]
    assert sent_payload["prompt"] == "what's up?"
    assert sent_payload["system"] == "be helpful"
    assert sent_payload["temperature"] == 0.5
    assert sent_payload["model"] == "test-model-v1"


async def test_chat_handles_plain_text_response():
    model = HTTPExternalModel(api_config={"endpoint": "https://api.example.com/echo"})

    fake_response = MagicMock()
    fake_response.json = MagicMock(side_effect=json.JSONDecodeError("x", "y", 0))
    fake_response.text = "raw plain text"
    fake_response.raise_for_status = MagicMock()

    fake_client = MagicMock()
    fake_client.post = AsyncMock(return_value=fake_response)

    with patch(
        "lmtwt.models.external.http.httpx.AsyncClient", return_value=fake_client
    ):
        response = await model.chat(Conversation().append("user", "hi"))

    assert response.content == "raw plain text"
