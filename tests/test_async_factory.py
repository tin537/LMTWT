import pytest

from lmtwt.models.async_anthropic import AsyncAnthropicModel
from lmtwt.models.async_factory import async_get_model
from lmtwt.models.async_gemini import AsyncGeminiModel
from lmtwt.models.async_openai import AsyncOpenAIModel
from lmtwt.models.external.http import HTTPExternalModel


def test_factory_picks_anthropic():
    m = async_get_model("anthropic", api_key="fake")
    assert isinstance(m, AsyncAnthropicModel)
    assert m.model_name == "claude-opus-4-7"


def test_factory_picks_openai_with_override():
    m = async_get_model("openai", api_key="fake", model_name="gpt-4o-mini")
    assert isinstance(m, AsyncOpenAIModel)
    assert m.model_name == "gpt-4o-mini"


def test_factory_picks_gemini():
    m = async_get_model("gemini", api_key="fake")
    assert isinstance(m, AsyncGeminiModel)


def test_factory_external_api_requires_config():
    with pytest.raises(ValueError, match="api_config"):
        async_get_model("external-api")


def test_factory_builds_external_api():
    m = async_get_model("external-api", api_config={"endpoint": "https://x.example.com/"})
    assert isinstance(m, HTTPExternalModel)


def test_factory_rejects_unknown_provider():
    with pytest.raises(ValueError, match="Unsupported provider"):
        async_get_model("not-a-provider")


def test_factory_provider_is_case_insensitive():
    m = async_get_model("Anthropic", api_key="fake")
    assert isinstance(m, AsyncAnthropicModel)
