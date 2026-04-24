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


def test_factory_openai_compat_requires_base_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("OPENAI_COMPAT_BASE_URL", raising=False)
    with pytest.raises(ValueError, match="OPENAI_COMPAT_BASE_URL"):
        async_get_model("openai-compat")


def test_factory_openai_compat_uses_env_base_url_and_optional_key(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("OPENAI_COMPAT_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("OPENAI_COMPAT_API_KEY", "ollama-key")
    monkeypatch.setenv("OPENAI_COMPAT_MODEL", "qwen2.5:7b")
    m = async_get_model("openai-compat")
    assert isinstance(m, AsyncOpenAIModel)
    assert m.base_url == "http://localhost:11434/v1"
    assert m.model_name == "qwen2.5:7b"


def test_factory_openai_compat_explicit_args_win_over_env(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("OPENAI_COMPAT_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("OPENAI_COMPAT_MODEL", "default-model")
    m = async_get_model(
        "openai-compat", api_key="caller-key", model_name="explicit-model",
    )
    assert m.model_name == "explicit-model"


def test_factory_openai_compatible_alias_works(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENAI_COMPAT_BASE_URL", "http://localhost:8080/v1")
    m = async_get_model("openai-compatible")
    assert isinstance(m, AsyncOpenAIModel)
