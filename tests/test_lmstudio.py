from unittest.mock import patch

from lmtwt.models.async_factory import async_get_model
from lmtwt.models.async_openai import AsyncOpenAIModel


def test_lmstudio_factory_returns_openai_with_local_base_url():
    m = async_get_model("lmstudio")
    assert isinstance(m, AsyncOpenAIModel)
    assert m.base_url == "http://localhost:1234/v1"
    assert m.model_name == "local-model"
    # Any non-empty key works for LM Studio.
    assert m.api_key == "lm-studio"


def test_lmstudio_factory_honors_LM_STUDIO_BASE_URL_env(monkeypatch):
    monkeypatch.setenv("LM_STUDIO_BASE_URL", "http://192.168.1.42:1234/v1")
    m = async_get_model("lmstudio")
    assert m.base_url == "http://192.168.1.42:1234/v1"


def test_lmstudio_factory_passes_model_name_through():
    m = async_get_model("lmstudio", model_name="qwen2.5-coder-7b-instruct")
    assert m.model_name == "qwen2.5-coder-7b-instruct"


def test_lmstudio_factory_threads_proxy_kwargs():
    m = async_get_model(
        "lmstudio",
        proxy="http://127.0.0.1:8080",
        ca_bundle="/ca.pem",
    )
    assert m.proxy == "http://127.0.0.1:8080"
    assert m.ca_bundle == "/ca.pem"


async def test_openai_initialize_passes_base_url_to_sdk():
    captured: dict = {}

    def _fake_async_openai(**kw):
        captured.update(kw)

        class _C:
            pass

        return _C()

    with patch("lmtwt.models.async_openai.openai.AsyncOpenAI", _fake_async_openai):
        m = AsyncOpenAIModel(
            api_key="fake",
            base_url="http://localhost:1234/v1",
        )
        await m.initialize()

    assert captured["base_url"] == "http://localhost:1234/v1"
    assert captured["api_key"] == "fake"


async def test_openai_initialize_omits_base_url_when_unset():
    captured: dict = {}

    def _fake_async_openai(**kw):
        captured.update(kw)

        class _C:
            pass

        return _C()

    with patch("lmtwt.models.async_openai.openai.AsyncOpenAI", _fake_async_openai):
        m = AsyncOpenAIModel(api_key="fake")
        await m.initialize()

    assert "base_url" not in captured
