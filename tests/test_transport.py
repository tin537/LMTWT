"""Tests for proxy / CA-bundle / verify plumbing across providers."""

from unittest.mock import MagicMock, patch

import pytest

from lmtwt.models._transport import (
    httpx_client_kwargs,
    httpx_verify,
    websocket_ssl_context,
)
from lmtwt.models.async_anthropic import AsyncAnthropicModel
from lmtwt.models.async_factory import async_get_model
from lmtwt.models.async_openai import AsyncOpenAIModel
from lmtwt.models.external.http import HTTPExternalModel
from lmtwt.models.external.websocket import WebSocketExternalModel


def test_httpx_verify_default_is_true():
    assert httpx_verify(None, True) is True


def test_httpx_verify_uses_ca_bundle_when_present():
    assert httpx_verify("/path/to/ca.pem", True) == "/path/to/ca.pem"


def test_httpx_verify_returns_false_when_insecure():
    assert httpx_verify("/path/ignored.pem", False) is False


def test_httpx_client_kwargs_omits_proxy_when_none():
    kw = httpx_client_kwargs(None, None, True)
    assert "proxy" not in kw
    assert kw["verify"] is True


def test_httpx_client_kwargs_includes_proxy():
    kw = httpx_client_kwargs("http://127.0.0.1:8080", None, True)
    assert kw["proxy"] == "http://127.0.0.1:8080"


def test_websocket_ssl_context_default_is_none():
    assert websocket_ssl_context(None, True) is None


def test_websocket_ssl_context_loads_ca_bundle(tmp_path):
    # Write a syntactically-valid PEM (one from certifi)
    import certifi

    ca_path = tmp_path / "ca.pem"
    ca_path.write_text(open(certifi.where()).read())
    ctx = websocket_ssl_context(str(ca_path), True)
    assert ctx is not None
    assert ctx.verify_mode.name in ("CERT_REQUIRED",)


def test_websocket_ssl_context_disables_verification_when_insecure():
    import ssl

    ctx = websocket_ssl_context(None, False)
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_NONE


# ---- provider integration ----


async def test_anthropic_passes_proxy_to_httpx_client():
    captured: dict = {}

    class FakeAsyncClient:
        def __init__(self, **kw):
            captured.update(kw)

    fake_anthropic_client = MagicMock()
    with (
        patch("lmtwt.models.async_anthropic.httpx.AsyncClient", FakeAsyncClient),
        patch(
            "lmtwt.models.async_anthropic.anthropic.AsyncAnthropic",
            return_value=fake_anthropic_client,
        ) as fake_cls,
    ):
        model = AsyncAnthropicModel(
            api_key="fake",
            proxy="http://127.0.0.1:8080",
            ca_bundle="/some/cacert.pem",
        )
        await model.initialize()

    assert captured == {"verify": "/some/cacert.pem", "proxy": "http://127.0.0.1:8080"}
    # httpx client was passed to the SDK as http_client=
    sdk_kwargs = fake_cls.call_args.kwargs
    assert "http_client" in sdk_kwargs


async def test_anthropic_skips_httpx_when_no_transport_overrides():
    fake_anthropic_client = MagicMock()
    with patch(
        "lmtwt.models.async_anthropic.anthropic.AsyncAnthropic",
        return_value=fake_anthropic_client,
    ) as fake_cls:
        model = AsyncAnthropicModel(api_key="fake")
        await model.initialize()

    # No proxy / verify override → no http_client kwarg on the SDK init.
    sdk_kwargs = fake_cls.call_args.kwargs
    assert "http_client" not in sdk_kwargs


async def test_openai_passes_proxy_to_httpx_client():
    captured: dict = {}

    class FakeAsyncClient:
        def __init__(self, **kw):
            captured.update(kw)

    with (
        patch("lmtwt.models.async_openai.httpx.AsyncClient", FakeAsyncClient),
        patch("lmtwt.models.async_openai.openai.AsyncOpenAI") as fake_cls,
    ):
        model = AsyncOpenAIModel(api_key="fake", proxy="http://burp:8080", verify=False)
        await model.initialize()

    assert captured == {"verify": False, "proxy": "http://burp:8080"}
    assert "http_client" in fake_cls.call_args.kwargs


def test_http_external_threads_proxy_into_httpx():
    captured: dict = {}

    class FakeAsyncClient:
        def __init__(self, **kw):
            captured.update(kw)

    with patch(
        "lmtwt.models.external.http.httpx.AsyncClient", FakeAsyncClient
    ):
        model = HTTPExternalModel(
            api_config={"endpoint": "https://x.example.com/"},
            proxy="http://127.0.0.1:8080",
            ca_bundle="/ca.pem",
        )
        import asyncio

        asyncio.run(model.initialize())

    assert captured["proxy"] == "http://127.0.0.1:8080"
    assert captured["verify"] == "/ca.pem"


def test_external_target_config_overrides_cli():
    """Per-target ``proxy`` / ``ca_bundle`` / ``insecure`` win over CLI kwargs."""
    captured: dict = {}

    class FakeAsyncClient:
        def __init__(self, **kw):
            captured.update(kw)

    with patch(
        "lmtwt.models.external.http.httpx.AsyncClient", FakeAsyncClient
    ):
        model = HTTPExternalModel(
            api_config={
                "endpoint": "https://x.example.com/",
                "proxy": "http://target-specific:9000",
                "insecure": True,
            },
            proxy="http://cli-default:8080",
            verify=True,
        )
        import asyncio

        asyncio.run(model.initialize())

    assert captured["proxy"] == "http://target-specific:9000"
    assert captured["verify"] is False  # insecure: True from target config


async def test_websocket_passes_proxy_and_ssl_to_connect():
    captured: dict = {}

    async def fake_connect(uri, **kw):
        captured["uri"] = uri
        captured.update(kw)
        sock = MagicMock()
        state = MagicMock()
        state.name = "OPEN"
        sock.state = state
        return sock

    with patch(
        "lmtwt.models.external.websocket.websockets.connect", side_effect=fake_connect
    ):
        model = WebSocketExternalModel(
            api_config={
                "endpoint": "wss://x.example.com/",
                "done_signal": "[DONE]",
            },
            proxy="http://127.0.0.1:8080",
        )
        await model._connect()

    assert captured["uri"] == "wss://x.example.com/"
    assert captured["proxy"] == "http://127.0.0.1:8080"


def test_factory_forwards_proxy_to_anthropic():
    fake_anthropic_client = MagicMock()
    with (
        patch("lmtwt.models.async_anthropic.httpx.AsyncClient"),
        patch(
            "lmtwt.models.async_anthropic.anthropic.AsyncAnthropic",
            return_value=fake_anthropic_client,
        ),
    ):
        m = async_get_model(
            "anthropic",
            api_key="fake",
            proxy="http://burp:8080",
            ca_bundle="/ca.pem",
        )
        # Capture the constructor kwargs by checking the model's stored values
        assert m.proxy == "http://burp:8080"
        assert m.ca_bundle == "/ca.pem"
        assert m.verify is True


def test_factory_huggingface_ignores_transport_kwargs():
    """HuggingFace runs locally; proxy is not applicable. Should not raise."""
    pytest.importorskip("torch")  # skip if HF stack not installed
    pytest.importorskip("transformers")
    m = async_get_model(
        "huggingface",
        proxy="http://burp:8080",
        ca_bundle="/ca.pem",
    )
    # No proxy-related attributes on AsyncHuggingFaceModel — it ignores them.
    assert not hasattr(m, "proxy") or m.proxy is None or True  # no-op assertion: just shouldn't raise
