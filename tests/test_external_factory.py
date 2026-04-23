import pytest

from lmtwt.models.async_factory import async_get_model
from lmtwt.models.external.http import HTTPExternalModel
from lmtwt.models.external.socketio import SocketIOExternalModel
from lmtwt.models.external.sse import SSEExternalModel
from lmtwt.models.external.websocket import WebSocketExternalModel


def test_factory_default_protocol_is_http():
    m = async_get_model("external-api", api_config={"endpoint": "https://x.example.com/"})
    assert isinstance(m, HTTPExternalModel)


def test_factory_http_explicit():
    m = async_get_model(
        "external-api",
        api_config={"protocol": "http", "endpoint": "https://x.example.com/"},
    )
    assert isinstance(m, HTTPExternalModel)


def test_factory_sse():
    m = async_get_model(
        "external-api",
        api_config={"protocol": "sse", "endpoint": "https://x.example.com/stream"},
    )
    assert isinstance(m, SSEExternalModel)


def test_factory_websocket():
    m = async_get_model(
        "external-api",
        api_config={"protocol": "websocket", "endpoint": "wss://x.example.com/"},
    )
    assert isinstance(m, WebSocketExternalModel)


def test_factory_websocket_alias():
    m = async_get_model(
        "external-api",
        api_config={"protocol": "wss", "endpoint": "wss://x.example.com/"},
    )
    assert isinstance(m, WebSocketExternalModel)


def test_factory_socketio():
    m = async_get_model(
        "external-api",
        api_config={"protocol": "socketio", "endpoint": "wss://x.example.com/socket.io/"},
    )
    assert isinstance(m, SocketIOExternalModel)


def test_factory_socketio_dot_alias():
    m = async_get_model(
        "external-api",
        api_config={"protocol": "socket.io", "endpoint": "wss://x.example.com/socket.io/"},
    )
    assert isinstance(m, SocketIOExternalModel)


def test_factory_rejects_unknown_protocol():
    with pytest.raises(ValueError, match="Unknown external-api protocol"):
        async_get_model(
            "external-api",
            api_config={"protocol": "carrierpigeon", "endpoint": "x"},
        )
