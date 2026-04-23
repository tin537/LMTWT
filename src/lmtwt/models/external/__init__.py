"""Per-protocol async adapters for ``--target external-api``."""

from .base import BaseExternalModel
from .http import HTTPExternalModel
from .sse import SSEExternalModel
from .websocket import WebSocketExternalModel

__all__ = [
    "BaseExternalModel",
    "HTTPExternalModel",
    "SSEExternalModel",
    "WebSocketExternalModel",
]
