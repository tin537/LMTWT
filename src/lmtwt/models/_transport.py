"""Shared transport helpers — proxy, CA bundle, and TLS verification.

Used by every async provider (Anthropic, OpenAI, Gemini, HTTP/SSE external,
WebSocket external) so the same ``--proxy`` / ``--ca-bundle`` / ``--insecure``
CLI flags work everywhere. Designed primarily for routing through Burp,
mitmproxy, ZAP, or a corporate egress proxy.
"""

from __future__ import annotations

import ssl
from typing import Any


def _load_ca_context(ca_bundle: str) -> ssl.SSLContext:
    """Build an SSL context from a CA file. Supports both PEM (.pem/.crt) and DER (.der/.cer).

    Python's ``cafile=`` arg only accepts PEM, so for DER we read the bytes and
    pass them to ``load_verify_locations(cadata=...)`` which auto-detects format.
    """
    ctx = ssl.create_default_context()
    lower = ca_bundle.lower()
    if lower.endswith((".der", ".cer")):
        with open(ca_bundle, "rb") as f:
            ctx.load_verify_locations(cadata=f.read())
    else:
        ctx.load_verify_locations(cafile=ca_bundle)
    return ctx


def httpx_verify(ca_bundle: str | None, verify: bool) -> bool | str | ssl.SSLContext:
    """Translate (ca_bundle, verify) into the value httpx expects for ``verify=``.

    - ``verify=False`` → return ``False`` (insecure; skips cert validation)
    - ``ca_bundle`` is PEM → return the path (httpx loads it directly)
    - ``ca_bundle`` is DER (.der/.cer) → return a pre-built ``SSLContext``
    - default → return ``True`` (uses certifi)
    """
    if not verify:
        return False
    if ca_bundle:
        if ca_bundle.lower().endswith((".der", ".cer")):
            return _load_ca_context(ca_bundle)
        return ca_bundle
    return True


def httpx_client_kwargs(
    proxy: str | None,
    ca_bundle: str | None,
    verify: bool,
) -> dict[str, Any]:
    """Kwargs for ``httpx.AsyncClient(...)``. Strips ``None`` values."""
    kw: dict[str, Any] = {"verify": httpx_verify(ca_bundle, verify)}
    if proxy:
        kw["proxy"] = proxy
    return kw


def websocket_ssl_context(ca_bundle: str | None, verify: bool) -> ssl.SSLContext | None:
    """Build an SSL context for ``websockets.connect(ssl=...)``.

    Returns ``None`` to mean "let websockets pick the default".
    """
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_bundle:
        return _load_ca_context(ca_bundle)
    return None
