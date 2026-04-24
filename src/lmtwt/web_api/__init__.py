"""FastAPI + SSE backend for LMTWT.

MVP scope: a single page that runs the YAML probe catalog against a
target with live outcome streaming. The Gradio UI in ``lmtwt.web``
remains available; this is a parallel surface that doesn't replace it
yet.

Why not extend Gradio? Two reasons:
1. Gradio is heavy (drag-in deps, opinions about routing/auth) and
   awkward to embed in a customer's own webapp.
2. A FastAPI + SSE backend is reusable: same backend serves the web UI
   today, an MCP server tomorrow, a customer-facing report viewer next
   quarter.

Why one screen, not several? See roadmap §5 — scope cuts beat feature
sprawl. The probe-catalog runner is the load-bearing screen; everything
else can come later as additive endpoints.
"""

from .app import create_app, run_server

__all__ = ["create_app", "run_server"]
