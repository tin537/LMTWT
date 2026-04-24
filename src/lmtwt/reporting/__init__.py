"""Engagement-grade reporting — Markdown + PDF deliverables.

Turns any LMTWT run output into a client-shippable report with executive
summary, methodology, sorted findings table, per-finding reproduction
packs, OWASP-tagged remediation guidance, and an appendix.

PDF generation uses WeasyPrint when installed (optional dep, install via
``pip install lmtwt[report]``). When WeasyPrint isn't available, we still
emit clean Markdown — the user can convert via pandoc or paste into any
Markdown→PDF converter.
"""

from .builder import (
    EngagementReport,
    Finding,
    build_report,
    render_html,
    render_markdown,
    render_pdf,
)

__all__ = [
    "EngagementReport",
    "Finding",
    "build_report",
    "render_html",
    "render_markdown",
    "render_pdf",
]
