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
from .diff import (
    DiffFinding,
    DiffReport,
    build_diff_report,
    diff_to_dict,
    render_diff_markdown,
)
from .repro import REPRO_PACK_VERSION, build_repro_pack, write_repro_pack
from .scorecard import (
    ScorecardCell,
    ScorecardReport,
    ScorecardRow,
    TargetSummary,
    build_scorecard,
    render_scorecard_markdown,
    scorecard_to_dict,
)

__all__ = [
    "DiffFinding",
    "DiffReport",
    "EngagementReport",
    "Finding",
    "REPRO_PACK_VERSION",
    "ScorecardCell",
    "ScorecardReport",
    "ScorecardRow",
    "TargetSummary",
    "build_diff_report",
    "build_report",
    "build_repro_pack",
    "build_scorecard",
    "diff_to_dict",
    "render_diff_markdown",
    "render_html",
    "render_markdown",
    "render_pdf",
    "render_scorecard_markdown",
    "scorecard_to_dict",
    "write_repro_pack",
]
