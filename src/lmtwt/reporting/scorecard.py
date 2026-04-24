"""Multi-target scorecard — same battery against N targets, side-by-side.

Sales / procurement use case: a buyer wants to compare 3 chatbot vendors
against the same LMTWT engagement, or an internal team wants to see
which of their 5 deployment regions is hardest to jailbreak. The output
is a single grid where rows are findings (union across targets) and
columns are targets.

Inputs are the same run-output JSONs ``--report-from`` accepts — one
per target. Findings are matched across targets via the same key
strategy ``diff.py`` uses (probe id preferred, falls back to a content
hash for chatbot-attack outputs without ids).
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from typing import Any

from .builder import Finding, build_report
from .diff import _match_key

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, None: 0}


@dataclass
class ScorecardCell:
    """One target's outcome for one finding (None = target didn't run that probe)."""

    finding: Finding | None  # ``None`` for absent rows

    @property
    def is_present(self) -> bool:
        return self.finding is not None

    @property
    def is_real(self) -> bool:
        if self.finding is None:
            return False
        from .diff import _is_real_finding
        return _is_real_finding(self.finding)


@dataclass
class ScorecardRow:
    """One finding across all targets."""

    key: str
    title: str
    coordinate: str | None
    owasp_tags: list[str] = field(default_factory=list)
    cells: list[ScorecardCell] = field(default_factory=list)

    @property
    def max_lss(self) -> float:
        return max(
            (c.finding.lss_score or 0.0 for c in self.cells if c.finding),
            default=0.0,
        )

    @property
    def worst_severity_rank(self) -> int:
        return max(
            (_SEVERITY_RANK.get(c.finding.severity, 0) if c.finding else 0
             for c in self.cells),
            default=0,
        )

    @property
    def hit_count(self) -> int:
        """Number of targets where this finding is real (medium+ or LSS>0)."""
        return sum(1 for c in self.cells if c.is_real)


@dataclass
class TargetSummary:
    """Per-column header summary."""

    name: str
    total_findings: int
    real_findings: int
    max_lss: float
    severity_counts: dict[str, int]


@dataclass
class ScorecardReport:
    """Full grid plus per-target summaries."""

    target_names: list[str]
    summaries: list[TargetSummary]
    rows: list[ScorecardRow]
    generated_at: str

    @property
    def total_targets(self) -> int:
        return len(self.target_names)

    @property
    def total_findings(self) -> int:
        return len(self.rows)


# ---------------------------------------------------------------- builder


def build_scorecard(
    payloads: list[dict | list],
    names: list[str] | None = None,
) -> ScorecardReport:
    """Build a side-by-side scorecard from N run-output payloads.

    ``names`` (one per payload) are the column labels. When omitted we
    derive them from each payload's ``metadata.target_model`` and fall
    back to ``Target {i+1}`` if absent.
    """
    if not payloads:
        raise ValueError("build_scorecard requires at least one payload")
    if names is not None and len(names) != len(payloads):
        raise ValueError(
            f"names ({len(names)}) must match payloads ({len(payloads)})"
        )

    reports = [build_report(p) for p in payloads]
    target_names = names or [
        r.target_name or f"Target {i + 1}" for i, r in enumerate(reports)
    ]

    # Per-target indices: key → Finding.
    per_target: list[dict[str, Finding]] = [
        {_match_key(f): f for f in r.findings} for r in reports
    ]

    # Union of keys, preserving deterministic ordering: first-seen across columns.
    all_keys: list[str] = []
    seen: set[str] = set()
    for column in per_target:
        for key in column:
            if key not in seen:
                seen.add(key)
                all_keys.append(key)

    rows: list[ScorecardRow] = []
    for key in all_keys:
        # Pick a representative for title/coordinate from the first column that has it.
        rep: Finding | None = None
        for column in per_target:
            f = column.get(key)
            if f is not None:
                rep = f
                break
        assert rep is not None  # at least one column had it (key came from there)

        cells = [
            ScorecardCell(finding=column.get(key)) for column in per_target
        ]
        rows.append(ScorecardRow(
            key=key,
            title=rep.title,
            coordinate=rep.coordinate,
            owasp_tags=list(rep.owasp_tags),
            cells=cells,
        ))

    # Sort rows: worst max-LSS first; tiebreak by hit-count desc, then key for stability.
    rows.sort(key=lambda r: (-r.max_lss, -r.hit_count, r.key))

    summaries = [_summarize(name, r) for name, r in zip(target_names, reports)]

    return ScorecardReport(
        target_names=list(target_names),
        summaries=summaries,
        rows=rows,
        generated_at=datetime.datetime.now().isoformat(timespec="seconds"),
    )


def _summarize(name: str, report) -> TargetSummary:
    from .diff import _is_real_finding

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    real = 0
    max_lss = 0.0
    for f in report.findings:
        if f.severity in sev:
            sev[f.severity] += 1
        if _is_real_finding(f):
            real += 1
        if f.lss_score and f.lss_score > max_lss:
            max_lss = f.lss_score
    return TargetSummary(
        name=name,
        total_findings=len(report.findings),
        real_findings=real,
        max_lss=max_lss,
        severity_counts=sev,
    )


# ---------------------------------------------------------------- render


def render_scorecard_markdown(report: ScorecardReport) -> str:
    lines: list[str] = []
    lines.append("# LMTWT Multi-Target Scorecard")
    lines.append("")
    lines.append(f"**Targets:** {report.total_targets}  ")
    lines.append(f"**Findings (union):** {report.total_findings}  ")
    lines.append(f"**Generated:** {report.generated_at}")
    lines.append("")

    # Per-target summary table.
    lines.append("## Per-Target Summary")
    lines.append("")
    lines.append("| Target | Findings | Real | Max LSS | Crit | High | Med | Low |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for s in report.summaries:
        lines.append(
            f"| {s.name} | {s.total_findings} | {s.real_findings} | "
            f"{s.max_lss:.2f} | {s.severity_counts['critical']} | "
            f"{s.severity_counts['high']} | {s.severity_counts['medium']} | "
            f"{s.severity_counts['low']} |"
        )
    lines.append("")

    # Findings grid.
    lines.append("## Findings Grid")
    lines.append("")
    header = "| # | Title | " + " | ".join(report.target_names) + " |"
    sep = "|---:|---|" + "|".join(["---"] * report.total_targets) + "|"
    lines.append(header)
    lines.append(sep)
    for i, row in enumerate(report.rows, start=1):
        cells_md = " | ".join(_cell_label(c) for c in row.cells)
        lines.append(f"| {i} | {row.title} | {cells_md} |")
    lines.append("")

    # Worst-of-class call-out — only meaningful with 2+ targets.
    if len(report.summaries) >= 2:
        worst = max(report.summaries, key=lambda s: s.max_lss)
        best = min(report.summaries, key=lambda s: (s.max_lss, s.real_findings))
        lines.append("## Headline")
        lines.append("")
        lines.append(
            f"- **Most exposed:** {worst.name} (max LSS {worst.max_lss:.2f}, "
            f"{worst.real_findings} real findings)"
        )
        lines.append(
            f"- **Least exposed:** {best.name} (max LSS {best.max_lss:.2f}, "
            f"{best.real_findings} real findings)"
        )
        lines.append("")

    return "\n".join(lines)


def _cell_label(cell: ScorecardCell) -> str:
    if cell.finding is None:
        return "—"
    f = cell.finding
    parts: list[str] = []
    if f.lss_score:
        parts.append(f"LSS={f.lss_score:.1f}")
    parts.append(f.severity)
    if f.refusal_grade:
        parts.append(f.refusal_grade)
    return " ".join(parts)


def scorecard_to_dict(report: ScorecardReport) -> dict[str, Any]:
    """JSON-serializable form for CI / vendor procurement decks."""
    return {
        "target_names": report.target_names,
        "generated_at": report.generated_at,
        "summaries": [
            {
                "name": s.name,
                "total_findings": s.total_findings,
                "real_findings": s.real_findings,
                "max_lss": s.max_lss,
                "severity_counts": s.severity_counts,
            }
            for s in report.summaries
        ],
        "rows": [
            {
                "key": r.key,
                "title": r.title,
                "coordinate": r.coordinate,
                "owasp_tags": r.owasp_tags,
                "max_lss": r.max_lss,
                "hit_count": r.hit_count,
                "cells": [
                    {
                        "target": name,
                        "finding": _finding_summary(c.finding),
                    }
                    for name, c in zip(report.target_names, r.cells)
                ],
            }
            for r in report.rows
        ],
    }


def _finding_summary(f: Finding | None) -> dict[str, Any] | None:
    if f is None:
        return None
    return {
        "severity": f.severity,
        "lss_score": f.lss_score,
        "refusal_grade": f.refusal_grade,
        "coordinate": f.coordinate,
    }
