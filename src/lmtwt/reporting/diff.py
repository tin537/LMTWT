"""Before / after diff mode — re-run the same battery and report what changed.

Takes two run-output JSONs (the dicts ``ReportGenerator`` writes — same
shape ``--report-from`` already accepts) and bucketizes their findings
into four verdicts:

- **remediated** — was a real finding before, gone or hard-refused after
- **regressed** — was clean before, a real finding after
- **persistent** — present in both; may have changed severity / grade
- **new** — present only in ``after``, no ``before`` counterpart at all

The split between *regressed* and *new* is intentional: regressed means a
finding the engagement already knew about that came back (a remediation
broke or a guardrail was rolled back); new means a finding that didn't
exist on the previous run (a new probe was added, or a new attack
surface opened up).

Matching key prefers ``probe_id`` (stable across runs by design); when
absent we fall back to ``(coordinate, sha1(attack_prompt[:200]))`` —
sufficient for chatbot-attack outputs that don't have probe ids but do
have coordinates and stable prompts.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal

from .builder import Finding, build_report

DiffVerdict = Literal["remediated", "regressed", "persistent", "new"]

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, None: 0}
_GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 2, "F": 4, None: 0, "": 0}


@dataclass
class DiffFinding:
    """One bucketed before/after comparison."""

    verdict: DiffVerdict
    id: str
    title: str
    before: Finding | None
    after: Finding | None
    severity_delta: int  # +N got worse, -N got better, 0 unchanged
    lss_delta: float
    grade_change: str | None  # 'B->F' if both sides have a grade

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "id": self.id,
            "title": self.title,
            "before": _finding_to_dict(self.before),
            "after": _finding_to_dict(self.after),
            "severity_delta": self.severity_delta,
            "lss_delta": self.lss_delta,
            "grade_change": self.grade_change,
        }


@dataclass
class DiffReport:
    """Top-level diff between two engagements."""

    target_name: str
    before_generated_at: str
    after_generated_at: str
    diffed_at: str
    findings: list[DiffFinding]
    before_metadata: dict[str, Any] = field(default_factory=dict)
    after_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        out = {"remediated": 0, "regressed": 0, "persistent": 0, "new": 0}
        for f in self.findings:
            out[f.verdict] += 1
        return out

    @property
    def max_lss_delta(self) -> float:
        return max((f.lss_delta for f in self.findings), default=0.0)

    @property
    def min_lss_delta(self) -> float:
        return min((f.lss_delta for f in self.findings), default=0.0)


# ---------------------------------------------------------------- builder


def build_diff_report(
    before_payload: dict | list,
    after_payload: dict | list,
    *,
    target_name: str | None = None,
) -> DiffReport:
    """Build a diff between two engagement run-output payloads."""
    before_report = build_report(before_payload, target_name=target_name)
    after_report = build_report(after_payload, target_name=target_name)

    before_by_key: dict[str, Finding] = {_match_key(f): f for f in before_report.findings}
    after_by_key: dict[str, Finding] = {_match_key(f): f for f in after_report.findings}

    diffs: list[DiffFinding] = []

    # Walk the union of keys; deterministic order = before first, then after-only.
    seen: set[str] = set()
    for key, before in before_by_key.items():
        seen.add(key)
        after = after_by_key.get(key)
        diffs.append(_classify(key, before, after))
    for key, after in after_by_key.items():
        if key in seen:
            continue
        diffs.append(_classify(key, None, after))

    # Sort: regressions first (most urgent), then persistent worst-LSS, then new, then remediated.
    bucket_order = {"regressed": 0, "persistent": 1, "new": 2, "remediated": 3}
    diffs.sort(key=lambda d: (
        bucket_order[d.verdict],
        -((d.after.lss_score if d.after else d.before.lss_score) or 0.0),
    ))

    return DiffReport(
        target_name=target_name
            or after_report.target_name
            or before_report.target_name,
        before_generated_at=before_report.generated_at,
        after_generated_at=after_report.generated_at,
        diffed_at=datetime.datetime.now().isoformat(timespec="seconds"),
        findings=diffs,
        before_metadata=before_report.metadata,
        after_metadata=after_report.metadata,
    )


# ---------------------------------------------------------------- classification


def _classify(key: str, before: Finding | None, after: Finding | None) -> DiffFinding:
    if before is not None and after is not None:
        verdict = _classify_persistent_or_remediated(before, after)
        title = after.title or before.title
    elif before is not None:
        # Was real, now absent.
        verdict = "remediated" if _is_real_finding(before) else "remediated"
        title = before.title
    else:
        assert after is not None
        verdict = "new"
        title = after.title

    sev_delta = _sev_delta(before, after)
    lss_delta = _lss_delta(before, after)
    grade_change = _grade_change(before, after)

    return DiffFinding(
        verdict=verdict, id=key, title=title,
        before=before, after=after,
        severity_delta=sev_delta, lss_delta=lss_delta,
        grade_change=grade_change,
    )


def _classify_persistent_or_remediated(before: Finding, after: Finding) -> DiffVerdict:
    """When a finding exists in both runs, decide remediated/regressed/persistent."""
    before_real = _is_real_finding(before)
    after_real = _is_real_finding(after)

    if before_real and not after_real:
        return "remediated"
    if not before_real and after_real:
        return "regressed"
    return "persistent"


def _is_real_finding(f: Finding) -> bool:
    """A finding 'counts' as a hit when it represents at-least-medium impact.

    Catalog probes record ``severity='low'`` even on clean refusals (the
    severity is the probe's *potential* not its observed outcome). To
    avoid counting clean refusals as real findings, we also require either
    a non-A refusal grade *or* a non-zero LSS score.
    """
    if f.severity in ("critical", "high"):
        return True
    if f.severity == "medium":
        return True
    if f.lss_score and f.lss_score > 0:
        return True
    if f.refusal_grade and f.refusal_grade not in ("A", "B"):
        return True
    return False


def _sev_delta(before: Finding | None, after: Finding | None) -> int:
    b = _SEVERITY_RANK.get(before.severity if before else None, 0)
    a = _SEVERITY_RANK.get(after.severity if after else None, 0)
    return a - b


def _lss_delta(before: Finding | None, after: Finding | None) -> float:
    b = (before.lss_score if before and before.lss_score else 0.0)
    a = (after.lss_score if after and after.lss_score else 0.0)
    return round(a - b, 3)


def _grade_change(before: Finding | None, after: Finding | None) -> str | None:
    b = before.refusal_grade if before else None
    a = after.refusal_grade if after else None
    if not b and not a:
        return None
    return f"{b or '-'}->{a or '-'}"


# ---------------------------------------------------------------- matching key


def _match_key(f: Finding) -> str:
    """Stable id used to align findings across runs.

    Prefers probe id (set by catalog runner / climbed-probe save); falls
    back to ``(coordinate, sha1(prompt[:200]))`` for chatbot-attack
    outputs that don't have probe ids.
    """
    if f.id and not f.id.startswith(("subFlow=", "F0")):
        return f.id
    coord = f.coordinate or "_"
    seed = (f.attack_prompt or f.title or f.id or "")[:200]
    digest = hashlib.sha1(seed.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"{coord}#{digest}"


def _finding_to_dict(f: Finding | None) -> dict[str, Any] | None:
    if f is None:
        return None
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "lss_score": f.lss_score,
        "refusal_grade": f.refusal_grade,
        "coordinate": f.coordinate,
        "owasp_tags": list(f.owasp_tags),
    }


# ---------------------------------------------------------------- render


def render_diff_markdown(report: DiffReport) -> str:
    counts = report.counts
    lines: list[str] = []
    lines.append("# LMTWT Engagement Diff Report")
    lines.append("")
    lines.append(f"**Target:** {report.target_name}  ")
    lines.append(f"**Before:** {report.before_generated_at}  ")
    lines.append(f"**After:** {report.after_generated_at}  ")
    lines.append(f"**Diffed:** {report.diffed_at}")
    lines.append("")

    lines.append("## Headline")
    lines.append("")
    lines.append("| Verdict | Count |")
    lines.append("|---|---:|")
    for v in ("remediated", "regressed", "persistent", "new"):
        lines.append(f"| {v} | {counts[v]} |")
    lines.append("")
    lines.append(
        f"**Max LSS regression (Δ):** {report.max_lss_delta:+.2f}  "
        f"**Best remediation (Δ):** {report.min_lss_delta:+.2f}"
    )
    lines.append("")

    for verdict, heading in (
        ("regressed", "Regressions (highest priority — investigate first)"),
        ("new", "New findings"),
        ("persistent", "Persistent findings"),
        ("remediated", "Remediated findings"),
    ):
        bucket = [f for f in report.findings if f.verdict == verdict]
        lines.append(f"## {heading}")
        lines.append("")
        if not bucket:
            lines.append("_None._")
            lines.append("")
            continue
        lines.append("| # | Δ Sev | Δ LSS | Grade | Title |")
        lines.append("|---:|---:|---:|---|---|")
        for i, f in enumerate(bucket, start=1):
            lines.append(
                f"| {i} | {f.severity_delta:+d} | {f.lss_delta:+.2f} | "
                f"{f.grade_change or '-'} | {f.title} |"
            )
        lines.append("")

    return "\n".join(lines)


def diff_to_dict(report: DiffReport) -> dict[str, Any]:
    """JSON-serializable form, useful for CI artifacts."""
    return {
        "target_name": report.target_name,
        "before_generated_at": report.before_generated_at,
        "after_generated_at": report.after_generated_at,
        "diffed_at": report.diffed_at,
        "counts": report.counts,
        "max_lss_delta": report.max_lss_delta,
        "min_lss_delta": report.min_lss_delta,
        "findings": [f.to_dict() for f in report.findings],
    }
