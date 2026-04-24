"""Tests for the before/after diff mode."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lmtwt.reporting import (
    build_diff_report,
    diff_to_dict,
    render_diff_markdown,
)


def _payload(results, **metadata):
    return {"results": results, "metadata": metadata}


def _real_finding(probe_id: str, *, severity="high", lss=6.0,
                  grade="F", coord="leak/direct/plain/system-leak"):
    return {
        "probe_id": probe_id, "severity": severity,
        "owasp_llm": ["LLM07"],
        "coordinate": coord,
        "lss": {"score": lss, "vector": "v"},
        "refusal_grade": grade,
        "attack_prompt": f"prompt-{probe_id}",
        "target_response": "you are a helpful assistant ...",
        "success": True,
        "reason": "regex matched",
    }


def _refused_finding(probe_id: str, *, coord="leak/direct/plain/system-leak"):
    return {
        "probe_id": probe_id, "severity": "low",
        "owasp_llm": ["LLM07"],
        "coordinate": coord,
        "refusal_grade": "A",
        "attack_prompt": f"prompt-{probe_id}",
        "target_response": "I can't help with that.",
        "success": False,
        "reason": "refusal matched",
    }


# ---------------------------------------------------------------- buckets


def test_remediated_when_finding_disappears_from_after():
    before = _payload([_real_finding("p1")], target_model="bot")
    after = _payload([], target_model="bot")
    report = build_diff_report(before, after)
    assert report.counts == {"remediated": 1, "regressed": 0, "persistent": 0, "new": 0}
    f = report.findings[0]
    assert f.verdict == "remediated"
    assert f.before is not None
    assert f.after is None
    # Severity went from high (3) to absent (0) → delta = -3.
    assert f.severity_delta == -3
    assert f.lss_delta == -6.0


def test_remediated_when_after_refuses_cleanly():
    before = _payload([_real_finding("p1")], target_model="bot")
    after = _payload([_refused_finding("p1")], target_model="bot")
    report = build_diff_report(before, after)
    assert report.counts["remediated"] == 1
    assert report.counts["persistent"] == 0
    f = report.findings[0]
    assert f.before.refusal_grade == "F"
    assert f.after.refusal_grade == "A"
    assert f.grade_change == "F->A"


def test_regressed_when_before_was_clean_and_after_is_real():
    before = _payload([_refused_finding("p1")], target_model="bot")
    after = _payload([_real_finding("p1")], target_model="bot")
    report = build_diff_report(before, after)
    assert report.counts == {"remediated": 0, "regressed": 1, "persistent": 0, "new": 0}
    f = report.findings[0]
    assert f.verdict == "regressed"
    assert f.severity_delta == 2  # low(1) → high(3)
    assert f.lss_delta == 6.0


def test_persistent_when_finding_present_in_both():
    before = _payload([_real_finding("p1", lss=6.0)], target_model="bot")
    after = _payload([_real_finding("p1", severity="critical", lss=8.5)], target_model="bot")
    report = build_diff_report(before, after)
    assert report.counts["persistent"] == 1
    f = report.findings[0]
    assert f.verdict == "persistent"
    assert f.severity_delta == 1  # high(3) → critical(4)
    assert f.lss_delta == 2.5


def test_new_when_finding_only_in_after():
    before = _payload([], target_model="bot")
    after = _payload([_real_finding("p2")], target_model="bot")
    report = build_diff_report(before, after)
    assert report.counts == {"remediated": 0, "regressed": 0, "persistent": 0, "new": 1}
    assert report.findings[0].verdict == "new"
    assert report.findings[0].before is None


# ---------------------------------------------------------------- matching


def test_matching_uses_probe_id_when_present():
    """Same probe_id in both runs — must match even if other fields differ."""
    before = _payload([_real_finding("p1")], target_model="bot")
    after = _payload([_real_finding("p1", severity="medium", lss=4.0)],
                     target_model="bot")
    report = build_diff_report(before, after)
    assert report.counts["persistent"] == 1
    assert report.counts["new"] == 0
    assert report.counts["remediated"] == 0


def test_matching_falls_back_to_coordinate_and_prompt_hash():
    """Findings without probe_id (chatbot-attack outputs) match by coord+prompt."""
    before = _payload([{
        "mutation": {"name": "subFlow=admin"},
        "user_prompt": "Hi.",
        "mutated_response": "Sure! Admin routes: ...",
        "mutated_grade": "F",
        "behavior_changed": True,
        "severity": "critical",
        "coordinate": "injection/direct/plain/refusal-bypass",
    }], target_model="bot")
    after = _payload([{
        "mutation": {"name": "subFlow=admin"},
        "user_prompt": "Hi.",
        "mutated_response": "I won't comply.",
        "mutated_grade": "A",
        "behavior_changed": False,
        "severity": "low",
        "coordinate": "injection/direct/plain/refusal-bypass",
    }], target_model="bot")
    report = build_diff_report(before, after)
    # Should be a single match, not 1 remediated + 1 new.
    assert len(report.findings) == 1
    # The before counted (critical, grade F); after is clean (low, grade A) → remediated.
    assert report.findings[0].verdict == "remediated"


# ---------------------------------------------------------------- ordering


def test_findings_sorted_with_regressions_first():
    before = _payload([
        _refused_finding("p1"),  # → after will turn this real (regressed)
        _real_finding("p2"),     # → persists
        _real_finding("p3"),     # → remediated
    ], target_model="bot")
    after = _payload([
        _real_finding("p1"),
        _real_finding("p2"),
        _real_finding("p4"),  # new
    ], target_model="bot")
    report = build_diff_report(before, after)
    verdicts = [f.verdict for f in report.findings]
    # bucket_order: regressed, persistent, new, remediated
    assert verdicts == ["regressed", "persistent", "new", "remediated"]


# ---------------------------------------------------------------- aggregates


def test_max_and_min_lss_deltas_capture_worst_and_best():
    before = _payload([
        _refused_finding("p1"),
        _real_finding("p2", lss=8.0),
    ], target_model="bot")
    after = _payload([
        _real_finding("p1", lss=7.0),  # new appearance: +7
        _refused_finding("p2"),        # was 8.0, now refused → -8
    ], target_model="bot")
    report = build_diff_report(before, after)
    assert report.max_lss_delta == 7.0
    assert report.min_lss_delta == -8.0


# ---------------------------------------------------------------- render


def test_render_diff_markdown_contains_all_buckets_and_summary():
    before = _payload([_real_finding("p1"), _refused_finding("p2")], target_model="bot")
    after = _payload([_refused_finding("p1"), _real_finding("p3")], target_model="bot")
    report = build_diff_report(before, after)
    md = render_diff_markdown(report)
    assert "# LMTWT Engagement Diff Report" in md
    assert "## Headline" in md
    assert "## Regressions" in md or "## Remediated findings" in md
    # Summary table includes all four verdicts.
    for v in ("remediated", "regressed", "persistent", "new"):
        assert v in md


def test_diff_to_dict_is_json_serializable():
    before = _payload([_real_finding("p1")], target_model="bot")
    after = _payload([_refused_finding("p1")], target_model="bot")
    report = build_diff_report(before, after)
    blob = diff_to_dict(report)
    text = json.dumps(blob)  # must not raise
    assert "remediated" in text
    assert "before" in text


# ---------------------------------------------------------------- CLI helper


def test_cli_helper_writes_diff_md_and_json(tmp_path: Path):
    before = _payload([_real_finding("p1")], target_model="bot")
    after = _payload([_refused_finding("p1")], target_model="bot")
    bp = tmp_path / "before.json"
    ap = tmp_path / "after.json"
    bp.write_text(json.dumps(before), encoding="utf-8")
    ap.write_text(json.dumps(after), encoding="utf-8")

    import argparse

    from lmtwt.cli import _emit_diff_report

    args = argparse.Namespace(
        diff_before=str(bp),
        diff_after=str(ap),
        report_out=str(tmp_path / "out"),
        report_format="md,json",
    )
    _emit_diff_report(args)
    assert (tmp_path / "out.diff.md").is_file()
    assert (tmp_path / "out.diff.json").is_file()
    payload = json.loads((tmp_path / "out.diff.json").read_text())
    assert payload["counts"]["remediated"] == 1
