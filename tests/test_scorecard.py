"""Tests for the multi-target scorecard."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lmtwt.reporting import (
    build_scorecard,
    render_scorecard_markdown,
    scorecard_to_dict,
)


def _payload(results, **metadata):
    return {"results": results, "metadata": metadata}


def _real(probe_id, *, severity="high", lss=6.0, grade="F"):
    return {
        "probe_id": probe_id, "severity": severity,
        "owasp_llm": ["LLM07"],
        "coordinate": "leak/direct/plain/system-leak",
        "lss": {"score": lss, "vector": "v"},
        "refusal_grade": grade,
        "attack_prompt": f"prompt-{probe_id}",
        "target_response": "you are a helpful assistant",
        "success": True,
        "reason": "regex matched",
    }


def _refused(probe_id):
    return {
        "probe_id": probe_id, "severity": "low",
        "owasp_llm": ["LLM07"],
        "coordinate": "leak/direct/plain/system-leak",
        "refusal_grade": "A",
        "attack_prompt": f"prompt-{probe_id}",
        "target_response": "I can't help.",
        "success": False,
    }


# ---------------------------------------------------------------- shape


def test_build_scorecard_unions_findings_across_targets():
    a = _payload([_real("p1"), _real("p2")], target_model="gpt-4o")
    b = _payload([_real("p1"), _real("p3")], target_model="claude-opus")
    sc = build_scorecard([a, b])
    keys = {row.key for row in sc.rows}
    assert keys == {"p1", "p2", "p3"}
    assert sc.target_names == ["gpt-4o", "claude-opus"]


def test_build_scorecard_uses_provided_names_over_metadata():
    a = _payload([_real("p1")], target_model="gpt-4o")
    b = _payload([_real("p2")], target_model="claude-opus")
    sc = build_scorecard([a, b], names=["Vendor A", "Vendor B"])
    assert sc.target_names == ["Vendor A", "Vendor B"]


def test_build_scorecard_validates_names_length():
    a = _payload([_real("p1")], target_model="gpt-4o")
    with pytest.raises(ValueError):
        build_scorecard([a], names=["A", "B"])


def test_build_scorecard_requires_at_least_one_payload():
    with pytest.raises(ValueError):
        build_scorecard([])


def test_cells_align_with_target_columns():
    """Each row must have exactly one cell per target, in the same order."""
    a = _payload([_real("p1")], target_model="bot-A")
    b = _payload([_real("p2")], target_model="bot-B")
    c = _payload([_real("p1"), _real("p2")], target_model="bot-C")
    sc = build_scorecard([a, b, c])
    for row in sc.rows:
        assert len(row.cells) == 3
    # p1 row: present in A and C, absent in B.
    p1 = next(r for r in sc.rows if r.key == "p1")
    assert p1.cells[0].is_present  # A
    assert not p1.cells[1].is_present  # B
    assert p1.cells[2].is_present  # C


# ---------------------------------------------------------------- sort


def test_rows_sorted_by_max_lss_desc():
    a = _payload([_real("low", lss=3.0), _real("high", lss=8.0)], target_model="x")
    b = _payload([_real("med", lss=5.0)], target_model="y")
    sc = build_scorecard([a, b])
    assert [r.key for r in sc.rows] == ["high", "med", "low"]


def test_rows_with_higher_hit_count_break_lss_ties():
    """Two findings at equal max-LSS — the one hitting more targets sorts first."""
    a = _payload([_real("widely-hit", lss=6.0)], target_model="x")
    b = _payload([_real("widely-hit", lss=6.0), _real("rare-hit", lss=6.0)],
                 target_model="y")
    sc = build_scorecard([a, b])
    assert sc.rows[0].key == "widely-hit"
    assert sc.rows[1].key == "rare-hit"


# ---------------------------------------------------------------- summaries


def test_per_target_summary_counts_real_vs_refused():
    a = _payload(
        [_real("p1"), _real("p2"), _refused("p3")],
        target_model="bot-A",
    )
    sc = build_scorecard([a])
    s = sc.summaries[0]
    assert s.total_findings == 3
    assert s.real_findings == 2  # p3 is a clean refusal
    assert s.severity_counts["high"] == 2
    assert s.severity_counts["low"] == 1
    assert s.max_lss == 6.0


def test_summary_max_lss_is_zero_when_all_findings_lack_lss():
    a = _payload([{"probe_id": "x", "severity": "low"}], target_model="t")
    sc = build_scorecard([a])
    assert sc.summaries[0].max_lss == 0.0


# ---------------------------------------------------------------- render


def test_render_scorecard_markdown_includes_grid_and_summary():
    a = _payload([_real("p1"), _real("p2", severity="critical", lss=9.0)],
                 target_model="gpt-4o")
    b = _payload([_real("p1"), _refused("p2")], target_model="claude")
    sc = build_scorecard([a, b])
    md = render_scorecard_markdown(sc)
    assert "# LMTWT Multi-Target Scorecard" in md
    assert "## Per-Target Summary" in md
    assert "## Findings Grid" in md
    assert "## Headline" in md
    assert "gpt-4o" in md
    assert "claude" in md
    # Cells render with severity + grade.
    assert "high" in md
    assert "critical" in md


def test_cells_render_dash_when_target_missing_finding():
    a = _payload([_real("p1")], target_model="A")
    b = _payload([], target_model="B")
    sc = build_scorecard([a, b])
    md = render_scorecard_markdown(sc)
    # Find the row line for p1; column B should be a dash.
    grid_lines = [l for l in md.splitlines() if l.startswith("| 1 |")]
    assert grid_lines, "no findings grid row found"
    assert "—" in grid_lines[0]


def test_headline_picks_worst_and_least_exposed_targets():
    a = _payload([_real("p1", lss=9.0)], target_model="weak-bot")
    b = _payload([_refused("p1")], target_model="strong-bot")
    sc = build_scorecard([a, b])
    md = render_scorecard_markdown(sc)
    assert "Most exposed" in md
    assert "weak-bot" in md
    assert "Least exposed" in md
    assert "strong-bot" in md


def test_headline_omitted_for_single_target_scorecard():
    """One-target scorecards have no meaningful 'most/least exposed' compare."""
    a = _payload([_real("p1", lss=9.0)], target_model="solo-bot")
    sc = build_scorecard([a])
    md = render_scorecard_markdown(sc)
    assert "## Headline" not in md
    assert "Most exposed" not in md


# ---------------------------------------------------------------- json export


def test_scorecard_to_dict_is_json_serializable():
    a = _payload([_real("p1")], target_model="A")
    b = _payload([_real("p2")], target_model="B")
    sc = build_scorecard([a, b])
    blob = scorecard_to_dict(sc)
    text = json.dumps(blob)  # must not raise
    assert "target_names" in text
    assert "rows" in text
    # Every row's cells list pairs target name with finding-or-null.
    assert blob["rows"][0]["cells"][0]["target"] in ("A", "B")


def test_scorecard_to_dict_marks_absent_cells_as_none():
    a = _payload([_real("p1")], target_model="A")
    b = _payload([], target_model="B")
    sc = build_scorecard([a, b])
    blob = scorecard_to_dict(sc)
    p1_row = next(r for r in blob["rows"] if r["key"] == "p1")
    a_cell = next(c for c in p1_row["cells"] if c["target"] == "A")
    b_cell = next(c for c in p1_row["cells"] if c["target"] == "B")
    assert a_cell["finding"] is not None
    assert b_cell["finding"] is None


# ---------------------------------------------------------------- chatbot-attack matching


def test_findings_without_probe_id_match_via_coordinate_and_prompt_hash():
    """Two run-output dicts with the same chatbot-attack mutation should align."""
    a = _payload([{
        "mutation": {"name": "subFlow=admin"},
        "user_prompt": "Hi.",
        "mutated_response": "Sure! Admin: ...",
        "mutated_grade": "F",
        "behavior_changed": True,
        "severity": "critical",
        "coordinate": "injection/direct/plain/refusal-bypass",
    }], target_model="A")
    b = _payload([{
        "mutation": {"name": "subFlow=admin"},
        "user_prompt": "Hi.",
        "mutated_response": "I won't.",
        "mutated_grade": "A",
        "behavior_changed": False,
        "severity": "low",
        "coordinate": "injection/direct/plain/refusal-bypass",
    }], target_model="B")
    sc = build_scorecard([a, b])
    # One row, both cells populated.
    assert len(sc.rows) == 1
    row = sc.rows[0]
    assert row.cells[0].is_present
    assert row.cells[1].is_present
    assert row.cells[0].finding.severity == "critical"
    assert row.cells[1].finding.severity == "low"


# ---------------------------------------------------------------- CLI helper


def test_cli_helper_writes_scorecard_md_and_json(tmp_path: Path):
    a = _payload([_real("p1")], target_model="A")
    b = _payload([_real("p1"), _real("p2")], target_model="B")
    ap = tmp_path / "a.json"
    bp = tmp_path / "b.json"
    ap.write_text(json.dumps(a), encoding="utf-8")
    bp.write_text(json.dumps(b), encoding="utf-8")

    import argparse

    from lmtwt.cli import _emit_scorecard_report

    args = argparse.Namespace(
        scorecard_from=[str(ap), str(bp)],
        scorecard_name=["Vendor A", "Vendor B"],
        report_out=str(tmp_path / "out"),
        report_format="md,json",
    )
    _emit_scorecard_report(args)
    assert (tmp_path / "out.scorecard.md").is_file()
    assert (tmp_path / "out.scorecard.json").is_file()
    blob = json.loads((tmp_path / "out.scorecard.json").read_text())
    assert blob["target_names"] == ["Vendor A", "Vendor B"]


def test_cli_helper_works_without_explicit_names(tmp_path: Path):
    a = _payload([_real("p1")], target_model="auto-named-A")
    ap = tmp_path / "a.json"
    ap.write_text(json.dumps(a), encoding="utf-8")

    import argparse

    from lmtwt.cli import _emit_scorecard_report

    args = argparse.Namespace(
        scorecard_from=[str(ap)],
        scorecard_name=None,
        report_out=str(tmp_path / "out"),
        report_format="md",
    )
    _emit_scorecard_report(args)
    md = (tmp_path / "out.scorecard.md").read_text()
    assert "auto-named-A" in md
