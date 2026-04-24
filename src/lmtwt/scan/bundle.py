"""Engagement bundle writer.

Given a ``ScanResult``, materialize the directory layout the operator
hands to a client::

    ./scan-2026-04-24-gpt-4o/
      scan.json            # canonical run output
      report.md            # engagement-grade Markdown
      report.html          # standalone HTML
      report.pdf           # if WeasyPrint installed
      scorecard.md         # severity histogram + headline (single-target form)
      repro/
        F001_<id>.json
        ...
        index.json
      fingerprint.json     # if a fingerprint step ran
      scan.db              # SQLite — same data as scan.json

Always-on by design — the operator shouldn't have to remember which
flags to combine. Missing optional outputs (e.g. PDF without WeasyPrint)
are skipped with a printed reason rather than crashing the run.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..reporting import (
    build_report,
    render_html,
    render_markdown,
    render_pdf,
    write_repro_pack,
)

if TYPE_CHECKING:
    from .orchestrator import ScanResult


def write_bundle(result: ScanResult, out_dir: Path | str) -> Path:
    """Write the full engagement bundle into ``out_dir``. Returns the path.

    Idempotent: re-runs overwrite. Non-existent ``out_dir`` is created.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    payload = result.to_run_payload()

    # 1. canonical scan.json
    (out / "scan.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default),
        encoding="utf-8",
    )

    # 2. plan.json + skipped-steps log
    plan_path = out / "plan.json"
    plan_path.write_text(
        json.dumps(_plan_to_dict(result), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # 3. fingerprint.json (if any)
    if result.fingerprint is not None:
        from dataclasses import asdict as _asdict
        (out / "fingerprint.json").write_text(
            json.dumps(_asdict(result.fingerprint), indent=2, default=str,
                       ensure_ascii=False),
            encoding="utf-8",
        )

    # 4. report.md / .html / .pdf
    report = build_report(payload, target_name=result.target_name,
                          attacker_name=result.attacker_name)
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (out / "report.html").write_text(render_html(report), encoding="utf-8")
    pdf_path = out / "report.pdf"
    try:
        render_pdf(report, pdf_path)
    except RuntimeError:
        # WeasyPrint missing — leave a marker so the operator knows why.
        (out / "report.pdf.skipped").write_text(
            "WeasyPrint not installed — PDF skipped. Install with `pip install lmtwt[report]`.",
            encoding="utf-8",
        )

    # 5. scorecard (single-target — degenerate but still useful for the headline)
    from ..reporting import build_scorecard, render_scorecard_markdown
    scorecard = build_scorecard([payload], names=[result.target_name])
    (out / "scorecard.md").write_text(
        render_scorecard_markdown(scorecard), encoding="utf-8",
    )

    # 6. per-finding repro packs
    write_repro_pack(payload, out / "repro", report=report)

    # 7. scan.db — copy from the orchestrator's working db, or initialize empty
    if result.db_path is not None and Path(result.db_path).is_file():
        if Path(result.db_path).resolve() != (out / "scan.db").resolve():
            shutil.copyfile(result.db_path, out / "scan.db")

    return out


# ---------------------------------------------------------------- helpers


def _plan_to_dict(result: ScanResult) -> dict[str, Any]:
    return {
        "depth": result.plan.depth,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "steps": [
            {
                "name": s.name,
                "enabled": s.enabled,
                "reason_if_skipped": s.reason_if_skipped,
                "kwargs": s.kwargs,
                "executed": s.name in result.executed_steps,
                "duration_seconds": result.step_durations.get(s.name),
                "outcome_count": result.step_outcome_counts.get(s.name),
                "error": result.step_errors.get(s.name),
            }
            for s in result.plan.steps
        ],
    }


def _json_default(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)
