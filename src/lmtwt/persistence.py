"""SQLite persistence for catalog runs.

Streams ``CatalogObserver`` events into a SQLite ``runs``/``outcomes``
schema so a long run survives crashes, Ctrl-C, and transient API
outages. The JSON run-output files remain canonical for reports / diff /
scorecard; this is durability + post-hoc inspection.

Design choices:

- **JSON-blob columns for outcomes.** Outcome shape evolves (we just
  added Wilson CI fields in 5.2a); migrating a normalized schema each
  time is busywork. We index on ``run_id`` + ``probe_id`` (stable) and
  let the rest live in ``outcome_json``.
- **WAL mode + single connection.** Writes don't block readers; the
  observer holds one connection through the run.
- **``asyncio.to_thread`` for writes.** SQLite is sync; we don't want to
  block the event loop. The thread cost is negligible per row.
- **Reuses the ``CatalogObserver`` protocol.** Zero changes to the
  runner — observer pattern paying dividends. Multiple observers can
  coexist (the dashboard + persistence both run in parallel).
"""

from __future__ import annotations

import asyncio
import datetime
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .attacks.catalog_probe import CatalogSummary, ProbeOutcome
    from .probes.schema import Probe


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  target_name TEXT,
  attacker_name TEXT,
  mode TEXT,
  metadata_json TEXT,
  total_probes INTEGER,
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outcomes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  probe_id TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  success INTEGER NOT NULL,
  severity TEXT,
  outcome_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS outcomes_run_id ON outcomes(run_id);
CREATE INDEX IF NOT EXISTS outcomes_probe_id ON outcomes(probe_id);
"""


def _connect(db_path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path | str) -> sqlite3.Connection:
    """Open ``db_path`` and ensure the schema exists."""
    conn = _connect(db_path)
    conn.executescript(_SCHEMA)
    return conn


# ---------------------------------------------------------------- observer


class SQLiteObserver:
    """``CatalogObserver`` that streams runs+outcomes into SQLite.

    Use as a regular observer::

        obs = SQLiteObserver("./lmtwt.db", target_name="gpt-4o", mode="probe-catalog")
        await runner.run()  # runner has [obs, ...] in observers
        # obs.run_id is set after on_run_started fires

    The observer survives mid-run crashes — partial runs leave their
    ``status='in-progress'`` row and whatever outcomes were recorded
    before the crash. ``list_runs`` surfaces them; the operator can
    decide whether to retry or write them off.
    """

    def __init__(
        self,
        db_path: Path | str,
        *,
        target_name: str | None = None,
        attacker_name: str | None = None,
        mode: str = "probe-catalog",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.target_name = target_name
        self.attacker_name = attacker_name
        self.mode = mode
        self.metadata = metadata or {}
        self.run_id: int | None = None
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------ lifecycle

    async def on_run_started(self, total: int) -> None:
        def _start() -> int:
            conn = init_db(self.db_path)
            self._conn = conn
            cur = conn.execute(
                "INSERT INTO runs (started_at, target_name, attacker_name, mode, "
                "metadata_json, total_probes, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.datetime.now().isoformat(timespec="seconds"),
                    self.target_name,
                    self.attacker_name,
                    self.mode,
                    json.dumps(self.metadata, ensure_ascii=False),
                    total,
                    "in-progress",
                ),
            )
            return cur.lastrowid or 0

        self.run_id = await asyncio.to_thread(_start)

    async def on_probe_started(self, probe: Probe) -> None:
        # We record only on completion; "started" is informational.
        del probe

    async def on_probe_completed(self, outcome: ProbeOutcome) -> None:
        if self._conn is None or self.run_id is None:
            return
        # Late import avoids circular deps at module load time.
        from .attacks.catalog_probe import _outcome_to_dict

        payload = _outcome_to_dict(outcome)
        run_id = self.run_id
        conn = self._conn

        def _write() -> None:
            conn.execute(
                "INSERT INTO outcomes (run_id, probe_id, recorded_at, success, "
                "severity, outcome_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    outcome.probe_id,
                    datetime.datetime.now().isoformat(timespec="seconds"),
                    1 if outcome.result.success else 0,
                    outcome.severity,
                    json.dumps(payload, ensure_ascii=False),
                ),
            )

        await asyncio.to_thread(_write)

    async def on_run_finished(self, summary: CatalogSummary) -> None:
        del summary
        if self._conn is None or self.run_id is None:
            return
        run_id = self.run_id
        conn = self._conn

        def _finish() -> None:
            conn.execute(
                "UPDATE runs SET finished_at = ?, status = 'finished' WHERE id = ?",
                (datetime.datetime.now().isoformat(timespec="seconds"), run_id),
            )
            conn.close()

        await asyncio.to_thread(_finish)
        self._conn = None


# ---------------------------------------------------------------- read API


@dataclass
class StoredRun:
    """A row from the ``runs`` table (with derived counters)."""

    id: int
    started_at: str
    finished_at: str | None
    target_name: str | None
    attacker_name: str | None
    mode: str | None
    total_probes: int
    status: str
    successes: int
    completed: int
    metadata: dict[str, Any]


def list_runs(db_path: Path | str, *, limit: int = 50) -> list[StoredRun]:
    """Return the most recent runs (latest first), with success / completed counters."""
    conn = init_db(db_path)
    try:
        cur = conn.execute(
            "SELECT r.id, r.started_at, r.finished_at, r.target_name, "
            "  r.attacker_name, r.mode, r.metadata_json, r.total_probes, r.status, "
            "  COALESCE(SUM(o.success), 0) AS successes, "
            "  COUNT(o.id) AS completed "
            "FROM runs r LEFT JOIN outcomes o ON o.run_id = r.id "
            "GROUP BY r.id ORDER BY r.id DESC LIMIT ?",
            (limit,),
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    out: list[StoredRun] = []
    for row in rows:
        try:
            metadata = json.loads(row[6]) if row[6] else {}
        except json.JSONDecodeError:
            metadata = {}
        out.append(StoredRun(
            id=row[0], started_at=row[1], finished_at=row[2],
            target_name=row[3], attacker_name=row[4], mode=row[5],
            total_probes=row[7] or 0, status=row[8],
            successes=int(row[9] or 0), completed=int(row[10] or 0),
            metadata=metadata,
        ))
    return out


def load_run_outcomes(db_path: Path | str, run_id: int) -> dict[str, Any]:
    """Reconstruct a run-output payload (``--report-from``-compatible) from SQLite."""
    conn = init_db(db_path)
    try:
        meta_row = conn.execute(
            "SELECT target_name, attacker_name, mode, metadata_json "
            "FROM runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        if meta_row is None:
            raise ValueError(f"no run with id {run_id}")
        try:
            stored_meta = json.loads(meta_row[3]) if meta_row[3] else {}
        except json.JSONDecodeError:
            stored_meta = {}
        metadata: dict[str, Any] = {
            "target_model": meta_row[0],
            "attacker_model": meta_row[1],
            "mode": meta_row[2],
            **stored_meta,
        }

        rows = conn.execute(
            "SELECT outcome_json FROM outcomes WHERE run_id = ? ORDER BY id ASC",
            (run_id,),
        ).fetchall()
    finally:
        conn.close()

    results: list[dict[str, Any]] = []
    for (raw,) in rows:
        try:
            results.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return {"metadata": metadata, "results": results}
