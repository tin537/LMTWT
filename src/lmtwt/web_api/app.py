"""FastAPI app factory + routes.

Endpoints (MVP):
- ``GET  /``                          — single-page UI (static HTML)
- ``GET  /api/probes``                — list catalog probes
- ``GET  /api/runs``                  — list persisted runs
- ``GET  /api/runs/{id}``             — load a single persisted run
- ``POST /api/runs``                  — start a new run, returns ``{run_id}``
- ``GET  /api/runs/{id}/events``      — SSE stream of outcomes for an active run

Auth: none. This is a single-user pentest tool — assume it runs on the
operator's laptop or behind their existing auth proxy.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from ..attacks.catalog_probe import AsyncCatalogProbe
from ..models.async_factory import async_get_model
from ..persistence import SQLiteObserver, list_runs, load_run_outcomes
from ..probes import load_corpus
from .broadcast import BroadcastObserver, is_end_sentinel

DEFAULT_DB_PATH = "lmtwt.db"


class _StartRunRequest(BaseModel):
    """Body shape for POST /api/runs."""

    target: str = "openai"
    target_model: str | None = None
    coordinate: str | None = None
    severity: str | None = None
    repeats: int = 1
    concurrency: int = 1
    persist: bool = True


class _ActiveRun:
    """In-memory bookkeeping for a run started via POST /api/runs."""

    def __init__(
        self,
        run_id: int,
        broadcaster: BroadcastObserver,
        task: asyncio.Task,
    ) -> None:
        self.run_id = run_id
        self.broadcaster = broadcaster
        self.task = task


def create_app(
    *,
    db_path: str | os.PathLike[str] = DEFAULT_DB_PATH,
    static_dir: Path | None = None,
) -> FastAPI:
    """Build the FastAPI app. ``db_path`` shared with the CLI persistence layer."""
    app = FastAPI(title="LMTWT Web API", version="1.0")
    static = Path(static_dir) if static_dir else Path(__file__).parent / "static"
    db = str(db_path)
    active: dict[int, _ActiveRun] = {}

    @app.get("/", include_in_schema=False)
    async def root() -> FileResponse:
        index = static / "index.html"
        if not index.is_file():
            raise HTTPException(404, "index.html not bundled")
        return FileResponse(index)

    @app.get("/api/probes")
    async def api_probes(
        coordinate: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        sev = [s.strip() for s in severity.split(",")] if severity else None
        try:
            corpus = load_corpus(coordinate_filter=coordinate, severity_filter=sev)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return [
            {
                "id": p.id,
                "name": p.name,
                "coordinate": p.coordinate,
                "severity": p.severity,
                "owasp_llm": list(p.owasp_llm),
            }
            for p in corpus
        ]

    @app.get("/api/runs")
    async def api_runs() -> list[dict[str, Any]]:
        if not Path(db).is_file():
            return []
        return [
            {
                "id": r.id, "started_at": r.started_at, "finished_at": r.finished_at,
                "target_name": r.target_name, "mode": r.mode,
                "total_probes": r.total_probes, "completed": r.completed,
                "successes": r.successes, "status": r.status,
            }
            for r in list_runs(db)
        ]

    @app.get("/api/runs/{run_id}")
    async def api_run_detail(run_id: int) -> dict[str, Any]:
        try:
            return load_run_outcomes(db, run_id)
        except ValueError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/api/runs")
    async def api_start_run(req: _StartRunRequest) -> dict[str, Any]:
        sev = [s.strip() for s in req.severity.split(",")] if req.severity else None
        try:
            corpus = load_corpus(
                coordinate_filter=req.coordinate, severity_filter=sev,
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        if not corpus:
            raise HTTPException(400, "No probes matched the filter")

        # Build target — supports the same provider names as the CLI.
        target_api_key = os.getenv(f"{req.target.upper()}_API_KEY")
        try:
            target_model = async_get_model(
                req.target, api_key=target_api_key, model_name=req.target_model,
            )
        except Exception as e:  # noqa: BLE001
            raise HTTPException(400, f"target init failed: {e}") from e

        broadcaster = BroadcastObserver()
        observers: list[Any] = [broadcaster]
        sql_observer: SQLiteObserver | None = None
        if req.persist:
            sql_observer = SQLiteObserver(
                db,
                target_name=getattr(target_model, "model_name", req.target),
                attacker_name=None,
                mode="probe-catalog (web)",
                metadata={"coordinate": req.coordinate, "severity": req.severity,
                          "repeats": req.repeats},
            )
            observers.append(sql_observer)

        runner = AsyncCatalogProbe(
            target_model, probes=corpus,
            concurrency=req.concurrency, repeats=req.repeats,
            observers=observers,  # type: ignore[arg-type]  # protocol-typed list
        )

        async def _go() -> None:
            try:
                await runner.run()
            finally:
                # Allow the active-run entry to be GC'd.
                if sql_observer and sql_observer.run_id is not None:
                    active.pop(sql_observer.run_id, None)

        task = asyncio.create_task(_go())

        # If we're persisting, the SQLite run id is the canonical id; otherwise
        # we synthesize a transient id (negative, doesn't collide with sqlite ids).
        # Wait briefly for the persistence-layer id to be assigned.
        run_id: int
        if sql_observer is not None:
            for _ in range(50):
                if sql_observer.run_id is not None:
                    break
                await asyncio.sleep(0.01)
            run_id = sql_observer.run_id or -id(broadcaster)
        else:
            run_id = -id(broadcaster)

        active[run_id] = _ActiveRun(run_id, broadcaster, task)
        return {"run_id": run_id, "status": "started", "total_probes": len(corpus)}

    @app.get("/api/runs/{run_id}/events")
    async def api_run_events(run_id: int) -> EventSourceResponse:
        entry = active.get(run_id)
        if entry is None:
            raise HTTPException(404, "no active run with that id")
        broadcaster = entry.broadcaster

        async def _stream():
            queue = await broadcaster.subscribe()
            try:
                while True:
                    event = await queue.get()
                    if is_end_sentinel(event):
                        return
                    yield {"event": event["event"], "data": json.dumps(event)}
            finally:
                await broadcaster.unsubscribe(queue)

        return EventSourceResponse(_stream())

    return app


def run_server(*, host: str = "127.0.0.1", port: int = 8500,
               db_path: str = DEFAULT_DB_PATH) -> None:
    """Convenience launcher used by the CLI ``--web-api`` flag."""
    import uvicorn

    app = create_app(db_path=db_path)
    uvicorn.run(app, host=host, port=port, log_level="info")
