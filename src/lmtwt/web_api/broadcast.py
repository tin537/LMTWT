"""Per-run broadcast: fan ``CatalogObserver`` events out to SSE subscribers.

One ``BroadcastObserver`` per run. Browsers (or any HTTP client) open a
GET on ``/api/runs/{run_id}/events`` to subscribe; that handler creates
a queue, registers it with the broadcaster, and yields events as they
arrive. When the run finishes, the broadcaster sends a sentinel and
each subscriber's stream completes naturally.

Multiple subscribers per run: each gets its own queue, so a slow client
can't backpressure others.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..attacks.catalog_probe import CatalogSummary, ProbeOutcome
    from ..probes.schema import Probe


_END_SENTINEL = {"event": "__end__"}


class BroadcastObserver:
    """``CatalogObserver`` that pushes JSON-serializable events to N async queues."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[dict[str, Any]]] = []
        self._lock = asyncio.Lock()
        self._finished = False
        self._summary_event: dict[str, Any] | None = None

    async def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """Register a new subscriber queue. Includes the final summary if late."""
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        async with self._lock:
            if self._finished:
                # Late subscriber — replay the summary sentinel so they see *something*.
                if self._summary_event is not None:
                    await q.put(self._summary_event)
                await q.put(_END_SENTINEL)
            else:
                self._subscribers.append(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    async def _broadcast(self, event: dict[str, Any]) -> None:
        async with self._lock:
            for q in list(self._subscribers):
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    # Subscriber's queue overflowed — drop them rather than block.
                    self._subscribers.remove(q)

    # ------------------------------------------------------------ observer hooks

    async def on_run_started(self, total: int) -> None:
        await self._broadcast({"event": "run_started", "total": total})

    async def on_probe_started(self, probe: "Probe") -> None:
        await self._broadcast({
            "event": "probe_started",
            "probe_id": probe.id,
            "coordinate": probe.coordinate,
            "severity": probe.severity,
        })

    async def on_probe_completed(self, outcome: "ProbeOutcome") -> None:
        from ..attacks.catalog_probe import _outcome_to_dict
        await self._broadcast({
            "event": "probe_completed",
            "outcome": _outcome_to_dict(outcome),
        })

    async def on_run_finished(self, summary: "CatalogSummary") -> None:
        summary_event = {
            "event": "run_finished",
            "total": summary.total,
            "executed": summary.executed,
            "successes": summary.successes,
            "errors": summary.errors,
            "max_lss": summary.max_lss,
            "by_severity": summary.by_severity,
            "by_refusal_grade": summary.by_refusal_grade,
        }
        async with self._lock:
            self._finished = True
            self._summary_event = summary_event
            for q in self._subscribers:
                try:
                    q.put_nowait(summary_event)
                    q.put_nowait(_END_SENTINEL)
                except asyncio.QueueFull:
                    pass


def is_end_sentinel(event: dict[str, Any]) -> bool:
    return event.get("event") == "__end__"
