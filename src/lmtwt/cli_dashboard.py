"""Live TUI dashboard for catalog runs.

Optional observer that renders run progress with a Rich ``Live`` panel:
status header (target / elapsed / in-flight), severity histogram, and a
scrolling tail of recent outcomes.

Plugged into ``AsyncCatalogProbe`` via the ``CatalogObserver`` protocol.
The runner doesn't know about Rich — the dashboard is one observer
among many; non-TTY runs (CI, log shippers) just don't enable it.
"""

from __future__ import annotations

import time
from collections import deque
from typing import TYPE_CHECKING

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from .attacks.catalog_probe import CatalogSummary, ProbeOutcome
    from .probes.schema import Probe


class RichDashboardObserver:
    """Live Rich-based progress panel for ``AsyncCatalogProbe``.

    Use as an async context manager so the ``Live`` instance is started
    and stopped cleanly even if the run raises::

        async with RichDashboardObserver("gpt-4o") as dash:
            await runner.run(observers=[dash])  # or pass via constructor
    """

    def __init__(
        self,
        target_name: str,
        *,
        console: Console | None = None,
        recent_size: int = 10,
        refresh_per_second: int = 4,
    ) -> None:
        self.target_name = target_name
        self.console = console or Console()
        self.recent: deque[tuple[str, str, str, float | None]] = deque(maxlen=recent_size)
        self.refresh_per_second = refresh_per_second

        self._total = 0
        self._completed = 0
        self._in_flight = 0
        self._sev_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        }
        self._max_lss = 0.0
        self._started_at: float | None = None
        self._live: Live | None = None

    # ------------------------------------------------------------ context

    async def __aenter__(self) -> "RichDashboardObserver":
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=self.refresh_per_second,
            transient=False,
        )
        self._live.__enter__()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._live is not None:
            self._live.__exit__(exc_type, exc, tb)
            self._live = None

    # ------------------------------------------------------------ observer hooks

    async def on_run_started(self, total: int) -> None:
        self._total = total
        self._started_at = time.monotonic()
        self._refresh()

    async def on_probe_started(self, probe: "Probe") -> None:
        del probe
        self._in_flight += 1
        self._refresh()

    async def on_probe_completed(self, outcome: "ProbeOutcome") -> None:
        self._completed += 1
        self._in_flight = max(0, self._in_flight - 1)
        if outcome.result.success:
            sev = outcome.severity if outcome.severity in self._sev_counts else "low"
            self._sev_counts[sev] += 1
            if outcome.lss and outcome.lss.score > self._max_lss:
                self._max_lss = outcome.lss.score
        mark = "[green]✓[/green]" if outcome.result.success else "[dim]✗[/dim]"
        lss_score = outcome.lss.score if outcome.lss else None
        self.recent.appendleft((mark, outcome.severity, outcome.probe_id, lss_score))
        self._refresh()

    async def on_run_finished(self, summary: "CatalogSummary") -> None:
        del summary
        self._in_flight = 0
        self._refresh()

    # ------------------------------------------------------------ render

    def _refresh(self) -> None:
        if self._live is None:
            return
        self._live.update(self._render())

    def _render(self) -> Group:
        return Group(self._header_panel(), self._severity_panel(), self._recent_panel())

    def _header_panel(self) -> Panel:
        elapsed = (
            f"{time.monotonic() - self._started_at:.1f}s"
            if self._started_at is not None
            else "—"
        )
        progress = f"{self._completed}/{self._total}"
        body = Text.from_markup(
            f"[bold]Target:[/bold] {self.target_name}    "
            f"[bold]Progress:[/bold] {progress}    "
            f"[bold]In-flight:[/bold] {self._in_flight}    "
            f"[bold]Elapsed:[/bold] {elapsed}    "
            f"[bold]Max LSS:[/bold] {self._max_lss:.2f}"
        )
        return Panel(body, title="LMTWT Probe Run", border_style="blue")

    def _severity_panel(self) -> Panel:
        table = Table.grid(padding=(0, 2))
        table.add_column(justify="right")
        table.add_column(justify="left")
        for sev, label_color in (
            ("critical", "red"), ("high", "yellow"),
            ("medium", "cyan"), ("low", "dim"),
        ):
            table.add_row(
                Text(sev, style=f"bold {label_color}"),
                Text(str(self._sev_counts[sev])),
            )
        return Panel(table, title="Successful by severity", border_style="magenta")

    def _recent_panel(self) -> Panel:
        body: Table | Text
        if not self.recent:
            body = Text("No completed probes yet.", style="dim")
        else:
            table = Table.grid(padding=(0, 1))
            table.add_column()
            table.add_column()
            table.add_column()
            table.add_column(justify="right")
            for mark, severity, probe_id, lss in self.recent:
                lss_str = f"LSS={lss:.2f}" if lss else ""
                table.add_row(
                    Text.from_markup(mark),
                    Text(f"[{severity}]"),
                    Text(probe_id),
                    Text(lss_str, style="bold"),
                )
            body = table
        return Panel(body, title="Recent outcomes", border_style="green")
