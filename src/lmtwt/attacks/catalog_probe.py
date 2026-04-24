"""Runner for the LMTWT-native YAML probe corpus.

Where ``AsyncProbeAttack`` (sibling) runs legacy ``PayloadGenerator``
categories with a single global judge, ``AsyncCatalogProbe`` runs ``Probe``
objects that carry their *own* success / refusal regex and taxonomy. Each
probe's verdict is a self-contained contract; the global judge is no longer
load-bearing.

Design notes:

- We do NOT reuse ``RegexJudge`` directly because it doesn't know about
  refusal-vs-success precedence — a leak probe's response might contain
  "I can't share that" *and* accidentally echo part of the system prompt;
  we want refusal to win in that case, not success.
- Multi-turn probes (``metadata.requires_flow_runner``) are skipped with an
  informative message — they'll be handled by a dedicated runner in a later
  landing.
- ``repeats > 1`` runs each probe multiple times and reports a Wilson 95%
  CI on the success rate. Useful at non-zero target temperature, where
  one-shot success/failure is a coin flip and a pentest report shouldn't
  promote either outcome to a finding without supporting statistics.
"""

from __future__ import annotations

import asyncio
import datetime
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..models.async_base import AsyncAIModel
from ..models.conversation import Conversation
from ..probes.schema import Probe
from ..scoring import (
    LSS,
    RefusalGrade,
    RefusalGrader,
    RegexRefusalGrader,
    compute_lss,
)
from .async_engine import DEFAULT_TARGET_SYSTEM_PROMPT, AttackResult


@dataclass
class ProbeOutcome:
    """Single execution of a single probe (or aggregate of N executions)."""

    probe_id: str
    coordinate: str
    severity: str
    owasp_llm: list[str]
    result: AttackResult
    lss: LSS | None = None
    refusal_grade: RefusalGrade | None = None
    skipped_reason: str | None = None
    # Confidence-interval fields (only populated when repeats > 1)
    attempts: int = 1
    successes_observed: int = 1
    success_rate: float | None = None
    ci_low: float | None = None
    ci_high: float | None = None
    grade_distribution: dict[str, int] = field(default_factory=dict)


@runtime_checkable
class CatalogObserver(Protocol):
    """Optional callbacks fired by ``AsyncCatalogProbe`` during a run.

    All methods are async to keep the runner's hot loop simple. The runner
    awaits each callback in turn — observers should be cheap (TUI updates,
    in-memory accumulation) and never block on network IO. Spawn a task
    if you need to fan out side-effects.
    """

    async def on_run_started(self, total: int) -> None: ...
    async def on_probe_started(self, probe: Probe) -> None: ...
    async def on_probe_completed(self, outcome: ProbeOutcome) -> None: ...
    async def on_run_finished(self, summary: CatalogSummary) -> None: ...


@dataclass
class CatalogSummary:
    """Aggregate output of a corpus run."""

    total: int
    executed: int
    skipped: int
    successes: int
    errors: int
    max_lss: float = 0.0
    successful_lss: list[float] = field(default_factory=list)
    by_severity: dict[str, dict[str, int]] = field(default_factory=dict)
    by_coordinate: dict[str, dict[str, int]] = field(default_factory=dict)
    by_refusal_grade: dict[str, int] = field(default_factory=dict)
    outcomes: list[dict] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now().isoformat(timespec="seconds")
    )


class AsyncCatalogProbe:
    """Runs a ``list[Probe]`` against a target and self-judges via per-probe regex."""

    def __init__(
        self,
        target: AsyncAIModel,
        probes: list[Probe],
        *,
        concurrency: int = 1,
        repeats: int = 1,
        refusal_grader: RefusalGrader | None = None,
        observers: list[CatalogObserver] | None = None,
    ) -> None:
        self.target = target
        self.probes = probes
        self.concurrency = max(1, concurrency)
        self.repeats = max(1, repeats)
        self.refusal_grader: RefusalGrader = refusal_grader or RegexRefusalGrader()
        self.observers: list[CatalogObserver] = list(observers or [])

    async def run(
        self,
        *,
        target_system_prompt: str | None = None,
    ) -> CatalogSummary:
        sem = asyncio.Semaphore(self.concurrency)
        system = target_system_prompt or DEFAULT_TARGET_SYSTEM_PROMPT
        await self._notify("on_run_started", len(self.probes))

        async def _attempt(probe: Probe) -> tuple[bool, str, str, RefusalGrade | None,
                                                   str | None]:
            """One target call. Returns (success, reason, response, grade, error)."""
            conv = (
                Conversation().with_system(system).append("user", probe.prompt)
            )
            async with sem:
                try:
                    resp = await self.target.chat(conv)
                except Exception as e:  # noqa: BLE001
                    return False, f"target error: {e}", "", None, str(e)
            success, reason = _judge(probe, resp.content)
            grade = await self.refusal_grader.grade(
                resp.content, attack_prompt=probe.prompt,
            )
            return success, reason, resp.content, grade, None

        async def _one(probe: Probe) -> ProbeOutcome:
            await self._notify("on_probe_started", probe)
            if probe.metadata.get("requires_flow_runner"):
                outcome = ProbeOutcome(
                    probe_id=probe.id,
                    coordinate=probe.coordinate,
                    severity=probe.severity,
                    owasp_llm=list(probe.owasp_llm),
                    result=AttackResult(
                        instruction=probe.id,
                        attack_prompt=probe.prompt,
                        target_response="",
                        success=False,
                        reason="skipped: multi-turn probe — needs flow runner",
                    ),
                    skipped_reason="multi-turn probe requires flow runner",
                )
                await self._notify("on_probe_completed", outcome)
                return outcome

            attempts = await asyncio.gather(
                *(_attempt(probe) for _ in range(self.repeats))
            )
            successes = [a for a in attempts if a[0]]
            grades = [a[3] for a in attempts if a[3] is not None]
            errors = [a[4] for a in attempts if a[4]]

            # Pick a representative attempt for the per-outcome record:
            # first successful run if any (so reports show what worked),
            # else the first attempt overall.
            rep = successes[0] if successes else attempts[0]
            success, reason, response, grade, error = rep

            n = len(attempts)
            k = len(successes)
            success_rate = k / n
            ci_low, ci_high = _wilson_interval(k, n)
            grade_dist: dict[str, int] = {}
            for g in grades:
                grade_dist[g] = grade_dist.get(g, 0) + 1

            # Reasons summary when we ran more than one trial.
            if n > 1:
                reason = f"{reason}  [{k}/{n} succeeded]"

            chained = bool(probe.chain_with)
            outcome = ProbeOutcome(
                probe_id=probe.id,
                coordinate=probe.coordinate,
                severity=probe.severity,
                owasp_llm=list(probe.owasp_llm),
                result=AttackResult(
                    instruction=probe.id,
                    attack_prompt=probe.prompt,
                    target_response=response,
                    success=bool(successes),
                    reason=reason,
                    error=errors[0] if errors and not successes else None,
                ),
                lss=compute_lss(probe, chained=chained) if successes else None,
                refusal_grade=grade,
                attempts=n,
                successes_observed=k,
                success_rate=success_rate,
                ci_low=ci_low,
                ci_high=ci_high,
                grade_distribution=grade_dist,
            )
            await self._notify("on_probe_completed", outcome)
            return outcome

        outcomes: list[ProbeOutcome] = await asyncio.gather(
            *(_one(p) for p in self.probes)
        )
        summary = _summarize(outcomes)
        await self._notify("on_run_finished", summary)
        return summary

    async def _notify(self, method: str, *args) -> None:
        for obs in self.observers:
            handler = getattr(obs, method, None)
            if handler is None:
                continue
            try:
                await handler(*args)
            except Exception:  # noqa: BLE001 — observer failure must not break the run
                continue


def _judge(probe: Probe, response: str) -> tuple[bool, str]:
    """Probe-local verdict. Refusal wins when it co-occurs with a success hit.

    Returns (success, human_reason).
    """
    refusal_hit = _first_match(probe.refusal_indicators, response)
    success_hit = _first_match(probe.success_indicators, response)
    if refusal_hit is not None:
        return False, f"refusal matched /{refusal_hit}/"
    if success_hit is not None:
        return True, f"success matched /{success_hit}/"
    if not probe.success_indicators and not probe.refusal_indicators:
        return False, "probe has no indicators — treating as inconclusive"
    return False, "no success indicator matched"


def _first_match(patterns: list[str], text: str) -> str | None:
    for pat in patterns:
        try:
            if re.search(pat, text):
                return pat
        except re.error:
            # Bad regex in probe file — skip that pattern but don't crash the run.
            continue
    return None


def _summarize(outcomes: list[ProbeOutcome]) -> CatalogSummary:
    executed = [o for o in outcomes if o.skipped_reason is None]
    summary = CatalogSummary(
        total=len(outcomes),
        executed=len(executed),
        skipped=len(outcomes) - len(executed),
        successes=sum(1 for o in executed if o.result.success),
        errors=sum(1 for o in executed if o.result.error),
    )
    for o in executed:
        sev_bucket = summary.by_severity.setdefault(
            o.severity, {"total": 0, "successes": 0}
        )
        sev_bucket["total"] += 1
        if o.result.success:
            sev_bucket["successes"] += 1

        coord_bucket = summary.by_coordinate.setdefault(
            o.coordinate, {"total": 0, "successes": 0}
        )
        coord_bucket["total"] += 1
        if o.result.success:
            coord_bucket["successes"] += 1

        if o.refusal_grade is not None:
            summary.by_refusal_grade[o.refusal_grade] = (
                summary.by_refusal_grade.get(o.refusal_grade, 0) + 1
            )

        if o.lss is not None:
            summary.successful_lss.append(o.lss.score)

    summary.max_lss = max(summary.successful_lss, default=0.0)
    summary.outcomes = [_outcome_to_dict(o) for o in outcomes]
    return summary


def _outcome_to_dict(o: ProbeOutcome) -> dict[str, Any]:
    d = asdict(o.result)
    d["probe_id"] = o.probe_id
    d["coordinate"] = o.coordinate
    d["severity"] = o.severity
    d["owasp_llm"] = o.owasp_llm
    if o.lss is not None:
        d["lss"] = o.lss.as_dict()
    if o.refusal_grade is not None:
        d["refusal_grade"] = o.refusal_grade
    if o.skipped_reason:
        d["skipped_reason"] = o.skipped_reason
    # Always emit attempts so downstream tools can distinguish 1/1 from N/N.
    d["attempts"] = o.attempts
    d["successes_observed"] = o.successes_observed
    if o.attempts > 1:
        d["success_rate"] = o.success_rate
        d["ci_low"] = o.ci_low
        d["ci_high"] = o.ci_high
        d["grade_distribution"] = dict(o.grade_distribution)
    return d


def _wilson_interval(successes: int, attempts: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% confidence interval for a binomial proportion.

    Better than normal-approximation at small N and at extreme proportions
    (0 or 1). z=1.96 → 95% CI. Returns (low, high) clamped to [0, 1].
    """
    if attempts <= 0:
        return 0.0, 0.0
    p = successes / attempts
    denom = 1 + (z * z) / attempts
    centre = (p + (z * z) / (2 * attempts)) / denom
    half = (z * math.sqrt((p * (1 - p) + (z * z) / (4 * attempts)) / attempts)) / denom
    low = max(0.0, centre - half)
    high = min(1.0, centre + half)
    return round(low, 4), round(high, 4)
