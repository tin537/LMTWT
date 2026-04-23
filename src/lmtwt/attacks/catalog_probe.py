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
"""

from __future__ import annotations

import asyncio
import datetime
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from ..models.async_base import AsyncAIModel
from ..models.conversation import Conversation
from ..probes.schema import Probe
from .async_engine import DEFAULT_TARGET_SYSTEM_PROMPT, AttackResult


@dataclass
class ProbeOutcome:
    """Single execution of a single probe."""

    probe_id: str
    coordinate: str
    severity: str
    owasp_llm: list[str]
    result: AttackResult
    skipped_reason: str | None = None


@dataclass
class CatalogSummary:
    """Aggregate output of a corpus run."""

    total: int
    executed: int
    skipped: int
    successes: int
    errors: int
    by_severity: dict[str, dict[str, int]] = field(default_factory=dict)
    by_coordinate: dict[str, dict[str, int]] = field(default_factory=dict)
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
    ) -> None:
        self.target = target
        self.probes = probes
        self.concurrency = max(1, concurrency)

    async def run(
        self,
        *,
        target_system_prompt: str | None = None,
    ) -> CatalogSummary:
        sem = asyncio.Semaphore(self.concurrency)
        system = target_system_prompt or DEFAULT_TARGET_SYSTEM_PROMPT

        async def _one(probe: Probe) -> ProbeOutcome:
            if probe.metadata.get("requires_flow_runner"):
                return ProbeOutcome(
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

            conv = (
                Conversation().with_system(system).append("user", probe.prompt)
            )
            async with sem:
                try:
                    resp = await self.target.chat(conv)
                except Exception as e:  # noqa: BLE001
                    return ProbeOutcome(
                        probe_id=probe.id,
                        coordinate=probe.coordinate,
                        severity=probe.severity,
                        owasp_llm=list(probe.owasp_llm),
                        result=AttackResult(
                            instruction=probe.id,
                            attack_prompt=probe.prompt,
                            target_response="",
                            success=False,
                            reason=f"target error: {e}",
                            error=str(e),
                        ),
                    )
            success, reason = _judge(probe, resp.content)
            return ProbeOutcome(
                probe_id=probe.id,
                coordinate=probe.coordinate,
                severity=probe.severity,
                owasp_llm=list(probe.owasp_llm),
                result=AttackResult(
                    instruction=probe.id,
                    attack_prompt=probe.prompt,
                    target_response=resp.content,
                    success=success,
                    reason=reason,
                ),
            )

        outcomes: list[ProbeOutcome] = await asyncio.gather(
            *(_one(p) for p in self.probes)
        )
        return _summarize(outcomes)


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

    summary.outcomes = [_outcome_to_dict(o) for o in outcomes]
    return summary


def _outcome_to_dict(o: ProbeOutcome) -> dict[str, Any]:
    d = asdict(o.result)
    d["probe_id"] = o.probe_id
    d["coordinate"] = o.coordinate
    d["severity"] = o.severity
    d["owasp_llm"] = o.owasp_llm
    if o.skipped_reason:
        d["skipped_reason"] = o.skipped_reason
    return d
