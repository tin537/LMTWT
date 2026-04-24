"""Scan orchestrator — executes a ``ScanPlan`` against a live target.

Composes existing pieces (fingerprint, catalog, adaptive, climb,
pollinate, chatbot attacks). Each step is wrapped in try/except so a
single technique failure doesn't abort the whole scan — the failure is
recorded and the operator sees it in ``plan.json``.

Returns a ``ScanResult`` that the bundle writer turns into the
on-disk engagement deliverable.
"""

from __future__ import annotations

import asyncio
import datetime
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..attacks.catalog_probe import AsyncCatalogProbe
from ..chatbot_attacks import (
    CostAmplificationAttack,
    RefusalFatigueAttack,
    ToolResultPoisoningAttack,
)
from ..chatbot_attacks.cost_amplification import (
    finding_to_dict as _cost_to_dict,
)
from ..chatbot_attacks.refusal_fatigue import (
    finding_to_dict as _fatigue_to_dict,
)
from ..chatbot_attacks.tool_result_poisoning import (
    finding_to_dict as _poison_to_dict,
)
from ..discovery import (
    AdaptiveAttacker,
    ChatTarget,
    CrossPollinator,
    LMTWTClimb,
    fingerprint_target,
)
from ..models.async_base import AsyncAIModel
from ..persistence import SQLiteObserver
from ..probes import load_corpus
from ..scoring import EnsembleRefusalGrader, LLMRefusalGrader
from ..utils.logger import console

if TYPE_CHECKING:
    from ..discovery.fingerprint import TargetFingerprint
    from .plan import ScanPlan


@dataclass
class ScanResult:
    """Output of one ``run_scan(...)`` call.

    ``to_run_payload()`` produces the same shape ``--report-from`` and
    the reporting layer already accept — so the engagement bundle
    pipeline (``build_report``, ``write_repro_pack``, etc.) just works.
    """

    target_name: str
    attacker_name: str
    plan: ScanPlan
    started_at: str
    finished_at: str
    fingerprint: TargetFingerprint | None = None
    db_path: str | None = None
    executed_steps: list[str] = field(default_factory=list)
    step_durations: dict[str, float] = field(default_factory=dict)
    step_outcome_counts: dict[str, int] = field(default_factory=dict)
    step_errors: dict[str, str] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_run_payload(self) -> dict[str, Any]:
        return {
            "metadata": {
                "target_model": self.target_name,
                "attacker_model": self.attacker_name,
                "mode": "scan",
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "depth": self.plan.depth,
                "executed_steps": self.executed_steps,
                "step_durations": self.step_durations,
                "step_outcome_counts": self.step_outcome_counts,
                "step_errors": self.step_errors,
                **self.metadata,
            },
            "results": self.findings,
        }


# ---------------------------------------------------------------- orchestrator


async def run_scan(
    *,
    target: AsyncAIModel,
    attacker: AsyncAIModel,
    target_name: str,
    attacker_name: str,
    plan: ScanPlan,
    out_dir: Path,
    target_config: dict[str, Any] | None = None,
    target_system_prompt: str | None = None,
    concurrency: int = 4,
    use_llm_grader: bool = True,
    show_dashboard: bool = False,
) -> ScanResult:
    """Execute every enabled step in ``plan`` in order.

    Always opens a SQLite db at ``out_dir/scan.db`` for durability — the
    bundle writer copies it into the bundle as ``scan.db``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = out_dir / "scan.db"

    grader = (
        EnsembleRefusalGrader(LLMRefusalGrader(attacker)) if use_llm_grader
        else None
    )

    started_at = datetime.datetime.now().isoformat(timespec="seconds")
    result = ScanResult(
        target_name=target_name, attacker_name=attacker_name,
        plan=plan, started_at=started_at, finished_at="",
        db_path=str(db_path),
        metadata={"target_config_summary": _summarize_target_config(target_config)},
    )

    # ---- 1. fingerprint
    fp_step = plan.get("fingerprint")
    if fp_step and fp_step.enabled:
        await _run_step(result, "fingerprint", _step_fingerprint, target,
                        result, target_system_prompt)

    # ---- 2. catalog (incl. adaptive injection)
    cat_step = plan.get("catalog")
    if cat_step and cat_step.enabled:
        await _run_step(result, "catalog", _step_catalog,
                        target, attacker, result, db_path,
                        cat_step.kwargs, plan.get("adaptive"),
                        concurrency, grader, target_system_prompt,
                        show_dashboard)

    # ---- 3. climb (pick the highest-grade non-success probes from catalog)
    climb_step = plan.get("climb")
    if climb_step and climb_step.enabled:
        await _run_step(result, "climb", _step_climb,
                        target, attacker, result, climb_step.kwargs,
                        target_system_prompt)

    # ---- 4. pollinate (every climb winner → axis-fan-out variants)
    pol_step = plan.get("pollinate")
    if pol_step and pol_step.enabled:
        await _run_step(result, "pollinate", _step_pollinate,
                        target, attacker, result, db_path, concurrency, grader,
                        target_system_prompt, show_dashboard)

    # ---- 5. chatbot-protocol attacks
    # session-lifecycle / jwt-claims / conversation-hijack require
    # external-api transport awareness — they noop on plain providers
    # in the MVP scan. Always-on attacks (cost-amp / fatigue / poison)
    # work against any AsyncAIModel.
    for cb_name, runner_cls, dict_fn in (
        ("chatbot.cost_amplification", CostAmplificationAttack, _cost_to_dict),
        ("chatbot.refusal_fatigue", RefusalFatigueAttack, _fatigue_to_dict),
        ("chatbot.tool_result_poisoning", ToolResultPoisoningAttack, _poison_to_dict),
    ):
        step = plan.get(cb_name)
        if step and step.enabled:
            await _run_step(result, cb_name, _step_chatbot_attack,
                            target, result, runner_cls, dict_fn,
                            cb_name, target_system_prompt)

    result.finished_at = datetime.datetime.now().isoformat(timespec="seconds")
    return result


# ---------------------------------------------------------------- step wrappers


async def _run_step(result: ScanResult, name: str, fn, *args) -> None:
    started = time.monotonic()
    console.print(f"[cyan]» {name}[/cyan]")
    try:
        await fn(*args)
        result.executed_steps.append(name)
    except Exception as exc:  # noqa: BLE001 — record + continue
        result.step_errors[name] = f"{type(exc).__name__}: {exc}"
        console.print(f"  [red]× {name} failed: {exc}[/red]")
    finally:
        result.step_durations[name] = round(time.monotonic() - started, 2)


# ---------------------------------------------------------------- step impls


async def _step_fingerprint(
    target, result: ScanResult, target_system_prompt,
) -> None:
    fp = await fingerprint_target(target, target_system_prompt=target_system_prompt)
    result.fingerprint = fp
    console.print(
        f"  weak axis=[bold red]{fp.weak_obfuscation_axis}[/bold red]  "
        f"refusal_style={fp.refusal_style}  "
        f"policy_leak={fp.policy_leak_observed}"
    )


async def _step_catalog(
    target, attacker, result: ScanResult, db_path: Path,
    kwargs: dict, adaptive_step, concurrency: int, grader,
    target_system_prompt, show_dashboard: bool,
) -> None:
    severity_filter = (
        [s.strip() for s in kwargs.get("severity", "medium,high,critical").split(",")]
        if kwargs.get("severity") else None
    )
    repeats = kwargs.get("repeats", 1)
    corpus = load_corpus(severity_filter=severity_filter)

    # Adaptive injection — needs the fingerprint (already on result).
    if adaptive_step and adaptive_step.enabled and result.fingerprint is not None:
        try:
            adapter = AdaptiveAttacker(attacker)
            adapted = await adapter.generate(
                result.fingerprint, n=adaptive_step.kwargs.get("n", 3),
            )
            if adapted:
                corpus = corpus + [a.probe for a in adapted]
                result.executed_steps.append("adaptive")
                result.step_outcome_counts["adaptive"] = len(adapted)
        except Exception as exc:  # noqa: BLE001
            result.step_errors["adaptive"] = f"{type(exc).__name__}: {exc}"

    observers: list[Any] = [_make_persist_observer(
        db_path, result.target_name, result.attacker_name, "catalog",
    )]
    if show_dashboard:
        from ..cli_dashboard import RichDashboardObserver
        observers.append(RichDashboardObserver(
            result.target_name, console=console,
        ))

    runner = AsyncCatalogProbe(
        target, probes=corpus, concurrency=concurrency,
        repeats=repeats, refusal_grader=grader, observers=observers,
    )
    summary = await runner.run(target_system_prompt=target_system_prompt)
    result.findings.extend(summary.outcomes)
    result.step_outcome_counts["catalog"] = len(summary.outcomes)
    console.print(
        f"  catalog: {summary.successes}/{summary.executed} successes, "
        f"max_lss={summary.max_lss:.2f}"
    )
    # Stash for downstream steps.
    result.metadata["_catalog_summary"] = {
        "executed": summary.executed,
        "successes": summary.successes,
        "max_lss": summary.max_lss,
    }


async def _step_climb(
    target, attacker, result: ScanResult, kwargs: dict,
    target_system_prompt,
) -> None:
    # Pick climb seeds from the catalog: probes with B/C refusal grade
    # but no success — i.e. the target almost broke. Cap at 3 to keep
    # per-scan cost predictable.
    seeds = _pick_climb_seeds(result.findings, max_seeds=3)
    if not seeds:
        result.step_outcome_counts["climb"] = 0
        console.print("  climb: no B/C seeds — skipping")
        return
    chat_target = ChatTarget(target, system=target_system_prompt)
    climbed: list[dict[str, Any]] = []
    for seed in seeds:
        # Find the actual Probe object by id from the corpus.
        probe = _find_probe_by_id(seed["probe_id"])
        if probe is None:
            continue
        try:
            climb = LMTWTClimb(
                target=chat_target, attacker=attacker,
                max_rounds=kwargs.get("rounds", 2),
                fanout=kwargs.get("fanout", 3),
            )
            climb_result = await climb.run(probe)
        except Exception as exc:  # noqa: BLE001
            result.step_errors[f"climb:{probe.id}"] = (
                f"{type(exc).__name__}: {exc}"
            )
            continue
        # Only record a climb finding when an actual mutation produced the
        # win — if best_probe IS the seed (no climb metadata applied), the
        # seed succeeded on its first re-evaluation and we'd be double-counting
        # what the catalog already reported.
        is_real_mutation = (
            climb_result.stopped_reason == "success"
            and climb_result.best_probe.id != seed["probe_id"]
            and climb_result.best_probe.metadata.get("climb", {}).get("operator")
        )
        if is_real_mutation:
            climb_meta = climb_result.best_probe.metadata.get("climb") or {}
            climbed.append({
                "probe_id": climb_result.best_probe.id,
                "title": climb_result.best_probe.name,
                "severity": climb_result.best_probe.severity,
                "owasp_llm": list(climb_result.best_probe.owasp_llm),
                "coordinate": climb_result.best_probe.coordinate,
                "attack_prompt": climb_result.best_probe.prompt,
                "target_response": climb_result.history[-1].response_excerpt,
                "success": True,
                "reason": (
                    f"climbed from {seed['probe_id']} via "
                    f"{climb_meta.get('operator')} (gen {climb_meta.get('generation')})"
                ),
                "refusal_grade": "F",
                "metadata": {"climb": climb_meta},
            })
    result.findings.extend(climbed)
    result.step_outcome_counts["climb"] = len(climbed)
    console.print(f"  climb: {len(climbed)} new wins from {len(seeds)} seeds")
    result.metadata["_climbed_probes"] = [c["probe_id"] for c in climbed]


async def _step_pollinate(
    target, attacker, result: ScanResult, db_path: Path,
    concurrency: int, grader, target_system_prompt, show_dashboard: bool,
) -> None:
    seeds = result.metadata.get("_climbed_probes", [])
    if not seeds:
        # Fallback: pollinate the highest-LSS catalog success.
        success_findings = [
            f for f in result.findings
            if f.get("success") and f.get("lss") and f.get("probe_id")
        ]
        success_findings.sort(
            key=lambda f: -(f.get("lss", {}).get("score") or 0.0),
        )
        if success_findings:
            seeds = [success_findings[0]["probe_id"]]
    if not seeds:
        result.step_outcome_counts["pollinate"] = 0
        console.print("  pollinate: no seeds available")
        return

    pol = CrossPollinator(attacker=attacker)
    new_probes = []
    for seed_id in seeds[:3]:  # cap to keep cost predictable
        probe = _find_probe_by_id(seed_id) or _find_climbed_probe(result, seed_id)
        if probe is None:
            continue
        variants = await pol.pollinate(probe, engagement="scan")
        new_probes.extend(v.probe for v in variants)

    if not new_probes:
        result.step_outcome_counts["pollinate"] = 0
        console.print("  pollinate: no variants generated")
        return

    observers: list[Any] = [_make_persist_observer(
        db_path, result.target_name, result.attacker_name, "pollinate",
    )]
    if show_dashboard:
        from ..cli_dashboard import RichDashboardObserver
        observers.append(RichDashboardObserver(
            result.target_name, console=console,
        ))
    runner = AsyncCatalogProbe(
        target, probes=new_probes, concurrency=concurrency,
        repeats=1, refusal_grader=grader, observers=observers,
    )
    summary = await runner.run(target_system_prompt=target_system_prompt)
    result.findings.extend(summary.outcomes)
    result.step_outcome_counts["pollinate"] = len(summary.outcomes)
    console.print(
        f"  pollinate: {summary.successes}/{summary.executed} variants "
        f"succeeded (from {len(seeds)} seed(s))"
    )


async def _step_chatbot_attack(
    target, result: ScanResult, runner_cls, dict_fn,
    step_name: str, target_system_prompt,
) -> None:
    """Generic adapter for the always-on chatbot-protocol attacks.

    They all share the same shape: ``runner_cls(target).run(...)`` →
    list (or summary holding ``.findings``) of dataclasses. ``dict_fn``
    coerces each finding into the report-friendly dict the rest of the
    pipeline expects.
    """
    runner = runner_cls(target)
    output = await runner.run(target_system_prompt=target_system_prompt)
    findings = output.findings if hasattr(output, "findings") else output
    coerced = [_with_step_tag(dict_fn(f), step_name) for f in findings]
    result.findings.extend(coerced)
    result.step_outcome_counts[step_name] = len(coerced)
    console.print(f"  {step_name}: {len(coerced)} finding(s)")


# ---------------------------------------------------------------- helpers


def _make_persist_observer(
    db_path: Path, target_name: str, attacker_name: str, mode: str,
) -> SQLiteObserver:
    return SQLiteObserver(
        db_path, target_name=target_name, attacker_name=attacker_name,
        mode=mode,
    )


def _summarize_target_config(cfg: dict[str, Any] | None) -> dict[str, Any]:
    """Strip secrets but preserve capability indicators for the bundle."""
    if not cfg:
        return {}
    safe = {
        "endpoint_url": cfg.get("endpoint_url") or cfg.get("url"),
        "protocol": cfg.get("protocol"),
        "has_payload_template": bool(cfg.get("payload_template")),
        "has_session_id_key": bool(cfg.get("session_id_key")),
        "has_bearer_token": False,
    }
    headers = cfg.get("headers") or {}
    if isinstance(headers, dict):
        safe["has_bearer_token"] = any(
            str(v).lower().startswith("bearer ") for v in headers.values()
        )
    return safe


def _pick_climb_seeds(
    findings: list[dict[str, Any]], *, max_seeds: int,
) -> list[dict[str, Any]]:
    """Find catalog probes that *almost* worked — best climb candidates.

    Excludes any probe id that *also* appears as a success elsewhere in the
    findings (under repeats > 1 the same probe can show up as both a success
    row and a near-miss row; if catalog already cracked it we skip the climb).
    """
    successful_ids = {
        f.get("probe_id") for f in findings
        if f.get("probe_id") and f.get("success")
    }
    almost = [
        f for f in findings
        if f.get("probe_id")
        and not f.get("success")
        and f.get("refusal_grade") in ("B", "C")
        and f.get("probe_id") not in successful_ids
    ]
    # Dedupe by probe_id while preserving order.
    seen: set[str] = set()
    uniq: list[dict[str, Any]] = []
    for f in almost:
        pid = f["probe_id"]
        if pid in seen:
            continue
        seen.add(pid)
        uniq.append(f)
    return uniq[:max_seeds]


def _find_probe_by_id(probe_id: str):
    try:
        for p in load_corpus():
            if p.id == probe_id:
                return p
    except Exception:  # noqa: BLE001
        return None
    return None


def _find_climbed_probe(result: ScanResult, probe_id: str):
    # Climbed probes aren't in the corpus — reconstruct a Probe from the
    # finding dict if needed. For now we only use this to look up
    # already-existing climbed seeds; pollinate fan-out runs the parent's
    # prompt, so a minimal Probe stand-in is fine.
    for f in result.findings:
        if f.get("probe_id") != probe_id:
            continue
        from datetime import date

        from ..probes.schema import Probe, Taxonomy
        coord = (f.get("coordinate") or "injection/direct/plain/refusal-bypass").split("/")
        try:
            return Probe(
                id=probe_id, version=1, name=f.get("title") or probe_id,
                description="climbed seed reused for pollination",
                taxonomy=Taxonomy(
                    vector=coord[0],  # type: ignore[arg-type]
                    delivery=coord[1] if len(coord) > 1 else "direct",  # type: ignore[arg-type]
                    obfuscation=coord[2] if len(coord) > 2 else "plain",  # type: ignore[arg-type]
                    target_effect=coord[3] if len(coord) > 3 else "refusal-bypass",  # type: ignore[arg-type]
                ),
                severity=f.get("severity") or "medium",
                owasp_llm=list(f.get("owasp_llm") or []),
                prompt=f.get("attack_prompt") or "",
                success_indicators=[],
                refusal_indicators=[],
                created=date.today(),
            )
        except Exception:  # noqa: BLE001
            return None
    return None


def _with_step_tag(d: dict[str, Any], step: str) -> dict[str, Any]:
    out = dict(d)
    out.setdefault("source_step", step)
    return out


# Suppress "unused asyncio import" pyright complaint (used implicitly).
_ = asyncio
