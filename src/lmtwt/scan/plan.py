"""Scan planner — decides which techniques to run for a given target.

The orchestrator (``orchestrator.py``) doesn't pick which steps fire;
it just executes the plan. The plan is data — easy to test, easy to
inspect with ``--dry-run``, easy to extend.

Decisions live here:
- Depth preset → which steps are enabled
- Target-config inspection → which chatbot-protocol attacks apply
  (skipping with a *reason* the operator can read in the bundle)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Depth = Literal["quick", "standard", "thorough"]


@dataclass
class ScanStep:
    """One executable step in a scan plan."""

    name: str
    enabled: bool
    reason_if_skipped: str = ""
    kwargs: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanPlan:
    """The set of steps that will (or won't) run for one scan."""

    depth: Depth
    steps: list[ScanStep]

    def enabled_step_names(self) -> list[str]:
        return [s.name for s in self.steps if s.enabled]

    def get(self, name: str) -> ScanStep | None:
        for s in self.steps:
            if s.name == name:
                return s
        return None


# ---------------------------------------------------------------- depth → defaults


def _depth_defaults(depth: Depth) -> dict[str, Any]:
    """Per-depth tuning of every step's knobs.

    quick      → catalog + fingerprint + always-on chatbot attacks (~2 min)
    standard   → above + adaptive + climb + pollinate + capability-gated
                 chatbot attacks + PAIR + TAP + multi-turn flows
                 (the full attack surface; ~30 min on a real target)
    thorough   → above + N=10 catalog repeats + self-play probe generation
                 (hours)
    """
    if depth == "quick":
        return {
            "fingerprint_enabled": True,
            "catalog_enabled": True,
            "catalog_repeats": 1,
            "catalog_severity": "high,critical",
            "adaptive_enabled": False,
            "climb_enabled": False,
            "pollinate_enabled": False,
            "chatbot_enabled": True,
            "pair_enabled": False,
            "tap_enabled": False,
            "multi_turn_enabled": False,
            "self_play_enabled": False,
        }
    if depth == "thorough":
        return {
            "fingerprint_enabled": True,
            "catalog_enabled": True,
            "catalog_repeats": 10,
            "catalog_severity": "low,medium,high,critical",
            "adaptive_enabled": True,
            "adaptive_n": 5,
            "climb_enabled": True,
            "climb_rounds": 3,
            "climb_fanout": 4,
            "pollinate_enabled": True,
            "chatbot_enabled": True,
            "pair_enabled": True,
            "pair_iterations": 5,
            "tap_enabled": True,
            "tap_branching": 3,
            "tap_depth": 4,
            "multi_turn_enabled": True,
            "self_play_enabled": True,
            "self_play_n": 2,
        }
    # standard — runs every attack mode, with cost-bounded knobs
    return {
        "fingerprint_enabled": True,
        "catalog_enabled": True,
        "catalog_repeats": 3,
        "catalog_severity": "medium,high,critical",
        "adaptive_enabled": True,
        "adaptive_n": 3,
        "climb_enabled": True,
        "climb_rounds": 2,
        "climb_fanout": 3,
        "pollinate_enabled": True,
        "chatbot_enabled": True,
        "pair_enabled": True,
        "pair_iterations": 3,
        "tap_enabled": True,
        "tap_branching": 2,
        "tap_depth": 3,
        "multi_turn_enabled": True,
        "self_play_enabled": False,
    }


# ---------------------------------------------------------------- chatbot detection


_CHATBOT_RULES: list[tuple[str, str, str]] = [
    # (step_name, target_config_key, reason_if_missing)
    ("chatbot.session_lifecycle", "payload_template",
     "no payload_template — session-lifecycle mutator needs a JSON body shape"),
    ("chatbot.jwt_claims", "headers",
     "no headers in target-config — jwt-claims attack needs a Bearer token"),
    ("chatbot.conversation_hijack", "session_id_key",
     "no session_id_key in target-config — hijack attack needs to know which "
     "field holds the session id"),
]


def _detect_chatbot_steps(
    target_config: dict[str, Any] | None,
    chatbot_enabled: bool,
) -> list[ScanStep]:
    """Per-chatbot-attack enablement based on target-config inspection."""
    steps: list[ScanStep] = []

    if not chatbot_enabled:
        for name in ("chatbot.session_lifecycle", "chatbot.jwt_claims",
                     "chatbot.conversation_hijack", "chatbot.cost_amplification",
                     "chatbot.refusal_fatigue", "chatbot.tool_result_poisoning"):
            steps.append(ScanStep(
                name=name, enabled=False,
                reason_if_skipped="depth preset disables chatbot attacks",
            ))
        return steps

    cfg = target_config or {}

    # Capability-detected attacks.
    for name, required_key, reason in _CHATBOT_RULES:
        present = bool(cfg.get(required_key))
        # JWT specifically needs a Bearer token in the headers.
        if name == "chatbot.jwt_claims":
            headers = cfg.get("headers") or {}
            present = any(
                str(v).lower().startswith("bearer ")
                for v in headers.values()
            ) if isinstance(headers, dict) else False
            if not present:
                reason = "no Bearer token in target-config headers — jwt-claims needs one"
        steps.append(ScanStep(
            name=name, enabled=present,
            reason_if_skipped="" if present else reason,
        ))

    # Always-on attacks (cheap, work against anything).
    steps.append(ScanStep(name="chatbot.cost_amplification", enabled=True))
    steps.append(ScanStep(name="chatbot.refusal_fatigue", enabled=True))
    steps.append(ScanStep(name="chatbot.tool_result_poisoning", enabled=True))

    return steps


# ---------------------------------------------------------------- public


def build_scan_plan(
    *,
    depth: Depth = "standard",
    target_config: dict[str, Any] | None = None,
) -> ScanPlan:
    """Build the set of steps that will execute for a scan.

    The plan is deterministic given (depth, target_config) — useful for
    a future ``--dry-run`` flag and for operator-facing "what will this
    do?" output.
    """
    if depth not in ("quick", "standard", "thorough"):
        raise ValueError(f"unknown depth: {depth!r}")

    d = _depth_defaults(depth)

    steps: list[ScanStep] = []

    steps.append(ScanStep(
        name="fingerprint", enabled=d["fingerprint_enabled"],
        reason_if_skipped="" if d["fingerprint_enabled"] else "depth preset disables fingerprint",
    ))
    steps.append(ScanStep(
        name="catalog", enabled=d["catalog_enabled"],
        kwargs={
            "repeats": d["catalog_repeats"],
            "severity": d["catalog_severity"],
        },
    ))
    steps.append(ScanStep(
        name="adaptive", enabled=d["adaptive_enabled"],
        reason_if_skipped="" if d["adaptive_enabled"] else "depth preset disables adaptive",
        kwargs={"n": d.get("adaptive_n", 3)},
    ))
    steps.append(ScanStep(
        name="climb", enabled=d["climb_enabled"],
        reason_if_skipped="" if d["climb_enabled"] else "depth preset disables climb",
        kwargs={
            "rounds": d.get("climb_rounds", 2),
            "fanout": d.get("climb_fanout", 3),
        },
    ))
    steps.append(ScanStep(
        name="pollinate", enabled=d["pollinate_enabled"],
        reason_if_skipped="" if d["pollinate_enabled"] else "depth preset disables pollinate",
    ))
    steps.append(ScanStep(
        name="self_play", enabled=d["self_play_enabled"],
        reason_if_skipped="" if d["self_play_enabled"] else "depth preset disables self-play",
        kwargs={"n": d.get("self_play_n", 2)},
    ))

    # Chatbot-protocol attacks — capability-detected.
    steps.extend(_detect_chatbot_steps(target_config, d["chatbot_enabled"]))

    # PAIR / TAP refinement strategies — model-based search loops over
    # generic high-value goals. Always applicable; no capability gate.
    steps.append(ScanStep(
        name="strategy.pair", enabled=d["pair_enabled"],
        reason_if_skipped="" if d["pair_enabled"] else "depth preset disables PAIR",
        kwargs={
            "iterations": d.get("pair_iterations", 3),
            "threshold": 8,
        },
    ))
    steps.append(ScanStep(
        name="strategy.tap", enabled=d["tap_enabled"],
        reason_if_skipped="" if d["tap_enabled"] else "depth preset disables TAP",
        kwargs={
            "branching": d.get("tap_branching", 2),
            "depth": d.get("tap_depth", 3),
            "prune": 2,
            "threshold": 8,
        },
    ))

    # Multi-turn social-engineering flows — runs every BUILT_IN_FLOWS
    # against a system-leak goal. Works against any AsyncAIModel.
    steps.append(ScanStep(
        name="multi_turn", enabled=d["multi_turn_enabled"],
        reason_if_skipped="" if d["multi_turn_enabled"] else "depth preset disables multi-turn flows",
    ))

    return ScanPlan(depth=depth, steps=steps)
