from __future__ import annotations

from itertools import cycle

from lmtwt.attacks.strategies import PAIRStrategy, TAPStrategy
from lmtwt.models.async_base import ChatResponse


class FakeModel:
    """Stand-in for AsyncAIModel. Returns canned responses cyclically."""

    def __init__(self, model_name: str, responses: list[str]):
        self.model_name = model_name
        self._cycle = cycle(responses)
        self.call_count = 0

    async def chat(self, conversation, *, temperature=0.7, max_tokens=4096):
        self.call_count += 1
        return ChatResponse(content=next(self._cycle), model=self.model_name)


class FakeScoringJudge:
    """Returns scores in order; cycles when exhausted."""

    def __init__(self, scores: list[int]):
        self._cycle = cycle(scores)
        self.calls: list[tuple[str, str]] = []

    async def score(self, attack, response):
        self.calls.append((attack, response))
        s = next(self._cycle)
        return s, f"fake reason for {s}"

    async def evaluate(self, attack, response):
        s, r = await self.score(attack, response)
        return s >= 8, f"score={s}: {r}"


# ---- PAIR ----


async def test_pair_stops_on_threshold():
    attacker = FakeModel("a", ["attack-1", "attack-2", "attack-3"])
    target = FakeModel("t", ["resp-1", "resp-2", "resp-3"])
    judge = FakeScoringJudge([3, 9, 5])  # second attempt crosses threshold
    strategy = PAIRStrategy(judge=judge, max_iterations=5, score_threshold=8)

    result = await strategy.refine(attacker, target, "objective")

    assert result.success is True
    assert result.attack_prompt == "attack-2"
    assert result.target_response == "resp-2"
    assert "score=9" in result.reason
    # judge invoked exactly twice (no third call after early stop)
    assert len(judge.calls) == 2


async def test_pair_returns_best_when_threshold_never_crossed():
    attacker = FakeModel("a", ["a1", "a2", "a3"])
    target = FakeModel("t", ["r1", "r2", "r3"])
    judge = FakeScoringJudge([3, 6, 5])
    strategy = PAIRStrategy(judge=judge, max_iterations=3, score_threshold=8)

    result = await strategy.refine(attacker, target, "objective")

    assert result.success is False
    # Best of (3, 6, 5) is 6 → second attempt
    assert result.attack_prompt == "a2"
    assert "score=6" in result.reason


async def test_pair_disabling_early_stop_runs_full_budget():
    attacker = FakeModel("a", ["a1", "a2", "a3"])
    target = FakeModel("t", ["r1", "r2", "r3"])
    judge = FakeScoringJudge([9, 9, 10])
    strategy = PAIRStrategy(
        judge=judge, max_iterations=3, score_threshold=8, early_stop_on_success=False
    )

    result = await strategy.refine(attacker, target, "objective")

    # Even though score 9 hits threshold, full budget runs; final best is the 10
    assert result.success is True
    assert "score=10" in result.reason
    assert len(judge.calls) == 3


async def test_pair_handles_target_error():
    class BoomTarget:
        model_name = "boom"
        call_count = 0

        async def chat(self, *a, **kw):
            self.call_count += 1
            raise RuntimeError("upstream down")

    attacker = FakeModel("a", ["a1"])
    target = BoomTarget()
    judge = FakeScoringJudge([10])
    strategy = PAIRStrategy(judge=judge, max_iterations=2, score_threshold=8)

    result = await strategy.refine(attacker, target, "obj")

    # Both attempts errored; never reached the judge.
    assert result.success is False
    assert result.error == "upstream down"
    assert len(judge.calls) == 0


# ---- TAP ----


async def test_tap_returns_best_leaf_score():
    attacker = FakeModel("a", ["a"] * 50)
    target = FakeModel("t", ["r"] * 50)
    # 3 roots scored [3, 5, 7]; second level (top-2 = the 5 and 7) generate 3 children each
    # children get scored [4, 6, 9, 2, 8, 1] — best is 9
    judge = FakeScoringJudge([3, 5, 7, 4, 6, 9, 2, 8, 1] + [1] * 50)
    strategy = TAPStrategy(
        judge=judge, branching_factor=3, depth=2, prune_top_k=2, score_threshold=8
    )

    result = await strategy.refine(attacker, target, "obj")

    assert result.success is True  # 9 ≥ 8
    assert "score=9" in result.reason


async def test_tap_pruning_keeps_top_k():
    attacker = FakeModel("a", ["a"] * 30)
    target = FakeModel("t", ["r"] * 30)
    # 4 roots: scores [1, 2, 3, 10]; with prune_top_k=2 → keep [10, 3]
    # depth=2, second level: 2 surviving × 2 branches = 4 calls
    # all return 5 → best stays at 10 from level 0
    judge = FakeScoringJudge([1, 2, 3, 10, 5, 5, 5, 5])
    strategy = TAPStrategy(
        judge=judge, branching_factor=4, depth=2, prune_top_k=2, score_threshold=20
    )

    result = await strategy.refine(attacker, target, "obj")

    # Best across the whole tree is 10 (from the root level)
    assert "score=10" in result.reason


async def test_tap_early_stop_on_threshold():
    attacker = FakeModel("a", ["a"] * 20)
    target = FakeModel("t", ["r"] * 20)
    # First 3 root scores cross threshold immediately
    judge = FakeScoringJudge([10, 9, 8])
    strategy = TAPStrategy(
        judge=judge, branching_factor=3, depth=4, prune_top_k=2, score_threshold=8
    )

    result = await strategy.refine(attacker, target, "obj")

    # Should have stopped after level 0 — no second-level children needed
    # (only 3 calls to attacker + 3 to target + 3 to judge)
    assert len(judge.calls) == 3
    assert result.success is True
