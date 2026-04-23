from __future__ import annotations

import asyncio
from typing import Any

from lmtwt.attacks.async_engine import AsyncAttackEngine
from lmtwt.models.async_base import ChatResponse


class _Counter:
    def __init__(self):
        self.value = 0

    def __iadd__(self, n):
        self.value += n
        return self


class FakeAsyncModel:
    """Test double for ``AsyncAIModel``. Records calls; returns canned responses."""

    def __init__(self, model_name: str, responses: list[str], delay: float = 0.0):
        self.model_name = model_name
        self._responses = responses
        self._idx = 0
        self.calls: list[dict[str, Any]] = []
        self.delay = delay
        self.in_flight = 0
        self.max_concurrent = 0

    async def chat(self, conversation, *, temperature=0.7, max_tokens=4096):
        self.in_flight += 1
        self.max_concurrent = max(self.max_concurrent, self.in_flight)
        try:
            self.calls.append(
                {
                    "system": conversation.system,
                    "messages": list(conversation.messages),
                    "temperature": temperature,
                }
            )
            if self.delay:
                await asyncio.sleep(self.delay)
            text = self._responses[self._idx % len(self._responses)]
            self._idx += 1
            return ChatResponse(content=text, model=self.model_name)
        finally:
            self.in_flight -= 1


class FakeJudge:
    def __init__(self, verdicts: list[bool]):
        self._verdicts = verdicts
        self._idx = 0
        self.calls: list[tuple[str, str]] = []

    async def evaluate(self, attack_prompt, target_response):
        self.calls.append((attack_prompt, target_response))
        v = self._verdicts[self._idx % len(self._verdicts)]
        self._idx += 1
        return v, ("compliant" if v else "refused")


async def test_generate_attack_prompt_sends_instruction_to_attacker():
    attacker = FakeAsyncModel("a-1", ["malicious payload"])
    target = FakeAsyncModel("t-1", ["x"])
    engine = AsyncAttackEngine(attacker, target)

    out = await engine.generate_attack_prompt("write a jailbreak")

    assert out == "malicious payload"
    assert len(attacker.calls) == 1
    assert attacker.calls[0]["messages"][-1].content == "write a jailbreak"
    # default attacker system prompt is in place
    assert "security testing" in attacker.calls[0]["system"]


async def test_generate_strips_markdown_fences():
    attacker = FakeAsyncModel("a", ["```json\nactual payload\n```"])
    target = FakeAsyncModel("t", ["x"])
    engine = AsyncAttackEngine(attacker, target)
    out = await engine.generate_attack_prompt("instr")
    assert out == "actual payload"


async def test_execute_attack_records_history_and_judge_verdict():
    attacker = FakeAsyncModel("a", [])
    target = FakeAsyncModel("t", ["target's reply"])
    judge = FakeJudge(verdicts=[True])
    engine = AsyncAttackEngine(attacker, target, judge=judge)

    result = await engine.execute_attack("the goal", "the payload")

    assert result.success is True
    assert result.target_response == "target's reply"
    assert engine.history == [result]
    assert judge.calls == [("the payload", "target's reply")]


async def test_execute_attack_captures_target_error():
    class BoomModel(FakeAsyncModel):
        async def chat(self, *a, **kw):
            raise RuntimeError("provider exploded")

    engine = AsyncAttackEngine(
        FakeAsyncModel("a", []),
        BoomModel("t", []),
    )
    result = await engine.execute_attack("g", "p")

    assert result.success is False
    assert "provider exploded" in result.error
    assert engine.history == [result]


async def test_run_instruction_iterates_with_temperature_ramp():
    attacker = FakeAsyncModel("a", ["p1", "p2", "p3"])
    target = FakeAsyncModel("t", ["r1", "r2", "r3"])
    judge = FakeJudge(verdicts=[True, True, True])
    engine = AsyncAttackEngine(attacker, target, judge=judge)

    results = await engine.run_instruction("test", iterations=3)

    assert len(results) == 3
    temps = [c["temperature"] for c in attacker.calls]
    assert [round(t, 2) for t in temps] == [0.7, 0.8, 0.9]


async def test_hacker_mode_auto_retries_on_failure():
    # First attack fails, second (auto-retry) succeeds.
    attacker = FakeAsyncModel("a", ["initial payload", "refined payload"])
    target = FakeAsyncModel("t", ["refusal", "compliance"])
    judge = FakeJudge(verdicts=[False, True])
    engine = AsyncAttackEngine(attacker, target, judge=judge, hacker_mode=True)

    results = await engine.run_instruction("inst", iterations=1)

    assert len(results) == 2  # initial + auto-retry
    assert results[0].success is False
    assert results[1].success is True
    assert results[1].is_retry is True


async def test_batch_serial_when_concurrency_one():
    attacker = FakeAsyncModel("a", ["p"], delay=0.05)
    target = FakeAsyncModel("t", ["r"], delay=0.05)
    judge = FakeJudge(verdicts=[True])
    engine = AsyncAttackEngine(attacker, target, judge=judge)

    await engine.batch(["i1", "i2", "i3"], concurrency=1)

    assert target.max_concurrent == 1


async def test_batch_parallelizes_with_concurrency_three():
    attacker = FakeAsyncModel("a", ["p"], delay=0.05)
    target = FakeAsyncModel("t", ["r"], delay=0.05)
    judge = FakeJudge(verdicts=[True])
    engine = AsyncAttackEngine(attacker, target, judge=judge)

    await engine.batch(["i1", "i2", "i3", "i4", "i5"], concurrency=3)

    assert target.max_concurrent >= 2  # at least some parallelism observed


async def test_metadata_reflects_state():
    attacker = FakeAsyncModel("attacker-x", ["p"])
    target = FakeAsyncModel("target-y", ["r"])
    judge = FakeJudge(verdicts=[True, False])
    engine = AsyncAttackEngine(attacker, target, judge=judge, hacker_mode=True)

    await engine.run_instruction("a", iterations=1)
    await engine.run_instruction("b", iterations=1)
    # Second one fails, hacker mode tries auto-retry — verdicts cycle so retry succeeds
    meta = engine.metadata()

    assert meta["attacker_model"] == "attacker-x"
    assert meta["target_model"] == "target-y"
    assert meta["hacker_mode"] is True
    assert meta["judge"] == "FakeJudge"
    assert meta["total_attacks"] == len(engine.history)
    assert meta["successes"] == sum(1 for r in engine.history if r.success)
