from lmtwt.attacks.async_probe import AsyncProbeAttack
from lmtwt.models.async_base import ChatResponse


class FakeTarget:
    def __init__(self, responses):
        self.model_name = "fake-target"
        self._responses = responses
        self._idx = 0
        self.calls = 0

    async def chat(self, conversation, *, temperature=0.7, max_tokens=4096):
        self.calls += 1
        text = self._responses[self._idx % len(self._responses)]
        self._idx += 1
        return ChatResponse(content=text, model=self.model_name)


class FakeJudge:
    def __init__(self, verdicts):
        self._verdicts = verdicts
        self._idx = 0

    async def evaluate(self, attack, response):
        v = self._verdicts[self._idx % len(self._verdicts)]
        self._idx += 1
        return v, "ok" if v else "no"


async def test_execute_category_returns_summary():
    target = FakeTarget(["I cannot help", "Sure, here you go", "I'm sorry"])
    probe = AsyncProbeAttack(target, judge=FakeJudge([False, True, False]))

    summary = await probe.execute_category("injection", iterations=3)

    assert summary["category"] == "injection"
    assert summary["iterations"] == 3
    assert summary["success_count"] == 1
    assert summary["error_count"] == 0
    assert summary["success_rate"] == 1 / 3
    assert summary["vulnerability_assessment"] == "Medium"
    assert len(summary["results"]) == 3


async def test_execute_category_captures_target_errors():
    class BoomTarget:
        model_name = "boom"

        async def chat(self, *a, **kw):
            raise RuntimeError("upstream down")

    probe = AsyncProbeAttack(BoomTarget(), judge=FakeJudge([True]))
    summary = await probe.execute_category("dan", iterations=2)

    assert summary["error_count"] == 2
    assert summary["success_count"] == 0
    assert summary["vulnerability_assessment"] == "Low"


async def test_vulnerability_assessment_bands():
    target = FakeTarget(["x", "x", "x", "x"])
    probe = AsyncProbeAttack(target, judge=FakeJudge([True, True, True, False]))
    summary = await probe.execute_category("dan", iterations=4)
    assert summary["vulnerability_assessment"] == "High"  # 75% success


async def test_execute_all_iterates_every_category():
    target = FakeTarget(["any reply"])
    probe = AsyncProbeAttack(
        target,
        judge=FakeJudge([True]),
        payload_categories=["dan", "injection"],
    )

    out = await probe.execute_all(iterations=1)

    assert set(out.keys()) == {"dan", "injection"}
    assert all(v["iterations"] == 1 for v in out.values())
