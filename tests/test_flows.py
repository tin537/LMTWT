from __future__ import annotations

from lmtwt.attacks.flows import (
    BUILT_IN_FLOWS,
    CrescendoStep,
    MultiTurnFlow,
    MultiTurnRunner,
    get_flow,
    list_flows,
    turn_log_to_attack_result,
)
from lmtwt.models.async_base import ChatResponse


class FakeModel:
    def __init__(self, model_name: str, responses: list[str]):
        self.model_name = model_name
        self._responses = responses
        self._idx = 0
        self.calls: list[dict] = []

    async def chat(self, conversation, *, temperature=0.7, max_tokens=4096):
        self.calls.append(
            {
                "system": conversation.system,
                "n_messages": len(conversation.messages),
                "last_user": next(
                    (m.content for m in reversed(conversation.messages) if m.role == "user"),
                    None,
                ),
                "temperature": temperature,
            }
        )
        text = self._responses[self._idx % len(self._responses)]
        self._idx += 1
        return ChatResponse(content=text, model=self.model_name)


class FakeJudge:
    def __init__(self, verdicts: list[bool]):
        self._verdicts = verdicts
        self._idx = 0

    async def evaluate(self, prompt, response):
        v = self._verdicts[self._idx % len(self._verdicts)]
        self._idx += 1
        return v, "ok" if v else "no"


def test_built_in_flows_have_expected_names():
    names = set(BUILT_IN_FLOWS.keys())
    assert names == {
        "crescendo_creative_writing",
        "crescendo_role_assumption",
        "topic_drift",
    }


def test_get_flow_returns_none_for_unknown():
    assert get_flow("does-not-exist") is None


def test_list_flows_contains_all_built_in():
    listed = {f["name"] for f in list_flows()}
    assert "crescendo_creative_writing" in listed
    assert "topic_drift" in listed


async def test_runner_executes_fixed_then_generated_steps():
    flow = MultiTurnFlow(
        name="t",
        description="",
        steps=[
            CrescendoStep("fixed", "first user turn (literal)"),
            CrescendoStep("generated", "make it spicier"),
        ],
    )
    attacker = FakeModel("a", ["second user turn (from attacker)"])
    target = FakeModel("t", ["target reply 1", "target reply 2"])
    runner = MultiTurnRunner(attacker, target, judge=FakeJudge([True]))

    result = await runner.run(flow, "global objective")

    assert len(result.turns) == 2
    assert result.turns[0].user == "first user turn (literal)"
    assert result.turns[0].assistant == "target reply 1"
    assert result.turns[1].user == "second user turn (from attacker)"
    assert result.turns[1].assistant == "target reply 2"
    assert result.final_success is True


async def test_runner_only_judges_last_turn_by_default():
    flow = MultiTurnFlow(
        name="t",
        description="",
        steps=[
            CrescendoStep("fixed", "u1"),
            CrescendoStep("fixed", "u2"),
            CrescendoStep("fixed", "u3"),
        ],
    )
    attacker = FakeModel("a", [])
    target = FakeModel("t", ["r1", "r2", "r3"])
    judge = FakeJudge([True])
    runner = MultiTurnRunner(attacker, target, judge=judge)

    result = await runner.run(flow, "obj")

    assert result.turns[0].success is None
    assert result.turns[1].success is None
    assert result.turns[2].success is True
    # judge invoked exactly once
    assert judge._idx == 1


async def test_runner_judges_each_turn_when_flag_set():
    flow = MultiTurnFlow(
        name="t",
        description="",
        steps=[CrescendoStep("fixed", "u1"), CrescendoStep("fixed", "u2")],
        judge_after_each=True,
    )
    attacker = FakeModel("a", [])
    target = FakeModel("t", ["r1", "r2"])
    judge = FakeJudge([False, True])
    runner = MultiTurnRunner(attacker, target, judge=judge)

    result = await runner.run(flow, "obj")

    assert result.turns[0].success is False
    assert result.turns[1].success is True
    assert result.final_success is True


async def test_runner_accumulates_history_across_turns():
    flow = MultiTurnFlow(
        name="t",
        description="",
        steps=[
            CrescendoStep("fixed", "u1"),
            CrescendoStep("fixed", "u2"),
        ],
    )
    attacker = FakeModel("a", [])
    target = FakeModel("t", ["r1", "r2"])
    runner = MultiTurnRunner(attacker, target, judge=FakeJudge([True]))

    await runner.run(flow, "obj")

    # Second target call should see full conversation: u1, r1, u2 = 3 messages
    assert target.calls[1]["n_messages"] == 3
    assert target.calls[1]["last_user"] == "u2"


async def test_runner_captures_target_error():
    class BoomTarget:
        model_name = "boom"

        async def chat(self, *a, **kw):
            raise RuntimeError("upstream down")

    flow = MultiTurnFlow(
        name="t",
        description="",
        steps=[CrescendoStep("fixed", "u1")],
    )
    runner = MultiTurnRunner(FakeModel("a", []), BoomTarget(), judge=FakeJudge([True]))

    result = await runner.run(flow, "obj")

    assert len(result.turns) == 1
    assert result.turns[0].success is False
    assert "upstream down" in result.turns[0].reason


async def test_run_many_parallel():
    flow = MultiTurnFlow(name="t", description="", steps=[CrescendoStep("fixed", "u")])
    attacker = FakeModel("a", [])
    target = FakeModel("t", ["r"])
    runner = MultiTurnRunner(attacker, target, judge=FakeJudge([True]))

    results = await runner.run_many(flow, ["i1", "i2", "i3"], concurrency=2)

    assert len(results) == 3
    assert all(r.final_success for r in results)


def test_turn_log_to_attack_result_adapter():
    from lmtwt.attacks.flows import MultiTurnTurnLog

    log = MultiTurnTurnLog(step_index=2, user="u", assistant="a", success=True, reason="ok")
    ar = turn_log_to_attack_result(log, "instr")
    assert ar.instruction == "instr"
    assert ar.attack_prompt == "u"
    assert ar.target_response == "a"
    assert ar.success is True
