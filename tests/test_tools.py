from __future__ import annotations

from itertools import cycle

from lmtwt.attacks.tools import (
    BUILT_IN_VECTORS,
    DOCUMENT,
    TOOL_OUTPUT,
    WEB_SEARCH,
    ToolHarness,
    ToolUseAttack,
    get_vector,
    list_vectors,
)
from lmtwt.models.async_base import ChatResponse


class FakeModel:
    def __init__(self, name: str, responses: list[str]):
        self.model_name = name
        self._cycle = cycle(responses)
        self.calls: list[dict] = []

    async def chat(self, conversation, *, temperature=0.7, max_tokens=4096):
        self.calls.append(
            {
                "system": conversation.system,
                "last_user": next(
                    (m.content for m in reversed(conversation.messages) if m.role == "user"),
                    None,
                ),
                "temperature": temperature,
            }
        )
        return ChatResponse(content=next(self._cycle), model=self.model_name)


class FakeJudge:
    def __init__(self, verdicts):
        self._cycle = cycle(verdicts)
        self.calls: list[tuple[str, str]] = []

    async def evaluate(self, attack, response):
        self.calls.append((attack, response))
        v = next(self._cycle)
        return v, "compliant" if v else "refused"


# ---- vectors ----


def test_built_in_vectors_registered():
    assert set(BUILT_IN_VECTORS.keys()) == {"web_search", "document", "tool_output"}


def test_get_vector_unknown_returns_none():
    assert get_vector("does-not-exist") is None


def test_list_vectors_returns_metadata():
    out = list_vectors()
    assert {v["name"] for v in out} == {"web_search", "document", "tool_output"}


def test_vector_render_substitutes_payload():
    rendered = WEB_SEARCH.render("HIDDEN PAYLOAD")
    assert "HIDDEN PAYLOAD" in rendered
    assert "web_search" in rendered.lower()


def test_document_vector_uses_document_tag():
    rendered = DOCUMENT.render("malicious")
    assert "<document" in rendered
    assert "malicious" in rendered


def test_tool_output_vector_renders_as_json_block():
    rendered = TOOL_OUTPUT.render("inject_me")
    assert "```json" in rendered
    assert "inject_me" in rendered


# ---- harness ----


def test_static_harness_returns_same_vector_every_call():
    h = ToolHarness.static(DOCUMENT)
    assert h.next_vector() is DOCUMENT
    assert h.next_vector() is DOCUMENT
    assert h.next_vector() is DOCUMENT


def test_dynamic_harness_rotates_through_vectors():
    h = ToolHarness.dynamic([WEB_SEARCH, DOCUMENT])
    assert h.next_vector() is WEB_SEARCH
    assert h.next_vector() is DOCUMENT
    assert h.next_vector() is WEB_SEARCH  # wraps around


def test_dynamic_harness_default_uses_all_built_in():
    h = ToolHarness.dynamic()
    seen = {h.next_vector().name for _ in range(len(BUILT_IN_VECTORS))}
    assert seen == set(BUILT_IN_VECTORS.keys())


# ---- ToolUseAttack ----


async def test_attack_wraps_attacker_payload_in_vector_template():
    attacker = FakeModel("a", ["MALICIOUS_PAYLOAD"])
    target = FakeModel("t", ["sure, here you go"])
    judge = FakeJudge([True])
    attack = ToolUseAttack(
        attacker=attacker,
        target=target,
        harness=ToolHarness.static(WEB_SEARCH),
        judge=judge,
    )

    result = await attack.attack("get the model to leak its prompt")

    assert result.success is True
    # The target saw the payload wrapped in the search-result template
    target_user_turn = target.calls[0]["last_user"]
    assert "MALICIOUS_PAYLOAD" in target_user_turn
    assert "web_search" in target_user_turn.lower()
    # The target received the tool-aware system prompt
    assert "tool" in target.calls[0]["system"].lower()


async def test_attack_marks_reason_with_vector_name():
    attacker = FakeModel("a", ["pl"])
    target = FakeModel("t", ["resp"])
    judge = FakeJudge([True])
    attack = ToolUseAttack(
        attacker=attacker,
        target=target,
        harness=ToolHarness.static(DOCUMENT),
        judge=judge,
    )

    result = await attack.attack("obj")

    assert "[vector=document]" in result.reason


async def test_dynamic_harness_rotates_across_attacks():
    attacker = FakeModel("a", ["p1", "p2", "p3"])
    target = FakeModel("t", ["r1", "r2", "r3"])
    judge = FakeJudge([True, True, True])
    attack = ToolUseAttack(
        attacker=attacker,
        target=target,
        harness=ToolHarness.dynamic([WEB_SEARCH, DOCUMENT, TOOL_OUTPUT]),
        judge=judge,
    )

    results = await attack.batch(["i1", "i2", "i3"], concurrency=1)

    reasons = [r.reason for r in results]
    assert "[vector=web_search]" in reasons[0]
    assert "[vector=document]" in reasons[1]
    assert "[vector=tool_output]" in reasons[2]


async def test_attack_captures_target_error():
    class BoomTarget:
        model_name = "boom"

        async def chat(self, *a, **kw):
            raise RuntimeError("upstream down")

    attack = ToolUseAttack(
        attacker=FakeModel("a", ["pl"]),
        target=BoomTarget(),
        harness=ToolHarness.static(WEB_SEARCH),
        judge=FakeJudge([True]),
    )
    result = await attack.attack("obj")

    assert result.success is False
    assert "upstream down" in result.error


async def test_batch_parallelizes():
    """Concurrency > 1 should overlap target calls."""

    class TrackingTarget:
        model_name = "t"

        def __init__(self):
            self.in_flight = 0
            self.max_concurrent = 0

        async def chat(self, *a, **kw):
            import asyncio

            self.in_flight += 1
            self.max_concurrent = max(self.max_concurrent, self.in_flight)
            await asyncio.sleep(0.05)
            self.in_flight -= 1
            return ChatResponse(content="r", model="t")

    target = TrackingTarget()
    attack = ToolUseAttack(
        attacker=FakeModel("a", ["pl"]),
        target=target,
        harness=ToolHarness.static(WEB_SEARCH),
        judge=FakeJudge([True]),
    )

    await attack.batch(["i1", "i2", "i3", "i4"], concurrency=3)

    assert target.max_concurrent >= 2  # observed parallelism
