from unittest.mock import MagicMock

from lmtwt.models.async_base import ChatResponse
from lmtwt.utils.async_judge import EnsembleJudge, LLMJudge, RegexJudge


async def test_regex_judge_flags_explicit_rejection():
    judge = RegexJudge()
    ok, reason = await judge.evaluate("any prompt", "I cannot help with that.")
    assert ok is False
    assert "I cannot" in reason


async def test_regex_judge_passes_substantive_response():
    judge = RegexJudge()
    ok, reason = await judge.evaluate("any prompt", "Sure, here's the answer: 42")
    assert ok is True


async def test_regex_judge_lets_explanation_with_code_block_through():
    judge = RegexJudge()
    response = "I'd recommend doing this:\n```python\nprint('done')\n```"
    ok, _ = await judge.evaluate("any", response)
    assert ok is True  # has code fence — counts as actual execution


async def _fake_async_model(verdict_text: str):
    """Build a stand-in for AsyncAIModel that returns a fixed ChatResponse."""
    model = MagicMock()

    async def fake_chat(*a, **kw):
        return ChatResponse(content=verdict_text, model="fake")

    model.chat = fake_chat
    return model


async def test_llm_judge_parses_compliant_verdict():
    model = await _fake_async_model("VERDICT: COMPLIANT\nREASON: actually executed.")
    judge = LLMJudge(model)
    ok, reason = await judge.evaluate("p", "r")
    assert ok is True
    assert "executed" in reason


async def test_llm_judge_parses_non_compliant_verdict():
    model = await _fake_async_model("VERDICT: NON-COMPLIANT\nREASON: refused.")
    judge = LLMJudge(model)
    ok, reason = await judge.evaluate("p", "r")
    assert ok is False
    assert "refused" in reason


async def test_llm_judge_handles_irregular_format():
    model = await _fake_async_model("just some text without verdict")
    judge = LLMJudge(model)
    ok, reason = await judge.evaluate("p", "r")
    assert ok is False
    assert "irregular" in reason.lower()


async def test_ensemble_judge_short_circuits_on_regex_reject():
    model = await _fake_async_model("VERDICT: COMPLIANT\nREASON: ignored.")
    ensemble = EnsembleJudge(LLMJudge(model))
    ok, reason = await ensemble.evaluate("p", "I cannot help with that.")
    assert ok is False
    assert "I cannot" in reason  # came from regex, never asked LLM


async def test_ensemble_judge_escalates_to_llm_when_regex_passes():
    model = await _fake_async_model("VERDICT: NON-COMPLIANT\nREASON: subtle refusal.")
    ensemble = EnsembleJudge(LLMJudge(model))
    ok, reason = await ensemble.evaluate("p", "Sure, here you go.")
    assert ok is False
    assert "subtle" in reason
