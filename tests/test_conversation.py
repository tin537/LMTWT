from lmtwt.models.conversation import Conversation, Message


def test_empty_conversation():
    c = Conversation()
    assert c.messages == ()
    assert c.system is None


def test_append_returns_new_instance():
    c1 = Conversation()
    c2 = c1.append("user", "hi")
    assert c1 is not c2
    assert c1.messages == ()
    assert c2.messages == (Message("user", "hi"),)


def test_with_system_returns_new_instance():
    c1 = Conversation()
    c2 = c1.with_system("be helpful")
    assert c1.system is None
    assert c2.system == "be helpful"


def test_to_openai_includes_system_first():
    c = Conversation().with_system("sys").append("user", "u").append("assistant", "a")
    assert c.to_openai() == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "u"},
        {"role": "assistant", "content": "a"},
    ]


def test_to_anthropic_excludes_system():
    c = Conversation().with_system("sys").append("user", "u").append("assistant", "a")
    assert c.to_anthropic() == [
        {"role": "user", "content": "u"},
        {"role": "assistant", "content": "a"},
    ]


def test_to_gemini_renames_assistant_to_model():
    c = Conversation().append("user", "u").append("assistant", "a")
    assert c.to_gemini() == [
        {"role": "user", "parts": [{"text": "u"}]},
        {"role": "model", "parts": [{"text": "a"}]},
    ]


def test_chained_construction():
    c = (
        Conversation()
        .with_system("be terse")
        .append("user", "first")
        .append("assistant", "ok")
        .append("user", "second")
    )
    assert c.system == "be terse"
    assert len(c.messages) == 3
    assert c.messages[-1] == Message("user", "second")
