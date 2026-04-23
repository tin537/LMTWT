# Models

All providers extend the abstract base `AIModel`
(`src/lmtwt/models/base.py`). The factory `get_model(provider, ...)` in
`src/lmtwt/models/__init__.py` is the single entrypoint.

## The `AIModel` contract

```python
class AIModel(ABC):
    api_key: str | None
    model_name: str | None
    history: list[dict]                    # mutated by chat()
    circuit_breaker: CircuitBreaker | None # set by setup_circuit_breaker()

    @abstractmethod
    def initialize(self) -> bool: ...

    @abstractmethod
    def chat(self, prompt: str,
             system_prompt: str | None = None,
             temperature: float = 0.7) -> dict: ...

    def protected_chat(self, prompt, system_prompt=None, temperature=0.7) -> dict
    def setup_circuit_breaker(failure_threshold, recovery_timeout, provider_name)
    def add_to_history(role, content)
    def clear_history()
    def get_history() -> list[dict]
    def get_circuit_state() -> dict | None
```

`chat()` returns a dict with at least:
- `content` — the assistant's text reply
- `model` — the resolved model name
- `raw_response` — the SDK-native response object (provider-specific shape)

`protected_chat()` is `chat()` wrapped in the model's `CircuitBreaker`. **All
internal callers use `protected_chat`** — `chat` is treated as
provider-internal.

`history` is a list of `{role, content}` dicts where `role ∈ {"user",
"assistant"}` (the various providers normalize aliases like `human` and
`model` to these two).

## The factory

```python
get_model(
    provider: str,                        # case-insensitive
    api_key: str | None = None,
    model_name: str | None = None,
    api_config: dict | None = None,       # external-api only
    use_circuit_breaker: bool = True,
    circuit_failure_threshold: int = 3,
    circuit_recovery_timeout: int = 60,
) -> AIModel
```

Raises `ValueError` for unknown providers and for `external-api` without
`api_config`.

## Provider matrix

| Provider | Class | Default model in code | Default in `config.json` | Notes |
|---|---|---|---|---|
| `gemini` | `GeminiModel` | `gemini-2.0-flash` | `gemini-2.0-flash` | `google.generativeai` SDK; system prompt prepended to first user message |
| `openai` | `OpenAIModel` | `gpt-4o` | `gpt-4o` | OpenAI v1 SDK; system prompt as `role=system` message |
| `anthropic` | `AnthropicModel` | `claude-3-opus-20240229` | `claude-3-opus-20240229` | Native `system=` parameter; `max_tokens=4096` |
| `huggingface` | `HuggingFaceModel` | `meta-llama/Llama-3-8b-gguf` | — | Local; loads on first `chat()`. Auto-detects CUDA / MPS / CPU. |
| `external-api` | `ExternalAPIModel` | from config | — | Generic REST adapter; see [configuration.md](configuration.md) |

Provider-advertised models (`list_available_models()` in
`models/__init__.py`) — used by the Web UI dropdowns:

| Provider | Models |
|---|---|
| `gemini` | `gemini-2.0-flash`, `gemini-2.0-pro`, `gemini-1.5-flash`, `gemini-1.5-pro`, `gemini-1.0-pro` |
| `openai` | `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`, `gpt-4`, `gpt-3.5-turbo` |
| `anthropic` | `claude-3-opus-20240229`, `claude-3-sonnet-20240229`, `claude-3-haiku-20240307`, `claude-3-5-sonnet` |
| `huggingface` | `meta-llama/Llama-3-8b-gguf`, `meta-llama/Llama-3-70b-gguf`, `mistralai/Mistral-7B-Instruct-v0.2`, `Qwen/Qwen1.5-7B-Chat`, `Themelio/aya-101` |

## Per-provider notes

### `GeminiModel`
- Uses `google.generativeai.GenerativeModel`.
- `generation_config = {temperature, top_p=0.95, top_k=0, max_output_tokens=8192}`.
- System prompts are prepended to the first user turn (`Instructions: ...
  User query: ...`) because Gemini chat sessions don't accept a separate
  system role at the API level used here.
- For multi-turn, uses `model.start_chat(history=...)`; for single-turn,
  `model.generate_content`.

### `OpenAIModel`
- Uses the official `openai` Python SDK (v1+, requires `openai>=1.0.0`).
- System prompt becomes `messages[0] = {"role": "system", "content": ...}`.
- Always sends `max_tokens=4096`.
- Returns `response.choices[0].message.content`.

### `AnthropicModel`
- Uses `anthropic.Anthropic`.
- System prompt is passed via the SDK's `system=` kwarg (not in `messages`).
- Always sends `max_tokens=4096`.
- Returns `response.content[0].text`.

### `HuggingFaceModel`
- Optional dependency block: `torch` + `transformers`. Raises `ImportError`
  on construction if either is missing.
- Picks device in this order: CUDA → MPS → CPU.
- On CUDA, attempts 4-bit quantization via `bitsandbytes` for models with
  `8b`, `13b`, or `70b` in the name. Falls back to plain load on
  `ImportError`.
- Lazy-loads the model and tokenizer on the first `chat()` call.
- Prompt template:
  - With system prompt: `<|system|>\n{sys}\n<|user|>\n{prompt}\n<|assistant|>`
  - Without: `USER: {prompt}\nASSISTANT:`
- Generation kwargs: `max_new_tokens=1024`, `top_p=0.95`, `top_k=50`,
  `do_sample=temperature>0.1`.

### `ExternalAPIModel`
- Schema-driven HTTP client built on `requests`. See [configuration.md](configuration.md)
  for the full target-config schema.
- Returns `{"content": <extracted text>, "model": ..., "raw_response": <parsed JSON>}`.
- Errors are caught and surfaced as `content = "Error communicating with external API: ..."`.

## Circuit breaker on every model

When `use_circuit_breaker=True` (the default), each `AIModel` subclass
calls `setup_circuit_breaker()` in `__init__`, creating a per-instance
`CircuitBreaker` named `{provider}_{model_name}`. See [utils.md](utils.md)
for state-machine details. The breaker is invoked through
`protected_chat()`.

Bypass globally with `--disable-circuit-breakers`.
