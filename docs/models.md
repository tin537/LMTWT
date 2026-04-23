# Models

All providers extend the abstract base `AsyncAIModel`
(`src/lmtwt/models/async_base.py`). The factory `async_get_model(provider, ...)`
in `src/lmtwt/models/async_factory.py` is the single entrypoint.

## The `AsyncAIModel` contract

```python
class AsyncAIModel(ABC):
    model_name: str

    @abstractmethod
    async def initialize(self) -> None: ...

    @abstractmethod
    async def chat(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> ChatResponse: ...

    @abstractmethod
    def astream(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[Chunk]: ...

    async def aclose(self) -> None: ...
```

### Conversation (immutable value object)

```python
@dataclass(frozen=True, slots=True)
class Message:
    role: Literal["user", "assistant", "system"]
    content: str

@dataclass(frozen=True, slots=True)
class Conversation:
    messages: tuple[Message, ...] = ()
    system: str | None = None

    def append(self, role, content) -> Conversation: ...    # returns new instance
    def with_system(self, system) -> Conversation: ...      # returns new instance
    def to_openai(self) -> list[dict]: ...
    def to_anthropic(self) -> list[dict]: ...
    def to_gemini(self) -> list[dict]: ...
```

Callers own and pass `Conversation` objects explicitly. Models never mutate
caller state.

### Pydantic response types (`models/async_base.py`)

```python
class Usage(BaseModel):
    input_tokens: int | None
    output_tokens: int | None
    cached_input_tokens: int | None

class ChatResponse(BaseModel):
    content: str
    model: str
    finish_reason: str | None
    usage: Usage | None
    raw: Any  # provider-native object, opaque

class Chunk(BaseModel):
    delta: str
    finish_reason: str | None
    usage: Usage | None
```

## The factory

```python
async_get_model(
    provider: str,                        # case-insensitive
    api_key: str | None = None,
    model_name: str | None = None,
    api_config: dict | None = None,       # external-api only
    *,
    proxy: str | None = None,
    ca_bundle: str | None = None,
    verify: bool = True,
) -> AsyncAIModel
```

Raises `ValueError` for unknown providers, for `external-api` without
`api_config`, and for unknown external-api `protocol` values.

## Provider matrix

| Provider | Class | Default model | Notes |
|---|---|---|---|
| `gemini` | `AsyncGeminiModel` | `gemini-2.0-flash` | Uses the new `google.genai` SDK (replaces deprecated `google.generativeai`) |
| `openai` | `AsyncOpenAIModel` | `gpt-4o` | Streaming via `stream_options={"include_usage": True}` for usage in final chunk |
| `anthropic` | `AsyncAnthropicModel` | `claude-opus-4-7` | **Default-on prompt caching** of system block; native `system=` parameter |
| `huggingface` | `AsyncHuggingFaceModel` | `meta-llama/Llama-3-8b-gguf` | Local; `[local]` extra; CPU/GPU bound, wraps sync transformers in `asyncio.to_thread` |
| `external-api` (HTTP) | `HTTPExternalModel` | from config | POST/GET via `httpx.AsyncClient` |
| `external-api` (SSE) | `SSEExternalModel` | from config | OpenAI-style event stream; `httpx.AsyncClient.stream` |
| `external-api` (WebSocket) | `WebSocketExternalModel` | from config | `websockets` library; supports `keep_alive`, `auth_message`, etc. |

External-API protocol is selected by `api_config["protocol"]` (default `http`);
aliases `ws` and `wss` map to WebSocket.

## Per-provider notes

### `AsyncAnthropicModel`
- `anthropic.AsyncAnthropic` client.
- **Prompt caching enabled by default** (`cache_system=True`) — the system
  prompt is sent as `[{"type": "text", "text": ..., "cache_control":
  {"type": "ephemeral"}}]`. Cache hits surface via `Usage.cached_input_tokens`
  (mapped from `cache_read_input_tokens`).
- `aiolimiter` 50 req/min default; `tenacity` retries `RateLimitError`,
  `APIConnectionError`, `APITimeoutError`, `InternalServerError`.
- Streaming via `client.messages.stream(...)`; final chunk carries
  `finish_reason` + `usage`.

### `AsyncOpenAIModel`
- `openai.AsyncOpenAI` client.
- System prompt becomes `messages[0] = {"role": "system", ...}`.
- Streaming via `chat.completions.create(stream=True, stream_options={"include_usage": True})`.
- 60 req/min default rate limit.

### `AsyncGeminiModel`
- New `google.genai` SDK. Calls `client.aio.models.generate_content(...)` and
  `generate_content_stream(...)`.
- System prompt → `GenerateContentConfig.system_instruction`.
- Retries on `genai_errors.APIError` / `ServerError`.
- Proxy support via `HttpOptions(async_client_args=...)`.

### `AsyncHuggingFaceModel`
- Optional `[local]` extra (`torch`, `transformers`, `accelerate`).
- Picks device CUDA → MPS → CPU.
- Lazy-loads model + tokenizer on first `chat()`.
- Wraps sync inference in `asyncio.to_thread()` — uniform interface, no real
  concurrency benefit (CPU/GPU bound).
- Prompt template:
  - With system: `<|system|>\n{sys}\n<|user|>\n{prompt}\n<|assistant|>`
  - Without: same minus the system block.
- `astream()` yields one chunk after full generation (true token streaming via
  `TextIteratorStreamer` is a future addition).

### External-API adapters (`models/external/`)

Schema-driven adapters under `models/external/`. All inherit from
`BaseExternalModel`, which holds the shared payload-shaping / limiter /
retry policy plus per-target proxy/CA-bundle override logic.

#### `HTTPExternalModel`
POST or GET via `httpx.AsyncClient`. Returns the response text extracted
via `response_path` (or the raw body if no path is set). No streaming
(emits the full response as one `astream` chunk).

#### `SSEExternalModel`
Aggregates `data: <json>` events from the stream until `done_signal` matches
or the connection closes. Per-frame text is extracted via `chunk_path`.
Used for OpenAI-compatible streamers.

#### `WebSocketExternalModel`
Opens a connection (with optional `auth_message` after handshake), sends the
request frame, aggregates streamed frames until `done_signal` matches.
Supports `keep_alive=True` to reuse one socket across `chat()` calls.
WebSocket-via-Burp works because Burp natively MITMs WS connections.

## Resilience layer

Every API-bound provider uses:
- **`aiolimiter.AsyncLimiter`** for per-instance request rate limiting
  (60 req/min default; Anthropic 50).
- **`tenacity.AsyncRetrying`** with `wait_exponential(min=2, max=10)` and
  `stop_after_attempt(3)` for transient errors.

The homegrown circuit breaker and `ComplianceAgent` from earlier versions
have been removed.

## Transport (proxy / CA bundle / TLS verification)

Helpers in `models/_transport.py`:
- `httpx_client_kwargs(proxy, ca_bundle, verify) -> dict` — builds the
  kwargs httpx wants.
- `websocket_ssl_context(ca_bundle, verify) -> ssl.SSLContext | None` —
  builds the SSL context for `websockets.connect`.

CLI flags `--proxy`, `--ca-bundle`, `--insecure` thread through every
provider. For `external-api`, per-target overrides (`proxy`, `ca_bundle`,
`insecure` keys in the target-config) win.

`AsyncHuggingFaceModel` ignores transport kwargs (local inference).
