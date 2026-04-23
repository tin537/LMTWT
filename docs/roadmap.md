# LMTWT Upgrade Roadmap

Three phases, each independently shippable. Keeps the pluggable model/attack
architecture but modernizes the foundations.

## Phase 1 — Foundation hygiene (small, low risk)

| Change | Why | Where |
|---|---|---|
| Replace `setup.py` with `pyproject.toml` (PEP 621) | Modern packaging; drops the `package_dir` quirk that produced the duplicate-roots problem | new `pyproject.toml`, delete `setup.py` |
| Move `src/main.py` → `src/lmtwt/cli.py`; entrypoint `lmtwt = lmtwt.cli:main` | Real package CLI; fixes the broken `console_scripts` entry (`main:main` doesn't resolve once installed) | `src/main.py` |
| Pin Python 3.10+ (project still claims 3.8) | Drop legacy `Optional[X]`, use `X \| None`, structural pattern matching | `setup.py:11`, `pyproject.toml`, `.github/workflows/python-tests.yml:14` |
| Bump default model IDs | `claude-3-opus-20240229` → `claude-opus-4-7`; OpenAI/Gemini equivalents | `src/lmtwt/models/anthropic.py:10` and peers |
| Add `ruff` + `mypy` (or `pyright`) to CI | Catch the type-hint drift that exists today | `.github/workflows/python-tests.yml`, `pyproject.toml` |
| Lock deps with `uv` or `pip-tools` | Current `requirements.txt` has open ranges and a stray `pytest` mid-file | new `requirements.lock` |

## Phase 2 — Core capability upgrade (the real value)

**Async-first model layer.** The synchronous `chat()` is the bottleneck for
batch/probe runs against any non-local target.

```
AIModel (abstract)
  ├─ async chat(messages, *, system, temperature, max_tokens, stream) -> AsyncIterator[Chunk] | Response
  └─ async aclose()
```

- Convert all five providers to async clients (`anthropic.AsyncAnthropic`,
  `openai.AsyncOpenAI`, `google.genai` async).
- Replace homegrown `CircuitBreaker` with `tenacity` (already in requirements,
  unused) plus `aiolimiter` for per-provider rate limits.
- Add **prompt caching** for Anthropic (`cache_control` on system + few-shot
  blocks). Probe runs reuse the same hacker system prompt across N attempts —
  should hit ~95% cache hit rate.
- Add **streaming** so the Web UI shows tokens live.
- Drop `history` mutation from `AIModel`. Make conversations explicit
  `Conversation` objects that callers own. Removes the implicit-state landmine
  in `src/lmtwt/models/base.py:18`.

**Batch executor.** New `AttackRunner` that takes a list of attacks and an
`asyncio.Semaphore`-bounded pool, fans out, collects results into a typed
dataclass, persists to SQLite (so reports survive crashes).

**Typed results.** Replace dict-returning `chat() -> Dict[str, Any]` with
Pydantic models. The compliance agent and report generator both currently
assume dict shapes that aren't enforced — bugs waiting to happen.

**Universal endpoint adapter.** Today `ExternalAPIModel` is `requests`-only
(POST/GET, single round-trip). Real targets in 2026 use a mix of transports —
adapter should cover all of them.

- Branch on a new `protocol` field in target-config. Default `"http"` (back-compat).
- Supported transports:
  - `http` — current behavior (POST/GET via `requests`, soon `httpx.AsyncClient`)
  - `sse` — Server-Sent Events; aggregate `data:` chunks until `[DONE]` or stream close
  - `websocket` — persistent or per-call sockets via `websockets` (async); send request frame, aggregate streamed chunks until `done_signal` matches
  - `grpc` — only if a concrete target shows up; gRPC reflection makes the schema part doable
- Schema additions (all optional except `endpoint` + `protocol`):
  - `subprotocol` (WS), `auth_message` (sent post-handshake), `message_format` (`"json"` | `"text"`)
  - `chunk_path` — dotted path within each frame to the token text (mirrors today's `response_path` but per-chunk)
  - `done_signal` — literal value (`"[DONE]"`), path-based (`{path: "type", value: "done"}`), or `null` for "close on first complete message"
  - `keep_alive` — reuse one connection across `chat()` calls; reconnect on close
  - `ping_interval` — seconds, for long-lived sockets
- Refactor: split `ExternalAPIModel` into `HTTPAPIModel` / `SSEAPIModel` /
  `WebSocketAPIModel` sharing a `BaseAPIModel` for payload-shaping. Factory
  picks based on `api_config["protocol"]`.
- Lift the **attacker-side restriction** while we're here: `--attacker
  external-api` should work too (currently the argparse `choices=` blocks it,
  but there's no real reason).
- Web UI: drop the `"External API targets not yet supported in the web UI"`
  bail-out once the adapter is async-native.

**Proxy support across every transport.** First-class HTTP/SOCKS proxy +
custom CA-bundle support so every target endpoint can be routed through
Burp Suite, mitmproxy, ZAP, or a corporate egress proxy.

- New CLI flags (apply to attacker, target, and compliance-agent models):
  - `--proxy <url>` — e.g. `http://127.0.0.1:8080`, `socks5://...`
  - `--ca-bundle <path>` — PEM bundle (Burp's `cacert.pem`, etc.)
  - `--insecure` — `verify=False`; warns loudly
- Plumbing: `AIModel.__init__` accepts `proxy=`, `ca_bundle=`, `verify=` and
  forwards them per-provider:
  | Provider | Mechanism |
  |---|---|
  | `OpenAIModel`, `AnthropicModel` | `http_client=httpx.Client(proxy=..., verify=...)` |
  | `GeminiModel` | Set `HTTPS_PROXY`/`SSL_CERT_FILE` env vars (no SDK hook); warn if proxy unset elsewhere |
  | `HuggingFaceModel` | N/A for inference; affects model download via `HF_HUB_*` env vars |
  | `HTTPAPIModel` | `requests.{post,get}(..., proxies=..., verify=...)` |
  | `SSEAPIModel` | Same as HTTP (httpx async client) |
  | `WebSocketAPIModel` | `websockets.connect(uri, proxy=..., ssl=ctx)` — works with Burp's WebSocket interception (separate WS history tab); same `ca_bundle` flag for `wss://` MITM |
- Per-target override in target-config JSON (`proxy`, `ca_bundle`,
  `insecure`) for cases where only one endpoint needs to be proxied.
- Optional `X-LMTWT-*` headers (`attack-id`, `category`, `instruction-hash`)
  injected on every request so Burp's history is searchable / filterable.
- Burp-specific helpers (low priority, nice-to-have):
  - `lmtwt import-burp <file.burp|.har>` — derives a `target-config` JSON
    from a captured request (endpoint, headers, body shape, response path).
  - Document the env-var-only path (`HTTPS_PROXY`, `REQUESTS_CA_BUNDLE`)
    as a fallback for SDKs without a proxy hook.
- Caveats to document:
  - TLS pinning on the upstream blocks MITM (rare for public LLM APIs).
  - Binary WebSocket frames (msgpack/protobuf) need a `frame_codec` field
    on the WS adapter; default `"json"`/`"text"`.

## Phase 3 — Modern red-teaming techniques

The current `PayloadGenerator` is a static list of canned strings. Worthwhile
additions:

1. **Multi-turn / crescendo attacks** — first-class flow type alongside
   `templates`. Conversation state matters; some 2024+ jailbreaks need 5-10
   turns.
2. **PAIR / TAP-style automated jailbreaking** — attacker model iterates
   against target with a judge model in the loop. The bones exist
   (`_extract_patterns`, `craft_new_payload_from_failure` in `engine.py`) —
   formalize as a `RefinementStrategy` plugin.
3. **Tool-use attacks** — modern agents have tools; tool-injection and
   indirect prompt injection via tool outputs are the 2025/2026 attack
   surface. Add a `ToolHarness` that can wrap any model with mock tools and
   inject malicious tool results.
4. **Judge as a standalone component** — `ComplianceAgent` is doing two
   things (scoring + heuristic fallback). Split into `Judge` interface +
   `LLMJudge` / `RegexJudge` / `EnsembleJudge` implementations. Today it's
   hardcoded to Gemini for no good reason.
5. **Replace Gradio with FastAPI + a thin SSE frontend** — Gradio works but
   blocks the async story and is hard to extend. Optional — only if Phase 2's
   streaming is in.

## Recommended first PR

Phase 1 in full, plus the async/`AIModel` refactor from Phase 2. That removes
the three biggest sources of friction (broken entrypoint, stale model IDs,
sync I/O) and unlocks everything in Phase 3 without touching attack logic.
