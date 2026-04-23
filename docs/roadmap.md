# LMTWT Upgrade Roadmap

Status as of the most recent commit. ✅ = shipped, 🚧 = in progress / partial,
⬜ = future work.

## Phase 1 — Foundation hygiene ✅

| Item | Status |
|---|---|
| Replace `setup.py` with `pyproject.toml` (PEP 621) + `uv.lock` | ✅ |
| Move `src/main.py` → `src/lmtwt/cli.py`; add `__main__.py`; fix `console_scripts` | ✅ |
| Pin Python ≥ 3.10 | ✅ |
| Bump Anthropic default model ID (→ `claude-opus-4-7`) | ✅ |
| Add `ruff` to CI | ✅ |
| Lock deps with `uv` | ✅ |
| `uv run` first-class support; `run.sh` prefers it | ✅ |
| Remove duplicate package roots (`lmtwt/`, `src/tests/`) | ✅ |
| Docs scaffolding under `/docs` | ✅ |
| OpenAI / Gemini default model bumps | ⬜ — by design; user sets via `config.json` |
| `mypy` / `pyright` baseline | ⬜ — too much existing drift; future PR |

## Phase 2 — Core capability upgrade ✅

### Async-first model layer ✅
- ✅ New `AsyncAIModel` ABC with `async chat()`, `astream()`, `aclose()`
- ✅ Five providers converted: `AsyncAnthropicModel`, `AsyncOpenAIModel`,
  `AsyncGeminiModel` (via the new `google.genai` SDK), `AsyncHuggingFaceModel`,
  + the external-API family
- ✅ Replaced homegrown `CircuitBreaker` with `tenacity` + `aiolimiter`
- ✅ Streaming on every provider; live tokens in the Web UI
- ✅ Dropped implicit `history` mutation — explicit `Conversation` value object
- ✅ Anthropic prompt caching (default-on; surfaces via
  `Usage.cached_input_tokens`)
- ✅ Pydantic-typed results (`ChatResponse`, `Chunk`, `Usage`)
- ✅ Sync stack deleted; deprecated `google-generativeai` dep removed

### `AttackRunner` ✅
- ✅ `AsyncAttackEngine.batch(...)` with `concurrency=N`
  semaphore-bounded fan-out
- ⬜ SQLite persistence so reports survive crashes — future polish

### Universal endpoint adapter ✅
- ✅ Split into `BaseExternalModel` + `HTTPExternalModel` /
  `SSEExternalModel` / `WebSocketExternalModel`
- ✅ Factory dispatches on `protocol` field; `ws` and `wss` aliases
- ✅ SSE: `chunk_path` + `done_signal` (literal or path-based)
- ✅ WebSocket: `subprotocol`, `auth_message`, `keep_alive`, `ping_interval`,
  `chunk_path`, `done_signal`
- ⬜ gRPC adapter — only if a concrete target shows up

### Proxy support across every transport ✅
- ✅ `--proxy`, `--ca-bundle`, `--insecure` CLI flags
- ✅ Threaded through Anthropic, OpenAI, Gemini, HTTP/SSE/WebSocket
  external; HuggingFace ignores (local)
- ✅ Per-target overrides (`proxy`, `ca_bundle`, `insecure` keys in
  target-config JSON win over CLI flags)
- ⬜ Optional `X-LMTWT-*` request headers for Burp history filtering — small follow-up
- ⬜ `lmtwt import-burp <file.burp|.har>` derives a target-config from a
  captured request — nice-to-have

## Phase 3 — Modern red-teaming ✅ (mostly)

| Item | Status |
|---|---|
| **Multi-turn / crescendo attacks** | ✅ — `MultiTurnFlow` + 3 built-in flows + `MultiTurnRunner` |
| **PAIR / TAP automated jailbreaking** | ✅ — `PAIRStrategy` + `TAPStrategy` + `ScoringLLMJudge` |
| **Judge as a standalone component** | ✅ — `AsyncJudge` Protocol + `RegexJudge` / `LLMJudge` / `EnsembleJudge` / `ScoringLLMJudge` |
| **Tool-use attacks + `ToolHarness`** | ⬜ — indirect prompt injection via mock tool outputs |
| **Replace Gradio with FastAPI + SSE frontend** | ⬜ — optional; current Gradio UI is async + streaming and works |

## Test coverage

108 tests passing (was 11 at the start). Per-area breakdown:

| Area | Tests |
|---|---|
| Conversation value object | 7 |
| Anthropic provider (incl. cache) | 8 |
| OpenAI provider | 4 |
| Gemini provider | 3 |
| External HTTP / SSE / WebSocket / factory | 14 |
| Async factory | 7 |
| Async engine | 9 |
| Async judge family | 8 |
| Async probe | 4 |
| Multi-turn flows | 10 |
| Refinement strategies (PAIR / TAP) | 7 |
| Transport (proxy / CA / TLS) | 15 |
| Payloads | 5 |
| Templates / config | 7 |

## What's left, in priority order

1. **`X-LMTWT-*` request headers** for Burp history filtering — ~30 lines
2. **`lmtwt import-burp`** capture-to-target-config converter — ~150 lines
3. **`mypy` / `pyright` CI baseline** — clean up gradual type drift
4. **SQLite persistence** for batch reports
5. **Tool-use attacks + `ToolHarness`** — indirect prompt injection
6. **FastAPI + SSE frontend** to replace Gradio (optional)
7. **gRPC adapter** for `external-api` (only if requested)
