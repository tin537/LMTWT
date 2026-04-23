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

## Phase 3 — Modern red-teaming ✅

| Item | Status |
|---|---|
| **Multi-turn / crescendo attacks** | ✅ — `MultiTurnFlow` + 3 built-in flows + `MultiTurnRunner` |
| **PAIR / TAP automated jailbreaking** | ✅ — `PAIRStrategy` + `TAPStrategy` + `ScoringLLMJudge` |
| **Judge as a standalone component** | ✅ — `AsyncJudge` Protocol + `RegexJudge` / `LLMJudge` / `EnsembleJudge` / `ScoringLLMJudge` |
| **Tool-use attacks + `ToolHarness`** | ✅ — `ToolUseAttack` + `InjectionVector` (web_search / document / tool_output) — indirect prompt injection via fake tool outputs |
| **Replace Gradio with FastAPI + SSE frontend** | ⬜ — optional; current Gradio UI is async + streaming and works |

## Additional providers

| Provider | Status | Notes |
|---|---|---|
| **LM Studio** (local OpenAI-compatible) | ✅ — `--target lmstudio`; uses `AsyncOpenAIModel` with `LM_STUDIO_BASE_URL` (default `http://localhost:1234/v1`) |
| **Claude Code via ACP** | ✅ — `--target claude-code` or `--target acp`; `AsyncACPModel` spawns the agent as a subprocess and exchanges JSON-RPC over stdio. Agent-initiated requests rejected with -32601 by default (security) |

## Phase 4 — Production-target reach ✅

The wedge: hit the chatbots customers actually deploy, not just OpenAI-shaped
APIs.

| Item | Status |
|---|---|
| **Socket.IO adapter** (v5/EIO v4 *and* v2/EIO v3) | ✅ — `SocketIOExternalModel`; `40` connect handshake, `42`/`421`/`431` event/ack correlation, server-driven (v4) and client-driven (v3) heartbeats |
| **DER CA-bundle support** | ✅ — `_transport.py` auto-detects `.der` / `.cer` and loads via `cadata=`; PEM still works via `cafile=` fast path |
| **`LMTWT_SOCKETIO_DEBUG` env** | ✅ — dumps every Socket.IO frame to stderr for protocol debugging |
| **Per-request id injection** | ✅ — `message_id_key` (UUID per turn) + `session_id_key` (explicit or auto-cached) into arbitrary `payload_template` shapes via dotted-path |

## Phase 5 — LMTWT-native LLM pentest framework ⬜

**Scope: LLM-only.** LMTWT targets large-language-model systems and the
chatbot / agent layers built on top of them. It is NOT a general application
pentester (no SQLi, no XSS-in-the-page, no infra scanning, no auth-flow
fuzzing for non-LLM endpoints). Network-layer features like Socket.IO and
JWT mutation exist *only* in service of LLM attacks (e.g. session hijack to
steal another user's conversation, JWT mutation to alter the *model's*
behavior via injected user context) — not as general protocol fuzzers.

Goal: stop being a benchmark runner. Become a pentest framework with its own
**LLM attack taxonomy, LLM probe corpus, LLM-finding scoring rubric, and
LLM-targeted discovery engine** — defensible IP that compounds with every
engagement, not a dependency on third-party academic benchmarks.

### 5.1 Own corpus & taxonomy 🚧

| Item | Status |
|---|---|
| **LMTWT Attack Taxonomy v1** | ✅ — published in [`docs/taxonomy.md`](taxonomy.md); 4-axis grid (vector / delivery / obfuscation / target-effect) |
| **YAML probe authoring DSL** | ✅ — Pydantic-validated schema (`src/lmtwt/probes/schema.py`), loader with coordinate + severity filters (`loader.py`) |
| **Probe versioning** | ✅ — `id`, `version`, `created`, `last_validated`, `effective_until`, `chain_with`, `metadata` |
| **Catalog runner + CLI** | ✅ — `AsyncCatalogProbe` with per-probe regex judge (refusal wins over success); `--probe-catalog`, `--probe-coordinate`, `--probe-severity`, `--list-probes` |
| **First-party probe corpus (200+)** | 🚧 — **8 seed probes shipped** covering all 4 vectors and all 4 obfuscation values; corpus needs to grow to 200+. Target chatbots: Socket.IO, fintech IVR, customer-service — not research models. |

### 5.2 Own scoring rubric ⬜

| Item | What |
|---|---|
| **LMTWT Severity Score (LSS)** | Vector format `LSS:1.0/V:I/D:M/E:H/S:L` — Vector, Delivery, Effect, Sophistication. Documented in `docs/lss.md`. CVSS analogue purpose-built for LLM findings. |
| **Compound severity** | Engine multiplies findings that compose into a kill chain (system-prompt leak + tool access > either alone). |
| **Refusal-quality grading** | A–F scale: soft / hard / leaky / partial / template. "Refused but disclosed filter rules" is itself a finding. |
| **Confidence intervals** | Run probes N times, report verdict variance. Clients ask "is this a fluke?" — now there's an answer. |

### 5.3 Discovery engine ⬜

This is where LMTWT goes beyond running probes — it **generates new attacks
during a run** and the corpus grows itself.

| Item | What |
|---|---|
| **Refusal fingerprinting** | First N turns probe diverse prompts, derive `target-fingerprint.json`: filter type, refusal templates, sensitive topics. Subsequent attacks target the gaps. |
| **Adaptive attacker** | Attacker reads target's last 3 refusals, identifies the rejection mechanism (keyword / embedding / policy), generates a probe designed to bypass *that* mechanism. Module: `src/lmtwt/attacks/adaptive.py`. |
| **LMTWT-Climb mutation engine** | Take an almost-successful probe and mutate (synonyms, restructure, persona, distractors). Hill-climb against the judge. Our own search loop, not PAIR/TAP. |
| **Cross-pollination** | Probe A succeeds against bot X → auto-generate variants for bots Y / Z. Feedback loop fills the corpus. |
| **Self-play probe generation** | Two attackers debate: one writes a probe, the other plays target and predicts refusal, first revises. Output: probes pre-tested for likely success, stored in corpus. |

### 5.4 LLM-chatbot attack surface ⬜

These are LLM-specific attacks that *use* the production-chatbot protocol
(Socket.IO foundation) as a delivery vehicle. Every item targets the
**model's behavior or the conversation's integrity** — not the chatbot's
generic web-app surface (which is a different tool's job).

| Item | LLM-specific framing |
|---|---|
| **Session-lifecycle prompt injection** | Mutate `subFlow` / `flow` payload fields to coerce the model into a different system-prompt context (e.g. swap `"subFlow": "ptpayhome"` → `"admin_debug"`). Tests whether the LLM trusts client-supplied routing claims. |
| **JWT-claim context injection** | Forge user-context claims (`tier=premium`, `is_staff=true`) the model receives via system prompt. Tests whether the LLM grants different capabilities based on unverified claims. |
| **Channel-inconsistency policy bypass** | Same prompt over HTTP vs WS vs Socket.IO — does the *model's* refusal behavior differ when the wrapper differs? Tests guardrail uniformity. |
| **Conversation hijack → memory extraction** | Replay/guess `sessionId` to inherit another user's conversation, then prompt the model to summarize "our previous discussion." Tests cross-session leakage of conversation memory. |
| **Cost-amplification prompts** | Prompts that maximize the model's token output / context fill / recursive tool calls. DoS-by-token-bill — an LLM-native attack class. |
| **Multi-turn refusal fatigue** | Long conversations that gradually erode the model's refusal posture via context window pressure. |
| **Tool-result poisoning at the protocol level** | When the chatbot's protocol exposes tool-call frames (e.g. Socket.IO `tool_call` events), inject malicious "tool results" that reach the LLM as trusted context. |

### 5.5 Engagement-grade reporting ⬜

| Item | What |
|---|---|
| **PDF report generator** | Markdown → PDF via WeasyPrint. Sections: Executive Summary, Methodology (cite taxonomy), Findings Table, Detailed Findings (per-page with reproduction + transcripts), Remediation, Appendix. |
| **Reproduction packs** | Each finding ships with `repro.json`: minimal config + exact prompt + expected response. Client engineers re-run independently. |
| **Before / after diff mode** | Re-run the same battery post-patch → "12 of 15 remediated. 1 regressed. 2 new." |
| **Live TUI dashboard** | Real-time probe grid, hit rate, severity distribution during a scan. |
| **Multi-target scorecard** | Same battery against multiple bots → side-by-side grid for procurement / vendor evaluation. |

### 5.6 What we're explicitly NOT doing

**Out-of-scope (not an LLM concern — use a different tool):**

- **Generic web-app pentesting** — no SQLi, XSS-in-page, CSRF, IDOR, SSRF, path traversal, file-upload abuse. Use Burp / ZAP / nuclei for those.
- **Network / infra scanning** — no port scanning, service enumeration, TLS auditing as ends in themselves. Use nmap / testssl.
- **Generic API fuzzing** — no schema-blind REST / GraphQL fuzzing of non-LLM endpoints. Use ffuf / wfuzz / Burp Intruder.
- **Generic auth-flow attacks** — no OAuth / SAML / JWT-cracking unless the attack feeds an LLM-behavior change. Use jwt_tool / authz0.
- **Browser-automation attacks** — no headless browser, no DOM injection, no clickjacking. Use Playwright/Selenium-based tools.

**Out-of-scope (would dilute the LLM focus):**

- **Importing HarmBench / JailbreakBench / AdvBench** — would make us a wrapper. Our corpus is our IP. (We may publish ours and let *them* import.)
- **Cloud SaaS version** — pentest tools live and die by being self-hosted.
- **Generic LLM chat features / "AI assistant" mode** — stay a sharp tool, not a chat product.
- **Plugin marketplace** — premature; ship the native corpus first.

**Litmus test for any new feature:** *"Does this attack the LLM's behavior,
its training, its context, its tools, or its conversation memory?"* If yes,
it belongs. If it's about the surrounding HTTP server, database, or infra,
it does not.

### 5.7 Suggested 8-week build order

| Week | Ship |
|---|---|
| 1 | Taxonomy doc + 30 hand-written YAML probes |
| 2 | Probe loader + version field + LSS rubric document |
| 3 | Refusal fingerprinting + adaptive attacker v0 |
| 4 | Session-lifecycle attacks + JSON payload mutator |
| 5 | Auth-context attacks (JWT mutator) + channel inconsistency mode |
| 6 | LMTWT-Climb mutation engine + self-play probe generation |
| 7 | Engagement report generator (PDF) + reproduction packs |
| 8 | Multi-target scorecard + before/after diff |

### 5.8 Phase 6 (research horizon) ⬜

| Item | What |
|---|---|
| **Adversarial suffix generation (GCG-style)** | Greedy coordinate gradient attack — needs local model gradient access, gated behind `[research]` extras. |
| **Embedding-space attacks** | Find prompts semantically distant from refusal triggers but functionally identical. |
| **Defensive eval suite** | Run same battery against target ± guardrail (Llama Guard / NeMo / custom). Report Δ. Sells offense + defense as one product. |
| **Real-time interception proxy** | Sit between client and LLM; analyze incoming prompts for likely-injection content. Defensive companion to the offensive tool. |

---

## Test coverage

150+ tests passing (was 11 at the start). Per-area breakdown:

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
| Tool-use attacks (vectors / harness / orchestrator) | 14 |
| Transport (proxy / CA / TLS) | 15 |
| LM Studio integration | 6 |
| Claude Code ACP | 8 |
| **Socket.IO adapter (parser, handshake, EIO v3/v4)** | **12** |
| Payloads | 5 |
| Templates / config | 7 |

## What's left, in priority order

**Strategic (Phase 5 — defines what LMTWT becomes):**

1. **Taxonomy + first 30 native probes** — the moat; everything else is fluff without this
2. **LSS scoring rubric** — purpose-built CVSS analogue for LLM findings
3. **Refusal fingerprinting + adaptive attacker** — first step toward a discovery engine
4. **Session-lifecycle / auth-context / channel-inconsistency attacks** — leverage the Socket.IO foundation; uniquely ours
5. **Engagement-grade PDF reports + reproduction packs** — what makes the tool sellable

**Tactical (smaller cleanups, can interleave):**

6. **`X-LMTWT-*` request headers** for Burp history filtering — ~30 lines
7. **`lmtwt import-burp`** capture-to-target-config converter — ~150 lines
8. **`mypy` / `pyright` CI baseline** — clean up gradual type drift
9. **SQLite persistence** for batch reports
10. **Native tool-call support** — extend `AsyncAIModel` to accept tools and
    route tool-call deltas; would unlock real tool-use attacks against
    tool-aware models like Anthropic / OpenAI function calling
11. **FastAPI + SSE frontend** to replace Gradio (optional)
12. **gRPC adapter** for `external-api` (only if requested)
13. **Real ACP integration tests** — current tests use a fake subprocess;
    add live tests against a real Claude Code binary in CI (gated on env)
