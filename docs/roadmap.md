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

### 5.2 Own scoring rubric 🚧

| Item | Status |
|---|---|
| **LMTWT Severity Score (LSS)** | ✅ — `src/lmtwt/scoring/lss.py`; vector string `LSS:1.0/V:L/D:D/O:P/E:S/S:M/C:N`, deterministic 0–10 score from base impact × vector × delivery × obfuscation × chain multipliers. Spec in [`docs/lss.md`](lss.md). |
| **Compound severity** | ✅ — `compound_lss([...])` boosts max-of-chain by 1.30 (clamped to 10), flips vector to `C:Y`. |
| **Refusal-quality grading** | ✅ — `grade_refusal()` returns A/B/C/D/F. Catalog runner attaches grade to every outcome (even failures), CLI surfaces histogram. |
| **CLI integration** | ✅ — `--probe-catalog` output now shows `LSS=X.XX  refusal=A` per probe + `Max LSS` + by-grade histogram. |
| **Confidence intervals** | ⬜ — run probes N times, report verdict variance. Next sub-landing in 5.2. |
| **LLM-backed refusal grader** | ⬜ — current grader is regex-only; an LLM second-opinion grader is future work. |

### 5.3 Discovery engine 🚧

This is where LMTWT goes beyond running probes — it **generates new attacks
during a run** and the corpus grows itself.

| Item | Status |
|---|---|
| **Refusal fingerprinting** | ✅ — `src/lmtwt/discovery/fingerprint.py`; 9-probe calibration set (4 refusal-trigger × 4 obfuscation axes + 1 multilingual trigger + 4 stress probes), per-axis refusal rates, weak-axis identification, refusal-style classifier (`hard` / `soft` / `leaky` / `none`), policy-leak detection, response timing/length stats. CLI: `--fingerprint --fingerprint-out target.json`. |
| **Adaptive attacker** | ✅ — `src/lmtwt/discovery/adaptive.py`; `AdaptiveAttacker` reads the fingerprint, picks the weak obfuscation axis, asks the attacker LLM for N fresh probes targeting that gap, returns `Probe`-shaped objects that flow through the existing catalog runner. CLI: `--probe-catalog --adaptive --fingerprint-in target.json`. |
| **LMTWT-Climb mutation engine** | ⬜ — Take an almost-successful probe and mutate (synonyms, restructure, persona, distractors). Hill-climb against the judge. Our own search loop, not PAIR/TAP. |
| **Cross-pollination** | ⬜ — Probe A succeeds against bot X → auto-generate variants for bots Y / Z. Feedback loop fills the corpus. |
| **Self-play probe generation** | ⬜ — Two attackers debate: one writes a probe, the other plays target and predicts refusal, first revises. Output: probes pre-tested for likely success, stored in corpus. |

### 5.4 LLM-chatbot attack surface ✅

These are LLM-specific attacks that *use* the production-chatbot protocol
(Socket.IO foundation) as a delivery vehicle. Every item targets the
**model's behavior or the conversation's integrity** — not the chatbot's
generic web-app surface (which is a different tool's job).

| Item | Status |
|---|---|
| **Session-lifecycle prompt injection** | ✅ — `chatbot_attacks/session_lifecycle.py`. `SessionLifecycleAttack` mutates routing fields (`subFlow`, `flow`, `role`, etc.) under a payload-template lock, diffs the response grade vs baseline, severity-classifies the change. CLI: `--chatbot-attack session-lifecycle`. |
| **Channel-inconsistency policy bypass** | ✅ — `chatbot_attacks/channel_inconsistency.py`. `ChannelInconsistencyAttack` sends identical prompts across N adapters in parallel and flags grade divergence. Critical severity when refused channel + compliant channel both exist. CLI: `--chatbot-attack channel-inconsistency --channel-config foo.json --channel-config bar.json`. |
| **JWT-claim context injection** | ✅ — `chatbot_attacks/jwt_claims.py`. Decodes the bearer token's payload, mutates one claim per pass (tier/role/is_staff/scope), re-emits with `alg:none` (or original signature via `--keep-signature`), grades behavior change. Transport rejection is recorded as low-severity (auth layer working). |
| **Conversation hijack → memory extraction** | ✅ — `chatbot_attacks/conversation_hijack.py`. `generate_candidate_session_ids` produces predictable variants (numeric ±N, prefix collisions); attack swaps `sessionId` per attempt, asks model to recall, scans response for PII/leak patterns; critical when leak patterns hit AND model didn't refuse. |
| **Cost-amplification prompts** | ✅ — `chatbot_attacks/cost_amplification.py`. 5-probe battery (repetition, recursive expansion, structured glut, translation chain, essay glut). Measures response chars / token estimate, computes amplification factor and est. USD cost. Critical at 200×+ amp or 4k+ token output. |
| **Multi-turn refusal fatigue** | ✅ — `chatbot_attacks/refusal_fatigue.py`. 3 built-in scripts (research-framing, incremental-roleplay, conditional-acceptance). Grades every turn; flags critical when initial A/B → mid-script F. |
| **Tool-result poisoning at the protocol level** | ✅ — `chatbot_attacks/tool_result_poisoning.py`. 3 default payloads (auth-uplift, balance-injection, instruction-injection-via-tool). Frames poisoned content as a tool reply in conversation, then asks an extraction question; per-payload swallow heuristics decide critical/high/low. |

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
