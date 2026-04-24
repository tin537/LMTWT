# LMTWT Upgrade Roadmap

Status as of the most recent commit. ✅ = shipped, 🚧 = in progress / partial,
⬜ = future work.

## Phase 6 — `lmtwt scan` front door ✅

The granular CLI grew to 30+ flags. The new front door collapses it to one
command for the common case:

```
lmtwt scan --target <provider> --attacker <provider> [--target-config x.json]
```

Composes **every** technique LMTWT supports — fingerprint → catalog →
adaptive → climb → pollinate → chatbot attacks (always-on +
capability-detected) → PAIR + TAP refinement → multi-turn flows. Self-play
is reserved for `--depth thorough` because it's target-independent corpus
generation. Capability-gated chatbot attacks (session-lifecycle, JWT-claims,
conversation-hijack) auto-detect from the target-config and skip with a
printed reason when prerequisites are missing. The engagement bundle lands
in `./scan-<date>-<target>/`:

```
scan.json   report.md   report.html   report.pdf   scorecard.md
fingerprint.json   plan.json   scan.db   repro/F00N_<id>.json   repro/index.json
```

Three depth presets — `quick` / `standard` / `thorough`. Defaults are
opinionated (concurrency 4, repeats 3, ensemble grader, dashboard if TTY,
persistence always on). `--dry-run` prints the plan without firing.

The legacy flat CLI (`--probe-catalog`, `--climb`, `--self-play`, `--pollinate`,
`--chatbot-attack`, etc.) keeps working untouched for power users. New top-level
subcommand routing is in `cli.py` (detects `argv[1] == "scan"`).

Files:
- `src/lmtwt/scan/plan.py` — `build_scan_plan(depth, target_config)`
- `src/lmtwt/scan/orchestrator.py` — `run_scan(...)` step pipeline
- `src/lmtwt/scan/bundle.py` — engagement bundle writer


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
| `mypy` / `pyright` baseline | ✅ — `pyrightconfig.json` at the repo root; `basic` strictness over `src/lmtwt/` only; legacy paths (`utils/report_generator.py`, `attacks/templates.py`) explicitly ignored; third-party SDK lines (gemini, openai, huggingface) get targeted `# type: ignore` for stub bugs. Now **0 errors / 16 advisory warnings**. CI gate added to `.github/workflows/python-tests.yml` — `uv run --with pyright pyright`. |

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
- ✅ SQLite persistence so reports survive crashes — `src/lmtwt/persistence.py` `SQLiteObserver` streams `runs`/`outcomes` rows via the `CatalogObserver` hook; `list_runs` / `load_run_outcomes` reconstruct a `--report-from`-compatible payload. CLI: `--persist`, `--persist-db`, `--list-runs`, `--show-run <id>`. WAL mode + `asyncio.to_thread` writes — no event-loop blocking.

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
| **Replace Gradio with FastAPI + SSE frontend** | ✅ (MVP, parallel — Gradio still works) — `src/lmtwt/web_api/`. FastAPI app with single-page UI for the probe-catalog runner; live SSE stream of outcomes per run; reuses `SQLiteObserver` for durability + `BroadcastObserver` for fan-out (multiple browsers per run). Endpoints: `GET /api/probes`, `GET/POST /api/runs`, `GET /api/runs/{id}/events` (SSE). CLI: `--web-api --web-api-port N --web-api-host H`. Install: `pip install lmtwt[api]`. |

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

### 5.2 Own scoring rubric ✅

| Item | Status |
|---|---|
| **LMTWT Severity Score (LSS)** | ✅ — `src/lmtwt/scoring/lss.py`; vector string `LSS:1.0/V:L/D:D/O:P/E:S/S:M/C:N`, deterministic 0–10 score from base impact × vector × delivery × obfuscation × chain multipliers. Spec in [`docs/lss.md`](lss.md). |
| **Compound severity** | ✅ — `compound_lss([...])` boosts max-of-chain by 1.30 (clamped to 10), flips vector to `C:Y`. |
| **Refusal-quality grading** | ✅ — `grade_refusal()` returns A/B/C/D/F. Catalog runner attaches grade to every outcome (even failures), CLI surfaces histogram. |
| **CLI integration** | ✅ — `--probe-catalog` output now shows `LSS=X.XX  refusal=A` per probe + `Max LSS` + by-grade histogram. |
| **Confidence intervals** | ✅ — `AsyncCatalogProbe(repeats=N)` runs each probe N times; outcome dict carries `attempts`, `successes_observed`, `success_rate`, `ci_low`, `ci_high` (Wilson 95% CI), and a `grade_distribution` histogram. CLI: `--probe-repeat N` (default 1, additive — N=1 keeps the original outcome shape). |
| **LLM-backed refusal grader** | ✅ — `src/lmtwt/scoring/refusal_grade.py`. New `RefusalGrader` Protocol + 3 impls: `RegexRefusalGrader` (default), `LLMRefusalGrader` (asks an attacker-side model for `GRADE: A-F` with regex fallback on malformed output), `EnsembleRefusalGrader` (regex first, only escalates to LLM on regex `F` — the case where regex is most likely wrong). Catalog runner accepts a custom grader via constructor. CLI: `--refusal-grader {regex,llm,ensemble} --refusal-grader-provider {gemini,openai,anthropic}`. |

### 5.3 Discovery engine ✅

This is where LMTWT goes beyond running probes — it **generates new attacks
during a run** and the corpus grows itself.

| Item | Status |
|---|---|
| **Refusal fingerprinting** | ✅ — `src/lmtwt/discovery/fingerprint.py`; 9-probe calibration set (4 refusal-trigger × 4 obfuscation axes + 1 multilingual trigger + 4 stress probes), per-axis refusal rates, weak-axis identification, refusal-style classifier (`hard` / `soft` / `leaky` / `none`), policy-leak detection, response timing/length stats. CLI: `--fingerprint --fingerprint-out target.json`. |
| **Adaptive attacker** | ✅ — `src/lmtwt/discovery/adaptive.py`; `AdaptiveAttacker` reads the fingerprint, picks the weak obfuscation axis, asks the attacker LLM for N fresh probes targeting that gap, returns `Probe`-shaped objects that flow through the existing catalog runner. CLI: `--probe-catalog --adaptive --fingerprint-in target.json`. |
| **LMTWT-Climb mutation engine** | ✅ — `src/lmtwt/discovery/climb.py`. `LMTWTClimb` hill-climbs a seed probe through 6 typed mutators (`SynonymMutator`, `RestructureMutator`, `PersonaMutator`, `DistractorMutator`, `EncodingMutator`, `TranslationMutator`). Fitness = `grade_refusal()` (A=0..F=4) by default, or a `ScoringJudge` 1-10 score (`--climb-judge`). Stops on success / plateau (configurable Δ over N rounds) / max-rounds. Each child probe carries `metadata.climb` lineage (parent_id, operator, generation, root_seed). CLI: `--climb --climb-seed <probe-id-or-yaml> --climb-rounds N --climb-fanout K --climb-keep K --climb-out result.json --climb-save best.yaml`. |
| **Cross-pollination** | ✅ — `src/lmtwt/discovery/pollinate.py`. `CrossPollinator.plan(seed)` derives the **taxonomy slots adjacent to the seed** (one per non-default obfuscation/delivery value the seed doesn't already cover); `pollinate()` fires one operator per slot. Six operators: 4 mechanical (`encode-base64`, `multi-turn-split`, `rag-wrap`, `indirect-frame`) + 2 LLM-driven (`translate-zh`, `persona-wrap`). Bigram-Jaccard dedupe (default 30% threshold) drops near-identical variants vs seed and pairwise. Each variant carries `metadata.cross_pollinated` lineage (seed_id, operator, axis-change, engagement). CLI: `--pollinate --pollinate-seed <id-or-yaml> [--pollinate-out file.yaml --pollinate-save-dir ./library/ --pollinate-engagement <tag> --pollinate-skip-op <name>]`. |
| **Self-play probe generation** | ✅ — `src/lmtwt/discovery/self_play.py`. `SelfPlay` runs a generator-vs-critic loop with **no live target**: generator drafts a probe at a (vector, obfuscation, target_effect) coordinate, critic predicts refusal text + 0-10 confidence, generator revises if confidence above threshold (default 6) for up to N rounds, then accept/reject. Critic's predicted refusal is harvested into the probe's `refusal_indicators` (free ground-truth indicators). Bigram-Jaccard diversity filter (reused from pollinate) drops near-duplicates within a coordinate. Sweeps all 64 coordinates by default; `--self-play-coordinate` restricts. Each accepted probe carries `metadata.self_play` lineage (generator/critic model names, critic confidence, predicted refusal, rounds, generated_at). CLI: `--self-play [--self-play-coordinate v/o/e]... --self-play-n N --self-play-rounds K --self-play-threshold T --self-play-out <dir> --self-play-trace <file.json> --self-play-critic <provider>`. |

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

### 5.5 Engagement-grade reporting 🚧 (most items shipped)

| Item | Status |
|---|---|
| **Markdown report generator** | ✅ — `src/lmtwt/reporting/builder.py`. Normalizes any run-output JSON (catalog probes, chatbot attacks, session/JWT/hijack findings) into a unified `Finding` shape, sorts by LSS desc, emits exec summary + methodology + findings table + per-finding detail + OWASP-tagged remediation guidance + appendix. |
| **HTML renderer** | ✅ — Standalone HTML with embedded print-friendly CSS, target-response escape, no external Markdown dep. |
| **PDF generator** | ✅ — `render_pdf()` via WeasyPrint (optional `lmtwt[report]` extra). Falls back gracefully to MD/HTML when WeasyPrint isn't installed. |
| **CLI integration** | ✅ — `--report-from <run.json> --report-out <basename> --report-format md,html,pdf`. |
| **Reproduction packs** | ✅ — `src/lmtwt/reporting/repro.py`. `write_repro_pack()` emits one `F00N_<id>.json` per finding plus an `index.json`, sorted by LSS desc. Each pack is versioned (`lmtwt_repro_pack_version`) and bundles target stub + exact prompt (or full conversation for multi-turn) + success/refusal indicators + observed-response excerpt + previous outcome. CLI: `--repro-out <dir>` alongside `--report-from`. |
| **Before / after diff mode** | ✅ — `src/lmtwt/reporting/diff.py`. `build_diff_report(before, after)` matches findings by probe id (preferred) or `(coordinate, sha1(prompt))` fallback, then bucketizes into **remediated / regressed / persistent / new** with severity Δ, LSS Δ, and grade transitions. Markdown renderer leads with regressions. CLI: `--diff-before <run.json> --diff-after <run.json>` + `--report-out`/`--report-format` (md, json). |
| **Live TUI dashboard** | ✅ — `src/lmtwt/cli_dashboard.py`. `RichDashboardObserver` renders status header (target / progress / in-flight / elapsed / max LSS), severity histogram of successful hits, and a scrolling tail of recent outcomes via Rich `Live`. Plugged in via the new `CatalogObserver` Protocol — runner is unaware of Rich; non-TTY runs leave the flag off. CLI: `--dashboard`. |
| **Multi-target scorecard** | ✅ — `src/lmtwt/reporting/scorecard.py`. `build_scorecard(payloads, names)` unions findings across N targets via the same `_match_key` strategy diff mode uses (probe id preferred, `(coord, sha1(prompt))` fallback). Grid sorted by max-LSS desc with hit-count tiebreak; per-target summary row (max LSS, real-findings count, severity histogram); headline picks most/least exposed target. CLI: `--scorecard-from <run.json>` (repeatable, one per target) `--scorecard-name <label>` (optional, paired by position) + `--report-out`/`--report-format` (md, json). |

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

385+ tests passing (was 11 at the start). Per-area breakdown:

| Area | Tests |
|---|---|
| LMTWT-Climb (mutators + orchestrator) | 18 |
| Diff mode (before/after bucketing) | 12 |
| Cross-pollination (plan + ops + dedupe) | 21 |
| Multi-target scorecard | 17 |
| Self-play probe generation | 17 |
| Confidence intervals (Wilson CI + repeats) | 5 |
| LLM-backed refusal grader (regex/llm/ensemble) | 9 |
| TUI dashboard (observer protocol + Rich render) | 7 |
| SQLite persistence (observer + read API) | 9 |
| FastAPI web API (broadcast + endpoints + UI) | 12 |
| Scan front door (plan + orchestrator + bundle) | 18 |
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
