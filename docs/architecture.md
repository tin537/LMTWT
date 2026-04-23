# Architecture

## Package layout

```
LMTWT/
├── pyproject.toml                  # PEP 621 metadata, hatchling backend
├── uv.lock                         # uv-managed dep lockfile
├── run.sh                          # Bash launcher — prefers `uv run`
├── run.py                          # Cross-platform Python launcher
├── config.json                     # Auto-created on first run
├── src/lmtwt/
│   ├── __init__.py                 # empty
│   ├── __main__.py                 # `python -m lmtwt` entrypoint
│   ├── cli.py                      # CLI (async-native; wraps async_main in asyncio.run)
│   ├── attacks/
│   │   ├── async_engine.py         # AsyncAttackEngine + AttackResult dataclass
│   │   ├── async_probe.py          # AsyncProbeAttack — categorical probing
│   │   ├── flows.py                # MultiTurnFlow / MultiTurnRunner + 3 built-in flows
│   │   ├── strategies.py           # PAIRStrategy + TAPStrategy + RefinementStrategy protocol
│   │   ├── payloads.py             # PayloadGenerator — canned attack strings
│   │   └── templates.py            # ATTACK_TEMPLATES — instruction presets
│   ├── models/
│   │   ├── async_base.py           # AsyncAIModel ABC + ChatResponse / Chunk / Usage Pydantic
│   │   ├── conversation.py         # Conversation / Message — immutable value objects
│   │   ├── async_factory.py        # async_get_model(provider, ...)
│   │   ├── async_anthropic.py      # AsyncAnthropicModel (with prompt caching)
│   │   ├── async_openai.py         # AsyncOpenAIModel
│   │   ├── async_gemini.py         # AsyncGeminiModel (new google.genai SDK)
│   │   ├── async_huggingface.py    # AsyncHuggingFaceModel (asyncio.to_thread)
│   │   ├── _transport.py           # httpx_client_kwargs / websocket_ssl_context helpers
│   │   └── external/               # External-API adapters (one per protocol)
│   │       ├── base.py             # BaseExternalModel — shared payload composition
│   │       ├── http.py             # HTTPExternalModel
│   │       ├── sse.py              # SSEExternalModel — Server-Sent Events
│   │       └── websocket.py        # WebSocketExternalModel — websockets library
│   ├── utils/
│   │   ├── async_judge.py          # AsyncJudge protocol + RegexJudge / LLMJudge /
│   │   │                           #   EnsembleJudge / ScoringLLMJudge
│   │   ├── config.py               # env + config.json + target-config loaders
│   │   ├── logger.py               # rich-backed logging + conversation log
│   │   └── report_generator.py     # json/csv/html/png reports
│   └── web/
│       └── __init__.py             # Gradio UI (async handlers, streaming generation)
├── tests/                          # pytest suite (108 tests, asyncio_mode=auto)
├── examples/                       # external-API config samples + scripts
├── docs/                           # this directory
└── .github/workflows/python-tests.yml   # uv-based CI: ruff + pytest matrix
```

## Runtime flow

### 1. Bootstrap (`src/lmtwt/cli.py`)
- `main()` wraps `asyncio.run(async_main())`.
- Loads `.env` via `python-dotenv`.
- Parses CLI args; routes to one of: `--list-templates`, `--list-flows`,
  `--web`, `--probe-mode`, `--strategy {pair|tap}`, or one of the four
  modes (`interactive`, `batch`, `template`, `multi-turn`).
- Loads `config.json` via `utils.config.load_config` (writes a default if
  missing).

### 2. Model construction (`models/async_factory.async_get_model`)
A single async-friendly factory builds an `AsyncAIModel` for a provider name
(`gemini`, `openai`, `anthropic`, `huggingface`, `external-api`). Threads
`proxy` / `ca_bundle` / `verify` to whichever transport each provider uses.
For `external-api`, dispatches on `api_config["protocol"]` →
HTTP / SSE / WebSocket subclasses under `models/external/`.

### 3. Judge construction (`utils/async_judge`)
Selected via `--judge {regex,llm,ensemble}` or, for PAIR / TAP, the
`ScoringLLMJudge` (1-10 numeric score). The legacy `--compliance-agent`
flag still maps to `EnsembleJudge` for back-compat.

### 4. Attack loop (`attacks/async_engine.AsyncAttackEngine`)
- `generate_attack_prompt(instruction)` — attacker model produces a payload.
- `execute_attack(instruction, payload)` — target model is hit with the
  payload under a defensive system prompt. Exceptions captured into
  `AttackResult`.
- `batch(instructions, concurrency=N)` — fans out via `asyncio.Semaphore`
  (the "AttackRunner" capability).
- Hacker mode: failed attempts feed into `craft_new_payload_from_failure`
  for up to `--max-retries` rounds. History spliced into attacker system
  prompt on subsequent turns.

### 5. Other entry points
- **Multi-turn flow** (`attacks/flows.MultiTurnRunner`): runs a sequence of
  steps sharing one `Conversation` with the target. Each step is either
  literal text or a meta-instruction asking the attacker to produce the
  next user turn.
- **Refinement strategy** (`attacks/strategies.PAIRStrategy` / `TAPStrategy`):
  closes the loop with a `ScoringJudge`. PAIR is linear (max_iterations);
  TAP is branching/pruning (B^D variants, top-K survivors per level).
- **Probe** (`attacks/async_probe.AsyncProbeAttack`): categorical sweep of
  canned payloads from `PayloadGenerator`.

### 6. Reporting
Every batch / flow / strategy run ends with
`ReportGenerator.generate_report` writing JSON / CSV / HTML / PNG to
`reports/`.

## Key invariants

- **Conversations are immutable.** `Conversation.append()` and
  `with_system()` return new instances. Models never mutate caller state.
- **`AsyncAIModel.chat()`** returns a typed Pydantic `ChatResponse`.
  `astream()` yields `Chunk` deltas.
- **All model API calls go through `aiolimiter` + `tenacity`**. Rate
  limits and transient errors are handled; the homegrown circuit breaker
  is gone.
- **Per-target overrides** (in `api_config` JSON) win over CLI flags for
  external-api targets — useful for `--proxy` etc.
- **HuggingFace inference is `asyncio.to_thread`-wrapped sync** under the
  hood (CPU/GPU bound; no real concurrency benefit, but uniform interface).

## Module-import rule of thumb

| Public surface | Import from |
|---|---|
| Async model factory | `lmtwt.models.async_factory` |
| Concrete async providers | `lmtwt.models.{async_anthropic, async_openai, ...}` |
| Conversation / responses | `lmtwt.models.conversation`, `lmtwt.models.async_base` |
| External adapters by protocol | `lmtwt.models.external.{http, sse, websocket}` |
| Attack engine + result | `lmtwt.attacks.async_engine` |
| Probe | `lmtwt.attacks.async_probe` |
| Multi-turn flows | `lmtwt.attacks.flows` |
| Refinement strategies | `lmtwt.attacks.strategies` |
| Judges | `lmtwt.utils.async_judge` |
