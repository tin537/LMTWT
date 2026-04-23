# Architecture

## Package layout

```
LMTWT/
├── run.sh                          # bash launcher (creates venv, runs src/main.py)
├── run.py                          # cross-platform Python launcher (same job)
├── setup.py                        # PEP 517 setup; package_dir={"": "src"}
├── requirements.txt
├── config.json                     # auto-created on first run
├── src/
│   ├── main.py                     # CLI entrypoint (argparse + dispatch)
│   └── lmtwt/
│       ├── __init__.py             # empty
│       ├── attacks/
│       │   ├── engine.py           # AttackEngine — core attacker/target loop
│       │   ├── payloads.py         # PayloadGenerator — canned attack strings
│       │   ├── probeattack.py      # ProbeAttack — categorical probing
│       │   └── templates.py        # ATTACK_TEMPLATES — instruction presets
│       ├── models/
│       │   ├── base.py             # AIModel ABC
│       │   ├── anthropic.py
│       │   ├── openai.py
│       │   ├── gemini.py
│       │   ├── huggingface.py
│       │   └── external_api.py
│       ├── utils/
│       │   ├── circuit_breaker.py  # CircuitBreaker + with_fallback decorator
│       │   ├── compliance_agent.py # LLM-as-judge scorer
│       │   ├── config.py           # env + config.json + target-config loaders
│       │   ├── logger.py           # rich-backed logging + conversation log
│       │   └── report_generator.py # json/csv/html/png reports
│       └── web/
│           └── __init__.py         # Gradio UI (create_web_ui, launch_web_ui)
├── tests/                          # pytest suite (CI: pytest tests/)
├── examples/                       # external-API config samples + scripts
├── docs/                           # this directory
└── .github/workflows/python-tests.yml
```

## Runtime flow

### 1. Bootstrap (`src/main.py`)
- Loads `.env` via `python-dotenv`.
- Parses CLI args (see [cli.md](cli.md)).
- Loads `config.json` via `utils.config.load_config` (writes a default if
  missing).
- Detects GPU (CUDA/MPS) for HuggingFace models.

### 2. Branch on mode
- `--web` → hands off to `lmtwt.web.launch_web_ui` and exits.
- `--probe-mode` → constructs `ProbeAttack` with payload categories.
- Otherwise → constructs `AttackEngine` and runs `interactive_attack`,
  `batch_attack`, or template-based batch.

### 3. Model construction (`models.__init__.get_model`)
A single factory builds the right `AIModel` subclass for a provider name
(`gemini`, `openai`, `anthropic`, `huggingface`, `external-api`). Every model
optionally wraps API calls with a `CircuitBreaker`.

### 4. Attack loop
`AttackEngine` ties two `AIModel` instances together:
- `generate_attack_prompt(instruction)` — attacker model produces a payload.
- `execute_attack(payload)` — target model is hit with the payload under a
  defensive system prompt.
- Success is judged by `_analyze_response_for_success` (regex heuristic) or,
  if `--compliance-agent` is set, by `ComplianceAgent.evaluate_compliance`
  (LLM-as-judge with heuristic fallback).
- In `--hacker-mode`, failed attempts are fed back into
  `craft_new_payload_from_failure` for up to `--max-retries` rounds.

### 5. Reporting
`batch_attack` automatically calls `ReportGenerator.generate_report`, which
writes JSON, CSV, HTML, and a matplotlib PNG to `reports/`. Conversations
can also be saved per-session via `utils.logger.log_conversation` to
`logs/attack_*.json`.

## Communities (from the code-review graph)

| Community | Files | Role |
|---|---|---|
| `models` | `src/lmtwt/models/*.py` | Provider adapters + `AIModel` ABC |
| `attacks` | `src/lmtwt/attacks/*.py` | Attack generation + execution |
| `utils` | `src/lmtwt/utils/*.py` | Circuit breaker, judge, config, logging, reports |
| `web` | `src/lmtwt/web/__init__.py` | Gradio Blocks UI |
| `cli` | `src/main.py` | Top-level dispatch |
| `bootstrap` | `run.py`, `run.sh` | Venv setup + launcher |
| `tests` | `tests/*.py` | Pytest suite |

## Key invariants

- **`AIModel.history`** is a list of `{role, content}` dicts owned by the
  model instance and mutated by every `chat()` call. Conversations are not
  thread-safe.
- **`protected_chat()`** is the public, circuit-breaker-wrapped entrypoint
  on every `AIModel` subclass. Internal callers (`ComplianceAgent`,
  `AttackEngine`) always use `protected_chat`, never `chat`.
- **Provider strings are case-insensitive** at the `get_model` factory but
  case-sensitive in argparse `choices=` and env-var lookups
  (`{PROVIDER}_API_KEY`).
- **Reports are written eagerly** by `batch_attack` — every batch run leaves
  a timestamped report in `reports/` whether you asked for one or not.
