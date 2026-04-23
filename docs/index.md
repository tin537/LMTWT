# LMTWT Documentation

LMTWT (Let Me Talk With Them) is an **async-first** Python framework for testing
LLM resistance to prompt injection, jailbreaks, multi-turn crescendo attacks,
and automated refinement strategies (PAIR / TAP). One model — the *attacker*
— generates payloads; another — the *target* — receives them; results are
scored by a pluggable *judge* and persisted to JSON / CSV / HTML / PNG.

## Contents

| File | What's in it |
|---|---|
| [architecture.md](architecture.md) | Module map, async runtime flow, package layout |
| [cli.md](cli.md) | Every command-line flag |
| [configuration.md](configuration.md) | `.env`, `config.json`, target-API config (HTTP / SSE / WebSocket) |
| [models.md](models.md) | `AsyncAIModel` ABC, the five async providers, transport layer |
| [attacks.md](attacks.md) | Engine, probe, multi-turn flows, PAIR / TAP strategies, payloads, templates |
| [utils.md](utils.md) | Judge family, config, logger, report generator |
| [web.md](web.md) | Gradio web UI (async handlers, streaming generation) |
| [roadmap.md](roadmap.md) | Done / in-progress / future work |

## Quick start

```bash
cp .env.example .env            # add API keys
uv run lmtwt --list-templates
uv run lmtwt --attacker gemini --target openai --mode interactive
uv run lmtwt --web              # Gradio UI on port 8501
```

`./run.sh` and `python -m lmtwt` work too. See [cli.md](cli.md) for all options
and [configuration.md](configuration.md) for required environment variables.

## At a glance

```
                ┌───────────────┐         ┌───────────────┐
   instruction  │  Attacker     │ payload │   Target      │  response
   ─────────────▶  AsyncAIModel │────────▶│   AsyncAIModel│─────────┐
                └───────────────┘         └───────────────┘         │
                       ▲                                            │
                       │ refined payload                            │
                       │  (hacker-mode / PAIR / TAP)                │
                       │                                            ▼
                ┌───────────────┐         ┌──────────────────────────┐
                │AsyncAttack    │◀────────│   AsyncJudge             │
                │Engine         │ verdict │   (Regex / LLM /          │
                └──────┬────────┘         │    Ensemble / ScoringLLM) │
                       │                  └──────────────────────────┘
                       ▼
                ┌──────────────┐
                │ ReportGen    │  json / csv / html / png
                └──────────────┘
```

Every provider is async (`anthropic.AsyncAnthropic`, `openai.AsyncOpenAI`,
`google.genai`, `httpx.AsyncClient` for external HTTP/SSE, the `websockets`
library for WebSocket targets). Resilience comes from `tenacity` (exponential
backoff on transient errors) plus `aiolimiter` (per-instance rate limiting).
Anthropic prompt caching is on by default.

## Notable capabilities

- **Five providers**: OpenAI, Anthropic, Gemini (new `google.genai` SDK),
  HuggingFace local models, and a generic external-API adapter that speaks
  HTTP, SSE, or WebSocket.
- **Multi-turn flows** (`--mode multi-turn --flow ...`): crescendo, role
  assumption, topic drift — three built-in flows.
- **PAIR / TAP refinement** (`--strategy pair|tap`): automated jailbreaking
  with a scoring LLM judge in the loop.
- **Concurrency**: `--concurrency N` for parallel batch runs.
- **Streaming**: `astream()` on every provider; live tokens in the Web UI.
- **Burp/mitmproxy integration**: `--proxy`, `--ca-bundle`, `--insecure` on
  every transport — including WebSocket.
- **Pluggable judges**: `RegexJudge`, `LLMJudge`, `EnsembleJudge`, and
  `ScoringLLMJudge` (used by PAIR / TAP).
