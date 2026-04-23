# LMTWT Documentation

LMTWT (Let Me Talk With Them) is a Python framework for testing LLM
resistance to prompt injection, jailbreaks, and other adversarial inputs.
One model (the *attacker*) generates attack prompts; another (the *target*)
receives them; results are scored, logged, and reported.

## Contents

| File | What's in it |
|---|---|
| [architecture.md](architecture.md) | Module map, runtime data flow, package layout |
| [cli.md](cli.md) | Every command-line flag in `src/main.py` |
| [configuration.md](configuration.md) | `.env`, `config.json`, target-API config files |
| [models.md](models.md) | The five model providers and their `chat()` contracts |
| [attacks.md](attacks.md) | `AttackEngine`, `ProbeAttack`, payloads, templates |
| [utils.md](utils.md) | Circuit breaker, compliance agent, report generator, logger |
| [web.md](web.md) | Gradio web UI tabs and event wiring |
| [roadmap.md](roadmap.md) | Planned upgrades (already drafted) |

## Quick start

```bash
cp .env.example .env            # add API keys
./run.sh --attacker gemini --target openai --mode interactive
./run.sh --web                  # Gradio UI on port 8501
```

See [cli.md](cli.md) for all options and [configuration.md](configuration.md)
for required environment variables.

## At a glance

```
                ┌──────────────┐         ┌──────────────┐
   instruction  │  Attacker    │ prompt  │   Target     │  response
   ─────────────▶  AIModel     │────────▶│   AIModel    │─────────┐
                └──────────────┘         └──────────────┘         │
                       ▲                                          │
                       │ refined payload (hacker mode)            │
                       │                                          ▼
                ┌──────────────┐         ┌──────────────────────────┐
                │  AttackEngine│◀────────│  ComplianceAgent / heur. │
                └──────┬───────┘ verdict │  success detection        │
                       │                 └──────────────────────────┘
                       ▼
                ┌──────────────┐
                │ ReportGen    │  json / csv / html / png
                └──────────────┘
```

All API calls flow through a per-provider `CircuitBreaker` (see
[utils.md](utils.md)) so rate-limit storms don't cascade.
