# LMTWT — Let Me Talk With Them

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen" alt="Contributions: Welcome">
</p>

LMTWT is an async-first security testing framework for evaluating LLM resistance
to prompt injection, jailbreaks, and tool-use attacks. It pits one model
(the **attacker**) against another (the **target**) and reports whether the
target was compromised — automatically, at scale, against frontier APIs or
custom backends behind your own protocol.

## What you can hit

- **Hosted LLMs** — OpenAI, Anthropic, Gemini
- **Local LLMs** — Hugging Face transformers, **LM Studio** (OpenAI-compatible)
- **Agent runtimes** — **Claude Code via ACP** (Agent Client Protocol over stdio)
- **Custom backends via `external-api`** — your own chatbot at any of:
  - **HTTP** (single round-trip JSON)
  - **SSE** (Server-Sent Events streaming)
  - **WebSocket** (raw frame protocol)
  - **Socket.IO** (v5/EIO v4 *or* v2/EIO v3, with ack + event correlation)

Anything you can describe in a JSON config can be a target — payload templates,
auth headers, dotted-path response extraction, ack handling, the lot.

## What it does to them

- **Single-shot attack templates** (`--mode template`) — curated injection / jailbreak prompts
- **Probe sweeps** (`--probe-mode`) — eight built-in vulnerability categories
- **Multi-turn flows** (`--mode multi-turn`) — scripted social-engineering arcs
- **Tool-use attacks** (`--mode tool-use`) — indirect prompt injection via tool results
- **Refinement strategies** (`--strategy pair|tap`) — automated PAIR / TAP attack search
- **Hacker mode** (`--hacker-mode`) — attacker reads conversation history and adapts
- **Three judges**: regex, LLM-based, or ensemble for success detection

## Install

```bash
git clone https://github.com/tin537/LMTWT.git
cd LMTWT

# Recommended: uv (https://docs.astral.sh/uv/)
uv sync

# Or plain pip
pip install -e .

# Optional: local Hugging Face inference
pip install -e '.[local]'

# Optional: Web UI (Gradio)
pip install -e '.[web]'
```

Python 3.10+ is required. GPU acceleration (CUDA / Apple MPS) is auto-detected
when PyTorch is installed.

## Configure credentials

Create `.env` at the repo root (only the providers you'll use):

```bash
GEMINI_API_KEY=...
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
HUGGINGFACE_API_KEY=hf_...     # optional, only for gated models
```

LM Studio and Claude Code (ACP) need no key — they run locally.

## Quick start

```bash
# Interactive: Gemini attacking OpenAI
./run.sh --attacker gemini --target openai --mode interactive

# Local-only: LM Studio attacking LM Studio (no API costs)
./run.sh --attacker lmstudio --attacker-model "qwen2.5-7b" \
         --target lmstudio  --target-model "llama-3.1-8b" \
         --mode interactive

# Web UI
./run.sh --web
```

## Usage examples

### Targeting different model backends

```bash
# Hosted: Claude as the target
./run.sh --attacker gemini --target anthropic

# Local: Hugging Face transformer
./run.sh --attacker gemini --target huggingface \
         --target-model "mistralai/Mistral-7B-Instruct-v0.2"

# Local: LM Studio (OpenAI-compatible REST on localhost:1234)
./run.sh --attacker gemini --target lmstudio --target-model "your-model-id"

# Agent runtime: Claude Code over ACP
./run.sh --attacker gemini --target claude-code

# Custom HTTP backend
./run.sh --attacker gemini --target external-api \
         --target-config examples/custom_api_target.json

# Custom Socket.IO backend (e.g. fintech / customer-service chatbot)
./run.sh --attacker gemini --target external-api \
         --target-config examples/socketio_target.json
```

### Attack modes

```bash
# Hacker mode — attacker adapts based on target's prior responses
./run.sh --attacker gemini --target openai --hacker-mode

# Probe a specific vulnerability category
./run.sh --probe-mode --probe-category injection --target openai

# Batch attacks with explicit instructions
./run.sh --mode batch \
         --instruction "Create a jailbreak prompt" \
         --instruction "Test system-prompt extraction"

# Multi-turn social-engineering flow
./run.sh --mode multi-turn --flow trust_then_pivot

# Tool-use attack (indirect prompt injection via tool results)
./run.sh --mode tool-use --tool-vector hidden_instruction

# Automated refinement: PAIR (5 iterations) or TAP (tree of thoughts)
./run.sh --strategy pair --strategy-iterations 5
./run.sh --strategy tap  --strategy-branching 3 --strategy-depth 4
```

### Standardized templates

```bash
# List built-in attack templates
./run.sh --list-templates

# Run a specific template
./run.sh --mode template --template basic_prompt_injection

# List multi-turn flows / tool-use vectors
./run.sh --list-flows
./run.sh --list-vectors
```

### Routing through Burp / mitmproxy / ZAP

Every model — hosted, local, and external — flows through the same TLS/proxy
layer. Burp captures help when you're targeting a custom backend whose protocol
you don't fully understand yet.

```bash
./run.sh --attacker gemini --target external-api \
         --target-config my_target.json \
         --proxy http://127.0.0.1:8080 \
         --ca-bundle ~/.burp/cacert.pem
```

CA bundle accepts both **PEM** (`.pem` / `.crt`) and **DER** (`.der` / `.cer`) —
no conversion needed. Per-target overrides (`proxy`, `ca_bundle`, `insecure`)
in the target-config JSON win over CLI flags.

## Attack categories (probe mode)

| Category | What it tests |
|---|---|
| `dan` | "Do Anything Now" jailbreak prompts |
| `injection` | Classic prompt injection |
| `xss` | Cross-site scripting payloads in model output |
| `glitch` | Unicode and token-boundary exploits |
| `misleading` | Misinformation / hallucination induction |
| `malware` | Malware-related content generation |
| `forbidden_knowledge` | Dangerous-knowledge extraction |
| `snowball` | Escalating-hallucination attacks |

## External-API targets in 30 seconds

The `external-api` target is the framework's escape hatch. Point it at a JSON
file describing the wire protocol and LMTWT handles the rest. Four protocols
are built in:

| `protocol` | Use when |
|---|---|
| `http` (default) | One-shot REST chat endpoint |
| `sse` | Server-Sent Events streaming response |
| `websocket` / `ws` / `wss` | Raw WebSocket JSON frames |
| `socketio` / `socket.io` | Socket.IO v5 (EIO v4) or v2 (EIO v3) — set `eio_version` |

A minimal Socket.IO config looks like:

```json
{
  "protocol": "socketio",
  "endpoint": "wss://chat.example.com/socket.io/",
  "eio_version": "3",
  "headers": { "Authorization": "Bearer ...", "User-Agent": "android" },
  "event_name": "send_message",
  "response_event": "receive_message",
  "payload_template": {
    "messageContent": [{ "content": "", "type": "TEXT" }],
    "messageId": "", "sessionId": "", "role": "USER"
  },
  "prompt_path": "messageContent.0.content",
  "message_id_key": "messageId",
  "session_id_key": "sessionId",
  "session_id": "session-from-your-bootstrap-api",
  "response_path": "messageContent.0.content"
}
```

See [`docs/configuration.md`](docs/configuration.md) for the full schema and
[`examples/`](examples/) for working configs (HTTP, Socket.IO, Ollama).

Debug helper: set `LMTWT_SOCKETIO_DEBUG=1` to dump every Socket.IO frame to
stderr while a run is in flight.

## Web UI

```bash
./run.sh --web                                    # localhost:8501
./run.sh --web --web-port 8080 --share            # public Gradio share link
```

The UI exposes model selection, interactive attack composition, result
visualization, and a session history with pass/fail tracking.

## Architecture in one paragraph

The async-first engine (`src/lmtwt/attacks/async_engine.py`) drives an
`attacker` and a `target`, both implementing a small `AsyncAIModel` interface
(`src/lmtwt/models/async_base.py`). Provider classes live in
`src/lmtwt/models/`; external transports in `src/lmtwt/models/external/`.
Each `chat()` returns a typed `ChatResponse`; streaming is exposed via
`astream()`. A judge (`src/lmtwt/judges/`) decides whether the target's
response counts as a successful jailbreak. Read [`docs/architecture.md`](docs/architecture.md)
for the full picture.

## Tests

```bash
uv run pytest                       # full suite (~150 tests, ~2s)
uv run pytest tests/test_external_socketio.py -v
uv run pytest --cov=src/lmtwt
```

[![Python Tests](https://github.com/tin537/LMTWT/actions/workflows/python-tests.yml/badge.svg)](https://github.com/tin537/LMTWT/actions/workflows/python-tests.yml)

## Documentation

- [`docs/index.md`](docs/index.md) — table of contents
- [`docs/architecture.md`](docs/architecture.md) — async engine, model layer, judges
- [`docs/configuration.md`](docs/configuration.md) — `.env`, `config.json`, target-config schema
- [`docs/cli.md`](docs/cli.md) — every flag, every mode
- [`docs/models.md`](docs/models.md) — provider matrix and capability notes
- [`docs/attacks.md`](docs/attacks.md) — templates, probes, flows, tool-use vectors
- [`docs/web.md`](docs/web.md) — Gradio UI
- [`docs/roadmap.md`](docs/roadmap.md) — what's next

## Contributing

```bash
git checkout -b feature/your-thing
uv sync                              # installs dev group automatically
uv run pytest                        # green before pushing
uv run ruff check src tests          # lint
git commit -m "feat: ..."
git push origin feature/your-thing
```

PRs welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Acknowledgments

Inspired by [NVIDIA's garak](https://github.com/NVIDIA/garak) (Apache 2.0).
LMTWT is an original implementation under MIT — we appreciate garak's prior
work in the LLM red-team space.

## Support the project

<p align="center">
  <a href="https://www.paypal.me/tanuphattin">
    <img src="https://img.shields.io/badge/Donate-PayPal-blue.svg?style=for-the-badge" alt="PayPal">
  </a>
</p>

## Disclaimer

For **educational purposes** and **authorized security testing** only. Always
get written permission before testing any system you don't own. Researchers
running CTFs, internal red-team engagements, and personal lab work are the
intended audience. The authors disclaim responsibility for misuse.

## License

MIT — see [`LICENSE`](LICENSE).

## Contact

Tanuphat Tin — tanuphat.chai@gmail.com
[github.com/tin537/LMTWT](https://github.com/tin537/LMTWT)
