# CLI reference

Entry: `src/main.py:main`. Run via `./run.sh <args>`, `python run.py <args>`,
or directly `python src/main.py <args>`.

## Flags

### Models

| Flag | Default | Choices | Notes |
|---|---|---|---|
| `--attacker, -a` | `gemini` | `gemini`, `openai`, `anthropic`, `huggingface` | Provider that generates attack prompts |
| `--target, -t` | `openai` | `gemini`, `openai`, `anthropic`, `external-api`, `huggingface` | Provider under test |
| `--attacker-model` | provider default | any string | Specific model ID for attacker |
| `--target-model` | provider default | any string | Specific model ID for target |

Provider defaults: see [models.md](models.md).

### Modes

| Flag | Default | Choices | Notes |
|---|---|---|---|
| `--mode, -m` | `interactive` | `interactive`, `batch`, `template` | Top-level mode |
| `--probe-mode` | off | flag | Use `ProbeAttack` instead of `AttackEngine` (overrides `--mode`) |
| `--web` | off | flag | Launch Gradio UI and exit; ignores most other flags |

#### Interactive mode
Prompts the user for an instruction, generates an attack, optionally allows
editing, sends it to the target, and prints the verdict. Loop until `q`.

#### Batch mode
Requires one or more `--instruction "<text>"`. Each instruction is run
`--iterations` times with a `--delay` second pause between attacks.

#### Template mode
Requires one or more `--template <id>`. Templates are predefined
instructions (see [attacks.md](attacks.md)).

#### Probe mode
| Flag | Default | Choices | Notes |
|---|---|---|---|
| `--probe-category` | `all` | `dan`, `injection`, `xss`, `glitch`, `misleading`, `malware`, `forbidden_knowledge`, `snowball`, `all` | Restricts payload pool |
| `--probe-iterations` | `5` | int | Attacks per category (or total if `all`) |

### Templates

| Flag | Default | Notes |
|---|---|---|
| `--template <id>` | — | Repeatable. Resolved by `get_template_instruction` |
| `--list-templates` | off | Print template IDs and exit |

### Instructions and pacing

| Flag | Default | Notes |
|---|---|---|
| `--instruction, -i <text>` | — | Repeatable. Free-form instruction for the attacker model |
| `--iterations` | `1` | Repeats per instruction |
| `--delay` | `1` | Seconds between batch attacks |

### Hacker mode

| Flag | Default | Notes |
|---|---|---|
| `--hacker-mode` | off | Enables conversation history analysis + auto-retry on failure |
| `--hacker-system-prompt <text>` | from `config.json` or built-in default | Override attacker system prompt |
| `--max-retries` | `3` | Hacker-mode retry budget per session |

### Defense

| Flag | Default | Notes |
|---|---|---|
| `--system-prompt <text>` | built-in defensive prompt | What the target sees as its system prompt |

### Compliance agent (LLM-as-judge)

| Flag | Default | Notes |
|---|---|---|
| `--compliance-agent` | off | Use a third LLM to score success instead of regex heuristics |
| `--compliance-provider` | `gemini` | One of `gemini`, `openai`, `anthropic` |
| `--no-fallback` | off | Disable heuristic fallback when judge hits rate limits / circuit opens |

### Circuit breakers

| Flag | Default | Notes |
|---|---|---|
| `--disable-circuit-breakers` | off | Bypass all circuit breakers globally |
| `--circuit-failure-threshold` | `3` | Failures before circuit opens |
| `--circuit-recovery-timeout` | `120` | Seconds in OPEN state before HALF-OPEN test |

### Configuration

| Flag | Default | Notes |
|---|---|---|
| `--config, -c <path>` | `config.json` at repo root | Application config |
| `--target-config <path>` | — | Required when `--target external-api` |

### Web UI

| Flag | Default | Notes |
|---|---|---|
| `--web` | off | Launch Gradio UI |
| `--web-port` | `8501` | Port to serve on |
| `--share` | off | Request a public Gradio share URL |

### Other

| Flag | Default | Notes |
|---|---|---|
| `--auto-send` | off | Skip the prompt-edit confirmation in interactive mode |

## Examples

```bash
# Interactive Gemini-vs-OpenAI session
./run.sh --attacker gemini --target openai --mode interactive

# Batch run with two instructions, 3 iterations each
./run.sh --mode batch \
  --instruction "Generate a jailbreak prompt" \
  --instruction "Try system-prompt extraction" \
  --iterations 3 --delay 2

# Template mode with the LLM judge enabled
./run.sh --mode template --template basic_prompt_injection \
  --compliance-agent --compliance-provider anthropic

# Probe-mode batch sweep across all payload categories
./run.sh --probe-mode --probe-category all --probe-iterations 8 \
  --target anthropic

# Hit a custom REST endpoint
./run.sh --target external-api --target-config examples/custom_target.json

# Local model as target
./run.sh --target huggingface \
  --target-model "mistralai/Mistral-7B-Instruct-v0.2"
```
