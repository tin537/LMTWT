# Web UI

Async-native Gradio Blocks app at `src/lmtwt/web/__init__.py`.

```bash
uv run lmtwt --web                    # default port 8501
uv run lmtwt --web --web-port 8080 --share
```

Or programmatically:

```python
from lmtwt.web import launch_web_ui
launch_web_ui(config_path=None, port=8501, share=False)
```

`launch_web_ui` calls `create_web_ui(config_path)`, then
`app.launch(server_port=port, share=share, server_name="0.0.0.0")`.

## Tabs

### 1. Setup

| Control | Notes |
|---|---|
| Attacker Provider | Dropdown: `gemini` / `openai` / `anthropic` / `huggingface` |
| Attacker Model | Dropdown — updates when provider changes |
| Target Provider | Dropdown — includes `external-api` (currently CLI-only) |
| Target Model | Dropdown — updates when provider changes |
| Hacker mode | Checkbox (default: on) |
| LLM judge (ensemble) | Checkbox (default: on) — uses `EnsembleJudge` |
| Judge provider | Dropdown: `gemini` / `openai` / `anthropic` |
| **Initialize Engine** | Builds `AsyncAttackEngine`; checks API keys; reports status |

Initialization is gated on `{PROVIDER}_API_KEY` being set in the
environment. If a target is `external-api`, the UI returns
`"External-API targets aren't wired into the web UI yet"` — use the CLI for
those.

### 2. Generate

| Control | Notes |
|---|---|
| Attack instruction | Free-form instruction for the attacker model |
| Temperature | Slider 0.1–1.0 (default 0.7) |
| **Generate (streaming)** | Streams tokens via `engine.attacker.astream()` into the textbox |
| Generated attack prompt | Streaming output |
| Status | `✍️ generating…` then `✅ Generated` |
| Copy to Execute tab | Copies the generated prompt to tab 3 |

### 3. Execute

| Control | Notes |
|---|---|
| Attack prompt | Editable; defaults to whatever was copied from Generate |
| Target system prompt (optional) | Overrides the engine's defensive default |
| **Execute Attack** | Calls `engine.execute_attack(...)` |
| Target response | Output |
| Status | `✅ SUCCESS` or `❌ FAILURE` plus reason |

Each execution appends to a session-level history list, which feeds tab 4.

### 4. History

| Control | Notes |
|---|---|
| Attack history | Color-coded card per attack (green = success, red = failure) |
| Clear | Resets the in-memory history list |

## State

The `attack_engine` and the history list are closures over `create_web_ui`
— process-local, **not persisted** across server restarts. A page reload
preserves them as long as the Python process is alive.

## Limitations

- No batch / probe / template / multi-turn / strategy modes — UI is
  single-shot generation + execution. Use the CLI for those.
- External-API targets still rejected in the UI.
- Execute tab does not stream — only Generate does. (Adding streaming to
  Execute would mean refactoring the response/status outputs into a generator.)
- HuggingFace local models block the UI on first chat() while weights load.
