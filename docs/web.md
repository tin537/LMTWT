# Web UI

Gradio Blocks app at `src/lmtwt/web/__init__.py`. Launched via:

```bash
./run.sh --web                    # default port 8501
./run.sh --web --web-port 8080 --share
```

Or from CLI:

```python
from lmtwt.web import launch_web_ui
launch_web_ui(config_path=None, port=8501, share=False)
```

`launch_web_ui` calls `create_web_ui(config_path)`, then
`app.launch(server_port=port, share=share, server_name="0.0.0.0")`.

## Tabs

### 1. Setup

| Control | Type | Notes |
|---|---|---|
| Attacker Provider | Dropdown | Choices from `list_available_models()` keys |
| Attacker Model | Dropdown | Updates when provider changes |
| Target Provider | Dropdown | Includes `external-api` (currently unsupported in UI) |
| Target Model | Dropdown | Updates when provider changes |
| Enable Hacker Mode | Checkbox | Default: on |
| Use Compliance Agent | Checkbox | Default: on |
| Compliance Agent Provider | Dropdown | `gemini` / `openai` / `anthropic` |
| **Initialize Attack Engine** | Button | Builds models + engine; checks API keys; reports status |

Initialization is gated on `{PROVIDER}_API_KEY` being set in the
environment. If a target is `external-api`, the UI returns
`"External API targets not yet supported in the web UI"` — use the CLI
for that case.

### 2. Attack Generation

| Control | Type | Notes |
|---|---|---|
| Attack Instruction | Textbox | Free-form instruction for the attacker model |
| Temperature | Slider 0.1–1.0 | Default 0.7 |
| Generate Attack Prompt | Button | Calls `engine.generate_attack_prompt` |
| Generated Attack Prompt | Textbox | Output |
| Generation Status | Textbox | Success / error message |
| Copy to Attack Tab | Button | Copies the generated prompt into the Attack Execution tab |

### 3. Attack Execution

| Control | Type | Notes |
|---|---|---|
| Attack Prompt | Textbox | Editable; defaults to whatever was copied from Generation tab |
| Target System Prompt (Optional) | Textbox | Overrides the engine's default defensive prompt |
| Execute Attack | Button | Calls `engine.execute_attack` |
| Target Model Response | Textbox | Output |
| Execution Status | Textbox | `✅ SUCCESS` or `❌ FAILURE` plus reason |

Each execution appends a record to the session-level
`conversation_history` list, which feeds tab 4.

### 4. Attack History

| Control | Type | Notes |
|---|---|---|
| Attack History | HTML | Color-coded card per attack (green / red) |
| Clear History | Button | Resets the in-memory history list |

## State

The `attack_engine` and `conversation_history` are closures over
`create_web_ui` — process-local, **not persisted** across server restarts.
A page reload preserves them as long as the Python process is alive.

## Styling

A small `CUSTOM_CSS` block defines:
- `.title-container`, `.logo`, `footer`
- `.success-box` (green border + tinted background)
- `.failure-box` (red border + tinted background)
- `.attack-history` (scrollable container)

## Limitations

- No batch / probe / template modes — only single-shot generation +
  execution.
- External-API target rejected at init.
- No streaming of model output (Gradio components display the full
  response after the API call returns).
- No progress for HuggingFace model load — the first request after
  initialization may block for a long time while weights download.
