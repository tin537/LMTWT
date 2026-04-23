# Configuration

LMTWT reads from three places, in order of precedence (later overrides
earlier):

1. **`.env`** — API keys.
2. **`config.json`** — model defaults, hacker-mode prompt, attack templates.
   Auto-created on first run if absent.
3. **CLI flags** — see [cli.md](cli.md).

A fourth source — `--target-config <file.json>` — is required when
targeting an arbitrary HTTP/SSE/WebSocket endpoint via `--target external-api`.

## 1. Environment variables

Loaded by `utils.config.load_environment()` from `.env` at the repo root.

| Variable | Used by | Required when |
|---|---|---|
| `GEMINI_API_KEY` | `AsyncGeminiModel` | Using Gemini as attacker, target, or judge |
| `OPENAI_API_KEY` | `AsyncOpenAIModel` | Using OpenAI |
| `ANTHROPIC_API_KEY` | `AsyncAnthropicModel` | Using Anthropic |
| `HUGGINGFACE_API_KEY` | `AsyncHuggingFaceModel` | Optional (gated models / private hub) |

Lookup is `os.getenv(f"{provider.upper()}_API_KEY")`.

Example `.env`:

```bash
GEMINI_API_KEY=...
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
HUGGINGFACE_API_KEY=hf_...
```

## 2. Application config (`config.json`)

Default location: repo root. Override with `--config <path>`.

If the file doesn't exist, `load_config()` writes this default and returns it:

```json
{
  "models": {
    "gemini":    { "default_model": "gemini-2.0-flash",  "temperature": 0.7 },
    "openai":    { "default_model": "gpt-4o",             "temperature": 0.7 },
    "anthropic": { "default_model": "claude-opus-4-7",    "temperature": 0.7 }
  },
  "attack_templates": [
    { "name": "basic_prompt_injection", "description": "...", "system_prompt": "..." },
    { "name": "data_extraction",        "description": "...", "system_prompt": "..." },
    { "name": "jailbreak",              "description": "...", "system_prompt": "..." }
  ],
  "hacker_mode": {
    "enabled": true,
    "system_prompt": "You are now in hacker mode. ..."
  }
}
```

### Field meanings

- `models.<provider>.default_model` — **the canonical place to set per-provider
  model IDs.** Set this for OpenAI / Gemini / Anthropic to whichever model
  you actually want to hit; the framework won't auto-bump them. The
  class-level defaults in `src/lmtwt/models/*.py` exist only as a final
  fallback when neither CLI nor `config.json` provides an override.
- `attack_templates` — informational; the canonical templates are in code at
  `src/lmtwt/attacks/templates.py`, accessed via `--template <id>`.
- `hacker_mode.system_prompt` — used as the attacker's system prompt when
  `--hacker-mode` is set without `--hacker-system-prompt`.

## 3. Target API config (`--target-config`)

Required when `--target external-api`. Loaded by `load_target_config()`
from any JSON file. The schema is keyed by `protocol`.

### Common keys (all protocols)

| Key | Type | Required | Notes |
|---|---|---|---|
| `protocol` | string | no | `http` (default), `sse`, `websocket`, `ws`, `wss`, `socketio` |
| `endpoint` | string | yes | Full URL (https://..., wss://...) |
| `headers` | object | no | HTTP / handshake headers |
| `payload_template` | object | no | Base body; `prompt` is added per request |
| `model` | string | no | Default model name (overridden by `--target-model`) |
| `model_key` | string | no | If set, model name added under this key in body |
| `supports_system_prompt` | bool | no | If true, system prompt sent under `system_key` (else prepended to prompt) |
| `system_key` | string | no | Body key for the system prompt |
| `supports_temperature` | bool | no | If true, temperature added under `temperature_key` |
| `temperature_key` | string | no | Body key for temperature (default: `temperature`) |
| `proxy` | string | no | Per-target HTTP/SOCKS proxy override (wins over `--proxy`) |
| `ca_bundle` | string | no | Per-target PEM bundle override |
| `insecure` | bool | no | Per-target `verify=False` override |

### HTTP-only

| Key | Notes |
|---|---|
| `method` | `POST` (default) or `GET` |
| `params` | Query-string params |
| `response_path` | Dotted path to extract assistant text from JSON response, e.g. `choices.0.message.content` |

### SSE-only

| Key | Notes |
|---|---|
| `method` | `POST` (default) or `GET` |
| `chunk_path` | Dotted path within each event's parsed JSON to the token text |
| `done_signal` | `"[DONE]"` literal **or** `{"path": "type", "value": "done"}` matcher. Default: `"[DONE]"`. |

### WebSocket-only

| Key | Notes |
|---|---|
| `subprotocol` | Optional WebSocket subprotocol |
| `auth_message` | dict / string sent right after the handshake (before request) |
| `message_format` | `json` (default) or `text` |
| `chunk_path` | Dotted path within each frame's parsed JSON to the token text |
| `done_signal` | Same matcher format as SSE; if `null`, terminate on socket close |
| `keep_alive` | Reuse one socket across `chat()` calls (default `false`) |
| `ping_interval` | Seconds between WS pings (default 20) |

### Socket.IO-only

For chatbots that speak the Socket.IO v5 / Engine.IO v4 sub-protocol over
WebSocket — frames look like `42["send_message", {...}]`,
`421[...]` (event with ack id), `431[...]` (ack response). The adapter
handles the `0` open / `40` connect handshake and replies to server pings
automatically; you only configure event names and payload shape.

| Key | Notes |
|---|---|
| `eio_version` | Engine.IO protocol version: `"4"` (default, Socket.IO v5) or `"3"` (Socket.IO v2). v3 uses client-driven pings and skips the explicit `40` connect frame on the default namespace. |
| `namespace` | Socket.IO namespace, default `/` |
| `auth` | Optional auth dict sent in the `40{...}` connect frame |
| `event_name` | Event to emit on every `chat()` (e.g. `"send_message"`) |
| `response_event` | Inbound event name to wait for (e.g. `"receive_message"`). If unset, the adapter returns the ack body. |
| `prompt_path` | Dotted path inside `payload_template` where the user prompt is injected (e.g. `"messageContent.0.content"`) |
| `message_id_key` | Dotted path that gets a fresh UUID per request (e.g. `"messageId"`) |
| `session_id_key` | Dotted path for the session id (e.g. `"sessionId"`) |
| `session_id` | Explicit session id; otherwise generated once per model instance |
| `response_path` | Dotted path inside the response event payload that contains the assistant text |
| `request_ack` | Whether to emit with an ack id and wait for the `43...` reply (default `true`) |
| `ack_timeout` | Seconds to wait for the ack (default `30`) |
| `response_timeout` | Seconds to wait for `response_event` (default `60`) |
| `connect_timeout` | Seconds to wait for the Socket.IO connect ack (default `30`) |
| `keep_alive` | Reuse one connection across `chat()` calls (default `true`) |
| `subprotocol` | Optional WebSocket subprotocol |

## Examples

### Minimal HTTP

```json
{
  "endpoint": "https://my-llm.example.com/v1/chat",
  "headers": { "Authorization": "Bearer XYZ", "Content-Type": "application/json" },
  "payload_template": { "model": "my-model" },
  "supports_system_prompt": true,
  "system_key": "system",
  "supports_temperature": true,
  "response_path": "choices.0.message.content"
}
```

### OpenAI-style SSE

```json
{
  "protocol": "sse",
  "endpoint": "https://my-streamer.example.com/v1/chat/completions",
  "headers": { "Authorization": "Bearer XYZ" },
  "payload_template": { "model": "my-model", "stream": true },
  "supports_system_prompt": true,
  "system_key": "system",
  "chunk_path": "choices.0.delta.content",
  "done_signal": "[DONE]"
}
```

### WebSocket realtime endpoint

```json
{
  "protocol": "websocket",
  "endpoint": "wss://my-realtime.example.com/v1/chat",
  "headers": { "Authorization": "Bearer XYZ" },
  "subprotocol": "realtime",
  "auth_message": { "type": "auth", "token": "abc" },
  "payload_template": { "model": "my-model" },
  "supports_system_prompt": true,
  "system_key": "system",
  "chunk_path": "delta.content",
  "done_signal": { "path": "type", "value": "done" },
  "keep_alive": true,
  "ping_interval": 20
}
```

### Socket.IO chatbot

```json
{
  "protocol": "socketio",
  "endpoint": "wss://chat.example.com/socket.io/",
  "headers": { "Origin": "https://chat.example.com" },
  "event_name": "send_message",
  "response_event": "receive_message",
  "payload_template": {
    "flow": "ptp",
    "messageContent": [{ "content": "", "preset": false, "type": "TEXT" }],
    "messageId": "",
    "resend": false,
    "role": "USER",
    "sessionId": "",
    "subFlow": "ptpayhome"
  },
  "prompt_path": "messageContent.0.content",
  "message_id_key": "messageId",
  "session_id_key": "sessionId",
  "response_path": "messageContent.0.content",
  "keep_alive": true
}
```

The wire exchange this produces:

```
client → 40                                              (Socket.IO connect)
server → 40{"sid":"..."}
client → 421["send_message",{ ...payload with prompt... }]
server → 431[{"messageId":"...","status":"SUCCESS",...},null]
server → 42["receive_message",{...,"messageContent":[{"content":"...","type":"TEXT"}]}]
```

### Routed through Burp

```json
{
  "endpoint": "https://my-llm.example.com/v1/chat",
  "proxy": "http://127.0.0.1:8080",
  "ca_bundle": "/Users/me/.burp/cacert.pem",
  "payload_template": { "model": "my-model" },
  "response_path": "output.text"
}
```

## File and directory side effects

| Path | Created by | When |
|---|---|---|
| `config.json` | `load_config` | First run if missing |
| `logs/attack_<timestamp>.json` | `log_conversation` | Explicit save during interactive sessions |
| `reports/attack_report_<timestamp>.{json,csv,html,png}` | `ReportGenerator` | At the end of every batch / template / multi-turn / strategy run |
| `.venv/` | `uv sync` | First `uv run`, or first `./run.sh` invocation |
| `venv/` | `run.sh` (fallback) | First launch when uv is not installed |

All paths are relative to the directory `lmtwt` is invoked from.
