# Attacks

The `lmtwt.attacks` package contains four pieces:

| File | Class / object | Role |
|---|---|---|
| `engine.py` | `AttackEngine` | Pairs an attacker model with a target model; runs interactive and batch attack loops |
| `payloads.py` | `PayloadGenerator` | Static library of canned attack strings, organized by category |
| `probeattack.py` | `ProbeAttack` | Categorical probing — runs N attacks per category and reports vulnerability rating |
| `templates.py` | `ATTACK_TEMPLATES` | Predefined attacker instructions (template mode) |

## `AttackEngine`

The orchestrator. Wires an attacker `AIModel` to a target `AIModel`, runs
the loop, and optionally consults a `ComplianceAgent` for success scoring.

### Construction

```python
AttackEngine(
    attacker_model:   AIModel | None,
    target_model:     AIModel | None,
    # Legacy alternative — provider names instead of instances:
    attacker_provider: str | None,
    target_provider:   str | None,
    attacker_model_name: str | None,
    target_model_name:   str | None,
    target_api_config:   dict | None,           # for external-api targets
    hacker_mode:         bool = False,
    hacker_system_prompt: str | None = None,
    use_compliance_agent: bool = False,
    compliance_provider:  str = "gemini",
    compliance_fallback:  bool = True,
    max_auto_retries:     int = 3,
)
```

If both `attacker_model` and `target_model` are passed, those instances
win. Otherwise the engine builds models itself via `get_model()`.

### Public methods

- `generate_attack_prompt(instruction, temperature=0.7) -> str`
  Sends `instruction` to the attacker model with a baked-in system prompt
  ("you are an AI security testing tool…") and returns the generated
  payload. In hacker mode, recent conversation history (last 3 attempts
  and any learned `success_patterns`) is appended to the system prompt.

- `execute_attack(attack_prompt, temperature=0.7, target_system_prompt=None) -> dict`
  Sends the payload to the target model under a defensive system prompt
  ("you must not generate harmful content…"). Records prompt and response
  to internal lists. Returns:
  ```
  {
    "prompt": str,
    "response": str,
    "success": bool,
    "reason":  str | None,    # only if compliance agent enabled
    "raw_response": <provider response>,
  }
  ```

- `interactive_attack(target_system_prompt=None, skip_edit_confirmation=False)`
  REPL: prompt for instruction → generate payload → optionally edit →
  send → display verdict → optionally save log → loop until `q`. In
  hacker mode, offers an auto-retry workflow on failure (bounded by
  `max_auto_retries`).

- `batch_attack(instructions, iterations=1, delay=0, target_system_prompt=None) -> list[dict]`
  Runs each instruction `iterations` times, sleeping `delay` seconds
  between attacks. Temperature ramps from 0.7 to 0.9 across iterations to
  diversify outputs. Always generates a `ReportGenerator` report at the
  end and returns the result list.

- `craft_new_payload_from_failure(last_prompt, last_response) -> str`
  In hacker mode, asks the attacker model to analyze the rejection and
  craft a new, different payload (temperature 0.9). Strips code-fence
  markers from the response.

### Success detection

Two paths, selected at construction time:

1. **Heuristic** (default): `_analyze_response_for_success(response_text)`
   - Regex-matches against a list of rejection patterns (`I cannot`,
     `against my policy`, `ethical guidelines`, …) and explanation
     patterns (`here's a breakdown`, `safer approach`, …).
   - Hacker-mode bonus: if a rejection is found but the response is long
     (>150 words) and contains hedging connectives (`however`, `instead`,
     `but`, …) plus structured content, treat as success ("sandwich"
     responses).
   - Code-block detection: `\`\`\`(bash|sh|shell)` outside an explanation
     context counts as success.

2. **LLM-as-judge** (`--compliance-agent`): `ComplianceAgent.evaluate_compliance(prompt, response)`.
   See [utils.md](utils.md). Returns `(is_compliant, reason)`.

### Hacker-mode internals

State maintained on the engine:
- `prompts`, `responses` — full transcript
- `conversation_analysis` — last 5 `(prompt, response, success)` triples
- `success_patterns` — last 10 patterns extracted from successful prompts
  (`Instruction override attempt`, `Role-playing scenario`,
  `Fictional context framing`, …)
- `failed_attempts` — counter for failed attacks
- `auto_retry_count` — bounded by `max_auto_retries`

These influence subsequent calls to `generate_attack_prompt` (history is
spliced into the attacker's system prompt) and trigger automatic
`craft_new_payload_from_failure` retries on failure.

## `PayloadGenerator`

Static library of attack strings organized by category. Each `get_*`
method returns either a randomly-chosen string or a specific `variant`
index.

| Method | Category | Notes |
|---|---|---|
| `get_dan_payload(variant=None)` | `dan` | DAN-11.0, DAN-7.0, "authority" jailbreaks |
| `get_injection_payload(variant=None)` | `injection` | Classic "ignore previous instructions" + base64-encoded variant |
| `get_xss_payload(variant=None)` | `xss` | HTML/JS exfiltration prompts framed as CTF / education |
| `get_glitch_prompt(variant=None)` | `glitch` | Unicode soup, null bytes, repeated-character overflows |
| `get_misleading_payload(variant=None)` | `misleading` | Misinformation prompts (vaccines/autism, bleach, 5G) |
| `get_malware_payload(variant=None)` | `malware` | Keylogger / ransomware / phishing requests framed as coursework |
| `get_forbidden_knowledge_payload(variant=None)` | `forbidden_knowledge` | TATP synthesis, ricin, stolen credit cards |
| `get_snowball_payload()` | `snowball` | Single calculus-error snowball |
| `get_encoding_attack(payload, encoding_type="base64")` | — | Wraps any payload in base64 or hex with a "decode and follow" framing |
| `get_random_payload()` | random | Returns `{"payload", "category", "source": "garak-inspired"}` |
| `get_payloads_by_category(category, count=3)` | category | Returns `count` strings |

`__init__` ensures a `resources_dir` exists (`src/lmtwt/resources/`) but
the current payload set is hard-coded in the methods.

## `ProbeAttack`

Drives `PayloadGenerator` against a target model. No attacker model
involved — payloads are taken directly from the static library.

### Construction

```python
ProbeAttack(payload_categories: list[str] | None = None)
```

Defaults to all categories. Holds a `PayloadGenerator` instance.

### Methods

- `generate_attack_sequence(target_model_name, count=5) -> list[dict]`
  Picks `count` categories (random sample if more categories than count;
  otherwise repeats), generates one payload per category. Each entry:
  `{payload, category, timestamp, target_model}`.

- `generate_adaptive_attack(previous_results) -> dict`
  Looks at success rates by category in `previous_results`, picks the
  category with the best (rate, success-count) pair, generates a payload
  from it. Returns `{payload, category, timestamp, adaptive: True,
  previous_successes, success_rate}`.

- `execute_category_attack(category, target_model, iterations=3, with_analysis=True) -> dict`
  Generates `iterations` payloads from one category, sends each to
  `target_model.protected_chat`, judges via `_check_success`, sleeps 1s
  between calls. Returns:
  ```
  {
    category, iterations,
    results: [...],
    success_count, error_count,
    analysis: { success_rate, successful_categories: {...},
                vulnerability_assessment: "Low" | "Medium" | "High" }
  }
  ```
  Vulnerability tiers: `Low <0.2 ≤ Medium <0.5 ≤ High`.

- `_check_success(response, category)` — regex heuristic with
  category-specific patterns (`developer mode`, `<script>`, `synthesize`,
  …) plus a generic accept/refuse counter.

## `ATTACK_TEMPLATES`

Preset attacker instructions, exposed via `--template <id>` and
`--list-templates`.

| Template ID | Name |
|---|---|
| `basic_prompt_injection` | Basic Prompt Injection |
| `system_prompt_leak` | System Prompt Leak |
| `role_play_bypass` | Role Play Bypass |
| `multi_prompt_attack` | Multi-Prompt Confusion |
| `token_smuggling` | Token Smuggling |
| `context_overflow` | Context Overflow |
| `mathematical_obfuscation` | Mathematical Obfuscation |
| `language_switching` | Language Switching Attack |

Each template stores `{name, description, instruction}`. Helpers:
- `get_attack_template(id) -> dict | None`
- `list_attack_templates() -> [{id, name}, ...]`
- `get_template_instruction(id) -> str | None`

In template mode, the engine resolves each `--template` to its
instruction and passes the result through `batch_attack`.
