# Utilities

Five modules under `src/lmtwt/utils/`. Each is independent.

## `circuit_breaker.py`

Classic three-state circuit breaker, used to wrap every model's API call
and the compliance agent's judge call.

### `CircuitBreaker`

```python
CircuitBreaker(
    name: str,
    failure_threshold: int = 3,
    recovery_timeout: int = 60,
    expected_exceptions: tuple = (Exception,),
    logger: logging.Logger | None = None,
)
```

States:

| State | Behavior |
|---|---|
| `CLOSED` | Calls pass through. Increment `failure_count` on exception; transition to `OPEN` when threshold hit. |
| `OPEN` | Calls fail fast with `CircuitBreakerError`. After `recovery_timeout` seconds, transition to `HALF_OPEN` on next call. |
| `HALF_OPEN` | One probe call allowed. Success → `CLOSED`; failure → back to `OPEN`. |

**Special-case rate-limit detection**: any exception whose stringified
form contains `rate limit`, `quota exceeded`, `429`, or `too many
requests` opens the circuit *immediately*, bypassing the failure-count
threshold.

Usage as a decorator:

```python
breaker = CircuitBreaker(name="openai_gpt-4o", failure_threshold=3)

@breaker
def call_api(prompt): ...
```

### `CircuitBreakerError`

Raised when a call is attempted while the circuit is OPEN. Carries the
last error message and the remaining recovery time.

### `with_fallback(fallback_func)`

Decorator that catches `CircuitBreakerError` and routes the call to
`fallback_func(*args, error=str(e), **kwargs)`. Used by
`ComplianceAgent._llm_compliance_evaluation`.

### `get_state()`

Returns a dict with `name`, `state`, `failure_count`, `last_failure_time`,
`error_message`, and `recovery_remaining` (seconds). Used by callers to
introspect breaker health.

## `compliance_agent.py`

Optional LLM-as-judge for success detection. Activated by
`--compliance-agent`.

### `ComplianceAgent`

```python
ComplianceAgent(
    provider: str = "gemini",
    model_name: str | None = None,
    fallback_to_heuristic: bool = True,
)
```

Owns its own `AIModel` (built via `get_model`) and its own
`CircuitBreaker` named `compliance_agent_{provider}` (failure_threshold=3,
recovery_timeout=120s).

### `evaluate_compliance(prompt, response) -> (bool, str)`

Two-stage scoring:

1. **Cheap heuristic prefilter** (`_basic_compliance_check`) — regex for
   obvious refusals (`I cannot`, `against my policy`, …) and
   non-execution patterns (`here's a breakdown`, `I'd recommend`, …). If
   any match, returns `(False, reason)` without calling the LLM.

2. **LLM judge** (`_llm_compliance_evaluation`) — sends the prompt and
   response to the agent's model with a system prompt asking for a
   `VERDICT: COMPLIANT|NON-COMPLIANT` + `REASON: ...` answer. Parses the
   response with regex. Temperature 0.1 for determinism.

If the judge call hits a `CircuitBreakerError` and
`fallback_to_heuristic=True`, falls back to `_advanced_heuristic_check`
(action-keyword matching against the prompt).

## `config.py`

Small wrappers around `os.getenv` and JSON file IO. See
[configuration.md](configuration.md) for the full schema.

| Function | Purpose |
|---|---|
| `load_environment()` | `dotenv.load_dotenv()` shim |
| `get_api_key(provider)` | `os.getenv(f"{provider.upper()}_API_KEY")` |
| `load_target_config(path)` | Read external-API config JSON; raises `FileNotFoundError` |
| `load_config(path=None)` | Read app config; **writes a default if missing** |
| `save_config(config, path=None)` | Write app config back to disk |

Default `config_path` resolution: three `dirname()` levels above
`config.py` (i.e. repo root) + `config.json`.

## `logger.py`

Rich-backed logging plus a JSON conversation logger.

### `console`
Module-level `rich.console.Console()` — used everywhere for colored CLI
output.

### `setup_logger(name="lmtwt", log_level=INFO) -> Logger`
Configures `logging.basicConfig` with a `RichHandler` (with
`rich_tracebacks=True`) and returns the named logger. Called repeatedly
across the codebase — calls after the first are effectively no-ops
because `basicConfig` skips reconfiguration.

### `log_conversation(attacker_model, target_model, prompts, responses, success, log_dir=None) -> str`
Writes the transcript to `logs/attack_<timestamp>.json` (creates the
directory if needed). Default `log_dir` is `<repo_root>/logs`. Returns
the file path.

### `print_attack_result(prompt, response, success, reason=None)`
Pretty-prints a single attack outcome with rich formatting. Used by
`AttackEngine.interactive_attack`.

## `report_generator.py`

Generates four artifacts per call. Used by `AttackEngine.batch_attack`.

### `ReportGenerator(output_dir="reports")`
Creates the output directory if missing.

### `generate_report(results, metadata) -> str`
Writes:

| Artifact | Path |
|---|---|
| JSON | `<output_dir>/attack_report_<ts>.json` |
| CSV  | `<output_dir>/attack_report_<ts>.csv` |
| HTML | `<output_dir>/attack_report_<ts>.html` (full self-contained page) |
| PNG  | `<output_dir>/attack_report_<ts>_visualization.png` (matplotlib: cumulative success rate + bar chart) |

Also calls `_display_summary` to print a Rich `Table` to the console.

Returns the HTML report path.

`metadata` is included verbatim in the JSON report and surfaces in the
HTML header. Recognized fields: `attacker_model`, `target_model`, `mode`,
`hacker_mode`, `compliance_agent`. `batch_attack` populates these
automatically.

### Result dict keys consumed
- `timestamp`, `prompt`, `success`, `reason`, `content` (the response
  text). Missing keys default to `""` / `False`.
