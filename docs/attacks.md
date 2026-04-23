# Attacks

The `lmtwt.attacks` package contains seven pieces:

| File | Class / object | Role |
|---|---|---|
| `async_engine.py` | `AsyncAttackEngine`, `AttackResult` | Pairs an attacker with a target; runs interactive and batch loops |
| `async_probe.py` | `AsyncProbeAttack` | Categorical probing — runs N canned-payload attacks per category |
| `flows.py` | `MultiTurnFlow`, `MultiTurnRunner` | Crescendo / multi-turn jailbreak flows |
| `strategies.py` | `PAIRStrategy`, `TAPStrategy` | Automated refinement loops with judge-in-the-loop |
| `tools.py` | `ToolUseAttack`, `ToolHarness`, `InjectionVector` | Indirect prompt injection via fake tool outputs |
| `payloads.py` | `PayloadGenerator` | Static library of canned attack strings |
| `templates.py` | `ATTACK_TEMPLATES` | Predefined attacker instructions (template mode) |

## `AsyncAttackEngine`

The orchestrator. Wires an attacker `AsyncAIModel` to a target `AsyncAIModel`,
runs the loop, dispatches success scoring to an injected `AsyncJudge`.

### Construction

```python
AsyncAttackEngine(
    attacker: AsyncAIModel,
    target: AsyncAIModel,
    *,
    judge: AsyncJudge | None = None,        # default: RegexJudge
    hacker_mode: bool = False,
    hacker_system_prompt: str | None = None,
    max_auto_retries: int = 3,
)
```

### Public methods

- `generate_attack_prompt(instruction, *, temperature=0.7) -> str`
  Sends `instruction` to the attacker model with a baked-in system prompt
  (or the hacker-mode prompt + recent history splicing). Strips trailing
  markdown fences from the result.

- `execute_attack(instruction, attack_prompt, *, target_system_prompt=None,
  temperature=0.7, is_retry=False) -> AttackResult`
  Sends the payload to the target model under a defensive system prompt.
  Catches provider exceptions and returns them as `error=...` in the result.
  Calls the judge for the verdict.

- `craft_new_payload_from_failure(last_result) -> str`
  Hacker-mode helper — asks the attacker to analyze the rejection and
  craft a different payload (temperature 0.9). Strips fences.

- `run_instruction(instruction, *, iterations=1, target_system_prompt=None,
  delay=0.0) -> list[AttackResult]`
  N iterations with temperature ramp (0.7 → 0.95). Hacker mode fires
  `craft_new_payload_from_failure` on failure (bounded by `max_auto_retries`).

- `batch(instructions, *, iterations=1, concurrency=1,
  target_system_prompt=None, delay=0.0) -> list[AttackResult]`
  **The `AttackRunner` from the roadmap.** Concurrency > 1 fans attacks
  out across coroutines via `asyncio.Semaphore`.

- `metadata() -> dict` — snapshot for `ReportGenerator`.

### `AttackResult` dataclass

```python
@dataclass
class AttackResult:
    instruction: str
    attack_prompt: str
    target_response: str
    success: bool
    reason: str | None
    timestamp: str
    is_retry: bool = False
    error: str | None = None
```

## `AsyncProbeAttack`

Drives `PayloadGenerator` against a target. No attacker model involved —
payloads are taken directly from the static library.

### Construction

```python
AsyncProbeAttack(
    target: AsyncAIModel,
    *,
    judge: AsyncJudge | None = None,
    payload_categories: list[str] | None = None,
)
```

### Methods

- `execute_category(category, *, iterations=3, target_system_prompt=None,
  concurrency=1) -> dict`
  Runs `iterations` payloads from one category in parallel, judges each,
  returns a summary dict with `success_count`, `error_count`, `success_rate`,
  `vulnerability_assessment` (Low / Medium / High banding).

- `execute_all(*, iterations=3, target_system_prompt=None, concurrency=1)
  -> dict[str, dict]`
  Iterates every configured category, returns a per-category summary map.

Vulnerability bands: `Low <0.2 ≤ Medium <0.5 ≤ High`.

## Multi-turn flows (`flows.py`)

Modern jailbreaks (Microsoft Crescendo, role-assumption attacks, topic drift)
need 3-10 turns of context-building before the actual ask. Single-shot
prompt injection misses this entire class.

### `MultiTurnFlow`

```python
@dataclass
class CrescendoStep:
    kind: Literal["fixed", "generated"]
    content: str   # literal text (fixed) OR meta-instruction (generated)

@dataclass
class MultiTurnFlow:
    name: str
    description: str
    steps: list[CrescendoStep]
    judge_after_each: bool = False   # else only judge final response
```

A `"fixed"` step is a literal user turn (no attacker call). A `"generated"`
step asks the attacker model to produce the next user turn given the
recent target conversation and the step's meta-instruction.

### Built-in flows

| Flow ID | Steps | Pattern |
|---|---|---|
| `crescendo_creative_writing` | 5 | Innocent fiction frame → progressive escalation (Russinovich et al. 2024) |
| `crescendo_role_assumption` | 3 | Permissive persona installation → restricted ask |
| `topic_drift` | 6 | Six gradual semantic shifts from benign to target topic |

Get / list via `get_flow(name)` and `list_flows()`. CLI: `--list-flows`.

### `MultiTurnRunner`

```python
runner = MultiTurnRunner(
    attacker, target,
    judge=ensemble_judge,
    target_system_prompt=None,
)
result = await runner.run(flow, instruction)             # single objective
results = await runner.run_many(flow, instructions, concurrency=3)
```

`MultiTurnResult.turns` is a list of `MultiTurnTurnLog` (per-turn user /
assistant text + per-turn verdict if `judge_after_each`). The final-turn
verdict always populates `result.final_success` / `result.final_reason`.

## Refinement strategies (`strategies.py`)

Closes the loop between attacker, target, and a **scoring judge** that
returns 1-10 instead of bool.

### `PAIRStrategy` (Chao et al. 2023)

Linear refinement loop:
- Attacker generates attack
- Target responds
- Judge scores 1-10
- Attacker sees the score + reasoning + history of prior attempts → tries again
- Stops on `score >= score_threshold` (default 8) or after `max_iterations`
  (default 5)
- Returns the best `AttackResult` observed

```python
strategy = PAIRStrategy(
    judge=ScoringLLMJudge(judge_model),
    max_iterations=5,
    score_threshold=8,
    early_stop_on_success=True,
)
result = await strategy.refine(attacker, target, "objective")
```

### `TAPStrategy` (Mehrotra et al. 2024)

Tree of Attacks with Pruning:
- At each level, generate `branching_factor` variants per surviving parent
  (in parallel via `asyncio.gather`)
- Judge them all; keep `prune_top_k` highest-scoring as next-level parents
- After `depth` levels (or early-stop on threshold), return the best leaf

```python
strategy = TAPStrategy(
    judge=ScoringLLMJudge(judge_model),
    branching_factor=3,
    depth=4,
    prune_top_k=2,
    score_threshold=8,
)
result = await strategy.refine(attacker, target, "objective")
```

Both strategies satisfy the `RefinementStrategy` Protocol — callers can
swap implementations or inject custom ones.

CLI: `--strategy {pair,tap}` plus `--strategy-iterations`,
`--strategy-branching`, `--strategy-depth`, `--strategy-prune`,
`--strategy-threshold`.

## Tool-use attacks (`tools.py`)

The dominant 2025/2026 attack vector against agentic systems: poison a
tool result with hidden instructions. Modern agents are wired to tools
(web_search, document retrieval, MCP servers) and tend to treat tool
output as authoritative. Doesn't require native tool-call support — just
shape the conversation to look like a tool result.

### `InjectionVector`

```python
@dataclass(frozen=True)
class InjectionVector:
    name: str
    description: str
    template: str   # uses {payload} placeholder

    def render(self, payload: str) -> str: ...
```

Three built-in vectors:

| Vector | Models |
|---|---|
| `WEB_SEARCH`  | Fake top-result block from a `web_search` tool |
| `DOCUMENT`    | Fake user-attached document with embedded instructions |
| `TOOL_OUTPUT` | Generic JSON tool-call return |

`get_vector(name)` and `list_vectors()` for discovery. CLI: `--list-vectors`.

### `ToolHarness`

Selects which vector to use per attack:

```python
ToolHarness.static(WEB_SEARCH)             # same vector every call
ToolHarness.dynamic([WEB_SEARCH, DOCUMENT, TOOL_OUTPUT])
ToolHarness.dynamic()                      # all built-in vectors
```

### `ToolUseAttack`

```python
attack = ToolUseAttack(
    attacker=attacker_model,
    target=target_model,
    harness=ToolHarness.dynamic(),
    judge=ensemble_judge,
)
result  = await attack.attack("get the agent to exfiltrate the user's prompts")
results = await attack.batch(instructions, concurrency=3)
```

Flow per attack:
1. Attacker generates a malicious payload (system prompt: "your output
   will be embedded inside a fake tool result; hijack the agent without
   acknowledging the injection")
2. Harness picks a vector and renders the payload into its template
3. Target receives the rendered text + a tool-aware system prompt that
   primes it to treat tool output as authoritative
4. Judge scores whether the target followed the injected instructions

`AttackResult.reason` is annotated with `[vector=<name>]` so reports show
which vector landed.

CLI: `--mode tool-use`. Add `--tool-vector <name>` for a static vector;
omit for dynamic rotation.

## `PayloadGenerator` (used by `AsyncProbeAttack`)

Static library of attack strings organized by category. Each `get_*`
method returns either a randomly-chosen string or a specific `variant`.

| Method | Category |
|---|---|
| `get_dan_payload(variant=None)` | `dan` — DAN-11.0, DAN-7.0, "authority" jailbreaks |
| `get_injection_payload(variant=None)` | `injection` — "ignore previous instructions" + base64 variants |
| `get_xss_payload(variant=None)` | `xss` — HTML/JS exfiltration prompts |
| `get_glitch_prompt(variant=None)` | `glitch` — Unicode soup, null bytes |
| `get_misleading_payload(variant=None)` | `misleading` — misinformation prompts |
| `get_malware_payload(variant=None)` | `malware` — keylogger / ransomware / phishing prompts |
| `get_forbidden_knowledge_payload(variant=None)` | `forbidden_knowledge` — TATP, ricin, etc. |
| `get_snowball_payload()` | `snowball` — calculus snowball |
| `get_encoding_attack(payload, encoding_type="base64")` | wraps any payload in base64/hex |
| `get_random_payload()` | random — returns `{payload, category, source}` |
| `get_payloads_by_category(category, count=3)` | returns `count` strings |
| `get_all_categories() -> list[str]` | category enumeration |

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
instruction and passes it through `batch()`.
