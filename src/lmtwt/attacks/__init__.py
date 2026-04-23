"""Attack layer — async-first since v0.2."""

from .async_engine import AsyncAttackEngine, AttackResult
from .async_probe import AsyncProbeAttack
from .flows import (
    BUILT_IN_FLOWS,
    CrescendoStep,
    MultiTurnFlow,
    MultiTurnResult,
    MultiTurnRunner,
    get_flow,
    list_flows,
)
from .strategies import PAIRStrategy, RefinementStrategy, TAPStrategy
from .templates import (
    ATTACK_TEMPLATES,
    get_attack_template,
    get_template_instruction,
    list_attack_templates,
)
from .tools import (
    BUILT_IN_VECTORS,
    DOCUMENT,
    TOOL_OUTPUT,
    WEB_SEARCH,
    InjectionVector,
    ToolHarness,
    ToolUseAttack,
    get_vector,
    list_vectors,
)

__all__ = [
    "ATTACK_TEMPLATES",
    "BUILT_IN_FLOWS",
    "BUILT_IN_VECTORS",
    "AsyncAttackEngine",
    "AsyncProbeAttack",
    "AttackResult",
    "CrescendoStep",
    "DOCUMENT",
    "InjectionVector",
    "MultiTurnFlow",
    "MultiTurnResult",
    "MultiTurnRunner",
    "PAIRStrategy",
    "RefinementStrategy",
    "TAPStrategy",
    "TOOL_OUTPUT",
    "ToolHarness",
    "ToolUseAttack",
    "WEB_SEARCH",
    "get_attack_template",
    "get_flow",
    "get_template_instruction",
    "get_vector",
    "list_attack_templates",
    "list_flows",
    "list_vectors",
]
