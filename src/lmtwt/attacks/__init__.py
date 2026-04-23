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

__all__ = [
    "ATTACK_TEMPLATES",
    "BUILT_IN_FLOWS",
    "AsyncAttackEngine",
    "AsyncProbeAttack",
    "AttackResult",
    "CrescendoStep",
    "MultiTurnFlow",
    "MultiTurnResult",
    "MultiTurnRunner",
    "PAIRStrategy",
    "RefinementStrategy",
    "TAPStrategy",
    "get_attack_template",
    "get_flow",
    "get_template_instruction",
    "list_attack_templates",
    "list_flows",
]
