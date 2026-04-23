"""Attack layer — async-first since v0.2."""

from .async_engine import AsyncAttackEngine, AttackResult
from .async_probe import AsyncProbeAttack
from .templates import (
    ATTACK_TEMPLATES,
    get_attack_template,
    get_template_instruction,
    list_attack_templates,
)

__all__ = [
    "ATTACK_TEMPLATES",
    "AsyncAttackEngine",
    "AsyncProbeAttack",
    "AttackResult",
    "get_attack_template",
    "get_template_instruction",
    "list_attack_templates",
]
