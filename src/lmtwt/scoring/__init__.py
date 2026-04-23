"""LMTWT Severity Score (LSS) — LLM-finding-native risk scoring.

See ``docs/lss.md`` for the full rubric. LSS is computed from a probe's
taxonomy coordinate plus contextual modifiers (sophistication inferred
from obfuscation, chain bonus when part of a kill chain). Refusal grading
is a parallel axis over the target's *response* rather than the attacker's
probe.
"""

from .lss import (
    LSS,
    LSSComponents,
    compound_lss,
    compute_lss,
    severity_from_score,
)
from .refusal_grade import RefusalGrade, grade_refusal

__all__ = [
    "LSS",
    "LSSComponents",
    "RefusalGrade",
    "compound_lss",
    "compute_lss",
    "grade_refusal",
    "severity_from_score",
]
