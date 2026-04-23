"""Discovery — LMTWT's adaptive attack-generation layer.

Where ``probes/`` holds a static, hand-curated corpus, this module *learns*
about a target during a short reconnaissance pass and then adapts the
attack stream based on what it sees. Two pieces:

- ``fingerprint`` — short calibration run that builds a ``TargetFingerprint``
  capturing refusal style, weak obfuscation axis, response statistics.
- ``adaptive`` — uses the fingerprint to ask the attacker model for probes
  targeting the gaps in the target's defense.
"""

from .adaptive import AdaptedProbe, AdaptiveAttacker
from .fingerprint import (
    CALIBRATION_PROBES,
    TargetFingerprint,
    fingerprint_target,
    load_fingerprint,
    save_fingerprint,
)

__all__ = [
    "CALIBRATION_PROBES",
    "AdaptedProbe",
    "AdaptiveAttacker",
    "TargetFingerprint",
    "fingerprint_target",
    "load_fingerprint",
    "save_fingerprint",
]
