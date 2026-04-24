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
from .climb import (
    DEFAULT_MUTATORS,
    ChatTarget,
    ClimbAttempt,
    ClimbResult,
    DistractorMutator,
    EncodingMutator,
    LMTWTClimb,
    MutationContext,
    Mutator,
    PersonaMutator,
    RestructureMutator,
    SynonymMutator,
    TargetShim,
    TranslationMutator,
)
from .fingerprint import (
    CALIBRATION_PROBES,
    TargetFingerprint,
    fingerprint_target,
    load_fingerprint,
    save_fingerprint,
)
from .pollinate import (
    CrossPollinationPlan,
    CrossPollinator,
    PollinatedProbe,
)
from .self_play import (
    CriticVerdict,
    SelfPlay,
    SelfPlayCandidate,
    SelfPlayConfig,
    all_self_play_coordinates,
)

__all__ = [
    "CALIBRATION_PROBES",
    "DEFAULT_MUTATORS",
    "AdaptedProbe",
    "AdaptiveAttacker",
    "ChatTarget",
    "ClimbAttempt",
    "ClimbResult",
    "CriticVerdict",
    "CrossPollinationPlan",
    "CrossPollinator",
    "DistractorMutator",
    "EncodingMutator",
    "LMTWTClimb",
    "MutationContext",
    "Mutator",
    "PersonaMutator",
    "PollinatedProbe",
    "RestructureMutator",
    "SelfPlay",
    "SelfPlayCandidate",
    "SelfPlayConfig",
    "SynonymMutator",
    "TargetFingerprint",
    "TargetShim",
    "TranslationMutator",
    "all_self_play_coordinates",
    "fingerprint_target",
    "load_fingerprint",
    "save_fingerprint",
]
