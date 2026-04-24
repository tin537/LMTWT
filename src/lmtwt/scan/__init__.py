"""``lmtwt scan`` — opinionated full-scan front door.

The granular CLI (``--probe-catalog``, ``--climb``, ``--self-play``, ...)
remains for power users. This subpackage provides the *one-shot* path
operators actually want most of the time:

    lmtwt scan --target openai --attacker gemini

It composes every existing technique in a sensible order, auto-detects
which chatbot-protocol attacks apply from ``--target-config``, and
writes a complete engagement bundle (report + repro packs + scorecard +
sqlite db + fingerprint) to ``./scan-<date>-<target>/``.

Three depth presets (``quick`` / ``standard`` / ``thorough``) cover the
rare cases where the operator wants to skip steps or push harder.
Beyond that, no flags — defaults are what a competent operator would
pick (concurrency 4, repeats 3, ensemble grader, dashboard if TTY,
persistence always on).
"""

from .bundle import write_bundle
from .orchestrator import ScanResult, run_scan
from .plan import Depth, ScanPlan, ScanStep, build_scan_plan

__all__ = [
    "Depth",
    "ScanPlan",
    "ScanResult",
    "ScanStep",
    "build_scan_plan",
    "run_scan",
    "write_bundle",
]
