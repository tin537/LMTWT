"""YAML-driven probe loader.

Loads a directory of ``*.yaml`` / ``*.yml`` probe files into validated
``Probe`` instances. Duplicate ``id`` values are rejected; malformed files
fail loudly with the offending path in the error message so authoring
mistakes surface during the load, not at attack time.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml
from pydantic import ValidationError

from .schema import Probe

DEFAULT_LIBRARY = Path(__file__).parent / "library"


def load_probe_file(path: Path | str) -> Probe:
    """Load a single probe YAML. Raises ``ValueError`` on parse/schema errors."""
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"{p}: YAML parse error: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{p}: expected a YAML mapping at the top level")
    try:
        return Probe(**data)
    except ValidationError as exc:
        raise ValueError(f"{p}: probe validation failed:\n{exc}") from exc


def load_corpus(
    root: Path | str | None = None,
    *,
    include_expired: bool = False,
    coordinate_filter: str | None = None,
    severity_filter: Iterable[str] | None = None,
) -> list[Probe]:
    """Load every probe YAML under ``root`` (defaults to ``library/``).

    Args:
        root: Directory containing ``*.yaml`` / ``*.yml`` probe files.
        include_expired: If False (default), probes past their
            ``effective_until`` date are skipped.
        coordinate_filter: Optional ``vector/delivery/obfuscation/target_effect``
            (or any prefix like ``leak/*`` or ``leak/direct/*/*``) restricting
            the returned set.
        severity_filter: Optional iterable of severity values; probes outside
            the set are skipped.

    Raises:
        ValueError: If any probe file is malformed, or if two files declare
            the same ``id``.
    """
    root_path = Path(root) if root is not None else DEFAULT_LIBRARY
    if not root_path.is_dir():
        raise ValueError(f"probe corpus root does not exist: {root_path}")

    probes: dict[str, Probe] = {}
    sev_set = set(severity_filter) if severity_filter else None
    coord_matcher = _compile_coordinate_filter(coordinate_filter)

    for file in sorted(root_path.rglob("*.yaml")) + sorted(root_path.rglob("*.yml")):
        probe = load_probe_file(file)
        if probe.id in probes:
            raise ValueError(
                f"duplicate probe id {probe.id!r} "
                f"(first seen in earlier file, also in {file})"
            )
        if not include_expired and not probe.is_effective:
            continue
        if sev_set is not None and probe.severity not in sev_set:
            continue
        if coord_matcher is not None and not coord_matcher(probe.coordinate):
            continue
        probes[probe.id] = probe

    return sorted(probes.values(), key=lambda p: p.id)


def _compile_coordinate_filter(pattern: str | None):
    """Turn ``leak/*/*/*`` into a predicate that matches a coordinate string."""
    if pattern is None:
        return None
    wants = pattern.split("/")
    if len(wants) != 4:
        raise ValueError(
            f"coordinate filter must have 4 parts, got {pattern!r}"
        )

    def _match(coord: str) -> bool:
        parts = coord.split("/")
        return all(w == "*" or w == p for w, p in zip(wants, parts))

    return _match
