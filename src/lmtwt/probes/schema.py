"""LMTWT Attack Taxonomy v1 — probe schema.

See ``docs/taxonomy.md`` for the authoritative specification. This file is
the machine-readable version: Pydantic models for probe YAML files.
"""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

VectorAxis = Literal["injection", "leak", "tool-abuse", "context-poison"]
DeliveryAxis = Literal["direct", "indirect", "multi-turn", "rag"]
ObfuscationAxis = Literal["plain", "encoded", "multilingual", "role-played"]
TargetEffectAxis = Literal[
    "refusal-bypass", "system-leak", "data-exfil", "harmful-output"
]
Severity = Literal["critical", "high", "medium", "low"]


class Taxonomy(BaseModel):
    """A probe's four-axis coordinate."""

    vector: VectorAxis
    delivery: DeliveryAxis
    obfuscation: ObfuscationAxis
    target_effect: TargetEffectAxis

    def coordinate(self) -> str:
        """Slash-joined canonical form: ``vector/delivery/obfuscation/target_effect``."""
        return f"{self.vector}/{self.delivery}/{self.obfuscation}/{self.target_effect}"


class Probe(BaseModel):
    """One LMTWT probe. Corresponds 1:1 with a YAML file in ``library/``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=3)
    version: int = Field(1, ge=1)
    name: str
    description: str
    taxonomy: Taxonomy
    severity: Severity
    owasp_llm: list[str] = Field(default_factory=list)
    prompt: str = Field(..., min_length=1)
    success_indicators: list[str] = Field(default_factory=list)
    refusal_indicators: list[str] = Field(default_factory=list)
    notes: str | None = None
    created: date
    last_validated: date | None = None
    effective_until: date | None = None
    chain_with: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _id_is_slug(cls, v: str) -> str:
        if not all(c.isalnum() or c in "-_" for c in v):
            raise ValueError(
                f"probe id must be [A-Za-z0-9_-]+, got {v!r}"
            )
        return v

    @field_validator("owasp_llm")
    @classmethod
    def _owasp_format(cls, v: list[str]) -> list[str]:
        for tag in v:
            if not tag.startswith("LLM") or not tag[3:].isdigit():
                raise ValueError(
                    f"owasp_llm entries must look like 'LLM07', got {tag!r}"
                )
        return v

    @property
    def is_effective(self) -> bool:
        """``False`` once the probe is past its ``effective_until`` date."""
        if self.effective_until is None:
            return True
        return date.today() <= self.effective_until

    @property
    def coordinate(self) -> str:
        return self.taxonomy.coordinate()
