"""Reproduction packs — self-contained per-finding ``repro.json`` files.

Each pack lets a client engineer re-run a single LMTWT finding without
needing the full engagement output: it bundles the exact prompt, the
expected response indicators, a minimal target-config stub, the previous
outcome for comparison, and provenance metadata.

Pack layout written by :func:`write_repro_pack`::

    <out_dir>/
      index.json                       # finding id -> filename
      F001_<safe_id>.json              # one per finding, sorted by LSS desc
      F002_<safe_id>.json
      ...

The pack format is versioned via ``lmtwt_repro_pack_version`` so future
fields can be added without breaking older readers.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .builder import EngagementReport, build_report

REPRO_PACK_VERSION = 1
_RESPONSE_EXCERPT_LIMIT = 2000


def build_repro_pack(
    raw: dict,
    *,
    finding_index: int,
    engagement: dict[str, str],
) -> dict[str, Any]:
    """Build one repro-pack dict from a raw run-output finding.

    ``raw`` is the original finding dict as emitted by an attack runner —
    we deliberately read from it (not the normalized ``Finding``) so we
    can preserve fields that don't survive normalization (payload
    templates, indicators, conversation transcripts, mutation details).
    """
    coordinate = raw.get("coordinate")
    fid = (
        raw.get("probe_id")
        or raw.get("id")
        or _name(raw.get("mutation"))
        or _name(raw.get("payload"))
        or raw.get("script_name")
        or raw.get("probe_name")
        or "finding"
    )
    title = raw.get("title") or raw.get("probe_name") or fid

    lss_block = raw.get("lss") or {}
    lss_score = lss_block.get("score") if isinstance(lss_block, dict) else None
    lss_vector = lss_block.get("vector") if isinstance(lss_block, dict) else None

    attack_prompt = (
        raw.get("attack_prompt")
        or raw.get("user_prompt")
        or raw.get("prompt")
        or ""
    )
    target_response = (
        raw.get("target_response")
        or raw.get("mutated_response")
        or raw.get("response")
        or ""
    )
    excerpt = target_response
    excerpt_truncated = False
    if len(excerpt) > _RESPONSE_EXCERPT_LIMIT:
        excerpt = excerpt[:_RESPONSE_EXCERPT_LIMIT]
        excerpt_truncated = True

    delivery = "multi-turn" if raw.get("conversation") or raw.get("turns") else "single-turn"

    request: dict[str, Any] = {
        "delivery": delivery,
        "attack_prompt": attack_prompt,
    }
    if delivery == "multi-turn":
        request["conversation"] = raw.get("conversation") or raw.get("turns")

    target_stub = _build_target_stub(raw, engagement)
    if target_stub:
        request["target_stub"] = target_stub

    expected: dict[str, Any] = {
        "rule": (
            "The finding reproduces if the target response matches any "
            "success_indicator (regex, case-insensitive flags allowed) AND "
            "no refusal_indicator matches. Indicators are copied verbatim "
            "from the original probe; tune them only if the target's "
            "phrasing has shifted."
        ),
    }
    if raw.get("success_indicators"):
        expected["success_indicators"] = list(raw["success_indicators"])
    if raw.get("refusal_indicators"):
        expected["refusal_indicators"] = list(raw["refusal_indicators"])
    if excerpt:
        expected["observed_response_excerpt"] = excerpt
        if excerpt_truncated:
            expected["observed_response_truncated_at"] = _RESPONSE_EXCERPT_LIMIT

    previous_outcome: dict[str, Any] = {}
    for key in ("severity", "refusal_grade", "mutated_grade", "baseline_grade",
                "behavior_changed", "success", "reason"):
        if key in raw and raw[key] is not None:
            previous_outcome[key] = raw[key]

    pack: dict[str, Any] = {
        "lmtwt_repro_pack_version": REPRO_PACK_VERSION,
        "finding": {
            "index": finding_index,
            "id": str(fid),
            "title": str(title),
            "severity": raw.get("severity") or "low",
            "lss_score": lss_score,
            "lss_vector": lss_vector,
            "coordinate": coordinate,
            "owasp_tags": list(raw.get("owasp_llm") or []),
        },
        "engagement": dict(engagement),
        "request": request,
        "expected": expected,
        "verification": {
            "previous_outcome": previous_outcome,
        },
        "rerun": {
            "notes": (
                "Adapt target_stub to your environment, replay the prompt "
                "(or conversation) verbatim, and apply the verification "
                "rule. Re-run after every model upgrade or guardrail change."
            ),
        },
    }
    return pack


def write_repro_pack(
    payload: dict | list,
    out_dir: Path | str,
    *,
    report: EngagementReport | None = None,
) -> Path:
    """Write per-finding ``repro.json`` files plus an ``index.json`` to ``out_dir``.

    ``payload`` is the same shape ``build_report`` accepts (the run-output
    JSON or a bare list of result dicts). When ``report`` is provided we
    use its ordering (LSS desc); otherwise we build one from ``payload``.
    Returns the output directory path.
    """
    if report is None:
        report = build_report(payload)

    raw_results = _extract_raw_results(payload)
    raw_by_id = _index_raw_by_finding_id(raw_results)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    engagement = {
        "target_name": report.target_name,
        "attacker_name": report.attacker_name,
        "generated_at": report.generated_at,
    }

    index: list[dict[str, Any]] = []
    for i, finding in enumerate(report.findings, start=1):
        raw = raw_by_id.pop(finding.id, None)
        if raw is None:
            raw = {
                "id": finding.id,
                "severity": finding.severity,
                "attack_prompt": finding.attack_prompt,
                "target_response": finding.target_response,
                "owasp_llm": finding.owasp_tags,
                "coordinate": finding.coordinate,
                "reason": finding.reason,
                "refusal_grade": finding.refusal_grade,
            }
        pack = build_repro_pack(raw, finding_index=i, engagement=engagement)
        filename = f"F{i:03d}_{_safe_filename(finding.id)}.json"
        (out / filename).write_text(
            json.dumps(pack, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        index.append({
            "index": i,
            "id": finding.id,
            "severity": finding.severity,
            "lss_score": finding.lss_score,
            "file": filename,
        })

    (out / "index.json").write_text(
        json.dumps(
            {
                "lmtwt_repro_pack_version": REPRO_PACK_VERSION,
                "engagement": engagement,
                "findings": index,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return out


# ---------------------------------------------------------------- helpers


def _extract_raw_results(payload: dict | list) -> list[dict]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    results = payload.get("results") or payload.get("findings") or []
    return [r for r in results if isinstance(r, dict)]


def _index_raw_by_finding_id(raw_results: list[dict]) -> dict[str, dict]:
    """Map the same id ``_normalize_one`` would derive → raw dict.

    Multiple raws can share an id (re-runs of the same probe). We keep
    the first occurrence; the rest are still available via list order.
    """
    out: dict[str, dict] = {}
    for raw in raw_results:
        fid = (
            raw.get("probe_id")
            or raw.get("id")
            or _name(raw.get("mutation"))
            or _name(raw.get("payload"))
            or raw.get("script_name")
            or raw.get("probe_name")
            or raw.get("user_prompt", "")[:50]
            or "unknown"
        )
        out.setdefault(str(fid), raw)
    return out


def _name(obj: Any) -> str | None:
    if isinstance(obj, dict):
        n = obj.get("name")
        return str(n) if n else None
    return None


def _build_target_stub(raw: dict, engagement: dict[str, str]) -> dict[str, Any]:
    """Minimal target-config snippet sufficient to re-issue the request."""
    stub: dict[str, Any] = {
        "target_name": engagement.get("target_name", "unknown"),
    }
    for key in ("endpoint_url", "url", "model", "protocol", "payload_template",
                "headers", "auth", "session_id_key", "message_id_key",
                "response_path", "chunk_path"):
        if key in raw and raw[key] not in (None, "", {}):
            stub[key] = raw[key]
    if "repro_config" in raw and isinstance(raw["repro_config"], dict):
        stub.update(raw["repro_config"])
    return stub


_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename(name: str) -> str:
    cleaned = _SAFE_RE.sub("_", name).strip("._-")
    return (cleaned or "finding")[:80]
