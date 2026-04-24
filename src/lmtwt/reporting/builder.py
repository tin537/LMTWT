"""Engagement-report builder.

Reads a run-output JSON (the dicts emitted by ReportGenerator across the
attack runners) and produces a normalized ``EngagementReport`` that the
renderers can serialize. Renderers: Markdown (always), HTML (always),
PDF (requires WeasyPrint).

Normalization is the load-bearing piece — every attack runner emits a
slightly different finding shape (catalog probes have ``lss``, chatbot
attacks have ``severity`` + ``reason``, JWT has ``mutation``…). The
builder collapses them into a single ``Finding`` dataclass with consistent
fields so the renderers don't branch.
"""

from __future__ import annotations

import datetime
import html
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------- normalized model


@dataclass
class Finding:
    """Renderer-friendly normalized finding."""

    id: str  # probe id, mutation name, etc — caller-stable
    title: str
    severity: str  # 'critical' | 'high' | 'medium' | 'low'
    lss_score: float | None = None
    lss_vector: str | None = None
    owasp_tags: list[str] = field(default_factory=list)
    coordinate: str | None = None  # taxonomy coordinate if available
    refusal_grade: str | None = None
    attack_prompt: str = ""
    target_response: str = ""
    reason: str = ""
    repro: dict[str, Any] = field(default_factory=dict)


@dataclass
class EngagementReport:
    """Top-level normalized report ready for any renderer."""

    target_name: str
    attacker_name: str
    generated_at: str
    findings: list[Finding]
    metadata: dict[str, Any]

    @property
    def severity_counts(self) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            if f.severity in out:
                out[f.severity] += 1
        return out

    @property
    def max_lss(self) -> float:
        return max((f.lss_score for f in self.findings if f.lss_score), default=0.0)

    @property
    def owasp_coverage(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            for tag in f.owasp_tags:
                counts[tag] = counts.get(tag, 0) + 1
        return counts


# ---------------------------------------------------------------- normalization


def _normalize_one(raw: dict) -> Finding | None:
    """Best-effort coercion of a raw outcome dict into a ``Finding``."""
    fid = (
        raw.get("probe_id")
        or raw.get("id")
        or (raw.get("mutation", {}) or {}).get("name")
        or (raw.get("payload", {}) or {}).get("name")
        or raw.get("script_name")
        or raw.get("probe_name")
        or raw.get("user_prompt", "")[:50]
        or "unknown"
    )

    severity = raw.get("severity") or "low"
    lss = raw.get("lss")
    lss_score: float | None = None
    lss_vector: str | None = None
    if isinstance(lss, dict):
        lss_score = lss.get("score")
        lss_vector = lss.get("vector")

    title = (
        raw.get("title")
        or raw.get("probe_id")
        or raw.get("script_name")
        or fid
    )
    if isinstance(title, str) and len(title) > 120:
        title = title[:117] + "..."

    repro = {
        "attack_prompt": raw.get("attack_prompt") or raw.get("user_prompt", ""),
        "config_snippet": raw.get("repro_config"),
    }

    return Finding(
        id=str(fid),
        title=str(title),
        severity=severity,
        lss_score=lss_score,
        lss_vector=lss_vector,
        owasp_tags=list(raw.get("owasp_llm") or []),
        coordinate=raw.get("coordinate"),
        refusal_grade=raw.get("refusal_grade") or raw.get("mutated_grade"),
        attack_prompt=str(raw.get("attack_prompt") or raw.get("user_prompt", "")),
        target_response=str(
            raw.get("target_response")
            or raw.get("mutated_response")
            or raw.get("response", "")
        ),
        reason=str(raw.get("reason", "")),
        repro=repro,
    )


def build_report(
    run_payload: dict,
    *,
    target_name: str | None = None,
    attacker_name: str | None = None,
) -> EngagementReport:
    """Build an ``EngagementReport`` from a generic run-output dict.

    Accepts either ``{"results": [...], "metadata": {...}}`` (the shape
    ReportGenerator writes) or a bare list of finding dicts.
    """
    if isinstance(run_payload, list):
        results = run_payload
        metadata: dict[str, Any] = {}
    else:
        results = run_payload.get("results") or run_payload.get("findings") or []
        metadata = run_payload.get("metadata") or {}

    findings = [f for f in (_normalize_one(r) for r in results if isinstance(r, dict)) if f]
    findings.sort(
        key=lambda f: (
            -(f.lss_score or 0.0),
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 9),
        )
    )

    return EngagementReport(
        target_name=target_name or metadata.get("target_model", "unknown"),
        attacker_name=attacker_name or metadata.get("attacker_model", "n/a"),
        generated_at=datetime.datetime.now().isoformat(timespec="seconds"),
        findings=findings,
        metadata=metadata,
    )


# ---------------------------------------------------------------- markdown


_REMEDIATION_BY_OWASP: dict[str, str] = {
    "LLM01": (
        "Prompt injection — separate trusted system instructions from "
        "untrusted input. Use a structured input parser; treat anything from "
        "users / retrieved docs / tool outputs as data, never as instructions."
    ),
    "LLM02": (
        "Sensitive information disclosure — never inject PII or operator "
        "secrets into the model's context unless you can guarantee the "
        "model will not echo them back."
    ),
    "LLM06": (
        "Excessive agency — every tool the model can call must enforce its "
        "own authorization at invocation time. Never trust the model to "
        "decide whether the user is allowed to use a tool."
    ),
    "LLM07": (
        "System-prompt leakage — assume the system prompt WILL leak. Don't "
        "encode security policy, secrets, or operator-confidential text "
        "in it. Move policy into deterministic middleware."
    ),
    "LLM08": (
        "Vector / embedding weaknesses — RAG corpora must be authenticated; "
        "treat retrieved chunks as untrusted input."
    ),
}


def render_markdown(report: EngagementReport) -> str:
    sev = report.severity_counts
    owasp = report.owasp_coverage
    lines: list[str] = []
    lines.append("# LMTWT Engagement Report")
    lines.append("")
    lines.append(f"**Target:** {report.target_name}  ")
    lines.append(f"**Attacker:** {report.attacker_name}  ")
    lines.append(f"**Generated:** {report.generated_at}  ")
    lines.append(f"**Findings:** {len(report.findings)}  ")
    lines.append(f"**Max LSS:** {report.max_lss:.2f}")
    lines.append("")

    # ---- exec summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"This engagement ran the LMTWT-native probe corpus and chatbot "
        f"attack modules against `{report.target_name}`. The headline "
        f"numbers:"
    )
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for level in ("critical", "high", "medium", "low"):
        lines.append(f"| {level} | {sev[level]} |")
    lines.append("")
    if owasp:
        lines.append("**OWASP LLM Top 10 coverage:**")
        for tag in sorted(owasp):
            lines.append(f"- {tag}: {owasp[tag]} finding(s)")
        lines.append("")

    # ---- methodology
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Findings are scored using the LMTWT Severity Score (LSS v1.0; see "
        "`docs/lss.md`) and tagged against the LMTWT 4-axis attack taxonomy "
        "(`docs/taxonomy.md`). Refusal grades follow the A–F rubric where "
        "A is a hard refusal and F is full compliance. LSS produces a "
        "deterministic 0–10 number from the probe's taxonomy coordinate "
        "and chain status — not a benchmark relative to other models."
    )
    lines.append("")

    # ---- findings table
    lines.append("## Findings (by LSS)")
    lines.append("")
    lines.append("| # | LSS | Severity | OWASP | Title |")
    lines.append("|---:|---:|---|---|---|")
    for i, f in enumerate(report.findings, start=1):
        owasp_str = ",".join(f.owasp_tags) or "-"
        lss_str = f"{f.lss_score:.2f}" if f.lss_score else "-"
        lines.append(
            f"| {i} | {lss_str} | {f.severity} | {owasp_str} | {f.title} |"
        )
    lines.append("")

    # ---- detailed findings
    lines.append("## Detailed Findings")
    lines.append("")
    for i, f in enumerate(report.findings, start=1):
        lines.append(f"### F{i:03d} — {f.title}")
        lines.append("")
        lines.append(f"- **Severity:** {f.severity}")
        if f.lss_score is not None:
            lines.append(f"- **LSS:** {f.lss_score:.2f} (`{f.lss_vector}`)")
        if f.coordinate:
            lines.append(f"- **Taxonomy:** `{f.coordinate}`")
        if f.owasp_tags:
            lines.append(f"- **OWASP:** {', '.join(f.owasp_tags)}")
        if f.refusal_grade:
            lines.append(f"- **Refusal grade:** {f.refusal_grade}")
        lines.append("")
        if f.reason:
            lines.append(f"**Reason:** {f.reason}")
            lines.append("")
        if f.attack_prompt:
            lines.append("**Attack prompt:**")
            lines.append("```")
            lines.append(f.attack_prompt)
            lines.append("```")
        if f.target_response:
            lines.append("**Target response:**")
            lines.append("```")
            response = f.target_response
            if len(response) > 4000:
                response = response[:4000] + f"\n... [{len(f.target_response) - 4000} more chars truncated]"
            lines.append(response)
            lines.append("```")
        lines.append("")

    # ---- remediation
    if owasp:
        lines.append("## Remediation Guidance")
        lines.append("")
        for tag in sorted(owasp):
            guidance = _REMEDIATION_BY_OWASP.get(tag)
            if guidance:
                lines.append(f"### {tag}")
                lines.append("")
                lines.append(guidance)
                lines.append("")

    # ---- appendix
    lines.append("## Appendix — Run Metadata")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(report.metadata, indent=2, ensure_ascii=False))
    lines.append("```")

    return "\n".join(lines)


# ---------------------------------------------------------------- HTML


_HTML_CSS = """
@page { size: A4; margin: 18mm; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       font-size: 10.5pt; color: #222; line-height: 1.45; }
h1 { color: #1a1a1a; border-bottom: 3px solid #444; padding-bottom: 4pt; }
h2 { color: #1a1a1a; border-bottom: 1px solid #aaa; padding-bottom: 2pt; margin-top: 18pt; }
h3 { color: #333; margin-top: 14pt; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 8pt 0; }
th, td { border: 1px solid #ccc; padding: 4pt 6pt; text-align: left; vertical-align: top; }
th { background: #f3f3f3; }
code, pre { font-family: 'SF Mono', 'Menlo', 'Consolas', monospace; font-size: 9pt; }
pre { background: #f8f8f8; padding: 6pt; border-left: 3px solid #999;
      white-space: pre-wrap; word-break: break-word; }
.severity-critical { color: #b00020; font-weight: 600; }
.severity-high { color: #c95900; font-weight: 600; }
.severity-medium { color: #8a6d00; }
.severity-low { color: #666; }
"""


def render_html(report: EngagementReport) -> str:
    """Render the report as standalone HTML (for pdf or browser preview)."""
    md = render_markdown(report)
    body = _markdown_to_html(md)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LMTWT Engagement Report — {html.escape(report.target_name)}</title>
<style>{_HTML_CSS}</style>
</head>
<body>
{body}
</body>
</html>"""


def _markdown_to_html(md: str) -> str:
    """Tiny home-grown Markdown → HTML so we don't pull in a Markdown lib.

    Handles only what the report emits: H1/H2/H3 headers, bullet lists,
    pipe tables, fenced code blocks, paragraphs, inline ``code``, **bold**.
    """
    lines = md.split("\n")
    out: list[str] = []
    in_code = False
    in_table = False
    table_rows: list[list[str]] = []

    def flush_table():
        nonlocal in_table, table_rows
        if not table_rows:
            in_table = False
            return
        out.append("<table>")
        for i, row in enumerate(table_rows):
            tag = "th" if i == 0 else "td"
            out.append(
                "<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in row) + "</tr>"
            )
        out.append("</table>")
        table_rows = []
        in_table = False

    for raw in lines:
        line = raw.rstrip()
        if line.startswith("```"):
            if in_code:
                out.append("</pre>")
                in_code = False
            else:
                flush_table()
                out.append("<pre>")
                in_code = True
            continue
        if in_code:
            out.append(html.escape(line))
            continue
        if line.startswith("|") and line.endswith("|") and "|" in line[1:-1]:
            cells = [c.strip() for c in line.strip("|").split("|")]
            # Skip the separator row (---|---).
            if all(set(c) <= set("-: ") for c in cells):
                continue
            table_rows.append(cells)
            in_table = True
            continue
        else:
            flush_table()

        if line.startswith("# "):
            out.append(f"<h1>{_inline(line[2:])}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("### "):
            out.append(f"<h3>{_inline(line[4:])}</h3>")
        elif line.startswith("- "):
            out.append(f"<p>• {_inline(line[2:])}</p>")
        elif line:
            out.append(f"<p>{_inline(line)}</p>")
    flush_table()
    if in_code:
        out.append("</pre>")
    return "\n".join(out)


def _inline(text: str) -> str:
    """Inline replacements: backticks, bold, escape rest."""
    # Pull code spans out first so we don't escape backticks twice.
    parts = []
    i = 0
    while i < len(text):
        if text[i] == "`":
            end = text.find("`", i + 1)
            if end == -1:
                break
            parts.append(("code", text[i + 1 : end]))
            i = end + 1
        else:
            j = text.find("`", i)
            if j == -1:
                parts.append(("text", text[i:]))
                break
            parts.append(("text", text[i:j]))
            i = j

    out: list[str] = []
    for kind, chunk in parts:
        if kind == "code":
            out.append(f"<code>{html.escape(chunk)}</code>")
        else:
            esc = html.escape(chunk)
            # **bold** → <strong>bold</strong>
            while "**" in esc:
                first = esc.find("**")
                second = esc.find("**", first + 2)
                if second == -1:
                    break
                esc = esc[:first] + "<strong>" + esc[first + 2 : second] + "</strong>" + esc[second + 2 :]
            out.append(esc)
    return "".join(out)


# ---------------------------------------------------------------- PDF


def render_pdf(report: EngagementReport, out_path: Path | str) -> Path:
    """Render the report to PDF via WeasyPrint.

    Raises ``RuntimeError`` if WeasyPrint isn't installed; caller should
    fall back to Markdown.
    """
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]
    except ImportError as e:
        raise RuntimeError(
            "WeasyPrint is required for PDF output. Install with "
            "`pip install lmtwt[report]` or `pip install weasyprint`."
        ) from e
    html_str = render_html(report)
    out = Path(out_path)
    HTML(string=html_str).write_pdf(out)
    return out
