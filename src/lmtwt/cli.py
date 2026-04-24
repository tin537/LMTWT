#!/usr/bin/env python3
"""LMTWT command-line entrypoint (async-native)."""

from __future__ import annotations

import argparse
import asyncio
import os
import platform
import sys
from dataclasses import asdict

from dotenv import load_dotenv

from .attacks.async_engine import AsyncAttackEngine, AttackResult
from .attacks.async_probe import AsyncProbeAttack
from .attacks.catalog_probe import AsyncCatalogProbe
from .attacks.flows import (
    BUILT_IN_FLOWS,
    MultiTurnRunner,
    get_flow,
    list_flows,
    turn_log_to_attack_result,
)
from .attacks.strategies import PAIRStrategy, TAPStrategy
from .attacks.templates import get_template_instruction, list_attack_templates
from .attacks.tools import (
    BUILT_IN_VECTORS,
    ToolHarness,
    ToolUseAttack,
    get_vector,
    list_vectors,
)
from .chatbot_attacks import (
    ChannelInconsistencyAttack,
    ConversationHijackAttack,
    CostAmplificationAttack,
    JWTClaimsAttack,
    RefusalFatigueAttack,
    SessionLifecycleAttack,
    ToolResultPoisoningAttack,
)
from .chatbot_attacks.channel_inconsistency import finding_to_dict as _channel_to_dict
from .chatbot_attacks.conversation_hijack import finding_to_dict as _hijack_to_dict
from .chatbot_attacks.cost_amplification import finding_to_dict as _cost_to_dict
from .chatbot_attacks.jwt_claims import finding_to_dict as _jwt_to_dict
from .chatbot_attacks.refusal_fatigue import finding_to_dict as _fatigue_to_dict
from .chatbot_attacks.session_lifecycle import finding_to_dict as _session_to_dict
from .chatbot_attacks.tool_result_poisoning import finding_to_dict as _poison_to_dict
from .discovery import (
    AdaptiveAttacker,
    fingerprint_target,
    load_fingerprint,
    save_fingerprint,
)
from .models.async_factory import async_get_model
from .probes import load_corpus
from .reporting import (
    build_diff_report,
    build_report,
    build_scorecard,
    diff_to_dict,
    render_diff_markdown,
    render_html,
    render_markdown,
    render_pdf,
    render_scorecard_markdown,
    scorecard_to_dict,
    write_repro_pack,
)
from .utils.async_judge import EnsembleJudge, LLMJudge, RegexJudge, ScoringLLMJudge
from .utils.config import load_config, load_target_config
from .utils.logger import console, setup_logger
from .utils.report_generator import ReportGenerator

try:
    import torch

    HAS_CUDA = torch.cuda.is_available()
    HAS_MPS = hasattr(torch.backends, "mps") and torch.backends.mps.is_available()
    GPU_INFO = (
        f"CUDA: {HAS_CUDA}, MPS: {HAS_MPS}"
        if (HAS_CUDA or HAS_MPS)
        else "No GPU acceleration"
    )
except ImportError:
    HAS_CUDA = False
    HAS_MPS = False
    GPU_INFO = "GPU detection requires PyTorch"


logger = setup_logger()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="LMTWT — Let Me Talk With Them: AI prompt-injection testing tool"
    )
    p.add_argument("--attacker", "-a", type=str, default="gemini",
                   choices=["gemini", "openai", "anthropic", "huggingface",
                            "lmstudio", "openai-compat", "claude-code", "acp"])
    p.add_argument("--target", "-t", type=str, default="openai",
                   choices=["gemini", "openai", "anthropic", "external-api",
                            "huggingface", "lmstudio", "openai-compat",
                            "claude-code", "acp"])
    p.add_argument("--attacker-model", type=str)
    p.add_argument("--target-model", type=str)
    p.add_argument("--mode", "-m", type=str, default="interactive",
                   choices=["interactive", "batch", "template", "multi-turn",
                            "tool-use"])
    p.add_argument("--instruction", "-i", type=str, action="append")
    p.add_argument("--template", type=str, action="append")
    p.add_argument("--list-templates", action="store_true")
    p.add_argument("--flow", type=str,
                   help=f"Multi-turn flow id (one of: {', '.join(BUILT_IN_FLOWS.keys())})")
    p.add_argument("--list-flows", action="store_true")
    # Tool-use attacks
    p.add_argument("--tool-vector", type=str, default=None,
                   choices=list(BUILT_IN_VECTORS.keys()),
                   help="Static injection vector for --mode tool-use (omit for dynamic rotation)")
    p.add_argument("--list-vectors", action="store_true",
                   help="Show built-in tool-use injection vectors and exit")
    p.add_argument("--iterations", type=int, default=1)
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--concurrency", type=int, default=1,
                   help="Parallel attacks for batch/template/probe (default: 1)")
    p.add_argument("--config", "-c", type=str)
    p.add_argument("--target-config", type=str)
    p.add_argument("--hacker-mode", action="store_true")
    p.add_argument("--system-prompt", type=str)
    p.add_argument("--hacker-system-prompt", type=str)
    p.add_argument("--auto-send", action="store_true")
    # Judge selection — supersedes the legacy --compliance-agent flag.
    p.add_argument("--judge", type=str, default="regex",
                   choices=["regex", "llm", "ensemble"],
                   help="Success-detection judge (default: regex)")
    p.add_argument("--compliance-agent", action="store_true",
                   help="Deprecated alias for --judge ensemble")
    p.add_argument("--compliance-provider", type=str, default="gemini",
                   choices=["gemini", "openai", "anthropic"],
                   help="Provider used for the LLM judge")
    p.add_argument("--max-retries", type=int, default=3)
    # Refinement strategies (PAIR / TAP)
    p.add_argument("--strategy", type=str, default=None,
                   choices=["pair", "tap"],
                   help="Run an automated refinement strategy instead of single-shot attacks")
    p.add_argument("--strategy-iterations", type=int, default=5,
                   help="PAIR: max iterations (default 5)")
    p.add_argument("--strategy-branching", type=int, default=3,
                   help="TAP: branching factor (variants per parent, default 3)")
    p.add_argument("--strategy-depth", type=int, default=4,
                   help="TAP: tree depth (default 4)")
    p.add_argument("--strategy-prune", type=int, default=2,
                   help="TAP: top-K survivors to keep at each level (default 2)")
    p.add_argument("--strategy-threshold", type=int, default=8,
                   help="Score threshold (1-10) that counts as a successful jailbreak (default 8)")
    # Proxy / TLS — for routing through Burp, mitmproxy, ZAP, corporate egress
    p.add_argument("--proxy", type=str,
                   help="HTTP/SOCKS proxy URL applied to attacker, target, judge")
    p.add_argument("--ca-bundle", type=str,
                   help="Path to PEM cert bundle (e.g. Burp's cacert.pem)")
    p.add_argument("--insecure", action="store_true",
                   help="Skip TLS verification (verify=False) — dangerous")
    # Web
    p.add_argument("--web", action="store_true")
    p.add_argument("--web-port", type=int, default=8501)
    p.add_argument("--share", action="store_true")
    # Probe
    p.add_argument("--probe-mode", action="store_true")
    p.add_argument("--probe-category", type=str, default="all",
                   choices=["dan", "injection", "xss", "glitch", "misleading",
                            "malware", "forbidden_knowledge", "snowball", "all"])
    p.add_argument("--probe-iterations", type=int, default=5)
    # LMTWT-native probe catalog (Phase 5.1)
    p.add_argument("--probe-catalog", action="store_true",
                   help="Run the LMTWT-native YAML probe corpus instead of "
                        "the legacy --probe-mode categories")
    p.add_argument("--probe-catalog-path", type=str, default=None,
                   help="Alternate directory of probe YAML files "
                        "(default: built-in library)")
    p.add_argument("--probe-coordinate", type=str, default=None,
                   help="Filter probes by taxonomy coordinate, e.g. "
                        "'leak/*/*/*' or 'injection/direct/*/*'")
    p.add_argument("--probe-severity", type=str, default=None,
                   help="Comma-separated severity filter: "
                        "critical,high,medium,low")
    p.add_argument("--list-probes", action="store_true",
                   help="List every probe in the corpus and exit")
    p.add_argument("--probe-repeat", type=int, default=1,
                   help="Re-run each probe N times and report a Wilson 95%% "
                        "CI on the success rate. Useful at non-zero target "
                        "temperature where 1-shot success is a coin flip "
                        "(default: 1, no behavior change).")
    p.add_argument("--refusal-grader", type=str, default="regex",
                   choices=["regex", "llm", "ensemble"],
                   help="Refusal-grade evaluator. 'regex' (default, free) "
                        "uses heuristics; 'llm' asks an attacker-side model "
                        "to grade; 'ensemble' uses regex first and only "
                        "escalates to the LLM on a regex 'F' (full "
                        "compliance) verdict — the case where regex is "
                        "most likely to be wrong.")
    p.add_argument("--refusal-grader-provider", type=str, default=None,
                   choices=["gemini", "openai", "anthropic"],
                   help="Provider for --refusal-grader=llm/ensemble. "
                        "Defaults to --compliance-provider.")
    p.add_argument("--dashboard", action="store_true",
                   help="Render a live TUI panel during --probe-catalog "
                        "runs (severity histogram, recent outcomes, "
                        "elapsed). Off by default — non-TTY environments "
                        "should leave it off.")
    # Persistence
    p.add_argument("--persist", action="store_true",
                   help="Stream catalog runs into a SQLite db so they "
                        "survive crashes / Ctrl-C. Pair with --persist-db.")
    p.add_argument("--persist-db", type=str, default="lmtwt.db",
                   help="Path to the SQLite db (default: ./lmtwt.db).")
    p.add_argument("--list-runs", action="store_true",
                   help="List recent runs from --persist-db and exit.")
    p.add_argument("--show-run", type=int, default=None,
                   help="Dump the outcomes of run <id> as a "
                        "--report-from-compatible JSON to stdout.")
    # FastAPI web backend (parallel to --web Gradio, doesn't replace it)
    p.add_argument("--web-api", action="store_true",
                   help="Launch the FastAPI + SSE web UI (probe-catalog "
                        "runner with live streaming). Requires "
                        "lmtwt[api]. Parallel to --web (Gradio).")
    p.add_argument("--web-api-port", type=int, default=8500,
                   help="Port for --web-api (default: 8500)")
    p.add_argument("--web-api-host", type=str, default="127.0.0.1",
                   help="Bind host for --web-api (default: 127.0.0.1)")
    # Phase 5.3 — discovery / adaptive attacker
    p.add_argument("--fingerprint", action="store_true",
                   help="Run target fingerprinting (calibration probes) and exit")
    p.add_argument("--fingerprint-out", type=str, default="target-fingerprint.json",
                   help="Where to write the fingerprint JSON (default: ./target-fingerprint.json)")
    p.add_argument("--fingerprint-in", type=str, default=None,
                   help="Use a pre-saved fingerprint instead of re-running calibration")
    p.add_argument("--adaptive", action="store_true",
                   help="In --probe-catalog mode, also generate adaptive probes "
                        "from the fingerprint via the attacker model")
    p.add_argument("--adaptive-n", type=int, default=3,
                   help="Number of adaptive probes to generate (default: 3)")
    # Phase 5.4 — chatbot-protocol-delivered LLM attacks
    p.add_argument("--chatbot-attack", type=str, default=None,
                   choices=["session-lifecycle", "channel-inconsistency",
                            "jwt-claims", "conversation-hijack",
                            "cost-amplification", "refusal-fatigue",
                            "tool-result-poisoning"],
                   help="Run an LLM-attack delivered through the chatbot's protocol")
    p.add_argument("--channel-config", action="append", default=None,
                   help="Path to additional --target-config JSON for "
                        "--chatbot-attack=channel-inconsistency. May be passed "
                        "multiple times. Each becomes a comparison channel "
                        "(named after the file's basename).")
    # Phase 5.5 — engagement-grade reporting
    p.add_argument("--report-from", type=str, default=None,
                   help="Build an engagement-grade report from a previous "
                        "run-output JSON file (no live attacks).")
    p.add_argument("--report-out", type=str, default="engagement-report",
                   help="Output base path for --report-from; "
                        ".md / .html / .pdf are appended (default: engagement-report)")
    p.add_argument("--report-format", type=str, default="md,html",
                   help="Comma-separated formats to emit: md, html, pdf "
                        "(pdf requires lmtwt[report]). Default: md,html")
    p.add_argument("--repro-out", type=str, default=None,
                   help="Directory to write per-finding repro.json packs "
                        "alongside --report-from. One file per finding plus "
                        "an index.json — client engineers can replay each "
                        "finding independently.")
    p.add_argument("--diff-before", type=str, default=None,
                   help="Run-output JSON for the BEFORE engagement (use with "
                        "--diff-after to produce a remediation diff report).")
    p.add_argument("--diff-after", type=str, default=None,
                   help="Run-output JSON for the AFTER engagement.")
    p.add_argument("--scorecard-from", type=str, action="append", default=None,
                   help="Run-output JSON for one target. Repeat for each "
                        "target (e.g. --scorecard-from a.json "
                        "--scorecard-from b.json) to build a side-by-side "
                        "multi-target scorecard.")
    p.add_argument("--scorecard-name", type=str, action="append", default=None,
                   help="Optional column label per --scorecard-from "
                        "(must match in count). Defaults to "
                        "metadata.target_model.")
    # Phase 5.3 — LMTWT-Climb mutation engine
    p.add_argument("--climb", action="store_true",
                   help="Run LMTWT-Climb: hill-climb a seed probe through "
                        "typed mutations until the target complies or the "
                        "search plateaus.")
    p.add_argument("--climb-seed", type=str, default=None,
                   help="Probe id (from the catalog) or path to a seed "
                        "probe YAML file. Required with --climb.")
    p.add_argument("--climb-rounds", type=int, default=4,
                   help="Maximum climb rounds (default: 4)")
    p.add_argument("--climb-fanout", type=int, default=3,
                   help="Mutations per parent per round (default: 3)")
    p.add_argument("--climb-keep", type=int, default=2,
                   help="Top-K survivors carried into the next round (default: 2)")
    p.add_argument("--climb-out", type=str, default=None,
                   help="Write climb result (best probe + history) as JSON")
    p.add_argument("--climb-save", type=str, default=None,
                   help="If the climb succeeds (full compliance), save the "
                        "best probe as a YAML file at this path for corpus "
                        "growth.")
    p.add_argument("--climb-judge", action="store_true",
                   help="Use the LLM scoring judge (1-10) for fitness "
                        "instead of the regex refusal grader.")
    # Phase 5.3 — cross-pollination
    p.add_argument("--pollinate", action="store_true",
                   help="Generate taxonomy-adjacent variants of a seed "
                        "probe (one per axis-change). Output is YAML — "
                        "feed it back through --probe-catalog to evaluate.")
    p.add_argument("--pollinate-seed", type=str, default=None,
                   help="Probe id (from the catalog) or path to a seed "
                        "probe YAML file. Required with --pollinate.")
    p.add_argument("--pollinate-out", type=str, default=None,
                   help="Single YAML file to write all variants into "
                        "(--- separated). Useful for review.")
    p.add_argument("--pollinate-save-dir", type=str, default=None,
                   help="Directory to write each variant as its own YAML "
                        "(corpus-style). Variants drop in alongside hand-"
                        "authored probes for the next --probe-catalog run.")
    p.add_argument("--pollinate-engagement", type=str, default=None,
                   help="Tag every variant's metadata with this engagement "
                        "name (e.g. 'acme-2026-q2') for provenance.")
    p.add_argument("--pollinate-skip-op", type=str, action="append", default=None,
                   help="Operator names to skip (repeatable). Available: "
                        "encode-base64, translate-zh, persona-wrap, "
                        "multi-turn-split, rag-wrap, indirect-frame.")
    # Phase 5.3 — self-play probe generation
    p.add_argument("--self-play", action="store_true",
                   help="Generate new corpus probes via generator-vs-critic "
                        "self-play. No live target needed.")
    p.add_argument("--self-play-coordinate", type=str, action="append", default=None,
                   help="Restrict to one or more coordinates "
                        "vector/obfuscation/effect (e.g. "
                        "leak/plain/system-leak). Repeatable. Default: "
                        "sweep all 64 (vector × obfuscation × effect) "
                        "combinations.")
    p.add_argument("--self-play-n", type=int, default=3,
                   help="Probes per coordinate (default: 3)")
    p.add_argument("--self-play-rounds", type=int, default=2,
                   help="Critic-revise cycles per probe before reject (default: 2)")
    p.add_argument("--self-play-threshold", type=int, default=6,
                   help="Critic confidence above this = predictable refusal "
                        "→ reject/revise (default: 6)")
    p.add_argument("--self-play-concurrency", type=int, default=4,
                   help="Coordinates evaluated in parallel (default: 4)")
    p.add_argument("--self-play-out", type=str, default=None,
                   help="Directory to write each accepted probe as its own "
                        "YAML (corpus-style). Use --probe-catalog --probe-"
                        "catalog-path to evaluate them next.")
    p.add_argument("--self-play-trace", type=str, default=None,
                   help="Path to a JSON file capturing every candidate "
                        "(accepted + rejected) with critic verdicts — useful "
                        "for tuning the threshold.")
    p.add_argument("--self-play-critic", type=str, default=None,
                   choices=["gemini", "openai", "anthropic"],
                   help="Provider for the critic role. Defaults to the "
                        "--attacker provider so the same key works.")
    return p.parse_args()


def list_templates_and_exit() -> None:
    print("\nAvailable Attack Templates:")
    print("---------------------------")
    for tpl in list_attack_templates():
        print(f"{tpl['id']}: {tpl['name']}")
    print()


def list_flows_and_exit() -> None:
    print("\nAvailable Multi-turn Flows:")
    print("---------------------------")
    for f in list_flows():
        print(f"{f['name']} ({f['steps']} steps): {f['description']}")
    print()


def list_vectors_and_exit() -> None:
    print("\nAvailable Tool-use Injection Vectors:")
    print("-------------------------------------")
    for v in list_vectors():
        print(f"{v['name']}: {v['description']}")
    print()


def _emit_engagement_report(args) -> None:
    import json as _json
    from pathlib import Path as _Path

    src = _Path(args.report_from)
    if not src.is_file():
        console.print(f"[red]No such file: {src}[/red]")
        sys.exit(1)
    payload = _json.loads(src.read_text(encoding="utf-8"))
    report = build_report(payload)
    formats = {f.strip().lower() for f in args.report_format.split(",") if f.strip()}
    base = _Path(args.report_out)

    if "md" in formats:
        out = base.with_suffix(".md")
        out.write_text(render_markdown(report), encoding="utf-8")
        console.print(f"[green]Wrote {out}[/green]")
    if "html" in formats:
        out = base.with_suffix(".html")
        out.write_text(render_html(report), encoding="utf-8")
        console.print(f"[green]Wrote {out}[/green]")
    if "pdf" in formats:
        try:
            out = render_pdf(report, base.with_suffix(".pdf"))
            console.print(f"[green]Wrote {out}[/green]")
        except RuntimeError as e:
            console.print(f"[yellow]Skipped PDF: {e}[/yellow]")
    if getattr(args, "repro_out", None):
        repro_dir = write_repro_pack(payload, args.repro_out, report=report)
        console.print(
            f"[green]Wrote {len(report.findings)} repro pack(s) to {repro_dir}/[/green]"
        )
    console.print(
        f"\n[bold]Findings: {len(report.findings)}[/bold]  "
        f"Max LSS: {report.max_lss:.2f}  "
        f"Severity: {dict(report.severity_counts)}"
    )


def _list_runs_and_exit(args) -> None:
    from .persistence import list_runs

    db = args.persist_db
    if not _Path_exists(db):
        console.print(f"[yellow]No db at {db}. Run with --persist to create one.[/yellow]")
        sys.exit(0)
    runs = list_runs(db)
    if not runs:
        console.print(f"[dim]No runs in {db}.[/dim]")
        return
    print(f"\nRuns in {db} ({len(runs)} most recent):")
    print("-" * 96)
    for r in runs:
        finished = r.finished_at or "—"
        target = r.target_name or "?"
        print(
            f"  [{r.id:5}] status={r.status:11}  target={target:25} "
            f"completed={r.completed:>4}/{r.total_probes:<4} "
            f"successes={r.successes:<3} started={r.started_at}  finished={finished}"
        )
    print()


def _show_run_and_exit(args) -> None:
    import json as _json

    from .persistence import load_run_outcomes

    if not _Path_exists(args.persist_db):
        console.print(f"[red]No db at {args.persist_db}[/red]")
        sys.exit(1)
    try:
        payload = load_run_outcomes(args.persist_db, args.show_run)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    print(_json.dumps(payload, indent=2, ensure_ascii=False))


def _Path_exists(path: str) -> bool:
    from pathlib import Path as _Path
    return _Path(path).is_file()


def _emit_diff_report(args) -> None:
    import json as _json
    from pathlib import Path as _Path

    if not args.diff_before or not args.diff_after:
        console.print(
            "[red]--diff-before AND --diff-after are both required.[/red]"
        )
        sys.exit(1)
    before_path = _Path(args.diff_before)
    after_path = _Path(args.diff_after)
    for label, path in (("before", before_path), ("after", after_path)):
        if not path.is_file():
            console.print(f"[red]No such {label} file: {path}[/red]")
            sys.exit(1)

    before = _json.loads(before_path.read_text(encoding="utf-8"))
    after = _json.loads(after_path.read_text(encoding="utf-8"))
    report = build_diff_report(before, after)

    formats = {f.strip().lower() for f in args.report_format.split(",") if f.strip()}
    base = _Path(args.report_out)

    if "md" in formats:
        out = base.with_suffix(".diff.md")
        out.write_text(render_diff_markdown(report), encoding="utf-8")
        console.print(f"[green]Wrote {out}[/green]")
    if "json" in formats or "html" in formats or "pdf" in formats:
        # JSON falls out of the diff naturally; always write it for CI use.
        out = base.with_suffix(".diff.json")
        out.write_text(
            _json.dumps(diff_to_dict(report), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[green]Wrote {out}[/green]")

    counts = report.counts
    console.print(
        f"\n[bold]Diff:[/bold] "
        f"[red]regressed={counts['regressed']}[/red]  "
        f"[yellow]new={counts['new']}[/yellow]  "
        f"persistent={counts['persistent']}  "
        f"[green]remediated={counts['remediated']}[/green]"
    )
    console.print(
        f"Max LSS Δ: [bold]{report.max_lss_delta:+.2f}[/bold]  "
        f"Best Δ: [bold]{report.min_lss_delta:+.2f}[/bold]"
    )


def _emit_scorecard_report(args) -> None:
    import json as _json
    from pathlib import Path as _Path

    paths = [_Path(p) for p in args.scorecard_from]
    for p in paths:
        if not p.is_file():
            console.print(f"[red]No such scorecard input: {p}[/red]")
            sys.exit(1)
    payloads = [_json.loads(p.read_text(encoding="utf-8")) for p in paths]

    names = args.scorecard_name
    if names is not None and len(names) != len(payloads):
        console.print(
            f"[red]--scorecard-name count ({len(names)}) must match "
            f"--scorecard-from count ({len(payloads)}).[/red]"
        )
        sys.exit(1)

    report = build_scorecard(payloads, names=names)

    formats = {f.strip().lower() for f in args.report_format.split(",") if f.strip()}
    base = _Path(args.report_out)

    if "md" in formats:
        out = base.with_suffix(".scorecard.md")
        out.write_text(render_scorecard_markdown(report), encoding="utf-8")
        console.print(f"[green]Wrote {out}[/green]")
    if "json" in formats or "html" in formats or "pdf" in formats:
        # JSON is always useful for procurement decks; emit it whenever any
        # rich format is requested.
        out = base.with_suffix(".scorecard.json")
        out.write_text(
            _json.dumps(scorecard_to_dict(report), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[green]Wrote {out}[/green]")

    console.print(
        f"\n[bold]Targets: {report.total_targets}[/bold]  "
        f"Findings (union): {report.total_findings}"
    )
    for s in report.summaries:
        console.print(
            f"  {s.name:30}  max LSS=[bold]{s.max_lss:>5.2f}[/bold]  "
            f"real={s.real_findings}  total={s.total_findings}"
        )


def list_probes_and_exit(args) -> None:
    severity_filter = (
        [s.strip() for s in args.probe_severity.split(",")]
        if args.probe_severity else None
    )
    corpus = load_corpus(
        root=args.probe_catalog_path,
        coordinate_filter=args.probe_coordinate,
        severity_filter=severity_filter,
    )
    print(f"\nLMTWT probe corpus — {len(corpus)} probes:")
    print("-" * 70)
    for p in corpus:
        owasp = ",".join(p.owasp_llm) or "-"
        print(f"{p.severity:8}  {p.coordinate:50}  {p.id}")
        print(f"          {p.name}  [OWASP: {owasp}]")
    print()


def _transport_kwargs(args) -> dict:
    return {
        "proxy": args.proxy,
        "ca_bundle": args.ca_bundle,
        "verify": not args.insecure,
    }


def _build_refusal_grader(args):
    """Construct the configured RefusalGrader (regex / llm / ensemble)."""
    from .scoring import (
        EnsembleRefusalGrader,
        LLMRefusalGrader,
        RegexRefusalGrader,
    )

    style = getattr(args, "refusal_grader", "regex")
    if style == "regex":
        return RegexRefusalGrader()
    provider = getattr(args, "refusal_grader_provider", None) or args.compliance_provider
    api_key = os.getenv(f"{provider.upper()}_API_KEY")
    grader_model = async_get_model(
        provider, api_key=api_key, **_transport_kwargs(args)
    )
    llm_grader = LLMRefusalGrader(grader_model)
    return EnsembleRefusalGrader(llm_grader) if style == "ensemble" else llm_grader


async def _build_judge(args):
    """Return an ``AsyncJudge``. ``--compliance-agent`` is a back-compat shim."""
    style = "ensemble" if args.compliance_agent else args.judge
    if style == "regex":
        return RegexJudge()

    api_key = os.getenv(f"{args.compliance_provider.upper()}_API_KEY")
    judge_model = async_get_model(
        args.compliance_provider, api_key=api_key, **_transport_kwargs(args)
    )
    llm_judge = LLMJudge(judge_model)
    return EnsembleJudge(llm_judge) if style == "ensemble" else llm_judge


def _result_to_legacy_dict(r: AttackResult) -> dict:
    """Adapter for the existing ``ReportGenerator`` (still expects dicts)."""
    d = asdict(r)
    d["prompt"] = r.attack_prompt
    d["response"] = r.target_response
    d["content"] = r.target_response
    return d


async def _run_interactive(engine: AsyncAttackEngine, args) -> None:
    console.print(f"\n[bold cyan]Attacker:[/bold cyan] {engine.attacker.model_name}")
    console.print(f"[bold cyan]Target:  [/bold cyan] {engine.target.model_name}")
    console.print(f"[bold cyan]Hacker mode:[/bold cyan] {'on' if engine.hacker_mode else 'off'}")
    console.print(f"[bold cyan]Judge:[/bold cyan] {type(engine.judge).__name__}\n")

    while True:
        instruction = input("Instruction (q to quit) > ").strip()
        if instruction.lower() in ("q", "quit", "exit"):
            break
        if not instruction:
            continue

        attack_prompt = await engine.generate_attack_prompt(instruction)
        console.print(f"\n[bold magenta]Attack prompt:[/bold magenta]\n{attack_prompt}\n")

        if not args.auto_send:
            edit = input("Edit before sending? (y/N) > ").strip().lower()
            if edit == "y":
                attack_prompt = input("Edited prompt > ")

        result = await engine.execute_attack(
            instruction, attack_prompt, target_system_prompt=args.system_prompt
        )
        verdict_color = "green" if result.success else "yellow"
        console.print(
            f"\n[bold {verdict_color}]"
            f"{'SUCCESS' if result.success else 'FAILED'}[/bold {verdict_color}]"
            f" — {result.reason}"
        )
        console.print(f"\n[bold]Response:[/bold]\n{result.target_response}\n")


async def _run_batch(engine: AsyncAttackEngine, args, instructions: list[str]) -> None:
    results = await engine.batch(
        instructions,
        iterations=args.iterations,
        concurrency=args.concurrency,
        target_system_prompt=args.system_prompt,
        delay=args.delay,
    )

    successes = sum(1 for r in results if r.success)
    console.print(f"\n[bold]Batch complete: {successes}/{len(results)} successes[/bold]")

    metadata = engine.metadata() | {
        "mode": args.mode,
        "instructions": instructions,
        "iterations": args.iterations,
        "compliance_agent": args.compliance_agent,
        "concurrency": args.concurrency,
    }
    ReportGenerator().generate_report(
        [_result_to_legacy_dict(r) for r in results], metadata
    )


async def _run_tool_use(args, attacker, target, judge) -> None:
    if args.tool_vector:
        vector = get_vector(args.tool_vector)
        if vector is None:
            logger.error(f"Unknown tool vector: {args.tool_vector}")
            sys.exit(1)
        harness = ToolHarness.static(vector)
        mode_label = f"static[{vector.name}]"
    else:
        harness = ToolHarness.dynamic()
        mode_label = "dynamic"

    attack = ToolUseAttack(
        attacker=attacker,
        target=target,
        harness=harness,
        judge=judge,
        target_system_prompt=args.system_prompt,
    )
    console.print(
        f"\n[bold magenta]Tool-use attack:[/bold magenta] {mode_label} "
        f"(indirect prompt injection via fake tool outputs)"
    )

    results = await attack.batch(args.instruction, concurrency=args.concurrency)
    successes = sum(1 for r in results if r.success)

    for r in results:
        marker = (
            "[green]SUCCESS[/green]" if r.success else "[yellow]FAILED[/yellow]"
        )
        console.print(f"{marker} — {r.reason}")
    console.print(
        f"\n[bold]Tool-use complete: {successes}/{len(results)} agent compromises[/bold]"
    )

    metadata = {
        "attacker_model": getattr(attacker, "model_name", "unknown"),
        "target_model": getattr(target, "model_name", "unknown"),
        "mode": "tool-use",
        "tool_vector": args.tool_vector or "dynamic",
        "instructions": args.instruction,
        "judge": type(judge).__name__,
        "total_attacks": len(results),
        "successes": successes,
    }
    ReportGenerator().generate_report(
        [_result_to_legacy_dict(r) for r in results], metadata
    )


async def _run_strategy(args, attacker, target) -> None:
    """Run PAIR or TAP refinement against each --instruction."""
    # The scoring judge always uses the LLM judge model (--compliance-provider).
    judge_api_key = os.getenv(f"{args.compliance_provider.upper()}_API_KEY")
    judge_model = async_get_model(
        args.compliance_provider,
        api_key=judge_api_key,
        **_transport_kwargs(args),
    )
    scoring_judge = ScoringLLMJudge(judge_model, threshold=args.strategy_threshold)

    if args.strategy == "pair":
        strategy = PAIRStrategy(
            judge=scoring_judge,
            max_iterations=args.strategy_iterations,
            score_threshold=args.strategy_threshold,
        )
    else:
        strategy = TAPStrategy(
            judge=scoring_judge,
            branching_factor=args.strategy_branching,
            depth=args.strategy_depth,
            prune_top_k=args.strategy_prune,
            score_threshold=args.strategy_threshold,
        )

    console.print(
        f"\n[bold magenta]Strategy:[/bold magenta] {args.strategy.upper()} "
        f"(threshold {args.strategy_threshold}/10)"
    )

    results: list[AttackResult] = []
    for instruction in args.instruction:
        console.print(f"\n[bold cyan]Objective:[/bold cyan] {instruction}")
        result = await strategy.refine(
            attacker, target, instruction, target_system_prompt=args.system_prompt
        )
        results.append(result)
        marker = (
            "[green]SUCCESS[/green]"
            if result.success
            else "[yellow]FAILED[/yellow]"
        )
        console.print(f"{marker} — {result.reason}")

    successes = sum(1 for r in results if r.success)
    console.print(
        f"\n[bold]{args.strategy.upper()} complete: "
        f"{successes}/{len(results)} jailbreaks succeeded[/bold]"
    )

    metadata = {
        "attacker_model": getattr(attacker, "model_name", "unknown"),
        "target_model": getattr(target, "model_name", "unknown"),
        "judge_model": getattr(judge_model, "model_name", "unknown"),
        "mode": "strategy",
        "strategy": args.strategy,
        "score_threshold": args.strategy_threshold,
        "instructions": args.instruction,
        "total_attacks": len(results),
        "successes": successes,
    }
    ReportGenerator().generate_report(
        [_result_to_legacy_dict(r) for r in results], metadata
    )


async def _run_multi_turn(args, attacker, target, judge, flow) -> None:
    runner = MultiTurnRunner(
        attacker, target, judge=judge, target_system_prompt=args.system_prompt
    )
    console.print(
        f"\n[bold magenta]Flow:[/bold magenta] {flow.name} "
        f"({len(flow.steps)} steps)"
    )

    results = await runner.run_many(
        flow, args.instruction, concurrency=args.concurrency
    )

    successes = sum(1 for r in results if r.final_success)
    console.print(
        f"\n[bold]Multi-turn complete: {successes}/{len(results)} flows succeeded[/bold]\n"
    )

    # Per-flow recap on stdout; full per-turn detail flushed to the report.
    for r in results:
        marker = "[green]SUCCESS[/green]" if r.final_success else "[yellow]FAILED[/yellow]"
        console.print(
            f"{marker}  {r.flow}  ({len(r.turns)} turns)  — {r.final_reason}"
        )

    # Flatten turn logs into AttackResult dicts for ReportGenerator.
    flat_results = []
    for r in results:
        for log in r.turns:
            flat_results.append(_result_to_legacy_dict(
                turn_log_to_attack_result(log, r.instruction)
            ))

    metadata = {
        "attacker_model": getattr(attacker, "model_name", "unknown"),
        "target_model": getattr(target, "model_name", "unknown"),
        "mode": "multi-turn",
        "flow": flow.name,
        "instructions": args.instruction,
        "judge": type(judge).__name__,
        "total_attacks": len(flat_results),
        "successes": successes,
    }
    ReportGenerator().generate_report(flat_results, metadata)


async def _run_probe(args, target_model) -> None:
    console.print("\n[bold red]🔥 PROBE MODE[/bold red]")

    judge = await _build_judge(args)
    categories = (
        None if args.probe_category == "all" else [args.probe_category]
    )
    probe = AsyncProbeAttack(target_model, judge=judge, payload_categories=categories)

    if args.mode == "interactive":
        for cat in probe.payload_categories:
            console.print(f"\n[bold]== {cat.upper()} ==[/bold]")
            summary = await probe.execute_category(
                cat,
                iterations=max(1, args.probe_iterations // len(probe.payload_categories)),
                target_system_prompt=args.system_prompt,
                concurrency=args.concurrency,
            )
            console.print(
                f"[bold]Risk: {summary['vulnerability_assessment']}[/bold] "
                f"({summary['success_count']}/{summary['iterations']} succeeded)"
            )
        return

    summaries = await probe.execute_all(
        iterations=args.probe_iterations,
        target_system_prompt=args.system_prompt,
        concurrency=args.concurrency,
    )
    for cat, summary in summaries.items():
        console.print(
            f"[bold]{cat.upper():22}[/bold] "
            f"risk={summary['vulnerability_assessment']:6} "
            f"successes={summary['success_count']}/{summary['iterations']} "
            f"errors={summary['error_count']}"
        )


async def _resolve_fingerprint(args, target_model):
    """For ``--adaptive``: reuse a saved fingerprint or run calibration now."""
    if args.fingerprint_in:
        console.print(f"[dim]Loading fingerprint from {args.fingerprint_in}[/dim]")
        return load_fingerprint(args.fingerprint_in)
    console.print("[dim]No --fingerprint-in given; calibrating target now...[/dim]")
    fp = await fingerprint_target(
        target_model, target_system_prompt=args.system_prompt
    )
    save_fingerprint(fp, args.fingerprint_out)
    console.print(
        f"[dim]Calibration complete (weak axis: "
        f"{fp.weak_obfuscation_axis}). Saved to {args.fingerprint_out}[/dim]\n"
    )
    return fp


async def _run_chatbot_attack(args, target_model) -> None:
    console.print(
        f"\n[bold magenta]🧪 CHATBOT ATTACK — {args.chatbot_attack}[/bold magenta]"
    )
    if args.chatbot_attack == "session-lifecycle":
        await _run_session_lifecycle(args, target_model)
    elif args.chatbot_attack == "channel-inconsistency":
        await _run_channel_inconsistency(args, target_model)
    elif args.chatbot_attack == "jwt-claims":
        await _run_jwt_claims(args, target_model)
    elif args.chatbot_attack == "conversation-hijack":
        await _run_conversation_hijack(args, target_model)
    elif args.chatbot_attack == "cost-amplification":
        await _run_cost_amplification(args, target_model)
    elif args.chatbot_attack == "refusal-fatigue":
        await _run_refusal_fatigue(args, target_model)
    elif args.chatbot_attack == "tool-result-poisoning":
        await _run_tool_result_poisoning(args, target_model)


async def _run_session_lifecycle(args, target_model) -> None:
    try:
        attack = SessionLifecycleAttack(target_model)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    findings = await attack.run(target_system_prompt=args.system_prompt)
    console.print(
        f"[bold]Tested {len(findings)} routing-field mutations.[/bold]\n"
    )
    for f in findings:
        marker = "[red]●[/red]" if f.behavior_changed else "[dim]·[/dim]"
        console.print(
            f"  {marker} [{f.severity:8}] {f.mutation.name:30} "
            f"grade {f.baseline_grade}→{f.mutated_grade}  {f.reason}"
        )
    metadata = {
        "target_model": getattr(target_model, "model_name", "unknown"),
        "mode": "chatbot-attack",
        "attack": "session-lifecycle",
        "total_findings": len(findings),
        "behavior_changed": sum(1 for f in findings if f.behavior_changed),
    }
    ReportGenerator().generate_report(
        [_session_to_dict(f) for f in findings], metadata
    )


async def _run_channel_inconsistency(args, target_model) -> None:
    if not args.channel_config:
        console.print(
            "[red]--chatbot-attack=channel-inconsistency requires at least one "
            "--channel-config to compare against the primary --target-config.[/red]"
        )
        sys.exit(1)

    channels: dict = {"primary": target_model}
    for path in args.channel_config:
        try:
            extra_cfg = load_target_config(path)
        except Exception as e:
            logger.error(f"Failed to load channel config {path}: {e}")
            sys.exit(1)
        ch_target = async_get_model(
            "external-api",
            api_config=extra_cfg,
            **_transport_kwargs(args),
        )
        # Channel name = config file's basename (without extension), de-collided
        # if the user passes the same basename twice.
        base = os.path.splitext(os.path.basename(path))[0]
        name = base
        suffix = 1
        while name in channels:
            suffix += 1
            name = f"{base}-{suffix}"
        channels[name] = ch_target

    attack = ChannelInconsistencyAttack(channels)
    findings = await attack.run(target_system_prompt=args.system_prompt)
    inconsistent_count = sum(1 for f in findings if f.inconsistent)
    console.print(
        f"[bold]{inconsistent_count}/{len(findings)} probes diverged across "
        f"{len(channels)} channels.[/bold]\n"
    )
    for f in findings:
        marker = "[red]●[/red]" if f.inconsistent else "[dim]·[/dim]"
        console.print(
            f"  {marker} [{f.severity:8}] '{f.user_prompt[:60]}...'"
        )
        for v in f.verdicts:
            err = f" ERROR={v.error}" if v.error else ""
            console.print(
                f"      {v.channel_name:18} grade={v.refusal_grade} "
                f"len={v.response_length}{err}"
            )
        console.print(f"    [dim]{f.reason}[/dim]")
    metadata = {
        "target_model": getattr(target_model, "model_name", "unknown"),
        "mode": "chatbot-attack",
        "attack": "channel-inconsistency",
        "channels": list(channels.keys()),
        "total_probes": len(findings),
        "inconsistent": inconsistent_count,
    }
    ReportGenerator().generate_report(
        [_channel_to_dict(f) for f in findings], metadata
    )


async def _run_jwt_claims(args, target_model) -> None:
    try:
        attack = JWTClaimsAttack(target_model)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    findings = await attack.run(target_system_prompt=args.system_prompt)
    console.print(f"[bold]Tested {len(findings)} JWT claim mutations.[/bold]\n")
    for f in findings:
        marker = (
            "[yellow]⊘[/yellow]" if f.transport_rejected
            else ("[red]●[/red]" if f.behavior_changed else "[dim]·[/dim]")
        )
        console.print(
            f"  {marker} [{f.severity:8}] {f.mutation.name:20} "
            f"grade {f.baseline_grade}→{f.mutated_grade}  {f.reason}"
        )
    metadata = {
        "target_model": getattr(target_model, "model_name", "unknown"),
        "mode": "chatbot-attack", "attack": "jwt-claims",
        "total_findings": len(findings),
        "behavior_changed": sum(1 for f in findings if f.behavior_changed),
        "transport_rejected": sum(1 for f in findings if f.transport_rejected),
    }
    ReportGenerator().generate_report([_jwt_to_dict(f) for f in findings], metadata)


async def _run_conversation_hijack(args, target_model) -> None:
    try:
        attack = ConversationHijackAttack(target_model)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    finding = await attack.run(target_system_prompt=args.system_prompt)
    console.print(
        f"[bold]Tried {len(finding.candidate_attempts)} candidate sessionIds.[/bold]\n"
    )
    for a in finding.candidate_attempts:
        marker = "[red]●[/red]" if a.severity in ("critical", "high") else "[dim]·[/dim]"
        console.print(
            f"  {marker} [{a.severity:8}] sid={a.candidate_session_id:30} "
            f"leaks={len(a.leaked_indicators)}  {a.reason}"
        )
    if finding.most_severe and finding.most_severe.severity in ("critical", "high"):
        console.print(
            f"\n[bold red]⚠ Most severe: {finding.most_severe.severity} on "
            f"sessionId {finding.most_severe.candidate_session_id}[/bold red]"
        )
    metadata = {
        "target_model": getattr(target_model, "model_name", "unknown"),
        "mode": "chatbot-attack", "attack": "conversation-hijack",
        "candidates_tested": len(finding.candidate_attempts),
    }
    ReportGenerator().generate_report([_hijack_to_dict(finding)], metadata)


async def _run_cost_amplification(args, target_model) -> None:
    summary = await CostAmplificationAttack(target_model).run(
        target_system_prompt=args.system_prompt
    )
    console.print(
        f"[bold]Total est. tokens: {summary.total_response_tokens_est:,} "
        f"(~${summary.total_estimated_cost_usd:.4f})  "
        f"Max amp: {summary.max_amplification:.0f}×[/bold]\n"
    )
    for f in summary.findings:
        marker = "[red]●[/red]" if f.severity in ("critical", "high") else "[dim]·[/dim]"
        console.print(
            f"  {marker} [{f.severity:8}] {f.probe_name:22} "
            f"out={f.response_tokens_est:>6} tok  amp={f.amplification_factor:>5.0f}× "
            f"~${f.estimated_cost_usd:.5f}"
        )
    metadata = {
        "target_model": getattr(target_model, "model_name", "unknown"),
        "mode": "chatbot-attack", "attack": "cost-amplification",
        "max_amplification": summary.max_amplification,
        "total_tokens": summary.total_response_tokens_est,
        "estimated_cost_usd": summary.total_estimated_cost_usd,
    }
    ReportGenerator().generate_report(
        [_cost_to_dict(f) for f in summary.findings], metadata
    )


async def _run_refusal_fatigue(args, target_model) -> None:
    findings = await RefusalFatigueAttack(target_model).run(
        target_system_prompt=args.system_prompt
    )
    eroded = sum(1 for f in findings if f.eroded)
    console.print(
        f"[bold]{eroded}/{len(findings)} scripts caused refusal erosion.[/bold]\n"
    )
    for f in findings:
        marker = "[red]●[/red]" if f.eroded else "[dim]·[/dim]"
        console.print(
            f"  {marker} [{f.severity:8}] {f.script_name:25} "
            f"grade {f.initial_grade}→{f.weakest_grade} (final {f.final_grade})  "
            f"{f.reason}"
        )
    metadata = {
        "target_model": getattr(target_model, "model_name", "unknown"),
        "mode": "chatbot-attack", "attack": "refusal-fatigue",
        "eroded_scripts": eroded, "total_scripts": len(findings),
    }
    ReportGenerator().generate_report(
        [_fatigue_to_dict(f) for f in findings], metadata
    )


async def _run_tool_result_poisoning(args, target_model) -> None:
    attempts = await ToolResultPoisoningAttack(target_model).run(
        target_system_prompt=args.system_prompt
    )
    swallowed = sum(1 for a in attempts if a.swallowed)
    console.print(
        f"[bold]{swallowed}/{len(attempts)} poisoned tool results were swallowed.[/bold]\n"
    )
    for a in attempts:
        marker = "[red]●[/red]" if a.swallowed else "[dim]·[/dim]"
        console.print(
            f"  {marker} [{a.severity:8}] {a.payload.name:30} "
            f"{a.reason}"
        )
    metadata = {
        "target_model": getattr(target_model, "model_name", "unknown"),
        "mode": "chatbot-attack", "attack": "tool-result-poisoning",
        "swallowed": swallowed, "total_payloads": len(attempts),
    }
    ReportGenerator().generate_report(
        [_poison_to_dict(a) for a in attempts], metadata
    )


async def _run_fingerprint(args, target_model) -> None:
    console.print("\n[bold cyan]🔍 FINGERPRINTING TARGET[/bold cyan]")
    fp = await fingerprint_target(
        target_model, target_system_prompt=args.system_prompt
    )
    save_fingerprint(fp, args.fingerprint_out)
    console.print(
        f"Target:           [bold]{fp.target_model}[/bold]\n"
        f"Refusal style:    [bold]{fp.refusal_style}[/bold]\n"
        f"Policy leak:      [bold]{fp.policy_leak_observed}[/bold]\n"
        f"Weak axis:        [bold red]{fp.weak_obfuscation_axis}[/bold red]\n"
        f"Avg resp length:  {fp.avg_response_length:.0f} chars\n"
        f"Avg resp time:    {fp.avg_response_seconds:.2f}s\n"
    )
    console.print("[bold]Per-axis refusal rates:[/bold]")
    for axis, rate in sorted(fp.axis_refusal_rates.items()):
        console.print(f"  {axis:13} {rate:.0%}")
    console.print(f"\n[dim]Wrote fingerprint to {args.fingerprint_out}[/dim]")


async def _run_self_play(args) -> None:
    import json as _json
    from pathlib import Path as _Path

    import yaml as _yaml

    from .discovery import (
        SelfPlay,
        SelfPlayConfig,
        all_self_play_coordinates,
    )

    coords = _parse_self_play_coordinates(args.self_play_coordinate)

    attacker_api_key = os.getenv(f"{args.attacker.upper()}_API_KEY")
    generator_model = async_get_model(
        args.attacker, api_key=attacker_api_key,
        model_name=args.attacker_model, **_transport_kwargs(args),
    )

    critic_provider = args.self_play_critic or args.attacker
    critic_api_key = os.getenv(f"{critic_provider.upper()}_API_KEY")
    critic_model = async_get_model(
        critic_provider, api_key=critic_api_key,
        **_transport_kwargs(args),
    )

    cfg = SelfPlayConfig(
        coordinates=coords,
        probes_per_coordinate=args.self_play_n,
        critic_rounds=args.self_play_rounds,
        refusal_threshold=args.self_play_threshold,
        concurrency=args.self_play_concurrency,
    )

    console.print(
        f"\n[bold magenta]🎭 SELF-PLAY[/bold magenta]  "
        f"coords={len(coords)}  per-coord={cfg.probes_per_coordinate}  "
        f"rounds={cfg.critic_rounds}  threshold={cfg.refusal_threshold}"
    )

    sp = SelfPlay(generator_model, critic_model, cfg)
    candidates = await sp.run()

    accepted = [c for c in candidates if c.accepted]
    rejected = [c for c in candidates if not c.accepted]

    console.print(
        f"\n[bold]Generated:[/bold] {len(candidates)}  "
        f"[green]accepted={len(accepted)}[/green]  "
        f"[yellow]rejected={len(rejected)}[/yellow]"
    )
    # Top 10 accepted by lowest critic confidence (most likely to succeed in the wild).
    top = sorted(accepted, key=lambda c: c.final_critic_confidence)[:10]
    if top:
        console.print("\n[bold]Top accepted (lowest critic confidence):[/bold]")
        for c in top:
            console.print(
                f"  conf={c.final_critic_confidence:>2}  rounds={c.rounds}  "
                f"{c.coordinate:50}  {c.probe.id}"
            )

    if args.self_play_out:
        out_dir = _Path(args.self_play_out)
        out_dir.mkdir(parents=True, exist_ok=True)
        for c in accepted:
            file_path = out_dir / f"{c.probe.id}.yaml"
            file_path.write_text(
                _yaml.safe_dump(
                    _self_play_probe_to_dict(c.probe),
                    sort_keys=False, allow_unicode=True,
                ),
                encoding="utf-8",
            )
        console.print(
            f"[green]Saved {len(accepted)} probe(s) → {out_dir}/ "
            "(re-run with --probe-catalog --probe-catalog-path to evaluate)[/green]"
        )

    if args.self_play_trace:
        trace_path = _Path(args.self_play_trace)
        trace_path.write_text(
            _json.dumps(
                {
                    "coordinates": [
                        f"{v}/{o}/{e}" for (v, o, e) in coords
                    ],
                    "probes_per_coordinate": cfg.probes_per_coordinate,
                    "critic_rounds": cfg.critic_rounds,
                    "refusal_threshold": cfg.refusal_threshold,
                    "candidates": [
                        {
                            "probe_id": c.probe.id,
                            "coordinate": c.coordinate,
                            "rounds": c.rounds,
                            "final_critic_confidence": c.final_critic_confidence,
                            "critic_predicted_refusal": c.critic_predicted_refusal,
                            "accepted": c.accepted,
                            "rejection_reason": c.rejection_reason,
                            "prompt": c.probe.prompt,
                        }
                        for c in candidates
                    ],
                },
                indent=2, ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        console.print(f"[green]Wrote self-play trace → {trace_path}[/green]")


def _parse_self_play_coordinates(raw: list[str] | None):
    """Parse vector/obfuscation/effect strings into typed tuples.

    None / empty → return all 64 combinations from
    ``all_self_play_coordinates()``.
    """
    from .discovery import all_self_play_coordinates

    if not raw:
        return all_self_play_coordinates()
    out = []
    for entry in raw:
        parts = entry.strip().split("/")
        if len(parts) != 3:
            logger.error(
                f"--self-play-coordinate must be vector/obfuscation/effect, "
                f"got {entry!r}"
            )
            sys.exit(1)
        out.append((parts[0], parts[1], parts[2]))
    return out


def _self_play_probe_to_dict(probe) -> dict:
    return {
        "id": probe.id,
        "version": probe.version,
        "name": probe.name,
        "description": probe.description,
        "taxonomy": {
            "vector": probe.taxonomy.vector,
            "delivery": probe.taxonomy.delivery,
            "obfuscation": probe.taxonomy.obfuscation,
            "target_effect": probe.taxonomy.target_effect,
        },
        "severity": probe.severity,
        "owasp_llm": probe.owasp_llm,
        "prompt": probe.prompt,
        "success_indicators": probe.success_indicators,
        "refusal_indicators": probe.refusal_indicators,
        "notes": probe.notes,
        "created": probe.created.isoformat(),
        "metadata": probe.metadata,
    }


async def _run_climb(args, target_model) -> None:
    import json as _json
    from pathlib import Path as _Path

    import yaml as _yaml

    from .discovery import ChatTarget, LMTWTClimb
    from .probes.loader import load_probe_file

    if not args.climb_seed:
        logger.error("--climb requires --climb-seed (probe id or YAML path)")
        sys.exit(1)

    seed = _resolve_climb_seed(args)
    console.print(
        f"\n[bold magenta]⛏️  LMTWT-CLIMB[/bold magenta]  "
        f"seed=[bold]{seed.id}[/bold]  "
        f"rounds={args.climb_rounds}  fanout={args.climb_fanout}  keep={args.climb_keep}"
    )

    attacker_api_key = os.getenv(f"{args.attacker.upper()}_API_KEY")
    attacker_model = async_get_model(
        args.attacker, api_key=attacker_api_key,
        model_name=args.attacker_model, **_transport_kwargs(args),
    )

    scoring_judge = None
    if args.climb_judge:
        scoring_judge = ScoringLLMJudge(
            attacker_model, threshold=args.strategy_threshold,
        )

    climb = LMTWTClimb(
        target=ChatTarget(target_model, system=args.system_prompt),
        attacker=attacker_model,
        scoring_judge=scoring_judge,
        max_rounds=args.climb_rounds,
        fanout=args.climb_fanout,
        keep=args.climb_keep,
    )
    result = await climb.run(seed)

    console.print(
        f"\n[bold]Stopped:[/bold] {result.stopped_reason}  "
        f"[bold]Best fitness:[/bold] {result.best_fitness:.2f}  "
        f"[bold]Rounds:[/bold] {result.rounds_run}  "
        f"[bold]Attempts:[/bold] {len(result.history)}"
    )
    console.print(f"[bold]Best probe:[/bold] {result.best_probe.id}")
    if result.best_probe.metadata.get("climb"):
        chain = result.best_probe.metadata["climb"]
        console.print(
            f"  parent={chain.get('parent_id')}  "
            f"operator={chain.get('operator')}  "
            f"generation={chain.get('generation')}"
        )

    # Top 5 attempts by fitness for a quick visual.
    top = sorted(result.history, key=lambda a: -a.fitness)[:5]
    console.print("\n[bold]Top attempts:[/bold]")
    for a in top:
        console.print(
            f"  fit={a.fitness:>4.1f} grade={a.grade}  "
            f"op={a.operator:<11} gen={a.generation}  id={a.probe_id}"
        )

    if args.climb_out:
        out = _Path(args.climb_out)
        out.write_text(_json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
                       encoding="utf-8")
        console.print(f"[green]Wrote climb result → {out}[/green]")

    if args.climb_save and result.stopped_reason == "success":
        save_path = _Path(args.climb_save)
        probe = result.best_probe
        # Dump as YAML in the same shape probe-files use, so it can drop into the corpus.
        probe_dict = {
            "id": probe.id,
            "version": probe.version,
            "name": probe.name,
            "description": probe.description,
            "taxonomy": {
                "vector": probe.taxonomy.vector,
                "delivery": probe.taxonomy.delivery,
                "obfuscation": probe.taxonomy.obfuscation,
                "target_effect": probe.taxonomy.target_effect,
            },
            "severity": probe.severity,
            "owasp_llm": probe.owasp_llm,
            "prompt": probe.prompt,
            "success_indicators": probe.success_indicators,
            "refusal_indicators": probe.refusal_indicators,
            "notes": probe.notes,
            "created": probe.created.isoformat(),
            "metadata": probe.metadata,
        }
        save_path.write_text(
            _yaml.safe_dump(probe_dict, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        console.print(f"[green]Saved climbed probe → {save_path}[/green]")
    elif args.climb_save:
        console.print(
            "[yellow]--climb-save skipped: climb did not reach 'success'.[/yellow]"
        )


def _resolve_climb_seed(args):
    return _resolve_seed(args.climb_seed, args.probe_catalog_path, flag="--climb-seed")


def _resolve_seed(seed_arg: str, catalog_path, *, flag: str):
    from pathlib import Path as _Path

    from .probes.loader import load_probe_file

    p = _Path(seed_arg)
    if p.is_file():
        return load_probe_file(p)
    corpus = load_corpus(root=catalog_path)
    for probe in corpus:
        if probe.id == seed_arg:
            return probe
    logger.error(
        f"{flag} {seed_arg!r} is neither an existing file nor a known "
        f"probe id in the catalog (use --list-probes to inspect)."
    )
    sys.exit(1)


async def _run_pollinate(args) -> None:
    import yaml as _yaml
    from pathlib import Path as _Path

    from .discovery import CrossPollinator

    if not args.pollinate_seed:
        logger.error("--pollinate requires --pollinate-seed (probe id or YAML path)")
        sys.exit(1)

    seed = _resolve_seed(
        args.pollinate_seed, args.probe_catalog_path, flag="--pollinate-seed",
    )

    # An attacker is only required for LLM-driven operators (translate,
    # persona). Mechanical operators run without one.
    attacker_model = None
    if not args.pollinate_skip_op or not {
        "translate-zh", "persona-wrap"
    }.issubset(set(args.pollinate_skip_op)):
        try:
            attacker_api_key = os.getenv(f"{args.attacker.upper()}_API_KEY")
            attacker_model = async_get_model(
                args.attacker, api_key=attacker_api_key,
                model_name=args.attacker_model, **_transport_kwargs(args),
            )
        except Exception as e:  # noqa: BLE001
            console.print(
                f"[yellow]Attacker model unavailable ({e}); LLM-driven "
                "operators (translate-zh, persona-wrap) will be skipped.[/yellow]"
            )

    pol = CrossPollinator(
        attacker=attacker_model,
        skip_operators=set(args.pollinate_skip_op or []),
    )
    plan = pol.plan(seed)
    console.print(
        f"\n[bold cyan]🌱 CROSS-POLLINATE[/bold cyan]  "
        f"seed=[bold]{seed.id}[/bold]  "
        f"obfuscation slots={plan.target_obfuscations}  "
        f"delivery slots={plan.target_deliveries}"
    )

    variants = await pol.pollinate(seed, engagement=args.pollinate_engagement)
    console.print(f"[bold]Generated {len(variants)} variant(s) (after dedupe).[/bold]\n")
    for v in variants:
        console.print(
            f"  [{v.operator:18}] {v.target_axis_change:42} -> {v.probe.coordinate}"
        )

    def _probe_to_yaml_dict(probe):
        d = {
            "id": probe.id,
            "version": probe.version,
            "name": probe.name,
            "description": probe.description,
            "taxonomy": {
                "vector": probe.taxonomy.vector,
                "delivery": probe.taxonomy.delivery,
                "obfuscation": probe.taxonomy.obfuscation,
                "target_effect": probe.taxonomy.target_effect,
            },
            "severity": probe.severity,
            "owasp_llm": probe.owasp_llm,
            "prompt": probe.prompt,
            "success_indicators": probe.success_indicators,
            "refusal_indicators": probe.refusal_indicators,
            "notes": probe.notes,
            "created": probe.created.isoformat(),
            "metadata": probe.metadata,
        }
        return d

    if args.pollinate_out:
        out = _Path(args.pollinate_out)
        out.write_text(
            _yaml.safe_dump_all(
                [_probe_to_yaml_dict(v.probe) for v in variants],
                sort_keys=False, allow_unicode=True,
            ),
            encoding="utf-8",
        )
        console.print(f"\n[green]Wrote {len(variants)} variant(s) → {out}[/green]")

    if args.pollinate_save_dir:
        out_dir = _Path(args.pollinate_save_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for v in variants:
            file_path = out_dir / f"{v.probe.id}.yaml"
            file_path.write_text(
                _yaml.safe_dump(
                    _probe_to_yaml_dict(v.probe),
                    sort_keys=False, allow_unicode=True,
                ),
                encoding="utf-8",
            )
        console.print(
            f"[green]Saved {len(variants)} variant(s) → {out_dir}/ "
            "(re-run --probe-catalog --probe-catalog-path to evaluate)[/green]"
        )


async def _run_probe_catalog(args, target_model) -> None:
    console.print("\n[bold red]🔥 PROBE CATALOG (LMTWT-native corpus)[/bold red]")

    severity_filter = (
        [s.strip() for s in args.probe_severity.split(",")]
        if args.probe_severity else None
    )
    corpus = load_corpus(
        root=args.probe_catalog_path,
        coordinate_filter=args.probe_coordinate,
        severity_filter=severity_filter,
    )

    # --adaptive: load or build a fingerprint, then ask the attacker model
    # for fresh probes that target the fingerprint's gaps.
    adapted = []
    if args.adaptive:
        fp = await _resolve_fingerprint(args, target_model)
        attacker_api_key = os.getenv(f"{args.attacker.upper()}_API_KEY")
        attacker_model = async_get_model(
            args.attacker,
            api_key=attacker_api_key,
            model_name=args.attacker_model,
            **_transport_kwargs(args),
        )
        adapter = AdaptiveAttacker(attacker_model)
        adapted = await adapter.generate(fp, n=args.adaptive_n)
        if adapted:
            console.print(
                f"[cyan]Adaptive attacker generated {len(adapted)} probe(s) "
                f"targeting weak axis '{fp.weak_obfuscation_axis}'[/cyan]"
            )
            corpus = corpus + [a.probe for a in adapted]

    if not corpus:
        console.print("[yellow]No probes matched the filter; nothing to run.[/yellow]")
        return

    console.print(
        f"Loaded [bold]{len(corpus)}[/bold] probes "
        f"({len(adapted)} adaptive, {len(corpus) - len(adapted)} static; "
        f"filter={args.probe_coordinate or '*'}, "
        f"severity={args.probe_severity or 'any'})\n"
    )

    observers = []
    dashboard = None
    if getattr(args, "dashboard", False):
        from .cli_dashboard import RichDashboardObserver

        dashboard = RichDashboardObserver(
            getattr(target_model, "model_name", str(args.target)),
            console=console,
        )
        observers.append(dashboard)
    if getattr(args, "persist", False):
        from .persistence import SQLiteObserver

        observers.append(SQLiteObserver(
            args.persist_db,
            target_name=getattr(target_model, "model_name", str(args.target)),
            attacker_name=str(args.attacker),
            mode="probe-catalog",
            metadata={
                "coordinate_filter": args.probe_coordinate,
                "severity_filter": args.probe_severity,
                "repeats": getattr(args, "probe_repeat", 1),
            },
        ))

    runner = AsyncCatalogProbe(
        target_model, probes=corpus, concurrency=args.concurrency,
        repeats=getattr(args, "probe_repeat", 1),
        refusal_grader=_build_refusal_grader(args),
        observers=observers,
    )
    if dashboard is not None:
        async with dashboard:
            summary = await runner.run(target_system_prompt=args.system_prompt)
    else:
        summary = await runner.run(target_system_prompt=args.system_prompt)

    console.print(
        f"[bold]Ran {summary.executed}/{summary.total} probes[/bold] "
        f"(skipped {summary.skipped}, errors {summary.errors})"
    )
    console.print(
        f"[bold green]Successful attacks: {summary.successes}/{summary.executed}[/bold green]  "
        f"[bold]Max LSS:[/bold] {summary.max_lss:.2f}\n"
    )

    console.print("[bold]By severity:[/bold]")
    for sev in ("critical", "high", "medium", "low"):
        b = summary.by_severity.get(sev)
        if b:
            console.print(
                f"  {sev:9}  {b['successes']}/{b['total']} hit"
            )

    console.print("\n[bold]By taxonomy coordinate:[/bold]")
    for coord, b in sorted(summary.by_coordinate.items()):
        console.print(f"  {coord:55} {b['successes']}/{b['total']} hit")

    if summary.by_refusal_grade:
        console.print("\n[bold]By refusal grade:[/bold]")
        for grade in ("A", "B", "C", "D", "F"):
            count = summary.by_refusal_grade.get(grade, 0)
            if count:
                console.print(f"  {grade}  {count}")

    console.print("\n[bold]Per-probe outcomes:[/bold]")
    for o in summary.outcomes:
        mark = "[green]✓[/green]" if o.get("success") else "[dim]·[/dim]"
        if o.get("skipped_reason"):
            mark = "[yellow]~[/yellow]"
        lss = o.get("lss")
        lss_tag = f"LSS={lss['score']:.2f}" if lss else "       "
        rg = o.get("refusal_grade") or "-"
        console.print(
            f"  {mark} [{o['severity']:8}] {lss_tag}  refusal={rg}  "
            f"{o['probe_id']:55} {o.get('reason') or ''}"
        )

    metadata = {
        "target_model": getattr(target_model, "model_name", "unknown"),
        "mode": "probe-catalog",
        "total_probes": summary.total,
        "executed": summary.executed,
        "successes": summary.successes,
        "by_severity": summary.by_severity,
        "by_coordinate": summary.by_coordinate,
    }
    ReportGenerator().generate_report(summary.outcomes, metadata)


async def async_main() -> None:
    load_dotenv()
    args = parse_args()

    if args.list_templates:
        list_templates_and_exit()
        return
    if args.list_flows:
        list_flows_and_exit()
        return
    if args.list_vectors:
        list_vectors_and_exit()
        return
    if args.list_probes:
        list_probes_and_exit(args)
        return
    if args.list_runs:
        _list_runs_and_exit(args)
        return
    if args.show_run is not None:
        _show_run_and_exit(args)
        return
    if args.report_from:
        _emit_engagement_report(args)
        return
    if args.diff_before or args.diff_after:
        _emit_diff_report(args)
        return
    if args.scorecard_from:
        _emit_scorecard_report(args)
        return
    if args.pollinate:
        await _run_pollinate(args)
        return
    if args.self_play:
        await _run_self_play(args)
        return

    config = load_config(args.config)

    if args.web:
        console.print("\n[bold blue]🌐 Launching LMTWT Web UI[/bold blue]")
        try:
            from .web import launch_web_ui

            launch_web_ui(config_path=args.config, port=args.web_port, share=args.share)
        except ImportError as e:
            logger.error(f"Failed to launch web UI: {e}")
            console.print("[bold red]Install gradio: pip install lmtwt[web][/bold red]")
            sys.exit(1)
        return

    if args.web_api:
        console.print(
            f"\n[bold blue]🌐 Launching LMTWT Web API on "
            f"{args.web_api_host}:{args.web_api_port}[/bold blue]"
        )
        try:
            from .web_api import run_server

            run_server(
                host=args.web_api_host,
                port=args.web_api_port,
                db_path=args.persist_db,
            )
        except ImportError as e:
            logger.error(f"Failed to launch web API: {e}")
            console.print("[bold red]Install: pip install lmtwt[api][/bold red]")
            sys.exit(1)
        return

    logger.info(f"System: {platform.system()} {platform.release()}")
    logger.info(f"Python: {platform.python_version()}")
    logger.info(f"GPU: {GPU_INFO}")

    target_api_config = None
    if args.target.lower() == "external-api":
        if not args.target_config:
            logger.error("--target-config is required for external-api targets")
            sys.exit(1)
        try:
            target_api_config = load_target_config(args.target_config)
        except Exception as e:
            logger.error(f"Failed to load target config: {e}")
            sys.exit(1)

    hacker_system_prompt = args.hacker_system_prompt
    if args.hacker_mode and not hacker_system_prompt:
        hacker_system_prompt = config.get("hacker_mode", {}).get("system_prompt")

    target_api_key = (
        os.getenv(f"{args.target.upper()}_API_KEY")
        if args.target != "external-api"
        else None
    )
    target_model = async_get_model(
        args.target,
        api_key=target_api_key,
        model_name=args.target_model,
        api_config=target_api_config,
        **_transport_kwargs(args),
    )

    if args.fingerprint:
        await _run_fingerprint(args, target_model)
        return

    if args.climb:
        await _run_climb(args, target_model)
        return

    if args.chatbot_attack:
        await _run_chatbot_attack(args, target_model)
        return

    if args.probe_catalog:
        await _run_probe_catalog(args, target_model)
        return

    if args.probe_mode:
        await _run_probe(args, target_model)
        return

    attacker_api_key = os.getenv(f"{args.attacker.upper()}_API_KEY")
    attacker_model = async_get_model(
        args.attacker,
        api_key=attacker_api_key,
        model_name=args.attacker_model,
        **_transport_kwargs(args),
    )

    judge = await _build_judge(args)
    engine = AsyncAttackEngine(
        attacker_model,
        target_model,
        judge=judge,
        hacker_mode=args.hacker_mode,
        hacker_system_prompt=hacker_system_prompt,
        max_auto_retries=args.max_retries,
    )

    if args.mode == "interactive":
        await _run_interactive(engine, args)
    elif args.mode == "batch":
        if not args.instruction:
            logger.error("Batch mode requires at least one --instruction")
            sys.exit(1)
        await _run_batch(engine, args, args.instruction)
    elif args.mode == "template":
        if not args.template:
            logger.error("Template mode requires at least one --template")
            sys.exit(1)
        instructions = [
            instr for tpl in args.template
            if (instr := get_template_instruction(tpl)) is not None
        ]
        if not instructions:
            logger.error("No valid templates resolved")
            sys.exit(1)
        await _run_batch(engine, args, instructions)
    elif args.strategy:
        if not args.instruction:
            logger.error("--strategy requires at least one --instruction (the goal)")
            sys.exit(1)
        await _run_strategy(args, attacker_model, target_model)
    elif args.mode == "multi-turn":
        if not args.flow:
            logger.error("Multi-turn mode requires --flow (use --list-flows)")
            sys.exit(1)
        flow = get_flow(args.flow)
        if flow is None:
            logger.error(f"Unknown flow: {args.flow}. Use --list-flows.")
            sys.exit(1)
        if not args.instruction:
            logger.error("Multi-turn mode requires at least one --instruction (the goal)")
            sys.exit(1)
        await _run_multi_turn(args, attacker_model, target_model, judge, flow)
    elif args.mode == "tool-use":
        if not args.instruction:
            logger.error("Tool-use mode requires at least one --instruction (the goal)")
            sys.exit(1)
        await _run_tool_use(args, attacker_model, target_model, judge)


def _parse_scan_args(argv: list[str]) -> argparse.Namespace:
    """Parser for the ``lmtwt scan`` subcommand. Tight, opinionated."""
    p = argparse.ArgumentParser(
        prog="lmtwt scan",
        description=(
            "Run a full vulnerability scan against a target with sensible "
            "defaults. One command, one bundle out. For granular control "
            "use the legacy CLI (lmtwt --probe-catalog, --climb, etc.)."
        ),
    )
    p.add_argument("--target", "-t", required=True,
                   choices=["gemini", "openai", "anthropic", "external-api",
                            "huggingface", "lmstudio", "openai-compat",
                            "claude-code", "acp"],
                   help="Target provider")
    p.add_argument("--attacker", "-a", default="gemini",
                   choices=["gemini", "openai", "anthropic", "huggingface",
                            "lmstudio", "openai-compat", "claude-code", "acp"],
                   help="Attacker / generator / critic model provider "
                        "(default: gemini). Use 'openai-compat' to point at "
                        "any OpenAI-compatible endpoint via OPENAI_COMPAT_BASE_URL.")
    p.add_argument("--target-model", default=None,
                   help="Specific target model id (else provider default)")
    p.add_argument("--attacker-model", default=None,
                   help="Specific attacker model id (else provider default)")
    p.add_argument("--target-config", default=None,
                   help="Path to a target-config JSON (required for "
                        "--target external-api; enables capability-detected "
                        "chatbot attacks)")
    p.add_argument("--depth", default="standard",
                   choices=["quick", "standard", "thorough"],
                   help="Scan depth (default: standard). 'quick' = "
                        "catalog+fingerprint only; 'thorough' = above + "
                        "self-play + N=10 repeats.")
    p.add_argument("--out", default=None,
                   help="Output directory for the engagement bundle "
                        "(default: ./scan-<date>-<target>/)")
    p.add_argument("--system-prompt", default=None,
                   help="System prompt to set on the target")
    p.add_argument("--no-llm-grader", action="store_true",
                   help="Use the regex-only refusal grader instead of the "
                        "LLM ensemble (faster, less accurate on edge cases)")
    p.add_argument("--no-dashboard", action="store_true",
                   help="Suppress the live TUI dashboard (auto-off on non-TTY)")
    p.add_argument("--concurrency", type=int, default=4,
                   help="Parallel target API calls (default: 4)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the scan plan and exit without running")
    # Proxy / TLS — mirror the legacy flags.
    p.add_argument("--proxy", default=None)
    p.add_argument("--ca-bundle", default=None)
    p.add_argument("--insecure", action="store_true")
    return p.parse_args(argv)


async def _run_scan_subcommand(argv: list[str]) -> int:
    import datetime as _dt
    import json as _json
    from pathlib import Path as _Path

    from .scan import build_scan_plan, run_scan, write_bundle
    from .utils.config import load_target_config

    # Load .env so OPENAI_COMPAT_BASE_URL / *_API_KEY etc. resolve the same
    # way the legacy CLI path expects.
    load_dotenv()

    args = _parse_scan_args(argv)

    # Build target_config so the planner can capability-detect chatbot attacks.
    target_config = None
    if args.target_config:
        try:
            target_config = load_target_config(args.target_config)
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]Failed to load target-config: {e}[/red]")
            return 1
    elif args.target == "external-api":
        console.print(
            "[red]--target external-api requires --target-config[/red]"
        )
        return 1

    plan = build_scan_plan(depth=args.depth, target_config=target_config)

    target_label = args.target_model or args.target
    today = _dt.date.today().isoformat()
    safe_target = "".join(c if c.isalnum() or c in "-_" else "_"
                          for c in target_label)[:40]
    out_dir = _Path(args.out or f"./scan-{today}-{safe_target}")

    if args.dry_run:
        console.print(f"\n[bold]Plan ({plan.depth} depth)[/bold]  out={out_dir}")
        for s in plan.steps:
            mark = "[green]✓[/green]" if s.enabled else "[dim]✗[/dim]"
            reason = f"  ({s.reason_if_skipped})" if not s.enabled and s.reason_if_skipped else ""
            console.print(f"  {mark} {s.name}{reason}")
        return 0

    console.print(
        f"\n[bold magenta]🔍 LMTWT SCAN[/bold magenta]  "
        f"target=[bold]{target_label}[/bold]  attacker=[bold]{args.attacker}[/bold]  "
        f"depth=[bold]{args.depth}[/bold]"
    )
    console.print(f"[dim]Bundle → {out_dir}[/dim]\n")

    target_api_key = (
        os.getenv(f"{args.target.upper()}_API_KEY")
        if args.target != "external-api" else None
    )
    transport = {"proxy": args.proxy, "ca_bundle": args.ca_bundle,
                 "verify": not args.insecure}
    target_model = async_get_model(
        args.target, api_key=target_api_key,
        model_name=args.target_model,
        api_config=target_config, **transport,
    )
    attacker_api_key = os.getenv(f"{args.attacker.upper()}_API_KEY")
    attacker_model = async_get_model(
        args.attacker, api_key=attacker_api_key,
        model_name=args.attacker_model, **transport,
    )

    show_dashboard = sys.stdout.isatty() and not args.no_dashboard

    try:
        result = await run_scan(
            target=target_model,
            attacker=attacker_model,
            target_name=target_label,
            attacker_name=args.attacker_model or args.attacker,
            plan=plan,
            out_dir=out_dir,
            target_config=target_config,
            target_system_prompt=args.system_prompt,
            concurrency=args.concurrency,
            use_llm_grader=not args.no_llm_grader,
            show_dashboard=show_dashboard,
        )
    except Exception as e:  # noqa: BLE001
        console.print(f"\n[red]scan failed: {e}[/red]")
        return 1

    bundle_path = write_bundle(result, out_dir)

    # Headline summary.
    findings = result.findings
    successes = sum(1 for f in findings if f.get("success"))
    max_lss = max(
        ((f.get("lss") or {}).get("score") or 0.0 for f in findings),
        default=0.0,
    )
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity") or "low"
        sev_counts[s] = sev_counts.get(s, 0) + 1
    console.print(
        f"\n[bold green]✓ scan complete[/bold green]  "
        f"findings={len(findings)}  successes={successes}  max_lss={max_lss:.2f}"
    )
    sev_str = "  ".join(f"{k}={v}" for k, v in sorted(sev_counts.items()))
    console.print(f"  severity:  {sev_str}")
    console.print(
        f"  steps executed: {', '.join(result.executed_steps) or 'none'}"
    )
    if result.step_errors:
        console.print(
            f"  [yellow]step errors:[/yellow] "
            f"{', '.join(result.step_errors.keys())}"
        )
    console.print(f"\n[bold]Bundle:[/bold] {bundle_path}/")
    for fname in ("scan.json", "report.md", "report.html", "report.pdf",
                  "scorecard.md", "fingerprint.json", "scan.db",
                  "repro/index.json"):
        p = bundle_path / fname
        if p.exists():
            console.print(f"  • {fname}")
    return 0


def main() -> None:
    # Subcommand dispatch — keep the legacy flat parser working untouched
    # for backward compat. The new scan front door is opt-in via the first
    # positional arg.
    if len(sys.argv) >= 2 and sys.argv[1] == "scan":
        try:
            rc = asyncio.run(_run_scan_subcommand(sys.argv[2:]))
        except KeyboardInterrupt:
            print("\nInterrupted")
            sys.exit(0)
        sys.exit(rc)
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(0)
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
