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
from .attacks.flows import (
    BUILT_IN_FLOWS,
    MultiTurnRunner,
    get_flow,
    list_flows,
    turn_log_to_attack_result,
)
from .attacks.strategies import PAIRStrategy, TAPStrategy
from .attacks.templates import get_template_instruction, list_attack_templates
from .models.async_factory import async_get_model
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
                            "lmstudio", "claude-code", "acp"])
    p.add_argument("--target", "-t", type=str, default="openai",
                   choices=["gemini", "openai", "anthropic", "external-api",
                            "huggingface", "lmstudio", "claude-code", "acp"])
    p.add_argument("--attacker-model", type=str)
    p.add_argument("--target-model", type=str)
    p.add_argument("--mode", "-m", type=str, default="interactive",
                   choices=["interactive", "batch", "template", "multi-turn"])
    p.add_argument("--instruction", "-i", type=str, action="append")
    p.add_argument("--template", type=str, action="append")
    p.add_argument("--list-templates", action="store_true")
    p.add_argument("--flow", type=str,
                   help=f"Multi-turn flow id (one of: {', '.join(BUILT_IN_FLOWS.keys())})")
    p.add_argument("--list-flows", action="store_true")
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


def _transport_kwargs(args) -> dict:
    return {
        "proxy": args.proxy,
        "ca_bundle": args.ca_bundle,
        "verify": not args.insecure,
    }


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


async def async_main() -> None:
    load_dotenv()
    args = parse_args()

    if args.list_templates:
        list_templates_and_exit()
        return
    if args.list_flows:
        list_flows_and_exit()
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


def main() -> None:
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
