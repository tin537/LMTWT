#!/usr/bin/env python3
import os
import sys
import argparse
from dotenv import load_dotenv

from lmtwt.models import get_model
from lmtwt.attacks.engine import AttackEngine
from lmtwt.attacks.templates import list_attack_templates, get_template_instruction
from lmtwt.utils.config import load_config, load_target_config
from lmtwt.utils.logger import setup_logger, console


# Set up logger
logger = setup_logger()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="LMTWT - Let Me Talk With Them: AI Prompt Injection Testing Tool"
    )
    
    parser.add_argument(
        "--attacker", "-a", type=str, default="gemini",
        choices=["gemini", "openai", "anthropic"],
        help="The model provider to use for generating attacks"
    )
    
    parser.add_argument(
        "--target", "-t", type=str, default="openai",
        choices=["gemini", "openai", "anthropic", "external-api"],
        help="The model provider to target with attacks"
    )
    
    parser.add_argument(
        "--attacker-model", type=str,
        help="Specific model name for the attacker (defaults to provider's default)"
    )
    
    parser.add_argument(
        "--target-model", type=str,
        help="Specific model name for the target (defaults to provider's default)"
    )
    
    parser.add_argument(
        "--mode", "-m", type=str, default="interactive",
        choices=["interactive", "batch", "template"],
        help="Attack mode: interactive, batch, or template"
    )
    
    parser.add_argument(
        "--instruction", "-i", type=str, action="append",
        help="Instructions for generating attack prompts (can be specified multiple times for batch mode)"
    )
    
    parser.add_argument(
        "--template", type=str, action="append",
        help="Predefined attack template to use (can be specified multiple times)"
    )
    
    parser.add_argument(
        "--list-templates", action="store_true",
        help="List available attack templates and exit"
    )
    
    parser.add_argument(
        "--iterations", type=int, default=1,
        help="Number of iterations for each instruction in batch or template mode"
    )
    
    parser.add_argument(
        "--delay", type=int, default=1,
        help="Delay between attacks in seconds (batch mode only)"
    )
    
    parser.add_argument(
        "--config", "-c", type=str,
        help="Path to config file"
    )
    
    parser.add_argument(
        "--target-config", type=str,
        help="Path to target API configuration file (required for external-api target)"
    )
    
    parser.add_argument(
        "--hacker-mode", action="store_true",
        help="Enable advanced hacker mode with conversation history analysis and automatic retry for failed attacks"
    )
    
    parser.add_argument(
        "--system-prompt", type=str,
        help="Custom system prompt for the target model"
    )
    
    parser.add_argument(
        "--hacker-system-prompt", type=str,
        help="Custom system prompt for hacker mode (if enabled)"
    )
    
    parser.add_argument(
        "--auto-send", action="store_true",
        help="Skip prompt editing confirmation in interactive mode"
    )
    
    parser.add_argument(
        "--compliance-agent", action="store_true",
        help="Enable the compliance agent for more accurate success detection"
    )
    
    parser.add_argument(
        "--compliance-provider", type=str, default="gemini",
        choices=["gemini", "openai", "anthropic"],
        help="The model provider to use for the compliance agent"
    )
    
    parser.add_argument(
        "--no-fallback", action="store_true",
        help="Disable fallback to heuristic evaluation when compliance agent hits rate limits"
    )
    
    parser.add_argument(
        "--disable-circuit-breakers", action="store_true",
        help="Disable all circuit breakers for API requests"
    )
    
    parser.add_argument(
        "--circuit-failure-threshold", type=int, default=3,
        help="Number of failures before a circuit breaker opens (default: 3)"
    )
    
    parser.add_argument(
        "--circuit-recovery-timeout", type=int, default=120,
        help="Seconds to wait before attempting recovery after circuit opens (default: 120)"
    )
    
    parser.add_argument(
        "--max-retries", type=int, default=3,
        help="Maximum number of automatic payload regenerations per session (default: 3)"
    )
    
    return parser.parse_args()


def list_templates():
    """List all available templates and exit."""
    templates = list_attack_templates()
    print("\nAvailable Attack Templates:")
    print("---------------------------")
    for template in templates:
        print(f"{template['id']}: {template['name']}")
    print()


def main():
    """Main entry point for the application."""
    # Load environment variables
    load_dotenv()
    
    # Parse command line arguments
    args = parse_args()
    
    # Check if we should just list templates and exit
    if args.list_templates:
        list_templates()
        sys.exit(0)
    
    # Load configuration
    config = load_config(args.config)
    
    # Initialize variables
    target_api_config = None
    hacker_system_prompt = None
    
    # Handle target API configuration for external-api targets
    if args.target.lower() == "external-api":
        if not args.target_config:
            logger.error("Target configuration file is required for external-api targets (use --target-config)")
            sys.exit(1)
            
        try:
            target_api_config = load_target_config(args.target_config)
            logger.info(f"Loaded target API configuration from {args.target_config}")
        except Exception as e:
            logger.error(f"Failed to load target configuration: {str(e)}")
            sys.exit(1)
    
    # Get hacker system prompt if not provided
    if args.hacker_mode and not args.hacker_system_prompt:
        if "hacker_mode" in config and "system_prompt" in config["hacker_mode"]:
            hacker_system_prompt = config["hacker_mode"]["system_prompt"]
        else:
            logger.info("Using default hacker mode system prompt")
    elif args.hacker_mode:
        hacker_system_prompt = args.hacker_system_prompt
    
    try:
        # Display banner for hacker mode
        if args.hacker_mode:
            console.print("\n[bold red]🔥 HACKER MODE ACTIVATED 🔥[/bold red]")
            console.print("[bold yellow]Conversation history analysis and adaptive attacks enabled[/bold yellow]")
            console.print("[bold yellow]The attacker will learn from previous interactions to improve effectiveness[/bold yellow]")
            console.print("[bold yellow]Failed attacks will automatically generate new payloads to retry with different approaches[/bold yellow]\n")
        
        # Display banner for compliance agent
        if args.compliance_agent:
            console.print("\n[bold blue]🔍 COMPLIANCE AGENT ACTIVATED 🔍[/bold blue]")
            console.print("[bold cyan]Enhanced detection of response compliance with prompt instructions[/bold cyan]")
            console.print("[bold cyan]Provides detailed reasoning for success/failure verdicts[/bold cyan]")
            if not args.no_fallback:
                console.print("[bold cyan]Will fallback to heuristic evaluation on rate limits or errors[/bold cyan]\n")
            else:
                console.print("[bold yellow]Fallback disabled - will fail on rate limits or errors[/bold yellow]\n")
        
        # Display banner for circuit breakers
        if not args.disable_circuit_breakers:
            console.print("\n[bold green]🔌 CIRCUIT BREAKERS ENABLED 🔌[/bold green]")
            console.print(f"[bold cyan]Failure threshold: {args.circuit_failure_threshold}, Recovery timeout: {args.circuit_recovery_timeout}s[/bold cyan]")
            console.print("[bold cyan]API requests will be protected against rate limits and cascading failures[/bold cyan]\n")
        
        # Display auto-retry limit if in hacker mode
        if args.hacker_mode:
            console.print(f"[bold yellow]Auto-retry limit: {args.max_retries} attempts per session[/bold yellow]\n")
        
        # Check for model API keys
        attacker_api_key = os.getenv(f"{args.attacker.upper()}_API_KEY")
        target_api_key = os.getenv(f"{args.target.upper()}_API_KEY") if args.target != "external-api" else None
        
        # Get model providers with circuit breaker settings
        attacker_model = get_model(
            provider=args.attacker,
            api_key=attacker_api_key,
            model_name=args.attacker_model,
            use_circuit_breaker=not args.disable_circuit_breakers,
            circuit_failure_threshold=args.circuit_failure_threshold,
            circuit_recovery_timeout=args.circuit_recovery_timeout
        )
        
        if args.target != "external-api":
            target_model = get_model(
                provider=args.target,
                api_key=target_api_key,
                model_name=args.target_model,
                use_circuit_breaker=not args.disable_circuit_breakers,
                circuit_failure_threshold=args.circuit_failure_threshold,
                circuit_recovery_timeout=args.circuit_recovery_timeout
            )
        else:
            target_model = get_model(
                provider=args.target,
                model_name=args.target_model,
                api_config=target_api_config,
                use_circuit_breaker=not args.disable_circuit_breakers,
                circuit_failure_threshold=args.circuit_failure_threshold,
                circuit_recovery_timeout=args.circuit_recovery_timeout
            )
        
        # Initialize attack engine with direct model instances
        engine = AttackEngine(
            attacker_model=attacker_model,
            target_model=target_model,
            hacker_mode=args.hacker_mode,
            hacker_system_prompt=hacker_system_prompt,
            use_compliance_agent=args.compliance_agent,
            compliance_provider=args.compliance_provider,
            compliance_fallback=not args.no_fallback,
            max_auto_retries=args.max_retries
        )
        
        # Run in appropriate mode
        if args.mode == "interactive":
            engine.interactive_attack(
                target_system_prompt=args.system_prompt,
                skip_edit_confirmation=args.auto_send
            )
        
        elif args.mode == "batch":
            if not args.instruction:
                logger.error("Batch mode requires at least one instruction (use --instruction)")
                sys.exit(1)
                
            results = engine.batch_attack(
                instructions=args.instruction,
                iterations=args.iterations,
                delay=args.delay,
                target_system_prompt=args.system_prompt
            )
            
            # Print summary
            successes = sum(1 for r in results if r["success"])
            console.print(f"\n[bold]Batch attack completed: {successes}/{len(results)} successful attacks[/bold]")
            
            # In hacker mode, show the most effective patterns
            if args.hacker_mode and hasattr(engine, "success_patterns") and len(engine.success_patterns) > 0:
                console.print("\n[bold green]Success Patterns Identified:[/bold green]")
                for pattern in set(engine.success_patterns):
                    console.print(f"- {pattern}")
        
        elif args.mode == "template":
            if not args.template:
                logger.error("Template mode requires at least one template (use --template)")
                sys.exit(1)
            
            # Convert templates to instructions
            instructions = []
            for template_name in args.template:
                instruction = get_template_instruction(template_name)
                if instruction:
                    instructions.append(instruction)
                else:
                    logger.warning(f"Template '{template_name}' not found. Use --list-templates to see available templates.")
            
            if not instructions:
                logger.error("No valid templates provided")
                sys.exit(1)
                
            results = engine.batch_attack(
                instructions=instructions,
                iterations=args.iterations,
                delay=args.delay,
                target_system_prompt=args.system_prompt
            )
            
            # Print summary
            successes = sum(1 for r in results if r["success"])
            console.print(f"\n[bold]Template attack completed: {successes}/{len(results)} successful attacks[/bold]")
            
            # In hacker mode, show the most effective patterns
            if args.hacker_mode and hasattr(engine, "success_patterns") and len(engine.success_patterns) > 0:
                console.print("\n[bold green]Success Patterns Identified:[/bold green]")
                for pattern in set(engine.success_patterns):
                    console.print(f"- {pattern}")
            
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 