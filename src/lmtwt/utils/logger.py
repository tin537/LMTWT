import json
import logging
import os
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

# Set up rich console
console = Console()


def setup_logger(name: str = "lmtwt", log_level: int = logging.INFO) -> logging.Logger:
    """
    Set up a logger with the given name and log level.

    Args:
        name: Logger name
        log_level: Logging level

    Returns:
        Configured logger
    """
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )

    return logging.getLogger(name)


def log_conversation(
    attacker_model: str,
    target_model: str,
    prompts: list,
    responses: list,
    success: bool,
    log_dir: str | None = None,
) -> str:
    """
    Log a conversation to a JSON file.

    Args:
        attacker_model: Name of the attacker model
        target_model: Name of the target model
        prompts: List of prompts sent to the target model
        responses: List of responses from the target model
        success: Whether the attack was successful
        log_dir: Directory to save logs

    Returns:
        Path to the log file
    """
    if not log_dir:
        log_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "logs"
        )

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_path / f"attack_{timestamp}.json"

    conversation = []
    for i, (prompt, response) in enumerate(zip(prompts, responses)):
        conversation.append({"turn": i + 1, "prompt": prompt, "response": response})

    log_data = {
        "timestamp": timestamp,
        "attacker_model": attacker_model,
        "target_model": target_model,
        "success": success,
        "conversation": conversation,
    }

    with open(log_file, "w") as f:
        json.dump(log_data, f, indent=2)

    return str(log_file)


def print_attack_result(prompt: str, response: str, success: bool, reason: str | None = None):
    """
    Print attack result to console with nice formatting.

    Args:
        prompt: The prompt sent to the target model
        response: The response from the target model
        success: Whether the attack was successful
        reason: Optional reason for the success/failure verdict from compliance agent
    """
    console.print("\n[bold cyan]===== Attack Result =====", style="bold cyan")

    if success:
        console.print(
            "\n[bold green]SUCCESS: Target model executed the instructions directly![/bold green]"
        )
        if reason:
            console.print(f"[green]Reason: {reason}[/green]")
    else:
        console.print(
            "\n[bold yellow]FAILED: Target model either rejected, defended, or only explained instead of executing.[/bold yellow]"
        )
        if reason:
            console.print(f"[yellow]Reason: {reason}[/yellow]")

    console.print("\n[bold magenta]Prompt:[/bold magenta]")
    console.print(prompt)

    console.print("\n[bold magenta]Response:[/bold magenta]")
    console.print(response)

    console.print("\n[bold cyan]" + "=" * 25 + "[/bold cyan]\n")
