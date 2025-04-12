"""
Utilities for initializing different language model providers.
"""
from typing import Dict, Optional, Any, List
from .base import AIModel
from .gemini import GeminiModel
from .openai import OpenAIModel
from .anthropic import AnthropicModel
from .external_api import ExternalAPIModel
from .huggingface import HuggingFaceModel


def get_model(provider: str, api_key: Optional[str] = None, model_name: Optional[str] = None, 
              api_config: Optional[Dict[str, Any]] = None, use_circuit_breaker: bool = True,
              circuit_failure_threshold: int = 3, circuit_recovery_timeout: int = 60) -> AIModel:
    """
    Get a model instance for the specified provider.
    
    Args:
        provider: The model provider (gemini, openai, anthropic, external-api, huggingface)
        api_key: API key for the provider (override environment variable)
        model_name: Specific model to use
        api_config: API configuration for external API targets
        use_circuit_breaker: Whether to use circuit breaker for API calls
        circuit_failure_threshold: Number of failures before circuit breaker opens
        circuit_recovery_timeout: Seconds to wait before trying to recover
        
    Returns:
        An initialized model instance
    """
    provider_lower = provider.lower()
    
    if provider_lower == "gemini":
        return GeminiModel(
            api_key=api_key,
            model_name=model_name,
            use_circuit_breaker=use_circuit_breaker,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_recovery_timeout=circuit_recovery_timeout
        )
    elif provider_lower == "openai":
        return OpenAIModel(
            api_key=api_key,
            model_name=model_name,
            use_circuit_breaker=use_circuit_breaker,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_recovery_timeout=circuit_recovery_timeout
        )
    elif provider_lower == "anthropic":
        return AnthropicModel(
            api_key=api_key,
            model_name=model_name,
            use_circuit_breaker=use_circuit_breaker,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_recovery_timeout=circuit_recovery_timeout
        )
    elif provider_lower == "external-api":
        if not api_config:
            raise ValueError("API configuration is required for external API targets")
        return ExternalAPIModel(
            api_config=api_config,
            model_name=model_name,
            use_circuit_breaker=use_circuit_breaker,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_recovery_timeout=circuit_recovery_timeout
        )
    elif provider_lower == "huggingface":
        return HuggingFaceModel(
            api_key=api_key,
            model_name=model_name,
            use_circuit_breaker=use_circuit_breaker,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_recovery_timeout=circuit_recovery_timeout
        )
    else:
        raise ValueError(f"Unsupported provider: {provider}")

def list_available_models() -> Dict[str, List[str]]:
    """
    Get a dictionary of available models for each provider.
    
    Returns:
        Dictionary mapping provider names to lists of available models
    """
    available_models = {
        "gemini": [
            "gemini-2.0-flash",
            "gemini-2.0-pro",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-1.0-pro"
        ],
        "openai": [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-4",
            "gpt-3.5-turbo"
        ],
        "anthropic": [
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "claude-3-5-sonnet"
        ],
        "huggingface": [
            "meta-llama/Llama-3-8b-gguf",
            "meta-llama/Llama-3-70b-gguf",
            "mistralai/Mistral-7B-Instruct-v0.2",
            "Qwen/Qwen1.5-7B-Chat",
            "Themelio/aya-101"
        ]
    }
    
    return available_models
