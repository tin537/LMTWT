from typing import Optional, Dict, Any
from .base import AIModel
from .gemini import GeminiModel
from .openai import OpenAIModel
from .anthropic import AnthropicModel
from .external_api import ExternalAPIModel


def get_model(provider: str, api_key: Optional[str] = None, model_name: Optional[str] = None, 
              api_config: Optional[Dict[str, Any]] = None, use_circuit_breaker: bool = True,
              circuit_failure_threshold: int = 3, circuit_recovery_timeout: int = 120) -> AIModel:
    """
    Factory function to get the appropriate AI model instance.
    
    Args:
        provider: The model provider name (gemini, openai, anthropic, external-api)
        api_key: Optional API key (will use environment variable if not provided)
        model_name: Optional specific model name to use
        api_config: Optional API configuration for external API providers
        use_circuit_breaker: Whether to enable circuit breaker protection
        circuit_failure_threshold: Number of failures before opening circuit
        circuit_recovery_timeout: Seconds to wait before trying again
    
    Returns:
        An instance of the appropriate AIModel subclass
    
    Raises:
        ValueError: If the provider is not supported
    """
    provider = provider.lower()
    model = None
    
    if provider == "gemini":
        if model_name:
            model = GeminiModel(api_key=api_key, model_name=model_name)
        else:
            model = GeminiModel(api_key=api_key)
    
    elif provider == "openai":
        if model_name:
            model = OpenAIModel(api_key=api_key, model_name=model_name)
        else:
            model = OpenAIModel(api_key=api_key)
    
    elif provider == "anthropic":
        if model_name:
            model = AnthropicModel(api_key=api_key, model_name=model_name)
        else:
            model = AnthropicModel(api_key=api_key)
    
    elif provider == "external-api":
        if not api_config:
            raise ValueError("API configuration is required for external API providers")
        model = ExternalAPIModel(api_config=api_config, model_name=model_name)
    
    else:
        raise ValueError(f"Unsupported model provider: {provider}")
    
    # Set up circuit breaker if enabled
    if use_circuit_breaker:
        model.setup_circuit_breaker(
            failure_threshold=circuit_failure_threshold,
            recovery_timeout=circuit_recovery_timeout,
            provider_name=provider
        )
    
    return model
