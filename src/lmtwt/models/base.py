from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from ..utils.circuit_breaker import CircuitBreaker, CircuitBreakerError, with_fallback
import logging

# Set up logger
logger = logging.getLogger(__name__)

class AIModel(ABC):
    """Base abstract class for AI model interactions."""
    
    def __init__(self):
        """
        Initialize the base AI model class.
        """
        self.api_key = None
        self.model_name = None
        self.history = []
        
        # Initialize circuit breaker for this model
        self.circuit_breaker = None
    
    def setup_circuit_breaker(self, 
                            failure_threshold: int = 3, 
                            recovery_timeout: int = 120,
                            provider_name: str = "unknown"):
        """
        Set up circuit breaker for this model.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before trying again
            provider_name: Name of the provider for this model
        """
        name = f"{provider_name}_{self.model_name or 'default'}"
        self.circuit_breaker = CircuitBreaker(
            name=name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            logger=logger
        )
        logger.info(f"Circuit breaker initialized for {name}")
    
    @abstractmethod
    def initialize(self):
        """Initialize the model client and validate API access."""
        pass
    
    @abstractmethod
    def chat(self, prompt: str, system_prompt: Optional[str] = None, 
             temperature: float = 0.7) -> Dict[str, Any]:
        """Send a prompt to the model and return the response."""
        pass
    
    def protected_chat(self, prompt: str, system_prompt: Optional[str] = None,
                     temperature: float = 0.7) -> Dict[str, Any]:
        """
        Send a prompt to the model with circuit breaker protection.
        
        Args:
            prompt: The prompt to send
            system_prompt: Optional system prompt
            temperature: Temperature for generation
            
        Returns:
            Response from the model
            
        Raises:
            CircuitBreakerError: If circuit is open
        """
        if self.circuit_breaker is None:
            # No circuit breaker configured, use regular chat
            return self.chat(prompt, system_prompt, temperature)
        
        # Use circuit breaker to protect the call
        @self.circuit_breaker
        def _protected_call():
            return self.chat(prompt, system_prompt, temperature)
        
        return _protected_call()
    
    def add_to_history(self, role: str, content: str):
        """Add message to conversation history."""
        self.history.append({"role": role, "content": content})
    
    def clear_history(self):
        """Clear conversation history."""
        self.history = []
    
    def get_history(self) -> List[Dict[str, str]]:
        """Get current conversation history."""
        return self.history
    
    def get_circuit_state(self) -> Dict[str, Any]:
        """
        Get the current state of the circuit breaker.
        
        Returns:
            Dictionary with circuit state or None if no circuit breaker
        """
        if self.circuit_breaker:
            return self.circuit_breaker.get_state()
        return None 