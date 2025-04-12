import os
from typing import Dict, Optional, Any, List
import anthropic
from .base import AIModel, CircuitBreakerError


class AnthropicModel(AIModel):
    """Anthropic API model implementation."""
    
    def __init__(self, api_key: Optional[str] = None, model_name: str = "claude-3-opus-20240229",
                use_circuit_breaker: bool = True, circuit_failure_threshold: int = 3,
                circuit_recovery_timeout: int = 60):
        """
        Initialize the Anthropic model.
        
        Args:
            api_key: API key for Anthropic (will use environment variable if not provided)
            model_name: Name of the model to use
            use_circuit_breaker: Whether to use circuit breaker for API calls
            circuit_failure_threshold: Number of failures before circuit breaker opens
            circuit_recovery_timeout: Seconds to wait before recovery attempt
        """
        super().__init__()
        self.api_key = api_key
        self.model_name = model_name
        self.client = None
        
        # Set up circuit breaker for API calls if enabled
        if use_circuit_breaker:
            self.setup_circuit_breaker(
                failure_threshold=circuit_failure_threshold,
                recovery_timeout=circuit_recovery_timeout,
                provider_name="anthropic"
            )
        
    def initialize(self):
        """Initialize the Anthropic API client."""
        self.api_key = self.api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("Anthropic API key not provided and not found in environment variables")
        
        self.client = anthropic.Anthropic(api_key=self.api_key)
        return True
    
    def _format_history_for_anthropic(self) -> List[Dict[str, str]]:
        """Format chat history for Anthropic's expected format."""
        anthropic_history = []
        
        for msg in self.history:
            role = "user" if msg["role"] in ["user", "human"] else "assistant"
            anthropic_history.append({"role": role, "content": msg["content"]})
            
        return anthropic_history
    
    def chat(self, prompt: str, system_prompt: Optional[str] = None, 
             temperature: float = 0.7) -> Dict[str, Any]:
        """Send a prompt to Anthropic and return the response."""
        if not self.client:
            self.initialize()
            
        # Add current message to history
        self.add_to_history("user", prompt)
        
        # Format messages for Anthropic
        messages = self._format_history_for_anthropic()
        
        # Make API call with system prompt if provided
        if system_prompt:
            response = self.client.messages.create(
                model=self.model_name,
                messages=messages,
                system=system_prompt,
                temperature=temperature,
                max_tokens=4096
            )
        else:
            response = self.client.messages.create(
                model=self.model_name,
                messages=messages,
                temperature=temperature,
                max_tokens=4096
            )
        
        # Extract the response text
        response_text = response.content[0].text
        
        # Add response to history
        self.add_to_history("assistant", response_text)
        
        return {
            "content": response_text,
            "model": self.model_name,
            "raw_response": response
        }
    
    def protected_chat(self, prompt: str, system_prompt: Optional[str] = None, 
                      temperature: float = 0.7) -> Dict[str, Any]:
        """
        Generate a response with circuit breaker protection.
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature
            
        Returns:
            Dictionary with model response
            
        Raises:
            CircuitBreakerError: If the circuit breaker is open
        """
        if hasattr(self, 'circuit_breaker'):
            # If circuit breaker is set up, use it to protect the call
            try:
                return self.circuit_breaker(self.chat)(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature
                )
            except CircuitBreakerError as e:
                # Log and re-raise the error
                raise e
        else:
            # No circuit breaker, just call directly
            return self.chat(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature
            ) 