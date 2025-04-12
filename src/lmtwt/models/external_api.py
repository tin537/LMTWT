import os
import json
import requests
from typing import Dict, Optional, Any, List
from .base import AIModel, CircuitBreakerError


class ExternalAPIModel(AIModel):
    """External API model implementation for interacting with custom API endpoints."""
    
    def __init__(self, api_config: Dict[str, Any], model_name: Optional[str] = None,
                use_circuit_breaker: bool = True, circuit_failure_threshold: int = 3,
                circuit_recovery_timeout: int = 60):
        """
        Initialize the External API model.
        
        Args:
            api_config: Dictionary containing API configuration
            model_name: Optional model name to use (if specified in the configuration)
            use_circuit_breaker: Whether to use circuit breaker for API calls
            circuit_failure_threshold: Number of failures before circuit breaker opens
            circuit_recovery_timeout: Seconds to wait before recovery attempt
        """
        super().__init__()
        
        self.api_config = api_config
        self.model_name = model_name or api_config.get("model", "external-api")
        self.endpoint = api_config.get("endpoint", "")
        self.headers = api_config.get("headers", {})
        self.method = api_config.get("method", "POST").upper()
        self.params = api_config.get("params", {})
        self.client = None
        
        # Set up circuit breaker for API calls if enabled
        if use_circuit_breaker:
            self.setup_circuit_breaker(
                failure_threshold=circuit_failure_threshold,
                recovery_timeout=circuit_recovery_timeout,
                provider_name="external-api"
            )
        
    def initialize(self):
        """Initialize the external API client (validation only)."""
        if not self.endpoint:
            raise ValueError("API endpoint not provided in the configuration")
            
        # Test the connection if needed
        return True
    
    def chat(self, prompt: str, system_prompt: Optional[str] = None, 
             temperature: float = 0.7) -> Dict[str, Any]:
        """
        Send a prompt to the external API and return the response.
        
        Args:
            prompt: The prompt to send
            system_prompt: Optional system prompt/instructions
            temperature: Temperature for generation
            
        Returns:
            Response from the API formatted to match our standard interface
        """
        # Add current message to history
        self.add_to_history("user", prompt)
        
        # Prepare the request payload based on the API configuration
        payload = self.api_config.get("payload_template", {}).copy()
        
        # Override with specific parameters
        payload["prompt"] = prompt
        
        # Include system prompt if provided and supported by the target API
        if system_prompt and self.api_config.get("supports_system_prompt", False):
            if "system_key" in self.api_config:
                payload[self.api_config["system_key"]] = system_prompt
            else:
                # Default behavior: prepend to the prompt
                payload["prompt"] = f"{system_prompt}\n\n{prompt}"
        
        # Add temperature if specified and supported
        if self.api_config.get("supports_temperature", False):
            temp_key = self.api_config.get("temperature_key", "temperature")
            payload[temp_key] = temperature
        
        # Add model name if specified in config or constructor
        if "model_key" in self.api_config:
            model_key = self.api_config["model_key"]
            payload[model_key] = self.model_name or self.api_config.get("model", "")
        
        # Make the API request
        try:
            if self.method == "POST":
                response = requests.post(
                    self.endpoint,
                    headers=self.headers,
                    json=payload,
                    params=self.params
                )
            else:  # GET
                response = requests.get(
                    self.endpoint,
                    headers=self.headers,
                    params={**self.params, **payload}  # Merge params with payload for GET
                )
            
            response.raise_for_status()  # Raise exception for HTTP errors
            
            # Parse the response
            response_data = response.json()
            
            # Extract the text response based on the response_path in config
            if "response_path" in self.api_config:
                path_parts = self.api_config["response_path"].split(".")
                response_text = response_data
                for part in path_parts:
                    if isinstance(response_text, dict) and part in response_text:
                        response_text = response_text[part]
                    else:
                        response_text = f"Error: Unable to extract response from path {self.api_config['response_path']}"
                        break
            else:
                # If no path specified, assume the entire response is the text or provide raw JSON
                response_text = response_data if isinstance(response_data, str) else json.dumps(response_data)
                
        except Exception as e:
            response_text = f"Error communicating with external API: {str(e)}"
            response_data = {"error": str(e)}
        
        # Add response to history
        self.add_to_history("assistant", response_text)
        
        return {
            "content": response_text,
            "model": self.model_name,
            "raw_response": response_data
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
        
    def validate_config(self) -> bool:
        """
        Validate that the API configuration has the required fields.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        required_fields = ["endpoint"]
        
        for field in required_fields:
            if field not in self.api_config:
                return False
                
        return True 