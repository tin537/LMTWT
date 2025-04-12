import os
from typing import Dict, Optional, Any, List
import google.generativeai as genai
from .base import AIModel, CircuitBreakerError


class GeminiModel(AIModel):
    """Gemini AI model implementation."""
    
    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-2.0-flash",
                use_circuit_breaker: bool = True, circuit_failure_threshold: int = 3,
                circuit_recovery_timeout: int = 60):
        """
        Initialize the Gemini model.
        
        Args:
            api_key: API key for Gemini (will use environment variable if not provided)
            model_name: Name of the model to use
            use_circuit_breaker: Whether to use circuit breaker for API calls
            circuit_failure_threshold: Number of failures before circuit breaker opens
            circuit_recovery_timeout: Seconds to wait before recovery attempt
        """
        super().__init__()
        self.api_key = api_key
        self.model_name = model_name
        self.client = None
        self.model = None
        
        # Set up circuit breaker for API calls if enabled
        if use_circuit_breaker:
            self.setup_circuit_breaker(
                failure_threshold=circuit_failure_threshold,
                recovery_timeout=circuit_recovery_timeout,
                provider_name="gemini"
            )
        
    def initialize(self):
        """Initialize the Gemini API client."""
        self.api_key = self.api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API key not provided and not found in environment variables")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(self.model_name)
        return True
    
    def _format_history_for_gemini(self) -> List[Dict[str, str]]:
        """Format chat history for Gemini's expected format."""
        gemini_history = []
        
        for msg in self.history:
            role = "user" if msg["role"] in ["user", "human"] else "model"
            gemini_history.append({"role": role, "parts": [{"text": msg["content"]}]})
            
        return gemini_history
    
    def chat(self, prompt: str, system_prompt: Optional[str] = None, 
             temperature: float = 0.7) -> Dict[str, Any]:
        """Send a prompt to Gemini and return the response."""
        if not self.model:
            self.initialize()
            
        generation_config = {
            "temperature": temperature,
            "top_p": 0.95,
            "top_k": 0,
            "max_output_tokens": 8192,
        }
        
        # Apply system prompt if provided
        if system_prompt:
            # For Gemini, we need to prepend the system prompt to the first user message
            # or create a chat with explicit system instructions
            if not self.history:
                prompt = f"Instructions: {system_prompt}\n\nUser query: {prompt}"
        
        # Add current message to history
        self.add_to_history("user", prompt)
        
        # Get formatted history
        gemini_history = self._format_history_for_gemini()
        
        # Start a new chat if history exists, otherwise send a single prompt
        if len(gemini_history) > 1:
            chat = self.model.start_chat(history=gemini_history[:-1])
            response = chat.send_message(
                gemini_history[-1]["parts"][0]["text"],
                generation_config=generation_config
            )
        else:
            response = self.model.generate_content(
                prompt,
                generation_config=generation_config
            )
        
        # Extract the text response
        response_text = response.text
        
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