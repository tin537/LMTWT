import os
from typing import Dict, Optional, Any, List
import anthropic
from .base import AIModel


class AnthropicModel(AIModel):
    """Anthropic API model implementation."""
    
    def __init__(self, api_key: Optional[str] = None, model_name: str = "claude-3-opus-20240229"):
        super().__init__(api_key)
        self.model_name = model_name
        self.client = None
        
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