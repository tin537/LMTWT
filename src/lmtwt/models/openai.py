import os
from typing import Dict, Optional, Any, List
from openai import OpenAI
from .base import AIModel


class OpenAIModel(AIModel):
    """OpenAI API model implementation."""
    
    def __init__(self, api_key: Optional[str] = None, model_name: str = "gpt-4o"):
        super().__init__(api_key)
        self.model_name = model_name
        self.client = None
        
    def initialize(self):
        """Initialize the OpenAI API client."""
        self.api_key = self.api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key not provided and not found in environment variables")
        
        self.client = OpenAI(api_key=self.api_key)
        return True
    
    def _format_history_for_openai(self) -> List[Dict[str, str]]:
        """Format chat history for OpenAI's expected format."""
        openai_history = []
        
        for msg in self.history:
            role = "user" if msg["role"] in ["user", "human"] else "assistant"
            openai_history.append({"role": role, "content": msg["content"]})
            
        return openai_history
    
    def chat(self, prompt: str, system_prompt: Optional[str] = None, 
             temperature: float = 0.7) -> Dict[str, Any]:
        """Send a prompt to OpenAI and return the response."""
        if not self.client:
            self.initialize()
            
        # Add current message to history
        self.add_to_history("user", prompt)
        
        # Format messages for OpenAI
        messages = self._format_history_for_openai()
        
        # Add system message if provided
        if system_prompt:
            messages.insert(0, {"role": "system", "content": system_prompt})
        
        # Make API call
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            temperature=temperature,
            max_tokens=4096
        )
        
        # Extract the response text
        response_text = response.choices[0].message.content
        
        # Add response to history
        self.add_to_history("assistant", response_text)
        
        return {
            "content": response_text,
            "model": self.model_name,
            "raw_response": response
        } 