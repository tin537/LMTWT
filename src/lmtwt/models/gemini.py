import os
from typing import Dict, Optional, Any, List
import google.generativeai as genai
from .base import AIModel


class GeminiModel(AIModel):
    """Gemini AI model implementation."""
    
    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-2.0-flash"):
        super().__init__(api_key)
        self.model_name = model_name
        self.client = None
        self.model = None
        
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