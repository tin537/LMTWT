"""
Hugging Face model integration for local models.
"""
import os
import logging
from typing import Dict, Optional, Any, List, Union

from .base import AIModel, CircuitBreakerError
from ..utils.logger import setup_logger

# Try to import the required libraries, and gracefully handle if not installed
try:
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
    HUGGINGFACE_AVAILABLE = True
except ImportError:
    HUGGINGFACE_AVAILABLE = False

# Set up logger
logger = setup_logger()

class HuggingFaceModel(AIModel):
    """Hugging Face model implementation for local models."""
    
    def __init__(self, 
                 api_key: Optional[str] = None, 
                 model_name: Optional[str] = None,
                 use_circuit_breaker: bool = True,
                 circuit_failure_threshold: int = 3,
                 circuit_recovery_timeout: int = 60):
        """
        Initialize the Hugging Face model.
        
        Args:
            api_key: Hugging Face API key (for model hub access)
            model_name: Model name (default: "meta-llama/Llama-3-8b-gguf")
            use_circuit_breaker: Whether to use circuit breaker
            circuit_failure_threshold: Number of failures before circuit opens
            circuit_recovery_timeout: Seconds to wait before recovery
        """
        super().__init__()
        
        # Check if HuggingFace libraries are available
        if not HUGGINGFACE_AVAILABLE:
            raise ImportError("HuggingFace transformers library is not installed. Please install with 'pip install transformers torch'")
        
        # Set API key from env or param
        self.api_key = api_key or os.getenv("HUGGINGFACE_API_KEY")
        self.model_name = model_name or "meta-llama/Llama-3-8b-gguf"  # Default model
        
        # Set up the model pipeline
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        
        # Set up circuit breaker for API calls if enabled
        if use_circuit_breaker:
            self.setup_circuit_breaker(
                failure_threshold=circuit_failure_threshold,
                recovery_timeout=circuit_recovery_timeout,
                provider_name="huggingface"
            )
    
    def _load_model(self):
        """Load the model and tokenizer on demand."""
        if self.model is None or self.tokenizer is None:
            logger.info(f"Loading HuggingFace model: {self.model_name}")
            
            # Check for GPU availability
            device = "cuda" if torch.cuda.is_available() else "mps" if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available() else "cpu"
            logger.info(f"Using device: {device}")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            
            # Load model with appropriate quantization based on device and available memory
            if device == "cuda":
                # If CUDA available, use 4-bit quantization for large models
                try:
                    import bitsandbytes as bnb
                    from transformers import BitsAndBytesConfig
                    
                    # Check if model is large (>7B parameters)
                    is_large_model = any(size in self.model_name.lower() for size in ['70b', '13b', '8b'])
                    
                    if is_large_model:
                        logger.info("Loading large model with 4-bit quantization")
                        quantization_config = BitsAndBytesConfig(
                            load_in_4bit=True,
                            bnb_4bit_compute_dtype=torch.float16,
                            bnb_4bit_quant_type="nf4",
                            bnb_4bit_use_double_quant=True
                        )
                        self.model = AutoModelForCausalLM.from_pretrained(
                            self.model_name,
                            device_map="auto",
                            trust_remote_code=True,
                            quantization_config=quantization_config
                        )
                    else:
                        # For smaller models, load normally
                        self.model = AutoModelForCausalLM.from_pretrained(
                            self.model_name,
                            device_map="auto",
                            trust_remote_code=True
                        )
                except (ImportError, Exception) as e:
                    logger.warning(f"Quantization not available or error: {str(e)}. Loading model normally.")
                    self.model = AutoModelForCausalLM.from_pretrained(
                        self.model_name,
                        device_map="auto",
                        trust_remote_code=True
                    )
            else:
                # For CPU or MPS, load normally
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_name,
                    device_map=device,
                    trust_remote_code=True
                )
            
            # Create the pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                device_map=device
            )
            
            logger.info(f"Model loaded successfully")
    
    def chat(self, prompt: str, system_prompt: Optional[str] = None, 
             temperature: float = 0.7) -> Dict[str, Any]:
        """
        Generate a response using the local model.
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature (higher = more random)
            
        Returns:
            Dictionary with model response
        """
        try:
            # Load model on demand
            self._load_model()
            
            # Format the input based on model type
            if system_prompt:
                # Format with system prompt for instruction-tuned models
                formatted_prompt = f"<|system|>\n{system_prompt}\n<|user|>\n{prompt}\n<|assistant|>"
            else:
                # Simple prompt for non-instruction models
                formatted_prompt = f"USER: {prompt}\nASSISTANT:"
            
            # Generate the response
            generation_args = {
                "max_new_tokens": 1024,
                "temperature": temperature,
                "top_p": 0.95,
                "top_k": 50,
                "do_sample": temperature > 0.1,
                "pad_token_id": self.tokenizer.eos_token_id
            }
            
            result = self.pipeline(
                formatted_prompt,
                **generation_args
            )[0]['generated_text']
            
            # Extract just the assistant's response
            response_text = result.split("<|assistant|>")[-1] if "<|assistant|>" in result else result.split("ASSISTANT:")[-1]
            
            return {
                "content": response_text.strip(),
                "role": "assistant",
                "provider": "huggingface",
                "model": self.model_name
            }
        except Exception as e:
            logger.error(f"Error generating response: {str(e)}")
            raise e
    
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