"""Async HuggingFace provider — wraps the sync transformers pipeline.

Local inference is CPU/GPU bound, not I/O bound, so we just defer to a thread
pool worker via ``asyncio.to_thread``. No real concurrency benefit — the value
here is a uniform async interface across providers so callers don't branch.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from .async_base import AsyncAIModel, ChatResponse, Chunk
from .conversation import Conversation

try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False


def _format_prompt(conversation: Conversation) -> str:
    """Render a conversation into the simple instruction template most models accept."""
    parts: list[str] = []
    if conversation.system:
        parts.append(f"<|system|>\n{conversation.system}")
    for msg in conversation.messages:
        tag = "<|user|>" if msg.role == "user" else "<|assistant|>"
        parts.append(f"{tag}\n{msg.content}")
    parts.append("<|assistant|>")
    return "\n".join(parts)


class AsyncHuggingFaceModel(AsyncAIModel):
    """HuggingFace local-model provider."""

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "meta-llama/Llama-3-8b-gguf",
    ) -> None:
        if not HF_AVAILABLE:
            raise ImportError(
                "transformers + torch are required. Install with `pip install lmtwt[local]`."
            )
        self.api_key = api_key
        self.model_name = model_name
        self._pipeline = None

    async def initialize(self) -> None:
        if self._pipeline is not None:
            return
        await asyncio.to_thread(self._load_sync)

    def _load_sync(self) -> None:
        device = (
            "cuda"
            if torch.cuda.is_available()
            else "mps"
            if hasattr(torch.backends, "mps") and torch.backends.mps.is_available()
            else "cpu"
        )
        tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            device_map=device,
            trust_remote_code=True,
        )
        self._pipeline = pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
            device_map=device,
        )

    async def chat(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> ChatResponse:
        await self.initialize()
        prompt = _format_prompt(conversation)

        def _run():
            assert self._pipeline is not None
            return self._pipeline(
                prompt,
                max_new_tokens=max_tokens,
                temperature=temperature,
                top_p=0.95,
                top_k=50,
                do_sample=temperature > 0.1,
                pad_token_id=self._pipeline.tokenizer.eos_token_id,
            )

        result = await asyncio.to_thread(_run)
        full_text = result[0]["generated_text"]
        # Extract just the assistant's reply after the final <|assistant|> tag.
        if "<|assistant|>" in full_text:
            content = full_text.rsplit("<|assistant|>", 1)[-1].strip()
        else:
            content = full_text.strip()
        return ChatResponse(content=content, model=self.model_name, raw=result)

    async def astream(
        self,
        conversation: Conversation,
        *,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> AsyncIterator[Chunk]:
        # True token streaming with TextIteratorStreamer is doable but adds
        # complexity. For now, run the full generation and emit one chunk.
        resp = await self.chat(
            conversation, temperature=temperature, max_tokens=max_tokens
        )
        yield Chunk(delta=resp.content, finish_reason="stop")
