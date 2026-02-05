"""
Unified LLM client for Resurface.

All LLM calls go through this module.
Uses LiteLLM for provider abstraction and instructor for structured output.
"""
from .client import (
    LLMClient,
    LLMError,
    RateLimitError,
    CreditExhaustedError,
    llm_call,
    llm_call_structured,
    get_client,
)

__all__ = [
    "LLMClient",
    "LLMError",
    "RateLimitError",
    "CreditExhaustedError",
    "llm_call",
    "llm_call_structured",
    "get_client",
]
