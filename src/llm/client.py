"""
Unified LLM Client for Resurface

Uses LiteLLM for provider abstraction + instructor for structured output.
Includes tenacity for automatic retries with exponential backoff.

Supported providers:
- groq: groq/meta-llama/llama-4-scout-17b-16e-instruct, groq/llama-3.3-70b-versatile
- gemini: gemini/gemini-2.0-flash, gemini/gemini-1.5-pro
- anthropic: anthropic/claude-sonnet-4-20250514
- openai: gpt-4o, gpt-4o-mini

Usage:
    from src.llm import LLMClient
    
    client = LLMClient(provider="groq", model="meta-llama/llama-4-scout-17b-16e-instruct")
    
    # Simple text response
    response = client.call("What is 2+2?")
    
    # Structured output with Pydantic
    from src.models import LLMParsedReport
    result = client.call_structured(prompt, response_model=LLMParsedReport)
"""
import json
import os
from typing import Optional, Type, TypeVar
from loguru import logger
from pydantic import BaseModel

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

try:
    import litellm
    from litellm import completion
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False
    logger.warning("LiteLLM not installed. Run: pip install litellm")

from src.cost_tracker import get_cost_tracker

try:
    import instructor
    from instructor import Mode
    INSTRUCTOR_AVAILABLE = True
except ImportError:
    INSTRUCTOR_AVAILABLE = False
    Mode = None
    logger.warning("instructor not installed. Run: pip install instructor")


T = TypeVar("T", bound=BaseModel)


class LLMError(Exception):
    """Base exception for LLM errors"""
    pass


class RateLimitError(LLMError):
    """Rate limit exceeded"""
    pass


class CreditExhaustedError(LLMError):
    """API credits exhausted"""
    pass


class LLMClient:
    """
    Unified LLM client with:
    - LiteLLM for provider abstraction
    - instructor for structured Pydantic output
    - tenacity for automatic retries
    """
    
    PROVIDER_PREFIXES = {
        "groq": "groq/",
        "gemini": "gemini/",
        "anthropic": "anthropic/",
        "openai": "",
        "claude": "anthropic/",
        "openrouter": "openrouter/",
    }
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "meta-llama/llama-4-scout-17b-16e-instruct",
        provider: str = "groq",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        verbose: bool = False,
    ):
        if not LITELLM_AVAILABLE:
            raise ImportError("LiteLLM is required. Run: pip install litellm")
        
        self.provider = provider.lower()
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.verbose = verbose
        
        if api_key:
            self._set_api_key(api_key)
        
        self.full_model = self._build_model_name(model, self.provider)
        
        # Initialize instructor client for structured output
        # Groq's tool calling is broken, use JSON mode instead
        # OpenRouter models vary — use JSON mode for safety (works with all models)
        if INSTRUCTOR_AVAILABLE:
            if self.provider in ("groq", "openrouter"):
                self._instructor_client = instructor.from_litellm(
                    litellm.completion,
                    mode=Mode.JSON
                )
            else:
                self._instructor_client = instructor.from_litellm(litellm.completion)
            self._instructor_mode = Mode.JSON if self.provider in ("groq", "openrouter") else Mode.TOOLS
        else:
            self._instructor_client = None
            self._instructor_mode = None
        
        if not verbose:
            litellm.suppress_debug_info = True
    
    def _set_api_key(self, api_key: str):
        """Set API key in environment for the provider."""
        env_vars = {
            "groq": "GROQ_API_KEY",
            "gemini": "GEMINI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "claude": "ANTHROPIC_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
        }
        env_var = env_vars.get(self.provider, "OPENAI_API_KEY")
        os.environ[env_var] = api_key
    
    def _build_model_name(self, model: str, provider: str) -> str:
        """Build full model name with provider prefix for LiteLLM.
        
        OpenRouter format: openrouter/provider/model (e.g. openrouter/moonshotai/kimi-k2.5)
        If model already starts with 'openrouter/', use as-is.
        """
        prefix = self.PROVIDER_PREFIXES.get(provider, "")
        
        # Already has the correct prefix
        if model.startswith(prefix) and prefix:
            return model
        
        # For openrouter, model should be like "moonshotai/kimi-k2.5"
        # which becomes "openrouter/moonshotai/kimi-k2.5"
        if provider == "openrouter":
            if model.startswith("openrouter/"):
                return model
            return f"openrouter/{model}"
        
        if "/" in model and not any(model.startswith(p) for p in self.PROVIDER_PREFIXES.values() if p):
            return f"{prefix}{model}"
        
        return f"{prefix}{model}"
    
    def _classify_error(self, e: Exception) -> Exception:
        """Classify exception for retry logic."""
        error_str = str(e).lower()
        
        if "rate" in error_str or "429" in error_str or "quota" in error_str:
            return RateLimitError(str(e))
        
        if "credit" in error_str or "balance" in error_str:
            return CreditExhaustedError(str(e))
        
        return LLMError(str(e))
    
    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=4, max=60),
        retry=retry_if_exception_type(RateLimitError),
        before_sleep=before_sleep_log(logger, "WARNING"),
        reraise=True,
    )
    def call(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_response: bool = False,
        label: str = "LLM",
    ) -> Optional[str]:
        """
        Call the LLM with automatic retries on rate limit.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            json_response: Request JSON-formatted response
            label: Label for logging
        
        Returns:
            Response text, or None on non-retryable failure
        """
        if self.verbose:
            logger.debug(f"[{label}] Prompt ({len(prompt)} chars)")
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        kwargs = {
            "model": self.full_model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        
        if json_response and self.provider in ("groq", "openai", "openrouter"):
            kwargs["response_format"] = {"type": "json_object"}
        
        try:
            response = completion(**kwargs)
            content = response.choices[0].message.content
            
            # Track cost via usage metadata
            try:
                usage = getattr(response, 'usage', None)
                if usage:
                    in_tok = getattr(usage, 'prompt_tokens', 0) or 0
                    out_tok = getattr(usage, 'completion_tokens', 0) or 0
                    get_cost_tracker().record(self.full_model, in_tok, out_tok, label=label)
            except Exception:
                pass
            
            if self.verbose:
                logger.debug(f"[{label}] Response ({len(content)} chars)")
            
            return content
            
        except Exception as e:
            classified = self._classify_error(e)
            
            if isinstance(classified, CreditExhaustedError):
                logger.error(f"[{label}] API credits exhausted: {e}")
                return None
            
            if isinstance(classified, RateLimitError):
                raise classified  # Let tenacity retry
            
            logger.error(f"[{label}] LLM call failed: {e}")
            return None
    
    def call_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        label: str = "LLM",
    ) -> Optional[dict]:
        """
        Call LLM and parse response as JSON.
        
        Returns:
            Parsed JSON dict, or None on failure
        """
        response = self.call(
            prompt=prompt,
            system_prompt=system_prompt,
            json_response=True,
            label=label,
        )
        
        if not response:
            return None
        
        try:
            text = response.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]
            
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"[{label}] Failed to parse JSON: {e}")
            return None
    
    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=4, max=60),
        retry=retry_if_exception_type(RateLimitError),
        before_sleep=before_sleep_log(logger, "WARNING"),
        reraise=True,
    )
    def call_structured(
        self,
        prompt: str,
        response_model: Type[T],
        system_prompt: Optional[str] = None,
        label: str = "LLM",
    ) -> Optional[T]:
        """
        Call LLM with instructor for guaranteed Pydantic structured output.
        
        This is the recommended method for any LLM call that expects structured data.
        instructor handles retries on validation failure internally.
        
        Args:
            prompt: User prompt
            response_model: Pydantic model class for the response
            system_prompt: Optional system prompt
            label: Label for logging
        
        Returns:
            Validated Pydantic model instance, or None on failure
        """
        if not INSTRUCTOR_AVAILABLE or not self._instructor_client:
            logger.warning(f"[{label}] instructor not available, falling back to call_json")
            result = self.call_json(prompt, system_prompt, label)
            if result:
                try:
                    return response_model.model_validate(result)
                except Exception as e:
                    logger.error(f"[{label}] Pydantic validation failed: {e}")
                    return None
            return None
        
        if self.verbose:
            logger.debug(f"[{label}] Structured call for {response_model.__name__}")
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        try:
            result = self._instructor_client.chat.completions.create(
                model=self.full_model,
                response_model=response_model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            
            # Track cost — instructor attaches _raw_response on the model
            try:
                raw = getattr(result, '_raw_response', None)
                if raw:
                    usage = getattr(raw, 'usage', None)
                    if usage:
                        in_tok = getattr(usage, 'prompt_tokens', 0) or 0
                        out_tok = getattr(usage, 'completion_tokens', 0) or 0
                        get_cost_tracker().record(self.full_model, in_tok, out_tok, label=label)
            except Exception:
                pass
            
            if self.verbose:
                logger.debug(f"[{label}] Got valid {response_model.__name__}")
            
            return result
            
        except Exception as e:
            classified = self._classify_error(e)
            
            if isinstance(classified, CreditExhaustedError):
                logger.error(f"[{label}] API credits exhausted: {e}")
                return None
            
            if isinstance(classified, RateLimitError):
                raise classified
            
            logger.error(f"[{label}] Structured call failed: {e}")
            return None


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

_default_client: Optional[LLMClient] = None


def get_client(
    api_key: Optional[str] = None,
    model: str = "meta-llama/llama-4-scout-17b-16e-instruct",
    provider: str = "groq",
    **kwargs
) -> LLMClient:
    """Get or create the default LLM client."""
    global _default_client
    
    if _default_client is None or api_key is not None:
        _default_client = LLMClient(
            api_key=api_key,
            model=model,
            provider=provider,
            **kwargs
        )
    
    return _default_client


def llm_call(
    prompt: str,
    system_prompt: Optional[str] = None,
    json_response: bool = False,
    api_key: Optional[str] = None,
    model: str = "meta-llama/llama-4-scout-17b-16e-instruct",
    provider: str = "groq",
    temperature: float = 0.1,
    max_tokens: int = 4096,
    label: str = "LLM",
    verbose: bool = False,
) -> Optional[str]:
    """Convenience function for one-off LLM calls."""
    client = LLMClient(
        api_key=api_key,
        model=model,
        provider=provider,
        temperature=temperature,
        max_tokens=max_tokens,
        verbose=verbose,
    )
    
    return client.call(
        prompt=prompt,
        system_prompt=system_prompt,
        json_response=json_response,
        label=label,
    )


def llm_call_structured(
    prompt: str,
    response_model: Type[T],
    system_prompt: Optional[str] = None,
    api_key: Optional[str] = None,
    model: str = "meta-llama/llama-4-scout-17b-16e-instruct",
    provider: str = "groq",
    temperature: float = 0.1,
    max_tokens: int = 4096,
    label: str = "LLM",
    verbose: bool = False,
) -> Optional[T]:
    """Convenience function for structured LLM calls with Pydantic models."""
    client = LLMClient(
        api_key=api_key,
        model=model,
        provider=provider,
        temperature=temperature,
        max_tokens=max_tokens,
        verbose=verbose,
    )
    
    return client.call_structured(
        prompt=prompt,
        response_model=response_model,
        system_prompt=system_prompt,
        label=label,
    )
