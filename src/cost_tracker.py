"""
Cost Tracker — tracks LLM token usage and estimated cost per replay.

Global singleton that accumulates across calls within a replay session.
"""
import threading
from loguru import logger


# Pricing per million tokens (input, output) in USD
MODEL_PRICING = {
    # Anthropic
    "claude-sonnet-4-0": (3.0, 15.0),
    "claude-sonnet-4-20250514": (3.0, 15.0),
    "anthropic/claude-sonnet-4-20250514": (3.0, 15.0),
    "anthropic/claude-sonnet-4-0": (3.0, 15.0),
    # Groq free tier
    "groq/meta-llama/llama-4-scout-17b-16e-instruct": (0.0, 0.0),
    "groq/llama-3.3-70b-versatile": (0.0, 0.0),
    "meta-llama/llama-4-scout-17b-16e-instruct": (0.0, 0.0),
    "llama-3.3-70b-versatile": (0.0, 0.0),
    # Gemini
    "gemini/gemini-2.0-flash": (0.10, 0.40),
    "gemini-2.0-flash": (0.10, 0.40),
    "gemini/gemini-1.5-pro": (0.10, 0.40),
    "gemini-1.5-pro": (0.10, 0.40),
}

# Default pricing if model not found (conservative estimate)
DEFAULT_PRICING = (3.0, 15.0)

# Estimated tokens per browser-use agent step (for ChatAnthropic cost estimation)
BROWSER_STEP_INPUT_TOKENS = 2000
BROWSER_STEP_OUTPUT_TOKENS = 500


class CostTracker:
    """Tracks LLM token usage and estimated cost. Thread-safe singleton."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._data_lock = threading.Lock()
        self.reset()

    def reset(self):
        """Clear all accumulated data. Call between replays."""
        with self._data_lock:
            self.total_input_tokens = 0
            self.total_output_tokens = 0
            self.estimated_cost_usd = 0.0
            self.call_count = 0
            self.calls = []  # detailed log per call

    def record(self, model: str, input_tokens: int, output_tokens: int, label: str = ""):
        """Record a single LLM call's token usage."""
        pricing = MODEL_PRICING.get(model, DEFAULT_PRICING)
        cost = (input_tokens / 1_000_000) * pricing[0] + (output_tokens / 1_000_000) * pricing[1]

        with self._data_lock:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.estimated_cost_usd += cost
            self.call_count += 1
            self.calls.append({
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost,
                "label": label,
            })

        logger.debug(
            f"[CostTracker] {label}: {input_tokens}in/{output_tokens}out "
            f"= ${cost:.6f} (total: ${self.estimated_cost_usd:.4f})"
        )

    def record_browser_steps(self, steps: int, model: str = "claude-sonnet-4-0"):
        """Estimate cost for browser-use agent steps (ChatAnthropic)."""
        input_tokens = steps * BROWSER_STEP_INPUT_TOKENS
        output_tokens = steps * BROWSER_STEP_OUTPUT_TOKENS
        self.record(model, input_tokens, output_tokens, label=f"browser-use ({steps} steps)")

    def get_summary(self) -> dict:
        """Get accumulated cost summary."""
        with self._data_lock:
            return {
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "estimated_cost_usd": round(self.estimated_cost_usd, 6),
                "call_count": self.call_count,
            }

    def format_summary(self) -> str:
        """Human-readable cost summary string."""
        s = self.get_summary()
        return (
            f"💰 Cost: ${s['estimated_cost_usd']:.4f} | "
            f"Tokens: {s['total_input_tokens']:,} in / {s['total_output_tokens']:,} out | "
            f"LLM calls: {s['call_count']}"
        )


# Module-level convenience accessor
def get_cost_tracker() -> CostTracker:
    """Get the global CostTracker singleton."""
    return CostTracker()
