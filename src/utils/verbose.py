"""
Verbose output helpers for Resurface CLI.

Prints LLM prompts/responses with colored, visually distinct headers.
Used by all LLM-calling components when --verbose is enabled.
"""

# ANSI color codes
CYAN = "\033[96m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
MAGENTA = "\033[95m"
DIM = "\033[2m"
RESET = "\033[0m"
BOLD = "\033[1m"

MAX_VERBOSE_CHARS = 3000


def _truncate(text: str, max_chars: int = MAX_VERBOSE_CHARS) -> str:
    """Truncate text with indicator if too long."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n{DIM}... [truncated — {len(text)} chars total]{RESET}"


def print_llm_prompt(prompt: str, label: str = ""):
    """Print an LLM prompt with a visually distinct header."""
    header = "LLM PROMPT"
    if label:
        header = f"LLM PROMPT ({label})"
    print(f"\n{CYAN}{BOLD}{'═' * 60}")
    print(f"  {header}")
    print(f"{'═' * 60}{RESET}")
    print(f"{CYAN}{_truncate(prompt)}{RESET}")
    print(f"{CYAN}{BOLD}{'─' * 60}{RESET}\n")


def print_llm_response(response: str, label: str = ""):
    """Print an LLM response with a visually distinct header."""
    header = "LLM RESPONSE"
    if label:
        header = f"LLM RESPONSE ({label})"
    print(f"\n{GREEN}{BOLD}{'═' * 60}")
    print(f"  {header}")
    print(f"{'═' * 60}{RESET}")
    print(f"{GREEN}{_truncate(response)}{RESET}")
    print(f"{GREEN}{BOLD}{'─' * 60}{RESET}\n")


def print_verbose_info(message: str):
    """Print a verbose informational message."""
    print(f"{MAGENTA}[verbose] {message}{RESET}")
