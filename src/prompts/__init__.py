"""
Prompt templates for Resurface LLM calls.

All prompts are stored as markdown files for easy editing and version control.
"""
from pathlib import Path
from functools import lru_cache

PROMPTS_DIR = Path(__file__).parent


@lru_cache(maxsize=32)
def load_prompt(name: str) -> str:
    """
    Load a prompt template from file.
    
    Args:
        name: Prompt name (without extension), e.g., "parse_report"
              Can include subdirectory: "playbooks/xss_reflected"
    
    Returns:
        Prompt template as string
    """
    path = PROMPTS_DIR / f"{name}.md"
    if not path.exists():
        raise FileNotFoundError(f"Prompt not found: {path}")
    return path.read_text()


def get_playbook(vuln_type: str) -> str:
    """Get the playbook for a specific vulnerability type."""
    try:
        return load_prompt(f"playbooks/{vuln_type}")
    except FileNotFoundError:
        return load_prompt("playbooks/generic")


def format_prompt(name: str, **kwargs) -> str:
    """Load and format a prompt template with variables."""
    template = load_prompt(name)
    return template.format(**kwargs)
