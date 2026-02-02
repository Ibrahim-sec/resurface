"""
Payload Library — loads curated payloads from data/payloads/*.txt files.
Provides per-vuln-type payload lists for the browser agent.
"""
import os
from pathlib import Path
from typing import Optional
from loguru import logger


class PayloadLibrary:
    """Loads and serves curated payloads by vulnerability type."""

    # Map vuln types to payload files
    VULN_TO_FILE = {
        "xss_reflected": "xss.txt",
        "xss_stored": "xss.txt",
        "xss_dom": "xss.txt",
        "sqli": "sqli.txt",
        "path_traversal": "path_traversal.txt",
        "idor": "idor.txt",
        "open_redirect": "open_redirect.txt",
    }

    def __init__(self, payloads_dir: str = None):
        if payloads_dir is None:
            # Default: data/payloads/ relative to project root
            payloads_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "data", "payloads"
            )
        self.payloads_dir = Path(payloads_dir)
        self._cache = {}

    def _load_file(self, filename: str) -> list[str]:
        """Load payloads from a file, stripping comments and blank lines."""
        if filename in self._cache:
            return self._cache[filename]

        filepath = self.payloads_dir / filename
        if not filepath.exists():
            logger.warning(f"  Payload file not found: {filepath}")
            return []

        payloads = []
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.append(line)

        self._cache[filename] = payloads
        logger.debug(f"  Loaded {len(payloads)} payloads from {filename}")
        return payloads

    def get_payloads(self, vuln_type: str, limit: int = 10) -> list[str]:
        """Get top N payloads for a vulnerability type."""
        filename = self.VULN_TO_FILE.get(vuln_type)
        if not filename:
            return []
        payloads = self._load_file(filename)
        return payloads[:limit]

    def get_all_payloads(self, vuln_type: str) -> list[str]:
        """Get ALL payloads for a vulnerability type."""
        filename = self.VULN_TO_FILE.get(vuln_type)
        if not filename:
            return []
        return self._load_file(filename)

    def format_for_prompt(self, vuln_type: str, limit: int = 8) -> str:
        """Format payloads as a numbered list for injection into agent prompts."""
        payloads = self.get_payloads(vuln_type, limit)
        if not payloads:
            return ""
        lines = [f"## Curated Payloads (use these, don't invent your own):"]
        for i, p in enumerate(payloads, 1):
            lines.append(f"  {i}. {p}")
        lines.append(f"  (Total available: {len(self.get_all_payloads(vuln_type))} — ask for more with get_payloads tool)")
        return "\n".join(lines)

    def has_payloads(self, vuln_type: str) -> bool:
        """Check if we have payloads for a given vuln type."""
        filename = self.VULN_TO_FILE.get(vuln_type)
        if not filename:
            return False
        return (self.payloads_dir / filename).exists()
