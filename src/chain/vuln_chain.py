"""
Multi-Step Vulnerability Chain module.

Formalizes multi-step exploitation chains so each step is tracked with status,
evidence, and retry logic. On failure, the chain knows exactly where to resume.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import time
import json


class StepStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ChainStep:
    name: str  # e.g. "register_account", "login", "escalate_privileges", "verify_admin"
    description: str  # Human-readable: "Register a new user account with role=admin"
    status: StepStatus = StepStatus.PENDING
    evidence: str = ""  # What happened (response summary, error message, etc.)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 2

    @property
    def duration(self) -> float:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return 0.0

    @property
    def can_retry(self) -> bool:
        return self.retry_count < self.max_retries and self.status == StepStatus.FAILED

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "evidence": self.evidence,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChainStep":
        return cls(
            name=data["name"],
            description=data["description"],
            status=StepStatus(data.get("status", "pending")),
            evidence=data.get("evidence", ""),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            retry_count=data.get("retry_count", 0),
            max_retries=data.get("max_retries", 2),
        )


# ---------------------------------------------------------------------------
# Status icons
# ---------------------------------------------------------------------------

_STATUS_ICONS = {
    StepStatus.PENDING: "⏳",
    StepStatus.IN_PROGRESS: "🔄",
    StepStatus.SUCCESS: "✅",
    StepStatus.FAILED: "❌",
    StepStatus.SKIPPED: "⏭️",
}


class VulnChain:
    """
    Manages a multi-step vulnerability exploitation chain.

    Usage::

        chain = VulnChain("privilege_escalation", "http://target:3333")
        chain.add_step("register", "Register account with role=admin via API")
        chain.add_step("login", "Login with the registered credentials")
        chain.add_step("verify", "Navigate to admin panel to verify access")

        # Agent calls checkpoint() after each successful step
        chain.checkpoint("register", evidence="Created user test@evil.com, API returned role:admin")
        chain.checkpoint("login", evidence="Got JWT token: eyJ...")
        chain.fail_step("verify", error="403 Forbidden on /admin")

        # On retry, chain tells agent where to resume
        resume = chain.get_resume_info()
        # -> "Steps completed: register ✅, login ✅. Resume from: verify (failed: 403 Forbidden). Retry 1/2."
    """

    def __init__(self, vuln_type: str, target_url: str):
        self.vuln_type = vuln_type
        self.target_url = target_url
        self.steps: list[ChainStep] = []
        self.created_at = time.time()
        self.metadata: dict = {}  # Store arbitrary data (credentials, tokens, etc.)

    # ------------------------------------------------------------------
    # Step helpers
    # ------------------------------------------------------------------

    def _find_step(self, name: str) -> Optional[ChainStep]:
        for step in self.steps:
            if step.name == name:
                return step
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_step(self, name: str, description: str, max_retries: int = 2) -> ChainStep:
        """Add a step to the chain. Steps are executed in order."""
        step = ChainStep(name=name, description=description, max_retries=max_retries)
        self.steps.append(step)
        return step

    def checkpoint(self, step_name: str, evidence: str = "") -> bool:
        """Mark a step as successfully completed. Returns True if step found."""
        step = self._find_step(step_name)
        if step is None:
            return False
        step.status = StepStatus.SUCCESS
        step.evidence = evidence
        step.completed_at = time.time()
        if step.started_at is None:
            step.started_at = step.completed_at
        return True

    def fail_step(self, step_name: str, error: str = "") -> bool:
        """Mark a step as failed. Returns True if step found."""
        step = self._find_step(step_name)
        if step is None:
            return False
        step.status = StepStatus.FAILED
        step.evidence = error
        step.completed_at = time.time()
        if step.started_at is None:
            step.started_at = step.completed_at
        step.retry_count += 1
        return True

    def skip_step(self, step_name: str, reason: str = "") -> bool:
        """Skip a step (e.g., auth not needed). Returns True if step found."""
        step = self._find_step(step_name)
        if step is None:
            return False
        step.status = StepStatus.SKIPPED
        step.evidence = reason or "Skipped"
        step.completed_at = time.time()
        if step.started_at is None:
            step.started_at = step.completed_at
        return True

    def get_current_step(self) -> Optional[ChainStep]:
        """Get the next step that needs to be executed (first non-success/non-skipped step)."""
        for step in self.steps:
            if step.status not in (StepStatus.SUCCESS, StepStatus.SKIPPED):
                return step
        return None

    def get_resume_info(self) -> str:
        """Human-readable resume info for the agent prompt.

        Shows completed steps, current step, and what to do next.
        """
        if not self.steps:
            return "No steps defined in chain."

        parts: list[str] = []

        # Completed steps
        completed = [s for s in self.steps if s.status in (StepStatus.SUCCESS, StepStatus.SKIPPED)]
        if completed:
            labels = [f"{s.name} {_STATUS_ICONS[s.status]}" for s in completed]
            parts.append(f"Steps completed: {', '.join(labels)}")

        # Current step
        current = self.get_current_step()
        if current is None:
            parts.append("All steps done! Chain complete.")
        elif current.status == StepStatus.FAILED:
            retry_info = f"Retry {current.retry_count}/{current.max_retries}" if current.can_retry else "No retries left"
            parts.append(
                f"Resume from: {current.name} (failed: {current.evidence}). {retry_info}."
            )
        else:
            parts.append(f"Next step: {current.name} — {current.description}")

        # Remaining steps (after current)
        if current is not None:
            remaining = []
            found_current = False
            for s in self.steps:
                if s is current:
                    found_current = True
                    continue
                if found_current and s.status not in (StepStatus.SUCCESS, StepStatus.SKIPPED):
                    remaining.append(s.name)
            if remaining:
                parts.append(f"Then: {' → '.join(remaining)}")

        return " | ".join(parts)

    def is_complete(self) -> bool:
        """True if all steps are SUCCESS or SKIPPED."""
        if not self.steps:
            return False
        return all(s.status in (StepStatus.SUCCESS, StepStatus.SKIPPED) for s in self.steps)

    def last_successful_step(self) -> Optional[ChainStep]:
        """The most recent successfully completed step."""
        last: Optional[ChainStep] = None
        for step in self.steps:
            if step.status == StepStatus.SUCCESS:
                last = step
        return last

    def store(self, key: str, value: str) -> None:
        """Store metadata (credentials, tokens) that persists across retries."""
        self.metadata[key] = value

    def recall(self, key: str) -> Optional[str]:
        """Recall stored metadata."""
        return self.metadata.get(key)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize chain state for JSON storage."""
        return {
            "vuln_type": self.vuln_type,
            "target_url": self.target_url,
            "created_at": self.created_at,
            "metadata": self.metadata,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VulnChain":
        """Reconstruct chain from serialized dict (for retry across sessions)."""
        chain = cls(
            vuln_type=data["vuln_type"],
            target_url=data["target_url"],
        )
        chain.created_at = data.get("created_at", time.time())
        chain.metadata = data.get("metadata", {})
        for step_data in data.get("steps", []):
            chain.steps.append(ChainStep.from_dict(step_data))
        return chain

    # ------------------------------------------------------------------
    # Prompt / display helpers
    # ------------------------------------------------------------------

    def to_prompt_context(self) -> str:
        """Generate context for the agent's task prompt.

        Includes chain overview, completed steps with evidence, current step,
        and stored metadata.
        """
        lines: list[str] = []
        lines.append(f"=== Exploit Chain: {self.vuln_type} ===")
        lines.append(f"Target: {self.target_url}")
        lines.append(f"Progress: {self.summary}")
        lines.append(f"Visual:  {self.progress_bar}")
        lines.append("")

        # Completed steps with evidence
        for step in self.steps:
            icon = _STATUS_ICONS[step.status]
            line = f"  {icon} {step.name}: {step.description}"
            if step.evidence:
                line += f"\n       Evidence: {step.evidence}"
            if step.duration > 0:
                line += f" ({step.duration:.1f}s)"
            lines.append(line)

        # Current step instructions
        current = self.get_current_step()
        if current:
            lines.append("")
            lines.append(f">>> CURRENT TASK: {current.name}")
            lines.append(f"    {current.description}")
            if current.status == StepStatus.FAILED:
                lines.append(f"    Previous attempt failed: {current.evidence}")
                lines.append(
                    f"    Retry {current.retry_count}/{current.max_retries}"
                )

        # Stored metadata
        if self.metadata:
            lines.append("")
            lines.append("Stored context:")
            for k, v in self.metadata.items():
                lines.append(f"  {k}: {v}")

        return "\n".join(lines)

    @property
    def summary(self) -> str:
        """One-line summary: '3/4 steps complete, current: verify_admin (failed, retry 1/2)'"""
        if not self.steps:
            return "No steps defined"

        done = sum(
            1
            for s in self.steps
            if s.status in (StepStatus.SUCCESS, StepStatus.SKIPPED)
        )
        total = len(self.steps)

        current = self.get_current_step()
        if current is None:
            return f"{done}/{total} steps complete — chain finished!"

        status_part = current.status.value
        if current.status == StepStatus.FAILED:
            status_part = f"failed, retry {current.retry_count}/{current.max_retries}"

        return f"{done}/{total} steps complete, current: {current.name} ({status_part})"

    @property
    def progress_bar(self) -> str:
        """Visual: [✅ register] [✅ login] [❌ verify] [⏳ exploit]"""
        if not self.steps:
            return "(empty chain)"
        parts = [f"[{_STATUS_ICONS[s.status]} {s.name}]" for s in self.steps]
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Pre-built chain templates for common vulnerability types
# ---------------------------------------------------------------------------

CHAIN_TEMPLATES: dict[str, list[tuple[str, str]]] = {
    "privilege_escalation": [
        (
            "register",
            "Register a new user account (use make_request to POST /api/Users with role=admin)",
        ),
        ("login", "Login with the registered credentials to get a session/token"),
        (
            "verify_escalation",
            "Verify the account has admin privileges (check admin panel or user profile)",
        ),
    ],
    "sqli": [
        ("find_input", "Find a vulnerable input field (login form, search bar)"),
        ("inject_payload", "Submit SQL injection payload"),
        (
            "verify_sqli",
            "Verify SQL injection worked (auth bypass, data extraction, or error)",
        ),
    ],
    "xss_reflected": [
        (
            "find_input",
            "Find an input that reflects user data (search, URL params)",
        ),
        ("inject_payload", "Submit XSS payload into the input"),
        (
            "verify_xss",
            "Verify XSS executed (dialog appeared, payload rendered as HTML)",
        ),
    ],
    "xss_stored": [
        (
            "find_storage",
            "Find a form that stores user data (comments, profile, reviews)",
        ),
        ("inject_payload", "Submit XSS payload into the storage field"),
        ("trigger_stored", "Navigate to where stored data is displayed"),
        ("verify_xss", "Verify stored XSS executed"),
    ],
    "idor": [
        ("authenticate", "Login or get a session as a regular user"),
        ("find_endpoint", "Find an API endpoint with an ID parameter"),
        ("test_idor", "Access another user's resource by changing the ID"),
        ("verify_idor", "Verify you can read/modify another user's data"),
    ],
}


def create_chain_for_vuln(vuln_type: str, target_url: str) -> VulnChain:
    """Create a pre-built chain from templates.

    Falls back to a generic chain if vuln_type is unknown.
    """
    chain = VulnChain(vuln_type=vuln_type, target_url=target_url)

    template = CHAIN_TEMPLATES.get(vuln_type)
    if template:
        for name, description in template:
            chain.add_step(name, description)
    else:
        # Generic fallback for unknown vuln types
        chain.add_step("recon", f"Reconnoitre the target for {vuln_type} vulnerability")
        chain.add_step("exploit", f"Attempt to exploit {vuln_type}")
        chain.add_step("verify", f"Verify {vuln_type} exploitation was successful")

    return chain


# ---------------------------------------------------------------------------
# Controller tool factory
# ---------------------------------------------------------------------------


def create_chain_tools(controller: object, chain: VulnChain) -> None:
    """Register checkpoint and chain-status tools on a browser-use Controller.

    Parameters
    ----------
    controller:
        A browser-use ``Controller`` instance that supports the
        ``@controller.action(description=...)`` decorator.
    chain:
        The :class:`VulnChain` to bind to the registered actions.
    """

    @controller.action(  # type: ignore[attr-defined]
        description="Mark a step in the exploit chain as completed. Call after each successful step.",
    )
    def checkpoint(step_name: str, evidence: str = "") -> str:
        chain.checkpoint(step_name, evidence)
        current = chain.get_current_step()
        if current:
            return (
                f"✅ Step '{step_name}' completed. "
                f"Next: {current.name} — {current.description}"
            )
        return f"✅ Step '{step_name}' completed. All steps done! Chain complete."

    @controller.action(  # type: ignore[attr-defined]
        description="Check the current exploit chain status and see what step to do next.",
    )
    def chain_status() -> str:
        return chain.get_resume_info()
