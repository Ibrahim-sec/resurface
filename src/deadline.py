"""
Deadline — simple wall-clock time limit for replay operations.
"""
import time


class Deadline:
    """Tracks wall-clock time and checks expiry."""

    def __init__(self, max_seconds=None):
        self.start = time.time()
        self.max_seconds = max_seconds

    @property
    def expired(self):
        if not self.max_seconds:
            return False
        return (time.time() - self.start) >= self.max_seconds

    @property
    def remaining(self):
        if not self.max_seconds:
            return float('inf')
        return max(0, self.max_seconds - (time.time() - self.start))

    @property
    def elapsed(self):
        return time.time() - self.start

    def check(self, label: str = ""):
        """Raise TimeoutError if deadline has expired."""
        if self.expired:
            msg = f"Deadline expired ({self.max_seconds:.0f}s)"
            if label:
                msg = f"{label}: {msg}"
            raise TimeoutError(msg)
