"""Abstract base class for sandbox backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from irondome.l3.models import Policy, SandboxResult


class SandboxBackend(ABC):
    """Abstract sandbox backend interface."""

    @abstractmethod
    def run(
        self,
        command: List[str],
        policy: Policy,
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> SandboxResult:
        """Execute a command under the given policy."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this backend is usable on the current system."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable backend name."""
        ...
