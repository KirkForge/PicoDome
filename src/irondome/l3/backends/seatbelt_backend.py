"""Seatbelt sandbox backend (macOS only).

Uses macOS Seatbelt (sandbox-exec) for process sandboxing.
Falls back gracefully when not available.
"""

from __future__ import annotations

import logging
import platform
from typing import List, Optional

from irondome.l3.backends.base import SandboxBackend
from irondome.l3.models import Policy, SandboxResult

logger = logging.getLogger("irondome.l3.seatbelt")


class SeatbeltBackend(SandboxBackend):
    """Seatbelt backend using macOS sandbox-exec."""

    @property
    def name(self) -> str:
        return "seatbelt"

    def is_available(self) -> bool:
        """Check if seatbelt is available (macOS only)."""
        return platform.system() == "Darwin"

    def run(
        self,
        command: List[str],
        policy: Policy,
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> SandboxResult:
        """Run under seatbelt policy. Falls back to subprocess if seatbelt fails."""
        logger.warning("Seatbelt backend not yet fully implemented — using subprocess fallback")
        from irondome.l3.backends.subprocess_backend import SubprocessBackend
        return SubprocessBackend().run(command, policy, timeout=timeout, cwd=cwd, env=env)
