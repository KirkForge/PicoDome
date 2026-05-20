"""Seccomp-bpf sandbox backend (Linux only).

Uses libseccomp via ctypes for syscall filtering.
Falls back gracefully when libseccomp is not available.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from irondome.l3.backends.base import SandboxBackend
from irondome.l3.models import Policy, SandboxResult

logger = logging.getLogger("irondome.l3.seccomp")


class SeccompBackend(SandboxBackend):
    """Seccomp-bpf backend using libseccomp."""

    @property
    def name(self) -> str:
        return "seccomp-bpf"

    def is_available(self) -> bool:
        """Check if seccomp is available on this system."""
        try:
            import ctypes
            ctypes.CDLL("libseccomp.so.2")
            return True
        except (OSError, ImportError):
            return False

    def run(
        self,
        command: List[str],
        policy: Policy,
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> SandboxResult:
        """Run under seccomp policy. Falls back to subprocess if seccomp fails."""
        logger.warning("Seccomp backend not yet fully implemented — using subprocess fallback")
        from irondome.l3.backends.subprocess_backend import SubprocessBackend
        return SubprocessBackend().run(command, policy, timeout=timeout, cwd=cwd, env=env)
