"""L3 Execution Sandbox — engine."""

from __future__ import annotations

import logging
import platform
from typing import List, Optional

from irondome.l3.backends.base import SandboxBackend
from irondome.l3.backends.subprocess_backend import SubprocessBackend
from irondome.l3.models import Policy, SandboxResult
from irondome.l3.policy import default_policy

logger = logging.getLogger("irondome.l3.engine")


def _detect_backend() -> SandboxBackend:
    """Auto-detect the best available sandbox backend."""
    system = platform.system()

    if system == "Linux":
        try:
            from irondome.l3.backends.seccomp_backend import SeccompBackend
            backend = SeccompBackend()
            if backend.is_available():
                logger.info("Using seccomp-bpf backend (Linux)")
                return backend
        except ImportError:
            pass
        except Exception:
            logger.debug("Seccomp backend unavailable", exc_info=True)

    elif system == "Darwin":
        try:
            from irondome.l3.backends.seatbelt_backend import SeatbeltBackend
            backend = SeatbeltBackend()
            if backend.is_available():
                logger.info("Using seatbelt backend (macOS)")
                return backend
        except ImportError:
            pass
        except Exception:
            logger.debug("Seatbelt backend unavailable", exc_info=True)

    logger.info("Using subprocess backend (fallback)")
    return SubprocessBackend()


_default_backend: Optional[SandboxBackend] = None


def get_backend() -> SandboxBackend:
    """Get the default sandbox backend (lazy init)."""
    global _default_backend
    if _default_backend is None:
        _default_backend = _detect_backend()
    return _default_backend


def set_backend(backend: SandboxBackend) -> None:
    """Override the default backend."""
    global _default_backend
    _default_backend = backend


def sandbox_run(
    command: List[str],
    policy: Optional[Policy] = None,
    timeout: Optional[float] = None,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    backend: Optional[SandboxBackend] = None,
) -> SandboxResult:
    """
    Run a command under sandbox policy.

    Args:
        command: Command and arguments to execute.
        policy: Sandbox policy (None = default deny-by-default).
        timeout: Wall-time limit in seconds.
        cwd: Working directory.
        env: Environment variables.
        backend: Override backend (None = auto-detect).

    Returns:
        SandboxResult with events and overall verdict.
    """
    if policy is None:
        policy = default_policy()

    be = backend or get_backend()
    result = be.run(command, policy, timeout=timeout, cwd=cwd, env=env)

    logger.info(
        "L3 sandbox %s: verdict=%s exit=%d duration=%dms events=%d",
        result.run_id,
        result.overall_verdict.value,
        result.exit_code,
        result.duration_ms,
        len(result.events),
    )

    return result


class SandboxEngine:
    """High-level sandbox engine interface."""

    def __init__(self, backend: Optional[SandboxBackend] = None):
        self._backend = backend

    @property
    def backend(self) -> SandboxBackend:
        if self._backend is None:
            self._backend = get_backend()
        return self._backend

    def run(
        self,
        command: List[str],
        policy: Optional[Policy] = None,
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> SandboxResult:
        return sandbox_run(
            command,
            policy=policy,
            timeout=timeout,
            cwd=cwd,
            env=env,
            backend=self._backend,
        )
