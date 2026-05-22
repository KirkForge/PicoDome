"""L3 Execution Sandbox — engine.

The `deterministic` parameter controls whether run_id, timestamp, and
duration_ms are included in the output. When deterministic=True (the default
for reproducible output), these fields are omitted. When deterministic=False,
they are filled in with real values.
"""

from __future__ import annotations

import logging
import platform
from typing import List, Optional

from irondome.l3.backends.base import SandboxBackend
from irondome.l3.backends.subprocess_backend import SubprocessBackend
from irondome.l3.models import Policy, SandboxResult
from irondome.l3.policy import default_policy
from irondome.models import _generate_run_id, _generate_timestamp

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
    deterministic: bool = True,
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
        deterministic: If True, omit run_id, timestamp, duration_ms
            for reproducible output. If False, fill with real values.

    Returns:
        SandboxResult with events and overall verdict.
    """
    if policy is None:
        policy = default_policy()

    be = backend or get_backend()
    result = be.run(command, policy, timeout=timeout, cwd=cwd, env=env)

    # If deterministic, strip non-deterministic fields by rebuilding
    if deterministic:
        result = SandboxResult(
            command=result.command,
            overall_verdict=result.overall_verdict,
            exit_code=result.exit_code,
            events=result.events,
            policy_name=result.policy_name,
            stdout=result.stdout,
            stderr=result.stderr,
        )
    else:
        # Fill in non-deterministic fields
        result = SandboxResult(
            run_id=_generate_run_id(),
            timestamp=_generate_timestamp(),
            command=result.command,
            overall_verdict=result.overall_verdict,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            events=result.events,
            policy_name=result.policy_name,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    logger.info(
        "L3 sandbox %s: verdict=%s exit=%d duration=%dms events=%d",
        result.run_id or "(deterministic)",
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
        deterministic: bool = True,
    ) -> SandboxResult:
        return sandbox_run(
            command,
            policy=policy,
            timeout=timeout,
            cwd=cwd,
            env=env,
            backend=self._backend,
            deterministic=deterministic,
        )