# =============================================================================
# PicoDome — Multi-stage Dockerfile
# =============================================================================
# Produces a minimal runtime image with PicoDome installed.
#
# Supports both CLI and daemon modes:
#   CLI:     picodome sandbox <command>
#   Daemon:  picodome daemon --host 0.0.0.0 --port 8443
#   gRPC:    picodome daemon --transport grpc
#
# For full seccomp-bpf kernel sandboxing, the runtime image includes
# libseccomp2. Without it, PicoDome falls back to the subprocess
# backend (observational only — not suitable for enterprise mode).
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1 — Builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies including libseccomp-dev for seccomp backend
RUN apt-get update && \
    apt-get install -y --no-install-recommends libseccomp-dev && \
    rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir --upgrade pip build wheel

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

# Build wheel
RUN python -m build --wheel --no-isolation

# ---------------------------------------------------------------------------
# Stage 2 — Runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/KirkForge/PicoDome"
LABEL org.opencontainers.image.title="PicoDome"
LABEL org.opencontainers.image.version="0.5.0"
LABEL org.opencontainers.image.description="Deterministic runtime sandbox and behavioral analysis engine for supply-chain security"

# Install runtime dependencies (seccomp + tini for signal handling)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libseccomp2 tini && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user and data directory
RUN groupadd --system picodome && \
    useradd --system --gid picodome --create-home --home-dir /home/picodome picodome && \
    mkdir -p /home/picodome/.picodome && \
    chown picodome:picodome /home/picodome/.picodome

WORKDIR /home/picodome

# Copy and install wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Daemon ports (HTTP and gRPC)
EXPOSE 8443 50051

# Persistent data volume
VOLUME /home/picodome/.picodome

# Health check — verify CLI is functional
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD picodome --version || exit 1

# Graceful shutdown: SIGTERM triggers PicoDomeDaemon.stop()
STOPSIGNAL SIGTERM

# Switch to non-root user
USER picodome

# Default: CLI mode. Override for daemon: picodome daemon --host 0.0.0.0
# Use tini as PID 1 for proper signal forwarding
ENTRYPOINT ["tini", "--", "picodome"]
