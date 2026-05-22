# =============================================================================
# Iron Dome — Multi-stage Dockerfile
# =============================================================================
# Produces a minimal runtime image with Iron Dome installed.
#
# Supports both CLI and daemon modes:
#   CLI:     irondome sandbox <command>
#   Daemon:  irondome daemon --host 0.0.0.0 --port 8443
#   gRPC:    irondome daemon --transport grpc
#
# For full seccomp-bpf kernel sandboxing, the runtime image includes
# libseccomp2. Without it, Iron Dome falls back to the subprocess
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

LABEL org.opencontainers.image.source="https://github.com/KirkForge/IronDome"
LABEL org.opencontainers.image.title="Iron Dome"
LABEL org.opencontainers.image.version="0.4.0"
LABEL org.opencontainers.image.description="Deterministic runtime sandbox and behavioral analysis engine for supply-chain security"

# Install runtime dependency for seccomp-bpf backend
RUN apt-get update && \
    apt-get install -y --no-install-recommends libseccomp2 && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --system irondome && \
    useradd --system --gid irondome --create-home --home-dir /home/irondome irondome

WORKDIR /home/irondome

# Copy and install wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Daemon ports (HTTP and gRPC)
EXPOSE 8443 50051

# Health check — verify CLI is functional
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD irondome --version || exit 1

# Switch to non-root user
USER irondome

# Default: CLI mode. Override for daemon: irondome daemon --host 0.0.0.0
ENTRYPOINT ["irondome"]