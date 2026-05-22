# =============================================================================
# Iron Dome — Multi-stage Dockerfile
# =============================================================================
# Produces a minimal runtime image with Iron Dome installed as a CLI tool.
# Iron Dome is NOT a daemon — it exposes no ports and runs as a one-shot
# sandboxing command. Use it in CI pipelines, pre-commit hooks, or as an
# entrypoint wrapper.
#
# NOTE: For full seccomp-bpf sandboxing on Linux, install libseccomp-dev
# in the builder stage and libseccomp2 in the runtime stage. The Python
# bindings (python-seccomp) are optional — IronDome degrades gracefully to
# subprocess sandboxing when libseccomp is unavailable.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1 — Builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
# Uncomment the next line for seccomp support:
# RUN apt-get update && apt-get install -y --no-install-recommends libseccomp-dev && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir --upgrade pip build wheel

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

# Build wheel
RUN python -m build --wheel --no-isolation

# ---------------------------------------------------------------------------
# Stage 2 — Runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/kirkforge/IronDome"
LABEL org.opencontainers.image.title="Iron Dome"
LABEL org.opencontainers.image.version="0.3.0"
LABEL org.opencontainers.image.description="Deterministic runtime sandbox and behavioral analysis engine for supply-chain security"

# Install runtime dependencies
# Uncomment the next line for seccomp support:
# RUN apt-get update && apt-get install -y --no-install-recommends libseccomp2 && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --system irondome && \
    useradd --system --gid irondome --create-home --home-dir /home/irondome irondome

WORKDIR /home/irondome

# Copy and install wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Health check — verify CLI is functional
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD irondome --version || exit 1

# Switch to non-root user
USER irondome

# Iron Dome is a CLI tool, not a daemon — no ports exposed
ENTRYPOINT ["irondome"]