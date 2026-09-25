# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# AlienBank — security-lab banking app. Multi-stage build using uv.

# Base images are pinned by digest (the tag is informational): the same
# commit must always build from the same bytes. Bump both deliberately, in a
# reviewed PR — G2's reproducible_build_config_controlled fails on a floating
# FROM.
FROM ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 AS uv

FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS builder

# SOURCE_DATE_EPOCH (commit time, passed by CI) makes py_compile write
# hash-based .pyc files instead of mtime-stamped ones, so bytecode compiled
# today and tomorrow is byte-identical.
ARG SOURCE_DATE_EPOCH

# uv: fast, lockfile-driven installs.
COPY --from=uv /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Install dependencies first (cached layer) — project code copied afterwards.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Now the project source, then install the project itself.
COPY src ./src
COPY README.md ./
COPY knowledge ./knowledge
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev


FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS runtime

# Declared per stage: useradd (shadow-utils) also honours it for the
# password-change date it writes into /etc/shadow.
ARG SOURCE_DATE_EPOCH

# Non-root runtime user.
# Fixed high uid/gid 10001 (no overlap with host system accounts) —
# deploy/kind's securityContext runs as exactly this.
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --home /app app

WORKDIR /app

# Bring in the resolved virtualenv and the app code from the builder.
COPY --from=builder /app /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    ALIENBANK_HOST=0.0.0.0 \
    ALIENBANK_PORT=8080

# Writable data dir for the SQLite DB / chroma index seeded at startup. Only
# this directory is the app user's — code and venv stay root-owned, so a
# compromised process can't rewrite the application.
RUN mkdir -p /app/data && chown app:app /app/data
# Numeric, so runAsNonRoot can verify it without reading /etc/passwd.
USER 10001:10001

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/login', timeout=4)"]
CMD ["alienbank"]
