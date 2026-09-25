# syntax=docker/dockerfile:1
# AlienBank — security-lab banking app. Multi-stage build using uv.

FROM python:3.12-slim AS builder

# uv: fast, lockfile-driven installs.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

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


FROM python:3.12-slim AS runtime

# Non-root runtime user.
RUN groupadd --system app && useradd --system --gid app --home /app app

WORKDIR /app

# Bring in the resolved virtualenv and the app code from the builder.
COPY --from=builder /app /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    ALIENBANK_HOST=0.0.0.0 \
    ALIENBANK_PORT=8080

# Writable data dir for the SQLite DB / chroma index seeded at startup.
RUN mkdir -p /app/data && chown -R app:app /app
USER app

EXPOSE 8080
CMD ["alienbank"]
