"""Run the AlienBank web app: ``uv run alienbank`` or ``python -m alienbank``."""
from __future__ import annotations

import os

import uvicorn

# Importing config runs load_dotenv(), so ALIENBANK_HOST/PORT from .env are
# available here (not just deep inside the app once uvicorn has already bound).
from . import config  # noqa: F401


def main() -> None:
    host = os.getenv("ALIENBANK_HOST", "127.0.0.1")
    port = int(os.getenv("ALIENBANK_PORT", "8000"))
    uvicorn.run("alienbank.web.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
