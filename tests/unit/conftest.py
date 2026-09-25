"""Unit-test isolation: a throwaway SQLite DB and no reachable LLM/embedder.

alienbank.config reads the environment at import time, so everything here
is set before the first `import alienbank`.
"""
from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="alienbank-test-"))
os.environ.update(
    {
        "ALIENBANK_SECRET_KEY": secrets.token_hex(32),
        "ALIENBANK_CHROMA_PATH": str(_TMP / "chroma"),
        "ALIENBANK_AUDIT_PATH": str(_TMP / "audit.jsonl"),
        # Port 9 (discard) refuses immediately — the knowledge index build
        # at startup fails fast and the app carries on without RAG.
        "ALIENBANK_EMBED_BASE_URL": "http://127.0.0.1:9/v1",
        "OLLAMA_BASE_URL": "http://127.0.0.1:9/v1",
        "ALIENBANK_LLM_PROVIDER": "ollama",
    }
)

from alienbank import db  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "alienbank.db")
    db.init_db()
    yield


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from alienbank.web.app import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def login(client):
    def _login(username: str, password: str):
        return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)

    return _login
