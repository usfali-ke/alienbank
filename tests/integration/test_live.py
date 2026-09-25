"""Integration/regression suite against a running AlienBank (the G2 image,
started by the G3 job). TARGET_URL points at it, e.g. http://127.0.0.1:8080.

Every test uses its own client (own cookie jar), and writes are limited to
small transfers between one customer's own accounts, so the suite can run
against any freshly seeded instance.
"""
from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

import httpx
import pytest

BASE = os.environ.get("TARGET_URL", "http://127.0.0.1:8080").rstrip("/")


@pytest.fixture
def anon():
    with httpx.Client(base_url=BASE, timeout=15, follow_redirects=False) as c:
        yield c


@contextmanager
def _session(username: str, password: str) -> Iterator[httpx.Client]:
    with httpx.Client(base_url=BASE, timeout=15, follow_redirects=False) as c:
        r = c.post("/login", data={"username": username, "password": password})
        assert r.status_code == 303, r.text[:200]
        yield c


@pytest.fixture
def ana():
    with _session("ana", "ana123") as c:
        yield c


def test_login_page_is_served(anon):
    r = anon.get("/login")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]


def test_static_assets_are_served(anon):
    assert anon.get("/static/css/app.css").status_code == 200


def test_session_cookie_is_httponly(anon):
    r = anon.post("/login", data={"username": "ana", "password": "ana123"})
    cookie = r.headers.get("set-cookie", "")
    assert "alienbank_session=" in cookie and "httponly" in cookie.lower()


def test_api_requires_a_session(anon):
    assert anon.get("/api/me").status_code == 401
    assert anon.get("/api/accounts").status_code == 401


def test_invalid_login_is_rejected(anon):
    assert anon.post("/login", data={"username": "ana", "password": "nope"}).status_code == 401


def test_authenticated_customer_flow(ana):
    assert ana.get("/api/me").json()["username"] == "ana"
    accounts = {a["account_number"]: a for a in ana.get("/api/accounts").json()}
    assert "0101700002" in accounts and "0202700010" not in accounts
    assert ana.get("/dashboard").status_code == 200


def test_cross_tenant_access_is_forbidden(ana):
    assert ana.get("/api/accounts/0202700010/balance").status_code == 403
    r = ana.post("/api/transfer", json={"from_account": "0202700010", "to_account": "0101700002", "amount": 1})
    assert r.status_code == 403


def test_transfer_between_own_accounts_updates_both_balances(ana):
    bal = lambda n: ana.get(f"/api/accounts/{n}/balance").json()["balance"]  # noqa: E731
    src, dst = bal("0101700002"), bal("0101700001")
    r = ana.post("/api/transfer", json={"from_account": "0101700002", "to_account": "0101700001", "amount": 1, "note": "integration test"})
    assert r.status_code == 200
    assert (bal("0101700002"), bal("0101700001")) == (src - 1, dst + 1)
    statement = ana.get("/api/accounts/0101700001/statement", params={"limit": 5}).json()
    assert any(t["description"] == "integration test" for t in statement["transactions"])


def test_logout_ends_the_session():
    with _session("duncan", "duncan123") as c:
        assert c.get("/api/me").status_code == 200
        c.get("/logout")
        assert c.get("/api/me").status_code == 401
