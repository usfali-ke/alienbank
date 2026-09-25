"""The hardened REST surface: identity only ever comes from the session."""
from __future__ import annotations


def test_login_page_renders(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "<form" in r.text and 'name="password"' in r.text


def test_root_and_dashboard_redirect_anonymous_users_to_login(client):
    for path in ("/", "/dashboard"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (302, 307) and r.headers["location"] == "/login"


def test_api_rejects_unauthenticated_requests(client):
    for method, path in [
        ("get", "/api/me"),
        ("get", "/api/accounts"),
        ("get", "/api/accounts/0101700001/balance"),
        ("post", "/api/transfer"),
        ("post", "/api/reset"),
    ]:
        r = getattr(client, method)(path)
        assert r.status_code == 401, (method, path, r.status_code)


def test_bad_credentials_are_rejected_without_a_session(client, login):
    r = login("ana", "wrong")
    assert r.status_code == 401 and "Invalid username or password" in r.text
    assert client.get("/api/me").status_code == 401


def test_login_sets_session_identity(client, login):
    r = login("ana", "ana123")
    assert r.status_code == 303 and r.headers["location"] == "/dashboard"
    assert client.get("/api/me").json() == {"username": "ana", "full_name": "Ana Mueli", "role": "customer"}
    assert client.get("/dashboard").status_code == 200

    client.get("/logout")
    assert client.get("/api/me").status_code == 401


def test_customer_sees_only_own_accounts(client, login):
    login("ana", "ana123")
    numbers = {a["account_number"] for a in client.get("/api/accounts").json()}
    assert numbers == {"0101700001", "0101700002", "0101700003"}


def test_customer_cannot_read_another_customers_account(client, login):
    """BOLA/IDOR: the REST API enforces ownership even for a valid account number."""
    login("ana", "ana123")
    assert client.get("/api/accounts/0202700010/balance").status_code == 403
    assert client.get("/api/accounts/0202700010/statement").status_code == 403


def test_customer_cannot_transfer_from_another_customers_account(client, login):
    login("ana", "ana123")
    r = client.post("/api/transfer", json={"from_account": "0202700010", "to_account": "0101700002", "amount": 100})
    assert r.status_code == 403


def test_transfer_moves_money_and_rejects_overdraft(client, login):
    login("ana", "ana123")
    before = client.get("/api/accounts/0101700002/balance").json()["balance"]

    r = client.post("/api/transfer", json={"from_account": "0101700002", "to_account": "0202700010", "amount": 250})
    assert r.status_code == 200 and r.json()["balance"] == before - 250

    r = client.post("/api/transfer", json={"from_account": "0101700002", "to_account": "0202700010", "amount": 10_000_000})
    assert r.status_code == 400 and r.json()["error"] == "InsufficientFunds"

    r = client.post("/api/transfer", json={"from_account": "0101700002", "to_account": "0202700010", "amount": -5})
    assert r.status_code == 400


def test_name_enquiry_reveals_name_but_not_balance(client, login):
    login("ana", "ana123")
    body = client.get("/api/name-enquiry/0202700010").json()
    assert set(body) == {"account_number", "account_name"}


def test_only_tellers_may_deposit(client, login):
    login("ana", "ana123")
    assert client.post("/api/teller/deposit", json={"account_number": "0101700002", "amount": 100}).status_code == 403

    client.get("/logout")
    login("teller", "teller123")
    r = client.post("/api/teller/deposit", json={"account_number": "0101700002", "amount": 100})
    assert r.status_code == 200
