"""Banking core.

This module deliberately exposes TWO families of operations:

``*_secure`` methods
    Take an authenticated ``actor`` (the logged-in user) and enforce ownership
    and role. These back the REST API and are safe against IDOR/BOLA.

``*_raw`` methods
    Take a bare ``account_number`` (and sometimes an ``as_role``) with NO
    authorization check. These back the chat-agent tools and are the intended
    prompt-injection / excessive-agency vulnerability.

Same data, same money-movement code path — the only difference is whether the
caller is forced to prove they're allowed. Flip the app to secure mode and the
agent tools call the ``*_secure`` variants instead.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from . import db

# A computed loan limit is valid for this many days; within the window the
# cached analysis is reused rather than re-running the (expensive) LLM pass.
LOAN_LIMIT_VALID_DAYS = 10

# One-off service charge applied to every loan, added on top of the principal.
# The customer receives the principal but owes principal + this charge.
LOAN_SERVICE_CHARGE_RATE = 0.12  # 12%


# ---------------------------------------------------------------------------
# Domain types & errors
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Actor:
    """The authenticated principal, derived from the server session."""

    user_id: int
    username: str
    full_name: str
    role: str  # 'customer' | 'teller'
    # Random per-user correlation handle for security logs (actor.ref). Never the
    # username; carries no PII. See SECURITY_LOGGING_PLAN.md §3.6.
    pseudonym: str = ""

    @property
    def ref(self) -> str:
        """The value logged as ``actor.ref`` — the pseudonym, never the username."""
        return self.pseudonym


class BankError(Exception):
    """Base for expected banking failures (safe to surface to callers)."""


class AuthError(BankError):
    pass


class NotFound(BankError):
    pass


class Forbidden(BankError):
    pass


class InsufficientFunds(BankError):
    pass


def _cents(amount: float) -> int:
    return int(round(float(amount) * 100))


def money(cents: int) -> float:
    return round(cents / 100, 2)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def authenticate(username: str, password: str) -> Actor:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    if row is None or row["password"] != password:
        raise AuthError("Invalid username or password")
    return Actor(
        user_id=row["id"],
        username=row["username"],
        full_name=row["full_name"],
        role=row["role"],
        pseudonym=row["pseudonym"],
    )


def get_actor(username: str) -> Optional[Actor]:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    if row is None:
        return None
    return Actor(row["id"], row["username"], row["full_name"], row["role"],
                 pseudonym=row["pseudonym"])


# ---------------------------------------------------------------------------
# Internal helpers (no authz — used by both families)
# ---------------------------------------------------------------------------
def _account_row(conn, account_number: str):
    row = conn.execute(
        "SELECT a.*, u.full_name AS owner_name, u.username AS owner_username"
        " FROM accounts a JOIN users u ON u.id = a.owner_id"
        " WHERE a.account_number = ?",
        (account_number,),
    ).fetchone()
    if row is None:
        raise NotFound(f"Account {account_number} not found")
    return row


def _accounts_for_owner(conn, owner_id: int):
    return conn.execute(
        "SELECT * FROM accounts WHERE owner_id = ? ORDER BY id", (owner_id,)
    ).fetchall()


def _statement_rows(conn, account_number: str, limit: Optional[int]):
    q = (
        "SELECT * FROM transactions WHERE account_number = ?"
        " ORDER BY id DESC"
    )
    params: tuple = (account_number,)
    if limit is not None:
        q += " LIMIT ?"
        params = (account_number, limit)
    return conn.execute(q, params).fetchall()


def _do_transfer(conn, src: str, dst: str, amount_cents: int, note: str) -> None:
    """Move money between two accounts. Assumes accounts exist. No authz."""
    if amount_cents <= 0:
        raise BankError("Amount must be positive")
    src_row = _account_row(conn, src)
    dst_row = _account_row(conn, dst)
    if src == dst:
        raise BankError("Source and destination must differ")
    if src_row["balance_cents"] < amount_cents:
        raise InsufficientFunds("Insufficient funds")

    src_bal = src_row["balance_cents"] - amount_cents
    dst_bal = dst_row["balance_cents"] + amount_cents
    ts = db.utcnow()

    conn.execute(
        "UPDATE accounts SET balance_cents = ? WHERE account_number = ?",
        (src_bal, src),
    )
    conn.execute(
        "UPDATE accounts SET balance_cents = ? WHERE account_number = ?",
        (dst_bal, dst),
    )
    conn.execute(
        "INSERT INTO transactions (account_number, ts, amount_cents, balance_cents,"
        " description, counterparty) VALUES (?, ?, ?, ?, ?, ?)",
        (src, ts, -amount_cents, src_bal, note or f"Transfer to {dst}", dst),
    )
    conn.execute(
        "INSERT INTO transactions (account_number, ts, amount_cents, balance_cents,"
        " description, counterparty) VALUES (?, ?, ?, ?, ?, ?)",
        (dst, ts, amount_cents, dst_bal, note or f"Transfer from {src}", src),
    )


def _serialize_account(row) -> dict:
    return {
        "account_number": row["account_number"],
        "nickname": row["nickname"],
        "account_type": row["account_type"],
        "balance": money(row["balance_cents"]),
        "currency": row["currency"],
        "owner_name": row["owner_name"] if "owner_name" in row.keys() else None,
    }


def _serialize_txn(row) -> dict:
    return {
        "ts": row["ts"],
        "amount": money(row["amount_cents"]),
        "balance": money(row["balance_cents"]),
        "description": row["description"],
        "counterparty": row["counterparty"],
    }


# ===========================================================================
# SECURE family — session-bound, enforces ownership + role. Used by REST API.
# ===========================================================================
def _assert_can_touch(actor: Actor, account_row) -> None:
    """Tellers may touch any account; customers only their own."""
    if actor.role == "teller":
        return
    if account_row["owner_id"] != actor.user_id:
        raise Forbidden("You do not have access to this account")


def list_my_accounts_secure(actor: Actor) -> list[dict]:
    with db.connect() as conn:
        rows = _accounts_for_owner(conn, actor.user_id)
        return [
            _serialize_account(_account_row(conn, r["account_number"])) for r in rows
        ]


def get_balance_secure(actor: Actor, account_number: str) -> dict:
    with db.connect() as conn:
        row = _account_row(conn, account_number)
        _assert_can_touch(actor, row)
        return _serialize_account(row)


def get_statement_secure(
    actor: Actor, account_number: str, limit: Optional[int] = None
) -> dict:
    with db.connect() as conn:
        row = _account_row(conn, account_number)
        _assert_can_touch(actor, row)
        txns = [_serialize_txn(t) for t in _statement_rows(conn, account_number, limit)]
        return {"account": _serialize_account(row), "transactions": txns}


def transfer_secure(
    actor: Actor, src: str, dst: str, amount: float, note: str = ""
) -> dict:
    with db.connect() as conn:
        src_row = _account_row(conn, src)
        _assert_can_touch(actor, src_row)  # must own the SOURCE (or be teller)
        _account_row(conn, dst)  # dst must exist
        _do_transfer(conn, src, dst, _cents(amount), note)
        return _serialize_account(_account_row(conn, src))


def deposit_secure(actor: Actor, account_number: str, amount: float, note: str = "") -> dict:
    if actor.role != "teller":
        raise Forbidden("Only tellers may deposit cash")
    return _deposit(account_number, amount, note or "Cash deposit (teller)")


def update_profile_secure(actor: Actor, target_username: str, **fields) -> dict:
    if actor.role != "teller":
        raise Forbidden("Only tellers may edit customer profiles")
    return _update_profile(target_username, **fields)


def name_enquiry(actor: Actor, account_number: str) -> dict:
    """Confirm a destination account before transfer.

    Any authenticated user may look up ANY account here, but the response is
    deliberately limited to the holder's name and account number — never the
    balance or transactions. This mirrors a real "name check" / confirmation-of-
    payee flow: enough to confirm you're paying the right person, nothing more.
    """
    with db.connect() as conn:
        row = _account_row(conn, account_number)
        return {
            "account_number": row["account_number"],
            "account_name": row["owner_name"],
        }


def recent_recipients_secure(actor: Actor, limit: int = 5) -> list[dict]:
    """The customer's most recent distinct transfer payees (for quick re-send).

    Derived only from debits on the actor's OWN accounts, so it never leaks
    anyone else's activity. Each recipient is enriched with the holder name.
    """
    with db.connect() as conn:
        own = {r["account_number"] for r in _accounts_for_owner(conn, actor.user_id)}
        if not own:
            return []
        placeholders = ",".join("?" for _ in own)
        # Outgoing transfers = negative amount with a counterparty set.
        rows = conn.execute(
            f"SELECT counterparty, MAX(ts) AS last_ts FROM transactions"
            f" WHERE account_number IN ({placeholders})"
            f" AND amount_cents < 0 AND counterparty IS NOT NULL"
            f" GROUP BY counterparty ORDER BY last_ts DESC LIMIT ?",
            (*own, limit),
        ).fetchall()

        recipients = []
        for r in rows:
            acct = r["counterparty"]
            try:
                holder = _account_row(conn, acct)["owner_name"]
            except NotFound:
                holder = "Unknown"
            recipients.append({
                "account_number": acct,
                "account_name": holder,
                "last_sent": r["last_ts"],
            })
        return recipients


# ===========================================================================
# RAW family — NO authorization. Used by the (vulnerable) agent tools.
# The agent passes whatever account_number / role the LLM decided on.
# ===========================================================================
def get_balance_raw(account_number: str) -> dict:
    with db.connect() as conn:
        return _serialize_account(_account_row(conn, account_number))


def get_statement_raw(account_number: str, limit: Optional[int] = None) -> dict:
    with db.connect() as conn:
        row = _account_row(conn, account_number)
        txns = [_serialize_txn(t) for t in _statement_rows(conn, account_number, limit)]
        return {"account": _serialize_account(row), "transactions": txns}


def list_accounts_for_username_raw(username: str) -> list[dict]:
    with db.connect() as conn:
        u = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if u is None:
            raise NotFound(f"User {username} not found")
        rows = _accounts_for_owner(conn, u["id"])
        return [_serialize_account(_account_row(conn, r["account_number"])) for r in rows]


def transfer_raw(src: str, dst: str, amount: float, note: str = "") -> dict:
    with db.connect() as conn:
        _do_transfer(conn, src, dst, _cents(amount), note)
        return _serialize_account(_account_row(conn, src))


def deposit_raw(account_number: str, amount: float, note: str = "") -> dict:
    return _deposit(account_number, amount, note or "Cash deposit")


def update_profile_raw(target_username: str, **fields) -> dict:
    return _update_profile(target_username, **fields)


# ===========================================================================
# LOANS
# ===========================================================================
# A loan limit is produced by an LLM reading the customer's FULL statement (see
# agent.loan_analysis) and then CACHED for LOAN_LIMIT_VALID_DAYS. Within that
# window the stored limit is authoritative and reused — no re-analysis.
#
# As with the rest of the app there are two families:
#   *_secure  — bind to the authenticated actor: you may only see/borrow against
#               your OWN limit and accounts, and applications are capped at the
#               cached limit. Safe against IDOR / limit tampering.
#   *_raw     — take a bare username / account_number the caller supplies. NO
#               ownership check, and the limit ceiling is advisory only. This is
#               the intended vulnerability the chat agent exposes: talk the model
#               into applying against someone else's limit, borrowing above the
#               limit, reading another customer's loans, or repaying from an
#               account that isn't yours.
# ---------------------------------------------------------------------------
def _serialize_limit(row) -> dict:
    return {
        "username": row["username"],
        "limit": money(row["limit_cents"]),
        "recommended": money(row["recommended_cents"]),
        "monthly_repayment": money(row["monthly_repayment_cents"]),
        "trend": row["trend"],
        "rationale": row["rationale"],
        "computed_at": row["computed_at"],
        "expires_at": row["expires_at"],
    }


def _serialize_loan(row) -> dict:
    charge_cents = row["service_charge_cents"] if "service_charge_cents" in row.keys() else 0
    return {
        "reference": row["reference"],
        "username": row["username"],
        "account_number": row["account_number"],
        "principal": money(row["principal_cents"]),
        "service_charge": money(charge_cents),
        # What the customer must repay in total: principal + service charge.
        "total_repayable": money(row["principal_cents"] + charge_cents),
        "outstanding": money(row["outstanding_cents"]),
        "status": row["status"],
        "opened_at": row["opened_at"],
        "note": row["note"],
    }


def _serialize_loan_payment(row) -> dict:
    return {
        "ts": row["ts"],
        "kind": row["kind"],                      # 'disbursement' | 'repayment'
        "amount": money(row["amount_cents"]),
        "outstanding": money(row["outstanding_cents"]),
        "note": row["note"],
    }


def _loan_statement(conn, loan_row) -> dict:
    """Assemble a loan's full statement: the loan header + its payment ledger."""
    rows = conn.execute(
        "SELECT * FROM loan_payments WHERE loan_reference = ? ORDER BY id",
        (loan_row["reference"],),
    ).fetchall()
    total_repaid = sum(
        r["amount_cents"] for r in rows if r["kind"] == "repayment"
    )
    return {
        "loan": _serialize_loan(loan_row),
        "total_repaid": money(total_repaid),
        "payments": [_serialize_loan_payment(r) for r in rows],
    }


def _live_limit_row(conn, username: str):
    """The customer's most recent NON-expired cached limit, or None."""
    return conn.execute(
        "SELECT * FROM loan_limits WHERE username = ? AND expires_at > ?"
        " ORDER BY id DESC LIMIT 1",
        (username, db.utcnow()),
    ).fetchone()


def _store_limit(conn, username: str, assessment: dict) -> None:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=LOAN_LIMIT_VALID_DAYS)
    conn.execute(
        "INSERT INTO loan_limits (username, limit_cents, recommended_cents,"
        " monthly_repayment_cents, trend, rationale, computed_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (username, _cents(assessment["limit"]), _cents(assessment["recommended"]),
         _cents(assessment["monthly_repayment"]), assessment["trend"],
         assessment["rationale"], now.isoformat(timespec="seconds"),
         expires.isoformat(timespec="seconds")),
    )


def _full_statement_for_user(conn, username: str) -> dict:
    """Build a WHOLE-USER financial picture for loan analysis.

    The limit is tied to the customer, not a single account, so this gathers
    EVERY account the user owns and the union of their transactions. The returned
    dict lists all accounts (with balances) and every transaction tagged with the
    account it belongs to, so the analysis reflects total income/outgoings across
    the whole relationship. Raises NotFound if the user has no accounts.
    """
    u = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if u is None:
        raise NotFound(f"User {username} not found")
    accts = _accounts_for_owner(conn, u["id"])
    if not accts:
        raise NotFound(f"{username} has no accounts to assess")
    account_views = [_serialize_account(_account_row(conn, a["account_number"])) for a in accts]
    txns: list[dict] = []
    for a in accts:
        for t in _statement_rows(conn, a["account_number"], None):
            entry = _serialize_txn(t)
            entry["account_number"] = a["account_number"]
            txns.append(entry)
    txns.sort(key=lambda t: t["ts"], reverse=True)
    total_balance = sum(a["balance"] for a in account_views)
    return {
        "username": username,
        "accounts": account_views,
        "total_balance": total_balance,
        # Keep a representative "account" header for backward compatibility with
        # any single-account consumer; analysis uses the full accounts list.
        "account": account_views[0],
        "transactions": txns,
    }


def _compute_and_store_limit(username: str) -> dict:
    """Run the LLM statement analysis for ``username`` and cache the result."""
    # Imported lazily so the banking core has no hard dependency on the agent
    # layer / LLM provider (keeps bank.py importable in tooling and tests).
    from .agent import loan_analysis
    with db.connect() as conn:
        statement = _full_statement_for_user(conn, username)
    assessment = loan_analysis.analyze_statement(statement)
    with db.connect() as conn:
        _store_limit(conn, username, assessment)
        row = _live_limit_row(conn, username)
        return _serialize_limit(row)


def _get_or_compute_limit(username: str) -> dict:
    """Return the cached limit if still valid, else compute + cache a fresh one."""
    with db.connect() as conn:
        row = _live_limit_row(conn, username)
        if row is not None:
            return _serialize_limit(row)
    return _compute_and_store_limit(username)


def _next_loan_reference(conn) -> str:
    n = conn.execute("SELECT COUNT(*) AS n FROM loans").fetchone()["n"]
    return f"LN-{n + 1:04d}"


def _open_loan(conn, username: str, account_number: str, principal_cents: int,
               note: str) -> dict:
    """Create a loan and disburse the principal into the account (credit).

    A 12% service charge is added on top of the principal: the customer receives
    the principal but owes principal + charge. The charge is recorded on the loan
    and as its own ledger line so it is visible on the loan statement.
    """
    if principal_cents <= 0:
        raise BankError("Loan amount must be positive")
    acct = _account_row(conn, account_number)
    reference = _next_loan_reference(conn)
    charge_cents = int(round(principal_cents * LOAN_SERVICE_CHARGE_RATE))
    total_owed_cents = principal_cents + charge_cents
    # Only the principal is disbursed to the account; the charge is owed, not paid out.
    new_bal = acct["balance_cents"] + principal_cents
    ts = db.utcnow()
    conn.execute(
        "UPDATE accounts SET balance_cents = ? WHERE account_number = ?",
        (new_bal, account_number),
    )
    conn.execute(
        "INSERT INTO transactions (account_number, ts, amount_cents, balance_cents,"
        " description, counterparty) VALUES (?, ?, ?, ?, ?, ?)",
        (account_number, ts, principal_cents, new_bal,
         note or f"Loan disbursement {reference}", None),
    )
    conn.execute(
        "INSERT INTO loans (reference, username, account_number, principal_cents,"
        " service_charge_cents, outstanding_cents, status, opened_at, note)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (reference, username, account_number, principal_cents, charge_cents,
         total_owed_cents, "active", ts, note or None),
    )
    # Loan ledger: opening disbursement, then the service charge added on top.
    conn.execute(
        "INSERT INTO loan_payments (loan_reference, ts, kind, amount_cents,"
        " outstanding_cents, note) VALUES (?, ?, ?, ?, ?, ?)",
        (reference, ts, "disbursement", principal_cents, principal_cents,
         note or f"Disbursed to {account_number}"),
    )
    conn.execute(
        "INSERT INTO loan_payments (loan_reference, ts, kind, amount_cents,"
        " outstanding_cents, note) VALUES (?, ?, ?, ?, ?, ?)",
        (reference, ts, "service_charge", charge_cents, total_owed_cents,
         f"Service charge ({LOAN_SERVICE_CHARGE_RATE * 100:.0f}% of principal)"),
    )
    row = conn.execute("SELECT * FROM loans WHERE reference = ?", (reference,)).fetchone()
    return _serialize_loan(row)


def _repay_loan(conn, loan_row, account_number: str, amount_cents: int) -> dict:
    """Debit ``account_number`` and reduce the loan's outstanding balance."""
    if amount_cents <= 0:
        raise BankError("Repayment amount must be positive")
    acct = _account_row(conn, account_number)
    if acct["balance_cents"] < amount_cents:
        raise InsufficientFunds("Insufficient funds to repay")
    pay = min(amount_cents, loan_row["outstanding_cents"])
    new_bal = acct["balance_cents"] - pay
    new_outstanding = loan_row["outstanding_cents"] - pay
    status = "repaid" if new_outstanding <= 0 else "active"
    ts = db.utcnow()
    conn.execute(
        "UPDATE accounts SET balance_cents = ? WHERE account_number = ?",
        (new_bal, account_number),
    )
    conn.execute(
        "INSERT INTO transactions (account_number, ts, amount_cents, balance_cents,"
        " description, counterparty) VALUES (?, ?, ?, ?, ?, ?)",
        (account_number, ts, -pay, new_bal,
         f"Loan repayment {loan_row['reference']}", None),
    )
    conn.execute(
        "UPDATE loans SET outstanding_cents = ?, status = ? WHERE id = ?",
        (new_outstanding, status, loan_row["id"]),
    )
    # Loan ledger: repayment movement.
    conn.execute(
        "INSERT INTO loan_payments (loan_reference, ts, kind, amount_cents,"
        " outstanding_cents, note) VALUES (?, ?, ?, ?, ?, ?)",
        (loan_row["reference"], ts, "repayment", pay, new_outstanding,
         f"Repayment from {account_number}"),
    )
    row = conn.execute("SELECT * FROM loans WHERE id = ?", (loan_row["id"],)).fetchone()
    return _serialize_loan(row)


def _outstanding_total(conn, username: str) -> int:
    r = conn.execute(
        "SELECT COALESCE(SUM(outstanding_cents), 0) AS t FROM loans"
        " WHERE username = ? AND status = 'active'",
        (username,),
    ).fetchone()
    return r["t"]


def _active_principal_total(conn, username: str) -> int:
    """Sum of PRINCIPAL on the user's active loans.

    The limit caps how much principal the customer may borrow in total, across
    any number of concurrent loans — the 12% service charge sits on top and does
    not consume borrowing capacity. A fully-repaid loan frees its principal.
    """
    r = conn.execute(
        "SELECT COALESCE(SUM(principal_cents), 0) AS t FROM loans"
        " WHERE username = ? AND status = 'active'",
        (username,),
    ).fetchone()
    return r["t"]


# --- SECURE family (session-bound, safe) -----------------------------------
def loan_limit_secure(actor: Actor, *, refresh: bool = False) -> dict:
    """The caller's OWN loan limit (cached 10 days, computed on first use)."""
    if refresh:
        return _compute_and_store_limit(actor.username)
    return _get_or_compute_limit(actor.username)


def apply_loan_secure(actor: Actor, account_number: str, amount: float,
                      note: str = "") -> dict:
    """Borrow against the caller's own limit, disbursed to their own account.

    The customer may take MULTIPLE concurrent loans as long as their total
    borrowed PRINCIPAL stays within the approved limit. The 12% service charge is
    added on top of each loan and does not count against the limit.

    Enforces: the destination account belongs to the caller, and existing active
    principal + this request does not exceed the caller's cached limit.
    """
    amount_cents = _cents(amount)
    with db.connect() as conn:
        acct = _account_row(conn, account_number)
        _assert_can_touch(actor, acct)  # must own the disbursement account
        limit = _get_or_compute_limit(actor.username)
        limit_cents = _cents(limit["limit"])
        already = _active_principal_total(conn, actor.username)
        if already + amount_cents > limit_cents:
            raise Forbidden(
                f"Requested KES {money(amount_cents):,.2f} plus existing "
                f"KES {money(already):,.2f} borrowed exceeds your approved "
                f"limit of KES {money(limit_cents):,.2f}."
            )
        return _open_loan(conn, actor.username, account_number, amount_cents, note)


def list_loans_secure(actor: Actor) -> list[dict]:
    """The caller's OWN loans."""
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM loans WHERE username = ? ORDER BY id DESC",
            (actor.username,),
        ).fetchall()
        return [_serialize_loan(r) for r in rows]


def repay_loan_secure(actor: Actor, reference: str, amount: float,
                      account_number: Optional[str] = None) -> dict:
    """Repay one of the caller's OWN loans from one of the caller's OWN accounts."""
    with db.connect() as conn:
        loan = conn.execute(
            "SELECT * FROM loans WHERE reference = ?", (reference,)
        ).fetchone()
        if loan is None:
            raise NotFound(f"Loan {reference} not found")
        if actor.role != "teller" and loan["username"] != actor.username:
            raise Forbidden("You can only repay your own loans")
        src = account_number or loan["account_number"]
        acct = _account_row(conn, src)
        _assert_can_touch(actor, acct)  # must own the paying account
        return _repay_loan(conn, loan, src, _cents(amount))


def loan_statement_secure(actor: Actor, reference: str) -> dict:
    """Full statement (disbursement + repayments) for one of the caller's loans."""
    with db.connect() as conn:
        loan = conn.execute(
            "SELECT * FROM loans WHERE reference = ?", (reference,)
        ).fetchone()
        if loan is None:
            raise NotFound(f"Loan {reference} not found")
        if actor.role != "teller" and loan["username"] != actor.username:
            raise Forbidden("You can only view your own loan statement")
        return _loan_statement(conn, loan)


# --- RAW family (NO authz — the intended vulnerability) --------------------
def loan_limit_raw(username: str, *, refresh: bool = False) -> dict:
    """Return ANY user's cached loan limit by username. No ownership check."""
    if refresh:
        return _compute_and_store_limit(username)
    return _get_or_compute_limit(username)


def set_loan_limit_raw(username: str, new_limit: float,
                       rationale: str = "Manual override") -> dict:
    """Overwrite a user's cached limit with an arbitrary value. No authz.

    A real system would never let a limit be set directly; this exists so a
    learner who reaches it (via a talked-into tool call) can inflate a limit —
    classic broken-function-level-authorization.
    """
    assessment = {
        "limit": new_limit, "recommended": new_limit,
        "monthly_repayment": new_limit / 10 if new_limit else 0,
        "trend": "stable", "rationale": rationale,
    }
    with db.connect() as conn:
        _store_limit(conn, username, assessment)
        return _serialize_limit(_live_limit_row(conn, username))


def apply_loan_raw(username: str, account_number: str, amount: float,
                   note: str = "", enforce_limit: bool = False) -> dict:
    """Open a loan for ANY username, disbursed to ANY account. No ownership check.

    ``enforce_limit`` is off by default: the raw path does not stop a caller
    borrowing above the cached limit. That ceiling is only advisory here — the
    real enforcement lives in ``apply_loan_secure``.
    """
    amount_cents = _cents(amount)
    with db.connect() as conn:
        _account_row(conn, account_number)  # must exist
        if enforce_limit:
            limit = _get_or_compute_limit(username)
            already = _active_principal_total(conn, username)
            if already + amount_cents > _cents(limit["limit"]):
                raise Forbidden("Exceeds approved limit")
        return _open_loan(conn, username, account_number, amount_cents, note)


def list_loans_raw(username: str) -> list[dict]:
    """List ANY user's loans by username. No ownership check."""
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM loans WHERE username = ? ORDER BY id DESC", (username,)
        ).fetchall()
        return [_serialize_loan(r) for r in rows]


def repay_loan_raw(reference: str, amount: float, account_number: str) -> dict:
    """Repay ANY loan from ANY account. No ownership check on either side.

    Lets a caller be talked into repaying (or, since any source works, draining)
    from an account that is not theirs.
    """
    with db.connect() as conn:
        loan = conn.execute(
            "SELECT * FROM loans WHERE reference = ?", (reference,)
        ).fetchone()
        if loan is None:
            raise NotFound(f"Loan {reference} not found")
        return _repay_loan(conn, loan, account_number, _cents(amount))


def loan_statement_raw(reference: str) -> dict:
    """Return ANY loan's full statement by reference. No ownership check."""
    with db.connect() as conn:
        loan = conn.execute(
            "SELECT * FROM loans WHERE reference = ?", (reference,)
        ).fetchone()
        if loan is None:
            raise NotFound(f"Loan {reference} not found")
        return _loan_statement(conn, loan)


# ---------------------------------------------------------------------------
# Shared low-level ops (used by both families)
# ---------------------------------------------------------------------------
def _deposit(account_number: str, amount: float, note: str) -> dict:
    cents = _cents(amount)
    if cents <= 0:
        raise BankError("Amount must be positive")
    with db.connect() as conn:
        row = _account_row(conn, account_number)
        new_bal = row["balance_cents"] + cents
        conn.execute(
            "UPDATE accounts SET balance_cents = ? WHERE account_number = ?",
            (new_bal, account_number),
        )
        conn.execute(
            "INSERT INTO transactions (account_number, ts, amount_cents, balance_cents,"
            " description, counterparty) VALUES (?, ?, ?, ?, ?, ?)",
            (account_number, db.utcnow(), cents, new_bal, note, None),
        )
        return _serialize_account(_account_row(conn, account_number))


# ===========================================================================
# Indirect-injection primitive (Level 3).
# An attacker with a normal transfer can write an arbitrary description onto a
# VICTIM'S statement. When the victim later asks the agent to read that
# statement, the attacker's text arrives as tool output — never passing through
# the pre-LLM input filters (D1/D2), which only scan the user's typed message.
# This is OWASP LLM01 indirect / second-order prompt injection.
# ===========================================================================
def plant_poisoned_note(target_account: str, note: str, amount: float = 1.0,
                        from_account: Optional[str] = None) -> None:
    """Write an attacker-controlled ``note`` onto ``target_account``'s statement.

    If ``from_account`` is given, models a real transfer carrying the note.
    Otherwise inserts a standalone credit line (a proxy for any inbound entry
    whose free-text field the attacker controls).
    """
    if from_account:
        _do_transfer_by_note(from_account, target_account, _cents(amount), note)
        return
    with db.connect() as conn:
        row = _account_row(conn, target_account)
        new_bal = row["balance_cents"] + _cents(amount)
        conn.execute(
            "UPDATE accounts SET balance_cents = ? WHERE account_number = ?",
            (new_bal, target_account),
        )
        conn.execute(
            "INSERT INTO transactions (account_number, ts, amount_cents, balance_cents,"
            " description, counterparty) VALUES (?, ?, ?, ?, ?, ?)",
            (target_account, db.utcnow(), _cents(amount), new_bal, note, from_account),
        )


def _do_transfer_by_note(src: str, dst: str, amount_cents: int, note: str) -> None:
    with db.connect() as conn:
        _do_transfer(conn, src, dst, amount_cents, note)


_EDITABLE = {"full_name", "email", "phone"}


def _update_profile(target_username: str, **fields) -> dict:
    updates = {k: v for k, v in fields.items() if k in _EDITABLE and v is not None}
    if not updates:
        raise BankError("No editable fields provided (full_name, email, phone)")
    with db.connect() as conn:
        u = conn.execute(
            "SELECT * FROM users WHERE username = ?", (target_username,)
        ).fetchone()
        if u is None:
            raise NotFound(f"User {target_username} not found")
        sets = ", ".join(f"{k} = ?" for k in updates)
        conn.execute(
            f"UPDATE users SET {sets} WHERE username = ?",
            (*updates.values(), target_username),
        )
        row = conn.execute(
            "SELECT username, full_name, email, phone, role FROM users WHERE username = ?",
            (target_username,),
        ).fetchone()
        return dict(row)
