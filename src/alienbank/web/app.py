"""FastAPI application.

The REST endpoints here are the HARDENED layer: every request derives the
acting principal from the signed server session and enforces ownership/role via
the ``*_secure`` banking core. There is no way to pass someone else's account
number to these endpoints and read/move their money.

The ``/api/chat`` endpoint bridges to the agent layer, which is where the
intentional prompt-injection vulnerability lives.
"""
from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from .. import bank, seclog
from ..agent import audit, chat
from ..agent.levels import LEVELS, spec
from ..agent.provider import provider_summary
from ..config import APP, MAX_LEVEL, MIN_LEVEL
from ..db import init_db, reset_db
from ..logging_setup import setup_security_logging

# --- Chat-hardening knobs (apply at levels where spec.server_history / .rate_limited) ---
# Server-held conversation history, keyed by an opaque per-session id (kept in the
# signed cookie). This closes the memory/context-poisoning hole where the client
# could submit forged prior turns. In-process store; fine for a single-node lab.
_HISTORY: dict[str, list[dict]] = {}
MAX_MESSAGE_CHARS = 4000       # cap a single user message
MAX_CLIENT_HISTORY = 20        # cap client-supplied history turns (when trusted, L0/L1)
MAX_SERVER_HISTORY = 40        # cap stored server history turns
RATE_MAX = 10                  # max chat requests ...
RATE_WINDOW = 60.0             # ... per this many seconds, per session
_RATE: dict[str, deque] = defaultdict(deque)

# Auth-failure tracking for brute-force / credential-stuffing OBSERVABILITY.
# This does NOT block a login (the plan is observability-only) — it just lets us
# emit a high-signal "auth throttle tripped" marker once failures from one source
# cross a threshold, and count distinct targets to tell spraying from brute force.
AUTH_FAIL_MAX = 5              # failures from one source.ip ...
AUTH_FAIL_WINDOW = 300.0       # ... within this many seconds trips the marker
_AUTH_FAILS: dict[str, deque] = defaultdict(deque)  # source.ip -> (ts, target_ref)


def _auth_fail_track(source_ip: str | None, target: str | None) -> tuple[int, int]:
    """Record a login failure for a source and report the burst it belongs to.

    Returns ``(failures_in_window, distinct_targets_in_window)`` for this
    ``source.ip``. A high failure count with **one** distinct target reads as
    brute force; a high count with **many** distinct targets reads as
    credential stuffing / password spraying. Never raises.
    """
    key = source_ip or "unknown"
    now = time.monotonic()
    q = _AUTH_FAILS[key]
    while q and now - q[0][0] > AUTH_FAIL_WINDOW:
        q.popleft()
    q.append((now, target or "?"))
    return len(q), len({t for _, t in q})

# Human-in-the-loop: transfers awaiting user confirmation, keyed by session id.
_PENDING_XFER: dict[str, dict] = {}
_AFFIRMATIONS = {"yes", "y", "confirm", "confirmed", "approve", "approved", "ok",
                 "okay", "go ahead", "do it", "proceed", "yes please", "sure"}


def _is_affirmation(message: str) -> bool:
    m = (message or "").strip().lower().rstrip(".!")
    return m in _AFFIRMATIONS or m.startswith(("yes", "confirm", "approve", "go ahead", "proceed"))

BASE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

@asynccontextmanager
async def lifespan(_app: FastAPI):
    setup_security_logging()
    init_db()
    # Build the RAG index if empty (needs the embedding model reachable). If the
    # embedder is down we log and continue — knowledge_search then returns empty
    # rather than crashing the app.
    try:
        from ..agent import knowledge
        if knowledge.index_count() == 0:
            n = knowledge.build_index()
            print(f"[alienbank] knowledge index ready: {n} chunks")
    except Exception as exc:  # noqa: BLE001
        print(f"[alienbank] knowledge index unavailable ({type(exc).__name__}: {exc}); "
              f"run 'uv run alienbank-index' once the embedding model is reachable.")
    yield


app = FastAPI(title="AlienBank", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=APP.secret_key, session_cookie="alienbank_session")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Stamp a correlation id on each request so all its log events link up."""
    request.state.request_id = uuid.uuid4().hex
    return await call_next(request)


# ---------------------------------------------------------------------------
# Logging helpers — turn a request + actor into the safe, shared log fields.
# Nothing here carries PII: identity is the pseudonym (actor.ref), never a name.
# ---------------------------------------------------------------------------
def _route_template(request: Request) -> str:
    """The route PATTERN (e.g. /api/accounts/{account_number}/balance), never the
    concrete path — so an account number in the URL never lands in a log."""
    route = request.scope.get("route")
    return getattr(route, "path", request.url.path)


def _log_ctx(request: Request, actor: bank.Actor | None = None) -> dict:
    """Common PII-free fields for a security event drawn from the request."""
    return {
        "actor_ref": actor.ref if actor else None,
        "role": actor.role if actor else None,
        "session_id": request.session.get("sid"),
        "source_ip": request.client.host if request.client else None,
        "http_method": request.method,
        "http_path": _route_template(request),
        "level": _session_level(request),
        "request_id": getattr(request.state, "request_id", None),
    }


# ---------------------------------------------------------------------------
# Session helpers — the ONLY source of caller identity for the API.
# ---------------------------------------------------------------------------
def current_actor(request: Request) -> bank.Actor | None:
    username = request.session.get("username")
    if not username:
        return None
    return bank.get_actor(username)


def require_actor(request: Request) -> bank.Actor:
    actor = current_actor(request)
    if actor is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return actor


def _bank_error_response(exc: bank.BankError) -> JSONResponse:
    status = {
        bank.AuthError: 401,
        bank.Forbidden: 403,
        bank.NotFound: 404,
        bank.InsufficientFunds: 400,
    }.get(type(exc), 400)
    return JSONResponse({"error": type(exc).__name__, "message": str(exc)}, status_code=status)


def _log_and_error(request: Request, actor: bank.Actor, action: str,
                   exc: bank.BankError, category: str = "data_access") -> JSONResponse:
    """Log a failed banking operation, then return the normal error response.

    A ``Forbidden`` on an account operation is the cross-tenant/BOLA signal: the
    caller tried to touch an object they don't own and the secure core stopped
    them. We flag it (``security.cross_tenant``, ``blocked``) so the SIEM can
    alert on IDOR probing — without logging *which* account was targeted.
    """
    resp = _bank_error_response(exc)
    is_forbidden = isinstance(exc, bank.Forbidden)
    outcome = "blocked" if is_forbidden else "failure"
    severity = "warning" if is_forbidden else "notice"
    security = {"cross_tenant": True, "attack": True} if is_forbidden else None
    seclog.security_event(
        category=category, action=action, outcome=outcome, severity=severity,
        http_status=resp.status_code, security=security,
        message=f"{action} denied ({type(exc).__name__})",
        **_log_ctx(request, actor),
    )
    return resp


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    actor = current_actor(request)
    if actor is None:
        return RedirectResponse("/login")
    return RedirectResponse("/dashboard")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    # Non-reversible per-username correlation token. Derived identically whether
    # or not the account exists, so it never reveals account existence, and never
    # carries the raw username (PII, and often a pasted password on failure).
    target = seclog.target_ref(username, APP.secret_key)
    try:
        actor = bank.authenticate(username, password)
    except bank.AuthError:
        # Failed login. We log the ATTEMPT with the target token (for brute-force
        # / stuffing detection) but never the submitted username or password.
        fails, distinct = _auth_fail_track(request.client.host if request.client else None, target)
        seclog.security_event(
            category="authentication", action="login", outcome="failure",
            severity="warning", http_status=401, target_ref=target,
            message="Login failed: invalid credentials",
            **_log_ctx(request),
        )
        # Observability marker (no block): burst from one source crossed the
        # threshold. distinct==1 => brute force on one account; distinct>1 =>
        # credential stuffing / spraying across accounts.
        if fails >= AUTH_FAIL_MAX:
            seclog.security_event(
                category="authentication", action="login_throttle", outcome="blocked",
                severity="critical" if distinct == 1 else "warning", http_status=401,
                target_ref=target if distinct == 1 else None,
                security={"attack": True, "owasp_id": "LLM10", "blocked_by": "auth-throttle"},
                message=("Brute-force burst on one account" if distinct == 1
                         else "Credential-stuffing burst across accounts"),
                **_log_ctx(request),
            )
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid username or password"}, status_code=401
        )
    request.session["username"] = actor.username
    _session_id(request)  # ensure a session id exists for correlation
    # Success carries BOTH the authenticated actor.ref and the target_ref, so the
    # SIEM can chain "failure burst on target X -> success for target X" = takeover.
    seclog.security_event(
        category="authentication", action="login", outcome="success",
        severity="info", http_status=303, target_ref=target, message="Login succeeded",
        **_log_ctx(request, actor),
    )
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request):
    actor = current_actor(request)
    seclog.security_event(
        category="authentication", action="logout", outcome="success",
        message="Logout succeeded", **_log_ctx(request, actor),
    )
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    actor = current_actor(request)
    if actor is None:
        return RedirectResponse("/login")
    level = _session_level(request)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "actor": actor,
            "is_teller": actor.role == "teller",
            "provider": provider_summary(),
            "secure_agent": APP.secure_agent,
            "level": level,
            "level_name": spec(level).name,
            "levels": [
                {"level": s.level, "name": s.name, "tagline": s.tagline}
                for s in LEVELS.values()
            ],
        },
    )


def _session_level(request: Request) -> int:
    """The per-session difficulty level (defaults to the app's configured level)."""
    lvl = request.session.get("level", APP.level)
    try:
        return max(MIN_LEVEL, min(MAX_LEVEL, int(lvl)))
    except (TypeError, ValueError):
        return APP.level


# ---------------------------------------------------------------------------
# REST API (hardened) — all identity comes from the session.
# ---------------------------------------------------------------------------
@app.get("/api/me")
def api_me(actor: bank.Actor = Depends(require_actor)):
    return {"username": actor.username, "full_name": actor.full_name, "role": actor.role}


@app.get("/api/accounts")
def api_accounts(request: Request, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.list_my_accounts_secure(actor)
        seclog.security_event(
            category="data_access", action="list_accounts", outcome="success",
            http_status=200, message="Listed own accounts",
            **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "list_accounts", exc)


@app.get("/api/accounts/{account_number}/balance")
def api_balance(account_number: str, request: Request, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.get_balance_secure(actor, account_number)
        seclog.security_event(
            category="data_access", action="get_balance", outcome="success",
            http_status=200, message="Read account balance",
            **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "get_balance", exc)


@app.get("/api/accounts/{account_number}/statement")
def api_statement(account_number: str, request: Request, limit: int | None = None, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.get_statement_secure(actor, account_number, limit)
        seclog.security_event(
            category="data_access", action="get_statement", outcome="success",
            http_status=200, message="Read account statement",
            **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "get_statement", exc)


class TransferBody(BaseModel):
    from_account: str
    to_account: str
    amount: float
    note: str = ""


@app.post("/api/transfer")
def api_transfer(body: TransferBody, request: Request, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.transfer_secure(actor, body.from_account, body.to_account, body.amount, body.note)
        seclog.security_event(
            category="transaction", action="transfer", outcome="success",
            http_status=200, amount=body.amount, security={"state_changing": True},
            message="Funds transfer executed", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "transfer", exc, category="transaction")


@app.get("/api/name-enquiry/{account_number}")
def api_name_enquiry(account_number: str, request: Request, actor: bank.Actor = Depends(require_actor)):
    """Confirm-payee: returns only the destination account holder's name."""
    try:
        result = bank.name_enquiry(actor, account_number)
        seclog.security_event(
            category="data_access", action="name_enquiry", outcome="success",
            http_status=200, message="Payee name enquiry", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "name_enquiry", exc)


@app.get("/api/recent-recipients")
def api_recent_recipients(request: Request, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.recent_recipients_secure(actor)
        seclog.security_event(
            category="data_access", action="recent_recipients", outcome="success",
            http_status=200, message="Listed recent recipients", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "recent_recipients", exc)


# --- Loans (hardened) — identity from the session; limit cached 10 days ---
@app.get("/api/loans/limit")
def api_loan_limit(request: Request, refresh: bool = False, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.loan_limit_secure(actor, refresh=refresh)
        seclog.security_event(
            category="data_access", action="loan_limit", outcome="success",
            http_status=200, message="Checked loan limit", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "loan_limit", exc)


@app.get("/api/loans")
def api_list_loans(request: Request, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.list_loans_secure(actor)
        seclog.security_event(
            category="data_access", action="list_loans", outcome="success",
            http_status=200, message="Listed loans", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "list_loans", exc)


class LoanApplyBody(BaseModel):
    account_number: str
    amount: float
    note: str = ""


@app.post("/api/loans/apply")
def api_apply_loan(body: LoanApplyBody, request: Request, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.apply_loan_secure(actor, body.account_number, body.amount, body.note)
        seclog.security_event(
            category="transaction", action="loan_apply", outcome="success",
            http_status=200, amount=body.amount, security={"state_changing": True},
            message="Loan application submitted", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "loan_apply", exc, category="transaction")


class LoanRepayBody(BaseModel):
    reference: str
    amount: float
    account_number: str | None = None


@app.post("/api/loans/repay")
def api_repay_loan(body: LoanRepayBody, request: Request, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.repay_loan_secure(actor, body.reference, body.amount, body.account_number)
        seclog.security_event(
            category="transaction", action="loan_repay", outcome="success",
            http_status=200, amount=body.amount, security={"state_changing": True},
            message="Loan repayment executed", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "loan_repay", exc, category="transaction")


@app.get("/api/loans/{reference}/statement")
def api_loan_statement(reference: str, request: Request, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.loan_statement_secure(actor, reference)
        seclog.security_event(
            category="data_access", action="loan_statement", outcome="success",
            http_status=200, message="Read loan statement", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "loan_statement", exc)


# --- Teller-only endpoints (role enforced in the secure core) ---
class DepositBody(BaseModel):
    account_number: str
    amount: float
    note: str = ""


@app.post("/api/teller/deposit")
def api_deposit(body: DepositBody, request: Request, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.deposit_secure(actor, body.account_number, body.amount, body.note)
        seclog.security_event(
            category="transaction", action="teller_deposit", outcome="success",
            http_status=200, amount=body.amount, security={"state_changing": True},
            message="Teller deposit executed", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "teller_deposit", exc, category="transaction")


@app.get("/api/teller/customer/{username}/accounts")
def api_customer_accounts(username: str, request: Request, actor: bank.Actor = Depends(require_actor)):
    if actor.role != "teller":
        # A non-teller reaching a teller-only endpoint is the privilege-escalation
        # signal (LLM06) — flag it, without logging the target username.
        seclog.security_event(
            category="authorization", action="teller_customer_accounts", outcome="blocked",
            severity="warning", http_status=403,
            security={"attack": True, "owasp_id": "LLM06"},
            message="Non-teller hit teller-only endpoint", **_log_ctx(request, actor),
        )
        return _bank_error_response(bank.Forbidden("Tellers only"))
    try:
        result = bank.list_accounts_for_username_raw(username)
        seclog.security_event(
            category="data_access", action="teller_customer_accounts", outcome="success",
            http_status=200, message="Teller listed customer accounts", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "teller_customer_accounts", exc)


class ProfileBody(BaseModel):
    username: str
    full_name: str | None = None
    email: str | None = None
    phone: str | None = None


@app.post("/api/teller/profile")
def api_profile(body: ProfileBody, request: Request, actor: bank.Actor = Depends(require_actor)):
    try:
        result = bank.update_profile_secure(
            actor, body.username, full_name=body.full_name, email=body.email, phone=body.phone
        )
        seclog.security_event(
            category="transaction", action="teller_update_profile", outcome="success",
            http_status=200, security={"state_changing": True},
            message="Teller updated customer profile", **_log_ctx(request, actor),
        )
        return result
    except bank.BankError as exc:
        return _log_and_error(request, actor, "teller_update_profile", exc, category="transaction")


# ---------------------------------------------------------------------------
# Difficulty level (runtime-switchable per session)
# ---------------------------------------------------------------------------
class LevelBody(BaseModel):
    level: int


@app.get("/api/level")
def api_get_level(request: Request, _: bank.Actor = Depends(require_actor)):
    lvl = _session_level(request)
    return {"level": lvl, "name": spec(lvl).name, "tagline": spec(lvl).tagline}


@app.post("/api/level")
def api_set_level(body: LevelBody, request: Request, actor: bank.Actor = Depends(require_actor)):
    lvl = max(MIN_LEVEL, min(MAX_LEVEL, body.level))
    request.session["level"] = lvl
    # Switching level starts a fresh challenge — drop any server-held history.
    _HISTORY.pop(request.session.get("sid", ""), None)
    _PENDING_XFER.pop(request.session.get("sid", ""), None)
    seclog.security_event(
        category="admin", action="level_change", outcome="success", severity="notice",
        http_status=200, message="Difficulty level changed", **_log_ctx(request, actor),
    )
    return {"level": lvl, "name": spec(lvl).name, "tagline": spec(lvl).tagline}


# ---------------------------------------------------------------------------
# Reset — rebuild the whole database from the canonical seed dataset.
# ---------------------------------------------------------------------------
@app.post("/api/reset")
def api_reset(request: Request, actor: bank.Actor = Depends(require_actor)):
    reset_db()
    seclog.security_event(
        category="admin", action="db_reset", outcome="success", severity="warning",
        http_status=200, message="Database reset to seed data", **_log_ctx(request, actor),
    )
    return {"status": "ok", "message": "Database reset to seed data."}


# ---------------------------------------------------------------------------
# Chat (bridges to the vulnerable agent layer)
# ---------------------------------------------------------------------------
class ChatBody(BaseModel):
    message: str
    history: list[dict] = []


def _session_id(request: Request) -> str:
    """Opaque id for this browser session's server-held chat history."""
    sid = request.session.get("sid")
    if not sid:
        sid = uuid.uuid4().hex
        request.session["sid"] = sid
    return sid


def _rate_ok(sid: str) -> bool:
    """Sliding-window per-session throttle. Returns False when over the limit."""
    now = time.monotonic()
    q = _RATE[sid]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_MAX:
        return False
    q.append(now)
    return True


@app.post("/api/chat")
async def api_chat(body: ChatBody, request: Request, actor: bank.Actor = Depends(require_actor)):
    level = _session_level(request)
    sp = spec(level)
    sid = _session_id(request)

    # LLM10 — rate limit + message size cap (levels where spec.rate_limited).
    if sp.rate_limited:
        if not _rate_ok(sid):
            seclog.security_event(
                category="abuse", action="chat", outcome="blocked", severity="notice",
                http_status=429, secure_agent=APP.secure_agent,
                security={"attack": True, "owasp_id": "LLM10", "blocked_by": "rate-limit"},
                message="Chat rate limit exceeded", **_log_ctx(request, actor),
            )
            return JSONResponse(
                {"reply": "You're sending messages too fast. Please wait a moment and try again.",
                 "history": [], "level": level, "blocked_by": "rate-limit", "guardrails": [],
                 "tool_calls": []},
                status_code=429,
            )
        if len(body.message) > MAX_MESSAGE_CHARS:
            seclog.security_event(
                category="abuse", action="chat", outcome="blocked", severity="notice",
                http_status=413, secure_agent=APP.secure_agent,
                security={"attack": True, "owasp_id": "LLM10", "blocked_by": "input-cap"},
                message="Chat message exceeded size cap", **_log_ctx(request, actor),
            )
            return JSONResponse(
                {"reply": f"Message too long (max {MAX_MESSAGE_CHARS} characters).",
                 "history": [], "level": level, "blocked_by": "input-cap", "guardrails": [],
                 "tool_calls": []},
                status_code=413,
            )

    # Memory poisoning — choose the history source by level.
    # L2+: server-held history (client history ignored -> cannot be forged).
    # L0/L1: trust client history (the vulnerable, teachable behaviour), but cap size.
    if sp.server_history:
        history = _HISTORY.get(sid, [])
    else:
        history = list(body.history or [])[-MAX_CLIENT_HISTORY:]

    # HITL — if a transfer is awaiting confirmation and the user affirms, carry
    # the approval into this turn so the agent can commit it.
    confirmed = None
    pending = _PENDING_XFER.get(sid)
    if pending and _is_affirmation(body.message):
        confirmed = pending
    if pending and not _is_affirmation(body.message):
        # A non-affirmation cancels the pending transfer.
        _PENDING_XFER.pop(sid, None)

    try:
        result = await chat.run_chat(actor, history, body.message, level=level,
                                     confirmed_transfer=confirmed)
    except Exception as exc:  # noqa: BLE001 — return a readable error to the widget
        seclog.security_event(
            category="agent_turn", action="chat", outcome="failure", severity="notice",
            http_status=200, secure_agent=APP.secure_agent,
            message="Agent turn errored", **_log_ctx(request, actor),
        )
        return JSONResponse(
            {"reply": f"[agent error] {type(exc).__name__}: {exc}", "history": body.history},
            status_code=200,
        )

    # Emit the PII-free agent-turn event to the SIEM — at ALL levels (unlike the
    # local audit trail, which is L2+). Carries only verdicts and an amount band,
    # never the user's message, the amounts, or the account numbers.
    try:
        owned = [a["account_number"] for a in bank.list_my_accounts_secure(actor)]
    except Exception:  # noqa: BLE001 — logging must not break the request path
        owned = []
    proj = audit.security_projection(
        level=level, blocked_by=result.get("blocked_by"),
        guardrails=result.get("guardrails", []), tool_calls=result.get("tool_calls", []),
        actor_username=actor.username, actor_role=actor.role, owned_accounts=owned,
    )
    seclog.security_event(
        category="agent_turn", action="chat", http_status=200,
        secure_agent=APP.secure_agent, **proj, **_log_ctx(request, actor),
    )

    # Track / clear the pending-confirmation transfer for the next turn.
    if result.get("pending_transfer"):
        _PENDING_XFER[sid] = result["pending_transfer"]
    elif confirmed:
        _PENDING_XFER.pop(sid, None)  # it was just committed

    if sp.server_history:
        # Persist the authoritative history server-side; don't echo it to the client.
        _HISTORY[sid] = (result.get("history") or [])[-MAX_SERVER_HISTORY:]
        result["history"] = []
    return result
