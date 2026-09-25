"""Security event logging — the PII-free stream that ships to the SIEM.

Every security-relevant thing that happens (a login, an account read, a
transfer, a blocked cross-tenant attempt) is emitted here as **one structured
JSON line to stdout**. In a container that stdout is what a Fluent Bit sidecar
tails and forwards to the SIEM; locally it is what you see in the terminal.

The load-bearing rule (see SECURITY_LOGGING_PLAN.md §0): **no PII, no financial
data ever leaves this module.** We log *verdicts and non-identifying handles*,
never names, account numbers, amounts, or message text. Two mechanisms enforce
it:

* **Omit at the source** — callers pass the pseudonym (``actor.ref``), a verdict
  flag, or an ``amount_band`` — never the raw value.
* **Allow-list serializer** — :func:`security_event` copies only known-safe keys
  into the emitted record; anything else is dropped. So a careless future call
  cannot leak a sensitive field into the SIEM stream.

The canonical envelope (ECS-inspired, vendor-neutral):

    { "@timestamp", "event": {category, action, outcome, severity, id},
      "actor": {ref, role}, "target_ref", "session_id", "source": {ip},
      "http": {method, path, status}, "labels": {level, secure_agent},
      "amount_band", "security": {...}, "trace": {request_id}, "message" }

``target_ref`` is the login-target correlation token (:func:`target_ref`) — used
on authentication events where there is no authenticated ``actor.ref`` yet, so
brute-force against one account is still detectable without logging the username.

Nothing here may raise into the request path (mirrors ``audit.record``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone

LOGGER_NAME = "alienbank.security"
_log = logging.getLogger(LOGGER_NAME)

# --- The allow-list. Only these top-level keys are ever serialized. ----------
# A key not in this set is dropped by _project(), even if a caller passes it —
# the structural guarantee that PII cannot leak by accident.
_ALLOWED_TOP = {
    "@timestamp", "event", "actor", "session_id", "source", "http",
    "labels", "amount_band", "security", "trace", "message", "target_ref",
}
_ALLOWED_EVENT = {"category", "action", "outcome", "severity", "id"}
_ALLOWED_ACTOR = {"ref", "role"}
_ALLOWED_SOURCE = {"ip"}
_ALLOWED_HTTP = {"method", "path", "status"}
_ALLOWED_LABELS = {"level", "secure_agent"}
_ALLOWED_SECURITY = {
    "attack", "owasp_id", "bypassed_layers", "blocked_by",
    "cross_tenant", "state_changing", "canary_leak",
}
_ALLOWED_TRACE = {"request_id"}

_SUBFILTERS = {
    "event": _ALLOWED_EVENT,
    "actor": _ALLOWED_ACTOR,
    "source": _ALLOWED_SOURCE,
    "http": _ALLOWED_HTTP,
    "labels": _ALLOWED_LABELS,
    "security": _ALLOWED_SECURITY,
    "trace": _ALLOWED_TRACE,
}

VALID_OUTCOMES = {"success", "failure", "blocked", "pending"}
VALID_SEVERITIES = {"info", "notice", "warning", "critical"}


def amount_band(amount: float | int | None) -> str | None:
    """Bucket a money value into a categorical band — never the exact amount.

    Bands: ``<1k`` | ``1k-10k`` | ``>10k``. Returns ``None`` for a missing value.
    This is how a large-transfer rule fires without the amount touching the log.
    """
    if amount is None:
        return None
    try:
        a = abs(float(amount))
    except (TypeError, ValueError):
        return None
    if a < 1_000:
        return "<1k"
    if a <= 10_000:
        return "1k-10k"
    return ">10k"


def target_ref(username: str | None, secret: str) -> str | None:
    """A stable, non-reversible correlation token for a login *target*.

    On a failed login there is no authenticated actor — and thus no
    ``actor.ref`` pseudonym — yet we still need to answer "is one account being
    brute-forced?" vs "is one source spraying many accounts?". This derives a
    per-username token that is:

    * **Stable** — same submitted username always maps to the same token, so a
      single-account attack is visible even when distributed across many IPs.
    * **Enumeration-safe** — computed identically for real *and* nonexistent
      usernames, so it never reveals whether an account exists.
    * **Non-reversible** without ``secret`` — the raw username (which is PII and
      may accidentally be a pasted password) never enters the log.

    Case/space-normalized so ``Ana``, ``ana `` and ``ana`` collapse to one token.
    Returns ``None`` for an empty username. Never raises.

    Caveat (see SECURITY_LOGGING_PLAN.md §3.6): AlienBank's user space is small,
    so an adversary who compromises *both* the log store *and* ``secret`` could
    brute-force tokens back to usernames. Accepted for this pre-auth-only case;
    the log store must stay access-controlled regardless.
    """
    try:
        norm = (username or "").strip().lower()
        if not norm:
            return None
        return hmac.new(secret.encode("utf-8"), norm.encode("utf-8"),
                        hashlib.sha256).hexdigest()[:16]
    except Exception:  # noqa: BLE001 — logging must never break the request path
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _project(record: dict) -> dict:
    """Copy only allow-listed keys into a clean record (drops everything else)."""
    out: dict = {}
    for key, val in record.items():
        if key not in _ALLOWED_TOP:
            continue  # unknown top-level key -> dropped (PII safety net)
        sub = _SUBFILTERS.get(key)
        if sub is not None and isinstance(val, dict):
            out[key] = {k: v for k, v in val.items() if k in sub and v is not None}
        elif val is not None:
            out[key] = val
    return out


def security_event(
    *,
    category: str,
    action: str,
    outcome: str,
    severity: str = "info",
    actor_ref: str | None = None,
    role: str | None = None,
    target_ref: str | None = None,
    session_id: str | None = None,
    source_ip: str | None = None,
    http_method: str | None = None,
    http_path: str | None = None,
    http_status: int | None = None,
    level: int | None = None,
    secure_agent: bool | None = None,
    amount: float | int | None = None,
    security: dict | None = None,
    request_id: str | None = None,
    message: str | None = None,
) -> dict:
    """Build, emit (JSON → stdout), and return one PII-free security event.

    Callers pass only safe values: ``actor_ref`` is the pseudonym (never the
    username), ``amount`` is bucketed to a band here (never logged raw), and
    ``message`` must be a fixed/templated string with no user text. Never raises.
    """
    record = {
        "@timestamp": _now(),
        "event": {
            "id": uuid.uuid4().hex,
            "category": category,
            "action": action,
            "outcome": outcome if outcome in VALID_OUTCOMES else "info",
            "severity": severity if severity in VALID_SEVERITIES else "info",
        },
        "actor": {"ref": actor_ref, "role": role},
        "target_ref": target_ref,
        "session_id": session_id,
        "source": {"ip": source_ip},
        "http": {"method": http_method, "path": http_path, "status": http_status},
        "labels": {"level": level, "secure_agent": secure_agent},
        "amount_band": amount_band(amount),
        "security": security or None,
        "trace": {"request_id": request_id},
        "message": message,
    }
    clean = _project(record)
    try:
        _log.info(json.dumps(clean, default=str, sort_keys=False))
    except Exception:  # noqa: BLE001 — logging must never break the request path
        pass
    return clean
