"""Audit logging for the agent — an append-only JSONL forensic trail.

Enabled at levels where ``spec.audit_log`` is true (L2+). Each chat turn writes
one JSON line that reconstructs the *security story* of that turn: who acted, at
what level, which defensive layers were active, which the attack got **past**,
which single layer (if any) **stopped** it, and — crucially — whether a
state-changing or cross-tenant action actually landed. This is the difference
between "the model refused" and "I fully drove the assistant to move another
customer's money and it was stopped at commit by a server-side check (D3)".

That distinction is the whole point of the lab, so the trail records it
explicitly per turn:

* ``outcome``    — compromise | blocked_at_tool | refused_pre_input |
                   sensitive_action | awaiting_confirmation | clean
* ``attack``     — did this turn look like an attack at all?
* ``bypassed``   — layers that ran and let it through
* ``blocked_by`` — the one layer that stopped it (if any)
* ``narrative``  — a one-line human summary in plain English
* per tool call  — target account/user, cross-tenant?, state-changing?, and the
                   real result (executed / blocked / pending / error)

At L0/L1 there is no trail at all (the teachable gap — you cannot investigate an
attack after the fact); at L2+ every turn is recorded for review.

Location: ``data/audit.jsonl`` (override with ``ALIENBANK_AUDIT_PATH``).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ..config import DATA_DIR, INJECTION_GUARD
from .levels import spec

AUDIT_PATH = Path(os.getenv("ALIENBANK_AUDIT_PATH", str(DATA_DIR / "audit.jsonl")))

# Tools that move money / mutate state (a successful call here is real impact,
# not just a data read) and the subset only a teller may legitimately use.
_STATE_CHANGING = {"transfer_funds", "teller_deposit", "teller_update_profile",
                   "apply_for_loan", "repay_loan"}
_TELLER_ONLY = {"teller_deposit", "teller_update_profile"}
# Read tools that take a target account/username and can therefore cross tenants.
_CROSS_TENANT_READS = {"get_balance", "get_statement", "list_accounts_for_customer",
                       "check_loan_limit", "list_loans"}

# Which numbered defensive layers a level has active (for the "what was in the
# attacker's way" part of the story). Keyed to LevelSpec flags.
_LAYER_FLAGS = [
    ("D1", "d1_filter"), ("D2", "d2_classifier"), ("D3", "d3_tool_guard"),
    ("D4", "d4_output_firewall"), ("D5", "prompt_canary"),
    ("D6", "d6_injection_guard"),
]

# Guardrail layers that run PRE-LLM (before any tool call). A block by one of
# these with no tool calls is a "refused_pre_input" outcome, not "blocked_at_tool".
_PRE_INPUT_LAYERS = frozenset({"D1", "D2", "D6"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record(event: dict) -> None:
    """Append one audit event as a JSON line. Never raises into the request path."""
    try:
        event = {"ts": _now(), **event}
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
    except Exception:  # noqa: BLE001 — auditing must not break the app
        pass


def _parse(blob) -> dict | None:
    """Best-effort JSON parse of a tool argument/output string."""
    if isinstance(blob, dict):
        return blob
    if not isinstance(blob, str) or not blob.strip():
        return None
    try:
        val = json.loads(blob)
        return val if isinstance(val, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _analyze_call(call: dict, owned: set[str], actor_username: str, actor_role: str) -> dict:
    """Turn one raw tool call into a security-aware record.

    Works out what the call targeted (account / customer), whether that crosses a
    tenant boundary, whether it changes state, and what actually happened
    (executed / blocked-by-guardrail / pending confirmation / error).
    """
    name = call.get("name") or "?"
    args = _parse(call.get("arguments")) or {}
    out = _parse(call.get("output"))

    target_account = args.get("account_number") or args.get("from_account")
    target_username = args.get("username")

    cross_tenant = False
    if target_account and target_account not in owned:
        cross_tenant = True
    if target_username and actor_role != "teller" and target_username != actor_username:
        cross_tenant = True

    state_changing = name in _STATE_CHANGING
    teller_only = name in _TELLER_ONLY

    # Reconstruct the real result from the tool output.
    if out is None:
        outcome, error, message = "executed", None, None
    elif "error" in out:
        error = out.get("error")
        message = out.get("message")
        outcome = "blocked" if error == "GuardrailBlocked" else "error"
    elif out.get("status") == "pending_confirmation":
        outcome, error, message = "pending", None, out.get("message")
    else:
        outcome, error, message = "executed", None, None

    # Did this specific call cause impact worth flagging?
    impact = None
    if outcome == "executed":
        if state_changing and cross_tenant:
            impact = "cross_tenant_state_change"   # e.g. moved someone else's money
        elif state_changing:
            impact = "state_change"                # own-account money movement
        elif cross_tenant and name in _CROSS_TENANT_READS:
            impact = "cross_tenant_read"           # read someone else's data (BOLA/IDOR)

    return {
        "name": name,
        "arguments": args,
        "target_account": target_account,
        "target_username": target_username,
        "cross_tenant": cross_tenant,
        "state_changing": state_changing,
        "teller_only": teller_only,
        "outcome": outcome,          # executed | blocked | pending | error
        "impact": impact,            # None | cross_tenant_state_change | state_change | cross_tenant_read
        "error": error,
        "message": (message or "")[:200] or None,
    }


def _summarize(level: int, guardrails: list[dict], calls: list[dict], blocked_by) -> dict:
    """Derive the turn-level verdict, bypassed layers, and a plain-English story."""
    active = [code for code, flag in _LAYER_FLAGS if getattr(spec(level), flag)]
    # D6 is gated by BOTH the level spec AND the env toggle; if the toggle is off
    # it never runs, so don't claim it was "in the attacker's way" (which would
    # also mislabel it as bypassed). Same fail-open honesty as the guard itself.
    if "D6" in active and not INJECTION_GUARD.enabled:
        active.remove("D6")
    ran = {g.get("layer"): g for g in guardrails}

    executed = [c for c in calls if c["outcome"] == "executed"]
    compromises = [c for c in executed if c["impact"] and c["impact"].startswith("cross_tenant")]
    own_state = [c for c in executed if c["impact"] == "state_change"]
    pending = [c for c in calls if c["outcome"] == "pending"]

    # Did anything about this turn look like an attack?
    attack = (
        bool(blocked_by)
        or any(g.get("matched") for g in guardrails)
        or any(c["cross_tenant"] or c["teller_only"] for c in calls)
    )

    # "Bypassed" = layers an *attack* ran through without being stopped. A
    # legitimate request passing guardrails is not a bypass, so only surface this
    # for attack turns (avoids implying every clean request evaded the defenses).
    bypassed = [code for code in active if code in ran and not ran[code].get("blocked")] if attack else []

    # Classify the outcome, most-severe first.
    if compromises:
        outcome = "compromise"
    elif blocked_by:
        # A pre-LLM refusal (no tools ran) vs a block at the tool boundary.
        outcome = ("refused_pre_input" if not calls and blocked_by in _PRE_INPUT_LAYERS
                   else "blocked_at_tool")
    elif own_state:
        outcome = "sensitive_action"
    elif pending:
        outcome = "awaiting_confirmation"
    else:
        outcome = "clean"

    return {
        "outcome": outcome,
        "attack": attack,
        "active_layers": active,
        "bypassed": bypassed,
        "narrative": _narrative(outcome, bypassed, blocked_by, guardrails,
                                 compromises, own_state, pending),
    }


def _acct(c: dict) -> str:
    return c.get("target_account") or c.get("target_username") or "?"


def _narrative(outcome, bypassed, blocked_by, guardrails, compromises, own_state, pending) -> str:
    """One-line story matching how a reviewer would describe the turn."""
    ran = {g.get("layer"): g for g in guardrails}
    past = f" Bypassed {', '.join(bypassed)} first." if bypassed else ""

    if outcome == "compromise":
        c = compromises[0] if compromises else None
        if c and c["state_changing"]:
            amt = c["arguments"].get("amount")
            amt_s = f"KES {float(amt):,.2f} " if isinstance(amt, (int, float)) else ""
            return (f"COMPROMISE — drove the assistant to run {c['name']} for {amt_s}"
                    f"on {_acct(c)} (not the caller's) and it EXECUTED. No layer stopped it.{past}")
        if c:
            return (f"COMPROMISE — read {_acct(c)} (not the caller's) via {c['name']}; "
                    f"cross-tenant data disclosed.{past}")
        return f"COMPROMISE — cross-tenant access executed.{past}"

    if outcome in ("refused_pre_input", "blocked_at_tool"):
        g = ran.get(blocked_by, {})
        detail = g.get("detail") or ""
        matched = ", ".join(g.get("matched") or [])
        why = f": {detail}" + (f" [{matched}]" if matched else "")
        where = "before the model ran" if outcome == "refused_pre_input" else "at the tool boundary"
        return f"Attack stopped {where} by {blocked_by} ({g.get('name', blocked_by)}){why}.{past}"

    if outcome == "sensitive_action":
        c = own_state[0]
        amt = c["arguments"].get("amount")
        amt_s = f"KES {float(amt):,.2f} " if isinstance(amt, (int, float)) else ""
        return f"Executed {c['name']} for {amt_s}on the caller's own account {_acct(c)}."

    if outcome == "awaiting_confirmation":
        c = pending[0]
        return f"High-value {c['name']} deferred — awaiting explicit user confirmation (HITL)."

    return "Normal activity — no attack indicators, no cross-tenant or state-changing impact."


def record_turn(*, actor_username: str, actor_role: str, level: int, message: str,
                blocked_by, guardrails: list[dict], tool_calls: list[dict],
                owned_accounts: list[str] | None = None) -> None:
    """Record a single chat turn's security-relevant telemetry, as a story.

    ``owned_accounts`` are the caller's real account numbers (from the session),
    used to decide whether a tool call crossed a tenant boundary. Pass them from
    the request path where the authenticated actor is known.
    """
    owned = set(owned_accounts or [])
    calls = [_analyze_call(c, owned, actor_username, actor_role) for c in (tool_calls or [])]
    grs = [
        {"layer": g.get("layer"), "name": g.get("name"), "blocked": g.get("blocked"),
         "detail": g.get("detail"), "matched": g.get("matched") or []}
        for g in (guardrails or [])
    ]
    summary = _summarize(level, grs, calls, blocked_by)
    record({
        "kind": "chat_turn",
        "actor": actor_username,
        "role": actor_role,
        "level": level,
        # Truncate the raw message so the log stays readable / bounded.
        "message": (message or "")[:500],
        "outcome": summary["outcome"],
        "attack": summary["attack"],
        "blocked_by": blocked_by,
        "bypassed": summary["bypassed"],
        "active_layers": summary["active_layers"],
        "narrative": summary["narrative"],
        "guardrails": grs,
        "tool_calls": calls,
    })


# ---------------------------------------------------------------------------
# PII-free projection for the SIEM stream (seclog).
#
# The local audit trail above is L2+ only. The SIEM, by contrast, must see every
# agent turn at ALL levels (SECURITY_LOGGING_PLAN.md §7) — but carrying only
# verdicts and bands, never the message text, amounts, or account numbers. This
# reuses the SAME verdict logic (`_analyze_call` / `_summarize`) so there is one
# source of truth; it just emits flags instead of raw values.
# ---------------------------------------------------------------------------

# Map the rich audit outcome onto seclog's (outcome, severity) vocabulary.
# seclog outcomes: success | failure | blocked | pending.
_SIEM_OUTCOME = {
    "compromise":            ("success", "critical"),  # the attack's action landed
    "blocked_at_tool":       ("blocked", "warning"),
    "refused_pre_input":     ("blocked", "warning"),
    "sensitive_action":      ("success", "notice"),
    "awaiting_confirmation": ("pending", "info"),
    "clean":                 ("success", "info"),
}

# Templated, non-identifying one-liners — NEVER the narrative (which embeds the
# amount and account number). One fixed string per outcome.
_SIEM_MESSAGE = {
    "compromise":            "Agent turn: cross-tenant/state-changing action executed",
    "blocked_at_tool":       "Agent turn: attack stopped at the tool boundary",
    "refused_pre_input":     "Agent turn: refused before the model ran",
    "sensitive_action":      "Agent turn: own-account state change executed",
    "awaiting_confirmation": "Agent turn: high-value action awaiting confirmation",
    "clean":                 "Agent turn: no attack indicators",
}


def security_projection(*, level: int, blocked_by, guardrails: list[dict],
                        tool_calls: list[dict], actor_username: str, actor_role: str,
                        owned_accounts: list[str] | None = None) -> dict:
    """Project one chat turn onto the PII-free fields ``seclog.security_event`` wants.

    Returns a dict ready to splat: ``outcome``, ``severity``, ``amount`` (the
    largest executed state-changing amount, bucketed to a band by seclog),
    ``message`` (a fixed templated string), and a ``security`` sub-object of
    verdict flags. Carries NO message text, account numbers, or exact amounts.
    Never raises.
    """
    try:
        owned = set(owned_accounts or [])
        calls = [_analyze_call(c, owned, actor_username, actor_role) for c in (tool_calls or [])]
        grs = [
            {"layer": g.get("layer"), "name": g.get("name"), "blocked": g.get("blocked"),
             "detail": g.get("detail"), "matched": g.get("matched") or []}
            for g in (guardrails or [])
        ]
        summary = _summarize(level, grs, calls, blocked_by)
        audit_outcome = summary["outcome"]

        cross_tenant = any(c["cross_tenant"] for c in calls)
        state_changing = any(c["state_changing"] for c in calls)
        # D5 caught a system-prompt/canary leak in the output (LLM07).
        canary_leak = any(g.get("layer") == "D5" and g.get("blocked") for g in grs)

        # OWASP tag, most-severe interpretation first.
        if canary_leak:
            owasp = "LLM07"
        elif audit_outcome == "compromise":
            owasp = "LLM06" if cross_tenant and state_changing else "LLM01"
        elif summary["attack"]:
            owasp = "LLM01"
        else:
            owasp = None

        # Largest executed state-changing amount -> band (seclog buckets it).
        amounts = [
            c["arguments"].get("amount") for c in calls
            if c["outcome"] == "executed" and c["state_changing"]
            and isinstance(c["arguments"].get("amount"), (int, float))
        ]
        amount = max((abs(a) for a in amounts), default=None)

        outcome, severity = _SIEM_OUTCOME.get(audit_outcome, ("success", "info"))
        return {
            "outcome": outcome,
            "severity": severity,
            "amount": amount,
            "message": _SIEM_MESSAGE.get(audit_outcome, "Agent turn: processed"),
            "security": {
                "attack": summary["attack"],
                "owasp_id": owasp,
                "bypassed_layers": summary["bypassed"] or None,
                "blocked_by": blocked_by,
                "cross_tenant": cross_tenant,
                "state_changing": state_changing,
                "canary_leak": canary_leak,
            },
        }
    except Exception:  # noqa: BLE001 — projection must never break the request path
        return {"outcome": "success", "severity": "info", "amount": None,
                "message": "Agent turn: projection unavailable", "security": None}


def tail(n: int = 20) -> list[dict]:
    """Return the last ``n`` audit events (for a CLI / review view)."""
    if not AUDIT_PATH.exists():
        return []
    lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()[-n:]
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except Exception:  # noqa: BLE001
            continue
    return out


# Glyphs that make the outcome column scannable in a terminal.
_OUTCOME_GLYPH = {
    "compromise": "🔴 COMPROMISE",
    "blocked_at_tool": "🟢 BLOCKED",
    "refused_pre_input": "🟢 REFUSED",
    "sensitive_action": "🟠 ACTION",
    "awaiting_confirmation": "🟡 PENDING",
    "clean": "⚪ clean",
}


def _fmt_event(e: dict) -> str:
    """Render one audit event as a short incident report."""
    lines = []
    tag = _OUTCOME_GLYPH.get(e.get("outcome", ""), e.get("outcome", "—"))
    lines.append(f"{e.get('ts','')}  L{e.get('level')}  {e.get('actor')}({e.get('role')})  {tag}")
    lines.append(f"    msg     : {e.get('message','')[:110]}")
    active = ", ".join(e.get("active_layers", [])) or "—"
    bypassed = ", ".join(e.get("bypassed", [])) or "—"
    lines.append(f"    layers  : active [{active}]   bypassed [{bypassed}]   blocked_by {e.get('blocked_by') or '—'}")
    for c in e.get("tool_calls", []):
        # Support both the new enriched shape and any legacy line.
        if "outcome" in c:
            flags = []
            if c.get("cross_tenant"):
                flags.append("CROSS-TENANT")
            if c.get("state_changing"):
                flags.append("state-changing")
            tgt = c.get("target_account") or c.get("target_username") or "—"
            extra = f"  [{', '.join(flags)}]" if flags else ""
            lines.append(f"    tool    : {c['name']}({tgt}) -> {c['outcome']}{extra}")
        else:
            lines.append(f"    tool    : {c.get('name')} (error={c.get('error')})")
    if e.get("narrative"):
        lines.append(f"    story   : {e['narrative']}")
    return "\n".join(lines)


def main() -> None:
    """CLI: `alienbank-audit [N]` — show the last N audit events as incident reports."""
    import sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 20
    events = tail(n)
    if not events:
        print(f"No audit trail yet at {AUDIT_PATH} (only levels 2+ log).")
        return

    attacks = sum(1 for e in events if e.get("attack"))
    compromised = sum(1 for e in events if e.get("outcome") == "compromise")
    stopped = sum(1 for e in events if e.get("outcome") in ("blocked_at_tool", "refused_pre_input"))
    print(f"Last {len(events)} audit events ({AUDIT_PATH})")
    print(f"  attacks seen: {attacks}   stopped by a defense: {stopped}   COMPROMISED: {compromised}\n")
    for e in events:
        print(_fmt_event(e))
        print()
