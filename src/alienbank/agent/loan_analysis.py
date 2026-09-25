"""LLM-driven loan-eligibility analysis.

A customer's loan limit is not a fixed multiple of salary — it is produced by
feeding the customer's FULL statement to the LLM and asking it to reason about
affordability: how much income is recurring, how volatile spending is, whether
earnings are trending up or down, and therefore how large a principal the person
can service and what monthly repayment is realistic.

The result is cached (see ``bank.loan_limit_*``) and reused for 10 days, so this
expensive analysis runs at most once per customer per window.

Everything the model sees here is the customer's OWN statement (data), and the
output is a small structured JSON object — not tool calls — so this module does
not itself expose the agentic vulnerability. The intentional weaknesses live in
how the *limit is stored and enforced* (bank.py) and in the agent tools that a
learner can talk into bypassing it (tools.py).
"""
from __future__ import annotations

import json
import re

from ..config import LLM
from .provider import analysis_client

# Bounds the engine will never cross regardless of what the model returns — keeps
# a hallucinating or jailbroken model from proposing an absurd limit. These are
# lab-scale numbers (KES).
_MIN_LIMIT = 0.0
_MAX_LIMIT = 2_000_000.0

_TRENDS = {"increasing", "stable", "declining"}

_SYSTEM = """You are AlienBank's loan underwriting analyst. You are given one
customer's transaction statement and must assess how much they can safely borrow.

Reason about:
- recurring INCOME (salary, regular business receipts) vs one-off credits,
- essential recurring OUTGOINGS (rent, utilities, subscriptions, fees),
- disposable income left after outgoings and its volatility,
- the TREND of earnings over the statement window: are credits growing,
  flat, or shrinking over time?

From that, decide:
- monthly_repayment: an affordable monthly repayment (roughly a third of stable
  disposable income; less if income is volatile or declining),
- limit: the maximum loan PRINCIPAL you would approve (a prudent multiple of the
  affordable monthly repayment, typically 6-12x depending on trend/stability),
- recommended: the principal you would actually advise this customer to take
  (<= limit), erring conservative,
- trend: exactly one of "increasing", "stable", "declining",
- rationale: one or two sentences a customer can understand.

If earnings are DECLINING, reduce the limit noticeably. If clearly INCREASING and
stable, you may be more generous. All amounts are in KES.

Reply with ONLY a JSON object, no prose, no code fences:
{"limit": <number>, "recommended": <number>, "monthly_repayment": <number>,
 "trend": "<increasing|stable|declining>", "rationale": "<text>"}"""


def _statement_digest(statement: dict) -> str:
    """Render the WHOLE-USER financial picture compactly for the model.

    The limit is tied to the customer, so the digest lists every account the
    customer holds (with balances and a combined total) followed by the union of
    transactions across all of them, each tagged with its account.
    """
    accounts = statement.get("accounts")
    if not accounts:  # backward-compat: single-account shape
        acct = statement.get("account", {})
        accounts = [acct] if acct else []

    lines = [f"Customer '{statement.get('username','?')}' — whole-relationship view "
             f"across {len(accounts)} account(s)."]
    for a in accounts:
        lines.append(
            f"- Account {a.get('account_number','?')} ({a.get('account_type','?')}, "
            f"{a.get('nickname','')}): balance KES {a.get('balance', 0):,.2f}")
    total = statement.get("total_balance")
    if total is not None:
        lines.append(f"Total balance across all accounts: KES {total:,.2f}.")
    lines.append("")
    lines.append("Transactions across ALL accounts (most recent first): "
                 "date | account | amount KES (+credit/-debit) | description")
    for t in statement.get("transactions", []):
        lines.append(f"{str(t.get('ts',''))[:10]} | {t.get('account_number','?')} | "
                     f"{t.get('amount', 0):+,.2f} | {t.get('description','')}")
    return "\n".join(lines)


def _clamp(value, lo: float, hi: float, default: float = 0.0) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def _parse_json(text: str) -> dict | None:
    """Pull the first JSON object out of the model reply, tolerating fences/prose."""
    if not text:
        return None
    # Strip code fences if present.
    text = re.sub(r"```(?:json)?", "", text)
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        val = json.loads(match.group(0))
        return val if isinstance(val, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _heuristic(statement: dict) -> dict:
    """Deterministic fallback when the LLM is unreachable or returns junk.

    Uses simple income/outgoing arithmetic on the statement so the feature keeps
    working offline (and so tests are not model-dependent).
    """
    txns = statement.get("transactions", [])
    credits = [t["amount"] for t in txns if t.get("amount", 0) > 0]
    debits = [-t["amount"] for t in txns if t.get("amount", 0) < 0]
    total_credit = sum(credits)
    total_debit = sum(debits)
    # Statement spans ~35 days of seed data -> treat the window as ~1 month.
    monthly_income = total_credit
    monthly_out = total_debit
    disposable = max(0.0, monthly_income - monthly_out)

    # Trend: compare the first half of credits to the second half (chronological).
    chrono = list(reversed(credits))
    trend = "stable"
    if len(chrono) >= 2:
        mid = len(chrono) // 2
        early, late = sum(chrono[:mid]), sum(chrono[mid:])
        if late > early * 1.15:
            trend = "increasing"
        elif late < early * 0.85:
            trend = "declining"

    monthly_repayment = round(disposable / 3, -2)  # ~a third of disposable
    mult = {"increasing": 12, "stable": 9, "declining": 6}[trend]
    limit = round(monthly_repayment * mult, -2)
    recommended = round(limit * 0.6, -2)
    return {
        "limit": _clamp(limit, _MIN_LIMIT, _MAX_LIMIT),
        "recommended": _clamp(recommended, _MIN_LIMIT, _MAX_LIMIT),
        "monthly_repayment": _clamp(monthly_repayment, 0.0, _MAX_LIMIT),
        "trend": trend,
        "rationale": (f"Heuristic estimate: ~KES {disposable:,.0f} disposable over the "
                      f"statement, earnings {trend}."),
        "engine": "heuristic",
    }


def analyze_statement(statement: dict) -> dict:
    """Compute a loan assessment from a full statement.

    Returns a dict with limit / recommended / monthly_repayment (KES floats),
    trend, rationale, and an ``engine`` marker ("llm" or "heuristic"). Falls back
    to the deterministic heuristic if the model is unavailable or unparseable.
    """
    digest = _statement_digest(statement)
    try:
        resp = analysis_client().chat.completions.create(
            model=LLM.model,
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": digest},
            ],
            temperature=0,
            # Generous ceiling: smaller local models reason before emitting the
            # JSON, and a truncated reply parses as empty and falls back to the
            # heuristic. 2000 leaves ample room for the statement analysis.
            max_tokens=2000,
        )
        data = _parse_json(resp.choices[0].message.content or "")
    except Exception:  # noqa: BLE001 — any provider error -> heuristic
        data = None

    if not data:
        return _heuristic(statement)

    trend = str(data.get("trend", "")).strip().lower()
    if trend not in _TRENDS:
        trend = "stable"
    limit = _clamp(data.get("limit"), _MIN_LIMIT, _MAX_LIMIT)
    recommended = _clamp(data.get("recommended"), _MIN_LIMIT, limit or _MAX_LIMIT)
    monthly = _clamp(data.get("monthly_repayment"), 0.0, _MAX_LIMIT)
    rationale = str(data.get("rationale", "")).strip()[:400] or "LLM statement analysis."
    return {
        "limit": limit,
        "recommended": recommended,
        "monthly_repayment": monthly,
        "trend": trend,
        "rationale": rationale,
        "engine": "llm",
    }
