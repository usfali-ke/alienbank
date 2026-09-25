"""Assemble and run the AlienBank chat agents, with leveled defenses.

The per-turn pipeline is:

    D1 deterministic filter  (pre-LLM)  ─┐  if either trips at this level,
    D2 guard-model classifier (pre-LLM) ─┘  we refuse WITHOUT calling the agent
    → agent run (leveled system prompt)
       └ D3 tool-call guardrail runs inside each tool (see tools.py)

Which layers are active is decided by the current level (see levels.py). The
tools remain vulnerable at every level; only ``secure_agent`` truly binds them
to the session. Levels just stack bypassable defenses in front.
"""
from __future__ import annotations

from agents import Agent, Runner

from .. import bank
from ..config import current_level, secure_agent_enabled
from . import audit, guardrails, injection_guard
from .levels import spec
from .prompts import system_prompt
from .provider import get_model
from .tools import CUSTOMER_TOOLS, TELLER_TOOLS, ChatContext


def build_agent(actor: bank.Actor, level: int) -> Agent[ChatContext]:
    if actor.role == "teller":
        instructions = system_prompt(level, "teller", name=actor.full_name, username=actor.username)
        tools = TELLER_TOOLS
    else:
        accounts = bank.list_my_accounts_secure(actor)
        acct_list = ", ".join(f"{a['account_number']} ({a['nickname']})" for a in accounts)
        instructions = system_prompt(level, "customer", name=actor.full_name,
                                     username=actor.username, accounts=acct_list)
        tools = CUSTOMER_TOOLS

    return Agent[ChatContext](
        name="Nova",
        instructions=instructions,
        model=get_model(),
        tools=tools,
    )


async def _pre_llm_gate(level: int, message: str) -> list[dict]:
    """Run the input-inspection layers (D1, D2, D6) enabled at this level."""
    sp = spec(level)
    decisions: list[dict] = []
    if sp.d1_filter:
        decisions.append(guardrails.d1_filter(message).as_dict())
    if sp.d2_classifier:
        decisions.append((await guardrails.d2_classifier(message)).as_dict())
    # D6 — external prompt-injection guard (Ollama LLM-judge or Bedrock
    # Guardrails). Catches the indirect/RAG-hijack class D1/D2 miss. Gated by the
    # level flag AND the env toggle; fails open if the backend is unavailable.
    if sp.d6_injection_guard and injection_guard.is_active():
        decisions.append((await injection_guard.scan_input(message)).as_dict())
    return decisions


async def run_chat(actor: bank.Actor, history: list[dict], message: str,
                   level: int | None = None, confirmed_transfer: dict | None = None) -> dict:
    """Run one turn under the given difficulty level (defaults to current_level).

    Returns reply, updated history, and rich guardrail/telemetry so the UI and
    the benchmark can see exactly which layer fired. ``confirmed_transfer`` carries
    a user approval from a prior turn (for the human-in-the-loop transfer gate);
    the result includes ``pending_transfer`` when the agent deferred one.
    """
    level = current_level() if level is None else level
    guard_decisions = await _pre_llm_gate(level, message)
    pre_blocked = [d for d in guard_decisions if d["blocked"]]

    if pre_blocked:
        # Refuse before the agent ever sees the message.
        out = {
            "reply": guardrails.REFUSAL,
            "history": list(history) + [
                {"role": "user", "content": message},
                {"role": "assistant", "content": guardrails.REFUSAL},
            ],
            "secure_mode": secure_agent_enabled(),
            "level": level,
            "blocked_by": pre_blocked[0]["layer"],
            "guardrails": guard_decisions,
            "tool_calls": [],
        }
        _audit(actor, level, message, out)
        return out

    agent = build_agent(actor, level)
    ctx = ChatContext(actor, level=level, confirmed_transfer=confirmed_transfer)
    input_items = list(history) + [{"role": "user", "content": message}]
    result = await Runner.run(agent, input_items, context=ctx, max_turns=8)

    # D3/D4 decisions were collected on the context during tool execution.
    guard_decisions += ctx.tool_guard_decisions
    blocked_by = next((d["layer"] for d in ctx.tool_guard_decisions if d["blocked"]), None)

    reply = result.final_output or ""
    history_out = result.to_input_list()

    # D5 — canary output guardrail: if the level embeds a canary and it leaked
    # into the reply, redact the reply before it reaches the user (LLM07).
    if spec(level).prompt_canary:
        reply, d5 = guardrails.d5_canary_output(reply)
        guard_decisions.append(d5.as_dict())
        if d5.blocked:
            blocked_by = blocked_by or "D5"
            # Don't persist the leaked assistant turn; replace it with the refusal.
            history_out = list(history) + [
                {"role": "user", "content": message},
                {"role": "assistant", "content": reply},
            ]

    out = {
        "reply": reply,
        "history": history_out,
        "secure_mode": secure_agent_enabled(),
        "level": level,
        "blocked_by": blocked_by,
        "guardrails": guard_decisions,
        "tool_calls": _tool_calls(result),
        "pending_transfer": ctx.pending_transfer,
    }
    _audit(actor, level, message, out)
    return out


def _audit(actor: bank.Actor, level: int, message: str, out: dict) -> None:
    """Write the turn to the audit trail if the level enables logging (L2+)."""
    if not spec(level).audit_log:
        return
    # The caller's real accounts (from the session) let the audit layer tell a
    # cross-tenant access apart from the customer touching their own account.
    try:
        owned = [a["account_number"] for a in bank.list_my_accounts_secure(actor)]
    except Exception:  # noqa: BLE001 — auditing must not break the request path
        owned = []
    audit.record_turn(
        actor_username=actor.username, actor_role=actor.role, level=level,
        message=message, blocked_by=out.get("blocked_by"),
        guardrails=out.get("guardrails", []), tool_calls=out.get("tool_calls", []),
        owned_accounts=owned,
    )


def _tool_calls(result) -> list[dict]:
    """Extract the tool calls the agent made, paired with their outputs.

    Used by the exploit-demo/benchmark to prove which banking tool fired, with
    what arguments, and what it returned (so a call that was made but rejected
    with an error is not mistaken for a successful exploit). Works off
    ``to_input_list()`` which carries ``function_call`` / ``function_call_output``
    entries keyed by ``call_id``.
    """
    calls: dict[str, dict] = {}
    order: list[str] = []
    for item in result.to_input_list():
        if not isinstance(item, dict):
            continue
        if item.get("type") == "function_call":
            cid = item.get("call_id")
            calls[cid] = {"name": item.get("name"), "arguments": item.get("arguments"), "output": None}
            order.append(cid)
        elif item.get("type") == "function_call_output":
            cid = item.get("call_id")
            if cid in calls:
                calls[cid]["output"] = item.get("output")
    return [calls[cid] for cid in order]
