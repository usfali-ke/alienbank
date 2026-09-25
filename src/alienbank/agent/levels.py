"""Difficulty levels for the agentic red-team gym.

A level is a *stack of defensive layers* on top of the (always-vulnerable) tools.
Every layer here is heuristic/probabilistic — it lowers attack success but can be
bypassed with enough skill. None of them is real authorization; that is what
``secure_agent`` provides and why it is kept orthogonal to levels.

Layers:
    D0  prompt posture         (see prompts.py) — soft / hardened / spotlighting
    D1  deterministic filter   (pre-LLM)  — regex/keyword/structural heuristics
    D2  LLM guard classifier   (pre-LLM)  — a local guard model scores the input
    D3  tool-call guardrail    (mid-LLM)  — blocks cross-tenant / escalating calls
    D4  output/context firewall (post-tool) — scans TOOL RESULTS (statements,
        retrieved chunks) for injected instructions before the model reads them

Two hardening controls are also level-gated (L2+), because their *absence* is a
teachable attack at L0/L1:
    server_history — ignore client-supplied conversation history and keep it in a
        server session store (defends memory/context poisoning & history spoofing)
    rate_limited   — per-session request throttle + message/history size caps
        (defends unbounded consumption / denial-of-wallet)
    audit_log      — persist every turn's telemetry (tool calls, guardrail
        decisions, blocks) to a JSONL trail (enables detection / incident review)
    confirm_transfers — money movement above a threshold returns "pending, confirm?"
        and requires an explicit user confirmation before committing (HITL)
    rag_partition  — scope RAG retrieval to the caller's audience so a customer's
        assistant can never surface staff-only knowledge docs (LLM08)
    prompt_canary  — embed a secret canary in the system prompt and run a D5
        output guardrail that redacts the reply if the canary (i.e. the leaked
        system prompt) appears in it (LLM07)

Ingest validation (content hash + injection scan of every knowledge chunk, LLM04)
and the embedding-dimension guard (LLM03) run at index time regardless of level —
they are corpus-integrity controls, not per-request defenses.

The indirect-injection surface (a poisoned transaction note or knowledge chunk
whose text reaches the model as a tool result) is open at L0–L2, because D1/D2
only inspect the user's typed message and D3 only inspects tool *arguments*.
Level 3 adds D4, which heuristically neutralises instruction-like text in tool
output — so L3 is genuinely the hardest, not merely the level with the hole open.
Like every layer, D4 is bypassable; only ``secure_agent`` stops the *impact*
(the injected instruction can still be delivered, but cannot move another
tenant's money).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LevelSpec:
    level: int
    name: str
    tagline: str
    d1_filter: bool          # deterministic pre-LLM filter
    d2_classifier: bool      # LLM injection classifier (guard model)
    d3_tool_guard: bool      # tool-call cross-tenant / escalation guardrail
    d4_output_firewall: bool  # scans tool output for injected instructions
    server_history: bool     # ignore client-supplied history; use server session store
    rate_limited: bool       # per-session request throttle + message/history size caps
    audit_log: bool          # persist per-turn telemetry (tool calls, guardrail decisions)
    confirm_transfers: bool  # money movement above a threshold needs explicit user confirmation
    rag_partition: bool      # scope RAG retrieval to the caller's audience (customers get public only)
    prompt_canary: bool      # embed a canary in the system prompt + D5 output guardrail on leak
    # D6: external prompt-injection guard (Ollama LLM-judge or Bedrock Guardrails).
    # Default off; further gated by the ALIENBANK_INJECTION_GUARD env toggle and
    # fail-open if the backend is unreachable. No ML model ships in the image.
    d6_injection_guard: bool = False


LEVELS: dict[int, LevelSpec] = {
    0: LevelSpec(0, "Naive", "Soft prompt only — trivial injection works.",
                 d1_filter=False, d2_classifier=False, d3_tool_guard=False, d4_output_firewall=False,
                 server_history=False, rate_limited=False, audit_log=False, confirm_transfers=False,
                 rag_partition=False, prompt_canary=False),
    1: LevelSpec(1, "Hardened", "Identity-bound prompt + deterministic input filter.",
                 d1_filter=True, d2_classifier=False, d3_tool_guard=False, d4_output_firewall=False,
                 server_history=False, rate_limited=False, audit_log=False, confirm_transfers=False,
                 rag_partition=False, prompt_canary=False),
    2: LevelSpec(2, "Defended", "Spotlighting + input filter + LLM guard + tool-call guardrail; server history, rate limits, audit log, transfer confirmation, RAG partitioning, prompt canary; external injection guard (D6) for indirect/RAG-hijack.",
                 d1_filter=True, d2_classifier=True, d3_tool_guard=True, d4_output_firewall=False,
                 server_history=True, rate_limited=True, audit_log=True, confirm_transfers=True,
                 rag_partition=True, prompt_canary=True,
                 d6_injection_guard=True),
    3: LevelSpec(3, "Hardest", "All L2 defenses PLUS an output/context firewall (D4) that scans tool results for injected instructions.",
                 d1_filter=True, d2_classifier=True, d3_tool_guard=True, d4_output_firewall=True,
                 server_history=True, rate_limited=True, audit_log=True, confirm_transfers=True,
                 rag_partition=True, prompt_canary=True,
                 d6_injection_guard=True),
}


def spec(level: int) -> LevelSpec:
    return LEVELS.get(level, LEVELS[0])
