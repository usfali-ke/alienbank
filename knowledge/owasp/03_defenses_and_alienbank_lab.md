# Defenses & the AlienBank Security Lab

> Educational reference. AlienBank's chat assistant is intentionally built as a
> teaching lab: the agent's tools are deliberately vulnerable so learners can
> practise attacking and defending an agentic banking assistant. This document
> explains the defensive layers and difficulty levels, mapped to OWASP risks.

## The two layers

AlienBank has two layers that share one banking core:

1. **REST API (hardened).** Every button-driven operation derives the acting
   customer from the signed server session and enforces ownership and role. No
   IDOR/BOLA is possible here.
2. **Chat agent (deliberately vulnerable).** The agent's tools accept an account
   number (and teller tools have no role gate) chosen by the LLM, so prompt
   injection can cross tenants and escalate privilege. This is the OWASP **LLM01
   → LLM06** (prompt injection → excessive agency) chain, made concrete.

The single *true* fix is `secure_agent` mode: the tools bind to the authenticated
session, so no prompt can make them act on another account. Everything else is
bypassable defence-in-depth.

## Defensive layers (D0–D3)

- **D0 — Prompt posture.** The system prompt ranges from naive to
  identity-bound to "spotlighting" (treat all user text as untrusted data).
  Persuasion only; never enforcement. (Mitigates LLM01/LLM07 partially.)
- **D1 — Deterministic input filter.** Regex/keyword/structural heuristics
  (normalised for zero-width and homoglyph tricks) that block obvious injection
  phrases before the model sees them. Bypassed by keyword-free phrasing.
- **D2 — Guard-model classifier.** A separate local model scores each user
  message ATTACK/SAFE (or Llama-Guard-style moderation). Bypassed by subtle,
  benign-framed intent.
- **D3 — Tool-call guardrail.** Inspects each *planned* tool call and blocks
  cross-tenant accounts or teller-only tools for a customer. Bypassed by attacks
  that stay within the caller's own accounts or arrive indirectly.

None of D0–D3 is authorization; they lower attack success but can all be beaten.

## Difficulty levels

- **Level 0 — Naive.** Soft prompt only. Trivial direct injection works.
- **Level 1 — Hardened.** Identity-bound prompt + D1 filter. Bypass needs
  obfuscation or keyword-free phrasing.
- **Level 2 — Defended.** Spotlighting + D1 + D2 + D3. Bypass needs real
  jailbreaks (persona/roleplay, "authorized test" framing, payload splitting).
- **Level 3 — Hardest.** All L2 defenses; the open surface is **indirect
  injection** via poisoned data (a transaction note the victim reads), which
  bypasses the input filters entirely and doesn't cross a tenant boundary.

## OWASP → AlienBank mapping

| OWASP risk | Where it shows up in AlienBank |
|------------|--------------------------------|
| LLM01 Prompt Injection | The core lab vuln; direct at L0–L1, jailbreak at L2, indirect at L3 |
| LLM02 Sensitive Info Disclosure | Cross-tenant balance/statement reads via the agent |
| LLM05 Improper Output Handling | Chat renders model output; tool output is HTML-escaped to prevent injection |
| LLM06 Excessive Agency | Customer-reachable teller tools (deposit, edit-profile, any-account transfer) |
| LLM07 System Prompt Leakage | "Reveal your instructions" attempts; D1 pattern + prompt refusal |
| LLM08 Vector & Embedding Weaknesses | The RAG knowledge base; retrieved text treated as untrusted |
| LLM09 Misinformation | RAG grounds bank-info answers; the agent says "I don't know" when unsupported |

## Practical checklist for building a safe banking agent

1. **Authorize in code, not the prompt.** Resolve the acting account from the
   session; enforce ownership and role before any tool acts.
2. **Least privilege.** Give the agent only the tools its role needs.
3. **Distrust everything the model reads** — user messages *and* tool results.
4. **Validate tool arguments** server-side; cap amounts; allow-list destinations.
5. **Human-in-the-loop** for high-impact actions.
6. **Defence-in-depth**: input filter + guard model + tool-call checks — as
   layers, never as the only control.
7. **Ground answers** in retrieval and let the model decline when unsupported.
8. **Bound consumption**: rate limits, token/turn/tool-call caps.
9. **Observe**: log tool calls and guardrail decisions for review.
10. **Test adversarially**: benchmark attack-success-rate per defense level.

## Try it in the lab

Switch the security level from **Profile → Security level**, turn on **Show
assistant tool calls** to watch guardrail decisions, and attempt the attacks.
The benchmark (`alienbank-bench`) measures attack-success-rate per level so you
can see defenses working — and find the payloads that still get through.
