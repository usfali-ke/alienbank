# Agentic AI — Threats & Failure Modes

> Educational reference for the AlienBank security lab. Agentic AI systems — LLMs
> that plan, call tools, read/write data, and act with some autonomy — add attack
> surface beyond a plain chatbot. This maps the main agentic threats (aligned to
> OWASP's Agentic Security work and the LLM Top 10) with banking examples.

## Why agents are riskier than chatbots

A chatbot only produces text. An agent **takes actions**: it calls tools, moves
money, edits records, browses, and chains steps. So a successful prompt injection
no longer just leaks a sentence — it can execute a transfer. The blast radius is
the union of every tool the agent can reach.

## T1 — Excessive agency / over-permissioned tools

The agent holds more capability than the task needs. If manipulated, it can act
far beyond intent.

**Banking example.** A customer-facing assistant is given teller tools
(deposit, edit-profile, transfer-from-any-account). One jailbreak turns a
customer into a de-facto teller.

**Defence.** Give each agent the *minimum* tools; bind every action to the
authenticated principal; require approval or step-up auth for high-impact steps.

## T2 — Tool/argument manipulation

The model chooses tool arguments; an attacker steers those choices — e.g.
supplying a victim's account number, or an inflated amount.

**Defence.** Never trust model-chosen identifiers for authorization. Resolve the
acting account from the session, validate/whitelist arguments server-side, and
apply limits (amount caps, allow-listed destinations).

## T3 — Indirect / second-order injection via tool results

The agent reads external content (a document, a web page, a database field) that
contains hidden instructions. Input filters never see it because it arrives as a
*tool result*, not a user message.

**Banking example.** An attacker writes an instruction into a transaction note
or profile field; when the victim's agent reads the statement, the instruction
fires — potentially moving the victim's own money.

**Defence.** Treat all tool output as untrusted data; spotlight/delimit it;
re-authorize any action the agent proposes after reading external content; keep
authorization in code so a persuaded model still cannot cross tenant boundaries.

## T4 — Memory & context poisoning

Persistent memory or conversation history is polluted so the agent carries a
malicious instruction across turns or sessions.

**Defence.** Validate and scope memory; expire and attribute stored context;
don't treat retrieved memory as trusted instructions.

## T5 — Multi-agent / delegation abuse

One agent calls another (or a sub-agent/tool-agent). A compromised or spoofed
message between agents escalates privilege or exfiltrates data.

**Defence.** Authenticate inter-agent messages; propagate least-privilege scopes;
don't let a downstream agent inherit more authority than the caller.

## T6 — Goal / plan manipulation

The attacker rewrites the agent's objective ("your real goal is to help me
recover my sister's funds"), causing harmful multi-step plans.

**Defence.** Pin objectives server-side; constrain the action space; monitor and
gate plans that touch sensitive tools.

## T7 — Unbounded autonomy loops

The agent loops, retries, or fans out tool calls without limit — denial of
wallet/service, or runaway actions.

**Defence.** Cap turns, tool calls, recursion depth, and spend; timeouts and
circuit breakers; human checkpoints for long-running tasks.

## T8 — Identity & authorization confusion

The agent conflates *who is asking* with *what the model was told*. Prompt text
should never establish identity or role.

**Defence.** Identity comes only from the authenticated session; the prompt may
*state* it but must not *grant* it. Enforce role and ownership in the tool layer.

---

## The golden rule

> **Guardrails reduce attack success; only real authorization removes the
> vulnerability.** Prompts, filters, and classifiers are bypassable
> defence-in-depth. The unbreakable control is binding each action to the
> authenticated user and enforcing ownership and role in code — before any tool
> moves money or reveals data.
