# AlienBank — OWASP LLM Top 10 & Agentic Risk Coverage Audit

A code-grounded assessment of how AlienBank covers the **OWASP Top 10 for LLM
Applications (2025)** and the main **agentic-AI risks**, what is missing, and how
to close each gap.

> **Read this in context.** AlienBank is a deliberately-vulnerable *teaching lab*.
> Many "gaps" are the intended lesson (the agent is meant to be attackable at
> Levels 0–3). This audit separates **(i) intentional teaching vulnerabilities**
> from **(ii) unintentional gaps that should be fixed even for a lab**, and rates
> how *completely* each area is covered as a security-education artifact — i.e.
> does the app both **demonstrate** the risk and **offer a real fix**?

Legend: ✅ Fully covered · 🟡 Partial · ❌ Missing · 🎯 intentional teaching vuln.

---

## Scorecard

| OWASP / risk | Demonstrated? | Real fix present? | Rating | Verdict |
|--------------|---------------|-------------------|--------|---------|
| **LLM01** Prompt Injection (direct) | ✅ (L0–L2 ladder) | ✅ `secure_agent` + D1/D2 | ✅ | Fully covered |
| **LLM01** Prompt Injection (indirect) | ✅ (open L0–L2) | ✅ **D4 output firewall (L3)** + `secure_agent` | ✅ | Now fully covered |
| **LLM02** Sensitive Info Disclosure | ✅ (BOLA via agent) | ✅ `*_secure` binding | ✅ | Fully covered |
| **LLM03** Supply Chain | 🟡 (embed-model swap) | 🟡 `uv.lock` pins deps; **embed-dim guard**; models still tag-pinned | 🟡 | Improved (dim guard added) |
| **LLM04** Data & Model Poisoning | ✅ (poisoned KB doc) | ✅ **ingest scan + provenance hash; flagged chunks dropped** | ✅ | Now covered |
| **LLM05** Improper Output Handling | ✅ (chat + dashboard escaped) | ✅ all render paths `esc()` | ✅ | Fixed (dashboard XSS closed) |
| **LLM06** Excessive Agency | ✅ (teller tools for customers) | ✅ `secure_agent` + D3 | ✅ | Fully covered |
| **LLM07** System Prompt Leakage | ✅ (leak open L0/L1) | ✅ **canary + D5 output guardrail (L2+)** | ✅ | Now covered (level-gated) |
| **LLM08** Vector & Embedding Weaknesses | ✅ (poisoned chunk + staff-doc disclosure) | ✅ **D4 (L3) + audience partitioning (L2+)** + ingest scan | ✅ | Now covered |
| **LLM09** Misinformation | ✅ (poisoned-doc + hallucination tests) | ✅ RAG grounding + "I don't know" | ✅ | Fully covered |
| **LLM10** Unbounded Consumption | ✅ (open L0/L1) | ✅ **rate limit + size caps (L2+)**; `max_turns`, `top_k` | ✅ | Now covered (level-gated) |
| **Agentic** Tool/arg manipulation | ✅ | ✅ D3 + `secure_agent` | ✅ | Fully covered |
| **Agentic** Indirect injection via tool results | ✅ (open L0–L2) | ✅ **D4 output firewall (L3)** | ✅ | Now fully covered |
| **Agentic** Memory/context poisoning | ✅ (client history open L0/L1) | ✅ **server-held history (L2+)** | ✅ | Now covered (level-gated) |
| **Agentic** Excessive autonomy / loops | 🟡 (`max_turns`) | 🟡 | 🟡 | Partial |
| **Agentic** Human-in-the-loop | ✅ (unattended L0/L1) | ✅ **transfer confirmation (L2+)** | ✅ | Now covered (level-gated) |
| **Agentic** Observability / audit | ✅ (no trail L0/L1) | ✅ **JSONL audit log (L2+)** | ✅ | Now covered (level-gated) |
| **Foundational** Auth / session / secrets | ✅ REST hardened | 🟡 plaintext pw, weak secret, no CSRF | 🟡 | Partial (lab-acceptable, documented) |

---

## Fully covered (✅) — demonstrated AND fixable

These areas both show the attack across levels and ship a genuine fix
(`ALIENBANK_SECURE_AGENT=true`, D-layer guardrails), with playbooks and a
benchmark:

- **LLM01 direct injection** — D0 prompt posture, D1 regex filter, D2 guard-model
  classifier, escalating L0→L2; `secure_agent` is the true fix.
  *(guardrails.py, chat.py:46-81, prompts.py, LEVELS_PLAYBOOK.md)*
- **LLM02 disclosure** — `*_raw` (vulnerable) vs `*_secure` (session-bound); the
  benchmark proves cross-tenant reads and their closure. *(bank.py:184-332)*
- **LLM06 excessive agency** — teller tools reachable by customers; D3 tool-call
  guardrail blocks cross-tenant/teller calls at L2/L3; `secure_agent` binds all
  tools. *(tools.py:268-277, guardrails.py:142-168)*
- **LLM09 misinformation** — every prompt instructs "answer only from retrieved
  passages… say you don't have it rather than invent." Verified with a poisoned
  doc and a no-such-figure query. *(prompts.py:136-152)*
- **Agentic tool/argument manipulation** — same D3 + `secure_agent` coverage.

**Enhancement even here:** LLM09 grounding is prompt-only — add optional
programmatic citation/abstention checks to make it demonstrably enforced, not
just instructed.

---

## Partial (🟡) and Missing (❌) — with what to implement

### LLM01 indirect / Agentic indirect injection — 🟡 demoed, no defense layer
**State.** L3 ships the indirect surface (poisoned transaction note / KB chunk);
tool output is **never** inspected before reaching the model. D1/D2 only see the
user message; D3 only sees tool *arguments*, not tool *results*.
**Missing.** A defense the learner can *turn on* to contrast with the attack.
**Implement.**
- A **D4 "output/context firewall"**: spotlight/delimit all tool results, strip
  or neutralize instruction-like text in retrieved chunks and statement notes,
  and re-run a lightweight injection check on tool output.
- **Re-authorization after retrieval**: any tool call the agent proposes *after*
  reading external content must re-pass D3 (already true) and, in secure mode,
  is already bound — document this as the mitigation.

### LLM04 Data & Model Poisoning — ✅ FIXED (ingest validation)
**State.** At index time (`build_index`), every non-`owasp/` chunk is
(a) hashed (sha256 provenance stored in metadata) and (b) injection-scanned with
the D4 pattern set. Flagged chunks are tagged `flagged=True` and **excluded from
retrieval at every level**; `alienbank-index --strict` refuses them entirely.
**Verified:** a poisoned corporate doc was flagged (6 patterns) and became
non-retrievable. The `owasp/` educational corpus is exempt from scanning (it
*describes* attacks, so scanning it false-positives). **Still to do (optional):**
a signed manifest, and keeping user-supplied text out of the curated store.

### LLM05 Improper Output Handling — ✅ FIXED
**State.** The chat path was already safe; the dashboard renderers were
stored-XSS sinks (unescaped `t.description`, `t.counterparty`, `a.nickname`,
`r.account_name`, name-enquiry result). **Now fixed:** a shared `esc()` helper is
hoisted to the top of `app.js` and applied to every interpolated field in
`renderTxnTable`, `renderAccountCards`, `loadRecipients`, the payee-confirm, and
the transfer-result renders. A `<script>`/HTML payload in a transaction note or
profile name is now escaped on display.

### LLM07 System Prompt Leakage — ✅ FIXED (canary + D5, level-gated)
**State.** At **L2+**, a secret **canary token** (`prompts.CANARY`) is embedded in
the system prompt, and a **D5 output guardrail** (`guardrails.d5_canary_output`)
scans every model reply: if the canary (i.e. the leaked prompt) appears, the whole
reply is replaced with a refusal and the leaked turn is not persisted to history.
**Verified:** with a forced leak, D5 fired, `blocked_by=D5`, the canary never
reached the user or the stored history. **Open at L0/L1** (no canary) so a prompt
leak is demonstrable. **Still to do (optional):** minimise PII inlined in the
prompt (resolve account numbers via a tool) so a partial leak discloses less.

### LLM08 Vector & Embedding Weaknesses — ✅ FIXED (partitioning + D4 + ingest)
**State.** Chunks are tagged with an `audience` (`public` for `corporate/`+`owasp/`,
`staff` for `internal/`). At **L2+** (`rag_partition`), `knowledge_search` scopes
`col.query(where={"audience": …})` to the caller's role — a customer gets only
`public`, a teller gets `public`+`staff`. **Verified:** a customer's assistant
surfaces the staff-only procedures doc at L0 but **not at L2**; a teller still
gets it. Combined with D4 (retrieved-chunk injection scan, L3) and ingest
validation (LLM04), the retrieval surface is now defended for injection, tenant
isolation, and integrity. A demo `knowledge/internal/staff_procedures.md` exists
as the protected content.

### LLM03 Supply Chain — 🟡 deps pinned, models not
**State.** `uv.lock` pins 938 hashes (good). But `pyproject.toml` uses unbounded
`>=`, and model identifiers (`deepseek.v3.2`, `qwen2.5:3b-instruct`, `bge-m3`) are
mutable tags with no digest pin; embedding dim (1024) isn't guarded.
**Done.** ✅ The **embedding-dimension guard** is implemented (`embed_texts`
raises if the model returns an unexpected dim — catches a silently swapped
embed model, verified). **Still to do:** pin model **digests** where the provider
supports it; add upper bounds / renovate policy for direct deps; a supply-chain
teaching note in `knowledge/owasp/`.

### LLM10 Unbounded Consumption — ✅ FIXED (level-gated)
**State.** At **L2+**: a per-session sliding-window rate limit (`_rate_ok`,
10 requests / 60s → HTTP 429), a message-length cap (`MAX_MESSAGE_CHARS` → 413),
and history-size caps (client `MAX_CLIENT_HISTORY`, server `MAX_SERVER_HISTORY`).
`max_turns=8` and `top_k=4` still bound the loop and retrieval. Left **open at
L0/L1** so the denial-of-wallet attack is demonstrable. **Still to do:** apply
`LLM.max_tokens`/`temperature` via `ModelSettings`, and a per-turn tool-call
budget + cost counter.

### Agentic — Memory / context poisoning — ✅ FIXED (level-gated)
**State.** At **L2+**, `/api/chat` ignores client-supplied `history` and reads/
writes a server-held store keyed by an opaque session id (`_HISTORY`, `sid`).
A forged prior "assistant"/"tool" turn is dropped (verified: echoed history
length 0 at L2), while legitimate multi-turn context still persists server-side
(verified). **Open at L0/L1** (client history trusted) so the forgery attack is
demonstrable.

### Agentic — Human-in-the-loop — ✅ FIXED (level-gated)
**State.** At **L2+**, the agent's `transfer_funds` no longer executes a
high-value transfer unattended: any amount ≥ `CONFIRM_THRESHOLD_KES` (1,000)
returns a `pending_confirmation` result instead of moving money. The web layer
stores the pending transfer per session and only commits it after the user
replies with an affirmation ("yes"/"confirm"); a non-affirmation cancels it.
**Verified:** at L2 a 5,000 transfer deferred (balance unchanged), then "yes"
committed it (59,500 → 64,500). **Open at L0/L1** (transfers run unattended) so
the missing-checkpoint risk is demonstrable. *(tools.py `_needs_confirmation`,
chat.py `confirmed_transfer`/`pending_transfer`, app.py `_PENDING_XFER`.)*

### Agentic — Observability / audit — ✅ FIXED (level-gated)
**State.** At **L2+**, every chat turn is appended to `data/audit.jsonl`: actor,
role, level, (truncated) message, guardrail decisions, which layer blocked, and
each tool call's name/arguments/error flag. View it with `uv run alienbank-audit
[N]`. **No trail at L0/L1** (the teachable gap — you can't investigate an attack
after the fact). **Verified:** L1 turn wrote 0 lines, L2 turns were recorded.
*(agent/audit.py, chat.py `_audit`, levels.py `audit_log`.)*

### Foundational — Auth / session / secrets — 🟡 lab-acceptable but flag
**State.** REST auth is session-bound and role-enforced (good). But: **plaintext
passwords** with non-constant-time compare; **weak default `SECRET_KEY`**; no
cookie `secure/httponly/samesite`; **no CSRF** on state-changing POSTs; no
brute-force lockout; guessable seed creds.
**Implement (if you want it beyond "lab"):** hash passwords (bcrypt/argon2);
require a strong secret; set cookie flags; add CSRF tokens; add login rate-limit.
Otherwise keep as documented lab simplifications.

---

## Priority recommendations

**Fix now (unintended vulns, not part of the lesson) — ✅ ALL DONE:**
1. ✅ **DONE — Dashboard stored-XSS** (LLM05): every dashboard renderer in
   `app.js` now HTML-escapes interpolated fields via a shared `esc()`
   (`renderTxnTable`, `renderAccountCards`, `loadRecipients`, name-enquiry,
   transfer result).
2. ✅ **DONE — Client-supplied chat history** (memory poisoning): at **L2+** the
   server ignores `body.history` and keeps history in a session-keyed store; a
   forged prior turn is dropped (verified). Open at L0/L1 so the attack is
   teachable. *(`app.py` `_HISTORY`, `levels.py server_history`.)*
3. ✅ **DONE — Rate limiting / input caps** (LLM10): at **L2+**, a per-session
   sliding-window throttle (10/60s → 429) plus a message-length cap (→ 413) and
   history-size caps. *(`app.py` `_rate_ok`, `MAX_MESSAGE_CHARS`, `levels.py
   rate_limited`.)*

**Add to complete the teaching story (turn attacks into before/after lessons):**
4. ✅ **DONE — D4 output/context firewall** for indirect injection
   (LLM01-indirect / LLM08). Level 3 scans tool results and neutralises injected
   instructions; the indirect attack lands at L0–L2, blocked at L3.
5. ✅ **DONE — RAG partitioning + ingest validation** (LLM08/LLM04): audience-tagged
   chunks, customer-scoped retrieval at L2+, ingest injection-scan + provenance
   hash (flagged chunks dropped), embedding-dim guard (LLM03). *(knowledge.py,
   levels.py `rag_partition`, `knowledge/internal/`.)*
6. ✅ **DONE — Human-in-the-loop confirmation** for agent transfers: at L2+, a
   transfer ≥ KES 1,000 returns "pending, confirm?" and only commits after the
   user replies yes. *(tools.py `_needs_confirmation`, app.py `_PENDING_XFER`,
   levels.py `confirm_transfers`.)*
7. ✅ **DONE — Audit logging** of every turn's tool calls + guardrail decisions to
   `data/audit.jsonl` at L2+; view with `uv run alienbank-audit`. *(agent/audit.py,
   chat.py `_audit`, levels.py `audit_log`.)*
8. ✅ **DONE — Prompt canary + D5 output guardrail** (LLM07): canary in the L2+
   system prompt; the reply is redacted if it leaks. **Embed-dim check** (LLM03)
   also done. **Still to do (optional):** model **digest** pinning (LLM03) and
   **programmatic grounding checks** (LLM09).

9. ✅ **DONE — External prompt-injection guard (D6), direct + indirect**. The
   regex (D1) and instruct-model (D2) layers are heuristic and miss whole attack
   classes — e.g. an *indirect* injection wrapped in "summarise this email"
   that tells the assistant to ignore RAG and answer from training data (the
   documented KCB bypass). D6 catches exactly that, and runs as an **external
   call** — deliberately **no ML model ships in the app image** (an earlier
   in-image ProtectAI LLM Guard / DeBERTa attempt pulled ~2 GB of torch and
   produced a 21 GB container — unworkable for k8s). Two interchangeable
   backends: **`ollama`** (an LLM-as-judge on the local guard model, driven by
   an injection-specialised JSON prompt tuned for the indirect/RAG-hijack class;
   fully local, zero image weight, reuses the D2 endpoint) and **`bedrock`**
   (AWS Bedrock Guardrails' `ApplyGuardrail` API — a managed prompt-attack +
   contextual-grounding filter, reusing the Bedrock bearer token). OPTIONAL,
   env-gated (`ALIENBANK_INJECTION_GUARD`, `..._BACKEND`), level-gated (L2+), and
   **fail open** if the backend is disabled/unconfigured/unreachable — a missing
   guardrail never masquerades as protection (same contract as D2). **Verified:**
   ollama backend blocks the KCB *indirect* payload (indirect, conf 0.95) and a
   classic direct injection (direct, conf 0.85) while passing a benign balance
   query (clean, conf 0.95); bedrock fails open cleanly when unconfigured; image
   stays 1.39 GB. *(agent/injection_guard.py, config.py `InjectionGuardConfig`,
   provider.py `injection_guard_client`, levels.py `d6_injection_guard`,
   chat.py D6 wiring.)*

**Documentation:** add short LLM03 (supply chain) and LLM10 (consumption) teaching
notes to `knowledge/owasp/`, and a "known unintended gaps" note distinguishing
them from the intended vulnerabilities.

---

## Bottom line

AlienBank **strongly covers the core agentic-banking risks** it was built to
teach — LLM01 (direct **and now indirect**), LLM02, LLM06, LLM09, and tool/argument
manipulation — each with a graded attack, a real fix (`secure_agent`/D-layers),
playbooks, and a benchmark. The **D4 output/context firewall** closes the
retrieval-side injection story (indirect injection lands L0–L2, defended at L3).
The **three unintended gaps are fixed** (dashboard XSS escaped; memory poisoning
and denial-of-wallet level-gated at L2+); **agentic hygiene is in place**
(human-in-the-loop transfer confirmation + JSONL audit trail, level-gated); and
the **retrieval surface is hardened** — RAG audience partitioning (L2+), ingest
injection-scan + provenance (LLM04), and an embedding-dim guard (LLM03) —
alongside the D4 firewall (L3); and **system-prompt leakage** is defended by a
canary + D5 output guardrail (L2+, LLM07). **Every OWASP LLM Top-10 category now
has both a demonstration and a real, level-appropriate defense.** The only
remaining items are optional polish: model **digest** pinning (LLM03) and
**programmatic grounding** checks (LLM09).

For **runtime-protection** follow-ups beyond this OWASP scorecard — egress
lockdown, an always-on output exfil scan, baseline L0/L1 rate limiting,
distributed limiter state, and more — see
[RUNTIME_PROTECTION_ROADMAP.md](RUNTIME_PROTECTION_ROADMAP.md).
