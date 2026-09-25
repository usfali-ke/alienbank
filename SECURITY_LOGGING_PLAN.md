# AlienBank — Security Logging & SIEM Monitoring Plan

> **Status:** PARTIALLY IMPLEMENTED. Phases 1–2 (schema/core `seclog` +
> `logging_setup`, and instrumentation of auth, REST money/data endpoints, and
> the agent turn) are in code; shipping (phase 3), detection content (phase 4),
> and the standalone docs (phase 5) remain. The design below is the source of
> truth and stays current with the code.

**Decisions locked in for this plan**

| Decision | Choice |
|----------|--------|
| SIEM target | **Vendor-neutral structured logs + pluggable shippers/adapters** (Splunk / Elastic / Wazuh / cloud by config swap) |
| Deployment model | **Containerized (Docker/K8s)** — app logs JSON to **stdout**, a Fluent Bit sidecar ships it |
| Scope | Observability only — **no changes to the security defenses themselves** |
| Privacy | **Zero PII, zero personal/financial data in logs** — no usernames, names, emails, phones, account numbers, amounts, or message text. Achieved by logging *verdicts and non-identifying IDs*, not by hashing — **with one documented exception:** the pre-auth `target_ref` is an HMAC of the submitted username (§3.7), because at a failed login there is no stored pseudonym to use. |

---

## 0. Guiding principle — no PII, no financial data, full detection

This is the load-bearing constraint, so it comes first.

**The insight:** AlienBank already computes every sensitive security verdict
*server-side* (`audit.py` derives `cross_tenant`, `state_changing`, `impact`,
`outcome` from the real account numbers and amounts). The SIEM therefore never
needs the raw sensitive values to detect an attack — it needs the **verdict**.

So the rule is simple:

| Do log (safe, enables detection) | Never log (PII / financial) |
|----------------------------------|-----------------------------|
| Non-identifying **IDs** kept raw for correlation: `session_id` (already a random `uuid4` token, not PII), `request_id`, and **`actor.ref`** — a random per-user **`pseudonym`** (a new `users.pseudonym` column, *not* the username or a sequential id) | Usernames, full names, emails, phone numbers |
| **Verdicts & flags** computed in-app: `cross_tenant`, `state_changing`, `outcome`, `attack`, `blocked_by` | Account numbers (in any form — not even masked) |
| **Categorical buckets**, not raw values: `amount_band` (`<1k` / `1k–10k` / `>10k`), transfer vs deposit | Exact amounts, balances |
| Route **templates**: `/api/accounts/{id}/statement` | Concrete paths carrying an account number |
| `role`, `level`, `source.ip`, timestamps, HTTP status | User message text, tool arguments, transaction notes, canary value |

**Why this keeps the SIEM fully capable — and why no hashing is needed:**

- **Correlation** works off the raw-but-opaque `session_id` (all of one session's
  activity) and the random `actor.ref` pseudonym (one actor across sessions).
  Neither is PII; both are stored random tokens, so **no hashing / key management**
  is needed — see [§3.6](#36-identity--correlation-model) for the full rationale.
- **Detection is unimpaired** because the signals rules fire on — `cross_tenant`,
  `attack`, `bypassed_layers`, `outcome=compromise`, `amount_band=>10k` — are all
  present as flags/buckets. A BOLA probe, a compromise, a brute-force burst, and a
  denial-of-wallet spike are all still detectable **without a single sensitive
  field** in the log.
- **Simple:** no key management, no HMAC salt to rotate, no reversible-token
  design. We omit sensitive data at the source and emit the verdict the app
  already knows.

---

## 1. Where we are today (grounding)

A code-grounded snapshot of AlienBank's current logging posture.

| Signal | State | Source |
|--------|-------|--------|
| **Agent audit trail** | Rich per-turn JSONL with excellent security semantics (outcome, bypassed layers, cross-tenant / state-changing impact, plain-English narrative) — **but only at L2+**, and only for the chat agent. | `src/alienbank/agent/audit.py` |
| **REST API** (money movement, auth, teller ops) | **No logging at all.** Logins, transfers, loan actions, BOLA-relevant reads, teller profile edits, DB resets emit nothing. | `src/alienbank/web/app.py` |
| **Auth events** | `bank.authenticate` failures surface only as HTTP 401 — **not logged.** No brute-force visibility. | `web/app.py:123` `login_submit` |
| **App / runtime logs** | Ad-hoc `print()` in `app.py` / `knowledge.py`; no structured logging, no request IDs, no correlation. | grep of `src/alienbank` |
| **Shipping** | None. `data/audit.jsonl` is local-file only, read via the `alienbank-audit` CLI. | `pyproject.toml` scripts |

**Core gap.** The security-richest events (transfers, logins, IDOR/BOLA-style
reads, teller actions) live in the *hardened REST layer*, which currently logs
**nothing** — while the good logging only covers the *chat agent* and only at
higher difficulty levels.

---

## 2. Goals

1. One **structured, security-focused logging layer** covering authentication,
   REST money/data actions, agent turns, and guardrail decisions — **always on**,
   not level-gated.
2. Emit **JSON to stdout** (12-factor / containerized) using a **vendor-neutral
   schema** plus documented adapter mappings.
3. **Ship** logs via a Fluent Bit sidecar to any SIEM (Splunk HEC / Elastic /
   Wazuh / cloud) by configuration swap — no app code change to re-target.
4. Provide **detection content** (correlation rules) and a **dashboard spec**,
   mapped to the OWASP LLM Top-10 risks AlienBank already teaches.
5. Preserve the lab's teaching value: keep the **L0/L1 "no local audit trail"
   gap** as an in-app lesson, but make *production-grade* logging a demonstrable
   "secure posture" that contrasts with it.

---

## 3. Design

### 3.1 Log event schema (vendor-neutral core)

A single canonical event envelope, ECS-inspired but neutral, so adapters can map
to ECS / Splunk CIM / OCSF.

```
timestamp        RFC3339 UTC
event.id         uuid
event.category   authentication | transaction | data_access | authorization
                 | agent_turn | admin | abuse
event.action     e.g. login, transfer, get_statement, deposit, level_change
event.outcome    success | failure | blocked | pending
event.severity   info | notice | warning | critical
actor.ref        random per-user pseudonym (users.pseudonym) — NOT the username or a sequential id
actor.role       customer | teller
target_ref       HMAC(secret, submitted_username) — login-target correlation on
                 AUTHENTICATION events, where there is no authenticated actor.ref
                 yet. Non-reversible, computed identically for real & nonexistent
                 users (no enumeration oracle). NEVER the raw username.
session_id       raw uuid4 token (already non-identifying) — session correlation
source.ip        network telemetry — retained (security signal, not treated as PII here)
http.method
http.path        route TEMPLATE only, e.g. /api/accounts/{id}/statement — never a concrete account number
http.status
labels.level     0-3   (per-session difficulty)
labels.secure_agent  bool
amount_band      "<1k" | "1k-10k" | ">10k"  — categorical, never the exact amount
security.*       (see below)
trace.request_id correlation id for one HTTP request
message          templated summary from a fixed set — NO free-form user text, names, or amounts
```

> No field above carries PII or financial data. `actor.ref` and `session_id` are
> non-identifying handles kept **raw** for correlation (no hashing); everything
> sensitive is represented by a verdict flag or a categorical band.

**Event categories to cover**

| Category | Fires on | Teaching signal |
|----------|----------|-----------------|
| `authentication` | login success/failure, logout, `login_throttle` marker — each carrying `target_ref` (the pre-auth per-username token) so an attack on a *specific* account is correlatable even before/without a valid login | brute-force, credential stuffing, distributed brute force, account takeover |
| `transaction` | transfer, deposit, loan apply/repay | money movement, denial-of-wallet |
| `data_access` | balance / statement / recipient reads, with an **object-ownership flag** | IDOR / BOLA (log denied cross-account attempts even though REST is hardened) |
| `authorization` | 403 / `Forbidden`, teller-only endpoints hit by non-tellers | privilege escalation (LLM06) |
| `agent_turn` | folds in existing `audit.py` **verdicts** (outcome, bypassed layers, cross_tenant, state_changing) — **not** the message text or tool arguments | prompt injection, guardrail evasion |
| `admin` | DB reset, level change | tamper / config drift |
| `abuse` | rate-limit 429, oversize 413 | unbounded consumption (LLM10) |

**Security-specific sub-object** — carries the AlienBank teaching signal into the
SIEM:

```
security.attack            bool
security.owasp_id          e.g. "LLM01", "LLM06"
security.bypassed_layers   [ "D1", "D2", ... ]
security.blocked_by        "D3" | "D5" | "rate-limit" | null
security.cross_tenant      bool
security.state_changing    bool
security.canary_leak       bool   (system-prompt leakage, LLM07)
```

### 3.2 New / changed modules

| Module | Role |
|--------|------|
| `src/alienbank/db.py` + `bank.py` *(small change)* | Add a nullable **`users.pseudonym`** column (random `secrets.token_hex(16)`), set on user creation and backfilled once for seed users via the existing idempotent `ALTER TABLE` migration pattern (`db.py:545+`). Expose it on `Actor` as `actor.ref`. **No FK changes** (only `accounts.owner_id` references `users.id`, which is untouched). |
| `src/alienbank/logging_setup.py` *(new)* | Configure stdlib `logging` with a **JSON formatter → stdout**; a `RequestIdMiddleware` (FastAPI) that stamps a per-request `trace.request_id` and captures `source.ip`, method, path, status, latency. |
| `src/alienbank/seclog.py` *(new)* | Thin helpers: `security_event(category, action, outcome, actor, **security)` emitting the canonical envelope. **Never raises into the request path** (mirrors `audit.record`'s safety contract). Builds only safe fields (verdicts, bands, refs); a final **allow-list serializer** drops any key not in the schema, so a sensitive value can never leak by accident. |
| `src/alienbank/agent/audit.py` *(refactor)* | Make the trail **PII-free at the source**: replace the truncated `message` text with a non-identifying **`message_shape`** (length band, detected-injection flag, no content), replace exact amounts with `amount_band`, and drop tool `arguments` in favour of the existing verdict fields (`target_account`→`cross_tenant` flag, name→omitted). The local `data/audit.jsonl` and `alienbank-audit` CLI keep working (same schema minus the sensitive fields); the SIEM gets the **same** PII-free projection via `seclog`. One representation everywhere. **Also reword the `narrative` string** — today it embeds the exact amount and account number (*"…transfer_funds for KES 5,000.00 on 0x…"*); it becomes band/flag-based (*"…transfer of amount_band `1k-10k` to a cross-tenant account, executed"*). |

### 3.3 Instrumentation points (edits, no new endpoints)

- **`web/app.py`**
  - `login_submit` — success **and** the 401 failure, both carrying `target_ref`
    (§3.7); plus a `login_throttle` marker when a per-`source.ip` failure burst
    trips the threshold
  - `logout`
  - `/api/transfer`, teller deposit / profile, loans apply / repay
  - `_log_and_error` (generalized `_bank_error_response`) — 403 / 404 / insufficient
    funds, flagging `Forbidden` as the cross-tenant/BOLA signal
  - rate-limit (429) and size-cap (413) returns
  - `/api/reset`, `/api/level`
- **`agent/chat.py`** `_audit` path — route through `seclog` so **all levels**
  emit a security event to the SIEM (while local `audit.jsonl` stays L2+ to
  preserve the teachable gap).

**PII / financial-data policy (enforced at the source + an allow-list serializer)**

- **Omit at the source** — the instrumentation never passes usernames (including
  the raw **submitted** username on a failed login — that is PII and often a
  pasted password; it is HMAC'd to `target_ref` instead, §3.7), names, emails,
  phones, account numbers, exact amounts, message text, tool arguments,
  transaction notes, or the canary value to `seclog`. It passes the verdict/band.
- **Kept raw for correlation (no hashing):** `session_id` (already a random
  `uuid4`), `request_id`, `actor.ref` (surrogate handle), `source.ip`, `role`.
- **Derived (hashed) for correlation:** `target_ref` = `HMAC(SECRET_KEY, username)`
  on auth events only (§3.7) — the one place the secret is used by the log path.
- **Allow-list serializer** — `seclog` emits *only* the schema fields; any unknown
  key is dropped. This is a safety net so a future careless call can't leak a
  sensitive value into the SIEM stream.
- **Secrets** `AWS_BEARER_TOKEN_BEDROCK` is never referenced by the logging path.
  `ALIENBANK_SECRET_KEY` is used **only** as the HMAC key for `target_ref` and is
  never itself logged; it becomes the security boundary for that token (§3.7).

> **Local `audit.jsonl` is PII-free too (decided).** The file currently stores
> truncated message text, exact amounts, and tool arguments. It will be changed to
> hold the **same PII-free projection** as the SIEM stream — `message_shape`
> instead of message text, `amount_band` instead of amounts, verdict flags instead
> of raw account numbers / names. There is **one** representation everywhere; the
> `alienbank-audit` CLI still renders the security story (outcome, layers,
> narrative) but no longer displays any personal or financial data.

### 3.4 Shipping pipeline (containerized)

```
AlienBank  (JSON → stdout)
      │   Docker json-file / K8s stdout
      ▼
 Fluent Bit sidecar        ← config-only routing, no app change
      │   parse · enrich (host, env, k8s meta) · drop-unknown-keys safety-net · buffer/retry (TLS)
      ├──► Splunk HEC             (splunk output)
      ├──► Elasticsearch / ELK    (es output, ECS mapping)
      ├──► Wazuh / OpenSearch     (opensearch output)
      └──► syslog / cloud         (generic)
```

**Deliverables:** `Dockerfile`, `docker-compose.yml` (app + Fluent Bit + one demo
SIEM, e.g. OpenSearch + Dashboards), `fluent-bit.conf` with commented output
stanzas for each target, TLS + buffered/retry config, and a `logging` env block
in `.env.example`.

### 3.5 Detection & monitoring content

**Correlation rules** — portable pseudo-rules plus one concrete syntax
(**Sigma**, convertible to Splunk/Elastic):

| Rule | Trigger | OWASP / risk | Severity |
|------|---------|--------------|----------|
| Brute force (single account) | N failed logins sharing **one** `target_ref` in window (any `source.ip` — catches distributed) | Auth | warning |
| Credential stuffing / spraying | one `source.ip` with **many distinct** `target_ref` failing in window | Auth | warning |
| Auth throttle tripped | `action=login_throttle` (app-side marker; `severity=critical` when single-target) | Auth | critical |
| Account takeover | failure burst on `target_ref` X → `outcome=success` for the same `target_ref` X | Auth | critical |
| IDOR / BOLA probing | `security.cross_tenant=true` OR `outcome=blocked` on `data_access` | LLM02 | warning |
| Guardrail evasion | `security.attack=true` with non-empty `bypassed_layers` | LLM01 | warning |
| **Compromise** | `agent_turn` `outcome=compromise` (money moved / cross-tenant executed) | LLM01/LLM06 | **critical** |
| Prompt leakage | `security.canary_leak=true` | LLM07 | critical |
| Denial-of-wallet | rate-limit 429 spikes | LLM10 | notice |
| Privilege escalation | teller-only endpoint hit by role ≠ teller | LLM06 | warning |

**Dashboard spec** (SIEM-agnostic panels):

- auth failures over time
- top actors (`actor.ref`) by attack score
- OWASP-LLM category breakdown
- compromise timeline
- guardrail-block funnel (active → bypassed → blocked_by)

**Alerting tiers** mapped to `event.severity`, with example notification routing.

### 3.6 Identity & correlation model

How the SIEM attributes activity to a user **without ever holding PII** — a
two-tier (separation-of-duties) design.

**The correlation handle: `actor.ref` = a random per-user pseudonym.**
A new nullable column `users.pseudonym` holds a random 128-bit token
(`secrets.token_hex(16)`), generated at user creation and backfilled once for
seed users. `Actor` exposes it; every event a user generates carries the same
`actor.ref`. This is a **stored random value, not a hash** — so there is no salt
to protect or rotate.

**Two tiers of identity:**

| Question | Answered by | Using |
|----------|-------------|-------|
| *"Is there an attack, and which actor / session is behind it?"* | **The SIEM** | `actor.ref`, `session_id`, `source.ip` — all in the log |
| *"Who is `actor.ref` `9f3a…` in the real world?"* | **The app / IR responder**, on a confirmed incident, under authorization | a privileged `pseudonym → username` lookup in the app DB |

The SIEM correlates on `actor.ref` exactly as it would on a username — timelines,
brute-force attribution, attack-chain reconstruction, cross-session pivots — so
**detection is not impaired**. Re-identification is a *separate, audited,
access-controlled* step in the app, done only when an incident justifies it.

**Why a random pseudonym and not the alternatives** (recap of the decision):

- **Not the sequential `users.id`** — that leaks user count/ordering (enumeration)
  and is a direct DB key.
- **Not `HMAC(user_id)`** — AlienBank's user space is tiny, so a leaked salt lets
  an attacker rebuild every token by brute force; also adds key custody/rotation.
- **Not a `users.id → UUID` PK migration** — cleaner in greenfield, but a wider
  schema change with a trap (a PK can leak into cookies/URLs and re-expose the
  identifier). Scoped out as its own initiative; the logging layer just reads
  `actor.ref`, so that migration could happen later without touching this design.
- **A dedicated random `pseudonym` column** — purpose-built for logging, zero FK
  churn, structurally cannot leak into URLs/sessions, no key management. **Chosen.**

**Honest caveats (true of any pseudonym):**

1. **Pseudonymized ≠ anonymous.** `source.ip` + timestamps + behaviour can still
   re-identify a person. So the **SIEM index itself must be secured**: access
   control, retention limits, and integrity (append-only / WORM). Pseudonymization
   shrinks the blast radius of a log leak; it does not remove the need to protect
   the store.
2. **`source.ip` is treated as a retained security signal**, not stripped — but
   note some regimes (e.g. GDPR) consider it personal data. This is a documented,
   deliberate governance choice, not an oversight.

### 3.7 Pre-auth identity: `target_ref` for login-attack detection

The pseudonym model above only works *after* login — a failed or scripted login
has **no authenticated actor**, so no `actor.ref`. Yet the auth surface is exactly
where brute-force, credential stuffing, spraying, and account takeover happen. To
detect *which account* is under attack without logging the username (PII — and on
a failure often a **pasted password**), authentication events carry a second
handle:

```
target_ref = HMAC_SHA256(ALIENBANK_SECRET_KEY, normalize(submitted_username))[:16]
```

- **Stable** — same username → same token, so single-account brute force is
  visible even when **distributed across many source IPs**.
- **Enumeration-safe** — computed identically for real *and* nonexistent
  usernames, so it never reveals whether an account exists (unlike, e.g., logging
  the raw username only for known users).
- **Non-reversible** without the secret; the raw username never enters the log.
- **Correlates the whole attack**: many failures on one `target_ref` = brute
  force; one `source.ip` with many distinct `target_ref` = stuffing; failure
  burst on `target_ref` X → `success` for X = **takeover**.

**Why HMAC here, when §3.6 rejected HMAC for the pseudonym.** Not a
contradiction — the two are different problems:

| | `actor.ref` (pseudonym) | `target_ref` (login target) |
|--|--|--|
| Identity exists at log time? | Yes — a DB row | Often **no** (failed/unknown login) |
| Random stored token possible? | Yes — `users.pseudonym` | No — nothing to store against |
| So the choice is | random column (no key) — **chosen** | HMAC is the only option that is stable + enumeration-safe |

The §3.6 objection to HMAC (tiny user space → a leaked *secret* lets an attacker
rebuild every token) still applies and is **accepted, scoped to this pre-auth
case**: it requires compromising *both* the access-controlled log store *and*
`ALIENBANK_SECRET_KEY`, and there is no random-pseudonym alternative for a login
that failed. `ALIENBANK_SECRET_KEY` is therefore the security boundary for
`target_ref` and **must** be set to a real random value in any deployment (it also
signs the session cookie). Where a stored pseudonym *does* exist (`actor.ref`), we
still prefer it — `target_ref` is purely the pre-auth complement.

**Auth throttle marker (observability, not a block).** A per-`source.ip` sliding
window (default 5 failures / 300s) emits an `action=login_throttle` event when
tripped — `severity=critical` when a single `target_ref` dominates (brute force),
`warning` when many distinct targets (stuffing). It does **not** block the login
(this plan is observability-only, §Non-goals); it is a high-signal marker for the
SIEM. The counters are in-process (single-node lab); the durable detector is the
SIEM correlation rule over the raw events.

---

## 4. Documentation deliverables

| File | Contents |
|------|----------|
| `SECURITY_LOGGING.md` *(new)* | Schema reference, event catalog, PII policy, adapter field mappings (neutral → ECS / CIM / OCSF). |
| `SIEM_INTEGRATION.md` *(new)* | Deploy the sidecar, point it at each SIEM, import rules/dashboards. |
| `SECURITY_COVERAGE.md` *(update)* | Upgrade the **Observability / audit** row from "JSONL at L2+" to full SIEM pipeline; add a **Logging & Monitoring** section. |

---

## 5. Implementation phases

1. ✅ **Schema + core** — `users.pseudonym` + `Actor.ref` (see
   [§3.6](#36-identity--correlation-model)); `logging_setup.py`, `seclog.py`
   (incl. `target_ref`, §3.7), request-ID middleware, allow-list serializer,
   JSON-to-stdout.
2. ✅ **Instrument REST + auth + agent** — points in [§3.3](#33-instrumentation-points-edits-no-new-endpoints)
   wired; `audit.py` gained the PII-free `security_projection` for the SIEM sink
   (agent turns emit at **all** levels; local `audit.jsonl` unchanged for now).
3. ⬜ **Ship** — Dockerfile, compose, Fluent Bit config, demo OpenSearch target.
4. ⬜ **Detect** — Sigma rules + dashboard spec + alert tiers.
5. ⬜ **Docs** — the deliverables in [§4](#4-documentation-deliverables).

---

## 6. Non-goals / decisions confirmed at build time

- `data/audit.jsonl` + the `alienbank-audit` CLI are **made PII-free** (decided —
  see below): same security story, no message text / amounts / account numbers /
  names. The file stays local and is never shipped; the SIEM gets the identical
  PII-free projection. The **L0/L1 "no local trail" lesson is unchanged** — that's
  about *absence* of a trail, independent of the trail's contents.
- L0/L1 keep **no local audit trail**, but **do** emit to the SIEM at all levels
  (decided) — so the SIEM sees the attacks the in-app trail deliberately misses (a
  teaching contrast: no local trail, yet central monitoring still caught it).
- **No changes to the security defenses** (D1–D5, `secure_agent`, guardrails).
  This is observability only.

---

## 7. Open questions for reviewer

1. ~~**L0/L1 SIEM emission**~~ — **RESOLVED:** emit to the SIEM at **all levels**
   (L0–L3). The SIEM sees every attack, including the ones the *local* L0/L1 trail
   deliberately omits — making "no local trail, but central monitoring still saw
   it" an explicit teaching contrast.
2. *(Deferred to build phase)* **Demo SIEM container** — include OpenSearch +
   Dashboards in `docker-compose` for a turnkey demo, or ship config only and
   assume an external SIEM?
3. *(Deferred to build phase)* **Concrete rule syntax** — Sigma (portable) is the
   plan default; want a second native format pre-generated (Splunk SPL / Elastic
   EQL)?
4. ~~**Local `audit.jsonl` privacy**~~ — **RESOLVED:** the local file is made
   PII-free too (`message_shape`/`amount_band`/verdict flags, reworded narrative).
   One PII-free representation everywhere.
