"""AlienBank — a security lab banking app.

Two layers share one banking core:

* The REST API (``web/app.py``) is *hardened*: every operation is bound to the
  authenticated server session and enforces ownership + role. No IDOR/BOLA.
* The chat agent (``agent/``) is *deliberately vulnerable*: its tools trust
  LLM-supplied ``account_number`` / ``role`` arguments, so prompt injection can
  cross tenant boundaries and escalate a customer into teller actions
  (OWASP LLM01 -> excessive agency).

Set ``ALIENBANK_SECURE_AGENT=true`` to swap the agent onto the secure core and
demonstrate the fix.
"""

__version__ = "0.1.0"
