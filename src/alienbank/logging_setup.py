"""Wire the security logger to stdout as newline-delimited JSON.

In a container, stdout is the log transport: a Fluent Bit sidecar tails it and
ships each line to the SIEM. Locally, it's what you see in the terminal — so the
lines you read here are byte-for-byte what would reach the SIEM.

:func:`security_event` already emits a fully-formed JSON string as the log
*message*; this module just makes sure that message is written to stdout once,
with no logger prefixes wrapping it (which would break JSON parsing downstream).
"""
from __future__ import annotations

import logging
import sys

from .seclog import LOGGER_NAME

_configured = False


def setup_security_logging(level: int = logging.INFO) -> None:
    """Attach a stdout handler to the security logger (idempotent).

    The formatter is ``%(message)s`` only: :func:`seclog.security_event` hands us
    a complete JSON object as the message, so we emit it raw — one JSON document
    per line, exactly what a SIEM shipper expects.
    """
    global _configured
    if _configured:
        return

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    # Don't bubble up to the root logger — avoids a second, prefixed copy.
    logger.propagate = False

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    _configured = True
