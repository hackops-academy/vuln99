"""
logging_setup.py — request/audit logging for vuln99.

Writes a rolling access log (method, path, status, source IP, UA) plus
an events log for admin actions (difficulty changed, become-admin-demo
used, etc.) so a class or CTF run has a paper trail to match up against
whatever scanner/proxy/capture the student is running alongside it.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

from flask import g, request
import time

from .config import Config

_configured = False


def _make_logger(name: str, filename: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(Config.LOG_LEVEL)
    logger.propagate = False
    if not logger.handlers:
        os.makedirs(Config.LOG_DIR, exist_ok=True)
        handler = RotatingFileHandler(
            os.path.join(Config.LOG_DIR, filename), maxBytes=2_000_000, backupCount=3
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(handler)
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console)
    return logger


access_log = _make_logger("vuln99.access", "access.log")
event_log = _make_logger("vuln99.events", "events.log")


def init_request_logging(app):
    """Registers before/after_request hooks that log every request.
    Idempotent -- safe to call once from create_app()."""
    global _configured
    if _configured:
        return
    _configured = True

    @app.before_request
    def _start_timer():
        g._t0 = time.time()

    @app.after_request
    def _log_request(response):
        try:
            elapsed_ms = (time.time() - getattr(g, "_t0", time.time())) * 1000
            access_log.info(
                "%s %s -> %s (%.1fms) ip=%s ua=%s",
                request.method,
                request.full_path if request.query_string else request.path,
                response.status_code,
                elapsed_ms,
                request.headers.get("X-Forwarded-For", request.remote_addr),
                request.headers.get("User-Agent", "-")[:120],
            )
        except Exception:
            pass  # logging must never break a response
        return response


def log_event(message: str, *args) -> None:
    event_log.info(message, *args)
