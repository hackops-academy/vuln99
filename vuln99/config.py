"""
config.py — central, environment-driven configuration for vuln99.

Everything here has a safe-by-default value (localhost only). If you're
running vuln99 in an isolated lab VM/network and want to point real
tools at it (nmap, Wireshark, Burp, a scanner on another VM), override
these with environment variables instead of editing code:

    VULN99_HOST=0.0.0.0 VULN99_PORT=5099 python run.py

⚠️ Only set VULN99_HOST to anything other than 127.0.0.1 on a host that
is itself isolated (a lab VM / private virtual network with no route to
the internet or a shared corporate network). This app contains real,
working exploits (SQLi, command injection, XXE, SSRF, insecure
deserialization, ...) and must never be reachable from an untrusted
network.
"""

import os


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Config:
    # Bind address. Default is localhost-only on purpose -- see the
    # module docstring before changing this.
    HOST = os.environ.get("VULN99_HOST", "127.0.0.1")
    PORT = int(os.environ.get("VULN99_PORT", "5099"))

    # Flask's debug reloader/debugger is itself dangerous to expose
    # (the Werkzeug debugger allows remote code execution if the pin
    # is leaked) -- keep it tied to host, not just an independent flag.
    DEBUG = _env_bool("VULN99_DEBUG", HOST in ("127.0.0.1", "localhost"))

    SECRET_KEY = os.environ.get("VULN99_SECRET_KEY", "vuln99-dev-secret-not-for-production")

    # Where request/audit logs are written (see logging_setup.py). Handy
    # for cross-referencing what the app saw against a simultaneous
    # nmap/Wireshark capture during a class or CTF.
    LOG_DIR = os.environ.get("VULN99_LOG_DIR", os.path.join(os.getcwd(), "logs"))
    LOG_LEVEL = os.environ.get("VULN99_LOG_LEVEL", "INFO")

    @classmethod
    def is_bound_publicly(cls) -> bool:
        return cls.HOST not in ("127.0.0.1", "localhost", "::1")
