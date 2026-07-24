"""
run.py — entry point for vuln99.

    python run.py
"""

from vuln99 import create_app
from vuln99.config import Config

app = create_app()

if __name__ == "__main__":
    # 127.0.0.1 only, by default, on purpose: this app is intentionally
    # vulnerable and must never be exposed beyond localhost / an
    # isolated lab VM. To point real tools (nmap, Wireshark, a scanner
    # on another VM in the same isolated lab network) at it, override
    # via environment variables instead of editing this file:
    #
    #   VULN99_HOST=0.0.0.0 VULN99_PORT=5099 python run.py
    #
    # See vuln99/config.py for the full list of overrides.
    if Config.is_bound_publicly():
        print(f"!! vuln99 is binding to {Config.HOST}, not just localhost.")
        print("!! Only do this on an isolated lab VM/network. Never expose")
        print("!! this app to the internet or a shared/corporate network.")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
