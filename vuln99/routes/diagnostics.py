import html as html_lib
import subprocess

from flask import Blueprint, request

from ..chrome import page
from ..difficulty import get_difficulty

bp = Blueprint("diagnostics", __name__)


@bp.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    diff = get_difficulty("command_injection")

    try:
        if diff == "low":
            # Deliberately vulnerable: shell=True with string-concatenated
            # input, e.g. host=127.0.0.1; cat /etc/passwd
            output = subprocess.run(
                f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=10,
            )
        elif diff == "medium":
            # naive blacklist -- strips ";" only, still bypassable with
            # "&&", "|", "$()", backticks, newlines, etc.
            cleaned = host.replace(";", "")
            output = subprocess.run(
                f"ping -c 1 {cleaned}", shell=True, capture_output=True, text=True, timeout=10,
            )
        else:
            # hard: shell=False with an argument list, same as safe_ping
            output = subprocess.run(
                ["ping", "-c", "1", host], shell=False, capture_output=True, text=True, timeout=10,
            )
        combined = html_lib.escape(output.stdout + output.stderr)
        body = f'<h1 class="page-title">Network diagnostics</h1><div class="card"><div class="panel-title">Ping result</div><pre>{combined}</pre></div>'
        return page("Diagnostics", body)
    except (subprocess.TimeoutExpired, OSError) as e:
        return page("Diagnostics", f'<div class="alert err">{html_lib.escape(str(e))}</div>'), 504


@bp.route("/ping-slow")
def ping_slow():
    """Same vulnerable pattern as /ping, but the output is discarded --
    the only observable signal is response timing, for practicing
    blind command injection."""
    host = request.args.get("host", "127.0.0.1")
    diff = get_difficulty("command_injection")
    try:
        if diff == "low":
            subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=20)
        elif diff == "medium":
            cleaned = host.replace(";", "")
            subprocess.run(f"ping -c 1 {cleaned}", shell=True, capture_output=True, text=True, timeout=20)
        else:
            subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        pass
    return page("Diagnostics", '<div class="alert ok">&#9989; Request processed.</div>')


@bp.route("/safe-ping")
def safe_ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        output = subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True, text=True, timeout=10)
        combined = html_lib.escape(output.stdout + output.stderr)
        return page("Diagnostics (safe)", f'<div class="card"><pre>{combined}</pre></div>')
    except (subprocess.TimeoutExpired, OSError) as e:
        return page("Diagnostics (safe)", f'<div class="alert err">{html_lib.escape(str(e))}</div>')
