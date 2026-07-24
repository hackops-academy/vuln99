import html as html_lib
import ipaddress
import socket
from urllib.parse import urlparse

import requests

from flask import Blueprint, request

from ..chrome import page
from ..difficulty import get_difficulty
from ..helpers import is_admin

bp = Blueprint("ssrf", __name__)


def _looks_blocked_naive(hostname: str) -> bool:
    """medium: a naive, commonly-seen-in-the-wild blacklist that only
    matches a handful of literal strings. It doesn't resolve DNS and
    doesn't understand alternate IP encodings, so it's bypassable with:
      - decimal/hex/octal IP forms (http://2130706433/, http://0x7f.0.0.1/)
      - a domain you control that resolves to an internal address (DNS
        rebinding) -- e.g. "attacker-owned-domain.test" -> 127.0.0.1
      - IPv6 loopback shorthand (http://[::1]/)
      - a trailing dot (http://127.0.0.1./)
    """
    h = (hostname or "").lower().strip(".")
    blocked_literals = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    if h in blocked_literals:
        return True
    if h.startswith("169.254.") or h.startswith("192.168.") or h.startswith("10."):
        return True
    return False


def _is_private(hostname: str) -> bool:
    """hard: resolves the hostname and checks the *actual* IP(s) it
    points to against RFC1918/loopback/link-local ranges -- this is
    what defeats decimal/hex encoding and DNS-rebinding tricks, because
    it looks at where the name really resolves rather than pattern-
    matching the string."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return True
        return False
    except Exception:
        return True  # fail closed if it can't be resolved


@bp.route("/admin/import-image", methods=["GET", "POST"])
def import_image():
    if request.method == "GET":
        return page("Import product image", """
        <h1 class="page-title">Import product image from URL</h1>
        <div class="card">
          <form class="stack" method="post" action="/admin/import-image">
            <label>Image URL</label><input type="text" name="url" placeholder="https://cdn.example.com/widget.png">
            <button type="submit">Fetch</button>
          </form>
          <p class="hint">Used by merchandisers to pull product photos from supplier CDNs. Server fetches the URL and reports back what it found.</p>
        </div>
        """)

    url = request.form.get("url", "")
    diff = get_difficulty("ssrf")
    parsed = urlparse(url)

    if diff == "medium" and _looks_blocked_naive(parsed.hostname or ""):
        return page("Import product image", '<div class="alert err">Refusing to fetch an internal/private address.</div>')
    if diff == "hard":
        if parsed.scheme not in ("http", "https"):
            return page("Import product image", '<div class="alert err">Only http/https URLs are allowed.</div>')
        if _is_private(parsed.hostname or ""):
            return page("Import product image", '<div class="alert err">Refusing to fetch an internal/private address.</div>')

    # SSRF: the server fetches an entirely attacker-controlled URL with
    # no allow-list. At 'low'/'medium' this can be pointed at internal
    # services (e.g. http://127.0.0.1:PORT/, a cloud metadata endpoint,
    # or another host on the internal network) and the response is
    # reflected back, turning the app into a proxy for internal recon.
    try:
        if diff == "hard":
            # Also re-check every hop: a URL that resolves safely at
            # request time can still 302 to an internal address.
            resp = requests.get(url, timeout=5, allow_redirects=False)
            hops = 0
            while resp.is_redirect and hops < 5:
                next_url = resp.headers.get("Location", "")
                next_host = urlparse(next_url).hostname or ""
                if _is_private(next_host):
                    return page("Import product image", '<div class="alert err">Refusing to follow a redirect into an internal/private address.</div>')
                resp = requests.get(next_url, timeout=5, allow_redirects=False)
                hops += 1
        else:
            resp = requests.get(url, timeout=5)
        snippet = resp.text[:1500]
        body = f"""
        <h1 class="page-title">Import result</h1>
        <div class="card">
          <p><b>Status:</b> {resp.status_code}</p>
          <p><b>Headers:</b></p>
          <pre>{html_lib.escape(chr(10).join(f"{k}: {v}" for k,v in resp.headers.items()))}</pre>
          <p><b>Body (first 1500 chars):</b></p>
          <pre>{html_lib.escape(snippet)}</pre>
        </div>
        """
    except Exception as e:
        body = f'<div class="alert err">Fetch failed: {html_lib.escape(str(e))}</div>'
    return page("Import result", body)
