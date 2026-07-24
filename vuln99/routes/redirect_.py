from flask import Blueprint, request, redirect

from ..chrome import page
from ..difficulty import get_difficulty

bp = Blueprint("redirect_", __name__)

ALLOWED_HOSTS = {"", "vuln99.test", "localhost"}


@bp.route("/go")
def go():
    url = request.args.get("url", "/")
    diff = get_difficulty("open_redirect")

    if diff == "low":
        # Open Redirect: the target is used completely unvalidated, e.g.
        # /go?url=https://evil.example/phish
        return redirect(url)
    elif diff == "medium":
        # naive check -- only blocks urls that literally start with
        # "http", so a protocol-relative "//evil.example" still works.
        if url.startswith("http://") or url.startswith("https://"):
            return page("Redirecting", '<div class="alert err">External redirects are blocked.</div>')
        return redirect(url)
    else:
        # hard: only relative, in-site paths are allowed
        if url.startswith("/") and not url.startswith("//"):
            return redirect(url)
        return page("Redirecting", '<div class="alert err">Invalid redirect target.</div>')


@bp.route("/safe-go")
def safe_go():
    url = request.args.get("url", "/")
    if url.startswith("/") and not url.startswith("//"):
        return redirect(url)
    return page("Redirecting (hardened)", '<div class="alert err">Invalid redirect target.</div>')
