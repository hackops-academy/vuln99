import html as html_lib
import os

from flask import Blueprint, request

from ..chrome import page
from ..difficulty import get_difficulty

bp = Blueprint("fileops", __name__)

DOCS_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_files")
DOCS_DIR = os.path.abspath(DOCS_DIR)


@bp.route("/read-file")
def read_file():
    filename = request.args.get("file", "readme.txt")
    diff = get_difficulty("path_traversal")

    if diff == "low":
        # Path Traversal / LFI: the filename is joined onto the base
        # directory with zero validation, so "../../../../etc/passwd"
        # (or an absolute path) escapes the intended folder entirely.
        target = os.path.join(DOCS_DIR, filename)
    elif diff == "medium":
        # naive filter -- strips the literal "../" but a payload like
        # "..%2f..%2f" or "....//" can still bypass a single-pass replace.
        cleaned = filename.replace("../", "")
        target = os.path.join(DOCS_DIR, cleaned)
    else:
        # hard: resolve to an absolute path and refuse anything that
        # escapes DOCS_DIR.
        candidate = os.path.abspath(os.path.join(DOCS_DIR, filename))
        if not candidate.startswith(DOCS_DIR + os.sep):
            return page("Document viewer", '<div class="alert err">Access denied.</div>'), 403
        target = candidate

    try:
        with open(target, "r", errors="replace") as fh:
            content = fh.read(4000)
    except Exception as e:
        content = f"Error reading file: {e}"

    body = f"""
    <h1 class="page-title">Document viewer</h1>
    <p class="hint">Requested file: {html_lib.escape(filename)}</p>
    <pre>{html_lib.escape(content)}</pre>
    <p class="hint">Available: <a href="/read-file?file=readme.txt">readme.txt</a>,
       <a href="/read-file?file=shipping-policy.txt">shipping-policy.txt</a></p>
    """
    return page("Document viewer", body)


@bp.route("/safe-read-file")
def safe_read_file():
    filename = os.path.basename(request.args.get("file", "readme.txt"))
    allow = {"readme.txt", "shipping-policy.txt"}
    if filename not in allow:
        return page("Document viewer (hardened)", '<div class="alert err">File not in allow-list.</div>')
    with open(os.path.join(DOCS_DIR, filename), "r") as fh:
        content = fh.read(4000)
    return page("Document viewer (hardened)", f"<pre>{html_lib.escape(content)}</pre>")
