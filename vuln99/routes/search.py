import html as html_lib

from flask import Blueprint, request

from ..chrome import page
from ..db import conn
from ..difficulty import get_difficulty

bp = Blueprint("search", __name__)


def _results_html(rows, q_echo):
    if not rows:
        return f'<p class="hint">No products matched.</p>'
    items = "".join(
        f"""<a class="product" href="/product?id={r['id']}">
              <div class="thumb">{r['image_url']}</div>
              <div class="body"><div class="name">{r['name']}</div><div class="price">${r['price']:.2f}</div></div>
            </a>""" for r in rows
    )
    return f'<div class="grid">{items}</div>'


@bp.route("/search")
def search():
    q = request.args.get("q", "")
    xss_diff = get_difficulty("reflected_xss")
    sqli_diff = get_difficulty("search_sqli")

    # Reflected XSS: the raw query string is echoed back into the page.
    # e.g. ?q=<script>alert(1)</script>
    if xss_diff == "low":
        echo = q
    elif xss_diff == "medium":
        # naive filter -- strips the literal string "<script>" but
        # nothing else, so it's bypassable with case changes, other
        # tags/event handlers, etc.
        echo = q.replace("<script>", "").replace("</script>", "")
    else:
        echo = html_lib.escape(q)

    sqli_note = ""
    if not q:
        rows = conn.execute("SELECT * FROM products").fetchall()
    elif sqli_diff == "low":
        # UNION-based SQLi: string-built LIKE query, e.g.
        #   q=xxxx' UNION SELECT id,username,1,password,role,'' FROM users --
        query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR category LIKE '%{q}%'"
        try:
            rows = conn.execute(query).fetchall()
        except Exception as e:
            rows = []
            sqli_note = f'<div class="alert err">Database error: {e}</div>'
    elif sqli_diff == "medium":
        safe_q = q.replace("'", "''")
        query = f"SELECT * FROM products WHERE name LIKE '%{safe_q}%' OR category LIKE '%{safe_q}%'"
        rows = conn.execute(query).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM products WHERE name LIKE ? OR category LIKE ?",
            (f"%{q}%", f"%{q}%"),
        ).fetchall()

    body = f"""
    <h1 class="page-title">Search results</h1>
    <p class="hint">You searched for: {echo}</p>
    {sqli_note}
    {_results_html(rows, q)}
    """
    return page("Search", body)


@bp.route("/safe-search")
def safe_search():
    q = request.args.get("q", "")
    rows = conn.execute(
        "SELECT * FROM products WHERE name LIKE ? OR category LIKE ?",
        (f"%{q}%", f"%{q}%"),
    ).fetchall() if q else conn.execute("SELECT * FROM products").fetchall()
    body = f"""
    <h1 class="page-title">Search results (hardened reference implementation)</h1>
    <p class="hint">You searched for: {html_lib.escape(q)}</p>
    {_results_html(rows, q)}
    """
    return page("Safe search", body)
