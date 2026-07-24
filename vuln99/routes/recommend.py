"""
routes/recommend.py — "Recommended for you", ported from VulnMart's
recommend.php.

The vulnerability lives in an HTTP *cookie* rather than a query string
or form field, which is the point of the lesson: it can't be reached by
just typing into the search box, it has to be found by reading the
app's Set-Cookie headers and then edited by hand (browser devtools,
Burp Suite's Cookie header, or curl -b).
"""

import html as html_lib

from flask import Blueprint, request, make_response

from ..chrome import page, difficulty_badge
from ..db import conn
from ..difficulty import get_difficulty
from ..helpers import is_logged_in

bp = Blueprint("recommend", __name__)

DEFAULT_CATEGORY = "Tools"


def _fmt_price(value) -> str:
    try:
        return f"${float(value):.2f}"
    except (TypeError, ValueError):
        # A UNION payload put a non-numeric value in the price column --
        # show it as-is instead of crashing with a raw ValueError.
        return html_lib.escape(str(value))


@bp.route("/recommend")
def recommend():
    if not is_logged_in():
        from flask import redirect
        return redirect("/login")

    diff = get_difficulty("recommend_sqli")
    last_category = request.cookies.get("last_category", DEFAULT_CATEGORY)

    query_note = ""
    sql_error = None
    rows = []

    if diff == "low":
        # VULNERABLE: cookie value concatenated straight into the query.
        # Set (via devtools/Burp/curl -b) a cookie like:
        #   last_category=Tools' UNION SELECT id,username,password,role,'',''  FROM users --
        # (column count/types must line up with `products`: id, name,
        # price, category, blurb, image_url)
        query = f"SELECT * FROM products WHERE category = '{last_category}' ORDER BY id DESC LIMIT 6"
        query_note = query
        try:
            rows = conn.execute(query).fetchall()
        except Exception as e:
            sql_error = str(e)
    elif diff == "medium":
        # addslashes()-style escaping only -- blocks the simplest
        # quote-breakout but a UNION using a doubled quote or a comment
        # sequence still gets through.
        safe_cat = last_category.replace("'", "\\'")
        query = f"SELECT * FROM products WHERE category = '{safe_cat}' ORDER BY id DESC LIMIT 6"
        query_note = f"[MEDIUM] backslash-escaped cookie value: {query}"
        try:
            rows = conn.execute(query).fetchall()
        except Exception as e:
            sql_error = str(e)
    else:
        rows = conn.execute(
            "SELECT * FROM products WHERE category = ? ORDER BY id DESC LIMIT 6", (last_category,)
        ).fetchall()
        query_note = "[HARD] parameterized query -- cookie value is not injectable"

    cards = "".join(
        f"""<a class="product" href="/product?id={r['id']}">
              <div class="thumb">{r['image_url']}</div>
              <div class="body"><div class="name">{html_lib.escape(str(r['name']))}</div><div class="price">{_fmt_price(r['price'])}</div></div>
            </a>""" for r in rows
    )

    hint = ""
    if diff != "hard":
        hint = f"""
        <div class="alert warn" style="font-size:13px;">
          🎯 <b>Vulnerability:</b> Cookie-based SQL injection ({difficulty_badge(diff)})<br>
          The <code>last_category</code> cookie is used to build this page's query. Edit it in
          devtools/Burp and reload &mdash; current value: <code>{html_lib.escape(last_category)}</code>
        </div>"""

    err_html = f'<div class="alert err">Database error: {html_lib.escape(sql_error)}</div>' if sql_error else ""
    query_html = f'<pre class="hint">{html_lib.escape(query_note)}</pre>' if query_note and diff != "hard" else ""

    body = f"""
    <h1 class="page-title">Recommended for you</h1>
    {hint}
    <p class="hint">Based on your recent browsing in <b>{html_lib.escape(last_category)}</b></p>
    {err_html}
    {'<div class="grid">' + cards + '</div>' if rows else ('' if sql_error else '<p class="hint">No products matched that category.</p>')}
    {query_html}
    """
    resp = make_response(page("Recommended for you", body))
    if not request.cookies.get("last_category"):
        resp.set_cookie("last_category", DEFAULT_CATEGORY)
    return resp
