"""
routes/category.py — category browsing, ported from VulnMart's
category.php.

The interesting vulnerability here isn't the category listing itself,
it's what happens on the side: every page view logs the request's
User-Agent / X-Forwarded-For headers into `activity_logs`, and those
headers are built into the INSERT with plain string concatenation. This
is a *second-order* / stored injection reachable only through HTTP
headers (not visible in the URL or a form), and the payoff (reading
extracted data, or just corrupting rows) shows up later on the admin
panel's Activity Logs screen -- teaching that "the input field" for an
injection isn't always something you can see in the UI.
"""

import html as html_lib

from flask import Blueprint, request

from ..chrome import page, difficulty_badge
from ..db import conn
from ..difficulty import get_difficulty

bp = Blueprint("category", __name__)


def _log_visit(page_name: str, diff: str):
    xff = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
    ua = request.headers.get("User-Agent", "")

    if diff == "low":
        # Both headers concatenated straight into the INSERT.
        # Try, e.g.: curl -H "X-Forwarded-For: 1.2.3.4', (SELECT password FROM users WHERE username='admin'), 'x')-- -" ...
        # or a time-based probe via User-Agent: ...' AND (SELECT sleep(3))--
        sql = (
            f"INSERT INTO activity_logs (user_agent, ip_address, page, action) "
            f"VALUES ('{ua}', '{xff}', '{page_name}', 'browse')"
        )
        try:
            conn.execute(sql)
            conn.commit()
        except Exception:
            pass
    elif diff == "medium":
        # IP is validated as a real IP address (blocks the X-Forwarded-For
        # angle) but User-Agent -- which is just as attacker-controlled --
        # is still concatenated raw.
        import ipaddress
        try:
            ipaddress.ip_address(xff)
            safe_ip = xff
        except ValueError:
            safe_ip = "0.0.0.0"
        sql = (
            f"INSERT INTO activity_logs (user_agent, ip_address, page, action) "
            f"VALUES ('{ua}', '{safe_ip}', '{page_name}', 'browse')"
        )
        try:
            conn.execute(sql)
            conn.commit()
        except Exception:
            pass
    else:
        conn.execute(
            "INSERT INTO activity_logs (user_agent, ip_address, page, action) VALUES (?,?,?,?)",
            (ua, xff, page_name, "browse"),
        )
        conn.commit()


@bp.route("/category")
def category():
    slug = request.args.get("name", "")
    diff = get_difficulty("header_sqli")
    _log_visit(slug or "all", diff)

    if slug:
        rows = conn.execute("SELECT * FROM products WHERE category = ?", (slug,)).fetchall()
    else:
        rows = conn.execute("SELECT DISTINCT category FROM products").fetchall()
        cats = "".join(
            f'<a class="product" href="/category?name={html_lib.escape(c["category"])}">'
            f'<div class="body"><div class="name">{html_lib.escape(c["category"])}</div></div></a>'
            for c in rows
        )
        hint = ""
        if diff != "hard":
            hint = f"""<div class="alert warn" style="font-size:13px;">
              🎯 <b>Vulnerability:</b> Header-based SQL injection ({difficulty_badge(diff)}) &mdash;
              every visit here logs your <code>User-Agent</code> / <code>X-Forwarded-For</code>
              headers unsanitized into the activity log. Check <a href="/admin">Admin &rarr; Activity logs</a>
              after sending a crafted header.</div>"""
        return page("Browse categories", f'<h1 class="page-title">Browse by category</h1>{hint}<div class="grid">{cats}</div>')

    items = "".join(
        f"""<a class="product" href="/product?id={r['id']}">
              <div class="thumb">{r['image_url']}</div>
              <div class="body"><div class="name">{html_lib.escape(r['name'])}</div><div class="price">${r['price']:.2f}</div></div>
            </a>""" for r in rows
    )
    return page(
        "Browse categories",
        f'<h1 class="page-title">{html_lib.escape(slug)}</h1><div class="grid">{items or "<p class=\'hint\'>No products in this category.</p>"}</div>',
        breadcrumb=[("Categories", "/category"), (slug, None)],
    )
