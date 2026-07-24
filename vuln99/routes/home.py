import html as html_lib

from flask import Blueprint

from ..chrome import page, difficulty_badge
from ..db import conn
from ..difficulty import VULN_CATALOG, all_difficulties

bp = Blueprint("home", __name__)


def _product_card(row):
    pid = row["id"]
    return f"""
    <a class="product" href="/product?id={pid}">
      <div class="thumb">{row['image_url']}</div>
      <div class="body">
        <div class="name">{html_lib.escape(row['name'])}</div>
        <div class="price">${row['price']:.2f}</div>
        <div class="blurb">{html_lib.escape(row['blurb'])}</div>
      </div>
    </a>
    """


def diagnostics_panel():
    """Compact teaser for the homepage — the full, searchable index of
    all 24 vulnerabilities (grouped by category) now lives at /lab, so
    the storefront front page doesn't dump every raw route at once."""
    diffs = all_difficulties()
    n_low = sum(1 for v in diffs.values() if v == "low")
    n_medium = sum(1 for v in diffs.values() if v == "medium")
    n_hard = sum(1 for v in diffs.values() if v == "hard")
    return f"""
    <div class="diag">
      <div class="diag-head">
        <span class="dot"></span>
        <span class="title">{len(VULN_CATALOG)} vulnerabilities catalogued</span>
        <span class="sub">{difficulty_badge('low')} &times;{n_low} &nbsp; {difficulty_badge('medium')} &times;{n_medium} &nbsp; {difficulty_badge('hard')} &times;{n_hard}</span>
      </div>
      <div class="diag-body">
        <a class="btn" href="/lab">Open the Vulnerability Lab &rarr;</a>
      </div>
    </div>
    """


@bp.route("/")
def home():
    products = conn.execute("SELECT * FROM products").fetchall()
    cards = "".join(_product_card(p) for p in products)
    body = f"""
    <div class="hero">
      <div>
        <div class="eyebrow">Security training lab</div>
        <h1>Precision tools.<br>Professionally vulnerable.</h1>
        <p>Vuln99 Outfitters is a realistic storefront built to practice web application penetration testing &mdash; every page here is intentionally vulnerable, with difficulty levels you can dial up or down.</p>
        <div class="actions"><a class="btn" href="#catalog">Shop the catalog</a> <a class="btn ghost" href="/lab">Vulnerability Lab</a></div>
      </div>
      <div class="hero-art">&#128295;</div>
    </div>
    <div class="section-head" id="catalog"><h2>Featured products</h2><span class="sub">{len(products)} items</span></div>
    <div class="grid">{cards}</div>
    {diagnostics_panel()}
    """
    return page("Home", body)
