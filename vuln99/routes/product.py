import html as html_lib

from flask import Blueprint, request

from ..chrome import page
from ..db import conn
from ..difficulty import get_difficulty

bp = Blueprint("product", __name__)


def _product_body(row, extra_note=""):
    if not row:
        return '<div class="alert err">Product not found.</div>'
    reviews = conn.execute(
        "SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC", (row["id"],)
    ).fetchall()

    xss_diff = get_difficulty("stored_xss")
    review_html = ""
    for r in reviews:
        body_text = r["body"] if xss_diff == "low" else (
            r["body"].replace("<script>", "").replace("</script>", "")
            if xss_diff == "medium" else html_lib.escape(r["body"])
        )
        review_html += f"""<div class="card"><b>{html_lib.escape(r['username'])}</b><p>{body_text}</p></div>"""

    return f"""
    <h1 class="page-title">{html_lib.escape(row['name'])}</h1>
    {extra_note}
    <div class="card">
      <div style="font-size:48px;">{row['image_url']}</div>
      <p>{html_lib.escape(row['blurb'])}</p>
      <div class="price" style="font-size:20px;">${row['price']:.2f}</div>
      <form method="post" action="/cart"><input type="hidden" name="product_id" value="{row['id']}">
        <input type="hidden" name="price" value="{row['price']}">
        <button type="submit">Add to cart</button></form>
    </div>
    <h3>Reviews</h3>
    {review_html or '<p class="hint">No reviews yet.</p>'}
    <div class="card">
      <form class="stack" method="post" action="/reviews"><input type="hidden" name="product_id" value="{row['id']}">
        <label>Leave a review</label><textarea name="body" rows="3"></textarea>
        <button type="submit">Post review</button></form>
    </div>
    """


@bp.route("/product")
def product():
    pid = request.args.get("id", "1")
    diff = get_difficulty("product_sqli")
    verbose = get_difficulty("verbose_errors")

    if diff == "low":
        # Error-based SQLi: id is concatenated straight into the query.
        # e.g. ?id=1 AND 1=CONVERT(int,(SELECT username FROM users))
        query = f"SELECT * FROM products WHERE id = {pid}"
        try:
            row = conn.execute(query).fetchone()
        except Exception as e:
            msg = f"Database error: {e}" if verbose != "hard" else "An internal error occurred."
            return page("Product", f'<div class="alert err">{msg}</div>' + (f"<pre>{html_lib.escape(query)}</pre>" if verbose == "low" else ""))
    elif diff == "medium":
        try:
            pid_int = int(pid)
            row = conn.execute("SELECT * FROM products WHERE id = ?", (pid_int,)).fetchone()
        except ValueError:
            # falls back to the unsafe path for non-numeric input
            query = f"SELECT * FROM products WHERE id = '{pid}'"
            try:
                row = conn.execute(query).fetchone()
            except Exception as e:
                return page("Product", f'<div class="alert err">Database error: {e}</div>')
    else:
        try:
            row = conn.execute("SELECT * FROM products WHERE id = ?", (int(pid),)).fetchone()
        except ValueError:
            return page("Product", '<div class="alert err">Invalid product id.</div>')

    return page("Product", _product_body(row), breadcrumb=[(row["name"] if row else "Product", None)])


@bp.route("/blind-product")
def blind_product():
    """Boolean-blind SQLi: no data or errors are ever shown -- only a
    generic 'found' / 'not found' response, so the injection must be
    inferred from the true/false behaviour of the page."""
    pid = request.args.get("id", "1")
    diff = get_difficulty("blind_sqli_bool")

    if diff == "low":
        query = f"SELECT id FROM products WHERE id = {pid}"
        try:
            row = conn.execute(query).fetchone()
        except Exception:
            row = None
    elif diff == "medium":
        safe_pid = pid.replace("'", "''")
        query = f"SELECT id FROM products WHERE id = '{safe_pid}'"
        try:
            row = conn.execute(query).fetchone()
        except Exception:
            row = None
    else:
        try:
            row = conn.execute("SELECT id FROM products WHERE id = ?", (int(pid),)).fetchone()
        except ValueError:
            row = None

    status = "ok" if row else "err"
    text = "Product exists." if row else "No such product."
    return page("Product lookup", f'<div class="alert {status}">{text}</div>')


@bp.route("/slow-product")
def slow_product():
    """Time-blind SQLi: response is delayed when the injected condition
    is true, via the sleep() function registered in db.py."""
    pid = request.args.get("id", "1")
    diff = get_difficulty("blind_sqli_time")

    if diff == "low":
        query = f"SELECT id FROM products WHERE id = {pid} OR sleep(0)=0"
        try:
            conn.execute(query).fetchall()
        except Exception:
            pass
    elif diff == "medium":
        safe_pid = pid.replace("'", "''")
        query = f"SELECT id FROM products WHERE id = '{safe_pid}'"
        try:
            conn.execute(query).fetchall()
        except Exception:
            pass
    else:
        try:
            conn.execute("SELECT id FROM products WHERE id = ?", (int(pid),)).fetchall()
        except ValueError:
            pass

    return page("Product lookup", '<div class="alert info">Lookup complete.</div>')


@bp.route("/safe-product")
def safe_product():
    pid = request.args.get("id", "1")
    try:
        row = conn.execute("SELECT * FROM products WHERE id = ?", (int(pid),)).fetchone()
    except ValueError:
        return page("Product", '<div class="alert err">Invalid product id.</div>')
    return page("Product (hardened)", _product_body(row))
