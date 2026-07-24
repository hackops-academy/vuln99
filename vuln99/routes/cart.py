import html as html_lib
import secrets

from flask import Blueprint, request, redirect, session

from ..chrome import page
from ..db import conn
from ..difficulty import get_difficulty
from ..helpers import is_logged_in

bp = Blueprint("cart", __name__)


def _cart():
    return session.setdefault("cart", [])


def _csrf_field():
    token = session.get("csrf_token")
    diff = get_difficulty("csrf")
    if diff == "low":
        return ""  # no token at all
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return f'<input type="hidden" name="csrf_token" value="{token}">'


@bp.route("/cart", methods=["GET"])
def view_cart():
    items = _cart()
    total = sum(i["price"] * i["qty"] for i in items)
    rows = "".join(
        f'<tr><td>{html_lib.escape(i["name"])}</td><td>{i["qty"]}</td><td>${i["price"]:.2f}</td><td>${i["price"]*i["qty"]:.2f}</td></tr>'
        for i in items
    )
    body = f"""
    <h1 class="page-title">Your cart</h1>
    <table><tr><th>Item</th><th>Qty</th><th>Unit price</th><th>Subtotal</th></tr>
      {rows or '<tr><td colspan="4">Your cart is empty.</td></tr>'}
    </table>
    <div class="card" style="margin-top:16px;">
      <p><b>Total: ${total:.2f}</b></p>
      <form method="post" action="/checkout">
        {_csrf_field()}
        <button type="submit" {"disabled" if not items else ""}>Checkout</button>
      </form>
    </div>
    """
    return page("Cart", body)


@bp.route("/cart", methods=["POST"])
def add_to_cart():
    product_id = request.form.get("product_id")
    submitted_price = request.form.get("price")
    diff = get_difficulty("price_tamper")

    row = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if not row:
        return redirect("/")

    if diff == "low":
        # Business-logic flaw: the price shown on the product page is
        # submitted right back by the client and trusted verbatim, so a
        # modified hidden <input name="price"> (or a raw curl request)
        # can buy anything for $0.01.
        try:
            price = float(submitted_price)
        except (TypeError, ValueError):
            price = row["price"]
    elif diff == "medium":
        # only guards against negative/zero, still lets you undercut
        # the real price to anything positive.
        try:
            price = float(submitted_price)
            if price <= 0:
                price = row["price"]
        except (TypeError, ValueError):
            price = row["price"]
    else:
        # hard: price always comes from the server-side catalog, the
        # client-submitted value is ignored entirely.
        price = row["price"]

    cart = _cart()
    cart.append({"product_id": row["id"], "name": row["name"], "price": price, "qty": 1})
    session["cart"] = cart
    return redirect("/cart")


@bp.route("/checkout", methods=["POST"])
def checkout():
    if not is_logged_in():
        return redirect("/login")

    diff = get_difficulty("csrf")
    if diff == "hard":
        submitted = request.form.get("csrf_token")
        if not submitted or submitted != session.get("csrf_token"):
            return page("Checkout", '<div class="alert err">Invalid or missing CSRF token.</div>'), 403
    # low: no check at all. medium: a token is rendered in the form but
    # the server never actually compares it against anything -- looks
    # protected, isn't.

    items = _cart()
    total = sum(i["price"] * i["qty"] for i in items)
    if not items:
        return redirect("/cart")

    cur = conn.execute(
        "INSERT INTO orders (user_id, total, status, created_at) VALUES (?,?,?,datetime('now'))",
        (session["user_id"], total, "placed"),
    )
    order_id = cur.lastrowid
    for i in items:
        conn.execute(
            "INSERT INTO order_items (order_id, product_id, qty, price) VALUES (?,?,?,?)",
            (order_id, i["product_id"], i["qty"], i["price"]),
        )
    conn.commit()
    session["cart"] = []
    return page("Checkout", f"""
    <div class="alert ok">Order #{order_id} placed successfully. Total charged: ${total:.2f}</div>
    <a class="btn" href="/orders">View my orders</a>
    """)
