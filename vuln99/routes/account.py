import html as html_lib
import os
import re
import tempfile

from flask import Blueprint, request, redirect, session

from ..chrome import page
from ..db import conn
from ..difficulty import get_difficulty
from ..helpers import is_logged_in, current_user, enumeration_guard

bp = Blueprint("account", __name__)

AVATAR_DIR = os.path.join(tempfile.gettempdir(), "vuln99_avatars")
os.makedirs(AVATAR_DIR, exist_ok=True)


def _require_login():
    return not is_logged_in()


@bp.route("/account")
def account():
    if request.args.get("id"):
        # IDOR: any authenticated user can view *any* user's profile by
        # supplying an arbitrary numeric id -- ownership is never
        # checked against the logged-in session.
        diff = get_difficulty("idor_orders")  # shares the "no ownership check" lesson
        if _require_login():
            return redirect("/login")
        try:
            uid = int(request.args["id"])
        except ValueError:
            return page("Account", '<div class="alert err">Invalid id.</div>')

        if diff == "hard" and uid != session.get("user_id") and session.get("role") != "admin":
            return page("Account", '<div class="alert err">You do not have access to that profile.</div>'), 403
        if diff == "medium" and enumeration_guard(uid, "_idor_account_seen"):
            return page("Account", '<div class="alert err">Too many different profiles requested from this session. Try again shortly.</div>'), 429

        target = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if not target:
            return page("Account", '<div class="alert err">User not found.</div>')
        return page("Account", f"""
        <h1 class="page-title">Profile: {html_lib.escape(target['username'])}</h1>
        <div class="card">
          <p><b>Email:</b> {html_lib.escape(target['email'] or '')}</p>
          <p><b>Role:</b> {html_lib.escape(target['role'])}</p>
          <p><b>Bio:</b> {target['bio']}</p>
        </div>
        <p class="hint">Try changing the ?id= parameter to view other accounts.</p>
        """)

    if _require_login():
        return redirect("/login")
    u = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return page("My account", f"""
    <h1 class="page-title">My account</h1>
    <div class="card">
      <p><b>Username:</b> {html_lib.escape(u['username'])}</p>
      <p><b>Role:</b> {html_lib.escape(u['role'])}</p>
      <form class="stack" method="post" action="/account">
        <label>Email</label><input type="text" name="email" value="{html_lib.escape(u['email'] or '')}">
        <label>Bio</label><textarea name="bio" rows="3">{u['bio']}</textarea>
        <input type="hidden" name="role" value="{html_lib.escape(u['role'])}">
        <button type="submit">Save changes</button>
      </form>
    </div>
    <div class="card">
      <div class="panel-title">Avatar</div>
      <form class="stack" method="post" action="/account/avatar" enctype="multipart/form-data">
        <input type="file" name="avatar">
        <button type="submit">Upload avatar</button>
      </form>
      <p class="hint">Uploaded files are saved under a server-side avatars directory.</p>
    </div>
    """)


@bp.route("/account", methods=["POST"])
def account_update():
    if _require_login():
        return redirect("/login")

    email = request.form.get("email", "")
    bio = request.form.get("bio", "")
    role = request.form.get("role")
    diff = get_difficulty("mass_assignment")

    if diff == "low" and role:
        # Mass assignment: the form ships a hidden "role" field and the
        # server blindly trusts and applies it -- an attacker can add
        # role=admin to a raw POST and self-promote.
        conn.execute(
            "UPDATE users SET email = ?, bio = ?, role = ? WHERE id = ?",
            (email, bio, role, session["user_id"]),
        )
        session["role"] = role
    elif diff == "medium":
        # only blocks the literal value "admin" -- still bypassable
        # with different casing / other privileged role names.
        safe_role = None if role == "admin" else role
        if safe_role:
            conn.execute(
                "UPDATE users SET email = ?, bio = ?, role = ? WHERE id = ?",
                (email, bio, safe_role, session["user_id"]),
            )
        else:
            conn.execute("UPDATE users SET email = ?, bio = ? WHERE id = ?", (email, bio, session["user_id"]))
    else:
        # hard: role is simply never accepted from the client
        conn.execute("UPDATE users SET email = ?, bio = ? WHERE id = ?", (email, bio, session["user_id"]))
    conn.commit()
    return redirect("/account")


@bp.route("/account/avatar", methods=["POST"])
def account_avatar():
    if _require_login():
        return redirect("/login")
    f = request.files.get("avatar")
    if not f or not f.filename:
        return redirect("/account")

    diff = get_difficulty("file_upload")

    if diff == "low":
        # Unrestricted file upload: the client-supplied filename is used
        # as-is, with no extension allow-list and no path sanitization,
        # so "../../somewhere/important.txt" escapes the avatars folder.
        dest = os.path.join(AVATAR_DIR, f.filename)
    elif diff == "medium":
        # strips path separators but still allows any extension
        name = f.filename.replace("/", "").replace("\\", "")
        dest = os.path.join(AVATAR_DIR, name)
    else:
        # hard: allow-listed extensions + a generated, collision-safe name
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in (".png", ".jpg", ".jpeg", ".gif"):
            return page("Account", '<div class="alert err">Unsupported file type.</div>')
        dest = os.path.join(AVATAR_DIR, f"user_{session['user_id']}{ext}")

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    f.save(dest)
    return redirect("/account")


@bp.route("/orders")
def orders():
    if _require_login():
        return redirect("/login")

    order_id = request.args.get("id")
    diff = get_difficulty("idor_orders")

    if order_id:
        try:
            oid = int(order_id)
        except ValueError:
            return page("Order", '<div class="alert err">Invalid order id.</div>')
        order = conn.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
        if not order:
            return page("Order", '<div class="alert err">Order not found.</div>')

        if diff == "hard" and order["user_id"] != session["user_id"] and session.get("role") != "admin":
            return page("Order", '<div class="alert err">You do not have access to this order.</div>'), 403
        if diff == "medium" and enumeration_guard(oid, "_idor_orders_seen"):
            return page("Order", '<div class="alert err">Too many different orders requested from this session. Try again shortly.</div>'), 429
        # low: no protection at all -- any logged-in user can read any
        # order by id. medium: still no ownership check, just a
        # per-session rate limiter on distinct ids (see enumeration_guard)
        # -- mistaking rate limiting for access control is a very real
        # bug, and it's still bypassable by slowing down or using a
        # fresh session.

        items = conn.execute("SELECT * FROM order_items WHERE order_id = ?", (oid,)).fetchall()
        rows = "".join(f"<tr><td>{i['product_id']}</td><td>{i['qty']}</td><td>${i['price']:.2f}</td></tr>" for i in items)
        return page("Order detail", f"""
        <h1 class="page-title">Order #{oid}</h1>
        <div class="card">
          <p><b>Placed by user id:</b> {order['user_id']} &nbsp; <b>Status:</b> {html_lib.escape(order['status'])}</p>
          <table><tr><th>Product</th><th>Qty</th><th>Price</th></tr>{rows}</table>
          <p style="margin-top:10px;"><b>Total:</b> ${order['total']:.2f}</p>
        </div>
        <p class="hint">Try changing ?id= to browse other orders.</p>
        """)

    my_orders = conn.execute("SELECT * FROM orders WHERE user_id = ?", (session["user_id"],)).fetchall()
    rows = "".join(f'<tr><td><a href="/orders?id={o["id"]}">#{o["id"]}</a></td><td>{html_lib.escape(o["status"])}</td><td>${o["total"]:.2f}</td></tr>' for o in my_orders)
    return page("My orders", f"""
    <h1 class="page-title">My orders</h1>
    <table><tr><th>Order</th><th>Status</th><th>Total</th></tr>{rows or '<tr><td colspan="3">No orders yet.</td></tr>'}</table>
    """)
