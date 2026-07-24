from flask import Blueprint, request, redirect

from ..db import conn
from ..helpers import is_logged_in, current_user

bp = Blueprint("reviews", __name__)


@bp.route("/reviews", methods=["POST"])
def post_review():
    """Submission side of the stored XSS in product.py -- the review
    body is stored completely as-is; sanitization (or lack of it) only
    happens at render time, controlled by the 'stored_xss' difficulty."""
    product_id = request.form.get("product_id")
    body = request.form.get("body", "")
    username = current_user()["username"] if is_logged_in() else "guest"

    if product_id and body.strip():
        conn.execute(
            "INSERT INTO reviews (product_id, username, body, created_at) VALUES (?,?,?,datetime('now'))",
            (product_id, username, body),
        )
        conn.commit()

    return redirect(f"/product?id={product_id}")
