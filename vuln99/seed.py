"""
seed.py — resets and populates the in-memory-on-disk SQLite db every
time the app starts, so the lab always boots into a known-good state
(same philosophy as VulnMart's `docker-compose down -v` + db/init.sql).
"""

import hashlib
from datetime import datetime, timedelta

from .db import conn, init_schema


def _md5(s: str) -> str:
    # Intentionally weak: unsalted MD5. This IS the "weak_crypto" vuln,
    # not a mistake — see difficulty.py's VULN_CATALOG.
    return hashlib.md5(s.encode()).hexdigest()


USERS = [
    # username, password, email, role
    ("admin",       "admin123",     "admin@vuln99.test",       "admin"),
    ("john_doe",    "password123",  "john@vuln99.test",        "user"),
    ("alice_smith", "password123",  "alice@vuln99.test",       "user"),
    ("bob_jones",   "password123",  "bob@vuln99.test",         "user"),
]

PRODUCTS = [
    ("Widget",          12.00, "Tools",      "A dependable, all-purpose widget.",                    "🔧"),
    ("Gadget",           24.00, "Tools",      "Does more than a widget. Allegedly.",                  "⚙️"),
    ("Precision Driver Set", 34.50, "Tools", "42-piece driver set for electronics work.",             "🪛"),
    ("Bench Multimeter", 58.00, "Electronics","Auto-ranging, true-RMS, safety-rated.",                "📟"),
    ("Cable Organizer",  9.99,  "Accessories","Keeps your bench from turning into spaghetti.",        "🧵"),
    ("Solder Station",   89.00, "Electronics","Temperature-controlled, digital display.",             "🔥"),
]

REVIEWS = [
    (1, "john_doe",    "Solid widget, does exactly what it says."),
    (1, "alice_smith", "Bought two, both work great."),
    (2, "bob_jones",   "Better than expected for the price."),
]


def seed_all():
    init_schema()
    c = conn
    c.execute("DELETE FROM users")
    c.execute("DELETE FROM products")
    c.execute("DELETE FROM reviews")
    c.execute("DELETE FROM orders")
    c.execute("DELETE FROM order_items")
    c.execute("DELETE FROM settings")
    c.execute("DELETE FROM activity_logs")

    for username, password, email, role in USERS:
        c.execute(
            "INSERT INTO users (username, password, email, role, bio) VALUES (?,?,?,?,?)",
            (username, _md5(password), email, role, f"Hi, I'm {username}!"),
        )

    for name, price, category, blurb, image in PRODUCTS:
        c.execute(
            "INSERT INTO products (name, price, category, blurb, image_url) VALUES (?,?,?,?,?)",
            (name, price, category, blurb, image),
        )

    now = datetime.utcnow()
    for product_id, username, body in REVIEWS:
        c.execute(
            "INSERT INTO reviews (product_id, username, body, created_at) VALUES (?,?,?,?)",
            (product_id, username, body, now.isoformat()),
        )

    # a couple of sample orders so IDOR / order-history routes have data
    c.execute(
        "INSERT INTO orders (user_id, total, status, created_at) VALUES (?,?,?,?)",
        (2, 36.00, "delivered", (now - timedelta(days=5)).isoformat()),
    )
    c.execute("INSERT INTO order_items (order_id, product_id, qty, price) VALUES (1,1,3,12.00)")
    c.execute(
        "INSERT INTO orders (user_id, total, status, created_at) VALUES (?,?,?,?)",
        (3, 58.00, "shipped", (now - timedelta(days=1)).isoformat()),
    )
    c.execute("INSERT INTO order_items (order_id, product_id, qty, price) VALUES (2,4,1,58.00)")

    c.commit()
