"""
db.py — shared SQLite connection + schema for vuln99.

One in-process SQLite database, created fresh on every startup (see
seed.py). Kept deliberately simple (no ORM) so every query in the route
modules is plain, readable SQL — the injection points are meant to be
obvious to a beginner reading the source, the same way DVWA / VulnMart
keep their query-building code un-abstracted.
"""

import os
import sqlite3
import tempfile

_DB_PATH = os.path.join(tempfile.gettempdir(), "vuln99.db")

# check_same_thread=False: Flask's dev server is multi-threaded and every
# route in this app shares one connection, same pattern glacier's test
# app already uses.
conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
conn.row_factory = sqlite3.Row

# SQLite has no SLEEP()/pg_sleep() built in — registering one is what
# lets time-based-blind routes stand in for a real database's timing
# side-channel.
import time as _time
conn.create_function("sleep", 1, lambda seconds: _time.sleep(float(seconds)) or 0)


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,           -- intentionally weak: plain MD5, no salt
    email TEXT,
    role TEXT DEFAULT 'user',
    bio TEXT DEFAULT '',
    avatar TEXT DEFAULT '/static/avatar-default.png'
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    price REAL,
    category TEXT,
    blurb TEXT,
    image_url TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY,
    product_id INTEGER,
    username TEXT,
    body TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    total REAL,
    status TEXT DEFAULT 'placed',
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY,
    order_id INTEGER,
    product_id INTEGER,
    qty INTEGER,
    price REAL
);

CREATE TABLE IF NOT EXISTS settings (
    vuln_key TEXT PRIMARY KEY,
    difficulty TEXT DEFAULT 'low'
);

-- Populated by /category on every page view (User-Agent / X-Forwarded-For
-- header values land here) and displayed back on the admin panel's
-- Activity Logs screen -- the "sink" half of the header_sqli lesson.
CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY,
    ip_address TEXT,
    user_agent TEXT,
    page TEXT,
    action TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


def init_schema():
    conn.executescript(SCHEMA)
    conn.commit()
