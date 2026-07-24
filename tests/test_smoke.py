"""
Smoke tests for vuln99.

These are NOT security tests -- they don't confirm the vulnerabilities
work (that's the point of the app). They confirm the app *boots and
serves every route without 500ing* at every difficulty tier, so an
edit to one route or a difficulty branch can't silently break the app
for a class/CTF run. Run with:

    pytest -q
    # or: ./setup.sh --test
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from vuln99 import create_app
from vuln99.difficulty import VULN_CATALOG, set_difficulty as set_difficulty


@pytest.fixture()
def app():
    app = create_app()
    app.testing = True
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


def _login(client, username="admin", password="admin123"):
    return client.post("/login", data={"username": username, "password": password})


def test_home_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200


@pytest.mark.parametrize("path", [
    "/", "/search?q=widget", "/product?id=1", "/blind-product?id=1",
    "/slow-product?id=1", "/login", "/register", "/cart",
    "/category", "/category?name=Tools", "/version",
])
def test_public_routes_load(client, path):
    resp = client.get(path)
    assert resp.status_code < 500, f"{path} returned {resp.status_code}"


def test_login_and_account(client):
    resp = _login(client)
    assert resp.status_code in (302, 303)
    resp = client.get("/account")
    assert resp.status_code == 200
    assert b"admin" in resp.data


def test_recommend_requires_login_then_loads(client):
    resp = client.get("/recommend")
    assert resp.status_code in (302, 303)  # redirected to /login
    _login(client)
    resp = client.get("/recommend")
    assert resp.status_code == 200


def test_admin_forbidden_when_logged_out(client):
    resp = client.get("/admin")
    assert resp.status_code == 403


def test_admin_reachable_when_logged_in_as_admin(client):
    # broken_admin's cookie-based bypass is what makes 'low' (the
    # default) grant access without a real login -- exercise the
    # *hard* tier here to confirm the real role check also works.
    set_difficulty("broken_admin", "hard")
    _login(client)
    resp = client.get("/admin")
    assert resp.status_code == 200
    resp = client.get("/admin/logs")
    assert resp.status_code == 200


def test_real_admin_login_works_at_every_difficulty(client):
    # Regression test: a genuinely logged-in admin must never be denied
    # by the broken_admin lesson, at any difficulty -- the vuln is that
    # *other* people can also get in, not that the real admin can't.
    _login(client)
    for level in ("low", "medium", "hard"):
        set_difficulty("broken_admin", level)
        resp = client.get("/admin")
        assert resp.status_code == 200, f"real admin denied at broken_admin={level}"


def test_become_admin_demo_cookie_bypass_at_low(client):
    # broken_admin defaults to 'low' on a fresh seed -- the documented
    # cookie bypass should work without logging in at all.
    resp = client.get("/admin/become-admin-demo")
    assert resp.status_code in (302, 303)
    resp = client.get("/admin")
    assert resp.status_code == 200


@pytest.mark.parametrize("level", ["low", "medium", "hard"])
def test_every_vuln_route_survives_every_difficulty(app, client, level):
    """Loop every catalog key through every tier and hit a representative
    route for it, making sure nothing 500s."""
    route_for_key = {
        "login_sqli": lambda: client.post("/login", data={"username": "a' OR '1'='1", "password": "x"}),
        "search_sqli": lambda: client.get("/search?q=widget"),
        "product_sqli": lambda: client.get("/product?id=1"),
        "blind_sqli_bool": lambda: client.get("/blind-product?id=1"),
        "blind_sqli_time": lambda: client.get("/slow-product?id=1"),
        "reflected_xss": lambda: client.get("/search?q=<b>hi</b>"),
        "stored_xss": lambda: client.get("/product?id=1"),
        "recommend_sqli": lambda: (_login(client), client.get("/recommend"))[-1],
        "header_sqli": lambda: client.get("/category?name=Tools"),
        "csrf": lambda: client.get("/cart"),
        "idor_orders": lambda: (_login(client), client.get("/orders?id=1"))[-1],
        "broken_admin": lambda: client.get("/admin"),
        "mass_assignment": lambda: (_login(client), client.post("/account", data={"email": "a@b.com", "bio": "hi"}))[-1],
        "price_tamper": lambda: client.post("/cart", data={"product_id": "1", "price": "1.00"}),
        "path_traversal": lambda: client.get("/read-file?file=notes.txt"),
        "file_upload": lambda: client.get("/account"),
        "command_injection": lambda: client.get("/ping?host=127.0.0.1"),
        "open_redirect": lambda: client.get("/go?url=/"),
        "ssrf": lambda: client.post("/admin/import-image", data={"url": "http://127.0.0.1:1/"}),
        "xxe": lambda: client.get("/admin/import-orders"),
        "insecure_deserialization": lambda: client.get("/login"),
        "ssti": lambda: client.get("/admin/email-preview"),
        "weak_crypto": lambda: client.post("/register", data={"username": f"u{level}", "email": "x@x.com", "password": "pw"}),
        "verbose_errors": lambda: client.get("/product?id=notanumber"),
    }

    with app.app_context():
        set_difficulty("login_sqli" if level else "login_sqli", level)  # no-op warmup

    key = None
    for key in route_for_key:
        set_difficulty(key, level)

    for key, call in route_for_key.items():
        resp = call()
        # Some are tuples from chained calls above; normalize.
        status = resp.status_code if hasattr(resp, "status_code") else resp[-1].status_code
        # 504 is allowed for command_injection specifically: /ping shells
        # out to the real `ping` binary, which may be unavailable or
        # network-restricted in a CI/sandbox environment. The route
        # already catches that timeout and returns a clean 504 rather
        # than crashing, which is what we're actually checking for.
        acceptable = status < 500 or (key == "command_injection" and status == 504)
        assert acceptable, f"{key} @ {level} returned {status}"


def test_all_catalog_keys_have_a_default_difficulty(app):
    from vuln99.difficulty import all_difficulties
    with app.app_context():
        diffs = all_difficulties()
    assert set(diffs.keys()) == set(VULN_CATALOG.keys())
    assert all(v in ("low", "medium", "hard") for v in diffs.values())
