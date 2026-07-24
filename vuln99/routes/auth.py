import base64
import hashlib
import io
import pickle

from flask import Blueprint, request, session, redirect, make_response

from ..chrome import page
from ..db import conn
from ..difficulty import get_difficulty
from ..helpers import is_logged_in

bp = Blueprint("auth", __name__)


def _md5(s):
    return hashlib.md5(s.encode()).hexdigest()


# medium tier for insecure_deserialization: a "restricted unpickler",
# the fix people reach for first in the real world. This one blacklists
# a handful of obviously-dangerous modules -- but blacklists are a leaky
# abstraction. It never blocks the `builtins` module itself, so a
# payload built around builtins.eval/exec (or another allowed module
# with a dangerous callable) still gets through. The properly fixed
# version doesn't use pickle for this at all (see below).
_DENYLISTED_MODULES = {"os", "posix", "nt", "subprocess", "shutil", "pickle", "socket"}


class _RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module.split(".")[0] in _DENYLISTED_MODULES:
            raise pickle.UnpicklingError(f"blocked module: {module}")
        return super().find_class(module, name)


def _restricted_loads(blob: bytes):
    return _RestrictedUnpickler(io.BytesIO(blob)).load()


def _login_form(error=None, username=""):
    err = f'<div class="alert err">{error}</div>' if error else ""
    body = f"""
    <h1 class="page-title">Log in</h1>
    <div class="card">
      <form class="stack" method="post" action="/login">
        <label>Username</label>
        <input type="text" name="username" value="{username}">
        <label>Password</label>
        <input type="password" name="password">
        <label style="flex-direction:row; display:flex; align-items:center; gap:8px;">
          <input type="checkbox" name="remember" value="1" style="width:auto;"> Remember me
        </label>
        <button type="submit">Log in</button>
      </form>
      {err}
      <p class="hint" style="margin-top:16px;">Test accounts: admin/admin123, john_doe/password123, alice_smith/password123, bob_jones/password123</p>
    </div>
    """
    return page("Log in", body)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Insecure Deserialization (low): a "remember me" cookie that is
        # a base64-encoded pickle blob, unpickled with no validation.
        # This is a classic RCE-capable pattern (a crafted pickle can
        # execute arbitrary code on load) -- kept here at 'low' as a
        # standalone lesson even though this route also happens to be
        # the login page.
        token = request.cookies.get("remember_token")
        deser_diff = get_difficulty("insecure_deserialization")
        if token and deser_diff in ("low", "medium"):
            try:
                raw = base64.b64decode(token)
                data = pickle.loads(raw) if deser_diff == "low" else _restricted_loads(raw)
                user = conn.execute(
                    "SELECT * FROM users WHERE id = ?", (data.get("uid"),)
                ).fetchone()
                if user:
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    return redirect("/account")
            except Exception:
                pass
        return _login_form()

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    remember = request.form.get("remember")
    diff = get_difficulty("login_sqli")

    if diff == "low":
        # Classic string-built query -- textbook SQLi auth bypass, e.g.
        #   username: admin' --
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{_md5(password)}'"
        try:
            user = conn.execute(query).fetchone()
        except Exception as e:
            return _login_form(error=f"Database error: {e}", username=username)
    elif diff == "medium":
        # Naive escaping -- blocks the simplest quote-breakout payloads
        # but is still bypassable with encoding tricks / other operators.
        safe_username = username.replace("'", "''")
        query = f"SELECT * FROM users WHERE username = '{safe_username}' AND password = '{_md5(password)}'"
        user = conn.execute(query).fetchone()
    else:
        # hard: fully parameterized
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, _md5(password)),
        ).fetchone()

    if not user:
        return _login_form(error="Invalid username or password.", username=username)

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    resp = make_response(redirect("/account"))
    if remember:
        deser_diff = get_difficulty("insecure_deserialization")
        if deser_diff in ("low", "medium"):
            # Same raw pickle cookie either way -- the difference is
            # entirely on the *reading* side (find_class filtering
            # above). That's deliberate: it demonstrates that a
            # blacklist-based unpickler doesn't make pickle itself any
            # safer to use, it just raises the bar for the payload.
            blob = base64.b64encode(pickle.dumps({"uid": user["id"]})).decode()
            resp.set_cookie("remember_token", blob, max_age=60 * 60 * 24 * 30)
        else:
            # hard: a signed, opaque, non-executable token instead of a
            # raw pickle -- Flask's session cookie already does this
            # correctly, so we just extend its lifetime.
            session.permanent = True
    return resp


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return page("Register", """
        <h1 class="page-title">Create an account</h1>
        <div class="card">
          <form class="stack" method="post" action="/register">
            <label>Username</label><input type="text" name="username">
            <label>Email</label><input type="email" name="email">
            <label>Password</label><input type="password" name="password">
            <button type="submit">Create account</button>
          </form>
        </div>
        """)

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        return page("Register", '<div class="alert err">Username and password are required.</div>')

    # weak_crypto (always-on lesson regardless of difficulty toggle,
    # same as VulnMart's unsalted-MD5 password column): passwords are
    # hashed with plain MD5 and no salt/pepper, so identical passwords
    # produce identical hashes and the hash is trivially reversible via
    # rainbow tables.
    try:
        conn.execute(
            "INSERT INTO users (username, password, email, role, bio) VALUES (?,?,?,?,?)",
            (username, _md5(password), email, "user", f"Hi, I'm {username}!"),
        )
        conn.commit()
    except Exception as e:
        return page("Register", f'<div class="alert err">Could not create account: {e}</div>')

    return redirect("/login")


@bp.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect("/"))
    resp.delete_cookie("remember_token")
    return resp
