import html as html_lib

from flask import Blueprint, request, redirect, session, make_response

from ..chrome import page, difficulty_badge
from ..db import conn
from ..difficulty import VULN_CATALOG, get_difficulty, set_difficulty, all_difficulties
from ..helpers import is_logged_in
from ..logging_setup import log_event

bp = Blueprint("admin", __name__)


def _admin_check():
    """Returns True if the current request is allowed into the admin
    area. A genuinely logged-in admin always gets in, at every
    difficulty -- the vulnerability is that *other* people can get in
    too, not that the real admin gets locked out.
    """
    if is_logged_in() and session.get("role") == "admin":
        return True

    diff = get_difficulty("broken_admin")
    if diff == "low":
        # Broken Access Control: admin-ness can ALSO be granted by a
        # client-supplied, unsigned cookie -- set `document.cookie =
        # "is_admin=true"` in devtools and you're in, logged in or not.
        return request.cookies.get("is_admin") == "true"
    elif diff == "medium":
        # A classic real-world bug: checks that a role *exists* on the
        # session instead of checking its *value*, so any logged-in
        # user (role="user") is let in as if they were staff.
        return bool(session.get("role"))
    else:
        # hard: only the real-admin check above applies.
        return False


@bp.route("/admin")
def admin_home():
    if not _admin_check():
        return page("Admin", '<div class="alert err">Forbidden. Admins only.</div>'), 403

    users = conn.execute("SELECT id, username, email, role FROM users").fetchall()
    rows = "".join(
        f'<tr><td>{u["id"]}</td><td>{html_lib.escape(u["username"])}</td>'
        f'<td>{html_lib.escape(u["email"] or "")}</td><td>{html_lib.escape(u["role"])}</td></tr>'
        for u in users
    )

    n_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    n_orders = conn.execute("SELECT COUNT(*) c FROM orders").fetchone()["c"]
    n_reviews = conn.execute("SELECT COUNT(*) c FROM reviews").fetchone()["c"]
    n_logs = conn.execute("SELECT COUNT(*) c FROM activity_logs").fetchone()["c"]
    diffs = all_difficulties()
    n_low = sum(1 for v in diffs.values() if v == "low")
    n_medium = sum(1 for v in diffs.values() if v == "medium")
    n_hard = sum(1 for v in diffs.values() if v == "hard")

    def _stat(label, value):
        return f'<div class="card" style="text-align:center;"><div style="font-size:26px;font-weight:800;">{value}</div><div class="hint">{label}</div></div>'

    stats = "".join([
        _stat("Users", n_users), _stat("Orders", n_orders), _stat("Reviews", n_reviews),
        _stat("Activity log entries", n_logs),
    ])
    diff_summary = f'{difficulty_badge("low")} &times;{n_low} &nbsp; {difficulty_badge("medium")} &times;{n_medium} &nbsp; {difficulty_badge("hard")} &times;{n_hard}'

    body = f"""
    <h1 class="page-title">Admin panel</h1>
    <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); margin-bottom:20px;">{stats}</div>
    <div class="card">
      <div class="panel-title">Users</div>
      <table><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>{rows}</table>
    </div>
    <div class="card">
      <div class="panel-title">Vulnerability difficulty ({len(VULN_CATALOG)} total)</div>
      <p class="hint">{diff_summary}</p>
    </div>
    <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(220px,1fr));">
      <a class="product" href="/admin/settings"><div class="body"><div class="name">Difficulty settings</div><div class="blurb">Tune every vulnerability's difficulty.</div></div></a>
      <a class="product" href="/admin/logs"><div class="body"><div class="name">Activity logs</div><div class="blurb">View logged page visits (header_sqli sink).</div></div></a>
      <a class="product" href="/admin/import-image"><div class="body"><div class="name">Import product image</div><div class="blurb">SSRF-prone URL fetcher.</div></div></a>
      <a class="product" href="/admin/import-orders"><div class="body"><div class="name">Bulk order import</div><div class="blurb">XXE-prone XML import.</div></div></a>
      <a class="product" href="/admin/email-preview"><div class="body"><div class="name">Email template preview</div><div class="blurb">SSTI-prone template renderer.</div></div></a>
    </div>
    """
    return page("Admin", body)


@bp.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    if not _admin_check():
        return page("Admin settings", '<div class="alert err">Forbidden. Admins only.</div>'), 403

    if request.method == "POST":
        bulk = request.form.get("bulk_set")
        if bulk in ("low", "medium", "hard"):
            for key in VULN_CATALOG:
                set_difficulty(key, bulk)
            log_event("Bulk difficulty change: all %d vulns set to %s", len(VULN_CATALOG), bulk)
            return redirect("/admin/settings")

        changed = 0
        for key in VULN_CATALOG:
            level = request.form.get(key)
            if level:
                set_difficulty(key, level)
                changed += 1
        log_event("Difficulty settings saved (%d vulns updated)", changed)
        return redirect("/admin/settings")

    diffs = all_difficulties()
    rows = []
    for key, (name, category, desc) in VULN_CATALOG.items():
        current = diffs[key]
        options = "".join(
            f'<option value="{lvl}" {"selected" if lvl == current else ""}>{lvl}</option>'
            for lvl in ("low", "medium", "hard")
        )
        rows.append(f"""
        <tr>
          <td><b>{html_lib.escape(name)}</b><div class="hint">{html_lib.escape(desc)}</div></td>
          <td>{html_lib.escape(category)}</td>
          <td>{difficulty_badge(current)}</td>
          <td><select name="{key}">{options}</select></td>
        </tr>""")

    body = f"""
    <h1 class="page-title">Difficulty settings</h1>
    <p class="hint">Set each vulnerability independently to <b>low</b> (fully vulnerable), <b>medium</b> (partial/bypassable mitigation), or <b>hard</b> (properly fixed) &mdash; same idea as VulnMart's per-page difficulty, applied per-vulnerability here.</p>
    <div class="card">
      <div class="panel-title">Bulk actions</div>
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <form method="post"><input type="hidden" name="bulk_set" value="low"><button type="submit">Set all to low</button></form>
        <form method="post"><input type="hidden" name="bulk_set" value="medium"><button type="submit">Set all to medium</button></form>
        <form method="post"><input type="hidden" name="bulk_set" value="hard"><button type="submit">Set all to hard</button></form>
      </div>
    </div>
    <form method="post">
      <div class="card">
        <table><tr><th>Vulnerability</th><th>Category</th><th>Current</th><th>Set to</th></tr>{''.join(rows)}</table>
      </div>
      <button type="submit">Save all</button>
    </form>
    <p class="hint">Tip (for the 'broken_admin' lesson at low difficulty): set a cookie <code>is_admin=true</code> to reach this page without logging in at all.</p>
    """
    return page("Admin settings", body)


@bp.route("/admin/logs")
def admin_logs():
    if not _admin_check():
        return page("Activity logs", '<div class="alert err">Forbidden. Admins only.</div>'), 403

    logs = conn.execute(
        "SELECT * FROM activity_logs ORDER BY id DESC LIMIT 100"
    ).fetchall()
    rows = "".join(
        f'<tr><td>{l["id"]}</td><td>{html_lib.escape(l["ip_address"] or "")}</td>'
        f'<td style="max-width:320px; overflow-wrap:anywhere;">{html_lib.escape(l["user_agent"] or "")}</td>'
        f'<td>{html_lib.escape(l["page"] or "")}</td><td>{html_lib.escape(l["action"] or "")}</td>'
        f'<td>{html_lib.escape(str(l["created_at"] or ""))}</td></tr>'
        for l in logs
    )
    body = f"""
    <h1 class="page-title">Activity logs</h1>
    <p class="hint">Most recent 100 entries. This is the sink for the <code>header_sqli</code> lesson &mdash;
    values here come straight from each visitor's <code>User-Agent</code> / <code>X-Forwarded-For</code>
    headers on <a href="/category">/category</a>, sanitized (or not) according to that vuln's difficulty.</p>
    <div class="card">
      <table><tr><th>ID</th><th>IP</th><th>User-Agent</th><th>Page</th><th>Action</th><th>When</th></tr>
        {rows or '<tr><td colspan="6">No activity logged yet. Visit /category to generate some.</td></tr>'}
      </table>
    </div>
    """
    return page("Activity logs", body)


@bp.route("/admin/become-admin-demo")
def become_admin_demo():
    """Convenience helper (not itself a vuln) that plants the is_admin
    cookie for people who want to see the 'low' broken_admin bypass
    without opening devtools."""
    resp = make_response(redirect("/admin"))
    resp.set_cookie("is_admin", "true")
    return resp
