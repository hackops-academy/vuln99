import html as html_lib

from flask import Blueprint

from ..chrome import page, difficulty_badge
from ..cheatsheet import CHEATSHEET
from ..difficulty import VULN_CATALOG, all_difficulties

bp = Blueprint("lab", __name__)

# key -> exploit URL (a request that demonstrates the vuln at "low")
EXPLOIT_URL = {
    "login_sqli": "/login",
    "search_sqli": "/search?q=widget",
    "product_sqli": "/product?id=1",
    "blind_sqli_bool": "/blind-product?id=1",
    "blind_sqli_time": "/slow-product?id=1",
    "recommend_sqli": "/recommend",
    "header_sqli": "/category",
    "reflected_xss": "/search?q=widget",
    "stored_xss": "/product?id=1",
    "csrf": "/checkout",
    "idor_orders": "/orders?id=1",
    "broken_admin": "/admin",
    "mass_assignment": "/account",
    "price_tamper": "/cart",
    "path_traversal": "/read-file?file=readme.txt",
    "file_upload": "/account/avatar",
    "command_injection": "/ping?host=127.0.0.1",
    "open_redirect": "/go?url=/",
    "ssrf": "/admin/import-image",
    "xxe": "/admin/import-orders",
    "insecure_deserialization": "/login",
    "ssti": "/admin/email-preview",
    "weak_crypto": "/register",
    "verbose_errors": "/product?id=abc",
}

# key -> the hardened sibling route, where one exists
SAFE_URL = {
    "search_sqli": "/safe-search?q=widget",
    "product_sqli": "/safe-product?id=1",
    "path_traversal": "/safe-read-file?file=readme.txt",
    "command_injection": "/safe-ping?host=127.0.0.1",
    "open_redirect": "/safe-go?url=/",
}

# Fixed display order for OWASP-ish categories so related vulns cluster
# together instead of appearing in catalog-insertion order.
CATEGORY_ORDER = [
    "A01 Broken Access Control",
    "A02 Cryptographic Failures",
    "A03 Injection",
    "A04 Insecure Design",
    "A05 Security Misconfiguration",
    "A08 Data Integrity Failures",
    "A10 SSRF",
]

TIERS = ["low", "medium", "hard"]


def _group_by_category():
    groups = {c: [] for c in CATEGORY_ORDER}
    for key, (name, category, desc) in VULN_CATALOG.items():
        groups.setdefault(category, []).append((key, name, desc))
    return groups


def _tier_row(key, tier, active: bool):
    entry = CHEATSHEET.get(key, {}).get(tier)
    if not entry:
        return ""
    cls = "atk-tier active" if active else "atk-tier"
    payload = entry["payload"]
    copy_btn = (
        f'<button type="button" class="copy-btn" data-copy="{html_lib.escape(payload, quote=True)}" '
        f'title="Copy payload">copy</button>'
        if payload and payload != "—" else ""
    )
    return f"""
    <div class="{cls}">
      <div class="atk-tier-head">{difficulty_badge(tier)}{' <span class="atk-current">current</span>' if active else ''}</div>
      <div class="atk-field"><span class="atk-label">Location</span><code>{html_lib.escape(entry['location'])}</code></div>
      <div class="atk-field"><span class="atk-label">Payload</span><code class="atk-payload">{html_lib.escape(payload)}</code>{copy_btn}</div>
      <div class="atk-note">{html_lib.escape(entry['note'])}</div>
    </div>"""


def _vuln_card(key, name, desc, difficulty):
    exploit = EXPLOIT_URL.get(key, "/")
    safe = SAFE_URL.get(key)
    safe_link = f' <a class="btn ghost" href="{safe}">Safe version</a>' if safe else ""
    tiers_html = "".join(_tier_row(key, t, t == difficulty) for t in TIERS)
    return f"""
    <details class="atk-card" data-name="{html_lib.escape(name.lower())}" data-key="{key}">
      <summary class="atk-summary">
        <span class="atk-summary-main">
          <b>{html_lib.escape(name)}</b>
          <span class="hint atk-desc">{html_lib.escape(desc)}</span>
        </span>
        <span class="atk-summary-side">{difficulty_badge(difficulty)}</span>
      </summary>
      <div class="atk-body">
        {tiers_html}
        <div class="atk-actions">
          <a class="btn" href="{exploit}">Try it</a>{safe_link}
        </div>
      </div>
    </details>"""


@bp.route("/lab")
def lab_index():
    diffs = all_difficulties()
    groups = _group_by_category()

    sections = []
    for category in CATEGORY_ORDER:
        entries = groups.get(category, [])
        if not entries:
            continue
        cards = "".join(_vuln_card(k, n, d, diffs[k]) for k, n, d in entries)
        sections.append(f"""
        <div class="lab-section" data-category="{html_lib.escape(category.lower())}">
          <div class="panel-title">{html_lib.escape(category)} &middot; {len(entries)}</div>
          <div class="atk-stack">{cards}</div>
        </div>""")

    n_low = sum(1 for v in diffs.values() if v == "low")
    n_medium = sum(1 for v in diffs.values() if v == "medium")
    n_hard = sum(1 for v in diffs.values() if v == "hard")

    body = f"""
    <h1 class="page-title">Vulnerability Lab</h1>
    <p class="hint">Every one of the {len(VULN_CATALOG)} vulnerabilities in Vuln99, grouped by
       category. Click a card to expand it &mdash; the location + payload shown match whatever
       difficulty that vuln is set to right now, so you never have to cross-reference a separate
       cheatsheet. Change difficulty in
       <a href="/admin/settings">Admin &rsaquo; Difficulty settings</a> &mdash;
       {difficulty_badge('low')} &times;{n_low} &nbsp; {difficulty_badge('medium')} &times;{n_medium}
       &nbsp; {difficulty_badge('hard')} &times;{n_hard} right now.</p>

    <div class="card">
      <input type="text" id="lab-filter" placeholder="Filter by name or category&hellip;"
             oninput="labFilter(this.value)"
             style="width:100%; background:var(--bg-alt); border:1px solid var(--line); color:var(--text); padding:10px 12px; border-radius:9px; font-size:13.5px;">
    </div>

    {''.join(sections)}

    <div class="card">
      <div class="panel-title">Pointing real tools at this app</div>
      <p class="hint">
        Vuln99 is a normal Flask/Werkzeug HTTP service &mdash; any standard proxy, fuzzer, or
        scanner works against it without special setup:
      </p>
      <ul class="hint" style="line-height:1.9;">
        <li><b>Burp Suite / OWASP ZAP / Glacier</b> &mdash; proxy your browser through it, browse the
            catalog and log in once to populate the site map and pick up a session cookie, then use
            Repeater against the <b>Location</b> + <b>Payload</b> pairs above, or run the active
            scanner / Spider from there.</li>
        <li><b>sqlmap</b> &mdash; e.g.
            <code>sqlmap -u "http://127.0.0.1:5099/product?id=1" -p id --batch</code>, or for the login
            form: <code>sqlmap -u "http://127.0.0.1:5099/login" --data="username=x&amp;password=x" -p username --batch</code>.</li>
        <li><b>nikto</b> &mdash; <code>nikto -h http://127.0.0.1:5099</code> for a general
            misconfiguration/info-disclosure sweep (pairs well with <code>verbose_errors</code> and
            <code>weak_crypto</code> at low difficulty).</li>
      </ul>
      <p class="hint">
        Keep the target on <code>low</code> difficulty while a scanner is confirming detections &mdash;
        bump individual vulns to <code>medium</code> afterward to practice manual filter-bypass technique
        instead of relying on the scanner's default payloads. Only bind beyond
        <code>127.0.0.1</code> on an isolated lab network &mdash; see the README's network binding
        section.
      </p>
    </div>

    <script>
    function labFilter(q) {{
      q = q.trim().toLowerCase();
      document.querySelectorAll('.atk-card').forEach(function(row) {{
        var hay = row.dataset.name + ' ' + row.closest('.lab-section').dataset.category;
        row.style.display = hay.indexOf(q) === -1 ? 'none' : '';
      }});
      document.querySelectorAll('.lab-section').forEach(function(sec) {{
        var anyVisible = Array.prototype.some.call(
          sec.querySelectorAll('.atk-card'), function(r) {{ return r.style.display !== 'none'; }}
        );
        sec.style.display = anyVisible ? '' : 'none';
      }});
    }}
    document.addEventListener('click', function(e) {{
      var btn = e.target.closest('.copy-btn');
      if (!btn) return;
      e.preventDefault();
      var text = btn.getAttribute('data-copy');
      navigator.clipboard.writeText(text).then(function() {{
        var orig = btn.textContent;
        btn.textContent = 'copied';
        setTimeout(function() {{ btn.textContent = orig; }}, 1200);
      }});
    }});
    </script>
    """
    return page("Vulnerability Lab", body, breadcrumb=[("Lab", None)])
