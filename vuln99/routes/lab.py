import html as html_lib

from flask import Blueprint

from ..chrome import page, difficulty_badge
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
    "file_upload": "/account",
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


def _group_by_category():
    groups = {c: [] for c in CATEGORY_ORDER}
    for key, (name, category, desc) in VULN_CATALOG.items():
        groups.setdefault(category, []).append((key, name, desc))
    return groups


def _vuln_row(key, name, desc, difficulty):
    exploit = EXPLOIT_URL.get(key, "/")
    safe = SAFE_URL.get(key)
    safe_link = f' <a class="btn ghost" href="{safe}">Safe version</a>' if safe else ""
    return f"""
    <tr class="lab-row" data-name="{html_lib.escape(name.lower())}" data-key="{key}">
      <td>
        <b>{html_lib.escape(name)}</b>
        <div class="hint">{html_lib.escape(desc)}</div>
      </td>
      <td>{difficulty_badge(difficulty)}</td>
      <td style="white-space:nowrap;">
        <a class="btn" href="{exploit}">Try it</a>{safe_link}
      </td>
    </tr>"""


@bp.route("/lab")
def lab_index():
    diffs = all_difficulties()
    groups = _group_by_category()

    sections = []
    for category in CATEGORY_ORDER:
        entries = groups.get(category, [])
        if not entries:
            continue
        rows = "".join(_vuln_row(k, n, d, diffs[k]) for k, n, d in entries)
        sections.append(f"""
        <div class="card lab-section" data-category="{html_lib.escape(category.lower())}">
          <div class="panel-title">{html_lib.escape(category)} &middot; {len(entries)}</div>
          <table><tbody>{rows}</tbody></table>
        </div>""")

    n_low = sum(1 for v in diffs.values() if v == "low")
    n_medium = sum(1 for v in diffs.values() if v == "medium")
    n_hard = sum(1 for v in diffs.values() if v == "hard")

    body = f"""
    <h1 class="page-title">Vulnerability Lab</h1>
    <p class="hint">Every one of the {len(VULN_CATALOG)} vulnerabilities in Vuln99, grouped by
       category. Click <b>Try it</b> to jump straight to a live payload, or <b>Safe version</b> to see
       the hardened sibling route side by side. Difficulty is set globally per-vulnerability in
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
        Vuln99 is a normal Flask/Werkzeug HTTP service &mdash; any standard web proxy or scanner
        works against it without special setup:
      </p>
      <ul class="hint" style="line-height:1.9;">
        <li><b>Burp Suite / OWASP ZAP</b> &mdash; set your browser's proxy to Burp/ZAP, browse the
            catalog and login once to populate the site map and pick up a session cookie, then run the
            active scanner or Spider/Ajax Spider from there. The QA links above give it a fast, complete
            crawl seed.</li>
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
      document.querySelectorAll('.lab-row').forEach(function(row) {{
        var hay = row.dataset.name + ' ' + row.closest('.lab-section').dataset.category;
        row.style.display = hay.indexOf(q) === -1 ? 'none' : '';
      }});
      document.querySelectorAll('.lab-section').forEach(function(sec) {{
        var anyVisible = Array.prototype.some.call(
          sec.querySelectorAll('.lab-row'), function(r) {{ return r.style.display !== 'none'; }}
        );
        sec.style.display = anyVisible ? '' : 'none';
      }});
    }}
    </script>
    """
    return page("Vulnerability Lab", body, breadcrumb=[("Lab", None)])
