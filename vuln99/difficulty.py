"""
difficulty.py — per-vulnerability difficulty control, in the same spirit
as VulnMart's `getDifficulty(page)` / admin settings panel, but keyed
per *vulnerability* rather than per page, since several vulns can live
on the same route.

  low    -> fully vulnerable, no mitigation
  medium -> a partial / commonly-seen-but-still-bypassable mitigation
  hard   -> properly fixed (parameterized queries, allow-lists, etc.)

Every route module calls get_difficulty("some_key") and branches on the
result. The full catalog (VULN_CATALOG) drives the admin settings page
and is the single source of truth for "what vulnerabilities does this
app contain".
"""

from .db import conn

DEFAULT_DIFFICULTY = "low"

# key -> (display name, OWASP-ish category, short description)
VULN_CATALOG = {
    "login_sqli":        ("Login SQL Injection",            "A03 Injection",              "Auth bypass via string-built SQL in the login form."),
    "search_sqli":       ("Search UNION SQL Injection",     "A03 Injection",              "UNION-based injection in the product search box."),
    "product_sqli":      ("Product ID SQL Injection",       "A03 Injection",              "Error-based injection in ?id= on the product page."),
    "blind_sqli_bool":   ("Boolean-Blind SQL Injection",    "A03 Injection",              "True/false response differs based on injected condition."),
    "blind_sqli_time":   ("Time-Blind SQL Injection",       "A03 Injection",              "Response is delayed based on injected SLEEP()."),
    "reflected_xss":     ("Reflected XSS",                  "A03 Injection",              "Search query reflected into the page unescaped."),
    "stored_xss":        ("Stored XSS",                     "A03 Injection",              "Product reviews / profile bio render unescaped HTML."),
    "csrf":              ("CSRF on checkout",                "A01 Broken Access Control",  "State-changing checkout POST has no anti-CSRF token."),
    "idor_orders":       ("IDOR on order history",           "A01 Broken Access Control",  "Any order can be viewed by guessing its numeric id."),
    "broken_admin":      ("Broken access control on /admin","A01 Broken Access Control",  "Admin panel trusts a client-supplied cookie/role."),
    "mass_assignment":   ("Mass assignment on profile",      "A01 Broken Access Control",  "Profile update accepts and applies a client-sent 'role' field."),
    "price_tamper":      ("Client-trusted price / cart logic","A04 Insecure Design",       "Checkout trusts a price submitted by the client."),
    "path_traversal":    ("Path Traversal / LFI",             "A01 Broken Access Control",  "Document viewer reads any file the process can access."),
    "file_upload":       ("Unrestricted File Upload",         "A05 Security Misconfiguration","Avatar upload accepts any filename/extension, incl. path characters."),
    "command_injection": ("OS Command Injection",             "A03 Injection",              "Network diagnostics tool shells out with unsanitized input."),
    "open_redirect":     ("Open Redirect",                    "A01 Broken Access Control",  "Post-login / logout redirect target is not validated."),
    "ssrf":              ("Server-Side Request Forgery",      "A10 SSRF",                   "'Import product image from URL' fetches any URL server-side."),
    "xxe":               ("XML External Entity Injection",    "A03 Injection",              "Admin bulk-order XML import parses external entities."),
    "insecure_deserialization": ("Insecure Deserialization",  "A08 Data Integrity Failures", "'Remember me' cookie is an unpickled Python object."),
    "ssti":              ("Server-Side Template Injection",   "A03 Injection",               "Admin email-preview renders user input as a Jinja2 template."),
    "weak_crypto":       ("Weak Password Hashing",             "A02 Cryptographic Failures",  "Passwords are stored as unsalted MD5."),
    "verbose_errors":    ("Verbose Error / Info Disclosure",   "A05 Security Misconfiguration","Stack traces and internal paths leak to the client."),
    "recommend_sqli":    ("Cookie-based SQL Injection",        "A03 Injection",               "The 'last_category' cookie is built into the /recommend query unsanitized."),
    "header_sqli":       ("HTTP Header SQL Injection",         "A03 Injection",               "User-Agent / X-Forwarded-For headers are logged into activity_logs unsanitized."),
}


def get_difficulty(key: str) -> str:
    row = conn.execute(
        "SELECT difficulty FROM settings WHERE vuln_key = ?", (key,)
    ).fetchone()
    return row["difficulty"] if row else DEFAULT_DIFFICULTY


def set_difficulty(key: str, level: str) -> None:
    if level not in ("low", "medium", "hard"):
        return
    conn.execute(
        "INSERT INTO settings (vuln_key, difficulty) VALUES (?, ?) "
        "ON CONFLICT(vuln_key) DO UPDATE SET difficulty = excluded.difficulty",
        (key, level),
    )
    conn.commit()


def all_difficulties() -> dict:
    rows = conn.execute("SELECT vuln_key, difficulty FROM settings").fetchall()
    have = {r["vuln_key"]: r["difficulty"] for r in rows}
    return {k: have.get(k, DEFAULT_DIFFICULTY) for k in VULN_CATALOG}
