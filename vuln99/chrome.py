"""
chrome.py — shared page shell (nav / footer / CSS) so every route just
returns a body fragment and gets a consistent, realistic storefront
around it. Styling is extended from Glacier's vulnerable_test_app.py
chrome (same dark, professional look) with an admin/difficulty layer
added on top, in the spirit of VulnMart's difficulty badges.
"""

import html as html_lib
from flask import session

STORE_NAME = "Vuln99 Outfitters"

BASE_CSS = """
  :root{
    --bg:#0d1117; --bg-alt:#11161f; --surface:#161c27; --surface-2:#1c2432;
    --line:#232c3d; --line-soft:#1a2130;
    --text:#e7ecf5; --text-dim:#8b96ab; --text-faint:#5b6579;
    --accent:#3fd0c9; --accent-2:#7c8cff; --accent-soft:rgba(63,208,201,0.12);
    --ok:#3fd07f; --warn:#f0b429; --danger:#f0556b;
    --radius:12px; --radius-sm:8px;
    --shadow:0 8px 24px rgba(0,0,0,0.35);
    --shadow-sm:0 2px 8px rgba(0,0,0,0.25);
  }
  *{box-sizing:border-box;}
  html{scroll-behavior:smooth;}
  body{
    margin:0; background:
      radial-gradient(1200px 500px at 15% -10%, rgba(63,208,201,0.08), transparent 60%),
      radial-gradient(900px 400px at 100% 0%, rgba(124,140,255,0.06), transparent 55%),
      var(--bg);
    color:var(--text);
    font-family:"Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;
    min-height:100vh; display:flex; flex-direction:column;
    -webkit-font-smoothing:antialiased;
  }
  a{color:inherit;}
  .utilitybar{background:var(--bg-alt); border-bottom:1px solid var(--line-soft); font-size:12px; color:var(--text-faint); padding:6px 32px; display:flex; justify-content:space-between;}
  nav{position:sticky; top:0; z-index:20; display:flex; align-items:center; gap:24px; padding:14px 32px; background:rgba(17,22,31,0.92); backdrop-filter:blur(10px); border-bottom:1px solid var(--line);}
  nav .brand{display:flex; align-items:center; gap:9px; text-decoration:none; color:var(--text);}
  nav .brand .mark{width:30px; height:30px; border-radius:9px; display:flex; align-items:center; justify-content:center; background:linear-gradient(135deg,var(--accent),var(--accent-2)); color:#04151a; font-weight:800; font-size:15px;}
  nav .brand .name{font-weight:700; letter-spacing:0.2px; font-size:16.5px;}
  nav .navlinks{display:flex; gap:20px; margin-left:4px;}
  nav .navlinks a{color:var(--text-dim); text-decoration:none; font-size:14px; font-weight:500;}
  nav .navlinks a:hover{color:var(--accent);}
  nav .navlinks a.lab-link{color:var(--accent); font-weight:700; display:flex; align-items:center; gap:5px; padding:5px 10px; border-radius:7px; border:1px solid rgba(63,208,201,0.3); background:var(--accent-soft);}
  nav .navlinks a.lab-link:hover{background:rgba(63,208,201,0.2);}
  nav .spacer{flex:1;}
  .lab-fab{position:fixed; right:22px; bottom:22px; z-index:30; background:var(--accent); color:#04151a; text-decoration:none; font-weight:700; font-size:13px; padding:12px 16px; border-radius:999px; box-shadow:var(--shadow); display:flex; align-items:center; gap:8px;}
  .lab-fab:hover{opacity:0.92;}
  @media (max-width:720px){ .lab-fab{padding:12px; font-size:0;} .lab-fab .fab-label{display:none;} }
  .navsearch{display:flex; align-items:center; background:var(--surface); border:1px solid var(--line); border-radius:999px; padding:7px 14px; gap:8px; min-width:200px;}
  .navsearch input{background:transparent; border:none; outline:none; color:var(--text); font-size:13.5px; width:100%;}
  .navicons{display:flex; align-items:center; gap:14px;}
  .navicons a{color:var(--text-dim); text-decoration:none; font-size:13.5px; font-weight:600; display:flex; align-items:center; gap:6px; padding:7px 12px; border-radius:8px;}
  .navicons a:hover{background:var(--surface); color:var(--text);}
  .navicons a.cta{background:var(--accent); color:#04151a;}
  main{flex:1; width:100%;}
  .wrap{max-width:1080px; margin:0 auto; padding:0 32px;}
  .breadcrumbs{font-size:12.5px; color:var(--text-faint); padding:18px 0 0;}
  .breadcrumbs a{color:var(--text-dim); text-decoration:none;}
  .hero{padding:48px 0 32px; display:flex; align-items:center; justify-content:space-between; gap:40px;}
  .hero .eyebrow{color:var(--accent); font-size:12.5px; font-weight:700; letter-spacing:1.5px; text-transform:uppercase;}
  .hero h1{font-size:34px; line-height:1.15; margin:10px 0 14px; letter-spacing:-0.5px;}
  .hero p{color:var(--text-dim); font-size:15px; max-width:480px; line-height:1.6;}
  .hero-art{width:190px; height:150px; border-radius:20px; flex-shrink:0; background:linear-gradient(150deg,var(--surface-2),var(--surface)); border:1px solid var(--line); display:flex; align-items:center; justify-content:center; font-size:56px; box-shadow:var(--shadow);}
  .section-head{display:flex; align-items:baseline; justify-content:space-between; margin:8px 0 20px;}
  .section-head h2{font-size:19px; margin:0;}
  .section-head .sub{color:var(--text-faint); font-size:13px;}
  .grid{display:grid; grid-template-columns:repeat(auto-fill,minmax(210px,1fr)); gap:16px; padding-bottom:32px;}
  .product{background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); text-decoration:none; color:var(--text); display:flex; flex-direction:column; overflow:hidden;}
  .product:hover{border-color:rgba(63,208,201,0.4); box-shadow:var(--shadow);}
  .product .thumb{height:100px; display:flex; align-items:center; justify-content:center; font-size:38px; background:linear-gradient(160deg,var(--surface-2),var(--bg-alt)); border-bottom:1px solid var(--line);}
  .product .body{padding:15px;}
  .product .name{font-weight:600; font-size:14.5px;}
  .product .price{color:var(--accent); font-weight:700; margin-top:8px; font-size:14.5px;}
  .product .blurb{color:var(--text-dim); font-size:12px; margin-top:6px; line-height:1.5;}
  .card{background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); padding:22px; margin-bottom:16px; box-shadow:var(--shadow-sm);}
  .panel-title{font-size:12px; font-weight:700; letter-spacing:0.6px; text-transform:uppercase; color:var(--text-faint); margin-bottom:12px;}
  h1.page-title{font-size:24px; margin:16px 0 18px;}
  button, .btn{background:var(--accent); color:#04151a; border:none; padding:10px 18px; border-radius:9px; font-weight:700; cursor:pointer; font-size:13.5px; text-decoration:none; display:inline-flex; align-items:center; gap:8px;}
  button:hover, .btn:hover{opacity:0.92;}
  .btn.ghost{background:transparent; color:var(--text); border:1px solid var(--line);}
  .btn.danger{background:var(--danger); color:#1a0508;}
  form.stack{display:flex; flex-direction:column; gap:12px; max-width:380px;}
  label{font-size:12.5px; color:var(--text-dim); font-weight:600; margin-bottom:-6px;}
  input[type=text], input[type=password], input[type=email], input[type=number], input[type=file], input[type=url], textarea, select{
    background:var(--bg-alt); border:1px solid var(--line); color:var(--text); padding:10px 12px; border-radius:9px; font-size:13.5px; outline:none;
  }
  textarea{font-family:inherit; resize:vertical;}
  .hint{color:var(--text-faint); font-size:12.5px; line-height:1.6;}
  .alert{padding:12px 15px; border-radius:9px; margin-top:14px; font-size:13.5px; display:flex; gap:10px; align-items:flex-start; line-height:1.5;}
  .alert.ok{background:rgba(63,208,127,0.1); border:1px solid rgba(63,208,127,0.35); color:var(--ok);}
  .alert.err{background:rgba(240,85,107,0.1); border:1px solid rgba(240,85,107,0.35); color:var(--danger);}
  .alert.info{background:var(--accent-soft); border:1px solid rgba(63,208,201,0.35); color:var(--accent);}
  pre{background:var(--bg-alt); border:1px solid var(--line); border-radius:var(--radius-sm); padding:15px; overflow-x:auto; font-size:12.5px; line-height:1.6; color:var(--text-dim);}
  table{width:100%; border-collapse:collapse; font-size:13px;}
  th,td{padding:9px 10px; border-bottom:1px solid var(--line); text-align:left;}
  th{color:var(--text-faint); font-size:11.5px; text-transform:uppercase; letter-spacing:0.4px;}
  .badge{display:inline-block; font-size:10.5px; font-weight:700; letter-spacing:0.4px; text-transform:uppercase; padding:3px 8px; border-radius:5px;}
  .badge.low{background:rgba(240,85,107,0.15); color:var(--danger);}
  .badge.medium{background:rgba(240,180,41,0.15); color:var(--warn);}
  .badge.hard{background:rgba(63,208,127,0.15); color:var(--ok);}
  .diag{background:var(--bg-alt); border:1px dashed var(--line); border-radius:var(--radius); margin-top:20px;}
  .diag .diag-head{display:flex; align-items:center; gap:10px; padding:15px 18px;}
  .diag .diag-head .dot{width:8px; height:8px; border-radius:50%; background:var(--ok); box-shadow:0 0 0 3px rgba(63,208,127,0.18);}
  .diag .diag-head .title{font-weight:700; font-size:13px;}
  .diag .diag-head .sub{color:var(--text-faint); font-size:12px;}
  .diag .diag-body{padding:0 18px 18px;}
  .diag-links{display:flex; flex-wrap:wrap; gap:8px;}
  .diag-links a{font-size:11px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; background:var(--surface); color:var(--text-dim); padding:5px 9px; border-radius:6px; border:1px solid var(--line); text-decoration:none;}
  .diag-links a:hover{border-color:var(--accent); color:var(--accent);}
  footer{border-top:1px solid var(--line); background:var(--bg-alt); margin-top:36px;}
  .footer-grid{max-width:1080px; margin:0 auto; padding:36px 32px 22px; display:grid; grid-template-columns:1.4fr 1fr 1fr 1fr; gap:24px;}
  .footer-grid p{color:var(--text-faint); font-size:12.5px; line-height:1.6; max-width:260px;}
  .footer-grid h4{font-size:12px; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-dim); margin:0 0 12px;}
  .footer-grid ul{list-style:none; padding:0; margin:0; display:flex; flex-direction:column; gap:9px;}
  .footer-grid a{color:var(--text-faint); text-decoration:none; font-size:13px;}
  .footer-grid a:hover{color:var(--accent);}
  .footer-bottom{border-top:1px solid var(--line-soft); padding:14px 32px; max-width:1080px; margin:0 auto; display:flex; justify-content:space-between; color:var(--text-faint); font-size:11.5px; flex-wrap:wrap; gap:8px;}
  @media (max-width:720px){ nav .navlinks, .navsearch{display:none;} .hero{flex-direction:column; align-items:flex-start;} .footer-grid{grid-template-columns:1fr 1fr;} }
"""


def difficulty_badge(level: str) -> str:
    return f'<span class="badge {level}">{level}</span>'


def _nav_right():
    if session.get("user_id"):
        links = f'<a href="/account">{html_lib.escape(session.get("username",""))}</a><a href="/orders">Orders</a>'
        if session.get("role") == "admin" or session.get("is_admin_cookie") == "true":
            links += '<a href="/admin">Admin</a>'
        links += '<a href="/logout">Log out</a>'
        return links
    return '<a href="/login">Log in</a><a href="/register">Register</a>'


def page(title, body, breadcrumb=None):
    crumb_html = ""
    if breadcrumb:
        parts = ['<a href="/">Catalog</a>'] + [
            f'<a href="{href}">{html_lib.escape(label)}</a>' if href else f'<span>{html_lib.escape(label)}</span>'
            for label, href in breadcrumb
        ]
        crumb_html = f'<div class="breadcrumbs wrap">{" &nbsp;/&nbsp; ".join(parts)}</div>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html_lib.escape(title)} &middot; {STORE_NAME}</title>
<style>{BASE_CSS}</style></head>
<body>
<div class="utilitybar"><span>Vuln99 &mdash; intentionally vulnerable training app</span><span>localhost only &middot; not for production</span></div>
<nav>
  <a class="brand" href="/"><span class="mark">99</span><span class="name">{STORE_NAME}</span></a>
  <div class="navlinks">
    <a href="/">Catalog</a>
    <a href="/category">Categories</a>
    <a href="/recommend">For you</a>
    <a href="/cart">Cart</a>
  </div>
  <span class="spacer"></span>
  <div class="navlinks">
    <a class="lab-link" href="/lab">&#129514;&nbsp;Lab</a>
  </div>
  <form class="navsearch" action="/search" method="get">
    <span class="icon">&#128269;</span>
    <input type="text" name="q" placeholder="Search products&hellip;">
  </form>
  <div class="navicons">{_nav_right()}<a class="cta" href="/cart">&#128722;&nbsp;Cart</a></div>
</nav>
{crumb_html}
<main><div class="wrap">{body}</div></main>
<a class="lab-fab" href="/lab" title="Vulnerability Lab">&#129514;<span class="fab-label">&nbsp;Lab</span></a>
<footer>
  <div class="footer-grid">
    <div>
      <div style="font-weight:700; font-size:14.5px; margin-bottom:8px;">{STORE_NAME}</div>
      <p>A realistic, self-contained e-commerce lab covering a wide range of web vulnerabilities across configurable difficulty levels &mdash; for authorized security training only.</p>
    </div>
    <div><h4>Shop</h4><ul><li><a href="/">Catalog</a></li><li><a href="/category">Categories</a></li><li><a href="/recommend">For you</a></li><li><a href="/cart">Cart</a></li><li><a href="/orders">Orders</a></li></ul></div>
    <div><h4>Account</h4><ul><li><a href="/login">Log in</a></li><li><a href="/register">Register</a></li><li><a href="/account">Profile</a></li></ul></div>
    <div><h4>Lab</h4><ul><li><a href="/lab">Vulnerability Lab</a></li><li><a href="/admin">Admin panel</a></li><li><a href="/admin/settings">Difficulty settings</a></li><li><a href="/admin/logs">Activity logs</a></li><li><a href="/version">Version</a></li></ul></div>
  </div>
  <div class="footer-bottom">
    <span>&copy; Vuln99 &mdash; built for security training, extended from Glacier + VulnMart</span>
    <span>Never expose this outside localhost</span>
  </div>
</footer>
</body></html>"""
