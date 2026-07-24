import html as html_lib

from flask import Blueprint, request, render_template_string

from ..chrome import page
from ..difficulty import get_difficulty

bp = Blueprint("ssti", __name__)

DEFAULT_TEMPLATE = "Hi {{ name }}, thanks for shopping with Vuln99!"
PAYLOAD_HINT = "{{ 7*7 }}"


@bp.route("/admin/email-preview", methods=["GET", "POST"])
def email_preview():
    if request.method == "GET":
        return page("Email template preview", f"""
        <h1 class="page-title">Marketing email template preview</h1>
        <div class="card">
          <form class="stack" method="post" action="/admin/email-preview">
            <label>Template body</label>
            <textarea name="template" rows="4">{html_lib.escape(DEFAULT_TEMPLATE)}</textarea>
            <button type="submit">Preview</button>
          </form>
          <p class="hint">Marketers can customize the welcome email body before it goes out. Try <code>{html_lib.escape(PAYLOAD_HINT)}</code> in the template to see it evaluated.</p>
        </div>
        """)

    template = request.form.get("template", DEFAULT_TEMPLATE)
    diff = get_difficulty("ssti")

    if diff == "low":
        # SSTI: the admin-supplied template string is rendered directly
        # with Jinja2, which can be abused to reach arbitrary Python
        # execution (e.g. via __class__.__mro__ gadget chains), not just
        # simple expression evaluation like {{7*7}}.
        try:
            rendered = render_template_string(template, name="Jane Doe")
        except Exception as e:
            rendered = f"Render error: {e}"
    elif diff == "medium":
        # naive filter -- blocks the literal substring "__class__" but
        # is trivially bypassed via string concatenation / attribute
        # access tricks or Jinja2 filters.
        if "__class__" in template or "__mro__" in template:
            rendered = "Blocked: disallowed template syntax."
        else:
            try:
                rendered = render_template_string(template, name="Jane Doe")
            except Exception as e:
                rendered = f"Render error: {e}"
    else:
        # hard: user input is only ever substituted as *data*, never
        # compiled as a template.
        rendered = DEFAULT_TEMPLATE.replace("{{ name }}", "Jane Doe")
        rendered = f"(Template editing is data-only in this mode.) {html_lib.escape(rendered)} | Your input, unrendered: {html_lib.escape(template)}"

    body = f"""
    <h1 class="page-title">Preview</h1>
    <div class="card"><pre>{rendered if diff != 'hard' else rendered}</pre></div>
    """
    return page("Preview", body)
