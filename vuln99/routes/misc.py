import platform
import sys

from flask import Blueprint

from ..chrome import page
from ..difficulty import get_difficulty

bp = Blueprint("misc", __name__)


@bp.route("/version")
def version():
    diff = get_difficulty("verbose_errors")
    if diff == "hard":
        return page("Version", '<div class="alert info">Vuln99 Outfitters storefront.</div>')

    # Information Disclosure: internal versions, paths, and stack details
    # are exposed to any visitor -- useful recon for an attacker fingerprinting
    # the stack before picking exploits.
    info = f"""
    Python: {sys.version}
    Platform: {platform.platform()}
    App: vuln99 (Flask)
    Debug mode: enabled
    """
    return page("Version", f'<h1 class="page-title">Version / diagnostics</h1><pre>{info}</pre>')
