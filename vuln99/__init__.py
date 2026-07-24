from flask import Flask

from .config import Config
from .db import conn
from .logging_setup import init_request_logging, event_log
from .seed import seed_all


def create_app():
    app = Flask(__name__)
    app.secret_key = Config.SECRET_KEY

    # Fresh, known-good state every time the process starts — same
    # philosophy as VulnMart's `docker-compose down -v`.
    seed_all()

    init_request_logging(app)
    if Config.is_bound_publicly():
        event_log.warning(
            "vuln99 is starting bound to %s (not localhost-only). Make sure this "
            "host is on an isolated lab network before pointing scanners at it.",
            Config.HOST,
        )

    from .routes.home import bp as home_bp
    from .routes.auth import bp as auth_bp
    from .routes.search import bp as search_bp
    from .routes.product import bp as product_bp
    from .routes.reviews import bp as reviews_bp
    from .routes.account import bp as account_bp
    from .routes.cart import bp as cart_bp
    from .routes.fileops import bp as fileops_bp
    from .routes.diagnostics import bp as diagnostics_bp
    from .routes.redirect_ import bp as redirect_bp
    from .routes.ssrf import bp as ssrf_bp
    from .routes.xxe import bp as xxe_bp
    from .routes.ssti import bp as ssti_bp
    from .routes.admin import bp as admin_bp
    from .routes.misc import bp as misc_bp
    from .routes.recommend import bp as recommend_bp
    from .routes.category import bp as category_bp
    from .routes.lab import bp as lab_bp

    for bp in (
        home_bp, auth_bp, search_bp, product_bp, reviews_bp, account_bp,
        cart_bp, fileops_bp, diagnostics_bp, redirect_bp, ssrf_bp, xxe_bp,
        ssti_bp, admin_bp, misc_bp, recommend_bp, category_bp, lab_bp,
    ):
        app.register_blueprint(bp)

    return app
