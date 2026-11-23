"""WanderWays Travel Portal - a travel booking prototype (Ezitech lab).

This app began as an intentionally vulnerable training target. Task 3 applied
the remediation patch set, so access control is now enforced centrally in
wanderways/authz.py. The exploitable version is preserved at the git tag
``task2-vulnerable`` for reference; docs/SECURITY_REPORT.md has the before/after.

Still a local lab: run it on 127.0.0.1. Set WANDERWAYS_SECRET_KEY before any
real deployment.
"""
import os
import secrets

from flask import Flask, jsonify, request

from . import db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        # Signing key comes from the environment. If unset (local dev) a fresh
        # random key is generated per process - never a hard-coded, guessable value.
        SECRET_KEY=os.environ.get("WANDERWAYS_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.path.join(app.instance_path, "wanderways.db"),
    )
    if test_config:
        app.config.update(test_config)

    app.json.sort_keys = False  # keep JSON fields in the order we build them
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)

    from . import admin, api, auth, views

    app.register_blueprint(auth.bp)
    app.register_blueprint(views.bp)
    app.register_blueprint(api.bp)
    app.register_blueprint(admin.bp)

    _register_error_handlers(app)

    # First run convenience: create and seed the database if it does not exist.
    # `flask --app wanderways init-db` resets it at any time.
    if not os.path.exists(app.config["DATABASE"]):
        with app.app_context():
            db.init_db(seed=True)
        app.logger.info("Created and seeded %s", app.config["DATABASE"])

    return app


def _register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return jsonify(error="not found"), 404
        return error

    @app.errorhandler(405)
    def method_not_allowed(error):
        if request.path.startswith("/api/"):
            response = jsonify(error="method not allowed")
            response.status_code = 405
            response.headers["Allow"] = ", ".join(sorted(error.valid_methods or []))
            return response
        return error
