"""WanderWays Travel Portal - an intentionally vulnerable booking prototype.

This app is the training target for the Ezitech "Access Control Hardening"
project. It contains insecure direct object references (IDOR) and broken
role-based access control on purpose, so they can be mapped (Task 1),
exploited (Task 2) and fixed (Task 3). Every weakness is marked in the code
with a ``LAB-VULN`` comment.

Only run it on 127.0.0.1. Never deploy it.
"""
import os

from flask import Flask, jsonify, request

from . import db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        # LAB-VULN: hard-coded, guessable signing key (also leaked by /api/internal/debug).
        SECRET_KEY="wanderways-dev-secret",
        DATABASE=os.path.join(app.instance_path, "wanderways.db"),
    )
    if test_config:
        app.config.update(test_config)

    app.json.sort_keys = False  # keep JSON fields in the order we build them
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)

    from . import admin, api, auth, legacy, views

    app.register_blueprint(auth.bp)
    app.register_blueprint(views.bp)
    app.register_blueprint(api.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(legacy.bp)

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
