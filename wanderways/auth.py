"""Login, logout and the login_required decorator.

Sessions use Flask's signed session cookie. At login the app also sets a
plain, unsigned ``ww_role`` cookie that the UI reads to decide which menu
items to show.
"""
import functools

from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .db import get_db

bp = Blueprint("auth", __name__)

ROLE_COOKIE = "ww_role"


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username, full_name, email, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def login_required(view):
    """Reject anonymous users: 401 JSON for API routes, redirect for pages."""

    @functools.wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            if request.path.startswith("/api/"):
                return jsonify(error="authentication required"), 401
            return redirect(url_for("auth.login", next=request.path))
        return view(**kwargs)

    return wrapped


def json_body():
    """The request's JSON object, or {} if the body is missing, invalid or not an object."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def public_user(user):
    return {
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "email": user["email"],
        "role": user["role"],
    }


def _check_credentials(username, password):
    user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is not None and check_password_hash(user["password_hash"], password):
        return user
    return None


def _open_session(response, user):
    session.clear()
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    # LAB-VULN: unsigned, client-editable role cookie. Fine for showing menus,
    # but /api/admin/bookings/export trusts it for authorisation.
    response.set_cookie(ROLE_COOKIE, user["role"], samesite="Lax")
    return response


def _close_session(response):
    session.clear()
    response.delete_cookie(ROLE_COOKIE)
    return response


def _safe_next(default="/dashboard"):
    target = request.args.get("next", "")
    # only allow local paths, never "//evil.example" or absolute URLs
    if target.startswith("/") and not target.startswith("//"):
        return target
    return default


@bp.route("/login", methods=("GET", "POST"))
def login():
    """HTML login form. The page's JavaScript normally uses /api/auth/login instead."""
    if request.method == "POST":
        user = _check_credentials(request.form.get("username", ""), request.form.get("password", ""))
        if user is not None:
            return _open_session(redirect(_safe_next()), user)
        flash("Invalid username or password.")
        return render_template("login.html"), 401

    if g.user is not None:
        return redirect(url_for("views.dashboard"))
    return render_template("login.html")


@bp.get("/logout")
def logout():
    return _close_session(redirect(url_for("auth.login")))


@bp.post("/api/auth/login")
def api_login():
    data = json_body()
    user = _check_credentials(str(data.get("username", "")), str(data.get("password", "")))
    if user is None:
        return jsonify(error="invalid username or password"), 401
    return _open_session(jsonify(message="login successful", user=public_user(user)), user)


@bp.post("/api/auth/logout")
def api_logout():
    return _close_session(jsonify(message="logged out"))


@bp.get("/api/auth/me")
@login_required
def me():
    return jsonify(public_user(g.user))
