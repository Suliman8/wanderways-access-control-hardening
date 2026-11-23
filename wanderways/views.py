"""HTML pages. Each page is a thin template; data is loaded by static/js/app.js."""
from flask import Blueprint, Response, g, jsonify, redirect, render_template, url_for

from .auth import login_required
from .db import get_db

bp = Blueprint("views", __name__)

ROBOTS_TXT = """User-agent: *
Disallow: /admin
"""


@bp.get("/")
def index():
    return redirect(url_for("views.dashboard" if g.user else "auth.login"))


@bp.get("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@bp.get("/bookings/new")
@login_required
def new_booking():
    return render_template("booking_new.html")


@bp.get("/bookings/<int:booking_id>")
@login_required
def booking_detail(booking_id):
    return render_template("booking_detail.html", booking_id=booking_id)


@bp.get("/profile")
@login_required
def profile():
    return render_template("profile.html")


@bp.get("/admin")
@login_required
def admin():
    # Non-admins are redirected away from the admin page (defence in depth; the
    # admin APIs are admin-only regardless). Only admins see the panel.
    if g.user["role"] != "admin":
        return redirect(url_for("views.dashboard"))
    return render_template("admin.html")


@bp.get("/robots.txt")
def robots():
    return Response(ROBOTS_TXT, mimetype="text/plain")


@bp.get("/health")
def health():
    get_db().execute("SELECT 1").fetchone()
    return jsonify(status="ok", service="wanderways", database="connected")
