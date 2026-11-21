"""Admin API (/api/admin). Three routes, three different authorisation styles."""
import csv
import functools
import io

from flask import Blueprint, Response, g, jsonify, request

from .auth import ROLE_COOKIE, login_required
from .db import get_db

bp = Blueprint("admin_api", __name__, url_prefix="/api/admin")


def admin_required(view):
    """Correct check: the role comes from the server-side session user."""

    @functools.wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            return jsonify(error="authentication required"), 401
        if g.user["role"] != "admin":
            return jsonify(error="admin role required"), 403
        return view(**kwargs)

    return wrapped


@bp.get("/users")
@login_required
# LAB-VULN (broken RBAC): role check missing - any logged-in user can list
# every account with email, phone and role.
def list_users():
    rows = get_db().execute(
        "SELECT id, username, full_name, email, phone, role, created_at FROM users ORDER BY id"
    )
    users = [dict(row) for row in rows]
    return jsonify(count=len(users), users=users)


@bp.get("/stats")
@admin_required  # enforced correctly - the reference pattern for the Task 3 fixes
def stats():
    db = get_db()
    users_by_role = {r["role"]: r["n"] for r in db.execute("SELECT role, COUNT(*) AS n FROM users GROUP BY role")}
    bookings_by_status = {
        r["status"]: r["n"] for r in db.execute("SELECT status, COUNT(*) AS n FROM bookings GROUP BY status")
    }
    revenue = db.execute("SELECT COALESCE(SUM(total_price), 0) FROM bookings WHERE status = 'confirmed'").fetchone()[0]
    return jsonify(
        users_by_role=users_by_role,
        bookings_by_status=bookings_by_status,
        total_bookings=sum(bookings_by_status.values()),
        confirmed_revenue_usd=round(revenue, 2),
    )


@bp.get("/bookings/export")
def export_bookings():
    # LAB-VULN (client-controlled authorisation): trusts the unsigned ww_role
    # cookie and never looks at the session, so "Cookie: ww_role=admin" is enough.
    if request.cookies.get(ROLE_COOKIE) != "admin":
        return jsonify(error="admin role required"), 403
    rows = get_db().execute(
        "SELECT b.booking_ref, u.full_name AS customer, u.email, b.destination, b.depart_date,"
        " b.return_date, b.travellers, b.total_price, b.status, b.passport_no, b.payment_last4"
        " FROM bookings b JOIN users u ON u.id = b.customer_id ORDER BY b.id"
    ).fetchall()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(rows[0].keys() if rows else ["booking_ref"])
    writer.writerows(tuple(row) for row in rows)
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=wanderways_bookings.csv"},
    )
