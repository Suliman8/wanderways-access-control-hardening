"""Admin API (/api/admin). HARDENED in Task 3: every route is admin-only,
checked against the server-side session role via the shared admin_required gate.
"""
import csv
import io

from flask import Blueprint, Response, jsonify

from .authz import admin_required
from .db import get_db

bp = Blueprint("admin_api", __name__, url_prefix="/api/admin")


@bp.get("/users")
@admin_required
def list_users():
    rows = get_db().execute(
        "SELECT id, username, full_name, email, phone, role, created_at FROM users ORDER BY id"
    )
    users = [dict(row) for row in rows]
    return jsonify(count=len(users), users=users)


@bp.get("/stats")
@admin_required
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
@admin_required
def export_bookings():
    # Authorisation is the server-side session role (admin_required). The old
    # client-editable ww_role cookie is gone, so this can no longer be forged.
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
