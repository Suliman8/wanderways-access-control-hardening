"""Booking and user REST API (/api).

INTENTIONALLY VULNERABLE. The *intended* access policy is:
  * customers see and change only their own bookings and profile;
  * agents see and update only the bookings assigned to them;
  * only admins delete bookings, change prices or owners, or change roles.
The routes below only check that the caller is logged in. Each gap is marked
LAB-VULN and is the subject of Task 2 (exploit) and Task 3 (fix).
"""
import sqlite3
from datetime import date

from flask import Blueprint, g, jsonify, request

from .auth import login_required
from .db import get_db
from .seed import DESTINATIONS

bp = Blueprint("api", __name__, url_prefix="/api")

BOOKING_SELECT = """
    SELECT b.*, c.full_name AS customer_name, a.full_name AS agent_name
    FROM bookings AS b
    JOIN users AS c ON c.id = b.customer_id
    LEFT JOIN users AS a ON a.id = b.agent_id
"""

BOOKING_FIELDS = (
    "id", "booking_ref", "customer_id", "customer_name", "agent_id", "agent_name",
    "destination", "hotel", "depart_date", "return_date", "travellers", "total_price",
    "status", "passport_no", "payment_last4", "notes", "created_at",
)

# Every column a client may send to PUT /api/bookings/<id>.
BOOKING_UPDATABLE = (
    "destination", "hotel", "depart_date", "return_date", "travellers", "notes",
    "status", "total_price", "customer_id", "agent_id",
)

USER_UPDATABLE = ("full_name", "email", "phone", "role")


def booking_to_dict(row):
    return {field: row[field] for field in BOOKING_FIELDS}


def fetch_booking(booking_id):
    return get_db().execute(BOOKING_SELECT + " WHERE b.id = ?", (booking_id,)).fetchone()


def _valid_iso_date(value):
    try:
        date.fromisoformat(str(value))
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- lookups

@bp.get("/destinations")
def destinations():
    return jsonify([
        {"name": name, "price_per_traveller": price, "hotels": hotels}
        for name, (price, hotels) in DESTINATIONS.items()
    ])


@bp.get("/agents")
@login_required
def agents():
    rows = get_db().execute("SELECT id, full_name FROM users WHERE role = 'agent' ORDER BY id")
    return jsonify([dict(row) for row in rows])


# --------------------------------------------------------------------------- bookings

@bp.get("/bookings")
@login_required
def list_bookings():
    db = get_db()
    # LAB-VULN (IDOR): a client-supplied ?customer_id= overrides the caller's own scope.
    customer_id = request.args.get("customer_id", type=int)
    if customer_id is not None:
        rows = db.execute(BOOKING_SELECT + " WHERE b.customer_id = ? ORDER BY b.id", (customer_id,))
    elif g.user["role"] == "admin":
        rows = db.execute(BOOKING_SELECT + " ORDER BY b.id")
    elif g.user["role"] == "agent":
        rows = db.execute(BOOKING_SELECT + " WHERE b.agent_id = ? ORDER BY b.id", (g.user["id"],))
    else:
        rows = db.execute(BOOKING_SELECT + " WHERE b.customer_id = ? ORDER BY b.id", (g.user["id"],))
    bookings = [booking_to_dict(row) for row in rows]
    return jsonify(count=len(bookings), bookings=bookings)


@bp.post("/bookings")
@login_required
def create_booking():
    data = request.get_json(silent=True) or {}
    missing = [f for f in ("destination", "depart_date", "return_date", "travellers") if not data.get(f)]
    if missing:
        return jsonify(error="missing fields", fields=missing), 400
    if data["destination"] not in DESTINATIONS:
        return jsonify(error="unknown destination"), 400
    if not (_valid_iso_date(data["depart_date"]) and _valid_iso_date(data["return_date"])):
        return jsonify(error="dates must be YYYY-MM-DD"), 400
    if data["return_date"] < data["depart_date"]:
        return jsonify(error="return_date is before depart_date"), 400
    try:
        travellers = int(data["travellers"])
    except (TypeError, ValueError):
        return jsonify(error="travellers must be a number"), 400

    price_per_traveller, hotels = DESTINATIONS[data["destination"]]
    db = get_db()
    next_id = db.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM bookings").fetchone()[0]

    # LAB-VULN (mass assignment): owner, price and status come from the request
    # body when present, so a customer can book for someone else or set price 0.
    values = {
        "booking_ref": f"WW-26-{1000 + next_id}",
        "customer_id": data.get("customer_id", g.user["id"]),
        "agent_id": data.get("agent_id") or None,
        "destination": data["destination"],
        "hotel": data.get("hotel") or hotels[0],
        "depart_date": data["depart_date"],
        "return_date": data["return_date"],
        "travellers": travellers,
        "total_price": data.get("total_price", float(price_per_traveller * travellers)),
        "status": data.get("status", "pending"),
        "passport_no": data.get("passport_no", "PENDING"),
        "payment_last4": data.get("payment_last4", "0000"),
        "notes": data.get("notes", ""),
    }
    try:
        cur = db.execute(
            f"INSERT INTO bookings ({', '.join(values)}) VALUES ({', '.join('?' for _ in values)})",
            tuple(values.values()),
        )
        db.commit()
    except sqlite3.IntegrityError as exc:
        return jsonify(error="invalid booking data", detail=str(exc)), 400
    return jsonify(booking_to_dict(fetch_booking(cur.lastrowid))), 201


@bp.get("/bookings/<int:booking_id>")
@login_required
def get_booking(booking_id):
    # LAB-VULN (IDOR): no ownership check - any logged-in user can read any
    # booking, including passport number and card digits.
    booking = fetch_booking(booking_id)
    if booking is None:
        return jsonify(error="booking not found"), 404
    return jsonify(booking_to_dict(booking))


@bp.put("/bookings/<int:booking_id>")
@login_required
def update_booking(booking_id):
    if fetch_booking(booking_id) is None:
        return jsonify(error="booking not found"), 404
    data = request.get_json(silent=True) or {}
    # LAB-VULN (IDOR + mass assignment): no ownership check, and privileged
    # fields (status, total_price, customer_id, agent_id) are writable by anyone.
    changes = {field: data[field] for field in BOOKING_UPDATABLE if field in data}
    if not changes:
        return jsonify(error="no updatable fields supplied", allowed=list(BOOKING_UPDATABLE)), 400
    assignments = ", ".join(f"{field} = ?" for field in changes)  # field names come from the allow-list
    db = get_db()
    try:
        db.execute(f"UPDATE bookings SET {assignments} WHERE id = ?", (*changes.values(), booking_id))
        db.commit()
    except sqlite3.IntegrityError as exc:
        return jsonify(error="invalid booking data", detail=str(exc)), 400
    return jsonify(booking_to_dict(fetch_booking(booking_id)))


@bp.delete("/bookings/<int:booking_id>")
@login_required
def delete_booking(booking_id):
    # LAB-VULN (broken RBAC): meant to be admin-only, but any logged-in user
    # can permanently delete any booking.
    booking = fetch_booking(booking_id)
    if booking is None:
        return jsonify(error="booking not found"), 404
    db = get_db()
    db.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    db.commit()
    return jsonify(message=f"booking {booking['booking_ref']} deleted")


@bp.post("/bookings/<int:booking_id>/cancel")
@login_required
def cancel_booking(booking_id):
    # LAB-VULN (IDOR): cancels any booking, not only the caller's own.
    if fetch_booking(booking_id) is None:
        return jsonify(error="booking not found"), 404
    db = get_db()
    db.execute("UPDATE bookings SET status = 'cancelled' WHERE id = ?", (booking_id,))
    db.commit()
    return jsonify(booking_to_dict(fetch_booking(booking_id)))


# --------------------------------------------------------------------------- users

@bp.get("/users/<int:user_id>")
@login_required
def get_user(user_id):
    # LAB-VULN (IDOR + excessive data exposure): returns any user's full
    # record, including the password hash.
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return jsonify(error="user not found"), 404
    return jsonify(dict(user))


@bp.patch("/users/<int:user_id>")
@login_required
def update_user(user_id):
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
        return jsonify(error="user not found"), 404
    data = request.get_json(silent=True) or {}
    # LAB-VULN (IDOR + privilege escalation): edits any profile and accepts
    # "role", so a customer can promote themselves to admin.
    changes = {field: data[field] for field in USER_UPDATABLE if field in data}
    if not changes:
        return jsonify(error="no updatable fields supplied", allowed=list(USER_UPDATABLE)), 400
    assignments = ", ".join(f"{field} = ?" for field in changes)
    try:
        db.execute(f"UPDATE users SET {assignments} WHERE id = ?", (*changes.values(), user_id))
        db.commit()
    except sqlite3.IntegrityError as exc:
        return jsonify(error="invalid user data", detail=str(exc)), 400
    return jsonify(dict(db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()))
