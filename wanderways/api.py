"""Booking and user REST API (/api).

HARDENED in Task 3. The access policy (enforced here via wanderways/authz.py):
  * customers see and change only their own bookings and their own profile;
  * agents see and update only the bookings assigned to them;
  * only admins delete bookings, reassign owners, or change roles;
  * privileged fields (price, status, owner, role) are never taken from the client.

See docs/SECURITY_REPORT.md for the before/after of every fix.
"""
import sqlite3
from datetime import date

from flask import Blueprint, g, jsonify

from .authz import (
    BOOKING_STATUSES,
    USER_ROLES,
    can_access_booking,
    can_access_user,
    public_user,
)
from .auth import json_body, login_required
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

# Fields a customer may set when editing a booking. Deliberately excludes the
# privileged fields (total_price, status, customer_id, agent_id): those are set
# by the server. Agents/admins may additionally set `status` (handled in-route).
CUSTOMER_BOOKING_FIELDS = ("destination", "hotel", "depart_date", "return_date", "travellers", "notes")

# Fields a user may change on a profile. `role` is admin-only (handled in-route).
USER_SELF_FIELDS = ("full_name", "email", "phone")


def booking_to_dict(row):
    return {field: row[field] for field in BOOKING_FIELDS}


def fetch_booking(booking_id):
    return get_db().execute(BOOKING_SELECT + " WHERE b.id = ?", (booking_id,)).fetchone()


def load_booking_or_error(booking_id, action):
    """Fetch a booking and enforce object-level access.

    Returns (booking, None) when allowed, or (None, (response, status)) otherwise:
    404 if it does not exist, 403 if it exists but the caller may not touch it.
    """
    booking = fetch_booking(booking_id)
    if booking is None:
        return None, (jsonify(error="booking not found"), 404)
    if not can_access_booking(booking, action, g.user):
        return None, (jsonify(error="forbidden: you do not have access to this booking"), 403)
    return booking, None


def _valid_iso_date(value):
    try:
        date.fromisoformat(str(value))
        return True
    except ValueError:
        return False


def _price_for(destination, travellers):
    """Server-authoritative price. The client can never set the price itself."""
    price_per_traveller, _hotels = DESTINATIONS[destination]
    return float(price_per_traveller * travellers)


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
    # Scope is derived from the server-side session user only. There is no
    # client-supplied override (the old ?customer_id= IDOR was removed).
    if g.user["role"] == "admin":
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
    data = json_body()
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

    db = get_db()
    # Owner is always the caller. Only an admin may create a booking for someone else.
    owner_id = g.user["id"]
    if g.user["role"] == "admin" and data.get("customer_id"):
        owner_id = int(data["customer_id"])

    # Optional preferred agent, but it must really be an agent.
    agent_id = data.get("agent_id") or None
    if agent_id is not None:
        if db.execute("SELECT 1 FROM users WHERE id = ? AND role = 'agent'", (agent_id,)).fetchone() is None:
            return jsonify(error="unknown agent"), 400

    _price_per, hotels = DESTINATIONS[data["destination"]]
    next_id = db.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM bookings").fetchone()[0]
    values = {
        "booking_ref": f"WW-26-{1000 + next_id}",
        "customer_id": owner_id,                        # server-set, not client mass-assigned
        "agent_id": agent_id,
        "destination": data["destination"],
        "hotel": data.get("hotel") or hotels[0],
        "depart_date": data["depart_date"],
        "return_date": data["return_date"],
        "travellers": travellers,
        "total_price": _price_for(data["destination"], travellers),  # server-computed price
        "status": "pending",                            # always starts pending
        "passport_no": str(data.get("passport_no", "PENDING"))[:20],
        "payment_last4": str(data.get("payment_last4", "0000"))[:4],
        "notes": str(data.get("notes", ""))[:200],
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
    booking, err = load_booking_or_error(booking_id, "view")
    if err:
        return err
    return jsonify(booking_to_dict(booking))


@bp.put("/bookings/<int:booking_id>")
@login_required
def update_booking(booking_id):
    booking, err = load_booking_or_error(booking_id, "update")
    if err:
        return err
    data = json_body()

    allowed = set(CUSTOMER_BOOKING_FIELDS)
    if g.user["role"] in ("agent", "admin"):
        allowed.add("status")  # only staff may change the booking status
    changes = {field: data[field] for field in allowed if field in data}
    if not changes:
        return jsonify(error="no updatable fields supplied", allowed=sorted(allowed)), 400

    if "destination" in changes and changes["destination"] not in DESTINATIONS:
        return jsonify(error="unknown destination"), 400
    for df in ("depart_date", "return_date"):
        if df in changes and not _valid_iso_date(changes[df]):
            return jsonify(error="dates must be YYYY-MM-DD"), 400
    if "travellers" in changes:
        try:
            changes["travellers"] = int(changes["travellers"])
        except (TypeError, ValueError):
            return jsonify(error="travellers must be a number"), 400
    if "status" in changes and changes["status"] not in BOOKING_STATUSES:
        return jsonify(error="invalid status"), 400

    # Price is server-authoritative: recompute it whenever destination/travellers change.
    if "destination" in changes or "travellers" in changes:
        new_destination = changes.get("destination", booking["destination"])
        new_travellers = changes.get("travellers", booking["travellers"])
        changes["total_price"] = _price_for(new_destination, new_travellers)

    assignments = ", ".join(f"{field} = ?" for field in changes)  # names are from our allow-list
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
    booking, err = load_booking_or_error(booking_id, "delete")  # non-admins get 403 here
    if err:
        return err
    db = get_db()
    db.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    db.commit()
    return jsonify(message=f"booking {booking['booking_ref']} deleted")


@bp.post("/bookings/<int:booking_id>/cancel")
@login_required
def cancel_booking(booking_id):
    _booking, err = load_booking_or_error(booking_id, "cancel")
    if err:
        return err
    db = get_db()
    db.execute("UPDATE bookings SET status = 'cancelled' WHERE id = ?", (booking_id,))
    db.commit()
    return jsonify(booking_to_dict(fetch_booking(booking_id)))


# --------------------------------------------------------------------------- users

@bp.get("/users/<int:user_id>")
@login_required
def get_user(user_id):
    # Object-level check first: only the owner or an admin may read a profile.
    if not can_access_user(user_id, g.user):
        return jsonify(error="forbidden: you may only view your own profile"), 403
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return jsonify(error="user not found"), 404
    return jsonify(public_user(user))  # never includes password_hash


@bp.patch("/users/<int:user_id>")
@login_required
def update_user(user_id):
    if not can_access_user(user_id, g.user):
        return jsonify(error="forbidden: you may only edit your own profile"), 403
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
        return jsonify(error="user not found"), 404
    data = json_body()

    allowed = set(USER_SELF_FIELDS)
    if g.user["role"] == "admin":
        allowed.add("role")  # only an admin may change a role (privilege-escalation fix)
    changes = {field: data[field] for field in allowed if field in data}
    if not changes:
        return jsonify(error="no updatable fields supplied", allowed=sorted(allowed)), 400
    if "role" in changes and changes["role"] not in USER_ROLES:
        return jsonify(error="invalid role"), 400

    assignments = ", ".join(f"{field} = ?" for field in changes)
    try:
        db.execute(f"UPDATE users SET {assignments} WHERE id = ?", (*changes.values(), user_id))
        db.commit()
    except sqlite3.IntegrityError as exc:
        return jsonify(error="invalid user data", detail=str(exc)), 400
    return jsonify(public_user(db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()))
