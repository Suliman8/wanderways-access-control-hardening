"""Leftover routes: not linked anywhere in the UI, but never removed.

They are the "hidden endpoints" that Task 1 enumeration has to discover.
"""
import os
import sys
from importlib.metadata import version

from flask import Blueprint, current_app, jsonify

from .api import BOOKING_SELECT, booking_to_dict
from .db import get_db

bp = Blueprint("legacy", __name__)


@bp.get("/api/v1/bookings")
def v1_list_bookings():
    # LAB-VULN (missing authentication): old mobile-app endpoint, no login at all.
    rows = get_db().execute(BOOKING_SELECT + " ORDER BY b.id")
    bookings = [booking_to_dict(row) for row in rows]
    return jsonify(api_version="v1", count=len(bookings), bookings=bookings)


@bp.get("/api/v1/bookings/<int:booking_id>")
def v1_get_booking(booking_id):
    # LAB-VULN (missing authentication + IDOR).
    row = get_db().execute(BOOKING_SELECT + " WHERE b.id = ?", (booking_id,)).fetchone()
    if row is None:
        return jsonify(error="booking not found"), 404
    return jsonify(api_version="v1", booking=booking_to_dict(row))


@bp.get("/api/internal/debug")
def debug_info():
    # LAB-VULN (information disclosure): leaks the session signing key, which
    # lets an attacker forge a Flask session cookie for any user id.
    return jsonify(
        service="wanderways",
        debug=current_app.debug,
        secret_key=current_app.config["SECRET_KEY"],
        # path shown relative to the app, so the leak doesn't print the host's home folder
        database=os.path.join("instance", os.path.basename(current_app.config["DATABASE"])),
        python=sys.version.split()[0],
        flask=version("flask"),
        route_count=len(list(current_app.url_map.iter_rules())),
    )
