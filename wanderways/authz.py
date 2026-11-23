"""Central authorization layer for WanderWays (Task 3 remediation).

Every access-control decision lives here, so each route enforces the *same*
policy and no route can silently "forget" a check (which is how the Task 2
vulnerabilities happened). This is the authorization middleware described in
docs/HANDOVER.md.

Two kinds of control:
  * function-level (can this ROLE use this endpoint at all?)  -> role_required / admin_required
  * object-level  (may this USER act on THIS specific record?) -> can_access_booking / can_access_user

Policy
------
  role      bookings it may act on                              profile it may edit
  --------  --------------------------------------------------  --------------------------
  admin     all: view / update / cancel / delete / reassign     anyone, incl. the role field
  agent     only bookings assigned to them: view / update /     their own (never the role)
            cancel   (may NOT delete)
  customer  only their own bookings: view / update / cancel     their own (never the role)
            (may NOT delete)
"""
import functools

from flask import g, jsonify

# Fields of a user record that are safe to return over the API.
# Note: password_hash is deliberately absent so it can never leak again.
PUBLIC_USER_FIELDS = ("id", "username", "full_name", "email", "phone", "role", "created_at")

BOOKING_STATUSES = ("pending", "confirmed", "cancelled")
USER_ROLES = ("admin", "agent", "customer")


def role_required(*roles):
    """Decorator: allow only the given role(s). 401 if anonymous, 403 if wrong role."""

    def decorator(view):
        @functools.wraps(view)
        def wrapped(**kwargs):
            if g.user is None:
                return jsonify(error="authentication required"), 401
            if g.user["role"] not in roles:
                return jsonify(error=f"forbidden: requires {' or '.join(roles)} role"), 403
            return view(**kwargs)

        return wrapped

    return decorator


# The single, correct admin gate used by every admin route.
admin_required = role_required("admin")


def can_access_booking(booking, action, user):
    """Object-level policy: may ``user`` perform ``action`` on ``booking``?

    action is one of: 'view', 'update', 'cancel', 'delete'. Pure function (no I/O)
    so it is trivial to unit-test.
    """
    role = user["role"]
    if role == "admin":
        return True
    if action == "delete":
        return False  # only admins may delete
    if role == "agent":
        return booking["agent_id"] == user["id"]      # the assigned agent only
    return booking["customer_id"] == user["id"]        # customer: their own only


def can_access_user(target_user_id, user):
    """Object-level policy for profiles: the owner, or an admin."""
    return user["role"] == "admin" or user["id"] == target_user_id


def public_user(row):
    """Projection of a user row that is safe to send to a client (never the hash)."""
    keys = set(row.keys())
    return {field: row[field] for field in PUBLIC_USER_FIELDS if field in keys}
